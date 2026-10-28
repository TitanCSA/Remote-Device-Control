#include "Host.h"
#include "Config.h"
#include "Wire.h"
#include "VirtualInput.h"
#include "CaptureAgent.h"
#include "RelayStream.h"
#include "VideoPacing.h"
#include "Directory.h"
#include "Discovery.h"
#include <wtsapi32.h>
#include <atomic>
#include <thread>
#include <memory>
#include <mutex>
#include <vector>
#include <chrono>
#include <algorithm>

namespace RemoteControl {
namespace {
SERVICE_STATUS_HANDLE serviceHandle=nullptr;SERVICE_STATUS serviceStatus{};HANDLE stopEvent=nullptr;
std::atomic<bool> revokeSession{false};
void Log(const std::string& message,WORD type=EVENTLOG_INFORMATION_TYPE){HANDLE source=RegisterEventSourceW(nullptr,ServiceName);if(source){auto value=Wide(message);LPCWSTR texts[]={value.c_str()};ReportEventW(source,type,0,1,nullptr,1,0,texts,nullptr);DeregisterEventSource(source);}}
void SetStatus(DWORD state,DWORD code=0){if(!serviceHandle)return;serviceStatus.dwServiceType=SERVICE_WIN32_OWN_PROCESS;serviceStatus.dwCurrentState=state;serviceStatus.dwWin32ExitCode=code;serviceStatus.dwControlsAccepted=state==SERVICE_RUNNING?(SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_SESSIONCHANGE):0;serviceStatus.dwWaitHint=state==SERVICE_STOP_PENDING?30000:0;SetServiceStatus(serviceHandle,&serviceStatus);}
struct Session {
 std::string token,credential;DWORD console=0;VirtualInput input;SessionCapture capture;
 std::weak_ptr<Link> inputLink,videoLink;std::mutex linksMutex,inputMutex;std::atomic<bool> stop{false},ready{false};
 ~Session(){input.Stop();capture.Stop();}
 void StopInput()noexcept{stop=true;std::lock_guard<std::mutex> lock(inputMutex);input.Stop();}
 void Close()noexcept{StopInput();std::lock_guard<std::mutex> lock(linksMutex);if(auto p=inputLink.lock())p->Close();if(auto p=videoLink.lock())p->Close();}
 bool BindVideo(const std::shared_ptr<Link>& link){std::lock_guard<std::mutex> lock(linksMutex);if(stop||!videoLink.expired())return false;videoLink=link;return true;}
};
class Host {
 Config config_;TitanTransport::Runtime network_;TitanTransport::Identity identity_;
 std::mutex mutex_;std::shared_ptr<Session> session_;std::vector<std::weak_ptr<Link>> links_;
 struct Job{std::thread thread;std::shared_ptr<std::atomic<bool>> done;};std::vector<Job> jobs_;
 std::vector<std::thread> relays_;std::thread publisher_;DiscoveryResponder discovery_;std::atomic<bool> stopping_{false};SOCKET listener_=INVALID_SOCKET;
 uint64_t nextApproval_=0;
 bool Stopping()const noexcept{return stopping_||WaitForSingleObject(stopEvent,0)==WAIT_OBJECT_0;}
 void Drop(const std::shared_ptr<Session>& session){session->Close();std::lock_guard<std::mutex> lock(mutex_);if(session_==session)session_.reset();}
 void Track(const std::shared_ptr<Link>& link){std::lock_guard<std::mutex> lock(mutex_);links_.erase(std::remove_if(links_.begin(),links_.end(),[](auto& p){return p.expired();}),links_.end());links_.push_back(link);}
 void InputLoop(const std::shared_ptr<Link>& link,const Packet& auth){
  const auto credential=Text(auth);const bool open=config_.noCode&&TitanTransport::ConstantTimeEqual(credential,OpenAccessSecret);
  if(!open&&!TitanTransport::ConstantTimeEqual(credential,config_.secret))throw std::runtime_error("Connection credentials were refused.");DWORD console=WTSGetActiveConsoleSessionId();if(!ConsoleAvailable(console))throw std::runtime_error("Sign in and unlock the target PC locally before connecting.");
  auto session=std::make_shared<Session>();session->console=console;session->credential=credential;session->token=TitanTransport::RandomSecret();session->inputLink=link;
  {std::lock_guard<std::mutex> lock(mutex_);if(session_)throw std::runtime_error("This host is busy with another controller or connection request.");if(config_.noCode&&config_.requireApproval){if(GetTickCount64()<nextApproval_)throw std::runtime_error("A recent connection request was declined or expired. Try again in a few seconds.");nextApproval_=GetTickCount64()+10000;}session_=session;}
  try{
   if(config_.noCode&&config_.requireApproval){
    link->Send(Message::Pending,std::string("Waiting for permission on the target PC (up to 25 seconds)."));
    std::wstring title=L"Remote Device Control - connection request";
    std::wstring message=L"Someone selected this PC from the public list.\n\nAllow this person to see your desktop and control your keyboard and mouse?\n\nChoose No if you are not expecting a remote connection.";
    DWORD response=IDNO;const BOOL shown=WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE,console,title.data(),static_cast<DWORD>(title.size()*sizeof(wchar_t)),message.data(),static_cast<DWORD>(message.size()*sizeof(wchar_t)),MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2|MB_TOPMOST|MB_SETFOREGROUND,25,&response,TRUE);
    if(!shown)throw std::runtime_error(WindowsError("Display local connection approval",GetLastError()));
    if(response!=IDYES){{std::lock_guard<std::mutex> lock(mutex_);nextApproval_=GetTickCount64()+10000;}throw std::runtime_error(response==IDTIMEOUT?"The connection request timed out without local permission.":"The person on the target PC declined the connection request.");}
    if(Stopping()||session->stop||!ConsoleAvailable(console))throw std::runtime_error("The desktop changed while waiting for permission.");
    link->Send(Message::Pending,std::string("Permission granted. Preparing virtual input and desktop capture."));
   }
   {std::lock_guard<std::mutex> lock(session->inputMutex);if(Stopping()||session->stop)throw std::runtime_error("Connection cancelled before virtual input setup.");session->input.Start();}if(Stopping()||session->stop||!ConsoleAvailable(console))throw std::runtime_error("The desktop changed during connection.");
   session->capture.Start(console);EncodedFrame first;if(!session->capture.Latest(first,0,5000))throw std::runtime_error("No interactive desktop frame is available: "+session->capture.Error());session->ready=true;link->Send(Message::Grant,session->token);Log("Authenticated remote control session started.");
   uint64_t previous=0;LARGE_INTEGER frequency{};QueryPerformanceFrequency(&frequency);
   while(!Stopping()&&!session->stop){
    auto packet=link->Receive(5000);if(packet.type!=Message::Inputs||packet.sequence<=previous||packet.data.size()>128*sizeof(Input)||packet.data.size()%sizeof(Input))throw std::runtime_error("Invalid input packet or sequence.");previous=packet.sequence;
    if(revokeSession||WTSGetActiveConsoleSessionId()!=console||!session->capture.Available())throw std::runtime_error("The active console desktop is unavailable or was disconnected.");
    uint64_t begin=NowQpc();size_t count=packet.data.size()/sizeof(Input);
    {std::lock_guard<std::mutex> lock(session->inputMutex);
     if(Stopping()||session->stop)throw std::runtime_error("Remote input stopped before this batch was applied.");
     for(size_t i=0;i<count;++i){Input input{};memcpy(&input,packet.data.data()+i*sizeof(Input),sizeof(input));if(!ValidInput(input))throw std::runtime_error("Invalid keyboard or mouse input.");}
     for(size_t i=0;i<count;++i){if(Stopping()||session->stop)throw std::runtime_error("Remote input stopped while applying this batch.");Input input{};memcpy(&input,packet.data.data()+i*sizeof(Input),sizeof(input));session->input.Apply(input);}
     if(!session->input.Running())throw std::runtime_error(session->input.Error());
    }
    uint64_t ack[3]{session->input.Remaining100ns(),NowQpc()-begin,static_cast<uint64_t>(frequency.QuadPart)};link->Send(Message::Ack,ack,sizeof(ack),packet.sequence);
   }
  }catch(const std::exception& error){session->StopInput();try{link->Send(Message::Error,std::string(error.what()));}catch(...){}Drop(session);Log("Remote session ended: "+std::string(error.what()));throw;}
  Drop(session);
 }
 void VideoLoop(const std::shared_ptr<Link>& link,const Packet& auth,bool relay){
  auto text=Text(auth);if(text.size()!=64)throw std::runtime_error("Video credentials were refused.");
  std::shared_ptr<Session> session;{std::lock_guard<std::mutex> lock(mutex_);session=session_;if(!session||!session->ready||session->stop||!TitanTransport::ConstantTimeEqual(text.substr(0,32),session->credential)||!TitanTransport::ConstantTimeEqual(text.substr(32),session->token)||!session->BindVideo(link))throw std::runtime_error("Video channel is not bound to the active controller.");}
  try{uint64_t sequence=0,lastSend=GetTickCount64();RelayVideoPacing pacing;while(!Stopping()&&!session->stop){
   if(relay){const auto wait=pacing.WaitMilliseconds(GetTickCount64());if(wait){if(WaitForSingleObject(stopEvent,static_cast<DWORD>((std::min)(wait,uint64_t(50))))==WAIT_OBJECT_0)break;continue;}}
   EncodedFrame frame;if(session->capture.Latest(frame,sequence,250)){sequence=frame.sequence;auto bytes=VideoBytes(frame);if(relay)pacing.Sent(bytes.size()+sizeof(WireHeader),GetTickCount64());link->Send(Message::Video,bytes,sequence);lastSend=GetTickCount64();}else if(!session->capture.Available())throw std::runtime_error(session->capture.Error());else if(GetTickCount64()-lastSend>4000){link->Send(Message::KeepAlive,nullptr,0,sequence);lastSend=GetTickCount64();}}}
  catch(...){Drop(session);throw;}
 }
 void Handle(const std::shared_ptr<Link>& link,bool relay=false,const std::string& expected={})noexcept{try{Track(link);link->channel.HandshakeServer(identity_);auto auth=link->Receive(5000);if((expected=="input"&&auth.type!=Message::Auth)||(expected=="video"&&auth.type!=Message::VideoAuth))throw std::runtime_error("Authentication does not match this relay channel.");if(auth.type==Message::Auth)InputLoop(link,auth);else if(auth.type==Message::VideoAuth)VideoLoop(link,auth,relay);else throw std::runtime_error("Authentication is required.");}catch(const std::exception& error){try{link->Send(Message::Error,std::string(error.what()));}catch(...){}link->Close();}catch(...){link->Close();}}
 void RelayLoop(std::string channel){const auto hostKey=!config_.directoryOwner.empty()&&config_.room==PublicRoom(config_.directoryOwner)?config_.directoryOwner:std::string{};while(!Stopping()){try{auto stream=OpenRelay(config_.relay,config_.room,config_.relayToken,"host",channel,[this]{return Stopping();},hostKey);if(Stopping()){stream->Close();return;}auto link=std::make_shared<Link>(std::move(stream));Handle(link,true,channel);}catch(const std::exception&){/* Retry only the relay; never restart/extend the driver demo. */}if(WaitForSingleObject(stopEvent,2000)==WAIT_OBJECT_0)break;}}
 std::string ComputerName(){wchar_t name[256]{};DWORD size=256;return GetComputerNameW(name,&size)?Utf8(name):"Windows PC";}
 bool Busy(){std::lock_guard<std::mutex> lock(mutex_);return bool(session_);}
 void PublishLoop(){
  PublicHost host;host.name=ComputerName();host.room=config_.room;host.pin=identity_.Fingerprint();host.relayToken=config_.relayToken;host.relay=config_.relay;host.requireApproval=config_.requireApproval;
  while(!Stopping()){host.busy=Busy();host.available=ConsoleAvailable(WTSGetActiveConsoleSessionId());try{PublishPublicHost(host,config_.directoryOwner,[this]{return Stopping();});}catch(const std::exception&){}if(WaitForSingleObject(stopEvent,3000)==WAIT_OBJECT_0)break;}
  // Failure to remove is harmless: the public listing has a twelve-second lease.
  try{RemovePublicHost(config_.room,config_.directoryOwner);}catch(const std::exception&){}
 }
public:
 Host():config_(LoadConfig()),identity_(config_.identity){jobs_.reserve(4);relays_.reserve(2);links_.reserve(6);}
 ~Host(){Stop();}
 void Stop()noexcept{stopping_=true;SetEvent(stopEvent);discovery_.Stop();{std::lock_guard<std::mutex> lock(mutex_);if(session_)session_->Close();for(auto& weak:links_)if(auto link=weak.lock())link->Close();}if(listener_!=INVALID_SOCKET){closesocket(listener_);listener_=INVALID_SOCKET;}if(publisher_.joinable())publisher_.join();for(auto& relay:relays_)if(relay.joinable())relay.join();for(auto& job:jobs_)if(job.thread.joinable())job.thread.join();std::lock_guard<std::mutex> lock(mutex_);session_.reset();}
 void Run(){
  listener_=TitanTransport::Listen("0.0.0.0",config_.port);u_long nonblocking=1;ioctlsocket(listener_,FIONBIO,&nonblocking);
  if(config_.internet&&!config_.relay.empty()){relays_.emplace_back([this]{RelayLoop("input");});relays_.emplace_back([this]{RelayLoop("video");});}
  if(config_.noCode){DiscoveryAnnouncement host;host.name=ComputerName();host.room=config_.room;host.pin=identity_.Fingerprint();host.port=config_.port;host.requireApproval=config_.requireApproval;host.available=ConsoleAvailable(WTSGetActiveConsoleSessionId());discovery_.Start(std::move(host));if(config_.internet)publisher_=std::thread([this]{PublishLoop();});}
  SetStatus(SERVICE_RUNNING);
  while(!Stopping()){
   if(config_.noCode)discovery_.Update(Busy(),ConsoleAvailable(WTSGetActiveConsoleSessionId()));
   bool revoked=revokeSession.exchange(false);{std::lock_guard<std::mutex> lock(mutex_);if(session_&&(revoked||!ConsoleAvailable(session_->console)))session_->Close();}
   for(auto it=jobs_.begin();it!=jobs_.end();)if(*it->done){it->thread.join();it=jobs_.erase(it);}else ++it;
   fd_set reads;FD_ZERO(&reads);FD_SET(listener_,&reads);timeval timeout{0,100000};int selected=select(0,&reads,nullptr,nullptr,&timeout);if(selected>0){SOCKET socket=accept(listener_,nullptr,nullptr);if(socket==INVALID_SOCKET)continue;if(jobs_.size()>=4){closesocket(socket);continue;}auto done=std::make_shared<std::atomic<bool>>(false);auto link=std::make_shared<Link>(socket);jobs_.push_back(Job{std::thread([this,link,done]{Handle(link);*done=true;}),done});}
  }
  Stop();
 }
};
DWORD WINAPI Control(DWORD control,DWORD event,LPVOID,LPVOID){if(control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN){SetStatus(SERVICE_STOP_PENDING);SetEvent(stopEvent);}else if(control==SERVICE_CONTROL_SESSIONCHANGE&&(event==WTS_SESSION_LOCK||event==WTS_SESSION_LOGOFF||event==WTS_CONSOLE_DISCONNECT||event==WTS_REMOTE_CONNECT||event==WTS_SESSION_LOGON)){revokeSession=true;}return NO_ERROR;}
void WINAPI ServiceMain(DWORD,LPWSTR*){serviceHandle=RegisterServiceCtrlHandlerExW(ServiceName,Control,nullptr);if(!serviceHandle)return;SetStatus(SERVICE_START_PENDING);stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);DWORD error=0;try{Host host;host.Run();}catch(const std::exception& e){Log(e.what(),EVENTLOG_ERROR_TYPE);error=ERROR_SERVICE_SPECIFIC_ERROR;}if(stopEvent)CloseHandle(stopEvent);stopEvent=nullptr;SetStatus(SERVICE_STOPPED,error);}
}
bool ConsoleAvailable(uint32_t sessionId)noexcept{
 if(sessionId==0xffffffff||WTSGetActiveConsoleSessionId()!=sessionId)return false;
 LPWSTR buffer=nullptr;DWORD size=0;bool available=false;
 if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,sessionId,WTSSessionInfoEx,&buffer,&size)){
  auto info=reinterpret_cast<WTSINFOEXW*>(buffer);if(size>=sizeof(WTSINFOEXW)&&info->Level==1)available=info->Data.WTSInfoExLevel1.SessionState==WTSActive&&info->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_UNLOCK;WTSFreeMemory(buffer);
 }return available;
}
int RunService(){SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(ServiceName),ServiceMain},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());}
int RunHostConsole(){stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);SetConsoleCtrlHandler([](DWORD)->BOOL{SetEvent(stopEvent);return TRUE;},TRUE);try{Host host;host.Run();CloseHandle(stopEvent);return 0;}catch(const std::exception& e){Log(e.what(),EVENTLOG_ERROR_TYPE);CloseHandle(stopEvent);return 1;}}
}
