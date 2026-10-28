#include "Client.h"
#include "Wire.h"
#include "RelayStream.h"
#include "FrameCodec.h"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <array>
#include <chrono>
namespace RemoteControl {
namespace {
bool RetryableRelayBootstrap(const std::runtime_error& error){
 const std::string_view text=error.what();
 if(text.find("Relay connection refused (HTTP 403)")==0||text.find("Relay connection refused (HTTP 503)")==0)return true;
 if(text.find("Relay ")!=0)return false;
 for(const auto* code:{" (Windows error 12002)."," (Windows error 12007)."," (Windows error 12029)."," (Windows error 12030)."," (Windows error 12032)."," (Windows error 12152)."," (Windows error 1460)."})if(text.find(code)!=text.npos)return true;
 return false;
}
}
struct Client::State {
 TitanTransport::Runtime runtime;std::function<void()> changed;mutable std::mutex mutex;std::condition_variable wake;ClientInfo info;
 std::shared_ptr<const Frame> latest;std::shared_ptr<Link> input,video;std::thread supervisor,sender,ackReader;std::deque<Input> queue;
 std::atomic<bool> stop{false};std::array<uint64_t,1024> sentTimes{},sentIds{};uint64_t sequence=0;
 explicit State(std::function<void()> callback):changed(std::move(callback)){}
 void Notify(){if(changed)changed();}
 void Close()noexcept{stop=true;wake.notify_all();std::lock_guard<std::mutex> lock(mutex);if(input)input->Close();if(video)video->Close();}
 void Stop()noexcept{Close();if(supervisor.joinable())supervisor.join();if(sender.joinable())sender.join();if(ackReader.joinable())ackReader.join();std::lock_guard<std::mutex> lock(mutex);queue.clear();input.reset();video.reset();info.connected=false;}
 std::shared_ptr<Link> Open(const Pairing& p,bool relay,const char* channel){
  std::shared_ptr<Link> link;
  if(relay){
   if(p.relay.empty())throw std::runtime_error("Internet relay was not enabled on the host.");
   const unsigned attempts=std::string_view(channel)=="input"?3u:1u;
   for(unsigned attempt=0;attempt<attempts;++attempt){
    if(stop)throw std::runtime_error("Connection cancelled.");
    try{link=std::make_shared<Link>(OpenRelay(p.relay,p.room,p.relayToken,"viewer",channel,[this]{return stop.load();}));break;}
    catch(const std::runtime_error& error){
     if(stop||attempt+1==attempts||!RetryableRelayBootstrap(error))throw;
     std::unique_lock<std::mutex> lock(mutex);
     if(wake.wait_for(lock,std::chrono::seconds(1),[this]{return stop.load();}))throw std::runtime_error("Connection cancelled.");
    }
   }
  }
  else link=std::make_shared<Link>(TitanTransport::Connect(p.host,p.port));
  {std::lock_guard<std::mutex> lock(mutex);if(std::string(channel)=="input")input=link;else video=link;}
  if(stop){link->Close();throw std::runtime_error("Connection cancelled.");}link->channel.HandshakeClient(p.pin);return link;
 }
 void Sender(){try{while(!stop){std::vector<Input> batch;uint64_t id=0;
   {std::unique_lock<std::mutex> lock(mutex);wake.wait_for(lock,std::chrono::seconds(1),[this]{return stop||!queue.empty();});if(stop)break;size_t count=(std::min)(queue.size(),size_t(128));batch.reserve(count);for(size_t i=0;i<count;++i){batch.push_back(queue.front());queue.pop_front();}id=++sequence;sentIds[id%sentIds.size()]=id;sentTimes[id%sentTimes.size()]=NowQpc();}
   input->Send(Message::Inputs,batch.data(),batch.size()*sizeof(Input),id);
  }}catch(const std::exception& e){if(!stop){std::lock_guard<std::mutex> lock(mutex);info.status=e.what();}Close();Notify();}}
 void Acks(){try{LARGE_INTEGER frequency{};QueryPerformanceFrequency(&frequency);uint64_t previous=0;while(!stop){auto packet=input->Receive(5000);ThrowIfError(packet);if(packet.type!=Message::Ack||packet.data.size()!=24)throw std::runtime_error("Invalid input acknowledgement.");uint64_t values[3]{};memcpy(values,packet.data.data(),sizeof(values));
   {std::lock_guard<std::mutex> lock(mutex);if(!packet.sequence||packet.sequence<=previous||packet.sequence>sequence)throw std::runtime_error("Invalid acknowledgement sequence.");previous=packet.sequence;auto stamp=sentTimes[packet.sequence%sentTimes.size()];if(stamp&&sentIds[packet.sequence%sentIds.size()]==packet.sequence)info.inputRttMs=double(NowQpc()-stamp)*1000.0/double(frequency.QuadPart);info.remaining100ns=values[0];}Notify();
  }}catch(const std::exception& e){if(!stop){std::lock_guard<std::mutex> lock(mutex);info.status=e.what();}Close();Notify();}}
 void Run(Pairing p,unsigned mode){try{
  bool relay=mode==2;std::shared_ptr<Link> auth;
  if(mode==0){try{auth=Open(p,false,"input");}catch(...){if(stop)throw;relay=true;}}
  if(!auth)auth=Open(p,relay,"input");auth->Send(Message::Auth,p.secret);auto grant=auth->Receive(30000);ThrowIfError(grant);if(grant.type!=Message::Grant||!TitanTransport::IsSecret(Text(grant)))throw std::runtime_error("Invalid authenticated session grant.");
  auto images=Open(p,relay,"video");images->Send(Message::VideoAuth,p.secret+Text(grant));
  {std::lock_guard<std::mutex> lock(mutex);info.connected=true;info.route=relay?"Internet relay / end-to-end TLS":"Direct LAN / pinned TLS";info.status="Connected. Click the desktop to send keyboard and mouse.";}Notify();
  sender=std::thread([this]{Sender();});ackReader=std::thread([this]{Acks();});FrameCodec codec;uint64_t previous=0,window=GetTickCount64(),frames=0;
  while(!stop){auto packet=images->Receive(15000);ThrowIfError(packet);if(packet.type==Message::KeepAlive&&packet.data.empty())continue;auto meta=VideoInfo(packet);if(meta.sequence<=previous)throw std::runtime_error("Video sequence is not increasing.");previous=meta.sequence;
   std::vector<uint8_t> jpeg(packet.data.begin()+sizeof(VideoMetadata),packet.data.end());auto decoded=std::make_shared<Frame>(codec.Decode(jpeg));if(decoded->width!=meta.width||decoded->height!=meta.height)throw std::runtime_error("Video dimensions do not match the authenticated frame.");decoded->sequence=meta.sequence;decoded->capturedQpc=meta.capturedQpc;
   {std::lock_guard<std::mutex> lock(mutex);latest=std::move(decoded);++frames;uint64_t now=GetTickCount64();if(now-window>=1000){info.framesPerSecond=double(frames)*1000.0/double(now-window);frames=0;window=now;}}Notify();
  }
 }catch(const std::exception& e){if(!stop){std::lock_guard<std::mutex> lock(mutex);info.status=e.what();}}
 Close();{std::lock_guard<std::mutex> lock(mutex);info.connected=false;}Notify();}
};
Client::Client(std::function<void()> changed):state_(std::make_unique<State>(std::move(changed))){}
Client::~Client(){Stop();}
void Client::Start(Pairing pairing,unsigned mode){
 wchar_t localRoom[64]{};DWORD size=sizeof(localRoom);if(RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl",L"HostRoom",RRF_RT_REG_SZ|RRF_SUBKEY_WOW6464KEY,nullptr,localRoom,&size)==ERROR_SUCCESS&&TitanTransport::ConstantTimeEqual(Utf8(localRoom),pairing.room))throw std::runtime_error("Connecting this viewer to its own installed host is refused to prevent keyboard/mouse feedback.");
 Stop();state_->stop=false;{std::lock_guard<std::mutex> lock(state_->mutex);state_->info.status="Connecting and preparing the signed-in desktop…";state_->latest.reset();state_->sentTimes.fill(0);}state_->Notify();state_->supervisor=std::thread([s=state_.get(),pairing=std::move(pairing),mode]()mutable{s->Run(std::move(pairing),mode);});}
void Client::Stop()noexcept{state_->Stop();}
void Client::Push(Input input){if(!ValidInput(input))return;{std::lock_guard<std::mutex> lock(state_->mutex);if(!state_->info.connected||state_->stop)return;
 if(input.kind==InputKind::Pointer&&!state_->queue.empty()&&state_->queue.back().kind==InputKind::Pointer)state_->queue.back()=input;
 else if(state_->queue.size()<256)state_->queue.push_back(input);else{state_->info.status="Input backlog exceeded the safe limit; disconnecting to release held inputs.";state_->stop=true;if(state_->input)state_->input->Close();if(state_->video)state_->video->Close();}}
 state_->wake.notify_one();}
ClientInfo Client::Info()const{std::lock_guard<std::mutex> lock(state_->mutex);return state_->info;}
std::shared_ptr<const Frame> Client::Latest()const{std::lock_guard<std::mutex> lock(state_->mutex);return state_->latest;}
}
