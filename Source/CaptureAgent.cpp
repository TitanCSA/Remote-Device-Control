#include "CaptureAgent.h"
#include "Config.h"
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace RemoteControl {
namespace {
constexpr wchar_t PipePrefix[]=L"\\\\.\\pipe\\RemoteDeviceControl-Capture-";
constexpr uint32_t PipeMagic=0x32414952,PipeVersion=2;
enum:uint32_t {ReadyPacket=1,UnavailablePacket=2,HeartbeatPacket=3,DisconnectPacket=4};
struct Header {
    uint32_t magic=PipeMagic,version=PipeVersion,type=0,bytes=0,width=0,height=0,reserved0=0,reserved1=0;
    uint64_t sequence=0,capturedQpc=0;
};
static_assert(sizeof(Header)==48);
struct Handle {
    HANDLE value=nullptr;
    explicit Handle(HANDLE handle=nullptr):value(handle){}
    ~Handle(){Reset();}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    void Reset(HANDLE handle=nullptr)noexcept{if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=handle;}
};
struct ServiceHandle {
    SC_HANDLE value=nullptr;
    explicit ServiceHandle(SC_HANDLE handle):value(handle){}
    ~ServiceHandle(){if(value)CloseServiceHandle(value);}
    ServiceHandle(const ServiceHandle&)=delete;ServiceHandle& operator=(const ServiceHandle&)=delete;
};
class PipeClosed final:public std::runtime_error {public:PipeClosed():std::runtime_error("The local capture helper pipe disconnected."){} };
bool Disconnected(DWORD code){return code==ERROR_BROKEN_PIPE||code==ERROR_NO_DATA||code==ERROR_PIPE_NOT_CONNECTED;}
[[noreturn]] void Fail(const char* operation,DWORD error=GetLastError()){
    throw std::runtime_error(std::string(operation)+" failed (Windows error "+std::to_string(error)+").");
}
void Require(bool condition,const char* operation){if(!condition)Fail(operation);}
bool ValidPipeName(const std::wstring& name){
    const std::wstring prefix=PipePrefix;if(name.size()!=prefix.size()+32||name.compare(0,prefix.size(),prefix)!=0)return false;
    for(size_t i=prefix.size();i<name.size();++i)if(!((name[i]>=L'0'&&name[i]<=L'9')||(name[i]>=L'a'&&name[i]<=L'f')))return false;
    return true;
}
std::wstring PipeName(){
    std::array<unsigned char,16> random{};const NTSTATUS status=BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status<0)throw std::runtime_error("Capture pipe randomness failed.");
    constexpr wchar_t alphabet[]=L"0123456789abcdef";std::wstring name=PipePrefix;
    for(auto byte:random){name.push_back(alphabet[byte>>4]);name.push_back(alphabet[byte&15]);}return name;
}
std::wstring Executable(){
    std::wstring path(32768,L'\0');const DWORD length=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!length||length>=path.size())Fail("Protected host executable path lookup");path.resize(length);return path;
}
std::wstring CanonicalPrefix(std::wstring path){if(path.compare(0,4,L"\\\\?\\")==0)path.erase(0,4);return path;}
void VerifyServer(HANDLE pipe){
    ULONG processId=0;Require(GetNamedPipeServerProcessId(pipe,&processId)!=FALSE,"Capture service PID lookup");
    ULONG sessionId=0;Require(GetNamedPipeServerSessionId(pipe,&sessionId)!=FALSE,"Capture service session lookup");
    if(sessionId!=0)throw std::runtime_error("The capture pipe does not belong to a Session 0 service.");
    // A normal console user cannot query a LocalSystem process image. Bind the
    // pipe's actual server PID to the protected SCM registration instead; this
    // requires no new access rights on the service process or its token.
    ServiceHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));Require(manager.value!=nullptr,"Capture service manager query");
    ServiceHandle service(OpenServiceW(manager.value,ServiceName,SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG));Require(service.value!=nullptr,"Capture service registration query");
    SERVICE_STATUS_PROCESS status{};DWORD needed=0;
    Require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)!=FALSE,"Capture service process verification");
    if(status.dwServiceType!=SERVICE_WIN32_OWN_PROCESS||status.dwCurrentState!=SERVICE_RUNNING||status.dwProcessId!=processId)throw std::runtime_error("The capture pipe does not belong to the running Remote Device Control service.");
    QueryServiceConfigW(service.value,nullptr,0,&needed);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||needed<sizeof(QUERY_SERVICE_CONFIGW)||needed>65536)throw std::runtime_error("The capture service image configuration is unavailable or invalid.");
    std::vector<uint8_t> bytes(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    Require(QueryServiceConfigW(service.value,config,needed,&needed)!=FALSE,"Capture service image configuration query");
    const auto own=CanonicalPrefix(Executable());const std::wstring expected=L"\""+own+L"\" --service";
    if(!config->lpBinaryPathName||_wcsicmp(config->lpBinaryPathName,expected.c_str())!=0||config->dwServiceType!=SERVICE_WIN32_OWN_PROCESS)throw std::runtime_error("The capture service registration belongs to a different executable.");
}
struct Operation {
    OVERLAPPED value{};Handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    Operation(){Require(event.value!=nullptr,"Capture I/O event creation");value.hEvent=event.value;}
};
void DrainCancelled(HANDLE pipe,OVERLAPPED& operation)noexcept{
    CancelIoEx(pipe,&operation);DWORD transferred=0;GetOverlappedResult(pipe,&operation,&transferred,TRUE);
}
DWORD Complete(HANDLE pipe,HANDLE stop,Operation& operation,ULONGLONG deadline){
    const ULONGLONG now=GetTickCount64();
    if(now>=deadline){DrainCancelled(pipe,operation.value);throw std::runtime_error("Capture helper I/O deadline exceeded.");}
    const HANDLE events[]{stop,operation.event.value};const DWORD wait=WaitForMultipleObjects(2,events,FALSE,static_cast<DWORD>(deadline-now));
    if(wait!=WAIT_OBJECT_0+1){DrainCancelled(pipe,operation.value);if(wait==WAIT_OBJECT_0)throw std::runtime_error("Capture helper stopped.");if(wait==WAIT_TIMEOUT)throw std::runtime_error("Capture helper heartbeat or I/O timed out.");Fail("Capture helper I/O wait");}
    DWORD transferred=0;if(!GetOverlappedResult(pipe,&operation.value,&transferred,FALSE)){const DWORD error=GetLastError();if(Disconnected(error))throw PipeClosed();Fail("Capture helper transfer",error);}return transferred;
}
void Transfer(HANDLE pipe,HANDLE stop,void* bytes,uint32_t length,bool writing,ULONGLONG deadline){
    auto data=static_cast<uint8_t*>(bytes);
    while(length){
        if(WaitForSingleObject(stop,0)==WAIT_OBJECT_0)throw std::runtime_error("Capture helper stopped.");
        Operation operation;DWORD transferred=0;
        const BOOL immediate=writing?WriteFile(pipe,data,length,&transferred,&operation.value):ReadFile(pipe,data,length,&transferred,&operation.value);
        if(!immediate){const DWORD error=GetLastError();if(Disconnected(error))throw PipeClosed();if(error!=ERROR_IO_PENDING)Fail(writing?"Capture helper write":"Capture helper read",error);transferred=Complete(pipe,stop,operation,deadline);}
        else Require(GetOverlappedResult(pipe,&operation.value,&transferred,FALSE)!=FALSE,"Immediate capture transfer");
        if(!transferred||transferred>length)throw std::runtime_error("Capture helper pipe closed or returned an invalid byte count.");
        data+=transferred;length-=transferred;
    }
}
void Read(HANDLE pipe,HANDLE stop,void* bytes,uint32_t length,ULONGLONG deadline){Transfer(pipe,stop,bytes,length,false,deadline);}
void Send(HANDLE pipe,HANDLE stop,const Header& header,const void* bytes=nullptr){
    const ULONGLONG deadline=GetTickCount64()+5000;
    Transfer(pipe,stop,const_cast<Header*>(&header),sizeof(header),true,deadline);
    if(header.bytes)Transfer(pipe,stop,const_cast<void*>(bytes),header.bytes,true,deadline);
}
std::string SafeError(std::string error){
    if(error.empty())error="The desktop is unavailable.";if(error.size()>512)error.resize(512);
    for(char& value:error){const unsigned char byte=static_cast<unsigned char>(value);if(byte<32||byte>126)value=' ';}return error;
}
struct Session {
    Handle pipe,process,job,stop{CreateEventW(nullptr,TRUE,FALSE,nullptr)},done{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    std::atomic<bool> available{false},stopping{false},ended{false},observedStatus{false};std::mutex mutex;std::condition_variable changed;
    std::string error="Waiting for the active desktop capture helper.";
    Session(){Require(stop.value&&done.value,"Capture session event creation");}
    void Note(std::string text,bool ready=false){
        {std::lock_guard<std::mutex> lock(mutex);error=std::move(text);available=ready;observedStatus=true;}changed.notify_all();
    }
    void Failed(std::string text){
        {std::lock_guard<std::mutex> lock(mutex);if(available||error.empty()||error=="Waiting for the active desktop capture helper.")error=std::move(text);available=false;observedStatus=true;}changed.notify_all();
    }
    void Run()noexcept{
        try{
            while(!stopping){
                const ULONGLONG deadline=GetTickCount64()+5000;Header header;Read(pipe.value,stop.value,&header,sizeof(header),deadline);
                if(header.magic!=PipeMagic||header.version!=PipeVersion||header.reserved0||header.reserved1)throw std::runtime_error("Capture helper packet header is invalid.");
                {
                    if(header.width||header.height||header.sequence||header.capturedQpc)throw std::runtime_error("Capture helper status contains frame fields.");
                    if(header.type==UnavailablePacket){
                        if(!header.bytes||header.bytes>512)throw std::runtime_error("Capture helper status exceeds its bounds.");
                        std::string text(header.bytes,'\0');Read(pipe.value,stop.value,text.data(),header.bytes,deadline);Note(SafeError(std::move(text)));
                    }else if(header.type==ReadyPacket){if(header.bytes)throw std::runtime_error("Indicator readiness has an unexpected body.");Note("",true);}
                    else if(header.type==HeartbeatPacket){if(header.bytes)throw std::runtime_error("Indicator heartbeat has an unexpected body.");}
                    else if(header.type==DisconnectPacket){if(header.bytes)throw std::runtime_error("Capture disconnect has an unexpected body.");throw std::runtime_error("The local user disconnected the remote-control session.");}
                    else throw std::runtime_error("Unknown capture helper message.");
                }
            }
        }catch(const std::exception& failure){if(!stopping)Failed(failure.what());}
        catch(...){if(!stopping)Failed("Capture helper stopped due to a local resource error.");}
        available=false;ended=true;changed.notify_all();SetEvent(done.value);
    }
};
void Launch(Session& session,uint32_t sessionId,const std::wstring& name){
    if(!sessionId||sessionId!=WTSGetActiveConsoleSessionId())throw std::runtime_error("Remote capture requires the active logged-in console session.");
    Handle token;Require(WTSQueryUserToken(sessionId,&token.value)!=FALSE,"Active console user token lookup");
    DWORD needed=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&needed);
    if(!needed||needed>65536)throw std::runtime_error("Capture user SID length is invalid.");
    std::vector<uint8_t> tokenBytes(needed);Require(GetTokenInformation(token.value,TokenUser,tokenBytes.data(),needed,&needed)!=FALSE,"Capture user SID lookup");
    LPWSTR sid=nullptr;Require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(tokenBytes.data())->User.Sid,&sid)!=FALSE,"Capture SID conversion");
    const std::wstring sidText=sid;LocalFree(sid);
    const std::wstring acl=L"D:P(A;;GA;;;SY)(A;;GRGW;;;"+sidText+L")";PSECURITY_DESCRIPTOR descriptor=nullptr;
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"Capture pipe ACL construction");
    SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
    const HANDLE pipe=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_INBOUND|FILE_FLAG_FIRST_PIPE_INSTANCE|FILE_FLAG_OVERLAPPED,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,0,65536,5000,&security);
    const DWORD pipeError=GetLastError();LocalFree(descriptor);if(pipe==INVALID_HANDLE_VALUE)Fail("Private capture pipe creation",pipeError);session.pipe.Reset(pipe);
    Operation connect;const BOOL immediate=ConnectNamedPipe(pipe,&connect.value);const DWORD connectError=immediate?ERROR_SUCCESS:GetLastError();
    if(!immediate&&connectError!=ERROR_IO_PENDING&&connectError!=ERROR_PIPE_CONNECTED)Fail("Capture pipe connection initialization",connectError);
    struct PendingConnection{HANDLE pipe;OVERLAPPED* operation;bool pending;~PendingConnection(){if(pending)DrainCancelled(pipe,*operation);}} pending{pipe,&connect.value,!immediate&&connectError==ERROR_IO_PENDING};
    session.job.Reset(CreateJobObjectW(nullptr,nullptr));Require(session.job.value!=nullptr,"Capture helper job creation");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Require(SetInformationJobObject(session.job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE,"Capture helper lifetime policy");
    const auto executable=Executable();std::wstring command=L"\""+executable+L"\" --agent \""+name+L"\"";
    const size_t slash=executable.find_last_of(L"\\/");const auto directory=slash==std::wstring::npos?std::wstring{}:executable.substr(0,slash);
    LPVOID environment=nullptr;Require(CreateEnvironmentBlock(&environment,token.value,FALSE)!=FALSE,"Capture user environment creation");
    struct Environment{LPVOID value;~Environment(){DestroyEnvironmentBlock(value);}} ownedEnvironment{environment};
    STARTUPINFOW startup{};startup.cb=sizeof(startup);wchar_t desktop[]=L"winsta0\\default";startup.lpDesktop=desktop;PROCESS_INFORMATION process{};
    Require(CreateProcessAsUserW(token.value,executable.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_UNICODE_ENVIRONMENT|CREATE_SUSPENDED,environment,directory.empty()?nullptr:directory.c_str(),&startup,&process)!=FALSE,"Interactive capture helper launch");
    session.process.Reset(process.hProcess);Handle thread(process.hThread);
    if(!AssignProcessToJobObject(session.job.value,process.hProcess)){const DWORD error=GetLastError();TerminateProcess(process.hProcess,ERROR_PROCESS_ABORTED);Fail("Capture helper job assignment",error);}
    Require(ResumeThread(thread.value)!=static_cast<DWORD>(-1),"Capture helper thread start");
    if(connectError==ERROR_PIPE_CONNECTED)SetEvent(connect.event.value);
    if(!immediate){
        const HANDLE events[]{connect.event.value,process.hProcess};const DWORD wait=WaitForMultipleObjects(2,events,FALSE,5000);
        if(wait!=WAIT_OBJECT_0){if(wait==WAIT_TIMEOUT)throw std::runtime_error("The interactive capture helper did not attach within five seconds.");throw std::runtime_error("The interactive capture helper exited before it attached.");}
        if(pending.pending){DWORD transferred=0;Require(GetOverlappedResult(pipe,&connect.value,&transferred,FALSE)!=FALSE,"Capture helper attachment");pending.pending=false;}
    }
    ULONG client=0,clientSession=0;Require(GetNamedPipeClientProcessId(pipe,&client)!=FALSE,"Capture helper client PID lookup");Require(GetNamedPipeClientSessionId(pipe,&clientSession)!=FALSE,"Capture helper client session lookup");
    if(client!=process.dwProcessId||clientSession!=sessionId)throw std::runtime_error("A different process attempted to attach to the capture pipe.");
}

constexpr UINT TrayEvent=WM_APP+41;constexpr wchar_t AgentClass[]=L"RemoteDeviceControlCaptureStatus";
struct AgentState {
    Handle pipe,stop{CreateEventW(nullptr,TRUE,FALSE,nullptr)};std::thread worker;HWND window=nullptr;UINT taskbarCreated=0;NOTIFYICONDATAW icon{};
    std::atomic<bool> failed{false};std::mutex pipeMutex;
    explicit AgentState(HANDLE handle):pipe(handle){Require(stop.value!=nullptr,"Capture agent stop event");}
    ~AgentState(){End();if(worker.joinable())worker.join();if(window&&IsWindow(window))DestroyWindow(window);}
    bool ShowIcon(bool balloon){
        icon={};icon.cbSize=sizeof(icon);icon.hWnd=window;icon.uID=1;icon.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;icon.uCallbackMessage=TrayEvent;icon.hIcon=LoadIconW(nullptr,IDI_APPLICATION);
        wcscpy_s(icon.szTip,L"Remote Device Control - host available");
        if(balloon){icon.uFlags|=NIF_INFO;wcscpy_s(icon.szInfoTitle,L"Remote control available");wcscpy_s(icon.szInfo,L"This PC accepts remote-control connections under your chosen access policy. Click this icon to disconnect or pause access.");icon.dwInfoFlags=NIIF_INFO;}
        return Shell_NotifyIconW(NIM_ADD,&icon)!=FALSE;
    }
    void End()noexcept{if(stop.value)SetEvent(stop.value);std::lock_guard<std::mutex> lock(pipeMutex);if(pipe.value)CancelIoEx(pipe.value,nullptr);}
    void ClosePipe()noexcept{std::lock_guard<std::mutex> lock(pipeMutex);pipe.Reset();}
    void Run()noexcept{
        try{
            Header ready;ready.type=ReadyPacket;Send(pipe.value,stop.value,ready);
            while(WaitForSingleObject(stop.value,1000)==WAIT_TIMEOUT){
                Header heartbeat;heartbeat.type=HeartbeatPacket;Send(pipe.value,stop.value,heartbeat);
            }
        }catch(const PipeClosed&){/* The service ended the authorized session. */}
        catch(const std::exception& failure){
            if(WaitForSingleObject(stop.value,0)!=WAIT_OBJECT_0){
                failed=true;
                try{const auto text=SafeError(failure.what());Header header;header.type=UnavailablePacket;header.bytes=static_cast<uint32_t>(text.size());Send(pipe.value,stop.value,header,text.data());}catch(...){}
            }
        }catch(...){
            if(WaitForSingleObject(stop.value,0)!=WAIT_OBJECT_0){
                failed=true;
                try{const std::string text="The desktop capture worker failed due to a local resource error.";Header header;header.type=UnavailablePacket;header.bytes=static_cast<uint32_t>(text.size());Send(pipe.value,stop.value,header,text.data());}catch(...){}
            }
        }
        ClosePipe();PostMessageW(window,WM_CLOSE,0,0);
    }
};
LRESULT CALLBACK AgentWindow(HWND window,UINT message,WPARAM wParam,LPARAM lParam){
    AgentState* state=reinterpret_cast<AgentState*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){state=static_cast<AgentState*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(state));state->window=window;}
    if(!state)return DefWindowProcW(window,message,wParam,lParam);
    if(message==state->taskbarCreated&&state->taskbarCreated){if(!state->ShowIcon(false)){state->End();PostMessageW(window,WM_CLOSE,0,0);}return 0;}
    switch(message){
    case TrayEvent:
        if(lParam==WM_LBUTTONUP||lParam==WM_RBUTTONUP||lParam==NIN_KEYSELECT){
            HMENU menu=CreatePopupMenu();if(menu){AppendMenuW(menu,MF_STRING|MF_DISABLED,0,L"Remote control available");AppendMenuW(menu,MF_SEPARATOR,0,nullptr);AppendMenuW(menu,MF_STRING,1,L"Disconnect and pause access for 30 seconds");POINT point{};GetCursorPos(&point);SetForegroundWindow(window);const UINT chosen=TrackPopupMenu(menu,TPM_RETURNCMD|TPM_RIGHTBUTTON,point.x,point.y,0,window,nullptr);DestroyMenu(menu);if(chosen==1){state->End();PostMessageW(window,WM_CLOSE,0,0);}}}return 0;
    case WM_QUERYENDSESSION:return TRUE;
    case WM_ENDSESSION:if(wParam){state->End();PostMessageW(window,WM_CLOSE,0,0);}return 0;
    case WM_CLOSE:state->End();DestroyWindow(window);return 0;
    case WM_DESTROY:Shell_NotifyIconW(NIM_DELETE,&state->icon);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(window,message,wParam,lParam);
}
}

struct SessionIndicator::State {
    std::mutex lifecycle,lastMutex;std::shared_ptr<Session> current;std::thread reader;std::string lastError="Capture is not running.";
    void StopLocked()noexcept{
        auto session=std::atomic_load(&current);if(!session)return;
        session->stopping=true;session->available=false;session->changed.notify_all();SetEvent(session->stop.value);
        if(session->pipe.value)CancelIoEx(session->pipe.value,nullptr);
        bool done=!reader.joinable()||WaitForSingleObject(session->done.value,2000)==WAIT_OBJECT_0;
        if(!done&&session->process.value){TerminateProcess(session->process.value,ERROR_PROCESS_ABORTED);done=WaitForSingleObject(session->done.value,500)==WAIT_OBJECT_0;}
        if(reader.joinable()){if(done)reader.join();else reader.detach();}
        if(done)session->pipe.Reset();
        if(session->process.value&&WaitForSingleObject(session->process.value,1500)==WAIT_TIMEOUT){TerminateProcess(session->process.value,ERROR_PROCESS_ABORTED);WaitForSingleObject(session->process.value,500);}
        {std::lock_guard<std::mutex> lock(lastMutex);std::lock_guard<std::mutex> sessionLock(session->mutex);lastError=session->error.empty()?"Capture session stopped.":session->error;}
        std::atomic_store(&current,std::shared_ptr<Session>{});
    }
};
SessionIndicator::SessionIndicator():state_(std::make_unique<State>()){}
SessionIndicator::~SessionIndicator(){Stop();}
void SessionIndicator::Start(uint32_t sessionId){
    std::lock_guard<std::mutex> lock(state_->lifecycle);state_->StopLocked();auto session=std::make_shared<Session>();std::atomic_store(&state_->current,session);
    try{Launch(*session,sessionId,PipeName());state_->reader=std::thread([session]{session->Run();});}
    catch(const std::exception& failure){session->Note(failure.what());state_->StopLocked();throw;}
    catch(...){session->Note("Capture helper could not start due to a local resource error.");state_->StopLocked();throw;}
}
void SessionIndicator::Stop()noexcept{try{std::lock_guard<std::mutex> lock(state_->lifecycle);state_->StopLocked();}catch(...){}}
bool SessionIndicator::WaitReady(uint32_t timeoutMs){
    auto session=std::atomic_load(&state_->current);if(!session)return false;
    std::unique_lock<std::mutex> lock(session->mutex);
    session->changed.wait_for(lock,std::chrono::milliseconds(timeoutMs),[&]{return session->observedStatus||session->ended||session->stopping;});
    return session->available&&!session->stopping&&!session->ended;
}
bool SessionIndicator::Available()const noexcept{auto session=std::atomic_load(&state_->current);return session&&session->available&&!session->stopping&&!session->ended;}
std::string SessionIndicator::Error()const{
    auto session=std::atomic_load(&state_->current);if(session){std::lock_guard<std::mutex> lock(session->mutex);return session->error;}
    std::lock_guard<std::mutex> lock(state_->lastMutex);return state_->lastError;
}
int RunCaptureAgent(const std::wstring& pipeName){
    try{
        if(!ValidPipeName(pipeName))throw std::runtime_error("Invalid local capture pipe name.");
        if(!WaitNamedPipeW(pipeName.c_str(),5000))Fail("Capture service pipe wait");
        const HANDLE pipe=CreateFileW(pipeName.c_str(),GENERIC_WRITE|FILE_READ_ATTRIBUTES,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
        if(pipe==INVALID_HANDLE_VALUE)Fail("Capture service pipe opening");AgentState state(pipe);
        try{
        VerifyServer(pipe);
        const HINSTANCE instance=GetModuleHandleW(nullptr);WNDCLASSW windowClass{};windowClass.hInstance=instance;windowClass.lpszClassName=AgentClass;windowClass.lpfnWndProc=AgentWindow;
        const ATOM registered=RegisterClassW(&windowClass);if(!registered&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)Fail("Capture status window registration");
        state.taskbarCreated=RegisterWindowMessageW(L"TaskbarCreated");
        const HWND window=CreateWindowExW(WS_EX_TOOLWINDOW,AgentClass,L"Remote Device Control - active sharing",WS_OVERLAPPED,0,0,0,0,nullptr,nullptr,instance,&state);
        Require(window!=nullptr,"Capture status window creation");
        if(!state.ShowIcon(true)){DestroyWindow(window);throw std::runtime_error("The visible remote-control tray indicator could not be created.");}
        try{state.worker=std::thread([&state]{state.Run();});}
        catch(...){DestroyWindow(window);throw;}
        MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
        state.End();if(state.worker.joinable())state.worker.join();if(IsWindow(window))DestroyWindow(window);return state.failed?1:0;
        }catch(const std::exception& failure){
            if(!state.worker.joinable()&&state.pipe.value){try{const auto text=SafeError(failure.what());Header header;header.type=UnavailablePacket;header.bytes=static_cast<uint32_t>(text.size());Send(state.pipe.value,state.stop.value,header,text.data());}catch(...){}}
            state.End();if(state.worker.joinable())state.worker.join();if(state.window&&IsWindow(state.window))DestroyWindow(state.window);throw;
        }
    }catch(...){return 1;}
}
}
