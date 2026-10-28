#include "Host.h"
#include "Config.h"
#include "Protocol.h"
#include "Transport.h"
#include "CaptureAgent.h"
#include "Discovery.h"
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>
#include <stdexcept>

namespace RemoteControl {
namespace {
SERVICE_STATUS_HANDLE serviceHandle=nullptr;SERVICE_STATUS serviceStatus{};HANDLE stopEvent=nullptr;
std::atomic<bool> revokeSession{false};
void Require(bool ok,const char* op){if(!ok)throw std::runtime_error(WindowsError(op,GetLastError()));}
struct Handle{HANDLE value=nullptr;~Handle(){Reset();}void Reset(HANDLE h=nullptr)noexcept{if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=h;}Handle()=default;Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;};
void Log(const std::string& message,WORD type=EVENTLOG_INFORMATION_TYPE){HANDLE source=RegisterEventSourceW(nullptr,ServiceName);if(source){auto value=Wide(message);LPCWSTR texts[]={value.c_str()};ReportEventW(source,type,0,1,nullptr,1,0,texts,nullptr);DeregisterEventSource(source);}}
void SetStatus(DWORD state,DWORD code=0){if(!serviceHandle)return;serviceStatus.dwServiceType=SERVICE_WIN32_OWN_PROCESS;serviceStatus.dwCurrentState=state;serviceStatus.dwWin32ExitCode=code;serviceStatus.dwControlsAccepted=state==SERVICE_RUNNING?(SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_SESSIONCHANGE):0;serviceStatus.dwWaitHint=state==SERVICE_STOP_PENDING?30000:0;SetServiceStatus(serviceHandle,&serviceStatus);}
std::wstring Join(const std::wstring& root,const wchar_t* name){return root+L"\\"+name;}
void WriteProtected(const std::wstring& path,const std::string& text){
    if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)CheckPlain(path);
    Handle file;file.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);Require(file.value!=INVALID_HANDLE_VALUE,"Write protected engine configuration");
    BY_HANDLE_FILE_INFORMATION info{};Require(GetFileInformationByHandle(file.value,&info)!=FALSE,"Inspect engine configuration handle");if(info.nNumberOfLinks!=1||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Linked engine configuration is refused.");
    DWORD written=0;Require(WriteFile(file.value,text.data(),static_cast<DWORD>(text.size()),&written,nullptr)!=FALSE&&written==text.size(),"Save engine configuration");
}
std::string PathText(const std::wstring& path){auto text=Utf8(path);if(text.find_first_of("\r\n\0",0,3)!=std::string::npos)throw std::runtime_error("Invalid engine configuration path.");return text;}
void PrepareEngine(const Config& config){
    CheckProtectedDirectory(EngineDirectory());ProtectDirectory(EngineStateDirectory());ProtectDirectory(Join(EngineStateDirectory(),L"credentials"));
    const auto state=EngineStateDirectory();
    WriteProtected(Join(state,L".rdc-state-owner.txt"),"RDC-OWNED-STATE-1\n");
    // Pairing is scoped to this engine lifetime. A previously public certificate
    // must never bypass a later protected access policy after repair/restart.
    for(const auto leaf:{L"pairing-state.json",L"stream-status.json",L"stream-status.json.tmp"}){const auto path=Join(state,leaf);if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES){CheckPlain(path);Require(DeleteFileW(path.c_str())!=FALSE,"Clear owned ephemeral pairing state");}}
    WriteProtected(Join(state,L"apps.json"),"{\"env\":{},\"apps\":[{\"name\":\"Desktop\",\"image-path\":\"\"}]}");
    std::string body="port = "+std::to_string(config.port)+"\nupnp = "+(config.internet?"enabled":"disabled")+"\n";
    body+="pkey = "+PathText(Join(state,L"credentials\\cakey.pem"))+"\ncert = "+PathText(Join(state,L"credentials\\cacert.pem"))+"\n";
    body+="file_state = "+PathText(Join(state,L"pairing-state.json"))+"\ncredentials_file = "+PathText(Join(state,L"disabled-web-credentials.json"))+"\nfile_apps = "+PathText(Join(state,L"apps.json"))+"\nlog_path = "+PathText(Join(state,L"sunshine.log"))+"\n";
    body+="sunshine_name = Remote Device Control\ncontroller = disabled\nkeyboard = enabled\nmouse = enabled\nstream_audio = disabled\ninstall_steam_audio_drivers = disabled\nlan_encryption_mode = 2\nwan_encryption_mode = 2\nhevc_mode = 1\nav1_mode = 1\nmin_log_level = 2\n";
    WriteProtected(Join(state,L"sunshine.conf"),body);
}
struct LessInsensitive{bool operator()(const std::wstring& a,const std::wstring& b)const{return _wcsicmp(a.c_str(),b.c_str())<0;}};
std::vector<wchar_t> ChildEnvironment(HANDLE token,const std::map<std::wstring,std::wstring,LessInsensitive>& extra){
    LPVOID raw=nullptr;Require(CreateEnvironmentBlock(&raw,token,FALSE)!=FALSE,"Create managed engine environment");
    std::map<std::wstring,std::wstring,LessInsensitive> values;
    try{for(const wchar_t* at=static_cast<const wchar_t*>(raw);*at;at+=wcslen(at)+1){std::wstring entry=at;const auto split=entry.find(L'=',entry[0]==L'='?1:0);if(split!=std::wstring::npos)values.emplace(entry.substr(0,split),entry.substr(split+1));}}catch(...){DestroyEnvironmentBlock(raw);throw;}DestroyEnvironmentBlock(raw);
    for(const auto& item:extra)values[item.first]=item.second;
    std::vector<wchar_t> out;for(const auto& item:values){out.insert(out.end(),item.first.begin(),item.first.end());out.push_back(L'=');out.insert(out.end(),item.second.begin(),item.second.end());out.push_back(0);}out.push_back(0);return out;
}
class EngineProcess {
    Handle process_,job_,engineStop_;DWORD session_=0;
public:
    ~EngineProcess(){Stop();}
    bool Started()const noexcept{return process_.value!=nullptr;}
    DWORD ExitCode()const noexcept{DWORD code=0;if(process_.value)GetExitCodeProcess(process_.value,&code);return code;}
    bool Running()const noexcept{return process_.value&&WaitForSingleObject(process_.value,0)==WAIT_TIMEOUT;}
    DWORD Session()const noexcept{return session_;}
    void Start(const Config& config,DWORD session){
        Stop();PrepareEngine(config);const auto executable=Join(EngineDirectory(),L"sunshine.exe");CheckPlain(executable);
        const auto eventName=L"Global\\RDC-EngineStop-"+Wide(TitanTransport::RandomSecret());PSECURITY_DESCRIPTOR descriptor=nullptr;
        Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)",SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"Managed engine event policy");SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};engineStop_.value=CreateEventW(&security,TRUE,FALSE,eventName.c_str());const DWORD error=GetLastError();LocalFree(descriptor);if(!engineStop_.value)throw std::runtime_error(WindowsError("Managed engine stop event",error));if(error==ERROR_ALREADY_EXISTS)throw std::runtime_error("An unexpected managed engine stop event already exists.");
        Handle own,primary;Require(OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY,&own.value)!=FALSE,"Open host service token");Require(DuplicateTokenEx(own.value,TOKEN_ALL_ACCESS,nullptr,SecurityImpersonation,TokenPrimary,&primary.value)!=FALSE,"Duplicate host engine token");Require(SetTokenInformation(primary.value,TokenSessionId,&session,sizeof(session))!=FALSE,"Assign engine to interactive console");
        const std::map<std::wstring,std::wstring,LessInsensitive> policy{{L"RDC_ACCESS_SECRET",Wide(config.secret)},{L"RDC_NO_CODE",config.noCode?L"1":L"0"},{L"RDC_REQUIRE_APPROVAL",config.requireApproval?L"1":L"0"},{L"RDC_HEADLESS",L"1"},{L"RDC_STOP_EVENT",eventName},{L"RDC_STATUS_FILE",Join(EngineStateDirectory(),L"stream-status.json")},{L"RDC_STATE_DIR",EngineStateDirectory()}};
        auto environment=ChildEnvironment(primary.value,policy);job_.value=CreateJobObjectW(nullptr,nullptr);Require(job_.value!=nullptr,"Create owned engine job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;Require(SetInformationJobObject(job_.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE,"Set owned engine lifetime");
        SECURITY_ATTRIBUTES inherited{sizeof(inherited),nullptr,TRUE};Handle output,nullInput;
        const auto bootstrap=Join(EngineStateDirectory(),L"bootstrap.log");if(GetFileAttributesW(bootstrap.c_str())!=INVALID_FILE_ATTRIBUTES)CheckPlain(bootstrap);
        output.value=CreateFileW(bootstrap.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&inherited,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);Require(output.value!=INVALID_HANDLE_VALUE,"Open protected engine startup log");
        nullInput.value=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherited,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);Require(nullInput.value!=INVALID_HANDLE_VALUE,"Open managed engine standard input");
        SIZE_T attributeSize=0;InitializeProcThreadAttributeList(nullptr,1,0,&attributeSize);std::vector<uint8_t> attributes(attributeSize);STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());Require(InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&attributeSize)!=FALSE,"Initialize managed engine handle policy");
        struct Attributes{LPPROC_THREAD_ATTRIBUTE_LIST value;~Attributes(){DeleteProcThreadAttributeList(value);}} ownedAttributes{startup.lpAttributeList};HANDLE permitted[]{output.value,nullInput.value};Require(UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,permitted,sizeof(permitted),nullptr,nullptr)!=FALSE,"Restrict engine inherited handles");
        wchar_t desktop[]=L"winsta0\\default";startup.StartupInfo.lpDesktop=desktop;startup.StartupInfo.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;startup.StartupInfo.wShowWindow=SW_HIDE;startup.StartupInfo.hStdOutput=startup.StartupInfo.hStdError=output.value;startup.StartupInfo.hStdInput=nullInput.value;PROCESS_INFORMATION process{};
        auto command=L"\""+executable+L"\" \""+Join(EngineStateDirectory(),L"sunshine.conf")+L"\"";
        const BOOL created=CreateProcessAsUserW(primary.value,executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,environment.data(),EngineDirectory().c_str(),&startup.StartupInfo,&process);SecureZeroMemory(environment.data(),environment.size()*sizeof(wchar_t));Require(created!=FALSE,"Launch managed Sunshine engine");process_.value=process.hProcess;Handle thread;thread.value=process.hThread;
        if(!AssignProcessToJobObject(job_.value,process_.value)){const auto code=GetLastError();TerminateProcess(process_.value,ERROR_PROCESS_ABORTED);throw std::runtime_error(WindowsError("Bind owned engine job",code));}Require(ResumeThread(thread.value)!=static_cast<DWORD>(-1),"Start managed Sunshine engine");session_=session;
    }
    void Stop()noexcept{if(engineStop_.value)SetEvent(engineStop_.value);if(process_.value&&WaitForSingleObject(process_.value,5000)==WAIT_TIMEOUT&&job_.value){TerminateJobObject(job_.value,ERROR_PROCESS_ABORTED);WaitForSingleObject(process_.value,1000);}process_.Reset();job_.Reset();engineStop_.Reset();session_=0;}
};
bool EngineReady(bool& busy){
    busy=false;try{const auto path=Join(EngineStateDirectory(),L"stream-status.json");if(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES)return false;CheckPlain(path);std::ifstream file(std::filesystem::path(path),std::ios::binary);std::string text(4097,'\0');file.read(text.data(),static_cast<std::streamsize>(text.size()));text.resize(static_cast<size_t>(file.gcount()));if(text.size()>4096)return false;busy=text.find("\"busy\":true")!=std::string::npos;return text.find("\"ready\":true")!=std::string::npos;}catch(...){return false;}
}
void PublishPin(const std::string& pin){HKEY key=nullptr;Require(RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl",0,nullptr,0,KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key,nullptr)==ERROR_SUCCESS,"Publish local host certificate identity");const auto text=Wide(pin);const auto code=RegSetValueExW(key,L"HostFingerprint",0,REG_SZ,reinterpret_cast<const BYTE*>(text.c_str()),static_cast<DWORD>((text.size()+1)*sizeof(wchar_t)));RegCloseKey(key);if(code)throw std::runtime_error(WindowsError("Save local host fingerprint",code));}
class Host {
    Config config_=LoadConfig();TitanTransport::Runtime network_;EngineProcess engine_;SessionIndicator indicator_;DiscoveryResponder discovery_;bool advertised_=false;std::string pin_;uint64_t nextStart_=0;
    void StopEngine()noexcept{discovery_.Stop();advertised_=false;engine_.Stop();indicator_.Stop();pin_.clear();}
public:
    ~Host(){StopEngine();}
    void Run(){
        SetStatus(SERVICE_RUNNING);
        while(WaitForSingleObject(stopEvent,500)==WAIT_TIMEOUT){
            const DWORD session=WTSGetActiveConsoleSessionId();const bool revoked=revokeSession.exchange(false);
            if(!ConsoleAvailable(session)||revoked||(engine_.Running()&&engine_.Session()!=session)){StopEngine();nextStart_=GetTickCount64()+1000;continue;}
            if(engine_.Running()&&!indicator_.Available()){Log("Remote control was disconnected locally; access is paused for 30 seconds.");StopEngine();nextStart_=GetTickCount64()+30000;continue;}
            if(engine_.Started()&&!engine_.Running()){Log("The streaming engine exited (Windows "+std::to_string(engine_.ExitCode())+"). Inspect the protected Sunshine bootstrap.log and sunshine.log.",EVENTLOG_ERROR_TYPE);StopEngine();nextStart_=GetTickCount64()+15000;continue;}
            if(!engine_.Running()){
                if(GetTickCount64()<nextStart_)continue;StopEngine();
                try{indicator_.Start(session);if(!indicator_.WaitReady())throw std::runtime_error(indicator_.Error());if(WaitForSingleObject(stopEvent,0)==WAIT_OBJECT_0||!ConsoleAvailable(session))throw std::runtime_error("The host stopped or the console changed during startup.");engine_.Start(config_,session);Log("Direct Sunshine/GameStream host engine started for the unlocked console.");}
                catch(const std::exception& failure){Log(failure.what(),EVENTLOG_ERROR_TYPE);StopEngine();nextStart_=GetTickCount64()+15000;continue;}
            }
            bool busy=false;const bool ready=EngineReady(busy);
            if(pin_.empty()){try{pin_=EngineFingerprint();PublishPin(pin_);}catch(...){continue;}}
            if(config_.noCode&&!advertised_){DiscoveryAnnouncement announcement;wchar_t name[256]{};DWORD length=256;announcement.name=GetComputerNameW(name,&length)?Utf8(name):"Windows PC";announcement.room=config_.room;announcement.pin=pin_;announcement.port=config_.port;announcement.requireApproval=config_.requireApproval;announcement.available=ready;discovery_.Start(std::move(announcement));advertised_=true;}
            if(advertised_)discovery_.Update(busy,ready);
        }
        StopEngine();
    }
};
DWORD WINAPI Control(DWORD control,DWORD event,LPVOID,LPVOID){if(control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN){SetStatus(SERVICE_STOP_PENDING);SetEvent(stopEvent);}else if(control==SERVICE_CONTROL_SESSIONCHANGE&&(event==WTS_SESSION_LOCK||event==WTS_SESSION_LOGOFF||event==WTS_CONSOLE_DISCONNECT||event==WTS_REMOTE_CONNECT||event==WTS_SESSION_LOGON))revokeSession=true;return NO_ERROR;}
void WINAPI ServiceMain(DWORD,LPWSTR*){serviceHandle=RegisterServiceCtrlHandlerExW(ServiceName,Control,nullptr);if(!serviceHandle)return;SetStatus(SERVICE_START_PENDING);stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);DWORD error=0;try{Require(stopEvent!=nullptr,"Create host service stop event");Host host;host.Run();}catch(const std::exception& failure){Log(failure.what(),EVENTLOG_ERROR_TYPE);error=ERROR_SERVICE_SPECIFIC_ERROR;}if(stopEvent)CloseHandle(stopEvent);stopEvent=nullptr;SetStatus(SERVICE_STOPPED,error);}
}
bool ConsoleAvailable(uint32_t sessionId)noexcept{if(sessionId==0xffffffff||WTSGetActiveConsoleSessionId()!=sessionId)return false;LPWSTR buffer=nullptr;DWORD size=0;bool available=false;if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,sessionId,WTSSessionInfoEx,&buffer,&size)){auto info=reinterpret_cast<WTSINFOEXW*>(buffer);if(size>=sizeof(WTSINFOEXW)&&info->Level==1)available=info->Data.WTSInfoExLevel1.SessionState==WTSActive&&info->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_UNLOCK;WTSFreeMemory(buffer);}return available;}
int RunService(){SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(ServiceName),ServiceMain},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());}
int RunHostConsole(){stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!stopEvent)return 1;SetConsoleCtrlHandler([](DWORD)->BOOL{SetEvent(stopEvent);return TRUE;},TRUE);try{Host host;host.Run();CloseHandle(stopEvent);return 0;}catch(const std::exception& failure){Log(failure.what(),EVENTLOG_ERROR_TYPE);CloseHandle(stopEvent);return 1;}}
}
