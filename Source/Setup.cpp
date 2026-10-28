#include "Transport.h"
#include "Setup.h"
#include "Config.h"
#include "Protocol.h"
#include "../Vdevice/Vdevice.h"
#include <windows.h>
#include <setupapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <netfw.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <array>
#include <cwctype>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

namespace RemoteControl::Setup {
namespace {
constexpr wchar_t Marker[]=L"ownership.txt",Pending[]=L"pending-removal.txt";
constexpr char MarkerBytes[]="REMOTE-DEVICE-CONTROL-HOST-1\r\n";
constexpr char PendingBytes[]="REMOTE-DEVICE-CONTROL-OWNED-DRIVER-REMOVAL-1\r\n";
constexpr wchar_t HostExe[]=L"RemoteDeviceHost.exe",DriverExe[]=L"VdeviceSetupConsole.exe",SetupExe[]=L"RemoteDeviceControlSetup.exe";
constexpr wchar_t FirewallName[]=L"Remote Device Control - private LAN";
constexpr wchar_t FirewallGroup[]=L"Remote Device Control";
constexpr wchar_t FirewallDescription[]=L"Remote Device Control host (owned private LAN rule)";
constexpr wchar_t DiscoveryFirewallName[]=L"Remote Device Control - nearby discovery";
constexpr wchar_t DiscoveryFirewallDescription[]=L"Remote Device Control host (owned private LAN discovery rule)";
constexpr long LanProfiles=NET_FW_PROFILE2_PRIVATE|NET_FW_PROFILE2_DOMAIN;
constexpr wchar_t AppKey[]=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\RemoteDeviceControl";
const std::array<const wchar_t*,5> ProgramFiles{HostExe,DriverExe,SetupExe,Marker,Pending};
const std::array<const wchar_t*,3> StateFiles{L"host.bin",Marker,L"host.bin.new"};
struct Handle {HANDLE value=nullptr;~Handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}Handle()=default;Handle(const Handle&)=delete;};
struct Service {SC_HANDLE value=nullptr;~Service(){if(value)CloseServiceHandle(value);}Service()=default;Service(const Service&)=delete;};
template<class T>struct Com {T* value=nullptr;~Com(){if(value)value->Release();}T** Put(){return &value;}T* operator->()const{return value;}};
struct Apartment {HRESULT value=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);~Apartment(){if(SUCCEEDED(value))CoUninitialize();}Apartment(){if(FAILED(value)&&value!=RPC_E_CHANGED_MODE)throw std::runtime_error(WindowsError("Initialize firewall COM",static_cast<uint32_t>(value)));}};
struct Bstr {BSTR value;explicit Bstr(const std::wstring& text):value(SysAllocStringLen(text.data(),static_cast<UINT>(text.size()))){if(!value)throw std::bad_alloc();}~Bstr(){SysFreeString(value);}};
void Require(bool condition,const char* operation){if(!condition)throw std::runtime_error(WindowsError(operation,GetLastError()));}
void Hr(HRESULT result,const char* operation){if(FAILED(result))throw std::runtime_error(WindowsError(operation,static_cast<uint32_t>(result)));}
void Notify(const Progress& progress,unsigned value,const std::wstring& text)noexcept{if(progress)try{progress(value,text);}catch(...){}}
std::wstring Lower(std::wstring text){for(auto& c:text)c=static_cast<wchar_t>(std::towlower(c));return text;}
bool Exists(const std::wstring& path){const auto attr=GetFileAttributesW(path.c_str());if(attr!=INVALID_FILE_ATTRIBUTES)return true;const auto error=GetLastError();if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND)return false;throw std::runtime_error(WindowsError("Inspect installation path",error));}
std::wstring Join(const std::wstring& directory,const wchar_t* leaf){return directory+L"\\"+leaf;}
std::vector<uint8_t> ReadFile(const std::wstring& path,size_t maximum){
    CheckPlain(path);Handle file;file.value=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    Require(file.value!=INVALID_HANDLE_VALUE,"Read owned file");BY_HANDLE_FILE_INFORMATION info{};Require(GetFileInformationByHandle(file.value,&info)!=FALSE,"Inspect owned file identity");
    if(info.nNumberOfLinks!=1||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Owned file is redirected or multiply linked.");
    LARGE_INTEGER length{};Require(GetFileSizeEx(file.value,&length)!=FALSE,"Read owned file size");
    if(length.QuadPart<0||static_cast<uint64_t>(length.QuadPart)>maximum)throw std::runtime_error("Owned file has an unexpected size.");
    std::vector<uint8_t> bytes(static_cast<size_t>(length.QuadPart));DWORD read=0;
    if(!bytes.empty())Require(::ReadFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)!=FALSE&&read==bytes.size(),"Read complete owned file");return bytes;
}
void Protected(const std::wstring& path){
    // The shared policy allows Users read/execute on the public program image,
    // never write/delete. State/private identity remains SYSTEM/Admin only.
    CheckProtectedDirectory(path);
}
void WriteAtomic(const std::wstring& path,const std::vector<uint8_t>& bytes){
    const auto parent=std::filesystem::path(path).parent_path().wstring();Protected(parent);
    if(Exists(path))(void)ReadFile(path,32*1024*1024);
    const auto temporary=path+L".new";if(Exists(temporary))throw std::runtime_error("A previous setup temporary file remains; review it before repairing.");
    Handle file;file.value=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);Require(file.value!=INVALID_HANDLE_VALUE,"Create protected setup file");
    DWORD written=0;const bool ok=WriteFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=FALSE&&written==bytes.size()&&FlushFileBuffers(file.value)!=FALSE;const auto error=GetLastError();CloseHandle(file.value);file.value=nullptr;
    if(!ok){DeleteFileW(temporary.c_str());throw std::runtime_error(WindowsError("Write protected setup file",error));}
    if(!MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){const auto commitError=GetLastError();DeleteFileW(temporary.c_str());throw std::runtime_error(WindowsError("Commit protected setup file",commitError));}
}
std::vector<uint8_t> Bytes(const char* text){return std::vector<uint8_t>(text,text+strlen(text));}
bool Marked(const std::wstring& directory){if(!Exists(directory))return false;Protected(directory);const auto marker=Join(directory,Marker);return Exists(marker)&&ReadFile(marker,128)==Bytes(MarkerBytes);}
void OwnDirectory(const std::wstring& directory){
    if(Exists(directory)){if(!Marked(directory))throw std::runtime_error("The target directory is not an owned Remote Device Control installation.");ProtectDirectory(directory);return;}
    ProtectDirectory(directory);Protected(directory);WriteAtomic(Join(directory,Marker),Bytes(MarkerBytes));
}
bool PendingRemoval(){const auto path=Join(ProgramDirectory(),Pending);return Exists(path)&&ReadFile(path,128)==Bytes(PendingBytes);}
std::vector<uint8_t> Resource(unsigned id){const auto module=GetModuleHandleW(nullptr);HRSRC found=FindResourceW(module,MAKEINTRESOURCEW(id),RT_RCDATA);Require(found!=nullptr,"Find embedded setup payload");const auto size=SizeofResource(module,found);if(size<2||size>32*1024*1024)throw std::runtime_error("Embedded setup payload size is invalid.");auto loaded=LoadResource(module,found);Require(loaded!=nullptr,"Load embedded setup payload");const auto bytes=static_cast<const uint8_t*>(LockResource(loaded));if(!bytes||bytes[0]!='M'||bytes[1]!='Z')throw std::runtime_error("Embedded setup executable is invalid.");return {bytes,bytes+size};}
struct Lock {Handle handle;Lock(){PSECURITY_DESCRIPTOR descriptor=nullptr;Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"Protect installation lock");SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};handle.value=CreateMutexW(&attributes,FALSE,L"Global\\RemoteDeviceControlSetup");const auto error=GetLastError();LocalFree(descriptor);if(!handle.value)throw std::runtime_error(WindowsError("Create installation lock",error));const auto wait=WaitForSingleObject(handle.value,0);if(wait!=WAIT_OBJECT_0&&wait!=WAIT_ABANDONED)throw std::runtime_error("Another Remote Device Control setup is active.");}~Lock(){if(handle.value)ReleaseMutex(handle.value);}};
void Administrator(){SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;PSID sid=nullptr;Require(AllocateAndInitializeSid(&nt,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)!=FALSE,"Read administrative membership");BOOL member=FALSE;const BOOL checked=CheckTokenMembership(nullptr,sid,&member);FreeSid(sid);if(!checked||!member)throw std::runtime_error("Run this installer as administrator.");}
struct ServiceState{bool exists=false,running=false,pendingDelete=false;};
ServiceState ServiceQuery(const wchar_t* name,bool own){
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);Require(manager.value!=nullptr,"Open Windows service manager");
    Service service;service.value=OpenServiceW(manager.value,name,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS);if(!service.value){const auto error=GetLastError();if(error==ERROR_SERVICE_DOES_NOT_EXIST)return {};if(error==ERROR_SERVICE_MARKED_FOR_DELETE)return {false,false,true};throw std::runtime_error(WindowsError("Inspect Windows service",error));}
    if(own){DWORD needed=0;QueryServiceConfigW(service.value,nullptr,0,&needed);if(needed<sizeof(QUERY_SERVICE_CONFIGW)||needed>65536)throw std::runtime_error("Invalid owned service configuration.");std::vector<uint8_t> bytes(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());Require(QueryServiceConfigW(service.value,config,needed,&needed)!=FALSE,"Read owned service configuration");
        if(config->dwServiceType!=SERVICE_WIN32_OWN_PROCESS||!config->lpBinaryPathName||!ServiceImageMatches(config->lpBinaryPathName,Join(ProgramDirectory(),HostExe)))throw std::runtime_error("A service with this name points outside this project's owned host image; it was retained.");
    }
    SERVICE_STATUS_PROCESS status{};DWORD needed=0;Require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)!=FALSE,"Read Windows service state");return {true,status.dwCurrentState==SERVICE_RUNNING};
}
bool VdevicePresent(){
    const auto main=ServiceQuery(L"Vdevice",false),clock=ServiceQuery(L"VdeviceDemoClock",false);if(main.exists||main.pendingDelete||clock.exists||clock.pendingDelete)return true;
    HDEVINFO devices=SetupDiGetClassDevsW(nullptr,nullptr,nullptr,DIGCF_ALLCLASSES);if(devices==INVALID_HANDLE_VALUE)throw std::runtime_error(WindowsError("Inspect existing Vdevice controllers",GetLastError()));
    struct Destroy{HDEVINFO value;~Destroy(){SetupDiDestroyDeviceInfoList(value);}} holder{devices};
    for(DWORD index=0;;++index){SP_DEVINFO_DATA item{};item.cbSize=sizeof(item);if(!SetupDiEnumDeviceInfo(devices,index,&item)){if(GetLastError()==ERROR_NO_MORE_ITEMS)break;throw std::runtime_error(WindowsError("Enumerate existing Vdevice controllers",GetLastError()));}
        wchar_t ids[4096]{};DWORD type=0;if(SetupDiGetDeviceRegistryPropertyW(devices,&item,SPDRP_HARDWAREID,&type,reinterpret_cast<BYTE*>(ids),sizeof(ids),nullptr)&&type==REG_MULTI_SZ){ids[4094]=ids[4095]=0;for(const wchar_t* id=ids;*id;id+=wcslen(id)+1)if(_wcsicmp(id,L"ROOT\\Vdevice")==0)return true;}}
    return false;
}
void StopService(const Progress& progress,bool remove){
    if(!ServiceQuery(ServiceName,true).exists)return;
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);Require(manager.value!=nullptr,"Open service manager");Service service;service.value=OpenServiceW(manager.value,ServiceName,SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE);Require(service.value!=nullptr,"Open owned host service");
    SERVICE_STATUS status{};if(!ControlService(service.value,SERVICE_CONTROL_STOP,&status)){const auto error=GetLastError();if(error!=ERROR_SERVICE_NOT_ACTIVE)throw std::runtime_error(WindowsError("Stop remote host service",error));}
    const auto begin=GetTickCount64();for(;;){SERVICE_STATUS_PROCESS current{};DWORD needed=0;Require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&current),sizeof(current),&needed)!=FALSE,"Wait for host shutdown");if(current.dwCurrentState==SERVICE_STOPPED)break;if(GetTickCount64()-begin>30000)throw std::runtime_error("Host service did not stop within 30 seconds; its files were retained.");Notify(progress,12,L"Waiting for the host to close its sessions and virtual input devices...");Sleep(50);}
    if(remove&&!DeleteService(service.value)&&GetLastError()!=ERROR_SERVICE_MARKED_FOR_DELETE)throw std::runtime_error(WindowsError("Remove owned host service",GetLastError()));
}
void StartService(){
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE);Require(manager.value!=nullptr,"Open service manager for installation");
    const auto command=Quote(Join(ProgramDirectory(),HostExe))+L" --service";
    Service service;service.value=OpenServiceW(manager.value,ServiceName,SERVICE_CHANGE_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START);
    if(service.value){Require(ChangeServiceConfigW(service.value,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr,ProductName)!=FALSE,"Repair automatic host service");}
    else{const auto error=GetLastError();if(error!=ERROR_SERVICE_DOES_NOT_EXIST)throw std::runtime_error(WindowsError("Open host service for installation",error));service.value=CreateServiceW(manager.value,ServiceName,ProductName,SERVICE_CHANGE_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr);Require(service.value!=nullptr,"Register automatic host service");}
    SERVICE_DESCRIPTIONW description{const_cast<LPWSTR>(L"Remote Device Control host. Starts with Windows; uses the Vdevice demo for keyboard and mouse. Signed-in console desktop only; access policy is set by its administrator.")};Require(ChangeServiceConfig2W(service.value,SERVICE_CONFIG_DESCRIPTION,&description)!=FALSE,"Set host service description");
    if(!::StartServiceW(service.value,0,nullptr)&&GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING)throw std::runtime_error(WindowsError("Start remote host service",GetLastError()));
    const auto begin=GetTickCount64();for(;;){SERVICE_STATUS_PROCESS current{};DWORD needed=0;Require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&current),sizeof(current),&needed)!=FALSE,"Verify host service startup");if(current.dwCurrentState==SERVICE_RUNNING)break;if(current.dwCurrentState==SERVICE_STOPPED)throw std::runtime_error("Host service stopped during startup (Windows "+std::to_string(current.dwWin32ExitCode)+").");if(GetTickCount64()-begin>15000)throw std::runtime_error("Host service did not report Running within 15 seconds. Review Windows service status and retry repair.");Sleep(50);}
}
bool FirewallOwned(INetFwRule* rule,bool discovery){
    BSTR app=nullptr,group=nullptr,description=nullptr,remote=nullptr,ports=nullptr;long protocol=0,profiles=0;NET_FW_RULE_DIRECTION direction{};
    HRESULT result=rule->get_ApplicationName(&app);result=SUCCEEDED(result)?rule->get_Grouping(&group):result;result=SUCCEEDED(result)?rule->get_Description(&description):result;result=SUCCEEDED(result)?rule->get_RemoteAddresses(&remote):result;result=SUCCEEDED(result)?rule->get_LocalPorts(&ports):result;result=SUCCEEDED(result)?rule->get_Protocol(&protocol):result;result=SUCCEEDED(result)?rule->get_Profiles(&profiles):result;result=SUCCEEDED(result)?rule->get_Direction(&direction):result;
    const bool owned=SUCCEEDED(result)&&app&&group&&description&&remote&&ports&&Lower(app)==Lower(Join(ProgramDirectory(),HostExe))&&std::wstring(group)==FirewallGroup&&std::wstring(description)==(discovery?DiscoveryFirewallDescription:FirewallDescription)&&_wcsicmp(remote,L"LocalSubnet")==0&&std::wstring(ports)==(discovery?L"48762":L"48761")&&protocol==(discovery?NET_FW_IP_PROTOCOL_UDP:NET_FW_IP_PROTOCOL_TCP)&&(profiles==NET_FW_PROFILE2_PRIVATE||profiles==LanProfiles)&&direction==NET_FW_RULE_DIR_IN;
    SysFreeString(app);SysFreeString(group);SysFreeString(description);SysFreeString(remote);SysFreeString(ports);return owned;
}
void FirewallRule(bool add,bool discovery){
    Apartment apartment;Com<INetFwPolicy2> policy;Hr(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),reinterpret_cast<void**>(policy.Put())),"Open Windows Firewall policy");Com<INetFwRules> rules;Hr(policy->get_Rules(rules.Put()),"Read Windows Firewall rules");Bstr name(discovery?DiscoveryFirewallName:FirewallName);Com<INetFwRule> existing;const auto found=rules->Item(name.value,existing.Put());
    if(SUCCEEDED(found)){if(!FirewallOwned(existing.value,discovery))throw std::runtime_error("A firewall rule with this name is not owned by Remote Device Control; it was retained.");Hr(rules->Remove(name.value),"Remove owned firewall rule");}else if(found!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&found!=HRESULT_FROM_WIN32(ERROR_NOT_FOUND))Hr(found,"Inspect owned firewall rule");
    if(!add)return;Com<INetFwRule> rule;Hr(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwRule),reinterpret_cast<void**>(rule.Put())),"Create private LAN firewall rule");
    Bstr app(Join(ProgramDirectory(),HostExe)),group(FirewallGroup),description(discovery?DiscoveryFirewallDescription:FirewallDescription),port(discovery?L"48762":L"48761"),remote(L"LocalSubnet");
    Hr(rule->put_Name(name.value),"Name private LAN firewall rule");Hr(rule->put_ApplicationName(app.value),"Bind firewall rule to owned host");Hr(rule->put_Grouping(group.value),"Group firewall rule");Hr(rule->put_Description(description.value),"Describe firewall rule");Hr(rule->put_Protocol(discovery?NET_FW_IP_PROTOCOL_UDP:NET_FW_IP_PROTOCOL_TCP),"Set firewall protocol");Hr(rule->put_LocalPorts(port.value),"Set firewall port");Hr(rule->put_RemoteAddresses(remote.value),"Restrict firewall rule to local subnet");Hr(rule->put_Profiles(LanProfiles),"Restrict firewall rule to private/domain network profiles");Hr(rule->put_Direction(NET_FW_RULE_DIR_IN),"Set firewall direction");Hr(rule->put_Action(NET_FW_ACTION_ALLOW),"Set firewall action");Hr(rule->put_Enabled(VARIANT_TRUE),"Enable private LAN firewall rule");Hr(rules->Add(rule.value),"Register private LAN firewall rule");
}
void Firewall(bool add,bool discovery=false){FirewallRule(add,false);FirewallRule(add&&discovery,true);}
std::wstring ReadReg(HKEY root,const wchar_t* key,const wchar_t* name){DWORD bytes=0;auto result=RegGetValueW(root,key,name,RRF_RT_REG_SZ,nullptr,nullptr,&bytes);if(result==ERROR_FILE_NOT_FOUND||result==ERROR_PATH_NOT_FOUND)return {};if(result!=ERROR_SUCCESS||bytes>65536)throw std::runtime_error("Invalid application registration.");std::vector<wchar_t> value(bytes/sizeof(wchar_t)+1);result=RegGetValueW(root,key,name,RRF_RT_REG_SZ,nullptr,value.data(),&bytes);if(result!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Read application registration",result));return value.data();}
void Apps(bool add){
    const auto command=Quote(Join(ProgramDirectory(),SetupExe))+L" --remove-ui";const auto existing=ReadReg(HKEY_LOCAL_MACHINE,AppKey,L"UninstallString");if(!existing.empty()&&existing!=command)throw std::runtime_error("The existing application uninstall entry is not owned by this installation.");
    if(!add){const auto result=RegDeleteTreeW(HKEY_LOCAL_MACHINE,AppKey);if(result!=ERROR_SUCCESS&&result!=ERROR_FILE_NOT_FOUND&&result!=ERROR_PATH_NOT_FOUND)throw std::runtime_error(WindowsError("Remove application registration",result));return;}
    HKEY key=nullptr;const auto result=RegCreateKeyExW(HKEY_LOCAL_MACHINE,AppKey,0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr);if(result!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Register Windows Apps entry",result));struct Close{HKEY key;~Close(){RegCloseKey(key);}} closer{key};
    for(const auto& pair:std::vector<std::pair<std::wstring,std::wstring>>{{L"DisplayName",ProductName},{L"DisplayVersion",L"0.2.0"},{L"Publisher",L"TitanCSA"},{L"UninstallString",command},{L"InstallLocation",ProgramDirectory()},{L"DisplayIcon",Join(ProgramDirectory(),HostExe)},{L"URLInfoAbout",L"https://github.com/TitanCSA/Remote-Device-Control"}}){const auto error=RegSetValueExW(key,pair.first.c_str(),0,REG_SZ,reinterpret_cast<const BYTE*>(pair.second.c_str()),static_cast<DWORD>((pair.second.size()+1)*sizeof(wchar_t)));if(error!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Write Windows Apps entry",error));}
    DWORD one=1;for(const wchar_t* field:{L"NoModify",L"NoRepair"}){const auto error=RegSetValueExW(key,field,0,REG_DWORD,reinterpret_cast<const BYTE*>(&one),sizeof(one));if(error!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Write Apps settings",error));}
}
struct ChildResult{DWORD code=0;std::wstring output;};
ChildResult Driver(const wchar_t* operation,const Progress& progress){
    const auto executable=Join(ProgramDirectory(),DriverExe);(void)ReadFile(executable,32*1024*1024);
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};Handle read,write;Require(CreatePipe(&read.value,&write.value,&security,0)!=FALSE,"Create driver setup output pipe");Require(SetHandleInformation(read.value,HANDLE_FLAG_INHERIT,0)!=FALSE,"Protect driver setup pipe");
    Handle input;input.value=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);Require(input.value!=INVALID_HANDLE_VALUE,"Create driver setup input");
    STARTUPINFOW start{};start.cb=sizeof(start);start.dwFlags=STARTF_USESTDHANDLES;start.hStdInput=input.value;start.hStdOutput=start.hStdError=write.value;
    std::wstring command=Quote(executable)+L" "+operation;PROCESS_INFORMATION process{};Require(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,ProgramDirectory().c_str(),&start,&process)!=FALSE,"Launch verified embedded Vdevice installer");
    Handle child,thread;child.value=process.hProcess;thread.value=process.hThread;CloseHandle(write.value);write.value=nullptr;
    std::string raw;const auto begin=GetTickCount64();uint64_t nextNotice=10000;
    for(;;){DWORD available=0;if(!PeekNamedPipe(read.value,nullptr,0,nullptr,&available,nullptr)){const auto error=GetLastError();if(error!=ERROR_BROKEN_PIPE)throw std::runtime_error(WindowsError("Read driver setup progress",error));available=0;}
        while(available){char chunk[4096];DWORD taken=0;Require(::ReadFile(read.value,chunk,(std::min)(available,static_cast<DWORD>(sizeof(chunk))),&taken,nullptr)!=FALSE,"Read driver setup output");raw.append(chunk,chunk+taken);if(raw.size()>65536)raw.erase(0,raw.size()-65536);available-=taken;if(!taken)break;}
        const auto wait=WaitForSingleObject(child.value,50);if(wait==WAIT_OBJECT_0)break;if(wait!=WAIT_TIMEOUT)throw std::runtime_error(WindowsError("Wait for Vdevice setup",GetLastError()));
        if(GetTickCount64()-begin>=nextNotice){Notify(progress,45,L"Windows is still completing the driver operation. Keep this window open; do not disconnect power.");nextNotice+=10000;}}
    ChildResult result;Require(GetExitCodeProcess(child.value,&result.code)!=FALSE,"Read Vdevice setup exit code");
    // Drain final buffered output after the process exits.
    for(;;){char chunk[4096];DWORD taken=0;if(!::ReadFile(read.value,chunk,sizeof(chunk),&taken,nullptr)||!taken)break;raw.append(chunk,chunk+taken);if(raw.size()>65536)raw.erase(0,raw.size()-65536);}
    result.output=Wide(raw);return result;
}
bool VdeviceInf(const std::wstring& path){
    const auto inf=SetupOpenInfFileW(path.c_str(),nullptr,INF_STYLE_WIN4,nullptr);if(inf==INVALID_HANDLE_VALUE){const auto error=GetLastError();if(error==ERROR_ACCESS_DENIED||error==ERROR_SHARING_VIOLATION)throw std::runtime_error(WindowsError("Read staged driver package ownership",error));return false;}
    struct Close{HINF value;~Close(){SetupCloseInfFile(value);}} closer{inf};
    INFCONTEXT line{};wchar_t provider[256]{},catalog[256]{};
    if(!SetupFindFirstLineW(inf,L"Version",L"Provider",&line)||!SetupGetStringFieldW(&line,1,provider,256,nullptr)||(_wcsicmp(provider,L"TitanCSA")&&_wcsicmp(provider,L"Vdevice"))||
       !SetupFindFirstLineW(inf,L"Version",L"CatalogFile",&line)||!SetupGetStringFieldW(&line,1,catalog,256,nullptr)||_wcsicmp(catalog,L"Vdevice.cat"))return false;
    bool hardware=false,service=false;
    for(UINT sectionIndex=0;sectionIndex<1024;++sectionIndex){
        wchar_t section[256]{};if(!SetupEnumInfSectionsW(inf,sectionIndex,section,256,nullptr))break;
        for(UINT lineIndex=0;lineIndex<32768;++lineIndex){
            if(!SetupGetLineByIndexW(inf,section,lineIndex,&line))break;
            wchar_t key[256]{},first[1024]{},second[1024]{};
            (void)SetupGetStringFieldW(&line,0,key,256,nullptr);(void)SetupGetStringFieldW(&line,1,first,1024,nullptr);(void)SetupGetStringFieldW(&line,2,second,1024,nullptr);
            hardware=hardware||!_wcsicmp(second,L"ROOT\\Vdevice");service=service||(!_wcsicmp(key,L"AddService")&&!_wcsicmp(first,L"Vdevice"));
            if(hardware&&service)return true;
        }
    }
    return false;
}
bool DriverPackagesRemain(){
    // The unchanged console installer consumes its structured status internally.
    // Query Windows INF ownership directly instead of parsing human progress.
    wchar_t windows[MAX_PATH]{};Require(GetWindowsDirectoryW(windows,MAX_PATH)!=0,"Find staged Windows driver packages");const auto directory=std::wstring(windows)+L"\\INF\\";
    WIN32_FIND_DATAW item{};const auto search=FindFirstFileW((directory+L"oem*.inf").c_str(),&item);
    if(search==INVALID_HANDLE_VALUE){const auto error=GetLastError();if(error==ERROR_FILE_NOT_FOUND)return false;throw std::runtime_error(WindowsError("Enumerate staged Windows driver packages",error));}
    struct Close{HANDLE value;~Close(){FindClose(value);}} closer{search};
    do{if(!(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&VdeviceInf(directory+item.cFileName))return true;}while(FindNextFileW(search,&item));
    const auto error=GetLastError();if(error!=ERROR_NO_MORE_FILES)throw std::runtime_error(WindowsError("Read remaining staged Windows driver packages",error));return false;
}
bool ClockRegistration(std::wstring& verifiedPath,bool remove){
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);Require(manager.value!=nullptr,"Open clock service manager");Service service;service.value=OpenServiceW(manager.value,L"VdeviceDemoClock",SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|DELETE);
    if(!service.value){const auto error=GetLastError();if(error==ERROR_SERVICE_DOES_NOT_EXIST)return false;if(error==ERROR_SERVICE_MARKED_FOR_DELETE)return true;throw std::runtime_error(WindowsError("Inspect owned Vdevice clock",error));}
    DWORD needed=0;QueryServiceConfigW(service.value,nullptr,0,&needed);if(needed<sizeof(QUERY_SERVICE_CONFIGW)||needed>65536)throw std::runtime_error("Invalid Vdevice clock registration.");std::vector<uint8_t> storage(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());Require(QueryServiceConfigW(service.value,config,needed,&needed)!=FALSE,"Read owned Vdevice clock path");
    wchar_t windows[MAX_PATH]{};Require(GetWindowsDirectoryW(windows,MAX_PATH)!=0,"Read Windows directory");std::wstring image=config->lpBinaryPathName?config->lpBinaryPathName:L"";if(image.size()>1&&image.front()==L'"'&&image.back()==L'"')image=image.substr(1,image.size()-2);if(image.rfind(L"\\??\\",0)==0)image.erase(0,4);if(Lower(image).rfind(L"\\systemroot\\",0)==0)image=std::wstring(windows)+image.substr(11);else{wchar_t expanded[32768]{};const auto n=ExpandEnvironmentStringsW(image.c_str(),expanded,32768);if(!n||n>32768)throw std::runtime_error("Invalid Vdevice clock image path.");image=expanded;}
    const auto lower=Lower(image),prefix=Lower(std::wstring(windows))+L"\\system32\\driverstore\\filerepository\\vdevice.inf_";
    const auto slash=lower.find(L'\\',prefix.size());if(config->dwServiceType!=SERVICE_KERNEL_DRIVER||lower.rfind(prefix,0)!=0||slash==std::wstring::npos||lower.substr(slash)!=L"\\titandemoclock.sys")throw std::runtime_error("The clock service path is not the owned Vdevice package; its registration was retained.");
    if(!verifiedPath.empty()&&Lower(verifiedPath)!=lower)throw std::runtime_error("The verified clock image path changed; its service registration was retained.");
    if(verifiedPath.empty()){
    CheckPlain(image);WINTRUST_FILE_INFO file{};file.cbStruct=sizeof(file);file.pcwszFilePath=image.c_str();WINTRUST_DATA trust{};trust.cbStruct=sizeof(trust);trust.dwUIChoice=WTD_UI_NONE;trust.fdwRevocationChecks=WTD_REVOKE_NONE;trust.dwUnionChoice=WTD_CHOICE_FILE;trust.pFile=&file;trust.dwStateAction=WTD_STATEACTION_VERIFY;trust.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;const auto verified=WinVerifyTrust(nullptr,&action,&trust);trust.dwStateAction=WTD_STATEACTION_CLOSE;(void)WinVerifyTrust(nullptr,&action,&trust);if(verified!=ERROR_SUCCESS)throw std::runtime_error("The owned demo clock signature could not be verified; its registration was retained.");
    HCERTSTORE store=nullptr;HCRYPTMSG message=nullptr;DWORD encoding=0,type=0,format=0;Require(CryptQueryObject(CERT_QUERY_OBJECT_FILE,image.c_str(),CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,CERT_QUERY_FORMAT_FLAG_BINARY,0,&encoding,&type,&format,&store,&message,nullptr)!=FALSE,"Read demo clock signer");
    struct CertClose{HCERTSTORE store;HCRYPTMSG message;~CertClose(){CryptMsgClose(message);CertCloseStore(store,0);}} certClose{store,message};DWORD bytes=0;Require(CryptMsgGetParam(message,CMSG_SIGNER_INFO_PARAM,0,nullptr,&bytes)!=FALSE,"Read demo clock signer identity");std::vector<uint8_t> signerStorage(bytes);Require(CryptMsgGetParam(message,CMSG_SIGNER_INFO_PARAM,0,signerStorage.data(),&bytes)!=FALSE,"Read demo clock signer data");const auto signer=reinterpret_cast<CMSG_SIGNER_INFO*>(signerStorage.data());CERT_INFO find{};find.Issuer=signer->Issuer;find.SerialNumber=signer->SerialNumber;auto certificate=CertFindCertificateInStore(store,encoding,0,CERT_FIND_SUBJECT_CERT,&find,nullptr);if(!certificate)throw std::runtime_error("Demo clock signer certificate is unavailable.");wchar_t subject[512]{};CertGetNameStringW(certificate,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,subject,512);CertFreeCertificateContext(certificate);if(std::wstring(subject)!=L"Microsoft Windows Hardware Compatibility Publisher")throw std::runtime_error("Unexpected demo clock signer; registration was retained.");
    verifiedPath=image;
    }
    SERVICE_STATUS_PROCESS status{};Require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)!=FALSE,"Read resident clock status");if(remove&&!DeleteService(service.value)&&GetLastError()!=ERROR_SERVICE_MARKED_FOR_DELETE)throw std::runtime_error(WindowsError("Remove owned clock registration",GetLastError()));return status.dwCurrentState!=SERVICE_STOPPED;
}
bool RestartFlag(){DWORD flag=0,bytes=sizeof(flag);return RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\Vdevice\\Setup\\BootSession",L"RestartRequired",RRF_RT_REG_DWORD,nullptr,&flag,&bytes)==ERROR_SUCCESS&&flag!=0;}
bool RemoveFile(const std::wstring& path){if(!Exists(path))return false;(void)ReadFile(path,32*1024*1024);if(DeleteFileW(path.c_str()))return false;const auto error=GetLastError();if(error!=ERROR_ACCESS_DENIED&&error!=ERROR_SHARING_VIOLATION)throw std::runtime_error(WindowsError("Remove owned installation file",error));Require(MoveFileExW(path.c_str(),nullptr,MOVEFILE_DELAY_UNTIL_REBOOT)!=FALSE,"Schedule locked owned file removal after restart");return true;}
bool RemoveOwnedDirectory(const std::wstring& path,std::wstring& retained){
    if(!Exists(path))return false;Protected(path);if(::RemoveDirectoryW(path.c_str()))return false;const auto error=GetLastError();
    if(error==ERROR_DIR_NOT_EMPTY){
        bool onlyScheduledFiles=true;const bool program=Lower(path)==Lower(ProgramDirectory());
        for(const auto& entry:std::filesystem::directory_iterator(path)){
            const auto leaf=entry.path().filename().wstring();const auto attr=GetFileAttributesW(entry.path().c_str());bool known=false;
            if(program){for(const auto* name:ProgramFiles)if(leaf==name)known=true;}else{for(const auto* name:StateFiles)if(leaf==name)known=true;}
            if(!known||attr==INVALID_FILE_ATTRIBUTES||(attr&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))){onlyScheduledFiles=false;retained+=L"\nUnexpected file retained: "+entry.path().wstring();}
        }
        // Every known remaining file has already been scheduled above; append
        // the empty-directory deletion after those exact file operations.
        if(!onlyScheduledFiles)return false;Require(MoveFileExW(path.c_str(),nullptr,MOVEFILE_DELAY_UNTIL_REBOOT)!=FALSE,"Schedule owned directory cleanup after its locked files");return true;
    }
    if(error==ERROR_ACCESS_DENIED||error==ERROR_SHARING_VIOLATION){Require(MoveFileExW(path.c_str(),nullptr,MOVEFILE_DELAY_UNTIL_REBOOT)!=FALSE,"Schedule owned directory removal");return true;}throw std::runtime_error(WindowsError("Remove empty owned directory",error));
}
}
bool OwnedLeaf(const std::wstring& leaf) noexcept {for(const auto* name:ProgramFiles)if(leaf==name)return true;for(const auto* name:StateFiles)if(leaf==name)return true;return false;}
std::wstring Quote(const std::wstring& value){if(value.find_first_of(L"\"\r\n\0",0,4)!=std::wstring::npos||value.empty()||value.back()==L'\\')throw std::invalid_argument("Unsafe installation command argument.");return L"\""+value+L"\"";}
bool ServiceImageMatches(const std::wstring& command,const std::wstring& executable) noexcept {try{return Lower(command)==Lower(Quote(executable)+L" --service");}catch(...){return false;}}
Snapshot Inspect(bool includeConnectionCode){
    Snapshot snapshot;try{
        const bool program=Marked(ProgramDirectory()),state=Marked(StateDirectory());const auto service=ServiceQuery(ServiceName,true);
        snapshot.installed=program||state||service.exists;snapshot.running=service.running;snapshot.driverPresent=VdevicePresent();snapshot.restartRequired=RestartFlag()||service.pendingDelete;
        if(program){snapshot.removalPending=PendingRemoval();snapshot.driverOwned=snapshot.removalPending;}
        if(state&&Exists(Join(StateDirectory(),L"host.bin"))){const auto config=LoadConfig();snapshot.internet=config.internet;snapshot.driverOwned=config.driverOwned;snapshot.removableDriver=config.driverOwned;snapshot.noCode=config.noCode;snapshot.requireApproval=config.requireApproval;
            if(includeConnectionCode&&!snapshot.removalPending){TitanTransport::Identity identity(config.identity);snapshot.connectionCode=PairingCode(config,identity.Fingerprint());}}
        snapshot.removableDriver=snapshot.driverOwned;snapshot.status=snapshot.removalPending?L"Removal pending restart / final cleanup":snapshot.running?L"Host service running":snapshot.installed?L"Installed — service stopped":L"Not installed";
        snapshot.detail=snapshot.removalPending?L"Restart Windows, reopen this installer and choose Uninstall to finish the owned driver-package cleanup.":snapshot.running?L"Starts with Windows. Keep the connection code private. Remote control requires an authenticated peer and the signed-in console desktop.":L"Install the Vdevice demo and one automatic host service. No separate controller installation is required.";
        if(snapshot.running&&snapshot.noCode){snapshot.detail=L"Public access enabled: visible in nearby lists"+std::wstring(snapshot.internet?L" and the public Internet directory.":L" on this private local network.")+(snapshot.requireApproval?L" Each new connection requires approval on this PC.":L" Anyone listed can connect without a code or permission prompt.")+L" Control is limited to the signed-in console desktop.";}
        if(snapshot.driverPresent){const auto info=Vdevice::Get_Info();if(!info)snapshot.detail+=L" Vdevice API: "+Wide(info.message)+L" (Windows "+std::to_wstring(info.error)+L").";else if(info.trial_expired)snapshot.detail+=L" The shared Vdevice demo has expired; restart Windows for another allowance.";else if(info.quiescing||info.removing){snapshot.restartRequired=true;snapshot.detail+=L" Vdevice is stopping; restart Windows if requested.";}}
    }catch(const std::exception& error){snapshot.status=L"Installation state needs attention";snapshot.detail=Wide(error.what());}return snapshot;
}
Result Install(bool internet,const Progress& progress,std::optional<bool> noCode,std::optional<bool> requireApproval){
    Result result;try{
        Administrator();Lock lock;Notify(progress,5,L"Verifying embedded host, Vdevice installer and removal helper...");const auto driver=Resource(301),host=Resource(302),uninstaller=Resource(303);
        if(ServiceQuery(ServiceName,true).pendingDelete){result.code=3010;result.restartRequired=true;result.message=L"The previous host service is pending deletion. Restart Windows and run Install / repair again; no installation files were changed.";Notify(progress,100,result.message);return result;}
        const bool previousDriver=VdevicePresent();const bool previousConfig=Exists(StateDirectory())&&Exists(Join(StateDirectory(),L"host.bin"));
        OwnDirectory(ProgramDirectory());OwnDirectory(StateDirectory());StopService(progress,false);
        Config config=previousConfig?LoadConfig():NewConfig();config.internet=internet;if(noCode.has_value())config.noCode=*noCode;if(requireApproval.has_value()){if(!config.noCode)throw std::runtime_error("Connection-approval options require public no-code access.");config.requireApproval=*requireApproval;}if(config.directoryOwner.empty())config.directoryOwner=TitanTransport::RandomSecret()+TitanTransport::RandomSecret();if(config.noCode)config.room=PublicRoom(config.directoryOwner);if(!previousDriver||PendingRemoval())config.driverOwned=true;SaveConfig(config);
        Notify(progress,20,L"Writing the protected host and the unchanged Vdevice demo installer...");WriteAtomic(Join(ProgramDirectory(),HostExe),host);WriteAtomic(Join(ProgramDirectory(),DriverExe),driver);
        // Use immutable bytes from the running full installer, never reopen a
        // potentially user-writable downloaded EXE path after elevation.
        WriteAtomic(Join(ProgramDirectory(),SetupExe),uninstaller);
        Apps(true);Notify(progress,35,previousDriver?(config.driverOwned?L"Repairing the Vdevice package owned by this host; removal remains optional at uninstall.":L"Checking/repairing the shared Vdevice installation; it will be preserved on host removal."):L"Installing the Microsoft-signed Vdevice demo package...");const auto installed=Driver(L"/install",progress);
        if(installed.code!=0&&installed.code!=3010)throw std::runtime_error("Vdevice installation failed (Windows "+std::to_string(installed.code)+"). "+Utf8(installed.output));
        result.restartRequired=installed.code==3010;Notify(progress,75,L"Adding private-subnet LAN firewall rules and the automatic host service...");Firewall(true,config.noCode);StartService();
        if(Exists(Join(ProgramDirectory(),Pending)))result.restartRequired=RemoveFile(Join(ProgramDirectory(),Pending))||result.restartRequired;
        result.code=result.restartRequired?3010:0;result.message=result.restartRequired?L"Host installed. Restart Windows to finish the Vdevice operation.":L"Host installed and started.";
        result.message+=config.noCode?(config.requireApproval?L" Public no-code access is enabled; each new connection requires approval on this PC.":L" Public no-code access is enabled. Anyone listed can connect without a code or permission prompt."):L" Share the private connection code only with the intended controller.";
        result.message+=L" Vdevice's shared one-hour allowance begins when virtual devices are first created.";Notify(progress,100,result.message);
    }catch(const std::exception& error){result.code=1;result.message=Wide(error.what());Notify(progress,100,L"Installation did not complete: "+result.message);}return result;
}
Result Uninstall(bool removeOwnedDriver,const Progress& progress){
    Result result;try{
        Administrator();Lock lock;const bool program=Marked(ProgramDirectory()),state=Marked(StateDirectory());if(!program&&!state){(void)ServiceQuery(ServiceName,true);result.message=L"No owned Remote Device Control installation was found.";return result;}
        if(!program)throw std::runtime_error("The owned program marker is missing; installation files were retained for review.");
        bool owned=PendingRemoval();if(state&&Exists(Join(StateDirectory(),L"host.bin")))owned=LoadConfig().driverOwned;
        Notify(progress,10,L"Stopping remote sessions, the host service and virtual input devices...");StopService(progress,true);result.restartRequired=ServiceQuery(ServiceName,true).pendingDelete;Notify(progress,25,L"Removing only this host's private LAN firewall rule...");Firewall(false);
        bool pending=false;
        if(removeOwnedDriver&&owned){Notify(progress,40,L"Removing the Vdevice package installed by this host. Shared Vdevice applications may need it.");std::wstring verifiedClock;try{(void)ClockRegistration(verifiedClock,false);}catch(const std::exception& error){Notify(progress,42,L"Clock ownership preflight: "+Wide(error.what()));}
            const auto removed=Driver(L"/uninstall",progress);if(removed.code!=0&&removed.code!=3010)throw std::runtime_error("Vdevice removal failed (Windows "+std::to_string(removed.code)+"). "+Utf8(removed.output));result.restartRequired=result.restartRequired||removed.code==3010;
            pending=DriverPackagesRemain();if(!pending){try{result.restartRequired=ClockRegistration(verifiedClock,true)||result.restartRequired;}catch(const std::exception& error){result.message+=L"\nClock registration retained: "+Wide(error.what());result.restartRequired=true;}}
        }
        Notify(progress,75,L"Removing owned configuration and application files; Windows audit/setup journals are preserved...");
        const auto roomKey=RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl");if(roomKey!=ERROR_SUCCESS&&roomKey!=ERROR_FILE_NOT_FOUND&&roomKey!=ERROR_PATH_NOT_FOUND)throw std::runtime_error(WindowsError("Remove owned local host identity",roomKey));
        if(state){for(const auto* name:StateFiles)result.restartRequired=RemoveFile(Join(StateDirectory(),name))||result.restartRequired;result.restartRequired=RemoveOwnedDirectory(StateDirectory(),result.message)||result.restartRequired;}
        if(pending){WriteAtomic(Join(ProgramDirectory(),Pending),Bytes(PendingBytes));result.restartRequired=RemoveFile(Join(ProgramDirectory(),HostExe))||result.restartRequired;Apps(true);result.restartRequired=true;result.message=L"Host service, remote access and configuration removed. Windows still retains the owned Vdevice package. Restart Windows, reopen this installer and choose Uninstall to finish cleanup."+result.message;}
        else{Apps(false);for(const auto* name:ProgramFiles)result.restartRequired=RemoveFile(Join(ProgramDirectory(),name))||result.restartRequired;result.restartRequired=RemoveOwnedDirectory(ProgramDirectory(),result.message)||result.restartRequired;result.message=std::wstring(L"Remote host service, firewall rule, configuration, Apps entry and owned application files removed.")+(owned&&removeOwnedDriver?L" Vdevice removal requested.":L" Existing/shared Vdevice installation preserved.")+result.message;}
        result.code=result.restartRequired?3010:0;if(result.restartRequired)result.message+=L"\nRestart Windows to release the resident demo clock and any locked package/files. Windows event and setup logs remain.";Notify(progress,100,result.message);
    }catch(const std::exception& error){result.code=1;result.message=L"Uninstall did not complete: "+Wide(error.what());Notify(progress,100,result.message);}return result;
}
void SelfTest(){const auto driver=Resource(301),host=Resource(302);if(driver.size()<4096||host.size()<4096||!OwnedLeaf(HostExe)||OwnedLeaf(L"..\\other.exe")||!ServiceImageMatches(L"\"C:\\Program Files\\TitanCSA\\RemoteDeviceControl\\RemoteDeviceHost.exe\" --service",L"C:\\Program Files\\TitanCSA\\RemoteDeviceControl\\RemoteDeviceHost.exe"))throw std::runtime_error("Offline setup/resource checks failed.");}
void RequestRestart(){HANDLE raw=nullptr;Require(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&raw)!=FALSE,"Open restart privilege token");Handle token;token.value=raw;TOKEN_PRIVILEGES privileges{};privileges.PrivilegeCount=1;Require(LookupPrivilegeValueW(nullptr,SE_SHUTDOWN_NAME,&privileges.Privileges[0].Luid)!=FALSE,"Read restart privilege");privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(ERROR_SUCCESS);Require(AdjustTokenPrivileges(token.value,FALSE,&privileges,0,nullptr,nullptr)!=FALSE&&GetLastError()==ERROR_SUCCESS,"Enable restart privilege");Require(ExitWindowsEx(EWX_REBOOT|EWX_RESTARTAPPS,SHTDN_REASON_MAJOR_APPLICATION|SHTDN_REASON_MINOR_INSTALLATION|SHTDN_REASON_FLAG_PLANNED)!=FALSE,"Restart Windows");}
}
