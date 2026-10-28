// Remote Device Control's Vdevice-only Windows input backend for the pinned
// Sunshine fork. No SendInput, SetCursorPos, ViGEm or libvirtualhid fallback.
#include "src/platform/common.h"
#include "src/globals.h"
#include "src/logging.h"
#include "RdcVdevice.h"
#include "RdcKeyMap.h"
#include "../../Source/VirtualInput.h"
#include <windows.h>
#include <objbase.h>
#include <wtsapi32.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <thread>
#include "src/platform/windows/keylayout.h"

namespace {
std::string Environment(const char* key){const char* text=std::getenv(key);return text?text:"";}
std::wstring WideEnvironment(const wchar_t* key){wchar_t value[32768]{};const DWORD count=GetEnvironmentVariableW(key,value,32768);return count&&count<32768?std::wstring(value,count):std::wstring{};}
bool Hex(std::string_view text,size_t length){if(text.size()!=length)return false;for(char c:text)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true;}
bool Equal(std::string_view a,std::string_view b){if(a.size()!=b.size())return false;unsigned difference=0;for(size_t i=0;i<a.size();++i)difference|=static_cast<unsigned char>(a[i])^static_cast<unsigned char>(b[i]);return difference==0;}
bool Named(HANDLE object,const wchar_t* name){wchar_t text[128]{};DWORD needed=0;return GetUserObjectInformationW(object,UOI_NAME,text,sizeof(text),&needed)&&_wcsicmp(text,name)==0;}
bool Desktop(){
    DWORD session=0;if(!ProcessIdToSessionId(GetCurrentProcessId(),&session)||!session||session!=WTSGetActiveConsoleSessionId())return false;
    LPWSTR data=nullptr;DWORD count=0;bool unlocked=false;
    if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&data,&count)){auto info=reinterpret_cast<WTSINFOEXW*>(data);unlocked=count>=sizeof(WTSINFOEXW)&&info->Level==1&&info->Data.WTSInfoExLevel1.SessionState==WTSActive&&info->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_UNLOCK;WTSFreeMemory(data);}
    if(!unlocked)return false;HDESK desktop=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS);if(!desktop)return false;const bool allowed=Named(desktop,L"Default");CloseDesktop(desktop);return allowed;
}
std::string Json(std::string_view text){std::string result="\"";for(unsigned char c:text){if(c=='"'||c=='\\')result+='\\';if(c>=32&&c<127)result+=static_cast<char>(c);else result+=' ';if(result.size()>512)break;}return result+'"';}
struct Policy {
    const std::string secret=Environment("RDC_ACCESS_SECRET"),noCode=Environment("RDC_NO_CODE"),approval=Environment("RDC_REQUIRE_APPROVAL");
    const bool valid=Hex(secret,32)&&(noCode=="0"||noCode=="1")&&(approval=="0"||approval=="1");
};
Vdevice::Device_Config RelativeConfig(std::wstring& serial){
    auto config=RemoteControl::InputProtocol::MouseConfig();
    const std::vector<uint8_t> report={0x05,1,0x09,2,0xa1,1,0x09,1,0xa1,0,0x05,9,0x19,1,0x29,5,0x15,0,0x25,1,0x95,5,0x75,1,0x81,2,0x95,1,0x75,3,0x81,1,0x05,1,0x09,0x30,0x09,0x31,0x16,1,0x80,0x26,0xff,0x7f,0x75,16,0x95,2,0x81,6,0x09,0x38,0x15,0x81,0x25,0x7f,0x75,8,0x95,1,0x81,6,0x05,0x0c,0x0a,0x38,2,0x81,6,0xc0,0xc0};
    GUID id{};if(FAILED(CoCreateGuid(&id)))throw std::runtime_error("Generate the owned relative mouse identity failed.");wchar_t guid[40]{};StringFromGUID2(id,guid,40);serial=L"RDC-R-";for(const auto c:guid)if((c>=L'0'&&c<=L'9')||(c>=L'A'&&c<=L'F'))serial+=c;
    for(auto& descriptor:config.descriptors){
        if(descriptor.kind==Vdevice::Descriptor_Kind::Report)descriptor.data=report;
        else if(descriptor.data.size()==18&&descriptor.data[1]==1)descriptor.data[10]=0x23;
        else if(descriptor.data.size()==34&&descriptor.data[1]==2){descriptor.data[25]=static_cast<uint8_t>(report.size());descriptor.data[26]=0;}
        else if(descriptor.index==3&&descriptor.language==0x409){descriptor.data={static_cast<uint8_t>(2+serial.size()*2),3};for(const auto c:serial){descriptor.data.push_back(static_cast<uint8_t>(c));descriptor.data.push_back(static_cast<uint8_t>(c>>8));}}
    }
    return config;
}
class Backend {
public:
    const Policy policy;RemoteControl::VirtualInput input;
    std::mutex mutex;std::condition_variable wake;std::thread maintenance;std::atomic<bool> stopping{false},active{false};
    bool reserved=false,claimed=false;uint64_t deadline=0,nextApproval=0;Vdevice::Device relative;
    std::vector<uint8_t> report=std::vector<uint8_t>(7);int wheel=0,pan=0;std::string error,clientIdentity;std::wstring relativeSerial;
    const std::wstring statusPath=WideEnvironment(L"RDC_STATUS_FILE"),stopName=WideEnvironment(L"RDC_STOP_EVENT");HANDLE stopEvent=nullptr;
    Backend(){if(!stopName.empty()&&stopName.rfind(L"Global\\RDC-EngineStop-",0)==0)stopEvent=OpenEventW(SYNCHRONIZE,FALSE,stopName.c_str());maintenance=std::thread([this]{Maintain();});}
    ~Backend(){stopping=true;wake.notify_all();if(maintenance.joinable())maintenance.join();{std::lock_guard<std::mutex> lock(mutex);StopLocked();}if(stopEvent)CloseHandle(stopEvent);}
    void Shutdown()noexcept{try{mail::man->event<bool>(mail::shutdown)->raise(true);}catch(...){}}
    void StopLocked()noexcept{
        active=false;try{if(relative){report.assign(7,0);(void)Vdevice::Send_Input(relative,0x81,report);(void)Vdevice::Delete_Device(relative);}relative=Vdevice::Device{};input.Stop();}catch(...){}reserved=claimed=false;clientIdentity.clear();deadline=0;wheel=pan=0;report.assign(7,0);wake.notify_all();
    }
    void Snapshot(bool force=false)noexcept{
        if(statusPath.empty())return;
        try{static uint64_t last=0;static std::string previous;const uint64_t now=GetTickCount64();std::string body;
            {std::lock_guard<std::mutex> lock(mutex);body="{\"busy\":"+std::string(reserved?"true":"false")+",\"remaining_100ns\":"+std::to_string(input.Remaining100ns())+",\"ready\":"+(policy.valid&&(!reserved||input.Running())?"true":"false")+",\"error\":"+Json(error)+"}";}
            if(!force&&now-last<1000&&body==previous)return;if(!force&&now-last<1000)return;
            const auto temp=statusPath+L".tmp";HANDLE file=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);if(file==INVALID_HANDLE_VALUE)return;DWORD written=0;const bool sent=WriteFile(file,body.data(),static_cast<DWORD>(body.size()),&written,nullptr)&&written==body.size()&&FlushFileBuffers(file);CloseHandle(file);if(sent&&MoveFileExW(temp.c_str(),statusPath.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){last=now;previous=std::move(body);}else DeleteFileW(temp.c_str());
        }catch(...){}
    }
    void Maintain()noexcept{
        while(!stopping){
            if(stopEvent&&WaitForSingleObject(stopEvent,0)==WAIT_OBJECT_0){Shutdown();break;}
            bool failed=false;{
                std::lock_guard<std::mutex> lock(mutex);
                if(reserved&&deadline&&GetTickCount64()>=deadline&&!claimed){error="The remote client did not start its stream before the reservation expired.";StopLocked();}
                if(claimed&&(!input.Running()||!Desktop())){error=input.Error();if(error.empty())error="The interactive desktop or Vdevice input is no longer available.";StopLocked();failed=true;}
            }
            Snapshot();if(failed){Shutdown();break;}
            std::unique_lock<std::mutex> lock(mutex);wake.wait_for(lock,std::chrono::milliseconds(100),[this]{return stopping.load();});
        }
    }
    void Relative(int x,int y,int vertical=0,int horizontal=0){
        if(!active)return;std::lock_guard<std::mutex> lock(mutex);if(!active||!relative)return;
        const auto put=[&](size_t at,int value){const auto word=static_cast<uint16_t>(static_cast<int16_t>(std::clamp(value,-32767,32767)));report[at]=static_cast<uint8_t>(word);report[at+1]=static_cast<uint8_t>(word>>8);};put(1,x);put(3,y);report[5]=static_cast<uint8_t>(std::clamp(vertical,-127,127));report[6]=static_cast<uint8_t>(std::clamp(horizontal,-127,127));
        const auto sent=Vdevice::Send_Input(relative,0x81,report);if(!sent){error="Vdevice relative mouse input failed: "+sent.message;StopLocked();Shutdown();}
    }
    void Apply(RemoteControl::Input value){if(!active)return;try{input.Apply(value);}catch(const std::exception& failure){std::lock_guard<std::mutex> lock(mutex);error=failure.what();StopLocked();Shutdown();}}
};
Backend& Engine(){static Backend backend;return backend;}
}
namespace rdc {
bool pairing_allowed(std::string_view secret)noexcept{try{const auto& policy=Engine().policy;if(!policy.valid||!Hex(secret,32))return false;return Equal(secret,policy.secret)||(policy.noCode=="1"&&Equal(secret,"00000000000000000000000000000000"));}catch(...){return false;}}
bool busy()noexcept{try{auto& backend=Engine();std::lock_guard<std::mutex> lock(backend.mutex);return backend.reserved;}catch(...){return true;}}
bool owns_session(std::string_view identity)noexcept{try{auto& backend=Engine();std::lock_guard<std::mutex> lock(backend.mutex);return backend.reserved&&Equal(identity,backend.clientIdentity);}catch(...){return false;}}
bool authorize_launch(std::string_view identity,std::string& error)noexcept{
    Backend* owner=nullptr;bool reservedHere=false;try{auto& backend=Engine();owner=&backend;
        {std::lock_guard<std::mutex> lock(backend.mutex);if(!backend.policy.valid||!Hex(identity,64))throw std::runtime_error("The managed host access policy or client certificate identity is invalid.");if(backend.reserved)throw std::runtime_error("This PC is busy with another controller or connection request.");if(GetTickCount64()<backend.nextApproval)throw std::runtime_error("A recent connection request was declined. Try again in a few seconds.");if(!Desktop())throw std::runtime_error("Sign in and unlock the target PC before connecting.");backend.reserved=true;backend.clientIdentity=identity;reservedHere=true;backend.error.clear();}
        if(backend.policy.noCode=="1"&&backend.policy.approval=="1"){
            std::wstring title=L"Remote Device Control - connection request",message=L"A remote viewer wants to see your desktop and control your keyboard and mouse.\n\nAllow this connection? Choose No if you are not expecting it.";DWORD response=IDNO;
            if(!WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE,WTSGetActiveConsoleSessionId(),title.data(),static_cast<DWORD>(title.size()*2),message.data(),static_cast<DWORD>(message.size()*2),MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2|MB_TOPMOST,25,&response,TRUE)||response!=IDYES){std::lock_guard<std::mutex> lock(backend.mutex);backend.nextApproval=GetTickCount64()+10000;throw std::runtime_error("The target PC declined the connection request or did not approve it within 25 seconds.");}
        }
        std::lock_guard<std::mutex> lock(backend.mutex);if(backend.stopping||!Desktop()||(backend.stopEvent&&WaitForSingleObject(backend.stopEvent,0)==WAIT_OBJECT_0))throw std::runtime_error("The target desktop changed while preparing this connection.");
        backend.input.Start();backend.relative=Vdevice::Create_Device(RelativeConfig(backend.relativeSerial));if(!backend.relative)throw std::runtime_error("Create the owned relative mouse: "+backend.relative.message);
        const auto deadline=GetTickCount64()+10000;bool ready=false;uint64_t primeTarget=0;
        do{const auto info=Vdevice::Get_Info();if(!info)throw std::runtime_error("Read Vdevice relative mouse state: "+info.message);for(const auto& device:info.devices)if(device.id==backend.relative.Id()){ready=device.plugged&&device.configured&&device.powered&&!device.error;primeTarget=device.inputs_accepted+1;}if(ready)break;if(!backend.input.Running())throw std::runtime_error(backend.input.Error());std::this_thread::sleep_for(std::chrono::milliseconds(25));}while(GetTickCount64()<deadline);
        if(!ready)throw std::runtime_error("Windows did not configure the owned relative mouse within ten seconds.");
        // A configured USB node may precede the Windows class reader. Prime
        // only with a neutral relative report: no movement, button or wheel.
        const auto prime=Vdevice::Send_Input(backend.relative,0x81,backend.report);
        if(!prime)throw std::runtime_error("Prime the owned relative mouse reader: "+prime.message);
        ready=false;std::string readerReason="Windows has not published the owned relative mouse input interface.";
        do{const auto info=Vdevice::Get_Info();if(!info)throw std::runtime_error("Read relative mouse consumption readiness: "+info.message);for(const auto& device:info.devices)if(device.id==backend.relative.Id())ready=device.plugged&&device.configured&&device.powered&&!device.error&&device.inputs_completed>=primeTarget;if(ready)ready=RemoteControl::RawInputDeviceReady(L"USB\\VID_FFFF&PID_0023\\"+backend.relativeSerial,false,readerReason);if(ready)break;if(!backend.input.Running()||!Desktop()||(backend.stopEvent&&WaitForSingleObject(backend.stopEvent,0)==WAIT_OBJECT_0))throw std::runtime_error("The interactive desktop changed while waiting for its mouse reader.");std::this_thread::sleep_for(std::chrono::milliseconds(25));}while(GetTickCount64()<deadline);
        if(!ready)throw std::runtime_error("Windows did not begin reading the owned relative mouse within ten seconds: "+readerReason);
        backend.deadline=GetTickCount64()+15000;return true;
    }catch(const std::exception& failure){error=failure.what();if(owner&&reservedHere){std::lock_guard<std::mutex> lock(owner->mutex);owner->error=error;owner->StopLocked();}return false;}catch(...){error="The target could not prepare virtual input due to a local resource error.";if(owner&&reservedHere){std::lock_guard<std::mutex> lock(owner->mutex);owner->error=error;owner->StopLocked();}return false;}
}
void cancel_launch()noexcept{try{auto& backend=Engine();std::lock_guard<std::mutex> lock(backend.mutex);backend.StopLocked();}catch(...){}}
void stream_started()noexcept{try{auto& backend=Engine();std::lock_guard<std::mutex> lock(backend.mutex);if(!backend.reserved||!backend.input.Running()){backend.Shutdown();return;}backend.claimed=true;backend.active=true;backend.deadline=0;}catch(...){}}
void stream_ended()noexcept{cancel_launch();}
}
namespace platf {
struct RdcInput {};
input_t input(){(void)Engine();return input_t{new RdcInput{}};}
void freeInput(void* input){rdc::cancel_launch();delete static_cast<RdcInput*>(input);}
struct RdcClient:client_input_t {RdcClient(){rdc::stream_started();}~RdcClient()override{rdc::stream_ended();}};
std::unique_ptr<client_input_t> allocate_client_input_context(input_t&){return std::make_unique<RdcClient>();}
util::point_t get_mouse_loc(input_t&){POINT point{};GetCursorPos(&point);return {static_cast<double>(point.x),static_cast<double>(point.y)};}
void move_mouse(input_t&,int x,int y){Engine().Relative(x,y);}
void abs_mouse(input_t&,const touch_port_t& port,float x,float y){if(!port.width||!port.height||!std::isfinite(x)||!std::isfinite(y))return;const auto normal=[](float value,float span){return static_cast<int>(std::clamp(std::lround(value*65535.0/span),0l,65535l));};RemoteControl::Input input{};input.kind=RemoteControl::InputKind::Pointer;input.x=normal(x,static_cast<float>(port.width));input.y=normal(y,static_cast<float>(port.height));Engine().Apply(input);}
void button_mouse(input_t&,int button,bool release){if(button<1||button>5)return;auto& backend=Engine();if(!backend.active)return;{std::lock_guard<std::mutex> lock(backend.mutex);const unsigned bit=button==2?2:button==3?1:static_cast<unsigned>(button-1);if(release)backend.report[0]&=static_cast<uint8_t>(~(1u<<bit));else backend.report[0]|=static_cast<uint8_t>(1u<<bit);}backend.Relative(0,0);}
void scroll(input_t&,int amount){auto& backend=Engine();int ticks=0;{std::lock_guard<std::mutex> lock(backend.mutex);backend.wheel+=amount;ticks=backend.wheel/120;backend.wheel%=120;}if(ticks)backend.Relative(0,0,ticks);}
void hscroll(input_t&,int amount){auto& backend=Engine();int ticks=0;{std::lock_guard<std::mutex> lock(backend.mutex);backend.pan+=amount;ticks=backend.pan/120;backend.pan%=120;}if(ticks)backend.Relative(0,0,0,ticks);}
void keyboard_update(input_t&,uint16_t key,bool release,uint8_t flags){const auto mapped=rdc::MapKey(key,flags);const uint32_t usage=mapped.usage?mapped.usage:RemoteControl::UsageFromScan(mapped.scan,mapped.extended);if(!usage)return;RemoteControl::Input input{};input.kind=RemoteControl::InputKind::Key;input.code=usage;input.down=release?0:1;Engine().Apply(input);}
void unicode(input_t&,char*,int){/* Raw HID carries physical keys, not arbitrary text injection. */}
int alloc_gamepad(input_t&,const gamepad_id_t&,const gamepad_arrival_t&,feedback_queue_t){return -1;}
void free_gamepad(input_t&,int){}
void gamepad_update(input_t&,int,const gamepad_state_t&){}
void gamepad_touch(input_t&,const gamepad_touch_t&){}
void gamepad_motion(input_t&,const gamepad_motion_t&){}
void gamepad_battery(input_t&,const gamepad_battery_t&){}
void touch_update(client_input_t*,const touch_port_t&,const touch_input_t&){}
void pen_update(client_input_t*,const touch_port_t&,const pen_input_t&){}
platform_caps::caps_t get_capabilities(){return 0;}
std::vector<supported_gamepad_t>& supported_gamepads(input_t*){static std::vector<supported_gamepad_t> disabled{{"disabled",false,"Only Vdevice keyboard and mouse are supported by this application."}};return disabled;}
}
