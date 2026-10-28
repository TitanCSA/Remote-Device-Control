#include "VirtualInput.h"
#include <windows.h>
#include <cfgmgr32.h>
#include <objbase.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace RemoteControl {
namespace {
std::wstring SessionSerial(const wchar_t* prefix){
    GUID id{};const auto result=CoCreateGuid(&id);
    if(FAILED(result))throw std::runtime_error(WindowsError("Generate private virtual input instance",static_cast<uint32_t>(result)));
    wchar_t text[40]{};if(!StringFromGUID2(id,text,40))throw std::runtime_error("Format virtual input instance identity failed.");
    std::wstring serial(prefix);for(const auto c:text)if((c>=L'0'&&c<=L'9')||(c>=L'A'&&c<=L'F')||(c>=L'a'&&c<=L'f'))serial.push_back(c);
    return serial;
}
void SetSerial(Vdevice::Device_Config& config,const std::wstring& serial){
    for(auto& descriptor:config.descriptors)if(descriptor.kind==Vdevice::Descriptor_Kind::Standard&&descriptor.index==3&&descriptor.language==0x409){
        descriptor.data={static_cast<uint8_t>(2+serial.size()*2),3};
        for(const auto c:serial){descriptor.data.push_back(static_cast<uint8_t>(c));descriptor.data.push_back(static_cast<uint8_t>(c>>8));}return;
    }
    throw std::runtime_error("The virtual input serial descriptor is missing.");
}
std::wstring DeviceProperty(DEVINST node,ULONG property){
    wchar_t value[1024]{};ULONG bytes=sizeof(value),type=0;
    if(CM_Get_DevNode_Registry_PropertyW(node,property,&type,value,&bytes,0)!=CR_SUCCESS||type!=REG_SZ)return {};
    value[1023]=0;return value;
}
bool ChildReady(DEVINST node,const wchar_t* target,unsigned depth,unsigned& budget,std::string& reason){
    if(depth>4||!budget)return false;--budget;
    const auto deviceClass=DeviceProperty(node,CM_DRP_CLASSGUID);
    if(_wcsicmp(deviceClass.c_str(),target)==0){
        ULONG status=0,problem=0;const auto result=CM_Get_DevNode_Status(&status,&problem,node,0);
        if(result==CR_SUCCESS&&(status&DN_STARTED)&&!(status&DN_HAS_PROBLEM)&&!problem)return true;
        const auto service=DeviceProperty(node,CM_DRP_SERVICE);std::string serviceText;
        for(const auto c:service)serviceText.push_back(c>=32&&c<=126?static_cast<char>(c):'?');
        reason="Windows HID class child is not started (PnP problem "+std::to_string(problem)+", status "+std::to_string(status)+", service "+(serviceText.empty()?"unassigned":serviceText)+"). Check the installed keyboard/mouse driver or conflicting filters.";
        return false;
    }
    DEVINST child=0;if(CM_Get_Child(&child,node,0)!=CR_SUCCESS)return false;
    do{if(ChildReady(child,target,depth+1,budget,reason))return true;DEVINST next=0;if(CM_Get_Sibling(&next,child,0)!=CR_SUCCESS)break;child=next;}while(budget);
    return false;
}
bool ClassReady(const std::wstring& serial,bool keyboard,std::string& reason){
    std::wstring instance=keyboard?L"USB\\VID_FFFF&PID_0021\\":L"USB\\VID_FFFF&PID_0022\\";instance+=serial;
    DEVINST parent=0;const auto result=CM_Locate_DevNodeW(&parent,instance.data(),CM_LOCATE_DEVNODE_NORMAL);
    if(result!=CR_SUCCESS){reason=keyboard?"Windows has not enumerated the owned remote keyboard.":"Windows has not enumerated the owned remote pointer.";return false;}
    unsigned budget=32;reason=keyboard?"Windows has not created the owned keyboard class child.":"Windows has not created the owned mouse class child.";
    return ChildReady(parent,keyboard?L"{4D36E96B-E325-11CE-BFC1-08002BE10318}":L"{4D36E96F-E325-11CE-BFC1-08002BE10318}",0,budget,reason);
}
}
uint32_t UsageFromScan(uint32_t scan,bool extended) noexcept {
    if(scan>255)return 0;
    if(extended){
        switch(scan){
        case 0x1c:return 0x58;case 0x1d:return 0xe4;case 0x35:return 0x54;
        case 0x37:return 0x46;case 0x38:return 0xe6;case 0x45:return 0x53;
        case 0x46:return 0x48;case 0x47:return 0x4a;case 0x48:return 0x52;
        case 0x49:return 0x4b;case 0x4b:return 0x50;case 0x4d:return 0x4f;
        case 0x4f:return 0x4d;case 0x50:return 0x51;case 0x51:return 0x4e;
        case 0x52:return 0x49;case 0x53:return 0x4c;case 0x5b:return 0xe3;
        case 0x5c:return 0xe7;case 0x5d:return 0x65;default:return 0;
        }
    }
    static constexpr uint8_t table[128]={
        0,0x29,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x2d,0x2e,0x2a,0x2b,
        0x14,0x1a,0x08,0x15,0x17,0x1c,0x18,0x0c,0x12,0x13,0x2f,0x30,0x28,0xe0,0x04,0x16,
        0x07,0x09,0x0a,0x0b,0x0d,0x0e,0x0f,0x33,0x34,0x35,0xe1,0x31,0x1d,0x1b,0x06,0x19,
        0x05,0x11,0x10,0x36,0x37,0x38,0xe5,0x55,0xe2,0x2c,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,
        0x3f,0x40,0x41,0x42,0x43,0x53,0x47,0x5f,0x60,0x61,0x56,0x5c,0x5d,0x5e,0x57,0x59,
        0x5a,0x5b,0x62,0x63,0,0,0x64,0x44,0x45,0,0,0,0,0,0,0,
        0,0,0,0,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0,
        0,0,0,0,0,0,0x73,0,0,0,0,0,0,0,0,0
    };
    return scan<128?table[scan]:0;
}

namespace InputProtocol {
namespace {
Vdevice::Descriptor String(uint32_t index,const std::u16string& text){
    Vdevice::Descriptor result;result.index=index;result.language=0x409;
    result.data={static_cast<uint8_t>(2+text.size()*2),3};
    for(char16_t character:text){result.data.push_back(static_cast<uint8_t>(character));result.data.push_back(static_cast<uint8_t>(character>>8));}
    return result;
}
Vdevice::Device_Config Configuration(std::vector<uint8_t> report,uint16_t pid,uint8_t packet,const std::u16string& product,const std::u16string& serial){
    Vdevice::Device_Config config;config.input_depth=32;
    Vdevice::Descriptor device;device.data={18,1,0,2,0,0,0,64,0xff,0xff,static_cast<uint8_t>(pid),static_cast<uint8_t>(pid>>8),0,1,1,2,3,1};
    Vdevice::Descriptor hid;hid.kind=Vdevice::Descriptor_Kind::Report;hid.data=std::move(report);
    Vdevice::Descriptor usb;usb.data={9,2,34,0,1,1,0,0x80,50,9,4,0,0,1,3,0,0,0,
        9,0x21,0x11,1,0,1,0x22,static_cast<uint8_t>(hid.data.size()),static_cast<uint8_t>(hid.data.size()>>8),
        7,5,0x81,3,packet,0,1};
    Vdevice::Descriptor languages;languages.data={4,3,9,4};
    config.descriptors={std::move(device),std::move(usb),std::move(hid),std::move(languages),
        String(1,u"Remote Device Control"),String(2,product),String(3,serial)};
    return config;
}
void Put16(std::vector<uint8_t>& report,size_t offset,uint16_t value){report[offset]=static_cast<uint8_t>(value);report[offset+1]=static_cast<uint8_t>(value>>8);}
uint16_t Absolute(uint16_t value) noexcept {return static_cast<uint16_t>((static_cast<uint32_t>(value)*32767u+32767u)/65535u);}
void KeyboardBytes(const HidState& state,std::vector<uint8_t>& report){
    report[0]=state.keys[28];std::copy_n(state.keys.begin(),28,report.begin()+1);
}
void MouseBytes(const HidState& state,std::vector<uint8_t>& report){
    report[0]=state.buttons;Put16(report,1,Absolute(state.x));Put16(report,3,Absolute(state.y));
    report[5]=static_cast<uint8_t>(state.wheel);report[6]=static_cast<uint8_t>(state.pan);
}
}
bool Valid(const Input& input) noexcept {
    switch(input.kind){
    case InputKind::Pointer:return input.x>=0&&input.x<=65535&&input.y>=0&&input.y<=65535&&!input.code&&!input.down;
    case InputKind::Button:return input.code>=1&&input.code<=5&&input.down<=1&&!input.x&&!input.y;
    case InputKind::Key:return input.code>=4&&input.code<=231&&input.down<=1&&!input.x&&!input.y;
    case InputKind::Wheel:return input.x>=-127&&input.x<=127&&input.y>=-127&&input.y<=127&&!input.code&&!input.down;
    case InputKind::ReleaseAll:return !input.x&&!input.y&&!input.code&&!input.down;
    default:return false;
    }
}
void Neutral(HidState& state) noexcept {state.keys.fill(0);state.buttons=0;state.wheel=state.pan=0;}
void Apply(HidState& state,const Input& input){
    if(!Valid(input))throw std::invalid_argument("Invalid bounded virtual HID input.");
    switch(input.kind){
    case InputKind::Pointer:state.x=static_cast<uint16_t>(input.x);state.y=static_cast<uint16_t>(input.y);break;
    case InputKind::Button:{const auto bit=static_cast<uint8_t>(1u<<(input.code-1));if(input.down)state.buttons|=bit;else state.buttons&=static_cast<uint8_t>(~bit);break;}
    case InputKind::Key:{auto& byte=state.keys[input.code/8];const auto bit=static_cast<uint8_t>(1u<<(input.code%8));if(input.down)byte|=bit;else byte&=static_cast<uint8_t>(~bit);break;}
    case InputKind::Wheel:state.pan=static_cast<int8_t>(input.x);state.wheel=static_cast<int8_t>(input.y);break;
    case InputKind::ReleaseAll:Neutral(state);break;
    default:break;
    }
}
Vdevice::Device_Config KeyboardConfig(){
    // Modifier bitmap followed by 224 ordinary key bits: no six-key rollover.
    return Configuration({0x05,1,0x09,6,0xa1,1,0x05,7,0x19,0xe0,0x29,0xe7,0x15,0,0x25,1,
        0x75,1,0x95,8,0x81,2,0x05,8,0x19,1,0x29,5,0x95,5,0x91,2,0x95,3,0x91,1,
        0x05,7,0x19,0,0x29,0xdf,0x95,0xe0,0x81,2,0xc0},0x21,32,u"Remote NKRO keyboard",u"RDC-Keyboard-1");
}
Vdevice::Device_Config MouseConfig(){
    return Configuration({0x05,1,0x09,2,0xa1,1,0x09,1,0xa1,0,0x05,9,0x19,1,0x29,5,
        0x15,0,0x25,1,0x95,5,0x75,1,0x81,2,0x95,1,0x75,3,0x81,1,
        0x05,1,0x09,0x30,0x09,0x31,0x15,0,0x26,0xff,0x7f,0x75,16,0x95,2,0x81,2,
        0x09,0x38,0x15,0x81,0x25,0x7f,0x75,8,0x95,1,0x81,6,
        0x05,0x0c,0x0a,0x38,2,0x81,6,0xc0,0xc0},0x22,8,u"Remote absolute pointer",u"RDC-Pointer-1");
}
std::vector<uint8_t> KeyboardReport(const HidState& state){std::vector<uint8_t> report(29);KeyboardBytes(state,report);return report;}
std::vector<uint8_t> MouseReport(const HidState& state){std::vector<uint8_t> report(7);MouseBytes(state,report);return report;}
}

struct VirtualInput::Impl {
    mutable std::mutex mutex;std::condition_variable changed;std::thread worker;
    Vdevice::Device keyboard,mouse;InputProtocol::HidState state;
    std::vector<uint8_t> keyboardReport=std::vector<uint8_t>(29),mouseReport=std::vector<uint8_t>(7);
    std::atomic<bool> stopping{true},running{false};std::atomic<uint64_t> remaining{0};
    bool ready=false,mouseUsed=false;std::string failure;
    static std::string Diagnostic(const char* operation,const Vdevice::Result& result){return std::string(operation)+": "+result.message+" (Windows error "+std::to_string(result.error)+").";}
    void Fail(const char* text) noexcept {running=false;stopping=true;ready=false;try{if(failure.empty())failure=text;}catch(...){}changed.notify_all();}
    void Fail(const std::string& text) noexcept {Fail(text.c_str());}
    bool SendKeyboard(){InputProtocol::KeyboardBytes(state,keyboardReport);const auto sent=Vdevice::Send_Input(keyboard,0x81,keyboardReport);if(!sent){Fail(Diagnostic("Send virtual keyboard report",sent));return false;}return true;}
    bool SendMouse(){InputProtocol::MouseBytes(state,mouseReport);const auto sent=Vdevice::Send_Input(mouse,0x81,mouseReport);state.wheel=state.pan=0;if(!sent){Fail(Diagnostic("Send virtual pointer report",sent));return false;}return true;}
    void Cleanup() noexcept {
        try{
            InputProtocol::Neutral(state);
            if(keyboard){InputProtocol::KeyboardBytes(state,keyboardReport);(void)Vdevice::Send_Input(keyboard,0x81,keyboardReport);}
            if(mouse&&mouseUsed){InputProtocol::MouseBytes(state,mouseReport);(void)Vdevice::Send_Input(mouse,0x81,mouseReport);}
            if(keyboard)(void)Vdevice::Delete_Device(keyboard);if(mouse)(void)Vdevice::Delete_Device(mouse);
            keyboard=Vdevice::Device{};mouse=Vdevice::Device{};
        }catch(...){keyboard=Vdevice::Device{};mouse=Vdevice::Device{};}
        ready=false;running=false;mouseUsed=false;changed.notify_all();
    }
    void Run() noexcept {
        try{
            auto nextStatus=std::chrono::steady_clock::now();
            while(!stopping){
                const auto output=Vdevice::Get_Output(100);
                if(!output&&!output.timed_out){std::lock_guard<std::mutex> guard(mutex);Fail(Diagnostic("Read virtual HID output",output));break;}
                if(output&&output.kind==Vdevice::Output_Kind::Control){
                    const auto responded=Vdevice::Respond_Output(output,{},true);
                    if(!responded&&responded.error!=1168){std::lock_guard<std::mutex> guard(mutex);Fail(Diagnostic("Complete virtual HID control",responded));break;}
                }
                const auto now=std::chrono::steady_clock::now();
                if(now<nextStatus&&(!output||output.kind!=Vdevice::Output_Kind::DeviceState))continue;
                nextStatus=now+std::chrono::milliseconds(250);
                const auto info=Vdevice::Get_Info();remaining=info.trial_remaining_100ns;
                std::lock_guard<std::mutex> guard(mutex);
                if(stopping)break;
                if(!info){Fail(Diagnostic("Read Vdevice state",info));break;}
                if(info.trial_expired){Fail("The shared one-hour Vdevice demo has expired. Restart Windows for a new demo allowance.");break;}
                if(info.quiescing||info.removing){Fail("Vdevice is stopping or being removed. Restart Windows if requested by its installer.");break;}
                bool keyboardReady=false,mouseReady=false;
                for(const auto& device:info.devices){
                    if(device.id==keyboard.Id())keyboardReady=device.plugged&&device.configured&&device.powered&&!device.error;
                    if(device.id==mouse.Id())mouseReady=device.plugged&&device.configured&&device.powered&&!device.error;
                }
                if(ready&&(!keyboardReady||!mouseReady)){Fail("A remote virtual input device was disconnected or stopped by Windows.");break;}
                if(keyboardReady&&mouseReady){ready=true;running=true;changed.notify_all();}
            }
        }catch(const std::exception& error){std::lock_guard<std::mutex> guard(mutex);Fail(error.what());}
        catch(...){std::lock_guard<std::mutex> guard(mutex);Fail("Unexpected virtual input worker error.");}
        std::lock_guard<std::mutex> guard(mutex);Cleanup();
    }
};
VirtualInput::VirtualInput():impl_(std::make_unique<Impl>()){}
VirtualInput::~VirtualInput(){Stop();}
void VirtualInput::Start(){
    Stop();
    const auto info=Vdevice::Get_Info();
    if(!info)throw std::runtime_error(Impl::Diagnostic("Open Vdevice; install the demo and run the host service as SYSTEM",info));
    if(info.trial_expired)throw std::runtime_error("The shared one-hour Vdevice demo has expired. Restart Windows for a new demo allowance.");
    if(info.quiescing||info.removing)throw std::runtime_error("Vdevice is stopping or requires a Windows restart.");
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
    const auto keyboardSerial=SessionSerial(L"RDC-K-"),mouseSerial=SessionSerial(L"RDC-M-");
    auto keyboardConfig=InputProtocol::KeyboardConfig(),mouseConfig=InputProtocol::MouseConfig();
    SetSerial(keyboardConfig,keyboardSerial);SetSerial(mouseConfig,mouseSerial);
    try{
        std::lock_guard<std::mutex> guard(impl_->mutex);impl_->failure.clear();impl_->state={};impl_->ready=false;impl_->mouseUsed=false;
        impl_->keyboard=Vdevice::Create_Device(keyboardConfig);
        if(!impl_->keyboard){const auto message="Create remote keyboard: "+impl_->keyboard.message+" (Windows error "+std::to_string(impl_->keyboard.error)+").";impl_->Cleanup();throw std::runtime_error(message);}
        impl_->mouse=Vdevice::Create_Device(mouseConfig);
        if(!impl_->mouse){const auto message="Create remote pointer: "+impl_->mouse.message+" (Windows error "+std::to_string(impl_->mouse.error)+").";impl_->Cleanup();throw std::runtime_error(message);}
        impl_->remaining=info.trial_remaining_100ns;impl_->stopping=false;
    }catch(...){Stop();throw;}
    try{impl_->worker=std::thread([this]{impl_->Run();});}catch(...){Stop();throw;}
    std::unique_lock<std::mutex> guard(impl_->mutex);
    const bool signaled=impl_->changed.wait_until(guard,deadline,[&]{return impl_->ready||!impl_->failure.empty()||impl_->stopping.load();});
    if(!signaled||!impl_->ready){
        const auto error=impl_->failure.empty()?"Windows did not configure the remote virtual keyboard and mouse within 15 seconds.":impl_->failure;
        guard.unlock();Stop();throw std::runtime_error(error);
    }
    guard.unlock();
    try{
        // USB configured/powered alone does not establish that kbdhid/mouhid
        // started. Inspect only these random per-capture instances, once at
        // startup; report broken third-party class drivers without altering them.
        std::string reason;
        do{
            if(!impl_->running||impl_->stopping){const auto error=Error();throw std::runtime_error(error.empty()?"Virtual input stopped during Windows class-driver setup.":error);}
            if(ClassReady(keyboardSerial,true,reason)&&ClassReady(mouseSerial,false,reason))return;
            if(std::chrono::steady_clock::now()>=deadline)break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }while(true);
        throw std::runtime_error("Remote input setup failed: "+reason);
    }catch(...){Stop();throw;}
}
void VirtualInput::Apply(const Input& input){
    if(!InputProtocol::Valid(input))throw std::invalid_argument("Invalid bounded virtual HID input.");
    std::lock_guard<std::mutex> guard(impl_->mutex);
    if(!impl_->running||impl_->stopping)throw std::runtime_error(impl_->failure.empty()?"Remote virtual input devices are not ready.":impl_->failure);
    try{
        InputProtocol::Apply(impl_->state,input);bool sent=true;
        if(input.kind==InputKind::Key||input.kind==InputKind::ReleaseAll)sent=impl_->SendKeyboard();
        if(input.kind==InputKind::Pointer||input.kind==InputKind::Button||input.kind==InputKind::Wheel){impl_->mouseUsed=true;sent=sent&&impl_->SendMouse();}
        else if(input.kind==InputKind::ReleaseAll&&impl_->mouseUsed)sent=sent&&impl_->SendMouse();
        if(!sent)throw std::runtime_error(impl_->failure.empty()?"Virtual HID transmission failed.":impl_->failure);
    }catch(...){impl_->stopping=true;impl_->Cleanup();throw;}
}
void VirtualInput::Release() noexcept {
    try{std::lock_guard<std::mutex> guard(impl_->mutex);InputProtocol::Neutral(impl_->state);
        if(impl_->running&&!impl_->stopping){const bool sent=impl_->SendKeyboard();if(impl_->mouseUsed)(void)impl_->SendMouse();if(!sent||impl_->stopping)impl_->Cleanup();}}
    catch(...){impl_->stopping=true;impl_->running=false;}
}
void VirtualInput::Stop() noexcept {
    impl_->stopping=true;impl_->changed.notify_all();
    if(impl_->worker.joinable())impl_->worker.join();
    std::lock_guard<std::mutex> guard(impl_->mutex);impl_->Cleanup();
}
bool VirtualInput::Running() const noexcept {return impl_->running.load();}
uint64_t VirtualInput::Remaining100ns() const noexcept {return impl_->remaining.load();}
std::string VirtualInput::Error() const {std::lock_guard<std::mutex> guard(impl_->mutex);return impl_->failure;}
}
