#include "../Source/VirtualInput.h"
#include <iostream>
#include <stdexcept>

namespace {
unsigned checks=0;
void Check(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
unsigned Word(const std::vector<uint8_t>& report,size_t offset){return unsigned(report[offset])|(unsigned(report[offset+1])<<8);}
}
int main(){
    try{
        using namespace RemoteControl;using namespace RemoteControl::InputProtocol;
        const auto keyboard=KeyboardConfig(),mouse=MouseConfig();
        Check(bool(Vdevice::Validate_Device(keyboard)),"Offline keyboard descriptor validation failed");
        Check(bool(Vdevice::Validate_Device(mouse)),"Offline absolute pointer descriptor validation failed");
        Check(keyboard.input_depth==32&&mouse.input_depth==32,"Queues must remain bounded");
        HidState state;auto report=KeyboardReport(state);Check(report.size()==29,"NKRO report size");
        for(unsigned code=4;code<=231;++code)Apply(state,{InputKind::Key,0,0,code,1});
        report=KeyboardReport(state);Check(report[0]==255,"All modifier bits retained");
        for(unsigned code=4;code<224;++code)Check((report[1+code/8]&(1u<<(code%8)))!=0,"NKRO lost a key");
        Check((report[1]&15)==0,"Reserved error usages must stay released");
        for(unsigned code=4;code<=231;++code)Apply(state,{InputKind::Key,0,0,code,0});
        for(auto byte:KeyboardReport(state))Check(byte==0,"Key release was lost");
        for(unsigned button=1;button<=5;++button)Apply(state,{InputKind::Button,0,0,button,1});
        Check(MouseReport(state)[0]==31,"Five mouse buttons");
        Apply(state,{InputKind::Wheel,-127,127,0,0});report=MouseReport(state);
        Check(report[5]==127&&report[6]==129,"Signed wheel and horizontal pan");
        unsigned previous=0;
        for(int coordinate=0;coordinate<=65535;++coordinate){
            Apply(state,{InputKind::Pointer,coordinate,65535-coordinate,0,0});report=MouseReport(state);
            const auto x=Word(report,1),y=Word(report,3);
            Check(x<=32767&&y<=32767,"Absolute HID range");
            Check(x>=previous,"Absolute mapping must be monotonic");previous=x;
        }
        Check(Word(MouseReport(state),1)==32767&&Word(MouseReport(state),3)==0,"Absolute endpoints");
        Apply(state,{InputKind::ReleaseAll,0,0,0,0});report=MouseReport(state);
        Check(report[0]==0&&report[5]==0&&report[6]==0,"Neutral pointer must release buttons and wheels");
        Check(Word(report,1)==32767&&Word(report,3)==0,"Neutral must preserve pointer position");
        for(const Input bad: {Input{InputKind::Pointer,-1,0,0,0},Input{InputKind::Pointer,0,65536,0,0},
             Input{InputKind::Button,0,0,6,1},Input{InputKind::Button,0,0,1,2},Input{InputKind::Key,0,0,3,1},
             Input{InputKind::Key,0,0,232,1},Input{InputKind::Wheel,128,0,0,0},Input{InputKind::ReleaseAll,1,0,0,0},
             Input{static_cast<InputKind>(99),0,0,0,0}}){
            Check(!Valid(bad),"Invalid input accepted");const auto before=KeyboardReport(state);bool rejected=false;
            try{Apply(state,bad);}catch(const std::invalid_argument&){rejected=true;}
            Check(rejected&&KeyboardReport(state)==before,"Invalid input mutated state");
        }
        Check(UsageFromScan(0x1e,false)==4,"A scan mapping");Check(UsageFromScan(0x10,false)==0x14,"Q scan mapping");
        Check(UsageFromScan(0x1d,false)==0xe0&&UsageFromScan(0x1d,true)==0xe4,"Left/right control mapping");
        Check(UsageFromScan(0x1c,false)==0x28&&UsageFromScan(0x1c,true)==0x58,"Enter/keypad enter mapping");
        Check(UsageFromScan(0x48,false)==0x60&&UsageFromScan(0x48,true)==0x52,"Keypad/navigation distinction");
        Check(UsageFromScan(0x5b,true)==0xe3&&UsageFromScan(0x5c,true)==0xe7,"Windows modifiers mapping");
        Check(UsageFromScan(0x76,false)==0x73,"F24 mapping");
        Check(UsageFromScan(999,false)==0&&UsageFromScan(0,true)==0,"Unsupported scan handling");
        // Construct/destruct without Start must never open the driver or create a device.
        {VirtualInput input;Check(!input.Running(),"Input started before authentication");input.Release();input.Stop();}
        std::cout<<"PASS: "<<checks<<" offline descriptor, NKRO, pointer, input-bounds and scan-map checks; no driver opened.\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
