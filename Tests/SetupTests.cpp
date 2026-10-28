#include "../Source/Setup.h"
#include "../Source/Config.h"
#include <netfw.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cstring>
namespace {
void Field(std::vector<uint8_t>& bytes,const std::string& value){const auto size=static_cast<uint32_t>(value.size());const auto raw=reinterpret_cast<const uint8_t*>(&size);bytes.insert(bytes.end(),raw,raw+4);bytes.insert(bytes.end(),value.begin(),value.end());}
std::vector<uint8_t> Legacy(const RemoteControl::Config& config,unsigned version=1,const std::string& port="48761"){
 std::vector<uint8_t> bytes{'R','D','C',static_cast<uint8_t>('0'+version)};
 Field(bytes,RemoteControl::Utf8(config.host));Field(bytes,"wss://example.invalid/retired-relay");Field(bytes,port);Field(bytes,config.secret);Field(bytes,config.room);Field(bytes,std::string(64,'3'));
 if(version==2)Field(bytes,std::string(64,'4'));bytes.push_back(1);bytes.push_back(config.driverOwned?1:0);
 if(version==2){bytes.push_back(config.noCode?1:0);bytes.push_back(config.requireApproval?1:0);uint32_t count=3;auto raw=reinterpret_cast<const uint8_t*>(&count);bytes.insert(bytes.end(),raw,raw+4);}
 bytes.insert(bytes.end(),{'P','F','X'});return bytes;
}
}
int main(){try{
 using namespace RemoteControl::Setup;using namespace RemoteControl;unsigned checks=0;
 const auto check=[&](bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);};
 for(const wchar_t* name:{L"RemoteDeviceHost.exe",L"VdeviceSetupConsole.exe",L"RemoteDeviceControlSetup.exe",L"ownership.txt",L"pending-removal.txt",L"host.bin",L"host.bin.new"})check(OwnedLeaf(name),"Owned file missing from allow-list");
 for(const wchar_t* name:{L"",L"..",L"..\\RemoteDeviceHost.exe",L"C:\\Windows\\system32\\kernel32.dll",L"RemoteDeviceHost.exe:stream",L"other.exe",L"ownership.txt\\child",L"RemoteDeviceHost.exe ",L"remoteDeviceHost.exe"})check(!OwnedLeaf(name),"Unsafe/unowned file accepted");
 const std::wstring exe=L"C:\\Program Files\\TitanCSA\\RemoteDeviceControl\\RemoteDeviceHost.exe";
 check(Quote(exe)==L"\""+exe+L"\"","Service path quoting");check(ServiceImageMatches(Quote(exe)+L" --service",exe),"Exact service identity rejected");
 check(ServiceImageMatches(L"\"c:\\program files\\titancsa\\remotedevicecontrol\\remotedevicehost.exe\" --service",exe),"Case-insensitive Windows service path rejected");
 for(const std::wstring& command:std::vector<std::wstring>{exe+L" --service",Quote(exe),Quote(exe)+L" --service extra",L"\"C:\\Other\\RemoteDeviceHost.exe\" --service",Quote(exe)+L" --agent",Quote(exe)+L" --service\n"})check(!ServiceImageMatches(command,exe),"Foreign or unquoted service identity accepted");
 for(const std::wstring& bad:std::vector<std::wstring>{L"",L"a\"b",L"a\nb",L"a\rb",L"C:\\path\\",std::wstring(L"a\0b",3)}){bool refused=false;try{(void)Quote(bad);}catch(const std::invalid_argument&){refused=true;}check(refused,"Unsafe command argument accepted");}
 check(bool(Result{}),"Success status");Result restart;restart.code=3010;restart.restartRequired=true;check(bool(restart),"Restart success status");Result error;error.code=5;check(!error,"Failure status");
 const auto lan=FirewallPlan(false,true);check(lan.size()==3,"LAN rules missing");check(lan[0].ports==L"48784,48789,48810"&&lan[0].protocol==NET_FW_IP_PROTOCOL_TCP,"GameStream TCP ports differ");check(lan[1].ports==L"48798,48799,48800,48802"&&lan[1].protocol==NET_FW_IP_PROTOCOL_UDP,"GameStream UDP ports differ");
 for(const auto& rule:lan)check(rule.remoteAddresses==L"LocalSubnet"&&rule.profiles==(NET_FW_PROFILE2_PRIVATE|NET_FW_PROFILE2_DOMAIN),"Default rule exposes public network");
 const auto online=FirewallPlan(true,true);check(online[0].profiles==NET_FW_PROFILE2_ALL&&online[0].remoteAddresses==L"*"&&online[1].profiles==NET_FW_PROFILE2_ALL,"Explicit Internet streaming scope missing");check(online[2].profiles==(NET_FW_PROFILE2_PRIVATE|NET_FW_PROFILE2_DOMAIN)&&online[2].remoteAddresses==L"LocalSubnet"&&online[2].ports==L"48762","Discovery exposed outside local subnet");
 check(online[0].application.find(L"\\Engine\\sunshine.exe")!=std::wstring::npos&&online[2].application.find(L"\\RemoteDeviceHost.exe")!=std::wstring::npos,"Firewall image binding differs");check(FirewallPlan(false,false).size()==2,"Disabled discovery still has a rule");
 for(uint16_t port:{uint16_t(0),uint16_t(1023),uint16_t(65515),uint16_t(65535)}){bool refused=false;try{(void)FirewallPlan(false,true,port);}catch(...){refused=true;}check(refused,"Overflowing/invalid streaming base port accepted");}
 check(FirewallPlan(false,false,65514)[0].ports==L"65509,65514,65535","Maximum base port arithmetic differs");
 Config config;config.host=L"192.0.2.1";config.secret=std::string(32,'1');config.room=std::string(32,'2');const std::string pin(64,'a');
 for(unsigned bits=0;bits<16;++bits){config.internet=(bits&1)!=0;config.driverOwned=(bits&2)!=0;config.noCode=(bits&4)!=0;config.requireApproval=(bits&8)!=0;auto restored=ConfigFormat::Decode(ConfigFormat::Encode(config));check(restored.internet==config.internet&&restored.driverOwned==config.driverOwned&&restored.noCode==config.noCode&&restored.requireApproval==config.requireApproval&&restored.port==48789&&restored.secret==config.secret&&restored.room==config.room,"Direct config flags changed on roundtrip");}
 for(unsigned version:{1u,2u}){const auto migrated=ConfigFormat::Decode(Legacy(config,version));check(!migrated.internet&&migrated.port==48789&&migrated.driverOwned==config.driverOwned&&migrated.secret==config.secret&&migrated.room==config.room,"Legacy relay settings enabled UPnP or changed driver/private credentials");if(version==1)check(!migrated.noCode&&migrated.requireApproval,"Legacy private-access defaults changed");}
 const auto encoded=ConfigFormat::Encode(config);
 const auto refuse=[&](const std::vector<uint8_t>& bytes){bool rejected=false;try{(void)ConfigFormat::Decode(bytes);}catch(...){rejected=true;}check(rejected,"Malformed direct config accepted");};
 for(size_t size=0;size<encoded.size();++size)refuse({encoded.begin(),encoded.begin()+static_cast<ptrdiff_t>(size)});
 auto changed=encoded;changed.push_back(0);refuse(changed);changed=encoded;changed[3]='9';refuse(changed);
 size_t at=4;for(unsigned i=0;i<4;++i){uint32_t size=0;memcpy(&size,encoded.data()+at,4);at+=4+size;}
 for(unsigned flag=0;flag<4;++flag){changed=encoded;changed[at+flag]=2;refuse(changed);}
 for(const char* port:{"0","65536","+123"," 80","1.0","48761x"})refuse(Legacy(config,1,port));
 auto unsafe=config;unsafe.secret=OpenAccessSecret;bool rejected=false;try{(void)ConfigFormat::Encode(unsafe);}catch(...){rejected=true;}check(rejected,"Public token replaced private host secret");
 const auto pairing=ParsePairing(PairingCode(config,pin));check(!pairing.noCode&&pairing.secret==config.secret&&pairing.pin==pin&&pairing.port==48789,"Private direct code lost certificate/secret");
 for(const auto* address:{L"192.0.2.2",L"example.invalid:48789",L"[2001:db8::1]:48789"}){const auto direct=ParseDirectAddress(address);check(direct.noCode&&direct.secret==OpenAccessSecret&&direct.port==48789,"Explicit direct-address public mode differs");}
 std::cout<<"PASS "<<checks<<" setup ownership, direct migration, policy bounds and firewall-plan checks; no installation, service or firewall mutation.\n";return 0;
 }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
