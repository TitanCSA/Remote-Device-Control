#include "../Source/Setup.h"
#include "../Source/Config.h"
#include "../Source/Transport.h"
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>
namespace {
void Field(std::vector<uint8_t>& bytes,const std::string& value){const auto size=static_cast<uint32_t>(value.size());const auto raw=reinterpret_cast<const uint8_t*>(&size);bytes.insert(bytes.end(),raw,raw+4);bytes.insert(bytes.end(),value.begin(),value.end());}
std::vector<uint8_t> Legacy(const RemoteControl::Config& c,const std::string& port="48761"){
    std::vector<uint8_t> bytes{'R','D','C','1'};Field(bytes,RemoteControl::Utf8(c.host));Field(bytes,RemoteControl::Utf8(c.relay));Field(bytes,port);Field(bytes,c.secret);Field(bytes,c.room);Field(bytes,c.relayToken);bytes.push_back(c.internet?1:0);bytes.push_back(c.driverOwned?1:0);bytes.insert(bytes.end(),c.identity.begin(),c.identity.end());return bytes;
}
}
int main(){
    try{
        using namespace RemoteControl::Setup;unsigned checks=0;
        auto check=[&](bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);};
        for(const wchar_t* name:{L"RemoteDeviceHost.exe",L"VdeviceSetupConsole.exe",L"RemoteDeviceControlSetup.exe",L"ownership.txt",L"pending-removal.txt",L"host.bin",L"host.bin.new"})check(OwnedLeaf(name),"Owned file missing from allow-list");
        for(const wchar_t* name:{L"",L"..",L"..\\RemoteDeviceHost.exe",L"C:\\Windows\\system32\\kernel32.dll",L"RemoteDeviceHost.exe:stream",L"other.exe",L"ownership.txt\\child",L"RemoteDeviceHost.exe ",L"remoteDeviceHost.exe"})check(!OwnedLeaf(name),"Unsafe/unowned file accepted");
        const std::wstring exe=L"C:\\Program Files\\TitanCSA\\RemoteDeviceControl\\RemoteDeviceHost.exe";
        check(Quote(exe)==L"\""+exe+L"\"","Service path quoting");
        check(ServiceImageMatches(Quote(exe)+L" --service",exe),"Exact service identity rejected");
        check(ServiceImageMatches(L"\"c:\\program files\\titancsa\\remotedevicecontrol\\remotedevicehost.exe\" --service",exe),"Case-insensitive Windows service path rejected");
        for(const std::wstring& command:std::vector<std::wstring>{exe+L" --service",Quote(exe),Quote(exe)+L" --service extra",L"\"C:\\Other\\RemoteDeviceHost.exe\" --service",Quote(exe)+L" --agent",Quote(exe)+L" --service\n"})check(!ServiceImageMatches(command,exe),"Foreign or unquoted service identity accepted");
        for(const std::wstring& bad:std::vector<std::wstring>{L"",L"a\"b",L"a\nb",L"a\rb",L"C:\\path\\",std::wstring(L"a\0b",3)}){bool refused=false;try{(void)Quote(bad);}catch(const std::invalid_argument&){refused=true;}check(refused,"Unsafe command argument accepted");}
        check(bool(Result{}),"Success status");Result restart;restart.code=3010;restart.restartRequired=true;check(bool(restart),"Restart success status");Result error;error.code=5;check(!error,"Failure status");
        using namespace RemoteControl;TitanTransport::Identity original;Config c;c.host=L"192.0.2.1";c.secret=std::string(32,'1');c.room=std::string(32,'2');c.relayToken=std::string(64,'3');c.directoryOwner=std::string(64,'4');c.identity=original.Export();
        check(PublicRoom(c.directoryOwner)=="f435f2420b50c70ec80865cf8e20b169","Public room SHA-256 ASCII test vector");
        check(PublicRoom(c.directoryOwner)!=PublicRoom(std::string(64,'5')),"Different private owners must derive different public rooms");
        for(const auto& owner:std::vector<std::string>{"",std::string(63,'a'),std::string(65,'a'),std::string(64,'g'),std::string(64,'A')}){bool invalidOwner=false;try{(void)PublicRoom(owner);}catch(const std::exception&){invalidOwner=true;}check(invalidOwner,"Invalid private directory owner accepted");}
        for(unsigned flags=0;flags<16;++flags){
            c.internet=(flags&1)!=0;c.driverOwned=(flags&2)!=0;c.noCode=(flags&4)!=0;c.requireApproval=(flags&8)!=0;
            c.room=c.noCode?PublicRoom(c.directoryOwner):std::string(32,'2');
            const auto restored=ConfigFormat::Decode(ConfigFormat::Encode(c));
            check(restored.host==c.host&&restored.relay==c.relay&&restored.port==c.port,"Config addresses changed on roundtrip");
            check(restored.secret==c.secret&&restored.room==c.room&&restored.relayToken==c.relayToken&&restored.directoryOwner==c.directoryOwner,"Private configuration credentials changed");
            check(restored.internet==c.internet&&restored.driverOwned==c.driverOwned&&restored.noCode==c.noCode&&restored.requireApproval==c.requireApproval,"Access-policy flags changed on roundtrip");
            check(restored.identity==c.identity,"Full PFX bytes changed on roundtrip");
        }
        auto old=c;old.room=std::string(32,'2');old.noCode=false;const auto migrated=ConfigFormat::Decode(Legacy(old));check(!migrated.noCode&&migrated.requireApproval&&migrated.directoryOwner.empty(),"Legacy config must retain protected access defaults");check(migrated.identity==old.identity&&migrated.secret==old.secret&&migrated.internet==old.internet&&migrated.room==old.room,"Legacy identity, room or settings changed");
        auto upgraded=migrated;upgraded.directoryOwner=c.directoryOwner;const auto protectedCode=PairingCode(upgraded,original.Fingerprint());check(ConfigFormat::Decode(ConfigFormat::Encode(upgraded)).room==migrated.room,"Protected legacy room changed during owner migration");
        upgraded.noCode=true;bool invalidRoom=false;try{(void)ConfigFormat::Encode(upgraded);}catch(const std::exception&){invalidRoom=true;}check(invalidRoom,"Public mode accepted a room unrelated to its owner");
        upgraded.room=PublicRoom(upgraded.directoryOwner);check(ConfigFormat::Decode(ConfigFormat::Encode(upgraded)).room==PublicRoom(c.directoryOwner),"Public opt-in did not derive the authenticated room");check(PairingCode(upgraded,original.Fingerprint())!=protectedCode&&upgraded.directoryOwner==c.directoryOwner&&upgraded.secret==migrated.secret,"Public migration must invalidate the old connection code without changing private owner/secret");
        TitanTransport::Identity reimported(migrated.identity);check(reimported.Fingerprint()==original.Fingerprint(),"Legacy migration changed the pinned TLS identity");
        const auto encoded=ConfigFormat::Encode(c);const auto refused=[&](const std::vector<uint8_t>& bytes){bool invalid=false;try{(void)ConfigFormat::Decode(bytes);}catch(const std::exception&){invalid=true;}check(invalid,"Malformed protected configuration accepted");};
        for(size_t size=0;size<encoded.size();++size)refused(std::vector<uint8_t>(encoded.begin(),encoded.begin()+static_cast<ptrdiff_t>(size)));
        auto changed=encoded;changed.push_back(0);refused(changed);changed=encoded;changed[3]='9';refused(changed);
        changed=encoded;const auto publicRoom=std::search(changed.begin(),changed.end(),c.room.begin(),c.room.end());check(publicRoom!=changed.end(),"Public-room fixture was not encoded");*publicRoom=*publicRoom=='a'?'b':'a';refused(changed);
        size_t at=4;for(unsigned field=0;field<7;++field){uint32_t size=0;memcpy(&size,encoded.data()+at,4);at+=4+size;}
        for(unsigned flag=0;flag<4;++flag){changed=encoded;changed[at+flag]=2;refused(changed);}
        changed=encoded;changed[at+4]=0;changed[at+5]=changed[at+6]=changed[at+7]=0;refused(changed);
        for(const char* port:{"0","65536","+123"," 80","1.0","48761x"})refused(Legacy(c,port));
        auto unsafe=c;unsafe.secret=OpenAccessSecret;bool invalid=false;try{(void)ConfigFormat::Encode(unsafe);}catch(const std::exception&){invalid=true;}check(invalid,"Public access token must not replace the private host secret");
        auto privatePairing=ParsePairing(PairingCode(c,original.Fingerprint()));check(!privatePairing.noCode&&privatePairing.secret==c.secret,"Public mode must preserve the private connection code");check(PairingCode(c,original.Fingerprint()).find(Wide(c.directoryOwner))==std::wstring::npos,"Private directory owner leaked into connection code");
        const auto publicPairing=ParsePairing(PairingCode(unsafe,original.Fingerprint()));check(publicPairing.noCode&&publicPairing.secret==OpenAccessSecret,"Public connection must remain explicitly identified");
        std::cout<<"PASS: "<<checks<<" offline setup ownership, config migration/bounds, access-policy and TLS identity checks; no installation, service or firewall mutation.\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
