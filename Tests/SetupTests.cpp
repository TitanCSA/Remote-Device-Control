#include "../Source/Setup.h"
#include <iostream>
#include <stdexcept>
#include <vector>
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
        std::cout<<"PASS: "<<checks<<" offline setup ownership/command/status checks; no installation, service or firewall mutation.\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
