#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
namespace RemoteControl {
constexpr wchar_t ServiceName[]=L"RemoteDeviceControlHost";
constexpr wchar_t ProductName[]=L"Remote Device Control";
struct Config {
 std::wstring host=L"127.0.0.1",relay=L"wss://licences.configcsa.com/remote-device-control/relay";
 uint16_t port=48761;bool internet=true,driverOwned=false;
 std::string secret,room,relayToken;std::vector<uint8_t> identity;
};
std::wstring ProgramDirectory();std::wstring StateDirectory();
void ProtectDirectory(const std::wstring& path);
void CheckProtectedDirectory(const std::wstring& path);
void CheckPlain(const std::wstring& path,bool directory=false);
Config NewConfig();void SaveConfig(const Config&);Config LoadConfig();
std::wstring PairingCode(const Config&,const std::string& fingerprint);
struct Pairing {std::string host,pin,secret,room,relayToken;std::wstring relay;uint16_t port=0;};
Pairing ParsePairing(const std::wstring&);
std::wstring Wide(const std::string&);std::string Utf8(const std::wstring&);
}
