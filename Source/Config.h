#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <string_view>
namespace RemoteControl {
constexpr wchar_t ServiceName[]=L"RemoteDeviceControlHost";
constexpr wchar_t ProductName[]=L"Remote Device Control";
// Accepted only when the host administrator explicitly enables public access.
constexpr char OpenAccessSecret[]="00000000000000000000000000000000";
struct Config {
 std::wstring host=L"127.0.0.1";
 // Sunshine HTTP base. HTTPS = base-5, RTSP = base+21; media uses UDP.
 uint16_t port=48789;bool internet=false,driverOwned=false,noCode=false,requireApproval=true;
 std::string secret,room;
};
std::wstring ProgramDirectory();std::wstring StateDirectory();
void ProtectDirectory(const std::wstring& path);
void CheckProtectedDirectory(const std::wstring& path);
void CheckPlain(const std::wstring& path,bool directory=false);
Config NewConfig();void SaveConfig(const Config&);Config LoadConfig();
namespace ConfigFormat { // Pure bounded codec; no DPAPI, files or registry access.
std::vector<uint8_t> Encode(const Config&);Config Decode(const std::vector<uint8_t>&);
}
std::wstring PairingCode(const Config&,const std::string& fingerprint);
struct Pairing {std::string host,pin,secret,room;uint16_t port=48789;bool noCode=false;};
Pairing ParsePairing(const std::wstring&);
Pairing ParseDirectAddress(const std::wstring&);
std::wstring EngineDirectory();std::wstring EngineStateDirectory();
std::string EngineFingerprint();
std::wstring Wide(const std::string&);std::string Utf8(const std::wstring&);
}
