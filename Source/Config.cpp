#include "Config.h"
#include "Protocol.h"
#include "Transport.h"
#include <shlobj.h>
#include <sddl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <cstring>
namespace RemoteControl {
namespace {
std::wstring Folder(REFKNOWNFOLDERID id){PWSTR value=nullptr;HRESULT hr=SHGetKnownFolderPath(id,0,nullptr,&value);if(FAILED(hr))throw std::runtime_error("Windows standard folder lookup failed.");std::wstring path(value);CoTaskMemFree(value);return path;}
void Require(bool ok,const char* op){if(!ok)throw std::runtime_error(WindowsError(op,GetLastError()));}
void Append(std::vector<uint8_t>& out,const std::string& text){uint32_t n=static_cast<uint32_t>(text.size());auto p=reinterpret_cast<const uint8_t*>(&n);out.insert(out.end(),p,p+4);out.insert(out.end(),text.begin(),text.end());}
std::string Take(const std::vector<uint8_t>& in,size_t& at,size_t max){if(at+4>in.size())throw std::runtime_error("Truncated host configuration.");uint32_t n=0;memcpy(&n,in.data()+at,4);at+=4;if(n>max||n>in.size()-at)throw std::runtime_error("Invalid host configuration field.");std::string text(reinterpret_cast<const char*>(in.data()+at),n);at+=n;return text;}
struct Wipe {std::vector<uint8_t>& bytes;~Wipe(){if(!bytes.empty())SecureZeroMemory(bytes.data(),bytes.size());}};
uint16_t Port(const std::string& value){unsigned number=0;if(value.empty()||value.size()>5)throw std::runtime_error("Invalid host port.");for(const auto c:value){if(c<'0'||c>'9')throw std::runtime_error("Invalid host port.");number=number*10+static_cast<unsigned>(c-'0');}if(!number||number>65535)throw std::runtime_error("Invalid host port.");return static_cast<uint16_t>(number);}
void ValidateConfig(const Config& c){
 const auto host=Utf8(c.host);
 if(host.empty()||host.size()>255||host.find_first_of("/\\ ;\r\n\t\0",0,9)!=std::string::npos)throw std::runtime_error("Invalid direct host address.");
 if(c.port<1024||c.port>65514||!TitanTransport::IsSecret(c.secret)||c.secret==OpenAccessSecret||!TitanTransport::IsSecret(c.room))throw std::runtime_error("Invalid direct host configuration.");
}
bool TrustedParentWriter(PSID sid){
 if(IsWellKnownSid(sid,WinLocalSystemSid)||IsWellKnownSid(sid,WinBuiltinAdministratorsSid))return true;
 BYTE trusted[SECURITY_MAX_SID_SIZE]{};wchar_t domain[256]{};DWORD sidSize=sizeof(trusted),domainSize=256;SID_NAME_USE use{};
 return LookupAccountNameW(nullptr,L"NT SERVICE\\TrustedInstaller",trusted,&sidSize,domain,&domainSize,&use)&&EqualSid(sid,trusted);
}
void SafeParent(const std::wstring& path){
 PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;DWORD error=GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor);if(error)throw std::runtime_error(WindowsError("Inspect shared parent permissions",error));
 bool safe=owner&&dacl&&(IsWellKnownSid(owner,WinLocalSystemSid)||IsWellKnownSid(owner,WinBuiltinAdministratorsSid));
 if(dacl)for(DWORD i=0;i<dacl->AceCount;++i){void* item=nullptr;if(!GetAce(dacl,i,&item)){safe=false;break;}auto h=static_cast<ACE_HEADER*>(item);if(h->AceType!=ACCESS_ALLOWED_ACE_TYPE||(h->AceFlags&INHERIT_ONLY_ACE))continue;auto ace=static_cast<ACCESS_ALLOWED_ACE*>(item);PSID sid=&ace->SidStart;constexpr DWORD write=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|FILE_DELETE_CHILD|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;if((ace->Mask&write)&&!TrustedParentWriter(sid))safe=false;}
 LocalFree(descriptor);if(!safe)throw std::runtime_error("The shared installation parent is writable by an unprivileged account; installation was refused.");
}
}
std::wstring Wide(const std::string& value){if(value.empty())return {};int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);if(!n)throw std::runtime_error("Invalid UTF-8 text.");std::wstring out(static_cast<size_t>(n),0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),n);return out;}
std::string Utf8(const std::wstring& value){if(value.empty())return {};int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);if(!n)throw std::runtime_error("Invalid Unicode text.");std::string out(static_cast<size_t>(n),0);WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),n,nullptr,nullptr);return out;}
std::wstring ProgramDirectory(){return Folder(FOLDERID_ProgramFiles)+L"\\TitanCSA\\RemoteDeviceControl";}
std::wstring StateDirectory(){return Folder(FOLDERID_ProgramData)+L"\\TitanCSA\\RemoteDeviceControl";}
void CheckPlain(const std::wstring& path,bool directory){
 std::filesystem::path p(path);for(auto current=p;!current.empty()&&current!=current.root_path();current=current.parent_path()){
  DWORD attr=GetFileAttributesW(current.c_str());if(attr==INVALID_FILE_ATTRIBUTES)throw std::runtime_error(WindowsError("Inspect owned path",GetLastError()));if(attr&FILE_ATTRIBUTE_REPARSE_POINT)throw std::runtime_error("Redirected installation/configuration paths are refused.");
 }
 DWORD attr=GetFileAttributesW(path.c_str());if(attr==INVALID_FILE_ATTRIBUTES||bool(attr&FILE_ATTRIBUTE_DIRECTORY)!=directory)throw std::runtime_error("Unexpected owned installation path type.");
}
void CheckProtectedDirectory(const std::wstring& path){
 CheckPlain(path,true);PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
 DWORD error=GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor);if(error)throw std::runtime_error(WindowsError("Read protected directory security",error));
 SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;GetSecurityDescriptorControl(descriptor,&control,&revision);
 bool program=_wcsicmp(path.c_str(),ProgramDirectory().c_str())==0;
 bool ownerValid=owner&&(IsWellKnownSid(owner,WinLocalSystemSid)||IsWellKnownSid(owner,WinBuiltinAdministratorsSid));bool valid=ownerValid&&dacl&&(dacl->AceCount==2||(program&&dacl->AceCount==3))&&(control&SE_DACL_PROTECTED);
 if(dacl){for(DWORD i=0;i<dacl->AceCount;++i){void* item=nullptr;if(!GetAce(dacl,i,&item)){valid=false;break;}auto header=static_cast<ACE_HEADER*>(item);if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE){valid=false;break;}auto ace=static_cast<ACCESS_ALLOWED_ACE*>(item);PSID sid=&ace->SidStart;if(!IsWellKnownSid(sid,WinLocalSystemSid)&&!IsWellKnownSid(sid,WinBuiltinAdministratorsSid)){constexpr DWORD write=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|FILE_DELETE_CHILD|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;if(!program||!IsWellKnownSid(sid,WinBuiltinUsersSid)||(ace->Mask&write)){valid=false;break;}}}}
 LocalFree(descriptor);if(!valid)throw std::runtime_error("The existing host directory has an unsafe owner or access policy; no files were changed.");
}
void ProtectDirectory(const std::wstring& path){
 std::filesystem::path p(path);
 if(!std::filesystem::exists(p.parent_path()))ProtectDirectory(p.parent_path().wstring());
 CheckPlain(p.parent_path().wstring(),true);
 if(p.parent_path().filename()==L"TitanCSA")SafeParent(p.parent_path().wstring());
 bool program=_wcsicmp(path.c_str(),ProgramDirectory().c_str())==0;
 PSECURITY_DESCRIPTOR descriptor=nullptr;Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(program?L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)":L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"Protected directory ACL");
 SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};BOOL created=CreateDirectoryW(path.c_str(),&security);DWORD error=GetLastError();LocalFree(descriptor);if(!created&&error!=ERROR_ALREADY_EXISTS)throw std::runtime_error(WindowsError("Create owned directory",error));
 if(created){BYTE sid[SECURITY_MAX_SID_SIZE]{};DWORD size=sizeof(sid);Require(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&size)!=FALSE,"Owner identity");DWORD changed=SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,sid,nullptr,nullptr,nullptr);if(changed)throw std::runtime_error(WindowsError("Protect directory owner",changed));}CheckProtectedDirectory(path);
 if(program&&!created){PSECURITY_DESCRIPTOR updated=nullptr;Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",SDDL_REVISION_1,&updated,nullptr)!=FALSE,"Program read policy");BOOL ok=SetFileSecurityW(path.c_str(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,updated);DWORD status=GetLastError();LocalFree(updated);if(!ok)throw std::runtime_error(WindowsError("Apply read-only program access",status));}
}
Config NewConfig(){Config c;
 ULONG size=16384;std::vector<uint8_t> addresses(size);ULONG status=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_GATEWAYS,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(addresses.data()),&size);if(status==ERROR_BUFFER_OVERFLOW&&size<1024*1024){addresses.resize(size);status=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_GATEWAYS,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(addresses.data()),&size);}
 if(status==NO_ERROR){for(auto adapter=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(addresses.data());adapter;adapter=adapter->Next){if(adapter->OperStatus!=IfOperStatusUp||!adapter->FirstGatewayAddress||(adapter->IfType!=IF_TYPE_ETHERNET_CSMACD&&adapter->IfType!=IF_TYPE_IEEE80211))continue;for(auto address=adapter->FirstUnicastAddress;address;address=address->Next){if(address->Address.lpSockaddr->sa_family!=AF_INET)continue;wchar_t text[INET_ADDRSTRLEN]{};auto ip=reinterpret_cast<sockaddr_in*>(address->Address.lpSockaddr);if(InetNtopW(AF_INET,&ip->sin_addr,text,INET_ADDRSTRLEN)){c.host=text;break;}}if(c.host!=L"127.0.0.1")break;}}
 c.secret=TitanTransport::RandomSecret();c.room=TitanTransport::RandomSecret();return c;}
namespace ConfigFormat {
std::vector<uint8_t> Encode(const Config& c){
 ValidateConfig(c);std::vector<uint8_t> raw{'R','D','C','3'};Append(raw,Utf8(c.host));Append(raw,std::to_string(c.port));Append(raw,c.secret);Append(raw,c.room);
 raw.push_back(c.internet?1:0);raw.push_back(c.driverOwned?1:0);raw.push_back(c.noCode?1:0);raw.push_back(c.requireApproval?1:0);return raw;
}
Config Decode(const std::vector<uint8_t>& raw){
 if(raw.size()<4||raw.size()>131072||(memcmp(raw.data(),"RDC1",4)&&memcmp(raw.data(),"RDC2",4)&&memcmp(raw.data(),"RDC3",4)))throw std::runtime_error("Host configuration version is not supported.");
 const unsigned version=static_cast<unsigned>(raw[3]-'0');size_t at=4;Config c;c.host=Wide(Take(raw,at,255));
 if(version<3){(void)Take(raw,at,512);(void)Port(Take(raw,at,5));c.secret=Take(raw,at,32);c.room=Take(raw,at,32);(void)Take(raw,at,64);if(version==2)(void)Take(raw,at,64);}
 else{c.port=Port(Take(raw,at,5));c.secret=Take(raw,at,32);c.room=Take(raw,at,32);}
 const size_t flags=version==1?2u:4u;if(raw.size()-at<flags)throw std::runtime_error("Truncated host settings.");for(size_t i=0;i<flags;++i)if(raw[at+i]>1)throw std::runtime_error("Invalid host configuration flag.");
 const bool previousInternet=raw[at++]!=0;c.internet=version==3&&previousInternet;c.driverOwned=raw[at++]!=0;if(version>=2){c.noCode=raw[at++]!=0;c.requireApproval=raw[at++]!=0;}
 if(version==3){if(at!=raw.size())throw std::runtime_error("Unexpected direct host configuration data.");}
 else if(version==2){if(raw.size()-at<4)throw std::runtime_error("Truncated legacy identity length.");uint32_t count=0;memcpy(&count,raw.data()+at,4);at+=4;if(!count||count>65536||count!=raw.size()-at)throw std::runtime_error("Invalid legacy identity length.");}
 else if(raw.size()==at||raw.size()-at>65536)throw std::runtime_error("Invalid legacy identity length.");
 ValidateConfig(c);return c;
}
}
void SaveConfig(const Config& c){
 auto raw=ConfigFormat::Encode(c);Wipe wipe{raw};ProtectDirectory(StateDirectory());
 DATA_BLOB input{static_cast<DWORD>(raw.size()),raw.data()},output{};Require(CryptProtectData(&input,L"Remote Device Control host",nullptr,nullptr,nullptr,CRYPTPROTECT_LOCAL_MACHINE|CRYPTPROTECT_UI_FORBIDDEN,&output)!=FALSE,"Protect host identity");
 const auto target=StateDirectory()+L"\\host.bin",temporary=target+L".new";
 if(std::filesystem::exists(target))CheckPlain(target);HANDLE file=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 if(file==INVALID_HANDLE_VALUE){LocalFree(output.pbData);SecureZeroMemory(raw.data(),raw.size());throw std::runtime_error(WindowsError("Create configuration",GetLastError()));}
 DWORD written=0;BOOL ok=WriteFile(file,output.pbData,output.cbData,&written,nullptr);DWORD error=GetLastError();if(ok&&!FlushFileBuffers(file)){ok=FALSE;error=GetLastError();}CloseHandle(file);LocalFree(output.pbData);SecureZeroMemory(raw.data(),raw.size());
 if(!ok||written!=output.cbData){DeleteFileW(temporary.c_str());throw std::runtime_error(WindowsError("Write configuration",error));}
 if(!MoveFileExW(temporary.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw std::runtime_error(WindowsError("Commit configuration",GetLastError()));
 HKEY key=nullptr;DWORD status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl",0,nullptr,0,KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key,nullptr);if(status!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Publish local host identity",status));auto room=Wide(c.room);status=RegSetValueExW(key,L"HostRoom",0,REG_SZ,reinterpret_cast<const BYTE*>(room.c_str()),static_cast<DWORD>((room.size()+1)*sizeof(wchar_t)));RegCloseKey(key);if(status!=ERROR_SUCCESS)throw std::runtime_error(WindowsError("Publish local host identity",status));
}
Config LoadConfig(){
 CheckProtectedDirectory(StateDirectory());auto path=StateDirectory()+L"\\host.bin";CheckPlain(path);auto length=std::filesystem::file_size(path);if(!length||length>131072)throw std::runtime_error("Missing or invalid protected host configuration.");std::ifstream file(path,std::ios::binary);std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(file)),{});if(encrypted.size()!=length)throw std::runtime_error("Protected host configuration could not be read completely.");
 DATA_BLOB input{static_cast<DWORD>(encrypted.size()),encrypted.data()},output{};Require(CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output)!=FALSE,"Read protected host identity");
 std::vector<uint8_t> raw(output.pbData,output.pbData+output.cbData);SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);
 Wipe wipe{raw};return ConfigFormat::Decode(raw);
}
std::wstring EngineDirectory(){return ProgramDirectory()+L"\\Engine";}
std::wstring EngineStateDirectory(){return StateDirectory()+L"\\Sunshine";}
std::string EngineFingerprint(){
 const auto path=EngineStateDirectory()+L"\\credentials\\cacert.pem";CheckPlain(path);const auto length=std::filesystem::file_size(path);if(!length||length>16384)throw std::runtime_error("The direct host certificate is unavailable.");
 std::ifstream input(path,std::ios::binary);std::string pem((std::istreambuf_iterator<char>(input)),{});if(pem.size()!=length)throw std::runtime_error("The direct host certificate could not be read completely.");
 DWORD count=0;Require(CryptStringToBinaryA(pem.c_str(),static_cast<DWORD>(pem.size()),CRYPT_STRING_BASE64HEADER,nullptr,&count,nullptr,nullptr)!=FALSE,"Read engine certificate");if(!count||count>8192)throw std::runtime_error("Invalid engine certificate size.");
 std::vector<uint8_t> der(count);Require(CryptStringToBinaryA(pem.c_str(),static_cast<DWORD>(pem.size()),CRYPT_STRING_BASE64HEADER,der.data(),&count,nullptr,nullptr)!=FALSE,"Decode engine certificate");auto cert=CertCreateCertificateContext(X509_ASN_ENCODING,der.data(),count);Require(cert!=nullptr,"Validate engine certificate");
 struct Free{PCCERT_CONTEXT value;~Free(){CertFreeCertificateContext(value);}} free{cert};if(CertVerifyTimeValidity(nullptr,cert->pCertInfo)!=0)throw std::runtime_error("The direct host certificate is expired or not yet valid.");
 BYTE digest[32]{};count=32;Require(CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM,0,nullptr,der.data(),static_cast<DWORD>(der.size()),digest,&count)!=FALSE&&count==32,"Fingerprint engine certificate");constexpr char hex[]="0123456789abcdef";std::string result;for(auto b:digest){result+=hex[b>>4];result+=hex[b&15];}return result;
}
std::wstring PairingCode(const Config& c,const std::string& fingerprint){if(!TitanTransport::IsFingerprint(fingerprint))throw std::invalid_argument("The direct host certificate is not ready.");return L"RDC3;"+c.host+L";"+std::to_wstring(c.port)+L";"+Wide(fingerprint)+L";"+Wide(c.secret)+L";"+Wide(c.room);}
Pairing ParsePairing(const std::wstring& value){
 if(value.size()>2048)throw std::runtime_error("Connection code is too long.");std::vector<std::wstring> fields;size_t start=0;for(size_t i=0;i<=value.size();++i)if(i==value.size()||value[i]==L';'){fields.push_back(value.substr(start,i-start));start=i+1;}
 if(fields.size()!=6||fields[0]!=L"RDC3")throw std::runtime_error("Install the updated direct host and copy its RDC3 connection code, or enter an IP address/DNS name for code-free access.");
 Pairing p;p.host=Utf8(fields[1]);if(p.host.empty()||p.host.size()>255||p.host.find_first_of("/\\ \r\n\t\0",0,8)!=p.host.npos)throw std::runtime_error("Invalid host address.");p.port=Port(Utf8(fields[2]));if(p.port<1024||p.port>65514)throw std::runtime_error("Invalid GameStream base port.");p.pin=Utf8(fields[3]);p.secret=Utf8(fields[4]);p.room=Utf8(fields[5]);p.noCode=p.secret==OpenAccessSecret;if(!TitanTransport::IsFingerprint(p.pin)||!TitanTransport::IsSecret(p.secret)||!TitanTransport::IsSecret(p.room))throw std::runtime_error("Invalid connection credentials.");return p;
}
Pairing ParseDirectAddress(const std::wstring& text){
 if(text.empty()||text.size()>300)throw std::invalid_argument("Enter an IP address or DNS name, optionally followed by :port.");Pairing p;p.noCode=true;p.secret=OpenAccessSecret;std::wstring host=text;
 if(text.front()==L'['){const auto close=text.find(L']');if(close==text.npos)throw std::invalid_argument("Use [IPv6-address]:port for a custom IPv6 port.");host=text.substr(1,close-1);if(close+1<text.size()){if(text[close+1]!=L':')throw std::invalid_argument("Invalid IPv6 host address.");p.port=Port(Utf8(text.substr(close+2)));}}
 else{const auto colon=text.rfind(L':');if(colon!=text.npos&&text.find(L':')==colon){host=text.substr(0,colon);p.port=Port(Utf8(text.substr(colon+1)));}}
 p.host=Utf8(host);if(p.host.empty()||p.host.size()>255||p.host.find_first_of("/\\ ;\r\n\t\0",0,9)!=p.host.npos||p.port<1024||p.port>65514)throw std::invalid_argument("Invalid direct host address or GameStream port.");return p;
}
}