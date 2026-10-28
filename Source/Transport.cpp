#define SECURITY_WIN32
#include "Transport.h"
#include <ws2tcpip.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace TitanTransport {
namespace {
[[noreturn]] void Fail(const char* stage,long code){throw std::runtime_error(std::string(stage)+" failed (Windows status "+std::to_string(static_cast<unsigned long>(code))+").");}
void Require(bool value,const char* stage){if(!value)Fail(stage,static_cast<long>(GetLastError()));}
std::string Hex(const unsigned char* p,size_t count){static constexpr char h[]="0123456789abcdef";std::string out(count*2,'0');for(size_t i=0;i<count;++i){out[i*2]=h[p[i]>>4];out[i*2+1]=h[p[i]&15];}return out;}
bool HexLength(std::string_view value,size_t count) noexcept{if(value.size()!=count)return false;for(char c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true;}
std::string Hash(PCCERT_CONTEXT cert){std::array<unsigned char,32> hash{};DWORD size=static_cast<DWORD>(hash.size());Require(CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM,0,nullptr,cert->pbCertEncoded,cert->cbCertEncoded,hash.data(),&size)!=FALSE,"Certificate SHA-256");Require(size==hash.size(),"Certificate hash length");return Hex(hash.data(),hash.size());}
void Budget(SOCKET socket,int option,ULONGLONG deadline){if(!deadline)return;auto now=GetTickCount64();if(now>=deadline)throw std::runtime_error("TLS operation deadline exceeded.");DWORD remaining=static_cast<DWORD>((std::min)(ULONGLONG(5000),deadline-now));if(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&remaining),sizeof(remaining)))Fail("TLS deadline policy",WSAGetLastError());}
void SendAll(SOCKET socket,const void* data,size_t count,ULONGLONG deadline=0){const char* p=static_cast<const char*>(data);while(count){Budget(socket,SO_SNDTIMEO,deadline);int n=send(socket,p,static_cast<int>((std::min)(count,size_t(1<<20))),0);if(n<=0)Fail("Socket send",n==0?WSAECONNRESET:WSAGetLastError());p+=n;count-=static_cast<size_t>(n);}}
void Configure(SOCKET socket){
 // Windows accept inherits FIONBIO from the listening socket. Only the listener
 // is nonblocking; this synchronous TLS channel uses bounded blocking I/O.
 u_long blocking=0;if(ioctlsocket(socket,FIONBIO,&blocking))Fail("TLS blocking socket policy",WSAGetLastError());
 DWORD ms=5000;int yes=1;if(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&ms),sizeof(ms))||setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&ms),sizeof(ms))||setsockopt(socket,IPPROTO_TCP,TCP_NODELAY,reinterpret_cast<const char*>(&yes),sizeof(yes)))Fail("Socket policy",WSAGetLastError());
}
sockaddr_in Address(std::string_view text,uint16_t port){if(text.empty()||text.size()>15||text.find('\0')!=text.npos)throw std::runtime_error("Use a numeric IPv4 address.");sockaddr_in result{};result.sin_family=AF_INET;result.sin_port=htons(port);std::string owned(text);if(InetPtonA(AF_INET,owned.c_str(),&result.sin_addr)!=1)throw std::runtime_error("Use a numeric IPv4 address.");return result;}
struct SocketGuard{SOCKET value=INVALID_SOCKET;~SocketGuard(){if(value!=INVALID_SOCKET)closesocket(value);}SOCKET Release(){return std::exchange(value,INVALID_SOCKET);}};
}
Runtime::Runtime(){WSADATA data{};int e=WSAStartup(MAKEWORD(2,2),&data);if(e)Fail("Winsock initialization",e);}
Runtime::~Runtime(){WSACleanup();}
struct Identity::State{HCRYPTPROV provider=0;HCRYPTKEY key=0;PCCERT_CONTEXT cert=nullptr;std::wstring name;~State(){if(cert)CertFreeCertificateContext(cert);if(key)CryptDestroyKey(key);if(provider)CryptReleaseContext(provider,0);if(!name.empty()){HCRYPTPROV ignored=0;CryptAcquireContextW(&ignored,name.c_str(),MS_ENH_RSA_AES_PROV_W,PROV_RSA_AES,CRYPT_DELETEKEYSET|CRYPT_SILENT);}}};
Identity::Identity():state_(std::make_unique<State>()){
 const auto session=RandomSecret();state_->name=L"TitanPairedSession-"+std::wstring(session.begin(),session.end());
 Require(CryptAcquireContextW(&state_->provider,state_->name.c_str(),MS_ENH_RSA_AES_PROV_W,PROV_RSA_AES,CRYPT_NEWKEYSET|CRYPT_SILENT)!=FALSE,"TLS session key provider");
 Require(CryptGenKey(state_->provider,AT_KEYEXCHANGE,(2048u<<16)|CRYPT_EXPORTABLE,&state_->key)!=FALSE,"TLS RSA2048 session key");
 DWORD length=0;Require(CertStrToNameW(X509_ASN_ENCODING,L"CN=Titan Paired Session",CERT_X500_NAME_STR,nullptr,nullptr,&length,nullptr)!=FALSE,"TLS subject size");
 std::vector<BYTE> name(length);Require(CertStrToNameW(X509_ASN_ENCODING,L"CN=Titan Paired Session",CERT_X500_NAME_STR,nullptr,name.data(),&length,nullptr)!=FALSE,"TLS subject");CERT_NAME_BLOB subject{length,name.data()};
 CRYPT_ALGORITHM_IDENTIFIER algorithm{};algorithm.pszObjId=const_cast<char*>(szOID_RSA_SHA256RSA);
 SYSTEMTIME start{},end{};GetSystemTime(&start);FILETIME file{};Require(SystemTimeToFileTime(&start,&file)!=FALSE,"TLS start time");ULARGE_INTEGER ticks{};ticks.LowPart=file.dwLowDateTime;ticks.HighPart=file.dwHighDateTime;ticks.QuadPart+=3650ull*24*60*60*10000000;file.dwLowDateTime=ticks.LowPart;file.dwHighDateTime=ticks.HighPart;Require(FileTimeToSystemTime(&file,&end)!=FALSE,"TLS expiry time");
 CRYPT_KEY_PROV_INFO providerInfo{};providerInfo.pwszContainerName=const_cast<wchar_t*>(state_->name.c_str());providerInfo.pwszProvName=const_cast<wchar_t*>(MS_ENH_RSA_AES_PROV_W);providerInfo.dwProvType=PROV_RSA_AES;providerInfo.dwKeySpec=AT_KEYEXCHANGE;
 char* serverOid=const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH);CERT_ENHKEY_USAGE usage{1,&serverOid};BYTE keyUsage=CERT_DIGITAL_SIGNATURE_KEY_USAGE|CERT_KEY_ENCIPHERMENT_KEY_USAGE;CRYPT_BIT_BLOB keyBits{1,&keyUsage,0};
 struct Encoded{BYTE* bytes=nullptr;DWORD size=0;~Encoded(){if(bytes)LocalFree(bytes);}} eku,ku;
 Require(CryptEncodeObjectEx(X509_ASN_ENCODING,X509_ENHANCED_KEY_USAGE,&usage,CRYPT_ENCODE_ALLOC_FLAG,nullptr,&eku.bytes,&eku.size)!=FALSE,"TLS server usage encoding");
 Require(CryptEncodeObjectEx(X509_ASN_ENCODING,X509_KEY_USAGE,&keyBits,CRYPT_ENCODE_ALLOC_FLAG,nullptr,&ku.bytes,&ku.size)!=FALSE,"TLS key usage encoding");
 CERT_EXTENSION extensions[2]{{const_cast<char*>(szOID_ENHANCED_KEY_USAGE),FALSE,{eku.size,eku.bytes}},{const_cast<char*>(szOID_KEY_USAGE),TRUE,{ku.size,ku.bytes}}};CERT_EXTENSIONS extensionList{2,extensions};
 state_->cert=CertCreateSelfSignCertificate(state_->provider,&subject,0,&providerInfo,&algorithm,&start,&end,&extensionList);Require(state_->cert!=nullptr,"Self-signed TLS session certificate");
 HCRYPTPROV_OR_NCRYPT_KEY_HANDLE acquired=0;DWORD specification=0;BOOL release=FALSE;
 Require(CryptAcquireCertificatePrivateKey(state_->cert,CRYPT_ACQUIRE_COMPARE_KEY_FLAG,nullptr,&acquired,&specification,&release)!=FALSE,"TLS certificate/key match");
 if(release){if(specification==CERT_NCRYPT_KEY_SPEC)NCryptFreeObject(acquired);else CryptReleaseContext(acquired,0);}
 // Schannel on downlevel Windows requires a named CSP key container. Its
 // random current-user name is deleted at owner cleanup; no certificate is
 // installed in any trust store. Abrupt process termination can leave the
 // temporary key container behind, so session fingerprints are not identities.
}

std::vector<uint8_t> Identity::Export()const{
 HCERTSTORE store=CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,nullptr);Require(store!=nullptr,"Certificate export store");
 CRYPT_DATA_BLOB blob{};
 try{
  Require(CertAddCertificateContextToStore(store,state_->cert,CERT_STORE_ADD_ALWAYS,nullptr)!=FALSE,"Certificate export context");
  Require(PFXExportCertStoreEx(store,&blob,L"",nullptr,EXPORT_PRIVATE_KEYS|REPORT_NO_PRIVATE_KEY|REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)!=FALSE,"Certificate export size");
  std::vector<uint8_t> data(blob.cbData);blob.pbData=data.data();
  Require(PFXExportCertStoreEx(store,&blob,L"",nullptr,EXPORT_PRIVATE_KEYS|REPORT_NO_PRIVATE_KEY|REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)!=FALSE,"Certificate export");
  CertCloseStore(store,0);return data;
 }catch(...){CertCloseStore(store,0);throw;}
}
Identity::Identity(const std::vector<uint8_t>& data):state_(std::make_unique<State>()){
 if(data.empty()||data.size()>65536)throw std::runtime_error("Invalid persisted host identity.");
 CRYPT_DATA_BLOB blob{static_cast<DWORD>(data.size()),const_cast<BYTE*>(data.data())};
 HCERTSTORE store=PFXImportCertStore(&blob,L"",CRYPT_EXPORTABLE|CRYPT_USER_KEYSET);Require(store!=nullptr,"Persisted host identity import");
 try{
  PCCERT_CONTEXT cert=CertEnumCertificatesInStore(store,nullptr);Require(cert!=nullptr,"Persisted host certificate");state_->cert=CertDuplicateCertificateContext(cert);CertFreeCertificateContext(cert);
  DWORD size=0;Require(CertGetCertificateContextProperty(state_->cert,CERT_KEY_PROV_INFO_PROP_ID,nullptr,&size)!=FALSE,"Persisted key provider size");
  std::vector<BYTE> buffer(size);Require(CertGetCertificateContextProperty(state_->cert,CERT_KEY_PROV_INFO_PROP_ID,buffer.data(),&size)!=FALSE,"Persisted key provider");
  auto info=reinterpret_cast<CRYPT_KEY_PROV_INFO*>(buffer.data());
  if(info->dwProvType==0)throw std::runtime_error("A legacy CSP host identity is required for Windows 10 compatibility.");
  state_->name=info->pwszContainerName;
  Require(CryptAcquireContextW(&state_->provider,info->pwszContainerName,info->pwszProvName,info->dwProvType,CRYPT_SILENT)!=FALSE,"Persisted key context");
  Require(CryptGetUserKey(state_->provider,info->dwKeySpec,&state_->key)!=FALSE,"Persisted private key");
  CertCloseStore(store,0);
 }catch(...){CertCloseStore(store,0);throw;}
}

Identity::~Identity()=default;
std::string Identity::Fingerprint()const{return Hash(state_->cert);}
bool IsFingerprint(std::string_view value)noexcept{return HexLength(value,64);}
bool IsSecret(std::string_view value)noexcept{return HexLength(value,32);}
bool ConstantTimeEqual(std::string_view a,std::string_view b)noexcept{if(a.size()!=b.size())return false;unsigned char difference=0;for(size_t i=0;i<a.size();++i)difference|=static_cast<unsigned char>(a[i]^b[i]);return difference==0;}
std::string RandomSecret(){std::array<unsigned char,16> bytes{};auto s=BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG);if(s<0)Fail("Pairing secret randomness",s);return Hex(bytes.data(),bytes.size());}


namespace {
class SocketStream final:public ByteStream {
 SOCKET socket_;
public:
 explicit SocketStream(SOCKET owned):socket_(owned){try{Configure(socket_);}catch(...){closesocket(socket_);throw;}}
 ~SocketStream(){Close();closesocket(socket_);}
 size_t ReadSome(void* bytes,size_t count,uint32_t timeout)override{
  Budget(socket_,SO_RCVTIMEO,GetTickCount64()+timeout);
  int n=recv(socket_,static_cast<char*>(bytes),static_cast<int>((std::min)(count,size_t(1<<20))),0);
  if(n<=0)Fail("Socket receive",n==0?WSAECONNRESET:WSAGetLastError());return static_cast<size_t>(n);
 }
 void WriteAll(const void* bytes,size_t count,uint32_t timeout)override{SendAll(socket_,bytes,count,GetTickCount64()+timeout);}
 void Close()noexcept override{shutdown(socket_,SD_BOTH);}
};
uint32_t Remaining(ULONGLONG deadline){auto now=GetTickCount64();if(now>=deadline)throw std::runtime_error("TLS operation deadline exceeded.");return static_cast<uint32_t>((std::min)(deadline-now,ULONGLONG(30000)));}
}
struct Channel::State{
 std::unique_ptr<ByteStream> stream;CredHandle credentials{};CtxtHandle context{};bool haveCredentials=false,haveContext=false,ready=false;SecPkgContext_StreamSizes sizes{};std::vector<unsigned char> wire,plain;size_t plainPosition=0;std::mutex writer;
 explicit State(std::unique_ptr<ByteStream> owned):stream(std::move(owned)){SecInvalidateHandle(&credentials);SecInvalidateHandle(&context);}
 ~State(){Close();if(haveContext)DeleteSecurityContext(&context);if(haveCredentials)FreeCredentialsHandle(&credentials);}
 void Close()noexcept{if(stream)stream->Close();}
 void More(ULONGLONG deadline=0){
  if(wire.size()>=262144)throw std::runtime_error("TLS record buffer limit exceeded.");
  std::array<unsigned char,16384> chunk{};size_t n=stream->ReadSome(chunk.data(),(std::min)(chunk.size(),262144-wire.size()),deadline?Remaining(deadline):5000);
  if(!n||n>chunk.size())throw std::runtime_error("Invalid TLS stream read.");wire.insert(wire.end(),chunk.begin(),chunk.begin()+static_cast<ptrdiff_t>(n));
 }
 void Extra(const SecBuffer* buffers,size_t count){size_t extra=0;for(size_t i=0;i<count;++i)if(buffers[i].BufferType==SECBUFFER_EXTRA){if(buffers[i].cbBuffer>wire.size())throw std::runtime_error("Invalid TLS extra bytes.");extra=buffers[i].cbBuffer;}if(extra){std::vector<unsigned char> keep(wire.end()-static_cast<ptrdiff_t>(extra),wire.end());wire.swap(keep);}else wire.clear();}
 void Handshake(Identity::State* identity,std::string_view pin){
  const bool server=identity!=nullptr;SCHANNEL_CRED config{};config.dwVersion=SCHANNEL_CRED_VERSION;config.grbitEnabledProtocols=server?SP_PROT_TLS1_2_SERVER:SP_PROT_TLS1_2_CLIENT;config.dwFlags=SCH_USE_STRONG_CRYPTO;
  PCCERT_CONTEXT certificate=server?identity->cert:nullptr;if(server){config.cCreds=1;config.paCred=&certificate;}else config.dwFlags|=SCH_CRED_MANUAL_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS;
  TimeStamp expiry{};auto status=AcquireCredentialsHandleW(nullptr,const_cast<wchar_t*>(UNISP_NAME_W),server?SECPKG_CRED_INBOUND:SECPKG_CRED_OUTBOUND,nullptr,&config,nullptr,nullptr,&credentials,&expiry);if(status!=SEC_E_OK)Fail(server?"TLS server credentials":"TLS client credentials",status);haveCredentials=true;
  bool first=true,needMore=server;const auto deadline=GetTickCount64()+5000;
  for(unsigned steps=0;steps<64&&GetTickCount64()<deadline;++steps){
   if(needMore)More(deadline);SecBuffer input[2]{{static_cast<ULONG>(wire.size()),SECBUFFER_TOKEN,wire.data()},{0,SECBUFFER_EMPTY,nullptr}};SecBufferDesc in{SECBUFFER_VERSION,2,input};SecBuffer output{0,SECBUFFER_TOKEN,nullptr};SecBufferDesc out{SECBUFFER_VERSION,1,&output};ULONG attributes=0;
   constexpr ULONG clientFlags=ISC_REQ_STREAM|ISC_REQ_CONFIDENTIALITY|ISC_REQ_INTEGRITY|ISC_REQ_REPLAY_DETECT|ISC_REQ_SEQUENCE_DETECT|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_MANUAL_CRED_VALIDATION|ISC_REQ_USE_SUPPLIED_CREDS;
   constexpr ULONG serverFlags=ASC_REQ_STREAM|ASC_REQ_CONFIDENTIALITY|ASC_REQ_INTEGRITY|ASC_REQ_REPLAY_DETECT|ASC_REQ_SEQUENCE_DETECT|ASC_REQ_ALLOCATE_MEMORY;
   if(server)status=AcceptSecurityContext(&credentials,first?nullptr:&context,&in,serverFlags,SECURITY_NATIVE_DREP,&context,&out,&attributes,&expiry);
   else status=InitializeSecurityContextW(&credentials,first?nullptr:&context,nullptr,clientFlags,0,SECURITY_NATIVE_DREP,first?nullptr:&in,0,&context,&out,&attributes,&expiry);
   if(SecIsValidHandle(&context))haveContext=true;
   if(status==SEC_I_COMPLETE_NEEDED||status==SEC_I_COMPLETE_AND_CONTINUE){auto e=CompleteAuthToken(&context,&out);if(e!=SEC_E_OK){if(output.pvBuffer)FreeContextBuffer(output.pvBuffer);Fail("TLS complete token",e);}status=status==SEC_I_COMPLETE_NEEDED?SEC_E_OK:SEC_I_CONTINUE_NEEDED;}
   if(output.pvBuffer){try{if(output.cbBuffer>262144)throw std::runtime_error("TLS handshake output limit exceeded.");stream->WriteAll(output.pvBuffer,output.cbBuffer,Remaining(deadline));}catch(...){FreeContextBuffer(output.pvBuffer);throw;}FreeContextBuffer(output.pvBuffer);}
   if(status==SEC_E_INCOMPLETE_MESSAGE){needMore=true;continue;}
   if(status!=SEC_E_OK&&status!=SEC_I_CONTINUE_NEEDED)Fail("TLS handshake",status);haveContext=true;first=false;Extra(input,2);
   if(status==SEC_E_OK){
    const ULONG required=server?(ASC_RET_CONFIDENTIALITY|ASC_RET_STREAM):(ISC_RET_CONFIDENTIALITY|ISC_RET_STREAM);if((attributes&required)!=required)throw std::runtime_error("TLS stream confidentiality was not negotiated.");
    SecPkgContext_ConnectionInfo info{};status=QueryContextAttributesW(&context,SECPKG_ATTR_CONNECTION_INFO,&info);if(status!=SEC_E_OK||info.dwCipherStrength<128||(info.dwProtocol&static_cast<DWORD>(server?SP_PROT_TLS1_2_SERVER:SP_PROT_TLS1_2_CLIENT))==0)throw std::runtime_error("A strong TLS 1.2 connection is required.");
    if(!server){PCCERT_CONTEXT remote=nullptr;status=QueryContextAttributesW(&context,SECPKG_ATTR_REMOTE_CERT_CONTEXT,&remote);if(status!=SEC_E_OK||!remote)Fail("TLS server certificate",status);std::string observed;bool valid=false;try{observed=Hash(remote);valid=CertVerifyTimeValidity(nullptr,remote->pCertInfo)==0;}catch(...){CertFreeCertificateContext(remote);throw;}CertFreeCertificateContext(remote);if(!valid||!ConstantTimeEqual(observed,pin))throw std::runtime_error("TLS server certificate fingerprint does not match the paired host, or has expired.");}
    status=QueryContextAttributesW(&context,SECPKG_ATTR_STREAM_SIZES,&sizes);if(status!=SEC_E_OK||!sizes.cbMaximumMessage||sizes.cbMaximumMessage>65536||sizes.cbHeader>4096||sizes.cbTrailer>4096)throw std::runtime_error("TLS stream sizes are invalid.");ready=true;return;
   }
   needMore=wire.empty();
  }
  throw std::runtime_error("TLS handshake deadline exceeded.");
 }
 void ReadPlain(ULONGLONG deadline){
  for(unsigned steps=0;steps<64;++steps){if(wire.empty())More(deadline);SecBuffer buffers[4]{{static_cast<ULONG>(wire.size()),SECBUFFER_DATA,wire.data()},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr}};SecBufferDesc desc{SECBUFFER_VERSION,4,buffers};auto s=DecryptMessage(&context,&desc,0,nullptr);if(s==SEC_E_INCOMPLETE_MESSAGE){More(deadline);continue;}if(s!=SEC_E_OK)Fail(s==SEC_I_RENEGOTIATE?"TLS renegotiation is not supported":"TLS record authentication",s);
   plain.clear();plainPosition=0;for(auto& b:buffers)if(b.BufferType==SECBUFFER_DATA&&b.cbBuffer){const auto first=reinterpret_cast<uintptr_t>(wire.data()),p=reinterpret_cast<uintptr_t>(b.pvBuffer);if(p<first||b.cbBuffer>wire.size()||p-first>wire.size()-b.cbBuffer||b.cbBuffer>65536)throw std::runtime_error("TLS plaintext bounds invalid.");auto data=static_cast<unsigned char*>(b.pvBuffer);plain.assign(data,data+b.cbBuffer);}
   Extra(buffers,4);if(!plain.empty())return;
  }throw std::runtime_error("Too many empty TLS records.");
 }
};
Channel::Channel(SOCKET socket):Channel(std::make_unique<SocketStream>(socket)){}
Channel::Channel(std::unique_ptr<ByteStream> stream){if(!stream)throw std::runtime_error("Missing byte stream.");state_=std::make_unique<State>(std::move(stream));}
void Channel::HandshakeServer(Identity& server){if(state_->haveCredentials)throw std::runtime_error("TLS handshake already attempted.");state_->Handshake(server.state_.get(),{});}
void Channel::HandshakeClient(std::string_view pin){if(state_->haveCredentials)throw std::runtime_error("TLS handshake already attempted.");if(!IsFingerprint(pin))throw std::runtime_error("Enter the host's exact 64-character lowercase SHA-256 fingerprint.");state_->Handshake(nullptr,pin);}
Channel::Channel(SOCKET socket,Identity& server):Channel(socket){HandshakeServer(server);}
Channel::Channel(SOCKET socket,std::string_view pin):Channel(socket){HandshakeClient(pin);}
Channel::~Channel()=default;
void Channel::Close()noexcept{state_->Close();}
void Channel::Send(const void* bytes,size_t count){if(!state_->ready)throw std::runtime_error("TLS handshake is not complete.");if(count&&bytes==nullptr)throw std::runtime_error("Missing TLS send buffer.");std::lock_guard<std::mutex> lock(state_->writer);const auto deadline=GetTickCount64()+5000;auto data=static_cast<const unsigned char*>(bytes);while(count){auto n=static_cast<ULONG>((std::min)(count,static_cast<size_t>(state_->sizes.cbMaximumMessage)));std::vector<unsigned char> buffer(state_->sizes.cbHeader+n+state_->sizes.cbTrailer);std::memcpy(buffer.data()+state_->sizes.cbHeader,data,n);SecBuffer b[4]{{state_->sizes.cbHeader,SECBUFFER_STREAM_HEADER,buffer.data()},{n,SECBUFFER_DATA,buffer.data()+state_->sizes.cbHeader},{state_->sizes.cbTrailer,SECBUFFER_STREAM_TRAILER,buffer.data()+state_->sizes.cbHeader+n},{0,SECBUFFER_EMPTY,nullptr}};SecBufferDesc desc{SECBUFFER_VERSION,4,b};auto s=EncryptMessage(&state_->context,0,&desc,0);if(s!=SEC_E_OK)Fail("TLS encryption",s);std::vector<unsigned char> packed;packed.reserve(buffer.size());for(unsigned i=0;i<3;++i){auto p=static_cast<unsigned char*>(b[i].pvBuffer);packed.insert(packed.end(),p,p+b[i].cbBuffer);}state_->stream->WriteAll(packed.data(),packed.size(),Remaining(deadline));data+=n;count-=n;}}
void Channel::Receive(void* bytes,size_t count,uint32_t timeoutMilliseconds){if(!state_->ready)throw std::runtime_error("TLS handshake is not complete.");if(count&&bytes==nullptr)throw std::runtime_error("Missing TLS receive buffer.");if(!timeoutMilliseconds||timeoutMilliseconds>30000)throw std::runtime_error("TLS receive timeout must be1..30000 milliseconds.");const auto deadline=GetTickCount64()+timeoutMilliseconds;auto out=static_cast<unsigned char*>(bytes);while(count){if(GetTickCount64()>=deadline)throw std::runtime_error("TLS application receive deadline exceeded.");if(state_->plainPosition==state_->plain.size())state_->ReadPlain(deadline);auto n=(std::min)(count,state_->plain.size()-state_->plainPosition);std::memcpy(out,state_->plain.data()+state_->plainPosition,n);out+=n;count-=n;state_->plainPosition+=n;}}
SOCKET Listen(std::string_view ip,uint16_t port,uint16_t* actual){auto address=Address(ip,port);SocketGuard socket{::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)};if(socket.value==INVALID_SOCKET)Fail("Listener creation",WSAGetLastError());int exclusive=1;if(setsockopt(socket.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))||bind(socket.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))||listen(socket.value,1))Fail("Explicit listener bind",WSAGetLastError());if(actual){int size=sizeof(address);if(getsockname(socket.value,reinterpret_cast<sockaddr*>(&address),&size))Fail("Listener port",WSAGetLastError());*actual=ntohs(address.sin_port);}return socket.Release();}
SOCKET Connect(std::string_view ip,uint16_t port){if(!port)throw std::runtime_error("A nonzero remote port is required.");auto address=Address(ip,port);SocketGuard socket{::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)};if(socket.value==INVALID_SOCKET)Fail("Client socket",WSAGetLastError());u_long nonblocking=1;if(ioctlsocket(socket.value,FIONBIO,&nonblocking))Fail("Connect policy",WSAGetLastError());int e=connect(socket.value,reinterpret_cast<sockaddr*>(&address),sizeof(address));if(e&&WSAGetLastError()!=WSAEWOULDBLOCK)Fail("Remote connection",WSAGetLastError());fd_set write,error;FD_ZERO(&write);FD_ZERO(&error);FD_SET(socket.value,&write);FD_SET(socket.value,&error);timeval wait{5,0};if(select(0,nullptr,&write,&error,&wait)<=0||FD_ISSET(socket.value,&error))throw std::runtime_error("Remote connection failed or timed out.");int code=0;int length=sizeof(code);if(getsockopt(socket.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&code),&length)||code)Fail("Remote connection",code?code:WSAGetLastError());nonblocking=0;if(ioctlsocket(socket.value,FIONBIO,&nonblocking))Fail("Connected socket policy",WSAGetLastError());return socket.Release();}
}
