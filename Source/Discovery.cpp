#include "Discovery.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netlistmgr.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace RemoteControl {
namespace {
using Microsoft::WRL::ComPtr;
using Nonce=std::array<uint8_t,16>;
constexpr size_t QueryBytes=1024,ReplyBytes=512,MaxInterfaces=32,MaxHosts=64;
constexpr uint64_t HostTtl=6000,NonceTtl=3000;
constexpr char Magic[]="RDC-LAN1";
struct Handle {
    HANDLE value=nullptr;
    explicit Handle(HANDLE v=nullptr):value(v){}
    ~Handle(){if(value)CloseHandle(value);}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
struct Socket {
    SOCKET value=INVALID_SOCKET;
    Socket()=default;~Socket(){if(value!=INVALID_SOCKET)closesocket(value);}
    Socket(Socket&& other)noexcept:value(other.value){other.value=INVALID_SOCKET;}
    Socket& operator=(Socket&& other)noexcept{if(this!=&other){if(value!=INVALID_SOCKET)closesocket(value);value=other.value;other.value=INVALID_SOCKET;}return *this;}
    Socket(const Socket&)=delete;Socket& operator=(const Socket&)=delete;
};
bool Hex(const std::string& text,size_t size){
    if(text.size()!=size)return false;
    for(char c:text)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
}
bool Name(const std::string& text){
    if(text.empty()||text.size()>96)return false;
    wchar_t decoded[96]{};const int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),decoded,96);
    if(!count)return false;
    for(int i=0;i<count;++i)if(decoded[i]<32||(decoded[i]>=127&&decoded[i]<=159)||(decoded[i]>=0x202a&&decoded[i]<=0x202e)||(decoded[i]>=0x2066&&decoded[i]<=0x2069))return false;
    return true;
}
bool Valid(const DiscoveryAnnouncement& item){return Name(item.name)&&Hex(item.room,32)&&Hex(item.pin,64)&&item.port!=0;}
bool Nonzero(const Nonce& nonce){for(auto b:nonce)if(b)return true;return false;}
bool Header(const uint8_t* data,size_t size,size_t expected,uint8_t kind){return data&&size==expected&&!std::memcmp(data,Magic,8)&&data[8]==kind;}
std::array<uint8_t,QueryBytes> Query(const Nonce& nonce){
    std::array<uint8_t,QueryBytes> bytes{};std::memcpy(bytes.data(),Magic,8);bytes[8]=1;std::memcpy(bytes.data()+12,nonce.data(),nonce.size());return bytes;
}
bool ParseQuery(const uint8_t* data,size_t size,Nonce& nonce){
    if(!Header(data,size,QueryBytes,1)||data[9]||data[10]||data[11])return false;
    for(size_t i=28;i<size;++i)if(data[i])return false;
    std::memcpy(nonce.data(),data+12,nonce.size());return Nonzero(nonce);
}
std::array<uint8_t,ReplyBytes> Reply(const DiscoveryAnnouncement& item,const Nonce& nonce){
    if(!Valid(item)||!Nonzero(nonce))throw std::runtime_error("Invalid LAN discovery announcement.");
    std::array<uint8_t,ReplyBytes> bytes{};std::memcpy(bytes.data(),Magic,8);bytes[8]=2;
    bytes[9]=static_cast<uint8_t>((item.busy?1:0)|(item.available?2:0)|(item.requireApproval?4:0));
    bytes[10]=static_cast<uint8_t>(item.port>>8);bytes[11]=static_cast<uint8_t>(item.port&255);
    std::memcpy(bytes.data()+12,nonce.data(),nonce.size());bytes[28]=static_cast<uint8_t>(item.name.size());
    std::memcpy(bytes.data()+32,item.room.data(),32);std::memcpy(bytes.data()+64,item.pin.data(),64);std::memcpy(bytes.data()+128,item.name.data(),item.name.size());return bytes;
}
bool ParseReply(const uint8_t* data,size_t size,const Nonce& expected,DiscoveryAnnouncement& item){
    if(!Header(data,size,ReplyBytes,2)||(data[9]&~7)||data[29]||data[30]||data[31]||!Nonzero(expected)||std::memcmp(data+12,expected.data(),expected.size())||!data[28]||data[28]>96)return false;
    for(size_t i=128+data[28];i<size;++i)if(data[i])return false;
    DiscoveryAnnouncement parsed;parsed.port=static_cast<uint16_t>((data[10]<<8)|data[11]);parsed.busy=(data[9]&1)!=0;parsed.available=(data[9]&2)!=0;parsed.requireApproval=(data[9]&4)!=0;
    parsed.room.assign(reinterpret_cast<const char*>(data+32),32);parsed.pin.assign(reinterpret_cast<const char*>(data+64),64);parsed.name.assign(reinterpret_cast<const char*>(data+128),data[28]);
    if(!Valid(parsed))return false;item=std::move(parsed);return true;
}
bool Subnet(uint32_t peer,uint32_t local,unsigned prefix){
    if(!prefix||prefix>30)return false;
    const uint32_t source=ntohl(peer),address=ntohl(local),mask=0xffffffffu<<(32-prefix);
    if(!source||(source>>24)==127||(source>>24)>=224||source==address)return false;
    const uint32_t host=source&~mask;
    return (source&mask)==(address&mask)&&host&&host!=~mask;
}
bool Expired(uint64_t stamp,uint64_t now,uint64_t ttl){return now<stamp||now-stamp>=ttl;}
bool Purge(std::vector<DiscoveredHost>& hosts,uint64_t now){const auto size=hosts.size();hosts.erase(std::remove_if(hosts.begin(),hosts.end(),[&](const auto& h){return Expired(h.seenTick,now,HostTtl);}),hosts.end());return hosts.size()!=size;}
bool Remember(std::vector<DiscoveredHost>& hosts,DiscoveredHost item,uint64_t now){
    Purge(hosts,now);item.seenTick=now;
    for(auto& old:hosts)if(old.room==item.room){const bool changed=old.name!=item.name||old.address!=item.address||old.pin!=item.pin||old.port!=item.port||old.busy!=item.busy||old.available!=item.available||old.requireApproval!=item.requireApproval;old=std::move(item);return changed;}
    if(hosts.size()>=MaxHosts)return false;hosts.push_back(std::move(item));return true;
}
bool Private(INetwork* network){NLM_NETWORK_CATEGORY category=NLM_NETWORK_CATEGORY_PUBLIC;return network&&SUCCEEDED(network->GetCategory(&category))&&(category==NLM_NETWORK_CATEGORY_PRIVATE||category==NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED);}
struct Interface {uint32_t address=0,index=0;unsigned prefix=0;ComPtr<INetwork> network;};
std::vector<Interface> Interfaces(){
    ComPtr<INetworkListManager> manager;
    if(FAILED(CoCreateInstance(CLSID_NetworkListManager,nullptr,CLSCTX_ALL,IID_PPV_ARGS(&manager))))return {};
    ComPtr<IEnumNetworkConnections> connections;if(FAILED(manager->GetNetworkConnections(&connections)))return {};
    struct Profile {GUID adapter{};ComPtr<INetwork> network;};std::vector<Profile> profiles;profiles.reserve(MaxInterfaces);
    for(size_t i=0;i<MaxInterfaces;++i){ComPtr<INetworkConnection> connection;ULONG fetched=0;if(connections->Next(1,&connection,&fetched)!=S_OK||fetched!=1)break;
        Profile profile;if(SUCCEEDED(connection->GetAdapterId(&profile.adapter))&&SUCCEEDED(connection->GetNetwork(&profile.network))&&Private(profile.network.Get()))profiles.push_back(std::move(profile));}
    if(profiles.empty())return {};
    ULONG bytes=16384;std::vector<uint8_t> storage(bytes);auto result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),&bytes);
    if(result==ERROR_BUFFER_OVERFLOW&&bytes<=1024*1024){storage.resize(bytes);result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),&bytes);}
    if(result!=NO_ERROR)return {};
    std::vector<Interface> output;output.reserve(MaxInterfaces);
    for(auto adapter=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());adapter&&output.size()<MaxInterfaces;adapter=adapter->Next){
        if(adapter->OperStatus!=IfOperStatusUp||!adapter->IfIndex||(adapter->IfType!=IF_TYPE_ETHERNET_CSMACD&&adapter->IfType!=IF_TYPE_IEEE80211)||!adapter->AdapterName)continue;
        wchar_t name[64]{};const size_t length=strnlen_s(adapter->AdapterName,64);if(!length||length>=64)continue;
        for(size_t n=0;n<length;++n)name[n]=static_cast<unsigned char>(adapter->AdapterName[n]);GUID id{};if(FAILED(CLSIDFromString(name,&id)))continue;
        auto profile=std::find_if(profiles.begin(),profiles.end(),[&](const auto& p){return IsEqualGUID(p.adapter,id)!=FALSE;});if(profile==profiles.end())continue;
        for(auto unicast=adapter->FirstUnicastAddress;unicast&&output.size()<MaxInterfaces;unicast=unicast->Next){
            if(unicast->DadState!=IpDadStatePreferred||unicast->Address.iSockaddrLength<static_cast<int>(sizeof(sockaddr_in))||!unicast->Address.lpSockaddr||unicast->Address.lpSockaddr->sa_family!=AF_INET||!unicast->OnLinkPrefixLength||unicast->OnLinkPrefixLength>30)continue;
            const uint32_t address=reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr)->sin_addr.s_addr;const auto host=ntohl(address);
            if(!host||(host>>24)==127||(host>>24)>=224||(host>>16)==0xa9fe)continue;
            output.push_back(Interface{address,adapter->IfIndex,unicast->OnLinkPrefixLength,profile->network});
        }
    }
    return output;
}
Socket Udp(uint32_t address,uint16_t port){
    Socket socket;socket.value=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(socket.value==INVALID_SOCKET)return socket;
    BOOL yes=TRUE;DWORD ttl=1;u_long nonblocking=1;int buffer=16384;
    if(setsockopt(socket.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&yes),sizeof(yes))||setsockopt(socket.value,SOL_SOCKET,SO_BROADCAST,reinterpret_cast<const char*>(&yes),sizeof(yes))||setsockopt(socket.value,IPPROTO_IP,IP_TTL,reinterpret_cast<const char*>(&ttl),sizeof(ttl))||ioctlsocket(socket.value,FIONBIO,&nonblocking))return {};
    setsockopt(socket.value,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<const char*>(&buffer),sizeof(buffer));
    sockaddr_in bindTo{};bindTo.sin_family=AF_INET;bindTo.sin_port=htons(port);bindTo.sin_addr.s_addr=address;if(bind(socket.value,reinterpret_cast<const sockaddr*>(&bindTo),sizeof(bindTo)))return {};return socket;
}
struct Worker:std::enable_shared_from_this<Worker> {
    Handle stop{CreateEventW(nullptr,TRUE,FALSE,nullptr)},done{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    std::atomic<bool> stopping{false},refresh{true};std::atomic<unsigned> flags{0};
    DiscoveryAnnouncement announcement;std::function<void()> changed;std::mutex mutex,callbackMutex;std::vector<DiscoveredHost> hosts;
    explicit Worker(){if(!stop.value||!done.value)throw std::runtime_error("LAN discovery event creation failed.");hosts.reserve(MaxHosts);}
    void Notify()noexcept{try{std::lock_guard<std::mutex> lock(callbackMutex);if(!stopping&&changed)changed();}catch(...){}}
    void Browse(){
        struct BrowserSocket {Interface adapter;Socket socket;};std::vector<BrowserSocket> sockets;
        struct Pending {Nonce nonce{};uint64_t sent=0;};std::array<Pending,4> pending{};size_t slot=0;
        uint64_t lastScan=0,lastInterfaces=0;
        while(!stopping){
            const uint64_t now=GetTickCount64();
            if(!lastInterfaces||now-lastInterfaces>=3000){
                sockets.clear();for(auto& adapter:Interfaces()){
                    auto socket=Udp(adapter.address,0);if(socket.value==INVALID_SOCKET)continue;
                    const DWORD yes=1,index=adapter.index,outgoing=htonl(index);
                    if(setsockopt(socket.value,IPPROTO_IP,IP_IFLIST,reinterpret_cast<const char*>(&yes),sizeof(yes))||setsockopt(socket.value,IPPROTO_IP,IP_ADD_IFLIST,reinterpret_cast<const char*>(&index),sizeof(index))||setsockopt(socket.value,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&outgoing),sizeof(outgoing)))continue;
                    sockets.push_back(BrowserSocket{std::move(adapter),std::move(socket)});
                }lastInterfaces=now;
            }
            if(stopping)break;
            if((!lastScan||now-lastScan>=2000||refresh.load())&&(!lastScan||now-lastScan>=1000)){
                refresh=false;lastScan=now;auto& request=pending[slot++%pending.size()];request.sent=now;
                if(BCryptGenRandom(nullptr,request.nonce.data(),static_cast<ULONG>(request.nonce.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("LAN discovery nonce generation failed.");const auto query=Query(request.nonce);
                for(auto& item:sockets){if(stopping)break;if(!Private(item.adapter.network.Get()))continue;
                    sockaddr_in destination{};destination.sin_family=AF_INET;destination.sin_port=htons(DiscoveryPort);const uint32_t mask=0xffffffffu<<(32-item.adapter.prefix);destination.sin_addr.s_addr=htonl(ntohl(item.adapter.address)|~mask);
                    sendto(item.socket.value,reinterpret_cast<const char*>(query.data()),static_cast<int>(query.size()),0,reinterpret_cast<const sockaddr*>(&destination),sizeof(destination));
                }
            }
            bool modified=false;
            for(auto& item:sockets){
                for(unsigned packets=0;packets<16&&!stopping;++packets){
                    std::array<uint8_t,ReplyBytes+1> data{};sockaddr_in peer{};int length=sizeof(peer);const int count=recvfrom(item.socket.value,reinterpret_cast<char*>(data.data()),static_cast<int>(data.size()),0,reinterpret_cast<sockaddr*>(&peer),&length);
                    if(count==SOCKET_ERROR)break;
                    if(length!=sizeof(peer)||peer.sin_family!=AF_INET||peer.sin_port!=htons(DiscoveryPort)||!Subnet(peer.sin_addr.s_addr,item.adapter.address,item.adapter.prefix))continue;
                    DiscoveryAnnouncement response;bool matched=false;
                    for(const auto& request:pending)if(request.sent&&!Expired(request.sent,now,NonceTtl)&&ParseReply(data.data(),static_cast<size_t>(count),request.nonce,response)){matched=true;break;}
                    if(!matched||!Private(item.adapter.network.Get())||stopping)continue;char address[INET_ADDRSTRLEN]{};if(!InetNtopA(AF_INET,&peer.sin_addr,address,sizeof(address)))continue;
                    DiscoveredHost host;static_cast<DiscoveryAnnouncement&>(host)=std::move(response);host.address=address;
                    {std::lock_guard<std::mutex> lock(mutex);modified=Remember(hosts,std::move(host),GetTickCount64())||modified;}
                }
            }
            {std::lock_guard<std::mutex> lock(mutex);modified=Purge(hosts,GetTickCount64())||modified;}if(modified)Notify();
            if(WaitForSingleObject(stop.value,100)==WAIT_OBJECT_0)break;
        }
    }
    void Respond(){
        Socket socket;std::vector<Interface> adapters;LPFN_WSARECVMSG receive=nullptr;uint64_t lastInterfaces=0,window=0;unsigned replies=0;
        while(!stopping){
            const uint64_t now=GetTickCount64();
            if(!lastInterfaces||now-lastInterfaces>=3000){
                socket={};adapters=Interfaces();lastInterfaces=now;
                if(!adapters.empty()){
                    socket=Udp(INADDR_ANY,DiscoveryPort);if(socket.value!=INVALID_SOCKET){
                        DWORD yes=1;bool enabled=setsockopt(socket.value,IPPROTO_IP,IP_IFLIST,reinterpret_cast<const char*>(&yes),sizeof(yes))==0&&setsockopt(socket.value,IPPROTO_IP,IP_PKTINFO,reinterpret_cast<const char*>(&yes),sizeof(yes))==0;
                        for(const auto& adapter:adapters){const DWORD index=adapter.index;if(setsockopt(socket.value,IPPROTO_IP,IP_ADD_IFLIST,reinterpret_cast<const char*>(&index),sizeof(index)))enabled=false;}
                        GUID function=WSAID_WSARECVMSG;DWORD bytes=0;receive=nullptr;if(WSAIoctl(socket.value,SIO_GET_EXTENSION_FUNCTION_POINTER,&function,sizeof(function),&receive,sizeof(receive),&bytes,nullptr,nullptr))enabled=false;
                        if(!enabled)socket={};
                    }
                }
            }
            if(stopping)break;
            if(!window||now-window>=1000){window=now;replies=0;}
            if(socket.value!=INVALID_SOCKET&&receive){
                for(unsigned packets=0;packets<32&&!stopping;++packets){
                    std::array<uint8_t,QueryBytes+1> data{};std::array<char,WSA_CMSG_SPACE(sizeof(IN_PKTINFO))> control{};sockaddr_in peer{};
                    WSABUF buffer{static_cast<ULONG>(data.size()),reinterpret_cast<char*>(data.data())};WSAMSG message{};message.name=reinterpret_cast<sockaddr*>(&peer);message.namelen=sizeof(peer);message.lpBuffers=&buffer;message.dwBufferCount=1;message.Control.buf=control.data();message.Control.len=static_cast<ULONG>(control.size());DWORD count=0;
                    if(receive(socket.value,&message,&count,nullptr,nullptr)==SOCKET_ERROR)break;
                    if(message.dwFlags&(MSG_TRUNC|MSG_CTRUNC)||message.namelen!=sizeof(peer)||peer.sin_family!=AF_INET||ntohs(peer.sin_port)<1024||replies>=20)continue;
                    Nonce nonce{};if(!ParseQuery(data.data(),count,nonce))continue;
                    const IN_PKTINFO* info=nullptr;
                    for(auto cmsg=WSA_CMSG_FIRSTHDR(&message);cmsg;cmsg=WSA_CMSG_NXTHDR(&message,cmsg))if(cmsg->cmsg_level==IPPROTO_IP&&cmsg->cmsg_type==IP_PKTINFO&&cmsg->cmsg_len>=WSA_CMSG_LEN(sizeof(IN_PKTINFO))){info=reinterpret_cast<const IN_PKTINFO*>(WSA_CMSG_DATA(cmsg));break;}
                    if(!info)continue;auto adapter=std::find_if(adapters.begin(),adapters.end(),[&](const auto& a){const uint32_t mask=0xffffffffu<<(32-a.prefix);const uint32_t destination=ntohl(info->ipi_addr.s_addr);return a.index==info->ipi_ifindex&&(destination==ntohl(a.address)||destination==(ntohl(a.address)|~mask))&&Subnet(peer.sin_addr.s_addr,a.address,a.prefix);});
                    if(adapter==adapters.end()||!Private(adapter->network.Get())||stopping)continue;
                    auto item=announcement;const auto current=flags.load();item.busy=(current&1)!=0;item.available=(current&2)!=0;const auto response=Reply(item,nonce);
                    const DWORD index=htonl(adapter->index);if(setsockopt(socket.value,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&index),sizeof(index)))continue;
                    ++replies;sendto(socket.value,reinterpret_cast<const char*>(response.data()),static_cast<int>(response.size()),0,reinterpret_cast<const sockaddr*>(&peer),sizeof(peer));
                }
            }
            if(WaitForSingleObject(stop.value,50)==WAIT_OBJECT_0)break;
        }
    }
    void Run(bool responder)noexcept{
        WSADATA data{};const bool winsock=WSAStartup(MAKEWORD(2,2),&data)==0;const auto com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        if(winsock&&SUCCEEDED(com)){try{if(responder)Respond();else Browse();}catch(...){}}
        if(SUCCEEDED(com))CoUninitialize();if(winsock)WSACleanup();SetEvent(done.value);
    }
};
struct Lifecycle {
    std::mutex mutex;std::shared_ptr<Worker> current;std::thread thread;
    void StopLocked()noexcept{
        if(!current)return;current->stopping=true;SetEvent(current->stop.value);
        {std::lock_guard<std::mutex> callbackLock(current->callbackMutex);current->changed={};}
        // A slow Windows profile RPC must not hold up uninstall. The retained
        // shared worker owns all resources, checks stopping before any I/O,
        // and a replacement is refused until the former worker has exited.
        if(thread.joinable()){if(WaitForSingleObject(current->done.value,250)==WAIT_OBJECT_0)thread.join();else thread.detach();}
    }
    void StartLocked(std::shared_ptr<Worker> worker,bool responder){
        StopLocked();if(current&&WaitForSingleObject(current->done.value,0)!=WAIT_OBJECT_0)throw std::runtime_error("The previous LAN discovery adapter query is still stopping.");
        current=std::move(worker);try{thread=std::thread([state=current,responder]{state->Run(responder);});}catch(...){current.reset();throw;}
    }
};
}
struct DiscoveryResponder::State {Lifecycle life;};
struct DiscoveryBrowser::State {Lifecycle life;};
DiscoveryResponder::DiscoveryResponder():state_(std::make_unique<State>()){}
DiscoveryResponder::~DiscoveryResponder(){Stop();}
void DiscoveryResponder::Start(DiscoveryAnnouncement announcement){
    if(!Valid(announcement))throw std::runtime_error("LAN discovery needs a valid display name, room ID, fingerprint and TCP port.");
    auto worker=std::make_shared<Worker>();worker->announcement=std::move(announcement);worker->flags=(worker->announcement.busy?1u:0u)|(worker->announcement.available?2u:0u);
    std::lock_guard<std::mutex> lock(state_->life.mutex);state_->life.StartLocked(std::move(worker),true);
}
void DiscoveryResponder::Update(bool busy,bool available)noexcept{try{std::lock_guard<std::mutex> lock(state_->life.mutex);if(state_->life.current)state_->life.current->flags=(busy?1u:0u)|(available?2u:0u);}catch(...){}}
void DiscoveryResponder::Stop()noexcept{try{std::lock_guard<std::mutex> lock(state_->life.mutex);state_->life.StopLocked();}catch(...){}}
DiscoveryBrowser::DiscoveryBrowser():state_(std::make_unique<State>()){}
DiscoveryBrowser::~DiscoveryBrowser(){Stop();}
void DiscoveryBrowser::Start(std::function<void()> changed){auto worker=std::make_shared<Worker>();worker->changed=std::move(changed);std::lock_guard<std::mutex> lock(state_->life.mutex);state_->life.StartLocked(std::move(worker),false);}
void DiscoveryBrowser::Refresh()noexcept{try{std::lock_guard<std::mutex> lock(state_->life.mutex);if(state_->life.current)state_->life.current->refresh=true;}catch(...){}}
std::vector<DiscoveredHost> DiscoveryBrowser::Hosts()const{
    std::shared_ptr<Worker> worker;{std::lock_guard<std::mutex> lock(state_->life.mutex);worker=state_->life.current;}if(!worker||worker->stopping)return {};
    std::lock_guard<std::mutex> lock(worker->mutex);auto hosts=worker->hosts;Purge(hosts,GetTickCount64());return hosts;
}
void DiscoveryBrowser::Stop()noexcept{try{std::lock_guard<std::mutex> lock(state_->life.mutex);state_->life.StopLocked();}catch(...){}}

// Internal deterministic test entry points; no sockets, adapter queries or
// local/remote machine state are used by the offline regression suite.
namespace DiscoveryTesting {
std::vector<uint8_t> QueryBytesFor(const std::array<uint8_t,16>& nonce){auto bytes=Query(nonce);return {bytes.begin(),bytes.end()};}
bool QueryValid(const std::vector<uint8_t>& bytes){Nonce nonce{};return ParseQuery(bytes.data(),bytes.size(),nonce);}
std::vector<uint8_t> ReplyBytesFor(const DiscoveryAnnouncement& item,const std::array<uint8_t,16>& nonce){auto bytes=Reply(item,nonce);return {bytes.begin(),bytes.end()};}
bool ReplyValid(const std::vector<uint8_t>& bytes,const std::array<uint8_t,16>& nonce){DiscoveryAnnouncement item;return ParseReply(bytes.data(),bytes.size(),nonce,item);}
bool SameSubnet(uint32_t source,uint32_t address,unsigned prefix){return Subnet(source,address,prefix);}
bool Add(std::vector<DiscoveredHost>& hosts,DiscoveredHost host,uint64_t now){return Remember(hosts,std::move(host),now);}
bool Expire(std::vector<DiscoveredHost>& hosts,uint64_t now){return Purge(hosts,now);}
}
}
