#include "Discovery.h"
#include <winsock2.h>
#include <array>
#include <iostream>
#include <stdexcept>
namespace RemoteControl::DiscoveryTesting {
std::vector<uint8_t> QueryBytesFor(const std::array<uint8_t,16>&);
bool QueryValid(const std::vector<uint8_t>&);
std::vector<uint8_t> ReplyBytesFor(const DiscoveryAnnouncement&,const std::array<uint8_t,16>&);
bool ReplyValid(const std::vector<uint8_t>&,const std::array<uint8_t,16>&);
bool SameSubnet(uint32_t,uint32_t,unsigned);
bool Add(std::vector<DiscoveredHost>&,DiscoveredHost,uint64_t);
bool Expire(std::vector<DiscoveredHost>&,uint64_t);
}
int main(){try{
    using namespace RemoteControl;using namespace DiscoveryTesting;size_t checks=0;auto check=[&](bool value){++checks;if(!value)throw std::runtime_error("Discovery regression check "+std::to_string(checks)+" failed.");};
    std::array<uint8_t,16> nonce{};nonce[3]=27;auto query=QueryBytesFor(nonce);check(query.size()==1024&&QueryValid(query));
    auto wrong=query;wrong.push_back(0);check(!QueryValid(wrong));wrong=query;wrong.pop_back();check(!QueryValid(wrong));wrong=query;wrong[1000]=1;check(!QueryValid(wrong));wrong=query;wrong[8]=2;check(!QueryValid(wrong));check(!QueryValid(QueryBytesFor({})));
    DiscoveryAnnouncement item;item.name="Sample PC";item.room=std::string(32,'a');item.pin=std::string(64,'b');item.available=true;auto response=ReplyBytesFor(item,nonce);check(response.size()==512&&response.size()<query.size()&&ReplyValid(response,nonce));
    auto other=nonce;other[0]^=1;check(!ReplyValid(response,other));wrong=response;wrong.resize(513);check(!ReplyValid(wrong,nonce));wrong=response;wrong.resize(511);check(!ReplyValid(wrong,nonce));
    for(size_t offset:{size_t(0),size_t(8),size_t(9),size_t(29),size_t(32),size_t(64),size_t(500)}){wrong=response;wrong[offset]=255;check(!ReplyValid(wrong,nonce));}
    wrong=response;wrong[10]=wrong[11]=0;check(!ReplyValid(wrong,nonce));wrong=response;wrong[28]=97;check(!ReplyValid(wrong,nonce));wrong=response;wrong[128]=0xc0;wrong[129]=0xaf;check(!ReplyValid(wrong,nonce));wrong=response;wrong[128]=0;check(!ReplyValid(wrong,nonce));
    auto rejected=[&](std::string name){auto invalid=item;invalid.name=std::move(name);try{ReplyBytesFor(invalid,nonce);return false;}catch(...){return true;}};check(rejected(""));check(rejected(std::string(97,'a')));check(rejected("Test\nPC"));check(rejected("Test\xE2\x80\xAE"));
    item.name="Ordinateur \xC3\xA9";item.busy=true;item.requireApproval=false;check(ReplyValid(ReplyBytesFor(item,nonce),nonce));
    const auto local=htonl(0xc0a80102);check(SameSubnet(htonl(0xc0a80103),local,24));for(auto source:{0u,0x7f000001u,0xc0a80203u,0xc0a80100u,0xc0a801ffu,0xc0a80102u,0xe0000001u})check(!SameSubnet(htonl(source),local,24));check(!SameSubnet(htonl(0xc0a80103),local,0));check(!SameSubnet(htonl(0xc0a80103),local,31));
    std::vector<DiscoveredHost> hosts;for(unsigned i=0;i<100;++i){DiscoveredHost host;static_cast<DiscoveryAnnouncement&>(host)=item;host.room=std::string(30,'a')+char('a'+i/16)+char('a'+i%16);host.address="192.168.1.3";Add(hosts,std::move(host),100);}check(hosts.size()==64);check(!Expire(hosts,6099));check(Expire(hosts,6100)&&hosts.empty());
    DiscoveredHost host;static_cast<DiscoveryAnnouncement&>(host)=item;host.address="192.168.1.3";check(Add(hosts,host,1000));check(!Add(hosts,host,2000)&&hosts.size()==1);host.busy=!host.busy;check(Add(hosts,host,3000)&&hosts[0].busy==host.busy);check(!Expire(hosts,8999));check(Expire(hosts,9000));check(Add(hosts,host,10000));check(Expire(hosts,9999)&&hosts.empty());
    // Mutation fuzzing must never allocate from attacker-controlled lengths.
    for(size_t n=0;n<response.size();++n){wrong=response;wrong[n]^=0x80;(void)ReplyValid(wrong,nonce);++checks;}
    std::cout<<"PASS "<<checks<<" offline LAN discovery nonce, packet, subnet, UTF-8, bounded list and TTL checks. No network I/O.\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
