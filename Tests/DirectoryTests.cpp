#include "Directory.h"
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace RemoteControl;
int main(){try{
 unsigned checks=0;auto check=[&](bool value){++checks;if(!value)throw std::runtime_error("Directory fixture check failed.");};
 PublicHost host;host.name="Fixture \"quoted\" PC";host.room=std::string(32,'a');host.pin=std::string(64,'b');host.relayToken=std::string(64,'c');const auto encoded=DirectoryFormat::Encode(host);const auto document="{\"hosts\":["+encoded+"]}";auto decoded=DirectoryFormat::Decode(document);check(decoded.size()==1&&decoded[0].name==host.name&&decoded[0].room==host.room&&decoded[0].requireApproval);
 check(DirectoryFormat::Decode("{\"hosts\":[]}").empty());
 for(const auto& bad:{std::string(""),std::string("[]"),std::string("{\"hosts\":null}"),std::string("{\"hosts\":[],\"extra\":1}"),"{\"hosts\":["+encoded+","+encoded+"]}","{\"hosts\":["+encoded+",]}","{\"hosts\":["+encoded+"],}",std::string(65537,' '),std::string("{\"hosts\":[{\"name\":\"\\ud800\"}]}"),std::string("{\"hosts\":[{\"name\":\"\\udc00\"}]}"),std::string("{\"hosts\":[{\"name\":\"x\",\"name\":\"x\"}]}")}){bool refused=false;try{(void)DirectoryFormat::Decode(bad);}catch(...){refused=true;}check(refused);}
 auto unicode=encoded;const auto start=unicode.find("Fixture");unicode.replace(start,7,"\\u00e9");check(DirectoryFormat::Decode("{\"hosts\":["+unicode+"]}")[0].name.find("\xc3\xa9")==0);
 std::string many="{\"hosts\":[";for(unsigned i=0;i<65;++i){auto next=host;constexpr char hex[]="0123456789abcdef";next.room[30]=hex[i/16];next.room[31]=hex[i%16];if(i)many+=',';many+=DirectoryFormat::Encode(next);}many+="]}";bool refused=false;try{(void)DirectoryFormat::Decode(many);}catch(...){refused=true;}check(refused);
 for(auto bad: {std::string(""),std::string(63,'a'),std::string(64,'x')}){refused=false;try{PublishPublicHost(host,bad);}catch(...){refused=true;}check(refused);}
 const auto begin=std::chrono::steady_clock::now();refused=false;try{(void)BrowsePublicHosts([]{return true;});}catch(const std::exception& e){refused=std::string(e.what()).find("995")!=std::string::npos;}check(refused);check(std::chrono::steady_clock::now()-begin<std::chrono::milliseconds(100));
 std::cout<<"PASS "<<checks<<" directory codec/bounds/owner/cancellation checks. No network request or host discovery performed.\n";
 }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
