
#include "EngineBundle.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace RemoteControl::EngineBundle;
namespace {
constexpr uint8_t Fixture[]={77,83,67,70,0,0,0,0,169,0,0,0,0,0,0,0,44,0,0,0,0,0,0,0,3,1,1,0,2,0,0,0,122,11,0,0,106,0,0,0,1,0,1,0,43,0,0,0,0,0,0,0,0,0,92,93,105,111,32,0,115,117,110,115,104,105,110,101,46,101,120,101,0,16,0,0,0,43,0,0,0,0,0,92,93,105,111,32,0,97,115,115,101,116,115,92,97,115,115,101,116,46,116,120,116,0,234,191,96,173,55,0,59,0,67,75,11,174,204,43,201,72,45,201,76,86,72,205,75,207,204,75,85,72,203,172,40,41,45,74,213,81,200,75,45,75,45,82,72,173,72,77,46,45,73,76,202,73,213,67,40,77,44,46,78,45,209,3,0};
constexpr char Manifest[]="RDC-ENGINE-1\n43	1348addedac0c88ce2eb06b22052af02a566b222008e178bf88c2fc2b468e3d8	sunshine.exe\n16	7c42bdd00722e74905b158e1d463bee6c8c533b6b64d2c9e731c2c719f6f1665	assets/asset.txt\n";
unsigned checks=0;
void Check(bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);}
std::vector<uint8_t> Bytes(std::string_view text){return {text.begin(),text.end()};}
bool Refused(std::string_view text){try{(void)ValidateManifest(text);return false;}catch(...){return true;}}
}
int main(){try{
 const std::string hash(64,'a');const auto row=[&](std::string path,std::string size="1"){return size+"\t"+hash+"\t"+path+"\n";};
 auto valid=ValidateManifest("RDC-ENGINE-1\r\n"+row("assets\\test-file_1.bin"));Check(valid.size()==1&&valid[0].path=="assets/test-file_1.bin"&&valid[0].size==1,"Canonical manifest parse failed");
 for(const auto& bad:std::vector<std::string>{"","RDC-ENGINE-1\n","RDC-ENGINE-2\n"+row("x"),"RDC-ENGINE-1\n\n","RDC-ENGINE-1\n"+row("x","-1"),"RDC-ENGINE-1\n"+row("x","+1"),"RDC-ENGINE-1\n"+row("x","134217729"),"RDC-ENGINE-1\n"+row("x","18446744073709551616"),"RDC-ENGINE-1\n"+row("x")+row("X"),"RDC-ENGINE-1\n1\t"+std::string(64,'A')+"\tx\n","RDC-ENGINE-1\n1\t"+std::string(63,'a')+"\tx\n",std::string(1048577,'x')})Check(Refused(bad),"Invalid manifest header/size/hash/count accepted");
 for(const auto* path:{"../x","x/../y","/root","C:/x","x:stream","x//y","x/","./x","x/./y","x.","x..y","CON","aux.txt","com1.dll","LPT9.bin","file name","file\tname",".rdc-manifest.txt",".rdc-engine-owner.txt","x/.. /y"})Check(Refused("RDC-ENGINE-1\n"+row(path)),"Unsafe Windows path accepted");
 std::string many="RDC-ENGINE-1\n";for(unsigned i=0;i<2049;++i)many+=row("file"+std::to_string(i));Check(Refused(many),"Excessive manifest file count accepted");
 std::string total="RDC-ENGINE-1\n";for(unsigned i=0;i<5;++i)total+=row("file"+std::to_string(i),"134217728");Check(Refused(total),"Excessive total extraction size accepted");
 Check(Refused("RDC-ENGINE-1\n"+row("assets")+row("assets/file.bin")),"File/directory collision accepted");
 std::string deep;for(unsigned i=0;i<33;++i)deep+="a/";Check(Refused("RDC-ENGINE-1\n"+row(deep+"x")),"Excessive directory nesting accepted");
 std::string maximum="RDC-ENGINE-1\n";for(unsigned i=0;i<4;++i)maximum+=row("file"+std::to_string(i),"134217728");Check(ValidateManifest(maximum).size()==4,"Exact total/file size limits rejected");
 std::vector<uint8_t> cabinet(std::begin(Fixture),std::end(Fixture));ValidateCabinet(cabinet,Bytes(Manifest));Check(true,"Synthetic cabinet validation failed");
 auto wrongHash=std::string(Manifest);auto tab=wrongHash.find('\t');wrongHash[tab+1]=wrongHash[tab+1]=='0'?'1':'0';bool rejected=false;try{ValidateCabinet(cabinet,Bytes(wrongHash));}catch(...){rejected=true;}Check(rejected,"Cabinet SHA mismatch accepted");
 auto wrongSize=std::string(Manifest);auto begin=wrongSize.find('\n')+1;wrongSize[begin]=wrongSize[begin]=='0'?'1':'0';rejected=false;try{ValidateCabinet(cabinet,Bytes(wrongSize));}catch(...){rejected=true;}Check(rejected,"Cabinet size mismatch accepted");
 auto truncated=cabinet;truncated.pop_back();rejected=false;try{ValidateCabinet(truncated,Bytes(Manifest));}catch(...){rejected=true;}Check(rejected,"Truncated cabinet accepted");
 const char unsafe[]="../evil1.exe";auto malicious=cabinet;auto found=std::search(malicious.begin(),malicious.end(),reinterpret_cast<const uint8_t*>("sunshine.exe"),reinterpret_cast<const uint8_t*>("sunshine.exe")+12);Check(found!=malicious.end(),"Synthetic CAB filename missing");std::copy_n(reinterpret_cast<const uint8_t*>(unsafe),12,found);rejected=false;try{ValidateCabinet(malicious,Bytes(Manifest));}catch(...){rejected=true;}Check(rejected,"CAB path traversal accepted");
 std::cout<<"PASS "<<checks<<" manifest/FDI/hash/path/bounds checks. Synthetic bytes only; no files extracted, engine executed, driver or service opened.\n";return 0;
 }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
