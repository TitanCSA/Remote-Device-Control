#include "../Source/FrameCodec.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <random>
#include <stdexcept>

namespace {
using namespace RemoteControl;
unsigned checks=0;
void Require(bool value,const char* message){if(!value)throw std::runtime_error(message);++checks;}
template<class Function>void Refused(Function function){bool rejected=false;try{function();}catch(const std::exception&){rejected=true;}Require(rejected,"Invalid JPEG/frame input was accepted");}
Frame Synthetic(uint32_t width,uint32_t height){
    Frame frame;frame.width=width;frame.height=height;frame.sequence=123;frame.capturedQpc=456;frame.bgra.resize(static_cast<size_t>(width)*height*4);
    for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x){const size_t p=(static_cast<size_t>(y)*width+x)*4;frame.bgra[p]=static_cast<uint8_t>(x*180/width+20);frame.bgra[p+1]=static_cast<uint8_t>(y*180/height+20);frame.bgra[p+2]=static_cast<uint8_t>((x*80/width+y*80/height)+30);frame.bgra[p+3]=255;}
    return frame;
}
void CheckDecoded(const Frame& source,const Frame& decoded){
    Require(source.width==decoded.width&&source.height==decoded.height,"JPEG dimensions changed");Require(source.bgra.size()==decoded.bgra.size(),"Decoded pixel count differs");
    double difference=0;size_t colors=0;bool opaque=true;
    for(size_t i=0;i<source.bgra.size();++i){if(i%4==3)opaque=opaque&&decoded.bgra[i]==255;else{difference+=std::abs(static_cast<int>(source.bgra[i])-decoded.bgra[i]);++colors;}}
    Require(opaque,"JPEG decoder did not return opaque BGRA");
    Require(difference/static_cast<double>(colors)<10.,"Synthetic JPEG image error exceeds the tested quality bound");
}
}
int main(){
    try{
        FrameCodec codec;
        for(const auto dimensions:{std::pair{16u,16u},std::pair{64u,48u},std::pair{1920u,1080u}}){
            const auto source=Synthetic(dimensions.first,dimensions.second);const auto encoded=codec.Encode(source,90);Require(!encoded.empty()&&encoded.size()<=MaxFrameBytes,"JPEG output exceeded its wire bound");
            const auto decoded=codec.Decode(encoded);CheckDecoded(source,decoded);Require(!decoded.sequence&&!decoded.capturedQpc,"JPEG bytes must not pretend to preserve authenticated wire metadata");
        }
        auto valid=Synthetic(64,48);auto jpeg=codec.Encode(valid);
        Refused([&]{codec.Encode(valid,0);});Refused([&]{codec.Encode(valid,101);});
        auto invalid=valid;invalid.bgra.pop_back();Refused([&]{codec.Encode(invalid);});
        invalid=valid;invalid.width=MaxWidth+1;Refused([&]{codec.Encode(invalid);});
        invalid=valid;invalid.height=MaxHeight+1;Refused([&]{codec.Encode(invalid);});
        invalid=valid;invalid.width=0;Refused([&]{codec.Encode(invalid);});
        Refused([&]{codec.Decode({});});Refused([&]{codec.Decode(std::vector<uint8_t>(MaxFrameBytes+1));});
        for(size_t size=0;size<128;++size){std::vector<uint8_t> garbage(size,0x53);if(size>=2){garbage[0]=0xff;garbage[1]=0xd8;}Refused([&]{codec.Decode(garbage);});}
        bool patched=false;
        for(size_t i=0;i+9<jpeg.size();++i)if(jpeg[i]==0xff&&(jpeg[i+1]==0xc0||jpeg[i+1]==0xc2)){
            auto oversized=jpeg;oversized[i+7]=static_cast<uint8_t>((MaxWidth+1)>>8);oversized[i+8]=static_cast<uint8_t>((MaxWidth+1)&255);Refused([&]{codec.Decode(oversized);});patched=true;break;
        }
        Require(patched,"Independent JPEG dimensions fixture did not find its start-of-frame marker");
        std::mt19937 random(991);
        for(unsigned iteration=0;iteration<96;++iteration){
            auto changed=jpeg;changed[random()%changed.size()]^=static_cast<uint8_t>((random()%255)+1);
            Frame decoded;bool accepted=false;try{decoded=codec.Decode(changed);accepted=true;}catch(const std::exception&){}
            if(accepted)Require(decoded.width&&decoded.width<=MaxWidth&&decoded.height&&decoded.height<=MaxHeight&&decoded.bgra.size()==static_cast<size_t>(decoded.width)*decoded.height*4,"Malformed JPEG escaped decoded-frame bounds");
        }
        const auto frame=Synthetic(1280,720);std::vector<double> encodeTimes,decodeTimes;size_t encodedBytes=0;
        for(unsigned iteration=0;iteration<20;++iteration){
            const auto before=std::chrono::steady_clock::now();auto encoded=codec.Encode(frame);const auto middle=std::chrono::steady_clock::now();auto decoded=codec.Decode(encoded);const auto after=std::chrono::steady_clock::now();
            Require(decoded.width==frame.width&&decoded.height==frame.height,"Benchmark codec roundtrip failed");encodedBytes+=encoded.size();
            encodeTimes.push_back(std::chrono::duration<double,std::milli>(middle-before).count());decodeTimes.push_back(std::chrono::duration<double,std::milli>(after-middle).count());
        }
        std::sort(encodeTimes.begin(),encodeTimes.end());std::sort(decodeTimes.begin(),decodeTimes.end());
        std::cout<<checks<<" offline JPEG bounds/quality checks passed. No desktop capture, input injection, service, driver or network access.\n";
        std::cout<<"Synthetic 1280x720 JPEG quality80, 20 iterations (nearest-rank quantiles): encode p50="<<encodeTimes[9]<<"ms p95="<<encodeTimes[18]<<"ms; decode p50="<<decodeTimes[9]<<"ms p95="<<decodeTimes[18]<<"ms; mean encoded bytes="<<encodedBytes/20<<". CPU codec only, not end-to-end desktop latency.\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
