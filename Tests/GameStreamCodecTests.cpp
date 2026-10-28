#include "GameStreamCodec.h"
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <codecapi.h>
#include <wmcodecdsp.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
using Microsoft::WRL::ComPtr;using namespace RemoteControl;
namespace {
unsigned checks=0;
void Check(bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);}
void Hr(HRESULT value,const char* text){if(FAILED(value))throw std::runtime_error(std::string(text)+" ("+std::to_string(static_cast<uint32_t>(value))+")");}
ComPtr<IMFMediaType> Type(REFGUID subtype,uint32_t w=128,uint32_t h=72){ComPtr<IMFMediaType> type;Hr(MFCreateMediaType(&type),"Create fixture type");Hr(type->SetGUID(MF_MT_MAJOR_TYPE,MFMediaType_Video),"Fixture major type");Hr(type->SetGUID(MF_MT_SUBTYPE,subtype),"Fixture subtype");Hr(MFSetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,w,h),"Fixture dimensions");Hr(MFSetAttributeRatio(type.Get(),MF_MT_FRAME_RATE,60,1),"Fixture rate");Hr(MFSetAttributeRatio(type.Get(),MF_MT_PIXEL_ASPECT_RATIO,1,1),"Fixture pixel aspect");Hr(type->SetUINT32(MF_MT_INTERLACE_MODE,MFVideoInterlace_Progressive),"Fixture progressive");return type;}
std::vector<std::vector<uint8_t>> Encoded(uint32_t w=128,uint32_t h=72,unsigned frameCount=4,bool allKeyFrames=true){
 ComPtr<IMFTransform> encoder;Hr(CoCreateInstance(__uuidof(CMSH264EncoderMFT),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&encoder)),"Create Windows fixture H264 encoder");ComPtr<ICodecAPI> api;Hr(encoder.As(&api),"Fixture codec API");VARIANT value;VariantInit(&value);value.vt=VT_UI4;value.ulVal=0;(void)api->SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount,&value);value.ulVal=allKeyFrames?1u:30u;(void)api->SetValue(&CODECAPI_AVEncMPVGOPSize,&value);ComPtr<IMFAttributes> attributes;Hr(encoder->GetAttributes(&attributes),"Fixture attributes");(void)attributes->SetUINT32(MF_LOW_LATENCY,TRUE);
 auto output=Type(MFVideoFormat_H264,w,h);Hr(output->SetUINT32(MF_MT_AVG_BITRATE,1000000),"Fixture bitrate");Hr(output->SetUINT32(MF_MT_MPEG2_PROFILE,eAVEncH264VProfile_Base),"Fixture baseline");Hr(encoder->SetOutputType(0,output.Get(),0),"Fixture H264 output");auto input=Type(MFVideoFormat_NV12,w,h);Hr(encoder->SetInputType(0,input.Get(),0),"Fixture NV12 input");Hr(encoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0),"Begin fixture");Hr(encoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0),"Start fixture");
 std::vector<std::vector<uint8_t>> frames;
 auto drain=[&]{for(unsigned attempt=0;attempt<16;++attempt){MFT_OUTPUT_STREAM_INFO info{};Hr(encoder->GetOutputStreamInfo(0,&info),"Fixture output policy");ComPtr<IMFSample> sample;ComPtr<IMFMediaBuffer> buffer;if(!(info.dwFlags&(MFT_OUTPUT_STREAM_PROVIDES_SAMPLES|MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES))){Hr(MFCreateSample(&sample),"Fixture output sample");Hr(MFCreateMemoryBuffer(info.cbSize,&buffer),"Fixture output buffer");Hr(sample->AddBuffer(buffer.Get()),"Fixture attach output");}MFT_OUTPUT_DATA_BUFFER data{};data.pSample=sample.Get();DWORD status=0;const auto result=encoder->ProcessOutput(0,1,&data,&status);if(data.pEvents)data.pEvents->Release();if(data.pSample!=sample.Get())sample.Attach(data.pSample);if(result==MF_E_TRANSFORM_NEED_MORE_INPUT)return;Hr(result,"Encode fixture output");Hr(sample->ConvertToContiguousBuffer(&buffer),"Fixture bytes");BYTE* bytes=nullptr;DWORD length=0;Hr(buffer->Lock(&bytes,nullptr,&length),"Lock fixture bytes");frames.emplace_back(bytes,bytes+length);Hr(buffer->Unlock(),"Unlock fixture bytes");}throw std::runtime_error("Fixture encoder drain exceeded bounds");};
 for(unsigned i=0;i<frameCount;++i){
  ComPtr<IMFSample> sample;ComPtr<IMFMediaBuffer> buffer;Hr(MFCreateSample(&sample),"Fixture input sample");Hr(MFCreateMemoryBuffer(w*h*3/2,&buffer),"Fixture NV12 buffer");BYTE* pixels=nullptr;Hr(buffer->Lock(&pixels,nullptr,nullptr),"Lock fixture NV12");
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<w;++x)pixels[y*w+x]=y<h*2/3?(x<w/2?uint8_t(40):uint8_t(200)):(x<w/2?uint8_t(63):uint8_t(32));
  std::fill_n(pixels+w*h,w*h/2,uint8_t(128));for(unsigned y=h/3;y<h/2;++y)for(unsigned x=0;x<w;x+=2){pixels[w*h+y*w+x]=x<w/2?uint8_t(102):uint8_t(240);pixels[w*h+y*w+x+1]=x<w/2?uint8_t(240):uint8_t(118);}
  Hr(buffer->Unlock(),"Unlock fixture NV12");Hr(buffer->SetCurrentLength(w*h*3/2),"Fixture NV12 length");Hr(sample->AddBuffer(buffer.Get()),"Fixture attach NV12");Hr(sample->SetSampleTime(i*166666),"Fixture sample time");Hr(sample->SetSampleDuration(166666),"Fixture duration");Hr(encoder->ProcessInput(0,sample.Get(),0),"Encode fixture input");drain();
 }
 Hr(encoder->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN,0),"Drain fixture encoder");drain();Check(frames.size()==frameCount,"Fixture encoder did not generate four frames");return frames;
}
}
int main(){const auto com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);bool mf=false;try{Hr(com,"Initialize fixture COM");Hr(MFStartup(MF_VERSION,MFSTARTUP_LITE),"Initialize fixture media");mf=true;const auto frames=Encoded();
 for(bool accelerated:{false,true}){GameStreamCodec decoder(accelerated);decoder.Configure(128,72,60);std::shared_ptr<Frame> latest;for(size_t i=0;i<frames.size();++i){const auto& bytes=frames[i];auto frame=decoder.Decode(bytes.data(),bytes.size(),i+1,true);if(frame)latest=frame;}Check(bool(latest),"Decoder did not return a synthetic frame");Check(latest->width==128&&latest->height==72&&latest->bgra.size()==128*72*4,"Decoded BGRA dimensions differ");Check(latest->sequence==4,"Decoded sequence correlation differs");const auto left=latest->bgra[(36*128+20)*4],right=latest->bgra[(36*128+100)*4];Check(left<80&&right>170&&right>left+100,"Decoded synthetic grayscale content differs");Check(std::abs(int(latest->bgra[(36*128+20)*4+1])-int(left))<4,"BGRA channel order differs");if(!accelerated)Check(!decoder.Hardware(),"Forced software path claimed GPU decoding");std::cout<<"PASS: "<<decoder.Description()<<"\n";
  const size_t red=(60*128+20)*4,blue=(60*128+100)*4;Check(latest->bgra[red]<50&&latest->bgra[red+2]>180&&latest->bgra[blue]>180&&latest->bgra[blue+2]<50,"Decoded color channel order or vertical orientation differs");
  for(const auto& invalid:std::vector<std::vector<uint8_t>>{{},{0,0,1,0x80,0},{1,2,3,4,5},{0,0,1,0x1f,0}}){bool refused=false;try{(void)decoder.Decode(invalid.data(),invalid.size(),9,true);}catch(...){refused=true;}Check(refused,"Malformed Annex-B access unit accepted");}
  bool wrongThread=false;std::thread other([&]{try{(void)decoder.Decode(frames[0].data(),frames[0].size(),10,true);}catch(...){wrongThread=true;}});other.join();Check(wrongThread,"Wrong-thread decoder call was accepted");decoder.Reset();Check(!decoder.Hardware(),"Reset retained hardware state");
 }
 const auto predicted=Encoded(128,72,4,false);for(bool gpu:{false,true}){GameStreamCodec decoder(gpu);decoder.Configure(128,72,60);Check(!decoder.Decode(predicted[1].data(),predicted[1].size(),1,false),"Dependent frame was decoded before initial keyframe");for(size_t i=0;i<predicted.size();++i){auto frame=decoder.Decode(predicted[i].data(),predicted[i].size(),i+1,i==0);Check(frame&&frame->sequence==i+1,"IPPP low-latency decode buffered/reordered a frame");}}
 for(const auto size:std::vector<std::array<uint32_t,2>>{{1280,720},{1920,1080}}){const auto encoded=Encoded(size[0],size[1],2);for(bool gpu:{false,true}){GameStreamCodec decoder(gpu);decoder.Configure(size[0],size[1],60);std::shared_ptr<Frame> latest;for(size_t i=0;i<encoded.size();++i){auto frame=decoder.Decode(encoded[i].data(),encoded[i].size(),i+1,true);if(frame)latest=frame;}Check(latest&&latest->width==size[0]&&latest->height==size[1]&&latest->bgra.size()==static_cast<size_t>(size[0])*size[1]*4,"HD or padded1080 H264 frame dimensions differ");const size_t offset=(static_cast<size_t>(size[1])*5/6*size[0]+size[0]/6)*4;Check(latest->bgra[offset]<50&&latest->bgra[offset+2]>180,"HD color crop or output orientation differs");}}
 for(auto invalid:std::vector<std::array<uint32_t,3>>{{0,720,60},{1922,1080,60},{1280,1082,60},{1279,720,60},{1280,719,60},{1280,720,0},{1280,720,241}}){bool refused=false;try{GameStreamCodec decoder;decoder.Configure(invalid[0],invalid[1],invalid[2]);}catch(...){refused=true;}Check(refused,"Invalid codec dimensions or rate accepted");}
 MFShutdown();CoUninitialize();std::cout<<"PASS "<<checks<<" H264 encode/decode, BGRA, fallback, bounds and thread-ownership checks. Synthetic pixels only; no capture, host, network or input.\n";return 0;
 }catch(const std::exception& error){if(mf)MFShutdown();if(SUCCEEDED(com))CoUninitialize();std::cerr<<error.what()<<'\n';return 1;}}
