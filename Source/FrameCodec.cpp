#include "FrameCodec.h"
#include <windows.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>

namespace RemoteControl {
namespace {
using Microsoft::WRL::ComPtr;
[[noreturn]] void Failure(const char* stage,HRESULT result){
    std::ostringstream text;text<<stage<<" failed (HRESULT 0x"<<std::hex<<std::setw(8)<<std::setfill('0')<<static_cast<uint32_t>(result)<<").";
    throw std::runtime_error(text.str());
}
void Check(HRESULT result,const char* stage){if(FAILED(result))Failure(stage,result);}
size_t PixelBytes(uint32_t width,uint32_t height){
    if(!width||width>MaxWidth||!height||height>MaxHeight)throw std::runtime_error("JPEG dimensions exceed the supported desktop bounds.");
    return static_cast<size_t>(width)*height*4;
}
// The WIC encoder can otherwise grow a memory stream before its caller gets a
// chance to inspect the resulting length. Cap every seek/write/resize instead.
class BoundedStream final:public IStream {
    std::atomic<ULONG> references_{1};size_t position_=0;
public:
    std::vector<uint8_t> bytes;
    BoundedStream(){bytes.reserve(MaxFrameBytes);}
    void Reset(){bytes.clear();position_=0;}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER;*out=nullptr;
        if(iid==IID_IUnknown||iid==IID_ISequentialStream||iid==IID_IStream){*out=static_cast<IStream*>(this);AddRef();return S_OK;}return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++references_;}
    ULONG STDMETHODCALLTYPE Release() override{const ULONG count=--references_;if(!count)delete this;return count;}
    HRESULT STDMETHODCALLTYPE Read(void* out,ULONG length,ULONG* read) override {
        if(read)*read=0;if(length&&!out)return STG_E_INVALIDPOINTER;
        const size_t count=(std::min)(static_cast<size_t>(length),position_<bytes.size()?bytes.size()-position_:0);
        if(count)std::memcpy(out,bytes.data()+position_,count);position_+=count;if(read)*read=static_cast<ULONG>(count);return count==length?S_OK:S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Write(const void* input,ULONG length,ULONG* written) override {
        if(written)*written=0;if(length&&!input)return STG_E_INVALIDPOINTER;
        if(length>MaxFrameBytes-position_)return STG_E_MEDIUMFULL;
        try{const size_t end=position_+length;if(bytes.size()<end)bytes.resize(end);if(length)std::memcpy(bytes.data()+position_,input,length);position_=end;if(written)*written=length;return S_OK;}
        catch(...){return E_OUTOFMEMORY;}
    }
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER offset,DWORD origin,ULARGE_INTEGER* result) override {
        size_t base=0;if(origin==STREAM_SEEK_CUR)base=position_;else if(origin==STREAM_SEEK_END)base=bytes.size();else if(origin!=STREAM_SEEK_SET)return STG_E_INVALIDFUNCTION;
        if(offset.QuadPart < -static_cast<LONGLONG>(base)||offset.QuadPart>static_cast<LONGLONG>(MaxFrameBytes-base))return STG_E_INVALIDFUNCTION;
        position_=static_cast<size_t>(static_cast<LONGLONG>(base)+offset.QuadPart);if(result)result->QuadPart=position_;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER size) override {
        if(size.QuadPart>MaxFrameBytes)return STG_E_MEDIUMFULL;
        try{bytes.resize(static_cast<size_t>(size.QuadPart));return S_OK;}catch(...){return E_OUTOFMEMORY;}
    }
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*,ULARGE_INTEGER,ULARGE_INTEGER*,ULARGE_INTEGER*) override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override{return S_OK;}
    HRESULT STDMETHODCALLTYPE Revert() override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* out,DWORD) override {
        if(!out)return E_POINTER;*out={};out->type=STGTY_STREAM;out->cbSize.QuadPart=bytes.size();out->grfMode=STGM_READWRITE;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Clone(IStream** out) override{if(out)*out=nullptr;return E_NOTIMPL;}
};
// Avoid copying an entire BGRA image into a temporary IWICBitmap. The source
// lives until this synchronous Encode call finishes; WIC converts rows to BGR.
class BgraSource final:public IWICBitmapSource {
    std::atomic<ULONG> references_{1};const Frame& frame_;
public:
    explicit BgraSource(const Frame& frame):frame_(frame){}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER;*out=nullptr;
        if(iid==IID_IUnknown||iid==__uuidof(IWICBitmapSource)){*out=static_cast<IWICBitmapSource*>(this);AddRef();return S_OK;}return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++references_;}
    ULONG STDMETHODCALLTYPE Release() override{const ULONG count=--references_;if(!count)delete this;return count;}
    HRESULT STDMETHODCALLTYPE GetSize(UINT* width,UINT* height) override{if(!width||!height)return E_POINTER;*width=frame_.width;*height=frame_.height;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetPixelFormat(WICPixelFormatGUID* format) override{if(!format)return E_POINTER;*format=GUID_WICPixelFormat32bppBGRA;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetResolution(double* x,double* y) override{if(!x||!y)return E_POINTER;*x=*y=96.;return S_OK;}
    HRESULT STDMETHODCALLTYPE CopyPalette(IWICPalette*) override{return WINCODEC_ERR_PALETTEUNAVAILABLE;}
    HRESULT STDMETHODCALLTYPE CopyPixels(const WICRect* rectangle,UINT stride,UINT capacity,BYTE* out) override {
        if(!out)return E_POINTER;WICRect area{0,0,static_cast<INT>(frame_.width),static_cast<INT>(frame_.height)};if(rectangle)area=*rectangle;
        if(area.X<0||area.Y<0||area.Width<=0||area.Height<=0||static_cast<uint64_t>(area.X)+area.Width>frame_.width||static_cast<uint64_t>(area.Y)+area.Height>frame_.height)return E_INVALIDARG;
        const uint64_t row=static_cast<uint64_t>(area.Width)*4;
        if(stride<row||static_cast<uint64_t>(stride)*(area.Height-1)+row>capacity)return WINCODEC_ERR_INSUFFICIENTBUFFER;
        for(INT y=0;y<area.Height;++y)std::memcpy(out+static_cast<size_t>(y)*stride,frame_.bgra.data()+(static_cast<size_t>(area.Y+y)*frame_.width+static_cast<UINT>(area.X))*4,static_cast<size_t>(row));
        return S_OK;
    }
};
}

struct FrameCodec::State {
    bool initialized=false;DWORD thread=GetCurrentThreadId();ComPtr<IWICImagingFactory> factory;ComPtr<BoundedStream> output;
    State(){
        const HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        if(SUCCEEDED(result))initialized=true;else if(result!=RPC_E_CHANGED_MODE)Failure("JPEG COM initialization",result);
        try{Check(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(factory.GetAddressOf())),"Windows JPEG factory creation");}
        catch(...){output.Reset();factory.Reset();if(initialized)CoUninitialize();throw;}
    }
    ~State(){output.Reset();factory.Reset();if(initialized)CoUninitialize();}
    void OnThread()const{if(GetCurrentThreadId()!=thread)throw std::runtime_error("Use each JPEG codec on its owning worker thread.");}
};
FrameCodec::FrameCodec():state_(std::make_unique<State>()){}
FrameCodec::~FrameCodec()=default;

std::vector<uint8_t> FrameCodec::Encode(const Frame& frame,unsigned quality){
    state_->OnThread();const size_t bytes=PixelBytes(frame.width,frame.height);
    if(frame.bgra.size()!=bytes)throw std::runtime_error("JPEG input BGRA byte count differs from its dimensions.");
    if(!quality||quality>100)throw std::runtime_error("JPEG quality must be from 1 to 100.");
    auto& stream=state_->output;if(!stream)stream.Attach(new BoundedStream());stream->Reset();
    ComPtr<IWICBitmapEncoder> encoder;Check(state_->factory->CreateEncoder(GUID_ContainerFormatJpeg,nullptr,&encoder),"JPEG encoder creation");
    Check(encoder->Initialize(stream.Get(),WICBitmapEncoderNoCache),"JPEG stream initialization");
    ComPtr<IWICBitmapFrameEncode> image;ComPtr<IPropertyBag2> properties;Check(encoder->CreateNewFrame(&image,&properties),"JPEG frame creation");
    PROPBAG2 option{};option.pstrName=const_cast<LPOLESTR>(L"ImageQuality");VARIANT value{};value.vt=VT_R4;value.fltVal=static_cast<float>(quality)/100.f;
    Check(properties->Write(1,&option,&value),"JPEG quality selection");Check(image->Initialize(properties.Get()),"JPEG frame initialization");
    Check(image->SetSize(frame.width,frame.height),"JPEG frame dimensions");
    WICPixelFormatGUID format=GUID_WICPixelFormat24bppBGR;Check(image->SetPixelFormat(&format),"JPEG pixel format");
    if(format!=GUID_WICPixelFormat24bppBGR)throw std::runtime_error("Windows JPEG encoder did not accept 24-bit BGR input.");
    ComPtr<BgraSource> source;source.Attach(new BgraSource(frame));ComPtr<IWICFormatConverter> converter;
    Check(state_->factory->CreateFormatConverter(&converter),"JPEG input converter creation");
    Check(converter->Initialize(source.Get(),format,WICBitmapDitherTypeNone,nullptr,0,WICBitmapPaletteTypeCustom),"JPEG input conversion");
    Check(image->WriteSource(converter.Get(),nullptr),"JPEG bounded encoding");Check(image->Commit(),"JPEG image completion");Check(encoder->Commit(),"JPEG stream completion");
    if(stream->bytes.empty()||stream->bytes.size()>MaxFrameBytes)throw std::runtime_error("JPEG output exceeds the encoded frame limit.");
    image.Reset();encoder.Reset();return stream->bytes;
}
Frame FrameCodec::Decode(const std::vector<uint8_t>& jpeg){
    state_->OnThread();
    if(jpeg.size()<4||jpeg.size()>MaxFrameBytes||jpeg[0]!=0xff||jpeg[1]!=0xd8)throw std::runtime_error("Invalid or oversized JPEG frame.");
    ComPtr<IWICStream> stream;Check(state_->factory->CreateStream(&stream),"JPEG input stream creation");
    Check(stream->InitializeFromMemory(const_cast<BYTE*>(jpeg.data()),static_cast<DWORD>(jpeg.size())),"JPEG input stream initialization");
    ComPtr<IWICBitmapDecoder> decoder;Check(state_->factory->CreateDecoderFromStream(stream.Get(),nullptr,WICDecodeMetadataCacheOnDemand,&decoder),"JPEG decoding");
    UINT count=0;Check(decoder->GetFrameCount(&count),"JPEG frame count");if(count!=1)throw std::runtime_error("A remote JPEG packet must contain one image.");
    ComPtr<IWICBitmapFrameDecode> image;Check(decoder->GetFrame(0,&image),"JPEG image decoding");
    Frame out;Check(image->GetSize(&out.width,&out.height),"JPEG decoded dimensions");const size_t bytes=PixelBytes(out.width,out.height);
    ComPtr<IWICFormatConverter> converter;Check(state_->factory->CreateFormatConverter(&converter),"JPEG output converter creation");
    Check(converter->Initialize(image.Get(),GUID_WICPixelFormat32bppBGRA,WICBitmapDitherTypeNone,nullptr,0,WICBitmapPaletteTypeCustom),"JPEG output conversion");
    out.bgra.resize(bytes);Check(converter->CopyPixels(nullptr,out.width*4,static_cast<UINT>(bytes),out.bgra.data()),"JPEG pixel decoding");return out;
}
}
