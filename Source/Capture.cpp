#include "Capture.h"
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace RemoteControl {
namespace {
using Microsoft::WRL::ComPtr;
class GraphicsFailure final:public std::runtime_error {
public:
    HRESULT result;
    GraphicsFailure(const char* stage,HRESULT code):std::runtime_error(Message(stage,code)),result(code){}
    static std::string Message(const char* stage,HRESULT code){std::ostringstream text;text<<stage<<" failed (HRESULT 0x"<<std::hex<<std::setw(8)<<std::setfill('0')<<static_cast<uint32_t>(code)<<").";return text.str();}
};
void Check(HRESULT result,const char* stage){if(FAILED(result))throw GraphicsFailure(stage,result);}
void Require(bool value,const char* stage){if(!value)throw std::runtime_error(std::string(stage)+" failed (Windows error "+std::to_string(GetLastError())+").");}
uint64_t Timestamp(){LARGE_INTEGER value{};QueryPerformanceCounter(&value);return static_cast<uint64_t>(value.QuadPart);}
class DpiScope {
    DPI_AWARENESS_CONTEXT previous_=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
public:~DpiScope(){if(previous_)SetThreadDpiAwarenessContext(previous_);}
};
bool NamedObject(HANDLE object,const wchar_t* expected){
    wchar_t name[128]{};DWORD needed=0;
    return GetUserObjectInformationW(object,UOI_NAME,name,sizeof(name),&needed)!=FALSE&&_wcsicmp(name,expected)==0;
}
void CheckDesktop(){
    DWORD session=0;Require(ProcessIdToSessionId(GetCurrentProcessId(),&session)!=FALSE,"Capture session lookup");
    if(!session||session!=WTSGetActiveConsoleSessionId())throw std::runtime_error("Desktop capture requires the active logged-in console user; Session 0 and inactive sessions are not captured.");
    if(!NamedObject(GetProcessWindowStation(),L"WinSta0")||!NamedObject(GetThreadDesktop(GetCurrentThreadId()),L"Default"))throw std::runtime_error("Desktop capture is limited to the interactive DEFAULT desktop.");
    HDESK desktop=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS);
    if(!desktop)throw std::runtime_error("The current input desktop is unavailable. Unlock Windows and return to the console DEFAULT desktop.");
    const bool allowed=NamedObject(desktop,L"Default");CloseDesktop(desktop);
    if(!allowed)throw std::runtime_error("The secure or locked desktop is not shared. Unlock Windows to resume the DEFAULT desktop.");
}
}

struct Capture::State {
    uint32_t maxWidth,maxHeight,width=0,height=0;uint64_t sequence=0,retryAt=0;DWORD thread=GetCurrentThreadId();
    std::string backend="Not started";
    ComPtr<ID3D11Device> device;ComPtr<ID3D11DeviceContext> context;ComPtr<IDXGIOutputDuplication> duplication;ComPtr<ID3D11Texture2D> staging;
    uint32_t stagingWidth=0,stagingHeight=0;
    HDC screen=nullptr,memory=nullptr;HBITMAP bitmap=nullptr;HGDIOBJ previous=nullptr;void* pixels=nullptr;
    HCURSOR cursorHandle=nullptr;LONG cursorWidth=0,cursorHeight=0;DWORD hotX=0,hotY=0;uint64_t cursorRefreshAt=0;
    explicit State(uint32_t w,uint32_t h):maxWidth(w),maxHeight(h){if(!w||w>MaxWidth||!h||h>MaxHeight)throw std::runtime_error("Capture dimensions exceed the supported frame bounds.");}
    ~State(){ClearDib();if(memory)DeleteDC(memory);if(screen)ReleaseDC(nullptr,screen);}
    void ClearDib(){if(previous&&previous!=HGDI_ERROR&&memory)SelectObject(memory,previous);previous=nullptr;if(bitmap)DeleteObject(bitmap);bitmap=nullptr;pixels=nullptr;width=height=0;}
    void ResetDxgi(){staging.Reset();duplication.Reset();context.Reset();device.Reset();stagingWidth=stagingHeight=0;}
    void Surface(uint32_t sourceWidth,uint32_t sourceHeight){
        if(!sourceWidth||!sourceHeight||sourceWidth>32768||sourceHeight>32768)throw std::runtime_error("Primary desktop dimensions are unavailable or unsupported.");
        const double factor=(std::min)({1.,static_cast<double>(maxWidth)/sourceWidth,static_cast<double>(maxHeight)/sourceHeight});
        const uint32_t w=(std::max)(1u,static_cast<uint32_t>(sourceWidth*factor)),h=(std::max)(1u,static_cast<uint32_t>(sourceHeight*factor));
        if(w==width&&h==height&&pixels)return;
        ClearDib();if(!screen){screen=GetDC(nullptr);Require(screen!=nullptr,"Desktop capture DC");}
        if(!memory){memory=CreateCompatibleDC(screen);Require(memory!=nullptr,"Desktop image DC");}
        BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=static_cast<LONG>(w);info.bmiHeader.biHeight=-static_cast<LONG>(h);info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
        bitmap=CreateDIBSection(screen,&info,DIB_RGB_COLORS,&pixels,nullptr,0);Require(bitmap&&pixels,"Desktop capture bitmap");
        previous=SelectObject(memory,bitmap);Require(previous&&previous!=HGDI_ERROR,"Desktop capture bitmap selection");width=w;height=h;
    }
    void Cursor(uint32_t sourceWidth,uint32_t sourceHeight){
        CURSORINFO cursor{sizeof(cursor)};if(!GetCursorInfo(&cursor)||!(cursor.flags&CURSOR_SHOWING)||!cursor.hCursor)return;
        if(cursorHandle!=cursor.hCursor||GetTickCount64()>=cursorRefreshAt){
            ICONINFO icon{};if(!GetIconInfo(cursor.hCursor,&icon))return;
            struct Icons{ICONINFO& value;~Icons(){if(value.hbmColor)DeleteObject(value.hbmColor);if(value.hbmMask)DeleteObject(value.hbmMask);}} owned{icon};
            BITMAP dimensions{};const bool color=icon.hbmColor!=nullptr;
            if(!GetObjectW(color?icon.hbmColor:icon.hbmMask,sizeof(dimensions),&dimensions)||dimensions.bmWidth<=0||dimensions.bmHeight<=0)return;
            const LONG h=color?dimensions.bmHeight:dimensions.bmHeight/2;if(!h||dimensions.bmWidth>4096||h>4096)return;
            cursorHandle=cursor.hCursor;cursorWidth=dimensions.bmWidth;cursorHeight=h;hotX=icon.xHotspot;hotY=icon.yHotspot;cursorRefreshAt=GetTickCount64()+1000;
        }
        const int x=static_cast<int>((static_cast<int64_t>(cursor.ptScreenPos.x)-hotX)*width/sourceWidth);
        const int y=static_cast<int>((static_cast<int64_t>(cursor.ptScreenPos.y)-hotY)*height/sourceHeight);
        const int w=(std::max)(1,static_cast<int>(static_cast<int64_t>(cursorWidth)*width/sourceWidth));
        const int h=(std::max)(1,static_cast<int>(static_cast<int64_t>(cursorHeight)*height/sourceHeight));
        DrawIconEx(memory,x,y,cursor.hCursor,w,h,0,nullptr,DI_NORMAL);
    }
    void Finish(Frame& frame,uint64_t captured){
        CheckDesktop();GdiFlush();frame.width=width;frame.height=height;frame.capturedQpc=captured;frame.sequence=++sequence;
        const size_t bytes=static_cast<size_t>(width)*height*4;frame.bgra.resize(bytes);std::memcpy(frame.bgra.data(),pixels,bytes);
    }
    void InitDxgi(){
        ResetDxgi();ComPtr<IDXGIFactory1> factory;Check(CreateDXGIFactory1(IID_PPV_ARGS(&factory)),"DXGI factory creation");
        for(UINT a=0;;++a){
            ComPtr<IDXGIAdapter1> adapter;HRESULT result=factory->EnumAdapters1(a,&adapter);if(result==DXGI_ERROR_NOT_FOUND)break;Check(result,"DXGI adapter enumeration");
            for(UINT i=0;;++i){
                ComPtr<IDXGIOutput> output;result=adapter->EnumOutputs(i,&output);if(result==DXGI_ERROR_NOT_FOUND)break;Check(result,"DXGI output enumeration");
                DXGI_OUTPUT_DESC description{};Check(output->GetDesc(&description),"DXGI output description");
                MONITORINFO monitor{sizeof(monitor)};if(!description.AttachedToDesktop||!GetMonitorInfoW(description.Monitor,&monitor)||!(monitor.dwFlags&MONITORINFOF_PRIMARY))continue;
                if(description.Rotation!=DXGI_MODE_ROTATION_UNSPECIFIED&&description.Rotation!=DXGI_MODE_ROTATION_IDENTITY)throw GraphicsFailure("DXGI rotated-display compatibility",DXGI_ERROR_UNSUPPORTED);
                constexpr D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_1,D3D_FEATURE_LEVEL_10_0};
                Check(D3D11CreateDevice(adapter.Get(),D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,static_cast<UINT>(std::size(levels)),D3D11_SDK_VERSION,&device,nullptr,&context),"Desktop D3D11 device creation");
                ComPtr<IDXGIOutput1> primary;Check(output.As(&primary),"Desktop duplication interface");Check(primary->DuplicateOutput(device.Get(),&duplication),"Desktop duplication initialization");backend="DXGI Desktop Duplication (CPU readback + JPEG)";return;
            }
        }
        throw GraphicsFailure("Active primary DXGI output lookup",DXGI_ERROR_NOT_FOUND);
    }
    void Fallback(const GraphicsFailure& failure){
        ResetDxgi();
        if(failure.result==E_ACCESSDENIED||failure.result==DXGI_ERROR_SESSION_DISCONNECTED)throw std::runtime_error("Desktop access is unavailable; secure and disconnected sessions are not captured.");
        ClearDib();if(memory){DeleteDC(memory);memory=nullptr;}if(screen){ReleaseDC(nullptr,screen);screen=nullptr;}
        backend="GDI compatibility fallback: "+std::string(failure.what());retryAt=GetTickCount64()+5000;
    }
    bool Gdi(Frame& frame){
        const int sourceWidth=GetSystemMetrics(SM_CXSCREEN),sourceHeight=GetSystemMetrics(SM_CYSCREEN);
        if(sourceWidth<=0||sourceHeight<=0)throw std::runtime_error("No active primary desktop is available.");
        Surface(static_cast<uint32_t>(sourceWidth),static_cast<uint32_t>(sourceHeight));const uint64_t captured=Timestamp();
        SetStretchBltMode(memory,COLORONCOLOR);
        Require(StretchBlt(memory,0,0,static_cast<int>(width),static_cast<int>(height),screen,0,0,sourceWidth,sourceHeight,SRCCOPY|CAPTUREBLT)!=FALSE,"GDI compatibility capture");
        Cursor(static_cast<uint32_t>(sourceWidth),static_cast<uint32_t>(sourceHeight));Finish(frame,captured);return true;
    }
    bool Dxgi(Frame& frame,uint32_t timeout){
        DXGI_OUTDUPL_FRAME_INFO info{};ComPtr<IDXGIResource> resource;const HRESULT result=duplication->AcquireNextFrame(timeout,&info,&resource);
        if(result==DXGI_ERROR_WAIT_TIMEOUT)return false;Check(result,"Desktop frame acquisition");
        struct Release {IDXGIOutputDuplication* value;~Release(){value->ReleaseFrame();}} acquired{duplication.Get()};const uint64_t captured=Timestamp();
        ComPtr<ID3D11Texture2D> texture;Check(resource.As(&texture),"Desktop frame texture");D3D11_TEXTURE2D_DESC description{};texture->GetDesc(&description);
        if(!description.Width||!description.Height||description.Width>32768||description.Height>32768||static_cast<uint64_t>(description.Width)*description.Height>64ull*1024*1024)throw GraphicsFailure("Desktop readback dimensions",DXGI_ERROR_UNSUPPORTED);
        if(description.Format!=DXGI_FORMAT_B8G8R8A8_UNORM&&description.Format!=DXGI_FORMAT_B8G8R8A8_UNORM_SRGB)throw GraphicsFailure("Desktop frame format",DXGI_ERROR_UNSUPPORTED);
        Surface(description.Width,description.Height);
        if(!staging||stagingWidth!=description.Width||stagingHeight!=description.Height){
            D3D11_TEXTURE2D_DESC copy=description;copy.Usage=D3D11_USAGE_STAGING;copy.BindFlags=0;copy.CPUAccessFlags=D3D11_CPU_ACCESS_READ;copy.MiscFlags=0;copy.MipLevels=1;copy.ArraySize=1;copy.SampleDesc={1,0};
            staging.Reset();Check(device->CreateTexture2D(&copy,nullptr,&staging),"Desktop readback texture allocation");stagingWidth=description.Width;stagingHeight=description.Height;
        }
        context->CopyResource(staging.Get(),texture.Get());D3D11_MAPPED_SUBRESOURCE mapped{};Check(context->Map(staging.Get(),0,D3D11_MAP_READ,0,&mapped),"Desktop texture readback");
        struct Unmap {ID3D11DeviceContext* context;ID3D11Texture2D* texture;~Unmap(){context->Unmap(texture,0);}} mapping{context.Get(),staging.Get()};
        if(!mapped.pData||mapped.RowPitch<static_cast<uint64_t>(description.Width)*4)throw std::runtime_error("Desktop texture row layout is invalid.");
        auto out=static_cast<uint32_t*>(pixels);
        for(uint32_t y=0;y<height;++y){
            const uint32_t sourceY=static_cast<uint32_t>(static_cast<uint64_t>(y)*description.Height/height);
            const auto row=reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(mapped.pData)+static_cast<size_t>(sourceY)*mapped.RowPitch);
            if(width==description.Width)std::memcpy(out+static_cast<size_t>(y)*width,row,static_cast<size_t>(width)*4);
            else for(uint32_t x=0;x<width;++x)out[static_cast<size_t>(y)*width+x]=row[static_cast<uint32_t>(static_cast<uint64_t>(x)*description.Width/width)];
        }
        if(info.PointerPosition.Visible)Cursor(description.Width,description.Height);Finish(frame,captured);return true;
    }
};
Capture::Capture(uint32_t width,uint32_t height):state_(std::make_unique<State>(width,height)){}
Capture::~Capture()=default;
bool Capture::Next(Frame& frame,uint32_t timeout){
    if(GetCurrentThreadId()!=state_->thread)throw std::runtime_error("Use desktop capture on its owning interactive worker thread.");
    if(timeout>1000)throw std::runtime_error("Desktop frame wait must be from 0 to 1000 milliseconds.");
    DpiScope dpi;CheckDesktop();
    if(!state_->duplication&&GetTickCount64()>=state_->retryAt){try{state_->InitDxgi();}catch(const GraphicsFailure& failure){state_->Fallback(failure);}}
    if(!state_->duplication)return state_->Gdi(frame);
    try{return state_->Dxgi(frame,timeout);}
    catch(const GraphicsFailure&){
        // One reconstruction attempt per call; never recurse/spin on a GPU or
        // display failure. Access checks are repeated before a fallback capture.
        state_->ResetDxgi();CheckDesktop();
        try{state_->InitDxgi();return state_->Dxgi(frame,0);}
        catch(const GraphicsFailure& failure){state_->Fallback(failure);CheckDesktop();return state_->Gdi(frame);}
    }
}
std::string Capture::Backend()const{return state_->backend;}
}
