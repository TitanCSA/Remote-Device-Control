#include "Client.h"
#include "VirtualInput.h"
#include "Discovery.h"
#include "Directory.h"
#include "Transport.h"
#include <windowsx.h>
#include <d2d1.h>
#include <wrl/client.h>
#include <commctrl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <thread>

using Microsoft::WRL::ComPtr;
using namespace RemoteControl;
namespace {
constexpr UINT Changed=WM_APP+1,Stopped=WM_APP+2,ToggleFullscreen=WM_APP+3,InputFailed=WM_APP+4,HostsChanged=WM_APP+5;
constexpr wchar_t WindowClass[]=L"RemoteDeviceControlViewer",ViewClass[]=L"RemoteDeviceControlDesktopView";
HWND window=nullptr,viewWindow=nullptr,codeEdit=nullptr,connectButton=nullptr,modeCombo=nullptr,hostList=nullptr,hostConnect=nullptr;
std::atomic<HWND> notifyWindow{nullptr};std::atomic<bool> posted{false},hostsPosted{false};
HFONT font=nullptr;UINT dpi=96;std::unique_ptr<Client> client;std::thread stopper;
std::unique_ptr<DiscoveryBrowser> discovery;std::unique_ptr<DirectoryBrowser> directory;
struct ListedHost {Pairing pairing;std::string name,address;bool local=false,busy=false,available=false,approval=true;};
std::vector<ListedHost> hosts;std::string hostsSignature,ownRoom;int sideWidth=270;
bool focused=false,closing=false,stopping=false,preview=false,sessionStarted=false,connecting=false,buttonHover=false;
bool fullScreen=false,fullscreenHeld=false;uint8_t mouseButtons=0;int wheelX=0,wheelY=0,viewTop=154;
RECT imageRect{};std::array<bool,256> heldKeys{};HHOOK keyboardHook=nullptr;
WINDOWPLACEMENT placement{sizeof(placement)};ULONGLONG statusPainted=0;std::string lastStatus;bool lastConnected=false;
std::wstring uiError;ComPtr<ID2D1Factory> factory;ComPtr<ID2D1HwndRenderTarget> target;ComPtr<ID2D1Bitmap> bitmap;
uint32_t bitmapWidth=0,bitmapHeight=0;uint64_t uploadedSequence=~uint64_t(0),uploadedQpc=0;

int Scale(int value){return MulDiv(value,static_cast<int>(dpi),96);}
std::wstring Text(HWND control){const int length=GetWindowTextLengthW(control);std::wstring value(static_cast<size_t>(length)+1,0);GetWindowTextW(control,value.data(),length+1);value.resize(length);return value;}
void Fill(HDC dc,RECT rect,COLORREF color){HBRUSH brush=CreateSolidBrush(color);FillRect(dc,&rect,brush);DeleteObject(brush);}
void Label(HDC dc,int x,int y,const std::wstring& text,COLORREF color=RGB(30,44,65)){SetBkMode(dc,TRANSPARENT);SetTextColor(dc,color);TextOutW(dc,x,y,text.data(),static_cast<int>(text.size()));}
void ChangedCallback(){const HWND destination=notifyWindow.load();if(destination&&!posted.exchange(true)&&!PostMessageW(destination,Changed,0,0))posted=false;}
void HostsCallback(){const HWND destination=notifyWindow.load();if(destination&&!hostsPosted.exchange(true)&&!PostMessageW(destination,HostsChanged,0,0))hostsPosted=false;}
ClientInfo Info(){ClientInfo result;if(client)result=client->Info();if(preview)result.status="Preview only. No connection, capture or input is active.";return result;}
void ResetTarget(){bitmap.Reset();target.Reset();bitmapWidth=bitmapHeight=0;uploadedSequence=~uint64_t(0);uploadedQpc=0;}
void UpdateControls(){
 const auto info=Info();const std::wstring label=stopping?L"Disconnecting…":sessionStarted||info.connected?L"Disconnect":L"Connect";
 if(Text(connectButton)!=label)SetWindowTextW(connectButton,label.c_str());
 EnableWindow(connectButton,!preview&&!stopping);EnableWindow(codeEdit,!sessionStarted&&!stopping);EnableWindow(modeCombo,!sessionStarted&&!stopping);
 const auto selected=static_cast<int>(SendMessageW(hostList,LB_GETCURSEL,0,0));const bool available=selected>=0&&static_cast<size_t>(selected)<hosts.size()&&hosts[static_cast<size_t>(selected)].available&&!hosts[static_cast<size_t>(selected)].busy;
 EnableWindow(hostConnect,!preview&&!stopping&&!sessionStarted&&available);
}
void RefreshHosts(){
 std::string selected;const auto old=static_cast<int>(SendMessageW(hostList,LB_GETCURSEL,0,0));if(old>=0&&static_cast<size_t>(old)<hosts.size())selected=hosts[static_cast<size_t>(old)].pairing.room;
 std::vector<ListedHost> next;
 if(directory)for(const auto& h:directory->Hosts()){if(h.room==ownRoom||next.size()==64)continue;ListedHost item;item.name=h.name;item.address="Internet relay";item.busy=h.busy;item.available=h.available;item.approval=h.requireApproval;item.pairing.pin=h.pin;item.pairing.room=h.room;item.pairing.secret=OpenAccessSecret;item.pairing.relayToken=h.relayToken;item.pairing.relay=h.relay;item.pairing.noCode=true;next.push_back(std::move(item));}
 if(discovery)for(const auto& h:discovery->Hosts()){if(h.room==ownRoom)continue;ListedHost item;item.name=h.name;item.address=h.address;item.local=true;item.busy=h.busy;item.available=h.available;item.approval=h.requireApproval;item.pairing.host=h.address;item.pairing.port=h.port;item.pairing.pin=h.pin;item.pairing.room=h.room;item.pairing.secret=OpenAccessSecret;item.pairing.noCode=true;
  auto existing=std::find_if(next.begin(),next.end(),[&](const ListedHost& row){return row.pairing.room==h.room;});if(existing!=next.end()){if(TitanTransport::ConstantTimeEqual(existing->pairing.pin,h.pin))*existing=std::move(item);}else if(next.size()<64)next.push_back(std::move(item));
 }
 std::stable_sort(next.begin(),next.end(),[](const ListedHost& a,const ListedHost& b){if(a.local!=b.local)return a.local;return a.name<b.name;});std::string signature;
 for(const auto& h:next)signature+=h.pairing.room+'|'+h.name+'|'+h.address+'|'+(h.local?'1':'0')+(h.busy?'1':'0')+(h.available?'1':'0')+(h.approval?'1':'0')+'|'+h.pairing.pin+'|'+h.pairing.relayToken+'\n';
 if(signature==hostsSignature){if(hosts.empty())InvalidateRect(hostList,nullptr,FALSE);return;}hostsSignature=std::move(signature);hosts=std::move(next);SendMessageW(hostList,WM_SETREDRAW,FALSE,0);SendMessageW(hostList,LB_RESETCONTENT,0,0);int selection=-1;
 for(size_t i=0;i<hosts.size();++i){SendMessageW(hostList,LB_ADDSTRING,0,0);if(hosts[i].pairing.room==selected)selection=static_cast<int>(i);}if(selection<0&&!hosts.empty())selection=0;SendMessageW(hostList,LB_SETCURSEL,static_cast<WPARAM>(selection),0);SendMessageW(hostList,WM_SETREDRAW,TRUE,0);InvalidateRect(hostList,nullptr,FALSE);UpdateControls();
}
void Connect(Pairing pairing,unsigned mode){uiError.clear();sessionStarted=connecting=true;UpdateControls();try{client->Start(std::move(pairing),mode);}catch(...){sessionStarted=connecting=false;UpdateControls();throw;}}
void ConnectSelected(){if(preview||stopping||sessionStarted||!client)return;const auto selected=static_cast<int>(SendMessageW(hostList,LB_GETCURSEL,0,0));if(selected<0||static_cast<size_t>(selected)>=hosts.size())return;const auto row=hosts[static_cast<size_t>(selected)];if(row.busy||!row.available)throw std::runtime_error(row.busy?"This PC already has a controller. Wait until its current session ends.":"Unlock and sign in to the target PC before connecting.");Connect(row.pairing,row.local?1u:2u);}
void ReleaseInput() noexcept {
 if(focused&&client)try{client->Push(Input{InputKind::ReleaseAll});}catch(...){}
 focused=false;mouseButtons=0;wheelX=wheelY=0;heldKeys.fill(false);fullscreenHeld=false;
 if(keyboardHook){const HHOOK old=keyboardHook;keyboardHook=nullptr;UnhookWindowsHookEx(old);}
 if(viewWindow&&GetCapture()==viewWindow)ReleaseCapture();
 if(window){RECT rect{};GetClientRect(window,&rect);rect.top=(std::max<LONG>)(0,rect.bottom-Scale(34));InvalidateRect(window,&rect,FALSE);}
}
void Stop(bool close){
 ReleaseInput();closing=closing||close;if(stopping)return;stopping=true;UpdateControls();
 if(stopper.joinable())stopper.join();
 stopper=std::thread([]{if(client)client->Stop();const HWND destination=notifyWindow.load();if(destination)PostMessageW(destination,Stopped,0,0);});
}
void SetFonts(){
 const HFONT old=font;font=CreateFontW(-Scale(16),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
 if(!font)throw std::runtime_error(WindowsError("Viewer font",GetLastError()));
 for(HWND control:{codeEdit,modeCombo,connectButton,hostList,hostConnect})if(control)SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
 if(hostList)SendMessageW(hostList,LB_SETITEMHEIGHT,0,Scale(84));
 if(old)DeleteObject(old);
}
void Layout(){
 if(!window)return;RECT rect{};GetClientRect(window,&rect);const int width=static_cast<int>(rect.right),heightPixels=static_cast<int>(rect.bottom);const int margin=Scale(24),gap=Scale(12),height=Scale(34);
 const bool stacked=width<Scale(850);const int modeWidth=Scale(180),buttonWidth=Scale(170);
 if(stacked){MoveWindow(codeEdit,margin,Scale(62),(std::max)(1,width-margin*2),height,TRUE);MoveWindow(modeCombo,margin,Scale(108),modeWidth,Scale(220),TRUE);MoveWindow(connectButton,(std::max)(margin,width-margin-buttonWidth),Scale(108),buttonWidth,height,TRUE);viewTop=Scale(198);}
 else{const int codeWidth=(std::max)(1,width-margin*2-modeWidth-buttonWidth-gap*2);MoveWindow(codeEdit,margin,Scale(62),codeWidth,height,TRUE);MoveWindow(modeCombo,margin+codeWidth+gap,Scale(62),modeWidth,Scale(220),TRUE);MoveWindow(connectButton,width-margin-buttonWidth,Scale(62),buttonWidth,height,TRUE);viewTop=Scale(154);}
 const int side=Scale(sideWidth);MoveWindow(hostList,Scale(16),viewTop+Scale(48),side-Scale(28),(std::max)(1,heightPixels-viewTop-Scale(138)),TRUE);MoveWindow(hostConnect,Scale(16),heightPixels-Scale(80),side-Scale(28),Scale(34),TRUE);
 MoveWindow(viewWindow,side,viewTop,(std::max)(1,width-side-Scale(12)),(std::max)(1,heightPixels-viewTop-Scale(36)),TRUE);
 InvalidateRect(window,nullptr,FALSE);
}
void FullScreen(){
 ReleaseInput();
 if(!fullScreen){GetWindowPlacement(window,&placement);SetWindowLongPtrW(window,GWL_STYLE,WS_POPUP|WS_VISIBLE|WS_CLIPCHILDREN);MONITORINFO monitor{sizeof(monitor)};if(GetMonitorInfoW(MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST),&monitor))SetWindowPos(window,HWND_TOP,monitor.rcMonitor.left,monitor.rcMonitor.top,monitor.rcMonitor.right-monitor.rcMonitor.left,monitor.rcMonitor.bottom-monitor.rcMonitor.top,SWP_FRAMECHANGED);}
 else{SetWindowLongPtrW(window,GWL_STYLE,WS_OVERLAPPEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN);SetWindowPlacement(window,&placement);SetWindowPos(window,nullptr,0,0,0,0,SWP_FRAMECHANGED|SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER);}
 fullScreen=!fullScreen;Layout();
}
void Pointer(int x,int y){
 if(!focused||!client)return;const int left=static_cast<int>(imageRect.left),top=static_cast<int>(imageRect.top),right=static_cast<int>(imageRect.right),bottom=static_cast<int>(imageRect.bottom);const int width=right-left,height=bottom-top;if(width<=1||height<=1)return;
 x=(std::max)(left,(std::min)(x,right-1));y=(std::max)(top,(std::min)(y,bottom-1));
 Input input;input.kind=InputKind::Pointer;input.x=static_cast<int32_t>(int64_t(x-left)*65535/(width-1));input.y=static_cast<int32_t>(int64_t(y-top)*65535/(height-1));client->Push(input);
}
LRESULT CALLBACK Keyboard(int code,WPARAM message,LPARAM parameter){
 try{
  if(code==HC_ACTION&&focused&&GetForegroundWindow()==window&&GetFocus()==viewWindow&&client&&Info().connected){
   const auto* key=reinterpret_cast<const KBDLLHOOKSTRUCT*>(parameter);const bool down=message==WM_KEYDOWN||message==WM_SYSKEYDOWN;const auto vk=key->vkCode;
   const bool control=heldKeys[VK_CONTROL]||heldKeys[VK_LCONTROL]||heldKeys[VK_RCONTROL]||(GetAsyncKeyState(VK_CONTROL)&0x8000);
   const bool alt=heldKeys[VK_MENU]||heldKeys[VK_LMENU]||heldKeys[VK_RMENU]||(GetAsyncKeyState(VK_MENU)&0x8000);
   if(vk==VK_F12&&control&&alt){if(down)ReleaseInput();return 1;}
   if(vk==VK_F11){if(down&&!fullscreenHeld){fullscreenHeld=true;PostMessageW(window,ToggleFullscreen,0,0);}if(!down)fullscreenHeld=false;return 1;}
   const uint32_t usage=vk==VK_PAUSE?0x48:UsageFromScan(key->scanCode,(key->flags&LLKHF_EXTENDED)!=0);
   if(usage){
    // An unmatched key-up may belong to a modifier held before remote focus.
    if(!down&&vk<heldKeys.size()&&!heldKeys[vk])return CallNextHookEx(keyboardHook,code,message,parameter);
    if(vk<heldKeys.size())heldKeys[vk]=down;
    Input input;input.kind=InputKind::Key;input.code=usage;input.down=down?1u:0u;client->Push(input);
    if(vk==VK_PAUSE&&down){input.down=0;client->Push(input);heldKeys[VK_PAUSE]=false;}
    return 1;
   }
  }
 }catch(...){ReleaseInput();const HWND destination=notifyWindow.load();if(destination)PostMessageW(destination,InputFailed,0,0);}
 return CallNextHookEx(keyboardHook,code,message,parameter);
}
void AcquireInput(){
 if(focused)return;
 SetFocus(viewWindow);heldKeys.fill(false);keyboardHook=SetWindowsHookExW(WH_KEYBOARD_LL,Keyboard,GetModuleHandleW(nullptr),0);
 if(!keyboardHook)throw std::runtime_error(WindowsError("Keyboard capture",GetLastError()));
 focused=true;InvalidateRect(window,nullptr,FALSE);
}
bool ValidImage(const std::shared_ptr<const Frame>& frame){return frame&&frame->width&&frame->height&&frame->width<=MaxWidth&&frame->height<=MaxHeight&&frame->bgra.size()==uint64_t(frame->width)*frame->height*4;}
struct PaintScope {HWND hwnd;PAINTSTRUCT paint{};HDC dc;explicit PaintScope(HWND value):hwnd(value),dc(BeginPaint(value,&paint)){}~PaintScope(){EndPaint(hwnd,&paint);}};
void RenderView(HWND hwnd,HDC dc,bool direct){
 RECT rect{};GetClientRect(hwnd,&rect);imageRect={};
 const auto frame=client?client->Latest():nullptr;
 if(!Info().connected||!ValidImage(frame)){
  Fill(dc,rect,RGB(15,20,30));SelectObject(dc,font);Label(dc,Scale(26),Scale(28),preview?L"Preview · no connection, capture or input is active.":L"The authenticated remote desktop will appear here.",RGB(218,227,244));return;
 }
 const float scale=(std::min)(float(rect.right)/float(frame->width),float(rect.bottom)/float(frame->height));const float width=float(frame->width)*scale,height=float(frame->height)*scale;
 const float x=(float(rect.right)-width)/2,y=(float(rect.bottom)-height)/2;imageRect={static_cast<LONG>(x),static_cast<LONG>(y),static_cast<LONG>(x+width),static_cast<LONG>(y+height)};
 if(direct&&!factory)D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,factory.GetAddressOf());
 if(direct&&factory&&!target){const auto properties=D2D1::RenderTargetProperties(D2D1_RENDER_TARGET_TYPE_DEFAULT,D2D1::PixelFormat(),96,96);factory->CreateHwndRenderTarget(properties,D2D1::HwndRenderTargetProperties(hwnd,D2D1::SizeU(static_cast<UINT32>(rect.right),static_cast<UINT32>(rect.bottom)),D2D1_PRESENT_OPTIONS_IMMEDIATELY),&target);}
 bool drawn=false;
 if(direct&&target){
  HRESULT result=S_OK;
  if(!bitmap||bitmapWidth!=frame->width||bitmapHeight!=frame->height){bitmap.Reset();bitmapWidth=frame->width;bitmapHeight=frame->height;result=target->CreateBitmap(D2D1::SizeU(bitmapWidth,bitmapHeight),frame->bgra.data(),bitmapWidth*4,D2D1::BitmapProperties(D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM,D2D1_ALPHA_MODE_IGNORE)),&bitmap);uploadedSequence=frame->sequence;uploadedQpc=frame->capturedQpc;}
  else if(uploadedSequence!=frame->sequence||uploadedQpc!=frame->capturedQpc){result=bitmap->CopyFromMemory(nullptr,frame->bgra.data(),frame->width*4);uploadedSequence=frame->sequence;uploadedQpc=frame->capturedQpc;}
  if(SUCCEEDED(result)&&bitmap){target->BeginDraw();target->Clear(D2D1::ColorF(0.06f,0.08f,0.12f));target->DrawBitmap(bitmap.Get(),D2D1::RectF(x,y,x+width,y+height),1,D2D1_BITMAP_INTERPOLATION_MODE_LINEAR);result=target->EndDraw();drawn=SUCCEEDED(result);}
  if(FAILED(result))ResetTarget();
 }
 if(!drawn){Fill(dc,rect,RGB(15,20,30));BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=static_cast<LONG>(frame->width);info.bmiHeader.biHeight=-static_cast<LONG>(frame->height);info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;SetStretchBltMode(dc,COLORONCOLOR);StretchDIBits(dc,imageRect.left,imageRect.top,imageRect.right-imageRect.left,imageRect.bottom-imageRect.top,0,0,static_cast<int>(frame->width),static_cast<int>(frame->height),frame->bgra.data(),&info,DIB_RGB_COLORS,SRCCOPY);}
}
void RenderWindow(HDC dc){
 RECT rect{};GetClientRect(window,&rect);SelectObject(dc,font);Fill(dc,rect,RGB(246,248,252));
 Label(dc,Scale(24),Scale(20),L"Remote Device Control",RGB(20,83,204));if(rect.right>=Scale(1050))Label(dc,rect.right-Scale(355),Scale(22),L"Portable viewer · Vdevice-powered host",RGB(98,111,132));
 const auto info=Info();std::wostringstream status;status<<Wide(info.status);if(info.connected){status<<L"  |  "<<Wide(info.route)<<L"  |  "<<std::fixed<<std::setprecision(0)<<info.framesPerSecond<<L" FPS  |  input ACK "<<std::setprecision(1)<<info.inputRttMs<<L" ms";if(info.remaining100ns){auto seconds=info.remaining100ns/10000000;status<<L"  |  demo "<<seconds/60<<L":"<<std::setfill(L'0')<<std::setw(2)<<seconds%60;}}if(!uiError.empty())status<<L"  |  "<<uiError;
 RECT statusRect{Scale(24),viewTop-Scale(46),rect.right-Scale(24),viewTop-Scale(8)};SetTextColor(dc,RGB(65,83,111));SetBkMode(dc,TRANSPARENT);DrawTextW(dc,status.str().c_str(),-1,&statusRect,DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS);
 Label(dc,Scale(20),viewTop+Scale(4),L"Available PCs",RGB(30,44,65));
 Label(dc,Scale(20),viewTop+Scale(23),preview?L"Discovery off in preview":L"LAN + Internet · auto refresh",RGB(98,111,132));
 Label(dc,Scale(24),rect.bottom-Scale(26),focused?L"Keyboard captured · Ctrl+Alt+F12 releases it · F11 full screen":L"Click the remote desktop to control it · Ctrl+Alt+F12 releases keyboard/mouse",RGB(96,112,136));
}
void DrawHost(const DRAWITEMSTRUCT& item){
 Fill(item.hDC,item.rcItem,(item.itemState&ODS_SELECTED)?RGB(228,238,255):RGB(255,255,255));if(item.itemID>=hosts.size())return;const auto& row=hosts[item.itemID];SelectObject(item.hDC,font);SetBkMode(item.hDC,TRANSPARENT);
 RECT text=item.rcItem;text.left+=Scale(12);text.right-=Scale(10);text.top+=Scale(9);text.bottom=text.top+Scale(23);SetTextColor(item.hDC,RGB(28,43,65));auto name=Wide(row.name);DrawTextW(item.hDC,name.c_str(),-1,&text,DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);
 text.top+=Scale(24);text.bottom=text.top+Scale(20);SetTextColor(item.hDC,RGB(97,113,136));auto address=Wide(row.address)+(row.local?L" · LAN":L"");DrawTextW(item.hDC,address.c_str(),-1,&text,DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);
 text.top+=Scale(23);text.bottom=text.top+Scale(19);const auto state=row.busy?L"Busy · one controller connected":!row.available?L"Locked · sign in on target":row.approval?L"Available · approval requested":L"Available · automatic access";SetTextColor(item.hDC,row.available&&!row.busy?RGB(25,87,211):RGB(97,113,136));DrawTextW(item.hDC,state,-1,&text,DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);
 RECT line=item.rcItem;line.top=line.bottom-1;Fill(item.hDC,line,RGB(233,238,246));if(item.itemState&ODS_FOCUS){RECT focus=item.rcItem;InflateRect(&focus,-2,-2);DrawFocusRect(item.hDC,&focus);}
}
LRESULT CALLBACK Widget(HWND hwnd,UINT message,WPARAM w,LPARAM l,UINT_PTR id,DWORD_PTR){
 if(hwnd==hostList&&message==WM_PAINT&&hosts.empty()){PaintScope paint(hwnd);RECT rect{};GetClientRect(hwnd,&rect);Fill(paint.dc,rect,RGB(255,255,255));SelectObject(paint.dc,font);InflateRect(&rect,-Scale(12),-Scale(16));SetTextColor(paint.dc,RGB(98,111,132));SetBkMode(paint.dc,TRANSPARENT);std::wstring text=preview?L"No network discovery runs in preview mode.":L"Looking for PCs…\n\nEnable public discovery in the target PC's setup. Private PCs still connect using their code above.";if(directory&&!directory->Error().empty())text+=L"\n\nInternet directory unavailable. LAN discovery continues.";DrawTextW(paint.dc,text.c_str(),-1,&rect,DT_WORDBREAK|DT_NOPREFIX);return 0;}
 if(message==WM_SETCURSOR&&IsWindowEnabled(hwnd)){SetCursor(LoadCursorW(nullptr,IDC_HAND));return TRUE;}
 if(hwnd==connectButton&&message==WM_MOUSEMOVE&&!buttonHover){buttonHover=true;TRACKMOUSEEVENT track{sizeof(track),TME_LEAVE,hwnd,0};TrackMouseEvent(&track);InvalidateRect(hwnd,nullptr,FALSE);}
 if(hwnd==connectButton&&message==WM_MOUSELEAVE){buttonHover=false;InvalidateRect(hwnd,nullptr,FALSE);}
 if(message==WM_NCDESTROY)RemoveWindowSubclass(hwnd,Widget,id);
 return DefSubclassProc(hwnd,message,w,l);
}
LRESULT ViewMessage(HWND hwnd,UINT message,WPARAM w,LPARAM l){
 switch(message){
 case WM_PAINT:{PaintScope paint(hwnd);RenderView(hwnd,paint.dc,true);return 0;}
 case WM_PRINTCLIENT:RenderView(hwnd,reinterpret_cast<HDC>(w),false);GdiFlush();return 0;
 case WM_ERASEBKGND:return 1;
 case WM_SIZE:if(target){if(LOWORD(l)&&HIWORD(l)&&FAILED(target->Resize(D2D1::SizeU(LOWORD(l),HIWORD(l)))))ResetTarget();}InvalidateRect(hwnd,nullptr,FALSE);return 0;
 case WM_SETCURSOR:{POINT point{};GetCursorPos(&point);ScreenToClient(hwnd,&point);SetCursor(LoadCursorW(nullptr,!focused&&Info().connected&&PtInRect(&imageRect,point)?IDC_HAND:IDC_ARROW));return TRUE;}
 case WM_LBUTTONDOWN:case WM_RBUTTONDOWN:case WM_MBUTTONDOWN:case WM_XBUTTONDOWN:{const POINT point{GET_X_LPARAM(l),GET_Y_LPARAM(l)};if(client&&Info().connected&&PtInRect(&imageRect,point)){AcquireInput();SetCapture(hwnd);Pointer(point.x,point.y);Input input;input.kind=InputKind::Button;input.code=message==WM_LBUTTONDOWN?1u:message==WM_RBUTTONDOWN?2u:message==WM_MBUTTONDOWN?3u:GET_XBUTTON_WPARAM(w)==XBUTTON1?4u:5u;input.down=1;mouseButtons|=static_cast<uint8_t>(1u<<(input.code-1));client->Push(input);}else ReleaseInput();return message==WM_XBUTTONDOWN?TRUE:0;}
 case WM_LBUTTONUP:case WM_RBUTTONUP:case WM_MBUTTONUP:case WM_XBUTTONUP:if(focused&&client){Pointer(GET_X_LPARAM(l),GET_Y_LPARAM(l));Input input;input.kind=InputKind::Button;input.code=message==WM_LBUTTONUP?1u:message==WM_RBUTTONUP?2u:message==WM_MBUTTONUP?3u:GET_XBUTTON_WPARAM(w)==XBUTTON1?4u:5u;mouseButtons&=static_cast<uint8_t>(~(1u<<(input.code-1)));client->Push(input);if(!mouseButtons&&GetCapture()==hwnd)ReleaseCapture();}return message==WM_XBUTTONUP?TRUE:0;
 case WM_MOUSEMOVE:if(focused)Pointer(GET_X_LPARAM(l),GET_Y_LPARAM(l));return 0;
 case WM_MOUSEWHEEL:case WM_MOUSEHWHEEL:if(focused&&client){POINT point{GET_X_LPARAM(l),GET_Y_LPARAM(l)};ScreenToClient(hwnd,&point);if(!PtInRect(&imageRect,point))return 0;int& remainder=message==WM_MOUSEWHEEL?wheelY:wheelX;remainder+=GET_WHEEL_DELTA_WPARAM(w);int notches=remainder/WHEEL_DELTA;remainder%=WHEEL_DELTA;while(notches){const int part=(std::max)(-127,(std::min)(127,notches));Input input;input.kind=InputKind::Wheel;if(message==WM_MOUSEWHEEL)input.y=part;else input.x=part;client->Push(input);notches-=part;}}return 0;
 case WM_KILLFOCUS:case WM_CANCELMODE:ReleaseInput();return 0;
 case WM_CAPTURECHANGED:if(mouseButtons)ReleaseInput();return 0;
 case WM_KEYDOWN:if(w==VK_F11&&!(l&(1ll<<30))){PostMessageW(window,ToggleFullscreen,0,0);return 0;}break;
 }
 return DefWindowProcW(hwnd,message,w,l);
}
LRESULT CALLBACK ViewProcedure(HWND hwnd,UINT message,WPARAM w,LPARAM l){try{return ViewMessage(hwnd,message,w,l);}catch(const std::exception& error){uiError=Wide(error.what());ReleaseInput();PostMessageW(window,InputFailed,0,0);return 0;}catch(...){ReleaseInput();PostMessageW(window,InputFailed,0,0);return 0;}}
LRESULT WindowMessage(HWND hwnd,UINT message,WPARAM w,LPARAM l){
 switch(message){
 case WM_CREATE:{
  window=hwnd;notifyWindow=hwnd;dpi=GetDpiForWindow(hwnd);if(!dpi)dpi=96;
  codeEdit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|WS_TABSTOP,0,0,0,0,hwnd,reinterpret_cast<HMENU>(1),nullptr,nullptr);
  modeCombo=CreateWindowW(WC_COMBOBOXW,L"",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_TABSTOP,0,0,0,0,hwnd,reinterpret_cast<HMENU>(2),nullptr,nullptr);
  connectButton=CreateWindowW(WC_BUTTONW,L"Connect",WS_CHILD|WS_VISIBLE|BS_OWNERDRAW|WS_TABSTOP,0,0,0,0,hwnd,reinterpret_cast<HMENU>(3),nullptr,nullptr);
  viewWindow=CreateWindowExW(0,ViewClass,L"Remote desktop",WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_CLIPSIBLINGS,0,0,1,1,hwnd,reinterpret_cast<HMENU>(4),nullptr,nullptr);
  hostList=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTBOXW,L"Available PCs",WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_TABSTOP|LBS_OWNERDRAWFIXED|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT,0,0,1,1,hwnd,reinterpret_cast<HMENU>(5),nullptr,nullptr);
  hostConnect=CreateWindowW(WC_BUTTONW,L"Connect selected PC",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,0,0,1,1,hwnd,reinterpret_cast<HMENU>(6),nullptr,nullptr);
  if(!codeEdit||!modeCombo||!connectButton||!viewWindow||!hostList||!hostConnect)throw std::runtime_error(WindowsError("Viewer controls",GetLastError()));
  SendMessageW(codeEdit,EM_SETCUEBANNER,FALSE,reinterpret_cast<LPARAM>(L"Paste the private connection code from the target PC"));SendMessageW(codeEdit,EM_SETLIMITTEXT,2048,0);
  for(const auto* text:{L"Automatic",L"LAN direct",L"Internet relay"})SendMessageW(modeCombo,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(text));SendMessageW(modeCombo,CB_SETCURSEL,0,0);
  SetWindowSubclass(connectButton,Widget,1,0);SetWindowSubclass(modeCombo,Widget,2,0);SetWindowSubclass(hostConnect,Widget,3,0);SetWindowSubclass(hostList,Widget,4,0);SetFonts();
  if(!preview){client=std::make_unique<Client>(ChangedCallback);wchar_t room[64]{};DWORD size=sizeof(room);if(RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl",L"HostRoom",RRF_RT_REG_SZ|RRF_SUBKEY_WOW6464KEY,nullptr,room,&size)==ERROR_SUCCESS)ownRoom=Utf8(room);discovery=std::make_unique<DiscoveryBrowser>();directory=std::make_unique<DirectoryBrowser>();discovery->Start(HostsCallback);directory->Start(HostsCallback);}UpdateControls();Layout();return 0;
 }
 case WM_SIZE:Layout();return 0;
 case WM_DPICHANGED:{dpi=HIWORD(w);SetFonts();const RECT* suggested=reinterpret_cast<const RECT*>(l);SetWindowPos(hwnd,nullptr,suggested->left,suggested->top,suggested->right-suggested->left,suggested->bottom-suggested->top,SWP_NOZORDER|SWP_NOACTIVATE);Layout();return 0;}
 case WM_GETMINMAXINFO:{auto* info=reinterpret_cast<MINMAXINFO*>(l);MONITORINFO monitor{sizeof(monitor)};GetMonitorInfoW(MonitorFromWindow(hwnd,MONITOR_DEFAULTTONEAREST),&monitor);info->ptMinTrackSize.x=(std::min<LONG>)(Scale(840),monitor.rcWork.right-monitor.rcWork.left);info->ptMinTrackSize.y=(std::min<LONG>)(Scale(520),monitor.rcWork.bottom-monitor.rcWork.top);return 0;}
 case Changed:{posted=false;const auto info=Info();if(info.connected){connecting=false;sessionStarted=true;}else if(sessionStarted&&(!connecting||info.status.rfind("Connecting",0)!=0)){sessionStarted=connecting=false;ReleaseInput();}UpdateControls();InvalidateRect(viewWindow,nullptr,FALSE);const auto now=GetTickCount64();if(now-statusPainted>=250||info.status!=lastStatus||info.connected!=lastConnected){RECT rect{};GetClientRect(hwnd,&rect);rect.top=viewTop-Scale(48);rect.bottom=viewTop;InvalidateRect(hwnd,&rect,FALSE);statusPainted=now;lastStatus=info.status;lastConnected=info.connected;}return 0;}
 case HostsChanged:hostsPosted=false;RefreshHosts();return 0;
 case WM_COMMAND:
  if(LOWORD(w)==5){if(HIWORD(w)==LBN_SELCHANGE)UpdateControls();else if(HIWORD(w)==LBN_DBLCLK)ConnectSelected();return 0;}
  if(LOWORD(w)==6){ConnectSelected();return 0;}
  if(LOWORD(w)==3&&!stopping&&!preview&&client){if(sessionStarted||Info().connected)Stop(false);else{auto pairing=ParsePairing(Text(codeEdit));const auto mode=SendMessageW(modeCombo,CB_GETCURSEL,0,0);if(mode<0||mode>2)throw std::runtime_error("Choose a connection mode.");Connect(std::move(pairing),static_cast<unsigned>(mode));}}return 0;
 case Stopped:if(stopper.joinable())stopper.join();stopping=false;sessionStarted=connecting=false;UpdateControls();if(closing)DestroyWindow(hwnd);else InvalidateRect(hwnd,nullptr,FALSE);return 0;
 case ToggleFullscreen:FullScreen();return 0;
 case InputFailed:if(uiError.empty())uiError=L"Input capture failed; the connection was stopped safely.";if(!stopping)Stop(false);return 0;
 case WM_ACTIVATE:if(LOWORD(w)==WA_INACTIVE)ReleaseInput();return 0;
 case WM_MEASUREITEM:{auto* item=reinterpret_cast<MEASUREITEMSTRUCT*>(l);if(item->CtlID==5){item->itemHeight=static_cast<UINT>(Scale(84));return TRUE;}break;}
 case WM_DRAWITEM:{const auto* item=reinterpret_cast<const DRAWITEMSTRUCT*>(l);if(item->CtlID==5){DrawHost(*item);return TRUE;}if(item->CtlID==3||item->CtlID==6){const bool disabled=(item->itemState&ODS_DISABLED)!=0;Fill(item->hDC,item->rcItem,disabled?RGB(176,189,209):(item->itemState&ODS_SELECTED)?RGB(15,64,165):buttonHover?RGB(25,102,235):RGB(25,87,211));SelectObject(item->hDC,font);SetBkMode(item->hDC,TRANSPARENT);SetTextColor(item->hDC,RGB(255,255,255));RECT rect=item->rcItem;const auto text=Text(item->hwndItem);DrawTextW(item->hDC,text.c_str(),-1,&rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);if(item->itemState&ODS_FOCUS){InflateRect(&rect,-Scale(4),-Scale(4));DrawFocusRect(item->hDC,&rect);}return TRUE;}break;}
 case WM_PAINT:{PaintScope paint(hwnd);RenderWindow(paint.dc);return 0;}
 case WM_PRINTCLIENT:RenderWindow(reinterpret_cast<HDC>(w));GdiFlush();return 0;
 case WM_ERASEBKGND:return 1;
 case WM_CLOSE:if(stopping){closing=true;return 0;}Stop(true);return 0;
 case WM_DESTROY:notifyWindow=nullptr;ReleaseInput();ResetTarget();factory.Reset();if(font){DeleteObject(font);font=nullptr;}window=nullptr;PostQuitMessage(0);return 0;
 }
 return DefWindowProcW(hwnd,message,w,l);
}
LRESULT CALLBACK Procedure(HWND hwnd,UINT message,WPARAM w,LPARAM l){
 try{return WindowMessage(hwnd,message,w,l);}
 catch(const std::exception& error){ReleaseInput();MessageBoxW(hwnd,Wide(error.what()).c_str(),ProductName,MB_OK|MB_ICONERROR);return message==WM_CREATE?-1:0;}
 catch(...){ReleaseInput();MessageBoxW(hwnd,L"The viewer could not complete this operation.",ProductName,MB_OK|MB_ICONERROR);return message==WM_CREATE?-1:0;}
}
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR command,int show){
 std::wstring arguments=command?command:L"";const auto first=arguments.find_first_not_of(L" \t\r\n");arguments=first==arguments.npos?L"":arguments.substr(first,arguments.find_last_not_of(L" \t\r\n")-first+1);
 if(!arguments.empty()&&arguments!=L"--preview")return ERROR_INVALID_PARAMETER;
 preview=arguments==L"--preview";SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
 INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_STANDARD_CLASSES};InitCommonControlsEx(&controls);const HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(com))return 1;
 WNDCLASSEXW view{sizeof(view)};view.lpfnWndProc=ViewProcedure;view.hInstance=instance;view.hCursor=LoadCursorW(nullptr,IDC_ARROW);view.lpszClassName=ViewClass;
 WNDCLASSEXW main{sizeof(main)};main.lpfnWndProc=Procedure;main.hInstance=instance;main.hCursor=LoadCursorW(nullptr,IDC_ARROW);main.hIcon=LoadIconW(nullptr,IDI_APPLICATION);main.lpszClassName=WindowClass;
 if(!RegisterClassExW(&view)||!RegisterClassExW(&main)){CoUninitialize();return 1;}
 RECT work{};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);const int width=(std::min<LONG>)(1280,(std::max<LONG>)(640,work.right-work.left-24)),height=(std::min<LONG>)(820,(std::max<LONG>)(480,work.bottom-work.top-24));
 HWND hwnd=CreateWindowExW(0,WindowClass,L"Remote Device Control · Viewer",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,CW_USEDEFAULT,CW_USEDEFAULT,width,height,nullptr,nullptr,instance,nullptr);
 if(!hwnd){client.reset();CoUninitialize();return 1;}ShowWindow(hwnd,show);MSG message{};
 while(GetMessageW(&message,nullptr,0,0)>0){if(message.message==WM_KEYDOWN&&message.wParam==VK_F11&&!(message.lParam&(1ll<<30))){PostMessageW(hwnd,ToggleFullscreen,0,0);continue;}if(!IsDialogMessageW(hwnd,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
 if(stopper.joinable())stopper.join();if(client)client->Stop();client.reset();if(discovery)discovery->Stop();if(directory)directory->Stop();discovery.reset();directory.reset();CoUninitialize();return 0;
}
