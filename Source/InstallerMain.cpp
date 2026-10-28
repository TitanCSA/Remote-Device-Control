#include "Setup.h"
#include "Config.h"
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <cstring>
#include <stdexcept>

namespace {
using namespace RemoteControl;
constexpr UINT ProgressMessage=WM_APP+61,DoneMessage=WM_APP+62;
constexpr int InstallId=101,UninstallId=102,CopyId=103,RefreshId=104,RestartId=105,InternetId=106,DriverId=107,NoCodeId=108,ApprovalId=109;
constexpr COLORREF Blue=RGB(23,92,222),Ink=RGB(17,33,58),Muted=RGB(83,103,131),Background=RGB(243,246,252),Line=RGB(217,225,237);
#ifdef RDC_UNINSTALL_ONLY
constexpr bool UninstallOnly=true;
#else
constexpr bool UninstallOnly=false;
#endif
struct Window {
    HWND hwnd=nullptr,status=nullptr,detail=nullptr,internet=nullptr,driver=nullptr,noCode=nullptr,approval=nullptr,disclosure=nullptr,log=nullptr;
    HWND install=nullptr,uninstall=nullptr,copy=nullptr,refresh=nullptr,restart=nullptr;
    HFONT font=nullptr,titleFont=nullptr;HBRUSH background=nullptr,white=nullptr;
    std::thread worker;std::mutex mutex;Setup::Snapshot snapshot;Setup::Result result;
    std::wstring progressText;unsigned target=0;double displayed=0;bool busy=false,preview=false,requestedUninstall=false;
    std::atomic<bool> progressQueued{false};
    int Scale(int value)const{return MulDiv(value,static_cast<int>(GetDpiForWindow(hwnd)),96);}
    ~Window(){if(worker.joinable())worker.join();if(font)DeleteObject(font);if(titleFont)DeleteObject(titleFont);if(background)DeleteObject(background);if(white)DeleteObject(white);}
    static LRESULT CALLBACK ButtonProc(HWND button,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR){if(message==WM_SETCURSOR){SetCursor(LoadCursorW(nullptr,IDC_HAND));return TRUE;}return DefSubclassProc(button,message,wp,lp);}
    HWND Control(const wchar_t* type,const wchar_t* text,DWORD style,int id){auto control=CreateWindowExW(0,type,text,WS_CHILD|WS_VISIBLE|style,0,0,0,0,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);if(!control)throw std::runtime_error("Could not create an installer control.");SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(font),FALSE);if(std::wstring(type)==L"BUTTON")SetWindowSubclass(control,ButtonProc,1,0);return control;}
    void Fonts(){auto old=font,oldTitle=titleFont;const auto dpi=GetDpiForWindow(hwnd);font=CreateFontW(-MulDiv(15,static_cast<int>(dpi),96),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");titleFont=CreateFontW(-MulDiv(29,static_cast<int>(dpi),96),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");for(HWND child=GetWindow(hwnd,GW_CHILD);child;child=GetWindow(child,GW_HWNDNEXT))SendMessageW(child,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);if(old)DeleteObject(old);if(oldTitle)DeleteObject(oldTitle);}
    void Build(){background=CreateSolidBrush(Background);white=CreateSolidBrush(RGB(255,255,255));Fonts();
        status=Control(L"STATIC",L"Reading installation state...",0,201);detail=Control(L"STATIC",L"",SS_LEFT,202);
        internet=Control(L"BUTTON",L"Allow encrypted Internet connections through the relay",BS_AUTOCHECKBOX|WS_TABSTOP,InternetId);
        noCode=Control(L"BUTTON",L"Allow connections without a code (visible in local-network and, if enabled, public Internet lists)",BS_AUTOCHECKBOX|BS_MULTILINE|WS_TABSTOP,NoCodeId);
        approval=Control(L"BUTTON",L"Ask me before allowing a connection",BS_AUTOCHECKBOX|WS_TABSTOP,ApprovalId);
        driver=Control(L"BUTTON",L"Also remove Vdevice installed by this host (other applications may need it)",BS_AUTOCHECKBOX|WS_TABSTOP,DriverId);
        disclosure=Control(L"STATIC",L"The host starts automatically with Windows. Only someone with your private connection code can connect. Keep it secret; control is limited to the signed-in console desktop.\r\nVdevice is a shared one-hour demo per Windows boot. Windows event/setup logs are preserved on removal.",SS_LEFT,203);
        install=Control(L"BUTTON",L"Install / repair",BS_OWNERDRAW|WS_TABSTOP,InstallId);uninstall=Control(L"BUTTON",L"Uninstall",BS_OWNERDRAW|WS_TABSTOP,UninstallId);copy=Control(L"BUTTON",L"Copy connection code",BS_OWNERDRAW|WS_TABSTOP,CopyId);refresh=Control(L"BUTTON",L"Refresh",BS_OWNERDRAW|WS_TABSTOP,RefreshId);restart=Control(L"BUTTON",L"Restart Windows",BS_OWNERDRAW|WS_TABSTOP,RestartId);
        log=Control(L"EDIT",L"",ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_TABSTOP,204);SetWindowTheme(log,L"Explorer",nullptr);
        SendMessageW(internet,BM_SETCHECK,BST_CHECKED,0);SendMessageW(approval,BM_SETCHECK,BST_CHECKED,0);ShowWindow(restart,SW_HIDE);UpdateDisclosure();Layout();
        if(preview){snapshot.status=L"Offline preview — no installation or connection";snapshot.detail=L"This labelled preview does not query the service, open the driver, change the firewall or start remote access.";SetWindowTextW(status,snapshot.status.c_str());SetWindowTextW(detail,snapshot.detail.c_str());Append(L"PREVIEW: controls are disabled. No driver was installed or device created.");UpdateButtons();}
        else Begin(0);
    }
    void Layout(){RECT rect{};GetClientRect(hwnd,&rect);const int margin=Scale(24),inside=Scale(44),width=rect.right-2*margin;
        auto move=[&](HWND control,int x,int y,int w,int h){MoveWindow(control,x,y,w,h,TRUE);};
        move(status,inside,Scale(122),width-Scale(40),Scale(25));move(detail,inside,Scale(154),width-Scale(40),Scale(45));
        move(internet,inside,Scale(224),width-Scale(40),Scale(25));move(noCode,inside,Scale(259),width-Scale(40),Scale(44));move(approval,inside+Scale(24),Scale(306),width-Scale(64),Scale(25));move(disclosure,inside,Scale(344),width-Scale(40),Scale(80));move(driver,inside,Scale(432),width-Scale(40),Scale(25));
        const int gap=Scale(10),buttonHeight=Scale(40),normal=Scale(135),copyWidth=Scale(190);
        move(install,margin,Scale(483),normal,buttonHeight);move(uninstall,margin+normal+gap,Scale(483),Scale(112),buttonHeight);
        move(copy,rect.right-margin-copyWidth-Scale(105)-gap,Scale(483),copyWidth,buttonHeight);move(refresh,rect.right-margin-Scale(105),Scale(483),Scale(105),buttonHeight);
        move(log,inside,Scale(570),width-Scale(40),(std::max)(Scale(60),static_cast<int>(rect.bottom)-Scale(654)));
        move(restart,rect.right-margin-Scale(165),rect.bottom-Scale(57),Scale(165),Scale(36));InvalidateRect(hwnd,nullptr,FALSE);
    }
    void Append(const std::wstring& text){if(GetWindowTextLengthW(log)>48000)SetWindowTextW(log,L"");const auto line=text+L"\r\n";SendMessageW(log,EM_SETSEL,static_cast<WPARAM>(-1),static_cast<LPARAM>(-1));SendMessageW(log,EM_REPLACESEL,FALSE,reinterpret_cast<LPARAM>(line.c_str()));}
    void UpdateButtons(){EnableWindow(install,!busy&&!preview&&!UninstallOnly);EnableWindow(uninstall,!busy&&!preview&&snapshot.installed);EnableWindow(copy,!busy&&!preview&&snapshot.running&&!snapshot.connectionCode.empty());EnableWindow(refresh,!busy&&!preview);EnableWindow(internet,!busy&&!preview&&!UninstallOnly);EnableWindow(noCode,!busy&&!preview&&!UninstallOnly);EnableWindow(approval,!busy&&!preview&&!UninstallOnly&&SendMessageW(noCode,BM_GETCHECK,0,0)==BST_CHECKED);EnableWindow(driver,!busy&&!preview&&snapshot.removableDriver);EnableWindow(restart,!busy&&!preview);ShowWindow(restart,(!preview&&(result.restartRequired||snapshot.restartRequired))?SW_SHOW:SW_HIDE);}
    void UpdateDisclosure(){
        const bool open=SendMessageW(noCode,BM_GETCHECK,0,0)==BST_CHECKED,ask=SendMessageW(approval,BM_GETCHECK,0,0)==BST_CHECKED,online=SendMessageW(internet,BM_GETCHECK,0,0)==BST_CHECKED;
        std::wstring text=L"The host starts with Windows. ";
        if(open){text+=online?L"This PC is publicly listed locally and on the Internet. ":L"This PC is listed on this private local network. ";text+=ask?L"Each connection requires approval on this PC. ":L"Anyone listed can control this PC without a code or permission prompt. ";}
        else text+=L"Only someone with your private connection code can connect. Keep it secret. ";
        text+=L"Only the signed-in console desktop is accessible.\r\nVdevice is a shared one-hour demo per boot. Windows event/setup logs are preserved on removal.";SetWindowTextW(disclosure,text.c_str());
    }
    void Progress(unsigned percent,const std::wstring& text){
        {std::lock_guard<std::mutex> guard(mutex);target=(std::min)(percent,100u);progressText=text;}
        if(!progressQueued.exchange(true)&&!PostMessageW(hwnd,ProgressMessage,0,0))progressQueued=false;
    }
    void Begin(int action){
        if(busy||preview||(action==1&&UninstallOnly))return;if(worker.joinable())worker.join();busy=true;target=0;displayed=0;result={};UpdateButtons();SetTimer(hwnd,1,16,nullptr);
        const bool useInternet=SendMessageW(internet,BM_GETCHECK,0,0)==BST_CHECKED;
        const bool useNoCode=SendMessageW(noCode,BM_GETCHECK,0,0)==BST_CHECKED,askPermission=SendMessageW(approval,BM_GETCHECK,0,0)==BST_CHECKED;
        const bool removeDriver=SendMessageW(driver,BM_GETCHECK,0,0)==BST_CHECKED&&snapshot.removableDriver;
        try{worker=std::thread([this,action,useInternet,useNoCode,askPermission,removeDriver]{
            Setup::Result done;Setup::Snapshot state;
            try{const auto callback=[this](unsigned percent,const std::wstring& text){Progress(percent,text);};
                if(action==1)done=Setup::Install(useInternet,callback,useNoCode,useNoCode?std::optional<bool>(askPermission):std::nullopt);else if(action==2)done=Setup::Uninstall(removeDriver,callback);
                state=Setup::Inspect(true);
            }catch(const std::exception& error){done.code=1;done.message=Wide(error.what());state.status=L"Operation needs attention";state.detail=done.message;}
            {std::lock_guard<std::mutex> guard(mutex);result=std::move(done);snapshot=std::move(state);target=100;}
            PostMessageW(hwnd,DoneMessage,0,0);
        });}catch(const std::exception& error){busy=false;Append(L"Could not start installer worker: "+Wide(error.what()));UpdateButtons();}
    }
    void Complete(){
        if(worker.joinable())worker.join();busy=false;SetWindowTextW(status,snapshot.status.c_str());SetWindowTextW(detail,snapshot.detail.c_str());
        SendMessageW(internet,BM_SETCHECK,snapshot.internet?BST_CHECKED:BST_UNCHECKED,0);SendMessageW(driver,BM_SETCHECK,snapshot.removableDriver?BST_CHECKED:BST_UNCHECKED,0);
        SendMessageW(noCode,BM_SETCHECK,snapshot.noCode?BST_CHECKED:BST_UNCHECKED,0);SendMessageW(approval,BM_SETCHECK,snapshot.requireApproval?BST_CHECKED:BST_UNCHECKED,0);UpdateDisclosure();
        if(!result.message.empty())Append(result.message);else Append(snapshot.status+L". "+snapshot.detail);
        UpdateButtons();if(requestedUninstall){requestedUninstall=false;Append(L"Review the Vdevice removal option, then choose Uninstall. Use the downloaded full installer for Install / repair.");SetFocus(uninstall);}
    }
    void Copy(){
        if(snapshot.connectionCode.empty())return;if(!OpenClipboard(hwnd)){Append(L"The clipboard is busy. Try Copy connection code again.");return;}
        const auto bytes=(snapshot.connectionCode.size()+1)*sizeof(wchar_t);HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,bytes);
        if(!memory){CloseClipboard();Append(L"Could not allocate clipboard text.");return;}auto data=GlobalLock(memory);if(!data){GlobalFree(memory);CloseClipboard();return;}memcpy(data,snapshot.connectionCode.c_str(),bytes);GlobalUnlock(memory);EmptyClipboard();if(!SetClipboardData(CF_UNICODETEXT,memory)){GlobalFree(memory);Append(L"Could not copy the private connection code.");}else Append(L"Connection code copied. Share it privately with the intended controller only.");CloseClipboard();
    }
    void Card(HDC dc,RECT rect){HBRUSH fill=CreateSolidBrush(RGB(255,255,255));HPEN border=CreatePen(PS_SOLID,1,Line);auto oldBrush=SelectObject(dc,fill),oldPen=SelectObject(dc,border);RoundRect(dc,rect.left,rect.top,rect.right,rect.bottom,Scale(14),Scale(14));SelectObject(dc,oldBrush);SelectObject(dc,oldPen);DeleteObject(fill);DeleteObject(border);}
    void Paint(){PAINTSTRUCT paint{};HDC targetDc=BeginPaint(hwnd,&paint);RECT rect{};GetClientRect(hwnd,&rect);HDC dc=CreateCompatibleDC(targetDc);HBITMAP bitmap=CreateCompatibleBitmap(targetDc,(std::max)(rect.right,1L),(std::max)(rect.bottom,1L));auto old=SelectObject(dc,bitmap);FillRect(dc,&rect,background);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,Ink);SelectObject(dc,titleFont);RECT title{Scale(24),Scale(23),rect.right-Scale(24),Scale(66)};DrawTextW(dc,L"Remote Device Control — Host setup",-1,&title,DT_SINGLELINE|DT_VCENTER);SelectObject(dc,font);SetTextColor(dc,Muted);RECT subtitle{Scale(25),Scale(70),rect.right-Scale(25),Scale(94)};DrawTextW(dc,L"Vdevice keyboard/mouse · private LAN and encrypted Internet access",-1,&subtitle,DT_SINGLELINE);
        Card(dc,{Scale(24),Scale(108),rect.right-Scale(24),Scale(204)});Card(dc,{Scale(24),Scale(210),rect.right-Scale(24),Scale(465)});Card(dc,{Scale(24),Scale(544),rect.right-Scale(24),rect.bottom-Scale(72)});
        SetTextColor(dc,Muted);RECT heading{Scale(44),Scale(549),rect.right-Scale(44),Scale(568)};DrawTextW(dc,L"Operation details",-1,&heading,DT_SINGLELINE);
        RECT track{Scale(24),rect.bottom-Scale(20),rect.right-Scale(24),rect.bottom-Scale(14)};HBRUSH trackBrush=CreateSolidBrush(Line);FillRect(dc,&track,trackBrush);DeleteObject(trackBrush);track.right=track.left+static_cast<int>((rect.right-Scale(48))*displayed/100.0);HBRUSH blue=CreateSolidBrush(Blue);FillRect(dc,&track,blue);DeleteObject(blue);
        BitBlt(targetDc,0,0,rect.right,rect.bottom,dc,0,0,SRCCOPY);SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);EndPaint(hwnd,&paint);
    }
    void DrawButton(const DRAWITEMSTRUCT& item){
        if(item.CtlType!=ODT_BUTTON)return;const bool primary=item.CtlID==InstallId;const bool disabled=(item.itemState&ODS_DISABLED)!=0,pressed=(item.itemState&ODS_SELECTED)!=0;
        COLORREF fill=primary&&!disabled?(pressed?RGB(15,70,175):Blue):RGB(255,255,255);HBRUSH brush=CreateSolidBrush(fill);HPEN pen=CreatePen(PS_SOLID,1,primary&&!disabled?fill:Line);auto oldBrush=SelectObject(item.hDC,brush),oldPen=SelectObject(item.hDC,pen);RoundRect(item.hDC,item.rcItem.left,item.rcItem.top,item.rcItem.right,item.rcItem.bottom,Scale(9),Scale(9));SelectObject(item.hDC,oldBrush);SelectObject(item.hDC,oldPen);DeleteObject(brush);DeleteObject(pen);
        wchar_t text[128]{};GetWindowTextW(item.hwndItem,text,128);SetBkMode(item.hDC,TRANSPARENT);SetTextColor(item.hDC,disabled?Muted:primary?RGB(255,255,255):Ink);SelectObject(item.hDC,font);RECT content=item.rcItem;DrawTextW(item.hDC,text,-1,&content,DT_CENTER|DT_VCENTER|DT_SINGLELINE);if(item.itemState&ODS_FOCUS){InflateRect(&content,-Scale(4),-Scale(4));DrawFocusRect(item.hDC,&content);}
    }
    LRESULT Message(UINT message,WPARAM wp,LPARAM lp){
        switch(message){
        case WM_CREATE:Build();return 0;
        case WM_SIZE:if(status)Layout();return 0;
        case WM_GETMINMAXINFO:{auto info=reinterpret_cast<MINMAXINFO*>(lp);info->ptMinTrackSize={Scale(850),Scale(760)};return 0;}
        case WM_DPICHANGED:{Fonts();const auto rect=reinterpret_cast<RECT*>(lp);SetWindowPos(hwnd,nullptr,rect->left,rect->top,rect->right-rect->left,rect->bottom-rect->top,SWP_NOZORDER|SWP_NOACTIVATE);Layout();return 0;}
        case WM_ERASEBKGND:return 1;
        case WM_PAINT:Paint();return 0;
        case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:{auto dc=reinterpret_cast<HDC>(wp);SetTextColor(dc,Ink);SetBkColor(dc,RGB(255,255,255));return reinterpret_cast<LRESULT>(white);}
        case WM_DRAWITEM:DrawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));return TRUE;
        case ProgressMessage:{progressQueued=false;std::wstring text;{std::lock_guard<std::mutex> guard(mutex);text=progressText;}if(!text.empty())Append(text);return 0;}
        case DoneMessage:Complete();return 0;
        case WM_TIMER:{unsigned value;{std::lock_guard<std::mutex> guard(mutex);value=target;}const auto gap=static_cast<double>(value)-displayed;displayed+=gap>0.3?gap*0.18:gap;if(!busy&&displayed>=99.9){displayed=100;KillTimer(hwnd,1);}InvalidateRect(hwnd,nullptr,FALSE);return 0;}
        case WM_COMMAND:if(HIWORD(wp)==BN_CLICKED){switch(LOWORD(wp)){
            case InstallId:Begin(1);break;
            case UninstallId:if(MessageBoxW(hwnd,L"Remove this remote host service and its settings?\n\nIf the Vdevice option is checked, the demo driver installed by this host will also be removed. Other Vdevice applications may need it.\n\nWindows event/setup logs are preserved. A restart may be required.",L"Uninstall Remote Device Control",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES)Begin(2);break;
            case CopyId:Copy();break;case RefreshId:Begin(0);break;
            case NoCodeId:
                if(SendMessageW(noCode,BM_GETCHECK,0,0)==BST_CHECKED){
                    const auto answer=MessageBoxW(hwnd,L"Do you want to approve each incoming connection on this PC?\n\nYes: ask for permission each time.\nNo: anyone who sees this PC in the local-network or public Internet list can connect directly, without a code or permission prompt.\nCancel: keep code-protected access.",L"Connections without a code",MB_YESNOCANCEL|MB_ICONQUESTION|MB_DEFBUTTON1);
                    if(answer==IDCANCEL)SendMessageW(noCode,BM_SETCHECK,BST_UNCHECKED,0);else SendMessageW(approval,BM_SETCHECK,answer==IDYES?BST_CHECKED:BST_UNCHECKED,0);
                }
                UpdateDisclosure();UpdateButtons();break;
            case ApprovalId:case InternetId:UpdateDisclosure();UpdateButtons();break;
            case RestartId:if(MessageBoxW(hwnd,L"Save your work before restarting Windows. Restart now?",L"Restart Windows",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES)try{Setup::RequestRestart();}catch(const std::exception& error){Append(Wide(error.what()));}break;
            default:break;}return 0;}break;
        case WM_CLOSE:if(busy){MessageBoxW(hwnd,L"Windows is completing the current operation. Keep the installer open until it finishes.",L"Operation in progress",MB_OK|MB_ICONINFORMATION);return 0;}DestroyWindow(hwnd);return 0;
        case WM_DESTROY:KillTimer(hwnd,1);PostQuitMessage(0);return 0;
        default:break;
        }return DefWindowProcW(hwnd,message,wp,lp);
    }
    static LRESULT CALLBACK Proc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp){auto window=reinterpret_cast<Window*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));if(message==WM_NCCREATE){window=static_cast<Window*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);window->hwnd=hwnd;SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(window));}if(!window)return DefWindowProcW(hwnd,message,wp,lp);try{return window->Message(message,wp,lp);}catch(const std::exception& error){MessageBoxA(hwnd,error.what(),"Installer error",MB_OK|MB_ICONERROR);return message==WM_CREATE?-1:0;}}
};
}
void Console(const std::wstring& text){
    HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);if(!output||output==INVALID_HANDLE_VALUE){if(AttachConsole(ATTACH_PARENT_PROCESS))output=GetStdHandle(STD_OUTPUT_HANDLE);}
    if(!output||output==INVALID_HANDLE_VALUE)return;DWORD written=0;DWORD mode=0;if(GetConsoleMode(output,&mode)){WriteConsoleW(output,text.c_str(),static_cast<DWORD>(text.size()),&written,nullptr);return;}
    const auto bytes=Utf8(text);WriteFile(output,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show){
    bool batch=false;
    try{
        int count=0;auto args=CommandLineToArgvW(GetCommandLineW(),&count);if(!args)throw std::runtime_error("Could not parse installer arguments.");bool preview=false,uninstall=false,status=false,selfTest=false,install=false,removeUi=false,lanOnly=false,keepDriver=false;std::optional<bool> publicAccess,askPermission;
        std::string optionError;const auto choose=[&](std::optional<bool>& option,bool value){if(option.has_value()&&*option!=value)optionError="Choose only one value for each access option.";option=value;};
        for(int i=1;i<count;++i){const std::wstring arg=args[i];if(arg==L"--preview")preview=true;else if(arg==L"/uninstall"||arg==L"--uninstall"){uninstall=true;batch=true;}else if(arg==L"/install"||arg==L"--install"){install=true;batch=true;}else if(arg==L"--remove-ui")removeUi=true;else if(arg==L"--status"||arg==L"/status"){status=true;batch=true;}else if(arg==L"--self-test"){selfTest=true;batch=true;}else if(arg==L"--lan-only")lanOnly=true;else if(arg==L"--keep-driver")keepDriver=true;else if(arg==L"--no-code")choose(publicAccess,true);else if(arg==L"--require-code")choose(publicAccess,false);else if(arg==L"--ask-permission")choose(askPermission,true);else if(arg==L"--allow-direct")choose(askPermission,false);else{batch=true;LocalFree(args);throw std::runtime_error("Use --preview, --status, --self-test, /install [--lan-only] [--no-code | --require-code] [--ask-permission | --allow-direct], /uninstall [--keep-driver], or --remove-ui.");}}LocalFree(args);
        if(!optionError.empty())throw std::runtime_error(optionError);
        if(static_cast<unsigned>(preview)+static_cast<unsigned>(uninstall)+static_cast<unsigned>(status)+static_cast<unsigned>(selfTest)+static_cast<unsigned>(install)+static_cast<unsigned>(removeUi)>1||(lanOnly&&!install)||(keepDriver&&!uninstall))throw std::runtime_error("Choose one installer operation; --preview never permits mutations.");
        if((publicAccess.has_value()||askPermission.has_value())&&!install)throw std::runtime_error("Access options are only valid with /install.");
        if(publicAccess.has_value()&&!*publicAccess&&askPermission.has_value())throw std::runtime_error("Permission-prompt options cannot be combined with --require-code.");
        if(install&&UninstallOnly)throw std::runtime_error("This installed removal helper cannot install or repair. Use the downloaded full RemoteDeviceControlSetup.exe.");
        if(selfTest){Setup::SelfTest();Console(L"PASS: embedded host/driver installer resources and ownership parser checks; no installation.\r\n");return 0;}
        if(status){const auto state=Setup::Inspect(false);Console(L"Remote Device Control: "+state.status+L"\r\n"+state.detail+L"\r\n");return 0;}
        if(install||uninstall){const auto progress=[](unsigned percent,const std::wstring& text){Console(L"["+std::to_wstring(percent)+L"%] "+text+L"\r\n");};const auto operation=install?Setup::Install(!lanOnly,progress,publicAccess,askPermission):Setup::Uninstall(!keepDriver,progress);Console(operation.message+L"\r\nExit code: "+std::to_wstring(operation.code)+L"\r\n");return static_cast<int>(operation.code);}
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_STANDARD_CLASSES};InitCommonControlsEx(&controls);
        Window window;window.preview=preview;window.requestedUninstall=removeUi||UninstallOnly;WNDCLASSEXW type{};type.cbSize=sizeof(type);type.lpfnWndProc=Window::Proc;type.hInstance=instance;type.hCursor=LoadCursorW(nullptr,IDC_ARROW);type.lpszClassName=L"RemoteDeviceControlSetupWindow";type.hIcon=LoadIconW(nullptr,IDI_APPLICATION);RegisterClassExW(&type);
        auto hwnd=CreateWindowExW(0,type.lpszClassName,L"Remote Device Control — Host setup",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,960,800,nullptr,nullptr,instance,&window);if(!hwnd)return 1;ShowWindow(hwnd,show);UpdateWindow(hwnd);MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(hwnd,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}return 0;
    }catch(const std::exception& error){if(batch)Console(L"ERROR: "+Wide(error.what())+L"\r\n");else MessageBoxA(nullptr,error.what(),"Remote Device Control setup",MB_OK|MB_ICONERROR);return 1;}
}
