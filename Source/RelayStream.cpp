#include "RelayStream.h"
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace RemoteControl {
namespace {
constexpr size_t PacketLimit=65536;
constexpr char Ready[]="RDC-READY-1";
[[noreturn]] void Fail(const char* stage,DWORD code) {
    throw std::runtime_error(std::string(stage)+" failed (Windows error "+std::to_string(code)+").");
}
void Require(BOOL value,const char* stage) {if(!value)Fail(stage,GetLastError());}
bool Hex(std::string_view value,size_t count) noexcept {
    if(value.size()!=count)return false;
    for(char c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
}
std::wstring Wide(std::string_view value) {return {value.begin(),value.end()};}
DWORD Remaining(ULONGLONG deadline) {
    const auto now=GetTickCount64();
    if(now>=deadline)Fail("Relay operation deadline",ERROR_TIMEOUT);
    return static_cast<DWORD>((std::min)(deadline-now,ULONGLONG(30000)));
}
void CheckTimeout(uint32_t milliseconds) {
    if(!milliseconds||milliseconds>30000)throw std::runtime_error("Relay timeout must be1..30000 milliseconds.");
}

// Pending WinHTTP callbacks own a temporary self-reference. HANDLE_CLOSING is
// the documented last callback for each handle, so cancellation cannot leave a
// callback or asynchronous I/O writing into destroyed caller memory.
struct State:std::enable_shared_from_this<State> {
    HINTERNET session=nullptr,connection=nullptr,request=nullptr,websocket=nullptr;
    HANDLE httpDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE readDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE writeDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE closed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    std::atomic<bool> stopping{false};std::atomic<DWORD> error{0},readBytes{0},readType{0};
    std::atomic<unsigned> callbackHandles{0};std::shared_ptr<State> callbackLease;
    std::function<bool()> cancelled;
    std::mutex apiMutex,readerMutex,writerMutex;
    std::array<uint8_t,PacketLimit> receiveBuffer{};
    std::array<uint8_t,PacketLimit> sendBuffer{};
    size_t available=0,position=0;
    DWORD ignoredSyncBytes=0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE ignoredSyncType=WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;

    State() {
        if(!httpDone||!readDone||!writeDone||!closed) {
            const DWORD code=GetLastError();
            for(HANDLE event:{httpDone,readDone,writeDone,closed})if(event)CloseHandle(event);
            Fail("Relay completion events",code);
        }
    }
    ~State() {
        Close();
        if(connection)WinHttpCloseHandle(connection);
        if(session)WinHttpCloseHandle(session);
        for(HANDLE event:{httpDone,readDone,writeDone,closed})CloseHandle(event);
    }
    static void CALLBACK Callback(HINTERNET,DWORD_PTR context,DWORD status,void* information,DWORD size) noexcept {
        auto* self=reinterpret_cast<State*>(context);
        if(!self)return;
        const auto lease=std::atomic_load(&self->callbackLease);
        if(status==WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
            if(self->callbackHandles.fetch_sub(1)==1)std::atomic_store(&self->callbackLease,std::shared_ptr<State>{});
        } else if(status==WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
            DWORD code=ERROR_WINHTTP_CONNECTION_ERROR;
            if(information&&size>=sizeof(WINHTTP_ASYNC_RESULT))code=static_cast<WINHTTP_ASYNC_RESULT*>(information)->dwError;
            self->error.store(code);SetEvent(self->closed);
        } else if(status==WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE||status==WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE) {
            SetEvent(self->httpDone);
        } else if(status==WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
            if(!information||size<sizeof(WINHTTP_WEB_SOCKET_STATUS)) {
                self->error.store(ERROR_WINHTTP_INVALID_SERVER_RESPONSE);SetEvent(self->closed);return;
            }
            const auto result=static_cast<WINHTTP_WEB_SOCKET_STATUS*>(information);
            self->readBytes.store(result->dwBytesTransferred);self->readType.store(result->eBufferType);SetEvent(self->readDone);
        } else if(status==WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE)SetEvent(self->writeDone);
    }
    void PinHandle() {
        std::atomic_store(&callbackLease,shared_from_this());callbackHandles.fetch_add(1);
    }
    void UnpinWithoutCallback() {
        if(callbackHandles.fetch_sub(1)==1)std::atomic_store(&callbackLease,std::shared_ptr<State>{});
    }
    void CheckOpen() {
        if(stopping.load()||WaitForSingleObject(closed,0)==WAIT_OBJECT_0)Fail("Relay connection",error.load()?error.load():ERROR_OPERATION_ABORTED);
    }
    void Wait(HANDLE completed,DWORD milliseconds,const char* stage) {
        HANDLE events[]{completed,closed};const auto deadline=GetTickCount64()+milliseconds;
        for(;;) {
            if(cancelled&&cancelled()){Close();Fail("Relay connection cancelled",ERROR_OPERATION_ABORTED);}
            const auto now=GetTickCount64();if(now>=deadline){Close();Fail(stage,ERROR_TIMEOUT);}
            const DWORD timeout=static_cast<DWORD>((std::min)(deadline-now,ULONGLONG(100)));
            const DWORD result=WaitForMultipleObjects(2,events,FALSE,timeout);
            if(result==WAIT_OBJECT_0) {CheckOpen();return;}
            if(result==WAIT_TIMEOUT)continue;
            const DWORD code=error.load()?error.load():ERROR_OPERATION_ABORTED;Close();Fail(stage,code);
        }
    }
    void Close() noexcept {
        if(stopping.exchange(true))return;
        SetEvent(closed);
        HINTERNET ws=nullptr,req=nullptr;
        {std::lock_guard<std::mutex> lock(apiMutex);ws=std::exchange(websocket,nullptr);req=std::exchange(request,nullptr);}
        // All operations use async WinHTTP. Closing their handles is the
        // documented cancellation mechanism; never race WebSocketClose.
        if(ws)WinHttpCloseHandle(ws);
        if(req)WinHttpCloseHandle(req);
    }
    void Initialize(std::wstring_view url,std::string_view room,std::string_view token,std::string_view role,std::string_view channel) {
        if(cancelled&&cancelled())Fail("Relay connection cancelled",ERROR_OPERATION_ABORTED);
        if(url.size()>2048||url.find(L'\0')!=url.npos||url.substr(0,6)!=L"wss://")throw std::runtime_error("Use an absolute wss:// relay URL.");
        if(!Hex(room,32)||!Hex(token,64)||(role!="host"&&role!="viewer")||(channel!="video"&&channel!="input"))throw std::runtime_error("Invalid relay pairing parameters.");
        std::wstring https=L"https://"+std::wstring(url.substr(6));URL_COMPONENTS parts{};parts.dwStructSize=sizeof(parts);
        parts.dwHostNameLength=parts.dwUrlPathLength=parts.dwExtraInfoLength=parts.dwUserNameLength=parts.dwPasswordLength=static_cast<DWORD>(-1);
        Require(WinHttpCrackUrl(https.c_str(),static_cast<DWORD>(https.size()),0,&parts),"Relay URL parsing");
        if(parts.nScheme!=INTERNET_SCHEME_HTTPS||!parts.nPort||!parts.dwHostNameLength||parts.dwHostNameLength>253||parts.dwUserNameLength||parts.dwPasswordLength||parts.dwExtraInfoLength||
           std::wstring_view(parts.lpszUrlPath,parts.dwUrlPathLength)!=L"/remote-device-control/relay")throw std::runtime_error("Relay URL must use the exact HTTPS relay path without credentials, query or fragment.");
        const std::wstring host(parts.lpszHostName,parts.dwHostNameLength);
        session=WinHttpOpen(L"RemoteDeviceControl/0.1",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,WINHTTP_FLAG_ASYNC);
        Require(session!=nullptr,"Relay HTTPS session");Require(WinHttpSetTimeouts(session,5000,5000,5000,5000),"Relay HTTPS timeouts");
        if(WinHttpSetStatusCallback(session,Callback,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS|WINHTTP_CALLBACK_FLAG_HANDLES,0)==WINHTTP_INVALID_STATUS_CALLBACK)Fail("Relay completion callback",GetLastError());
        connection=WinHttpConnect(session,host.c_str(),parts.nPort,0);Require(connection!=nullptr,"Relay HTTPS destination");
        request=WinHttpOpenRequest(connection,L"GET",L"/remote-device-control/relay",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
        Require(request!=nullptr,"Relay HTTPS request");
        PinHandle();DWORD_PTR context=reinterpret_cast<DWORD_PTR>(this);
        if(!WinHttpSetOption(request,WINHTTP_OPTION_CONTEXT_VALUE,&context,sizeof(context))) {
            UnpinWithoutCallback();const DWORD code=GetLastError();Fail("Relay request context",code);
        }
        DWORD redirects=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        Require(WinHttpSetOption(request,WINHTTP_OPTION_REDIRECT_POLICY,&redirects,sizeof(redirects)),"Relay redirect policy");
        DWORD disabled=WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION|WINHTTP_DISABLE_REDIRECTS;
        Require(WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled)),"Relay authentication policy");
        Require(WinHttpSetOption(request,WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,nullptr,0),"Relay WebSocket upgrade");
        const std::wstring headers=L"x-remote-room: "+Wide(room)+L"\r\nx-remote-token: "+Wide(token)+L"\r\nx-remote-role: "+Wide(role)+L"\r\nx-remote-channel: "+Wide(channel)+L"\r\n";
        Require(WinHttpAddRequestHeaders(request,headers.c_str(),static_cast<DWORD>(headers.size()),WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE),"Relay capability headers");
        ResetEvent(httpDone);
        Require(WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,context),"Relay HTTPS request send");Wait(httpDone,5000,"Relay HTTPS request completion");
        ResetEvent(httpDone);Require(WinHttpReceiveResponse(request,nullptr),"Relay HTTPS response");Wait(httpDone,5000,"Relay HTTPS headers");
        DWORD status=0,size=sizeof(status);Require(WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX),"Relay HTTPS status");
        if(status!=101)throw std::runtime_error("Relay connection refused (HTTP "+std::to_string(status)+"). Check host availability, pairing information and relay capacity.");
        websocket=WinHttpWebSocketCompleteUpgrade(request,context);Require(websocket!=nullptr,"Relay WebSocket establishment");PinHandle();
        if(WinHttpSetStatusCallback(websocket,Callback,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS|WINHTTP_CALLBACK_FLAG_HANDLES,0)==WINHTTP_INVALID_STATUS_CALLBACK)Fail("Relay WebSocket callback",GetLastError());
        HINTERNET completed=std::exchange(request,nullptr);WinHttpCloseHandle(completed);
        const auto deadline=GetTickCount64()+20000;NextMessage(deadline);
        if(available!=sizeof(Ready)-1||std::memcmp(receiveBuffer.data(),Ready,sizeof(Ready)-1))throw std::runtime_error("Relay pairing handshake is invalid.");
        available=position=0;
    }
    void NextMessage(ULONGLONG deadline) {
        available=position=0;
        for(unsigned fragments=0;fragments<128;++fragments) {
            if(available==PacketLimit)throw std::runtime_error("Relay WebSocket message exceeds its size limit.");
            ResetEvent(readDone);readBytes.store(0);
            DWORD result=NO_ERROR;
            {
                std::lock_guard<std::mutex> lock(apiMutex);CheckOpen();
                result=WinHttpWebSocketReceive(websocket,receiveBuffer.data()+available,static_cast<DWORD>(PacketLimit-available),&ignoredSyncBytes,&ignoredSyncType);
            }
            if(result!=NO_ERROR&&result!=ERROR_IO_PENDING){Close();Fail("Relay receive start",result);}
            Wait(readDone,Remaining(deadline),"Relay receive completion");
            const DWORD count=readBytes.load();const DWORD type=readType.load();
            if(count>PacketLimit-available){Close();throw std::runtime_error("Relay receive bounds are invalid.");}
            if(type!=WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE&&type!=WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE){Close();throw std::runtime_error("Relay closed or sent a non-binary message.");}
            available+=count;
            if(type==WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
                if(!available){Close();throw std::runtime_error("Relay sent an empty message.");}
                return;
            }
        }
        Close();throw std::runtime_error("Too many relay WebSocket fragments.");
    }
    size_t ReadSome(void* bytes,size_t capacity,uint32_t timeout) {
        CheckTimeout(timeout);if(!bytes||!capacity)throw std::runtime_error("Missing relay receive buffer.");
        std::lock_guard<std::mutex> lock(readerMutex);CheckOpen();
        if(position==available) {
            try {NextMessage(GetTickCount64()+timeout);}
            catch(...) {Close();throw;}
        }
        const size_t count=(std::min)(capacity,available-position);std::memcpy(bytes,receiveBuffer.data()+position,count);position+=count;return count;
    }
    void WriteAll(const void* bytes,size_t count,uint32_t timeout) {
        CheckTimeout(timeout);if(count&&!bytes)throw std::runtime_error("Missing relay send buffer.");
        std::lock_guard<std::mutex> lock(writerMutex);const auto deadline=GetTickCount64()+timeout;
        auto input=static_cast<const uint8_t*>(bytes);
        try {while(count) {
            const size_t amount=(std::min)(count,PacketLimit);std::memcpy(sendBuffer.data(),input,amount);ResetEvent(writeDone);
            DWORD result=NO_ERROR;
            {
                std::lock_guard<std::mutex> apiLock(apiMutex);CheckOpen();
                result=WinHttpWebSocketSend(websocket,WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,sendBuffer.data(),static_cast<DWORD>(amount));
            }
            if(result!=NO_ERROR&&result!=ERROR_IO_PENDING){Close();Fail("Relay send start",result);}
            Wait(writeDone,Remaining(deadline),"Relay send completion");input+=amount;count-=amount;
        }}catch(...) {Close();throw;}
    }
};

class RelayStream final:public TitanTransport::ByteStream {
    std::shared_ptr<State> state_;
public:
    explicit RelayStream(std::shared_ptr<State> state):state_(std::move(state)){}
    ~RelayStream() override {Close();}
    size_t ReadSome(void* bytes,size_t capacity,uint32_t timeout) override{return state_->ReadSome(bytes,capacity,timeout);}
    void WriteAll(const void* bytes,size_t count,uint32_t timeout) override{state_->WriteAll(bytes,count,timeout);}
    void Close() noexcept override{state_->Close();}
};
}

std::unique_ptr<TitanTransport::ByteStream> OpenRelay(std::wstring_view url,std::string_view room,std::string_view token,std::string_view role,std::string_view channel,std::function<bool()> cancelled) {
    auto state=std::make_shared<State>();
    state->cancelled=std::move(cancelled);
    try {state->Initialize(url,room,token,role,channel);return std::make_unique<RelayStream>(std::move(state));}
    catch(...) {state->Close();throw;}
}
}
