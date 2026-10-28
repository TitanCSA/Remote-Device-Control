#include "Directory.h"
#include "Config.h"
#include "Transport.h"
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

namespace RemoteControl {
namespace {
constexpr size_t Limit=65536;
constexpr wchar_t Path[]=L"/remote-device-control/hosts";
constexpr wchar_t Relay[]=L"wss://licences.configcsa.com/remote-device-control/relay";
[[noreturn]] void Fail(const char* stage,DWORD error=GetLastError()){throw std::runtime_error(std::string(stage)+" failed (Windows error "+std::to_string(error)+").");}
void Require(BOOL value,const char* stage){if(!value)Fail(stage);}
bool Valid(const PublicHost& h){
 if(h.name.empty()||h.name.size()>128||!TitanTransport::IsSecret(h.room)||!TitanTransport::IsFingerprint(h.pin)||!TitanTransport::IsFingerprint(h.relayToken)||h.relay!=Relay)return false;
 for(unsigned char c:h.name)if(c<32||c==127)return false;
 try{(void)Wide(h.name);}catch(...){return false;}return true;
}
std::string Quote(std::string_view text){std::string out="\"";for(unsigned char c:text){if(c=='"'||c=='\\'){out+='\\';out+=static_cast<char>(c);}else if(c<32||c==127)throw std::runtime_error("Invalid public host text.");else out+=static_cast<char>(c);}return out+'"';}
class Json {
 std::string_view text_;size_t at_=0;
 [[noreturn]] static void Bad(){throw std::runtime_error("Invalid bounded public directory response.");}
 unsigned Hex(){unsigned out=0;for(unsigned i=0;i<4;++i){if(at_==text_.size())Bad();char c=text_[at_++];unsigned n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;if(n==16)Bad();out=out*16+n;}return out;}
 static void Append(std::string& out,unsigned c){if(c<0x80)out+=static_cast<char>(c);else if(c<0x800){out+=static_cast<char>(0xc0|(c>>6));out+=static_cast<char>(0x80|(c&63));}else if(c<0x10000){out+=static_cast<char>(0xe0|(c>>12));out+=static_cast<char>(0x80|((c>>6)&63));out+=static_cast<char>(0x80|(c&63));}else{out+=static_cast<char>(0xf0|(c>>18));out+=static_cast<char>(0x80|((c>>12)&63));out+=static_cast<char>(0x80|((c>>6)&63));out+=static_cast<char>(0x80|(c&63));}}
public:
 explicit Json(std::string_view text):text_(text){if(text.empty()||text.size()>Limit)Bad();}
 void Space(){while(at_<text_.size()&&(text_[at_]==' '||text_[at_]=='\n'||text_[at_]=='\r'||text_[at_]=='\t'))++at_;}
 bool Is(char c){Space();return at_<text_.size()&&text_[at_]==c;}
 void Take(char c){if(!Is(c))Bad();++at_;}
 std::string String(){Take('"');std::string out;bool closed=false;while(at_<text_.size()){unsigned char c=text_[at_++];if(c=='"'){closed=true;break;}if(c<32)Bad();if(c=='\\'){if(at_==text_.size())Bad();c=text_[at_++];if(c=='"'||c=='\\'||c=='/')out+=static_cast<char>(c);else if(c=='u'){unsigned point=Hex();if(point>=0xd800&&point<=0xdbff){if(at_+2>text_.size()||text_[at_]!='\\'||text_[at_+1]!='u')Bad();at_+=2;unsigned low=Hex();if(low<0xdc00||low>0xdfff)Bad();point=0x10000+((point-0xd800)<<10)+(low-0xdc00);}else if(point>=0xdc00&&point<=0xdfff)Bad();Append(out,point);}else Bad();}else out+=static_cast<char>(c);if(out.size()>2048)Bad();}if(!closed)Bad();try{(void)Wide(out);}catch(...){Bad();}return out;}
 bool Boolean(){Space();for(auto pair:{std::pair<std::string_view,bool>{"true",true},{"false",false}})if(text_.substr(at_,pair.first.size())==pair.first){at_+=pair.first.size();return pair.second;}Bad();}
 PublicHost Host(){Take('{');PublicHost h;std::set<std::string> keys;while(!Is('}')){auto key=String();if(!keys.insert(key).second)Bad();Take(':');if(key=="name")h.name=String();else if(key=="room")h.room=String();else if(key=="pin")h.pin=String();else if(key=="relay_token")h.relayToken=String();else if(key=="relay")h.relay=Wide(String());else if(key=="busy")h.busy=Boolean();else if(key=="available")h.available=Boolean();else if(key=="require_approval")h.requireApproval=Boolean();else Bad();if(Is('}'))break;Take(',');if(Is('}'))Bad();}Take('}');if(keys.size()!=8||!Valid(h))Bad();return h;}
 std::vector<PublicHost> Hosts(){Take('{');if(String()!="hosts")Bad();Take(':');Take('[');std::vector<PublicHost> hosts;std::set<std::string> rooms;while(!Is(']')){if(hosts.size()==64)Bad();auto h=Host();if(!rooms.insert(h.room).second)Bad();hosts.push_back(std::move(h));if(Is(']'))break;Take(',');if(Is(']'))Bad();}Take(']');Take('}');Space();if(at_!=text_.size())Bad();return hosts;}
};

struct Http:std::enable_shared_from_this<Http> {
 HINTERNET session=nullptr,connection=nullptr,request=nullptr;
 HANDLE completed=CreateEventW(nullptr,TRUE,FALSE,nullptr),closed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 std::atomic<DWORD> error{0},bytes{0};std::atomic<bool> closing{false};std::shared_ptr<Http> lease;
 std::function<bool()> cancelled;std::array<char,4096> buffer{};std::string body;
 Http(){if(!completed||!closed){if(completed)CloseHandle(completed);if(closed)CloseHandle(closed);Fail("Directory completion events");}}
 ~Http(){Close();if(connection)WinHttpCloseHandle(connection);if(session)WinHttpCloseHandle(session);CloseHandle(completed);CloseHandle(closed);}
 void Close()noexcept{if(closing.exchange(true))return;SetEvent(closed);if(request){auto handle=request;request=nullptr;WinHttpCloseHandle(handle);}}
 static void CALLBACK Callback(HINTERNET,DWORD_PTR context,DWORD status,void* info,DWORD length)noexcept{
  auto* self=reinterpret_cast<Http*>(context);if(!self)return;auto keep=std::atomic_load(&self->lease);
  if(status==WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING)std::atomic_store(&self->lease,std::shared_ptr<Http>{});
  else if(status==WINHTTP_CALLBACK_STATUS_REQUEST_ERROR){self->error=info&&length>=sizeof(WINHTTP_ASYNC_RESULT)?static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError:ERROR_WINHTTP_CONNECTION_ERROR;SetEvent(self->closed);}
  else if(status==WINHTTP_CALLBACK_STATUS_READ_COMPLETE){self->bytes=length;SetEvent(self->completed);}
  else if(status==WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE||status==WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE)SetEvent(self->completed);
 }
 void Wait(ULONGLONG deadline){for(;;){if(cancelled&&cancelled()){Close();Fail("Directory request cancelled",ERROR_OPERATION_ABORTED);}const auto now=GetTickCount64();if(now>=deadline){Close();Fail("Directory request deadline",ERROR_TIMEOUT);}HANDLE events[]{completed,closed};auto result=WaitForMultipleObjects(2,events,FALSE,static_cast<DWORD>((std::min)(deadline-now,ULONGLONG(100))));if(result==WAIT_OBJECT_0){if(error)Fail("Directory HTTPS request",error);return;}if(result==WAIT_OBJECT_0+1)Fail("Directory HTTPS request",error?error.load():ERROR_OPERATION_ABORTED);if(result!=WAIT_TIMEOUT)Fail("Directory wait");}}
 std::string Run(const wchar_t* method,const std::wstring& path,std::string_view owner){
  if(cancelled&&cancelled())Fail("Directory request cancelled",ERROR_OPERATION_ABORTED);const auto deadline=GetTickCount64()+5000;
  session=WinHttpOpen(L"RemoteDeviceControl/0.1",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,WINHTTP_FLAG_ASYNC);Require(session!=nullptr,"Directory HTTPS session");Require(WinHttpSetTimeouts(session,3000,3000,3000,3000),"Directory timeouts");
  if(WinHttpSetStatusCallback(session,Callback,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS|WINHTTP_CALLBACK_FLAG_HANDLES,0)==WINHTTP_INVALID_STATUS_CALLBACK)Fail("Directory callback");
  connection=WinHttpConnect(session,L"licences.configcsa.com",INTERNET_DEFAULT_HTTPS_PORT,0);Require(connection!=nullptr,"Directory destination");request=WinHttpOpenRequest(connection,method,path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);Require(request!=nullptr,"Directory HTTPS request");
  const DWORD_PTR context=reinterpret_cast<DWORD_PTR>(this);if(!WinHttpSetOption(request,WINHTTP_OPTION_CONTEXT_VALUE,const_cast<DWORD_PTR*>(&context),sizeof(context)))Fail("Directory context");std::atomic_store(&lease,shared_from_this());
  DWORD disabled=WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION|WINHTTP_DISABLE_REDIRECTS,redirects=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;Require(WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled)),"Directory auth policy");Require(WinHttpSetOption(request,WINHTTP_OPTION_REDIRECT_POLICY,&redirects,sizeof(redirects)),"Directory redirects");
  std::wstring headers=L"Content-Type: application/json\r\nAccept: application/json\r\n";if(!owner.empty())headers+=L"x-remote-owner: "+std::wstring(owner.begin(),owner.end())+L"\r\n";
  Require(WinHttpAddRequestHeaders(request,headers.c_str(),static_cast<DWORD>(headers.size()),WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE),"Directory headers");
  ResetEvent(completed);Require(WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,body.empty()?WINHTTP_NO_REQUEST_DATA:body.data(),static_cast<DWORD>(body.size()),static_cast<DWORD>(body.size()),context),"Directory request send");Wait(deadline);
  ResetEvent(completed);Require(WinHttpReceiveResponse(request,nullptr),"Directory response");Wait(deadline);DWORD status=0,length=sizeof(status);Require(WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&length,WINHTTP_NO_HEADER_INDEX),"Directory response status");if(status!=200&&status!=204)throw std::runtime_error("Public directory request refused (HTTP "+std::to_string(status)+").");
  std::string response;for(;;){ResetEvent(completed);bytes=0;Require(WinHttpReadData(request,buffer.data(),static_cast<DWORD>(buffer.size()),nullptr),"Directory response read");Wait(deadline);const size_t count=bytes.load();if(count>buffer.size()||count>Limit-response.size())throw std::runtime_error("Public directory response exceeds its limit.");if(!count)break;response.append(buffer.data(),count);}return response;
 }
};
std::string Request(const wchar_t* method,std::wstring path,std::string body,std::string_view owner,std::function<bool()> cancelled){auto http=std::make_shared<Http>();http->cancelled=std::move(cancelled);http->body=std::move(body);try{auto response=http->Run(method,path,owner);http->Close();return response;}catch(...){http->Close();throw;}}
}
namespace DirectoryFormat {
std::string Encode(const PublicHost& h){if(!Valid(h))throw std::runtime_error("Invalid public host announcement.");return "{\"name\":"+Quote(h.name)+",\"room\":"+Quote(h.room)+",\"pin\":"+Quote(h.pin)+",\"relay_token\":"+Quote(h.relayToken)+",\"relay\":"+Quote(Utf8(h.relay))+",\"busy\":"+(h.busy?"true":"false")+",\"available\":"+(h.available?"true":"false")+",\"require_approval\":"+(h.requireApproval?"true":"false")+"}";}
std::vector<PublicHost> Decode(std::string_view text){return Json(text).Hosts();}
}
std::vector<PublicHost> BrowsePublicHosts(std::function<bool()> cancelled){return DirectoryFormat::Decode(Request(L"GET",Path,{}, {},std::move(cancelled)));}
void PublishPublicHost(const PublicHost& host,std::string_view owner,std::function<bool()> cancelled){if(!TitanTransport::IsFingerprint(owner))throw std::runtime_error("Invalid directory ownership token.");(void)Request(L"POST",Path,DirectoryFormat::Encode(host),owner,std::move(cancelled));}
void RemovePublicHost(std::string_view room,std::string_view owner,std::function<bool()> cancelled){if(!TitanTransport::IsSecret(room)||!TitanTransport::IsFingerprint(owner))throw std::runtime_error("Invalid directory removal identity.");(void)Request(L"DELETE",std::wstring(Path)+L"?room="+std::wstring(room.begin(),room.end()),{},owner,std::move(cancelled));}
struct DirectoryBrowser::State {
 mutable std::mutex mutex;std::condition_variable wake;std::thread worker;std::atomic<bool> stop{true};std::vector<PublicHost> hosts;std::string error;std::function<void()> changed;
 void Run(){while(!stop){try{auto next=BrowsePublicHosts([this]{return stop.load();});{std::lock_guard<std::mutex> lock(mutex);hosts=std::move(next);error.clear();}}catch(const std::exception& failure){std::lock_guard<std::mutex> lock(mutex);hosts.clear();error=failure.what();}if(stop)break;if(changed)try{changed();}catch(...){}std::unique_lock<std::mutex> lock(mutex);wake.wait_for(lock,std::chrono::seconds(3),[this]{return stop.load();});}}
};
DirectoryBrowser::DirectoryBrowser():state_(std::make_unique<State>()){}DirectoryBrowser::~DirectoryBrowser(){Stop();}
void DirectoryBrowser::Start(std::function<void()> changed){Stop();state_->changed=std::move(changed);state_->stop=false;state_->worker=std::thread([this]{state_->Run();});}
void DirectoryBrowser::Stop()noexcept{state_->stop=true;state_->wake.notify_all();if(state_->worker.joinable())state_->worker.join();}
std::vector<PublicHost> DirectoryBrowser::Hosts()const{std::lock_guard<std::mutex> lock(state_->mutex);return state_->hosts;}
std::string DirectoryBrowser::Error()const{std::lock_guard<std::mutex> lock(state_->mutex);return state_->error;}
}
