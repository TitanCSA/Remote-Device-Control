#include "Protocol.h"
#include <windows.h>
#include <stdexcept>
namespace RemoteControl {
bool ValidInput(const Input& i)noexcept{
 switch(i.kind){
 case InputKind::Pointer:return i.x>=0&&i.x<=65535&&i.y>=0&&i.y<=65535&&!i.code&&!i.down;
 case InputKind::Button:return i.code>=1&&i.code<=5&&i.down<=1&&!i.x&&!i.y;
 case InputKind::Key:return i.code>=4&&i.code<=231&&i.down<=1&&!i.x&&!i.y;
 case InputKind::Wheel:return i.x>=-127&&i.x<=127&&i.y>=-127&&i.y<=127&&!i.code&&!i.down;
 case InputKind::ReleaseAll:return !i.x&&!i.y&&!i.code&&!i.down;
 default:return false;
 }
}
std::string WindowsError(const char* operation,uint32_t code){
 LPWSTR text=nullptr;FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,0,reinterpret_cast<LPWSTR>(&text),0,nullptr);
 std::string result=std::string(operation)+" failed (Windows "+std::to_string(code)+")";
 if(text){int n=WideCharToMultiByte(CP_UTF8,0,text,-1,nullptr,0,nullptr,nullptr);if(n>1){std::string value(static_cast<size_t>(n),0);WideCharToMultiByte(CP_UTF8,0,text,-1,value.data(),n,nullptr,nullptr);value.pop_back();result+=": "+value;}LocalFree(text);}return result;
}
uint64_t NowQpc()noexcept{LARGE_INTEGER value{};QueryPerformanceCounter(&value);return static_cast<uint64_t>(value.QuadPart);}
}
