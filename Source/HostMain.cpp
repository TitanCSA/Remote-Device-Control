#include "Host.h"
#include "CaptureAgent.h"
#include "Config.h"
#include <shellapi.h>
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){int argc=0;LPWSTR* argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 87;int result=87;try{if(argc==2&&std::wstring(argv[1])==L"--service")result=RemoteControl::RunService();else if(argc==3&&std::wstring(argv[1])==L"--agent")result=RemoteControl::RunCaptureAgent(argv[2]);else if(argc==2&&std::wstring(argv[1])==L"--console")result=RemoteControl::RunHostConsole();}catch(...){result=1;}LocalFree(argv);return result;}
