#include "Transport.h"
#include "Config.h"
#include "Protocol.h"
#include <thread>
#include <iostream>
#include <exception>
#include <atomic>
#include <chrono>
#include <stdexcept>
using namespace RemoteControl;
int main(){try{
 std::atomic<size_t> assertions{0};auto check=[&](bool value){const auto n=++assertions;if(!value)throw std::runtime_error("Core assertion "+std::to_string(n)+" failed.");};
 Config c;c.host=L"192.0.2.1";c.secret=std::string(32,'a');c.room=std::string(32,'b');const std::string pin(64,'d');auto parsed=ParsePairing(PairingCode(c,pin));check(parsed.host=="192.0.2.1"&&parsed.pin==pin&&parsed.secret==c.secret&&parsed.port==48789);
 for(const auto text:{L"",L"invalid",L"RDC1;x;0;x;x;x;x;x",L"RDC3;example/../;48789;pin;secret;room"}){bool refused=false;try{ParsePairing(text);}catch(...){refused=true;}check(refused);}
 auto direct=ParseDirectAddress(L"example.com:49100");check(direct.host=="example.com"&&direct.port==49100&&direct.noCode&&direct.pin.empty());direct=ParseDirectAddress(L"[2001:db8::1]:48789");check(direct.host=="2001:db8::1");
 for(int i=-100;i<70000;++i){Input value;value.x=i;check(ValidInput(value)==(i>=0&&i<=65535));}
 TitanTransport::Runtime runtime;TitanTransport::Identity original;auto exported=original.Export();TitanTransport::Identity persisted(exported);check(original.Fingerprint()==persisted.Fingerprint());check(original.CertificatePem().find("BEGIN CERTIFICATE")!=std::string::npos);
 uint16_t port=0;SOCKET listener=TitanTransport::Listen("127.0.0.1",0,&port);std::exception_ptr failure,clientFailure;std::atomic<bool> serverObservedClose{false};
 std::thread server([&]{try{TitanTransport::Channel link(accept(listener,nullptr,nullptr));link.HandshakeServer(persisted);std::vector<uint8_t> bytes(70001);link.Receive(bytes.data(),bytes.size());for(size_t i=0;i<bytes.size();++i)check(bytes[i]==static_cast<uint8_t>(i));link.Send(bytes.data(),bytes.size());
  std::this_thread::sleep_for(std::chrono::milliseconds(5500));const uint8_t notice=42;link.Send(&notice,1);
  const auto closeWait=GetTickCount64();try{link.Receive(bytes.data(),1,15000);}catch(const std::exception&){serverObservedClose=GetTickCount64()-closeWait<2000;}
 }catch(...){failure=std::current_exception();}});
 try{TitanTransport::Channel viewer(TitanTransport::Connect("localhost",port));viewer.HandshakeClient(original.Fingerprint());std::vector<uint8_t> bytes(70001);for(size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<uint8_t>(i);viewer.Send(bytes.data(),bytes.size());std::vector<uint8_t> echo(bytes.size());viewer.Receive(echo.data(),echo.size());check(echo==bytes);
  const auto began=GetTickCount64();uint8_t notice=0;viewer.Receive(&notice,1,7000);check(notice==42&&GetTickCount64()-began>=5000);
  std::atomic<bool> started{false};std::exception_ptr cancelled;std::thread waiting([&]{started=true;try{viewer.Receive(&notice,1,90000);}catch(...){cancelled=std::current_exception();}});
  while(!started)std::this_thread::yield();std::this_thread::sleep_for(std::chrono::milliseconds(100));const auto closing=GetTickCount64();viewer.Close();waiting.join();check(cancelled!=nullptr&&GetTickCount64()-closing<1500);
 }catch(...){clientFailure=std::current_exception();}
 closesocket(listener);server.join();if(clientFailure)std::rethrow_exception(clientFailure);if(failure)std::rethrow_exception(failure);check(serverObservedClose);
 // Credential-free first contact never turns into an application-data channel.
 listener=TitanTransport::Listen("127.0.0.1",0,&port);failure=nullptr;
 std::thread probeServer([&]{try{TitanTransport::Channel link(accept(listener,nullptr,nullptr));link.HandshakeServer(persisted);uint8_t b=0;try{link.Receive(&b,1,2000);}catch(...){}}catch(...){failure=std::current_exception();}});
 try{TitanTransport::Channel probe(TitanTransport::Connect("127.0.0.1",port));check(probe.ProbeServerCertificate()==persisted.Fingerprint());bool refused=false;try{const char b='x';probe.Send(&b,1);}catch(...){refused=true;}check(refused);}catch(...){clientFailure=std::current_exception();}
 closesocket(listener);probeServer.join();if(clientFailure)std::rethrow_exception(clientFailure);if(failure)std::rethrow_exception(failure);
 std::cout<<"PASS "<<assertions.load()<<" direct configuration, input bounds and native pinned TLS checks. No driver or desktop capture.\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
