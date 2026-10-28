#include "Wire.h"
#include "Config.h"
#include "VideoPacing.h"
#include <thread>
#include <iostream>
#include <exception>
#include <array>
#include <atomic>
#include <chrono>
using namespace RemoteControl;
int main(){try{
 std::atomic<size_t> assertions{0};auto check=[&](bool value){++assertions;if(!value)throw std::runtime_error("Core assertion failed.");};
 RelayVideoPacing pacing;check(pacing.WaitMilliseconds(0)==0);pacing.Sent(600000,100);check(pacing.WaitMilliseconds(100)>1000&&pacing.WaitMilliseconds(100)<1100);check(pacing.WaitMilliseconds(5000)==0);
 pacing.Sent(30000,5000);check(pacing.WaitMilliseconds(5000)>=50&&pacing.WaitMilliseconds(5000)<60);check(pacing.WaitMilliseconds(6000)==0);
 // A long idle interval cannot accumulate a burst of old-frame credit.
 pacing.Sent(30000,6000);check(pacing.WaitMilliseconds(6000)>=50);pacing.Sent(MaxFrameBytes+64,10000);check(pacing.WaitMilliseconds(10000)>6900&&pacing.WaitMilliseconds(10000)<7100);
 for(size_t invalid:{size_t(0),size_t(MaxFrameBytes+65)}){bool refused=false;try{pacing.Sent(invalid,0);}catch(...){refused=true;}check(refused);}
 const auto end=(std::numeric_limits<uint64_t>::max)();pacing.Sent(30000,end-10);check(pacing.WaitMilliseconds(end-10)==10&&pacing.WaitMilliseconds(end)==0);
 // Simulate two minutes of full-motion 60-fps production. Transmission always
 // takes the newest frame, and the long-run relay budget stays below 6 Mbit/s.
 RelayVideoPacing motion;uint64_t sentBytes=0,sentFrames=0,lastProducer=0;for(uint64_t now=0;now<120000;++now){if(!motion.WaitMilliseconds(now)){const auto newest=now/16+1;check(newest>lastProducer);lastProducer=newest;motion.Sent(40000,now);sentBytes+=40000;++sentFrames;}}
 check(sentBytes<=72000000&&sentFrames>1000);
 Config c;c.host=L"192.0.2.1";c.secret=std::string(32,'a');c.room=std::string(32,'b');c.relayToken=std::string(64,'c');std::string pin(64,'d');auto parsed=ParsePairing(PairingCode(c,pin));check(parsed.host=="192.0.2.1"&&parsed.pin==pin&&parsed.secret==c.secret&&parsed.relayToken==c.relayToken);
 for(auto text:{L"",L"invalid",L"RDC1;x;0;x;x;x;x;x",L"RDC1;example/../;48761;pin;secret;room;token;wss://host"}){bool refused=false;try{ParsePairing(text);}catch(...){refused=true;}check(refused);}
 for(int i=-100;i<70000;++i){Input value;value.x=i;check(ValidInput(value)==(i>=0&&i<=65535));}
 TitanTransport::Runtime runtime;TitanTransport::Identity original;auto exported=original.Export();TitanTransport::Identity persisted(exported);check(original.Fingerprint()==persisted.Fingerprint());
 uint16_t port=0;SOCKET listener=TitanTransport::Listen("127.0.0.1",0,&port);std::exception_ptr failure,clientFailure;std::atomic<bool> serverObservedClose{false};
 std::thread server([&]{try{SOCKET socket=accept(listener,nullptr,nullptr);Link link(socket);link.channel.HandshakeServer(persisted);auto packet=link.Receive();check(packet.type==Message::Auth&&Text(packet)==c.secret);link.Send(Message::Grant,c.secret);auto payload=link.Receive();check(payload.data.size()==70001);link.Send(Message::Inputs,payload.data,payload.sequence);
  // Approval/status messages legitimately arrive after five seconds. This
  // real socket/TLS wait regresses the former hidden SO_RCVTIMEO=5000 cap.
  std::this_thread::sleep_for(std::chrono::milliseconds(5500));link.Send(Message::Pending,std::string("Delayed local approval fixture"));
  const auto closeWait=GetTickCount64();try{(void)link.Receive(15000);}catch(const std::exception&){serverObservedClose=GetTickCount64()-closeWait<2000;}
 }catch(...){failure=std::current_exception();}});
 try{Link viewer(TitanTransport::Connect("127.0.0.1",port));viewer.channel.HandshakeClient(original.Fingerprint());viewer.Send(Message::Auth,c.secret);auto reply=viewer.Receive();check(reply.type==Message::Grant&&Text(reply)==c.secret);std::vector<uint8_t> bytes(70001);for(size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<uint8_t>(i);viewer.Send(Message::Inputs,bytes,9);auto echo=viewer.Receive();check(echo.sequence==9&&echo.data==bytes);
  const auto began=GetTickCount64();auto delayed=viewer.Receive(7000);check(delayed.type==Message::Pending&&Text(delayed)=="Delayed local approval fixture");check(GetTickCount64()-began>=5000);
  std::atomic<bool> started{false};std::exception_ptr cancelled;
  std::thread waiting([&]{started=true;try{(void)viewer.Receive(30000);}catch(...){cancelled=std::current_exception();}});
  while(!started)std::this_thread::yield();std::this_thread::sleep_for(std::chrono::milliseconds(100));const auto closing=GetTickCount64();viewer.Close();waiting.join();check(cancelled!=nullptr);check(GetTickCount64()-closing<1500);
 }catch(...){clientFailure=std::current_exception();}
 closesocket(listener);server.join();if(clientFailure)std::rethrow_exception(clientFailure);if(failure)std::rethrow_exception(failure);check(serverObservedClose);
 std::cout<<"PASS "<<assertions.load()<<" core assertions. No driver, capture or real host connection.\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
