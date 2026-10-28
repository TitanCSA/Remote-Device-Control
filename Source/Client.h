#pragma once
#include "Protocol.h"
#include "Config.h"
#include <functional>
#include <memory>
namespace RemoteControl {
struct ClientInfo {bool connected=false;std::string status="Paste the host connection code to connect.",route;double framesPerSecond=0,inputRttMs=0;uint64_t remaining100ns=0;};
class Client {
 struct State;std::unique_ptr<State> state_;
public:
 explicit Client(std::function<void()> changed);~Client();
 void Start(Pairing pairing,unsigned mode=0); //0 auto,1 LAN,2 relay
 void Stop() noexcept;void Push(Input input);ClientInfo Info()const;std::shared_ptr<const Frame> Latest()const;
};
}
