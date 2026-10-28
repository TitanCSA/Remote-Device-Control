#pragma once
#include "Protocol.h"
#include "Config.h"
#include <functional>
#include <memory>
namespace RemoteControl {
struct ClientInfo {bool connected=false,connecting=false;std::string status="Enter a host address or connection code to connect.",route;double framesPerSecond=0,inputRttMs=0;uint64_t remaining100ns=0;};
struct GameStreamHostProbe {std::string name,pin;};
// Credential-free TLS probe. The UI establishes trust before Start sends a code.
GameStreamHostProbe ProbePublicHost(const std::string& host,uint16_t basePort,std::function<bool()> cancelled={});
class Client {
 struct State;std::unique_ptr<State> state_;
public:
 explicit Client(std::function<void()> changed);~Client();
 void Start(Pairing pairing,unsigned mode=0,unsigned framesPerSecond=60); // Direct Sunshine; no relay.
 void Stop() noexcept;void Push(Input input);ClientInfo Info()const;std::shared_ptr<const Frame> Latest()const;
};
}
