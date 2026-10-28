#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace RemoteControl {
constexpr uint16_t DiscoveryPort=48762;
struct DiscoveryAnnouncement {
    std::string name,room,pin;
    uint16_t port=48789;
    bool busy=false,available=false,requireApproval=true;
};
struct DiscoveredHost:DiscoveryAnnouncement {
    std::string address;
    uint64_t seenTick=0;
};
// Only public LAN metadata is advertised. No pairing secret, private code,
// Internet directory or credentials are carried by this protocol.
class DiscoveryResponder {
    struct State;std::unique_ptr<State> state_;
public:
    DiscoveryResponder();~DiscoveryResponder();
    DiscoveryResponder(const DiscoveryResponder&)=delete;DiscoveryResponder& operator=(const DiscoveryResponder&)=delete;
    void Start(DiscoveryAnnouncement announcement);
    void Update(bool busy,bool available)noexcept;
    void Stop()noexcept;
};
class DiscoveryBrowser {
    struct State;std::unique_ptr<State> state_;
public:
    DiscoveryBrowser();~DiscoveryBrowser();
    DiscoveryBrowser(const DiscoveryBrowser&)=delete;DiscoveryBrowser& operator=(const DiscoveryBrowser&)=delete;
    // The callback runs on the discovery worker; post a UI message instead of
    // blocking. Start scans automatically, with a maximum of one scan/second.
    void Start(std::function<void()> changed={});
    void Refresh()noexcept;
    std::vector<DiscoveredHost> Hosts()const;
    void Stop()noexcept;
};
}
