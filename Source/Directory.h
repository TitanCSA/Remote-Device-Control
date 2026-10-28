#pragma once
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
namespace RemoteControl {
struct PublicHost {
 std::string name,room,pin,relayToken;
 std::wstring relay=L"wss://licences.configcsa.com/remote-device-control/relay";
 bool busy=false,available=true,requireApproval=true;
};
// Public metadata only. ownerToken is private and is sent in an HTTPS header.
std::vector<PublicHost> BrowsePublicHosts(std::function<bool()> cancelled={});
void PublishPublicHost(const PublicHost&,std::string_view ownerToken,std::function<bool()> cancelled={});
void RemovePublicHost(std::string_view room,std::string_view ownerToken,std::function<bool()> cancelled={});
namespace DirectoryFormat {
std::string Encode(const PublicHost&);
std::vector<PublicHost> Decode(std::string_view);
}
class DirectoryBrowser {
 struct State;std::unique_ptr<State> state_;
public:
 DirectoryBrowser();~DirectoryBrowser();
 DirectoryBrowser(const DirectoryBrowser&)=delete;DirectoryBrowser& operator=(const DirectoryBrowser&)=delete;
 // changed runs on the worker. Post a UI message; do not Stop/destroy this
 // browser synchronously from its callback. Stop cancels bounded HTTP waits.
 void Start(std::function<void()> changed={});void Stop()noexcept;
 std::vector<PublicHost> Hosts()const;std::string Error()const;
};
}
