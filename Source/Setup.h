#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <optional>

namespace RemoteControl::Setup {
using Progress=std::function<void(unsigned,const std::wstring&)>;
struct Snapshot {
    bool installed=false,running=false,driverOwned=false,driverPresent=false;
    bool restartRequired=false,internet=true,removableDriver=false,removalPending=false;
    bool noCode=false,requireApproval=true;
    std::wstring status,detail,connectionCode;
};
struct Result {
    uint32_t code=0;bool restartRequired=false;
    std::wstring message;
    explicit operator bool() const noexcept {return code==0||code==3010;}
};
bool OwnedLeaf(const std::wstring&) noexcept;
std::wstring Quote(const std::wstring&);
bool ServiceImageMatches(const std::wstring& command,const std::wstring& executable) noexcept;
Snapshot Inspect(bool includeConnectionCode=true);
// Unspecified access options preserve an existing host's settings on repair.
Result Install(bool internet,const Progress& progress={},std::optional<bool> noCode={},std::optional<bool> requireApproval={});
Result Uninstall(bool removeOwnedDriver,const Progress& progress={});
void SelfTest(); // Resource and parser checks only; never opens/installs a driver.
void RequestRestart(); // Caller must ask the user first; never called by installation.
}
