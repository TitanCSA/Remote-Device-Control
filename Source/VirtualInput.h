#pragma once
#include "Protocol.h"
#include "../Vdevice/Vdevice.h"
#include <array>
#include <memory>

namespace RemoteControl {
// Windows Set-1 make scan code, with E0 expressed separately. Unsupported
// consumer/vendor keys return zero. Handle VK_PAUSE explicitly in the viewer.
uint32_t UsageFromScan(uint32_t scan,bool extended) noexcept;
// Startup-only, nonblocking check: require the started class child and a Raw
// Input interface whose devnode ancestry reaches this exact owned USB instance.
// Pass the complete per-session USB instance, not merely a VID/PID or serial.
bool RawInputDeviceReady(const std::wstring& ownedUsbInstance,bool keyboard,std::string& reason);

namespace InputProtocol {
struct HidState {
    std::array<uint8_t,29> keys{}; // USB page7 usages0..231, including modifiers.
    uint8_t buttons=0;
    uint16_t x=32768,y=32768; // Wire coordinates, normalized over the primary screen.
    int8_t wheel=0,pan=0;
};
bool Valid(const Input&) noexcept;
void Apply(HidState&,const Input&); // Pure state transformation; throws invalid_argument.
void Neutral(HidState&) noexcept; // Preserve absolute position; release keys/buttons.
Vdevice::Device_Config KeyboardConfig();
Vdevice::Device_Config MouseConfig();
std::vector<uint8_t> KeyboardReport(const HidState&);
std::vector<uint8_t> MouseReport(const HidState&);
}

// Start/Stop lifecycle calls must be serialized by the owner. Apply/Release may
// run alongside the finite-timeout status worker. No network access or Windows
// SendInput/SetCursorPos fallback exists. Start only AFTER peer authentication.
class VirtualInput {
    struct Impl;std::unique_ptr<Impl> impl_;
public:
    VirtualInput();~VirtualInput();
    VirtualInput(const VirtualInput&)=delete;
    VirtualInput& operator=(const VirtualInput&)=delete;
    void Start(); // Throws detailed English diagnostics, including demo expiry.
    void Apply(const Input&);
    void Release() noexcept;
    void Stop() noexcept;
    bool Running() const noexcept;
    uint64_t Remaining100ns() const noexcept;
    std::string Error() const;
};
}
