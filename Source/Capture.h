#pragma once
#include "Protocol.h"
#include <memory>
#include <string>

namespace RemoteControl {
// Use on its owning interactive thread. Next never grants desktop access:
// the current session must be the active console's DEFAULT desktop.
class Capture {
    struct State;
    std::unique_ptr<State> state_;
public:
    explicit Capture(uint32_t maxWidth=MaxWidth,uint32_t maxHeight=MaxHeight);
    ~Capture();
    Capture(const Capture&)=delete;
    Capture& operator=(const Capture&)=delete;
    // timeoutMs bounds AcquireNextFrame's wait, not graphics initialization.
    // False means no new DXGI frame. Unsupported outputs use an explicit GDI
    // compatibility fallback. Errors must be reported rather than showing an
    // old frame as if the remote desktop were still available.
    bool Next(Frame& frame,uint32_t timeoutMs=100);
    std::string Backend() const;
};
}
