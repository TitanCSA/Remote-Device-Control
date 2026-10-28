#pragma once
#include "Protocol.h"
#include <memory>
#include <string>

namespace RemoteControl {
// A service-owned, one-way JPEG/status bridge to a visible capture helper in
// the active console user's DEFAULT desktop. It never accepts input commands.
class SessionCapture {
    struct State;
    std::unique_ptr<State> state_;
public:
    SessionCapture();
    ~SessionCapture();
    SessionCapture(const SessionCapture&)=delete;
    SessionCapture& operator=(const SessionCapture&)=delete;
    void Start(uint32_t sessionId);
    void Stop() noexcept;
    bool Latest(EncodedFrame& frame,uint64_t afterSequence,uint32_t timeoutMs=100);
    bool Available() const noexcept;
    std::string Error() const;
};
// Invoked only by the protected host EXE's --agent entry point. The pipe must
// belong to that same executable in Session 0 before any capture is attempted.
int RunCaptureAgent(const std::wstring& pipeName);
}
