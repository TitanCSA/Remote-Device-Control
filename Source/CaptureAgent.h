#pragma once
#include <cstdint>
#include <memory>
#include <string>
namespace RemoteControl {
// A visible normal-user indicator. Its authenticated local pipe carries only
// readiness, heartbeats and disconnect, never pixels or input commands.
class SessionIndicator {
    struct State;std::unique_ptr<State> state_;
public:
    SessionIndicator();~SessionIndicator();
    SessionIndicator(const SessionIndicator&)=delete;
    SessionIndicator& operator=(const SessionIndicator&)=delete;
    void Start(uint32_t sessionId);void Stop()noexcept;
    bool WaitReady(uint32_t timeoutMs=5000);
    bool Available()const noexcept;std::string Error()const;
};
int RunCaptureAgent(const std::wstring& pipeName);
}
