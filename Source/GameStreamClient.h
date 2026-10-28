#pragma once
#include "Client.h"
#include <Limelight.h>
#include <functional>
#include <memory>

namespace RemoteControl {
class GameStreamControl {
    struct State;std::unique_ptr<State> state_;
public:
    GameStreamControl(Pairing,std::function<bool()> cancelled);
    ~GameStreamControl();
    GameStreamControl(const GameStreamControl&)=delete;
    void AuthorizeAndLaunch(uint32_t width,uint32_t height,uint32_t fps);
    SERVER_INFORMATION Server() const;
    STREAM_CONFIGURATION Stream() const;
    void Cancel() noexcept;
    void CloseApp() noexcept;
};
namespace GameStreamFormat {
void InitializeCrypto(); // Once before any upstream PSA call; safe to repeat.
struct HttpMessage {unsigned status=0;std::string body;};
HttpMessage DecodeHttp(std::string_view); // Pure bounded parser qualification.
void RequireXmlSuccess(std::string_view); // Bounded authenticated status/error.
void ValidateVersion(std::string_view,bool allowSunshineMarker=false);
std::string XmlText(std::string_view xml,std::string_view element,size_t maximum=1024);
uint32_t Decimal(std::string_view text,uint32_t maximum);
std::string JsonQuote(std::string_view text);
struct WindowsKey {uint16_t value=0;bool extended=false;};
WindowsKey KeyFromUsage(uint32_t usage) noexcept;
}
}
