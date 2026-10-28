#pragma once
#include <string>
#include <string_view>
namespace rdc {
bool pairing_allowed(std::string_view secret)noexcept;
bool authorize_launch(std::string_view clientIdentity,std::string& error)noexcept;
bool owns_session(std::string_view clientIdentity)noexcept;
void cancel_launch()noexcept;
void stream_started()noexcept;
void stream_ended()noexcept;
bool busy()noexcept;
}
