#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
namespace RemoteControl {int RunService();int RunHostConsole();bool ConsoleAvailable(uint32_t sessionId) noexcept;}
