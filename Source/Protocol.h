#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace RemoteControl {
constexpr uint32_t ProtocolVersion=1;
constexpr uint32_t MaxFrameBytes=4*1024*1024;
constexpr uint32_t MaxWidth=1920,MaxHeight=1080;
enum class InputKind:uint32_t { Pointer=1,Button=2,Key=3,Wheel=4,ReleaseAll=5 };
// Pointer x/y are absolute 0..65535; key code is a USB HID usage; button code1..5.
struct Input {InputKind kind=InputKind::Pointer;int32_t x=0,y=0;uint32_t code=0,down=0;};
struct Frame {uint32_t width=0,height=0;uint64_t sequence=0,capturedQpc=0;std::vector<uint8_t> bgra;};
struct EncodedFrame {uint32_t width=0,height=0;uint64_t sequence=0,capturedQpc=0;std::vector<uint8_t> jpeg;};
bool ValidInput(const Input&) noexcept;
std::string WindowsError(const char* operation,uint32_t code);
uint64_t NowQpc() noexcept;
}
