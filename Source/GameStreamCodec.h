#pragma once
#include "Protocol.h"
#include <cstddef>
#include <memory>
namespace RemoteControl {
// Configure/Decode/Reset/destruction belong to the same decoding thread.
// Complete bounded H.264 Annex-B access units in; latest owned BGRA frame out.
// There is no application frame queue. GPU output is converted and read back;
// the public Frame remains CPU memory for the existing viewer renderer.
class GameStreamCodec {
 struct State;std::unique_ptr<State> state_;
public:
 explicit GameStreamCodec(bool preferHardware=true);~GameStreamCodec();
 GameStreamCodec(const GameStreamCodec&)=delete;GameStreamCodec& operator=(const GameStreamCodec&)=delete;
 void Configure(uint32_t width,uint32_t height,uint32_t framesPerSecond);
 std::shared_ptr<Frame> Decode(const uint8_t* annexB,size_t length,uint64_t sequence,bool keyFrame);
 bool Hardware()const noexcept;std::string Description()const;void Reset()noexcept;
};
}
