#pragma once
#include "Protocol.h"
#include <memory>

namespace RemoteControl {
// Bounded, independent JPEG images using Windows Imaging Component. There is
// no video reordering or inter-frame state. Sequence/timing are wire metadata,
// not JPEG metadata; the receiver restores them from its authenticated packet.
// Use one instance per worker thread. A factory is reused across frames.
class FrameCodec {
    struct State;
    std::unique_ptr<State> state_;
public:
    FrameCodec();
    ~FrameCodec();
    FrameCodec(const FrameCodec&)=delete;
    FrameCodec& operator=(const FrameCodec&)=delete;
    std::vector<uint8_t> Encode(const Frame& frame,unsigned quality=80);
    Frame Decode(const std::vector<uint8_t>& jpeg);
};
}
