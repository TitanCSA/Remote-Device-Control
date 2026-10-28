#pragma once
#include "Protocol.h"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace RemoteControl {
// The relay forwards at 750,000 ciphertext bytes/s. Leave headroom for TLS
// records and the independent handshake/reverse-direction messages. Never
// retain transmission credit: after a pause only one current frame is sent.
class RelayVideoPacing {
    static constexpr uint64_t BytesPerSecond=600000;
    uint64_t next_=0;
public:
    uint64_t WaitMilliseconds(uint64_t now)const noexcept{return now<next_?next_-now:0;}
    void Sent(size_t payloadBytes,uint64_t now){
        if(!payloadBytes||payloadBytes>MaxFrameBytes+64)throw std::runtime_error("Relay video packet exceeds its pacing bounds.");
        const uint64_t bytes=static_cast<uint64_t>(payloadBytes);
        const uint64_t wireBytes=bytes+128+64*((bytes+16383)/16384);
        const uint64_t duration=(wireBytes*1000+BytesPerSecond-1)/BytesPerSecond;
        next_=now>(std::numeric_limits<uint64_t>::max)()-duration?(std::numeric_limits<uint64_t>::max)():now+duration;
    }
};
}
