#pragma once
#include <cstdint>
#include <span>
namespace rdc::control {
// Views begin immediately after the outer two-byte ENet message type.
inline std::uint16_t Little16(std::span<const std::uint8_t> bytes) {
    return static_cast<std::uint16_t>(bytes[0] | (unsigned(bytes[1]) << 8));
}
inline bool Encrypted(std::span<const std::uint8_t> payload) {
    // length(2), sequence(4), tag(16), inner type/length(4), optional data.
    if (payload.size() < 26 || payload.size() > 16386) return false;
    const auto declared = Little16(payload);
    return declared >= 24 && declared <= 16384 && declared == payload.size() - 2;
}
inline bool Plaintext(std::span<const std::uint8_t> payload) {
    if (payload.size() < 4 || payload.size() > 16364) return false;
    return Little16(payload.subspan(2)) == payload.size() - 4;
}
inline bool LegacyInput(std::span<const std::uint8_t> payload) {
    if (payload.size() < 20 || payload.size() > 16388) return false;
    const std::uint32_t declared = (std::uint32_t(payload[0]) << 24) |
        (std::uint32_t(payload[1]) << 16) | (std::uint32_t(payload[2]) << 8) | payload[3];
    return declared >= 16 && declared <= 16384 && declared == payload.size() - 4;
}
}
