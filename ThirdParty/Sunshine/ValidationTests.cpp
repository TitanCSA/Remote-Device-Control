// Offline protocol-boundary tests; never opens a driver or captures a desktop.
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <random>
#include <Input.h>
#include "RdcKeyMap.h"
#include "ControlValidation.h"
namespace util::endian {
constexpr std::uint32_t little(std::uint32_t value) { return value; }
constexpr std::uint32_t big(std::uint32_t value) {
    return ((value & 255u) << 24) | ((value & 65280u) << 8) |
           ((value >> 8) & 65280u) | (value >> 24);
}
}
#include "InputValidation.inc"
namespace {
unsigned checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("Input validation regression"); }
std::vector<std::uint8_t> Packet(std::uint32_t magic, std::size_t bytes) {
    std::vector<std::uint8_t> result(bytes);
    const NV_INPUT_HEADER header{util::endian::big(static_cast<std::uint32_t>(bytes - 4)), magic};
    std::memcpy(result.data(), &header, sizeof(header));
    return result;
}
template<class T> void Fixed(std::uint32_t magic) {
    auto packet = Packet(magic, sizeof(T));
    Check(validate_input_packet(packet));
    for (std::size_t length = 0; length < packet.size(); ++length)
        Check(!validate_input_packet(std::span(packet).first(length)));
    packet.push_back(0); Check(!validate_input_packet(packet));
    packet = Packet(magic, sizeof(T) + 1); Check(!validate_input_packet(packet));
    packet = Packet(magic, sizeof(T)); packet[0] = 255; Check(!validate_input_packet(packet));
}
}
int main() {
    try {
        Fixed<NV_REL_MOUSE_MOVE_PACKET>(MOUSE_MOVE_REL_MAGIC_GEN5);
        Fixed<NV_ABS_MOUSE_MOVE_PACKET>(MOUSE_MOVE_ABS_MAGIC);
        Fixed<NV_MOUSE_BUTTON_PACKET>(MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5);
        Fixed<NV_MOUSE_BUTTON_PACKET>(MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5);
        Fixed<NV_SCROLL_PACKET>(SCROLL_MAGIC_GEN5);
        Fixed<SS_HSCROLL_PACKET>(SS_HSCROLL_MAGIC);
        Fixed<NV_KEYBOARD_PACKET>(KEY_DOWN_EVENT_MAGIC);
        Fixed<NV_KEYBOARD_PACKET>(KEY_UP_EVENT_MAGIC);
        Fixed<NV_MULTI_CONTROLLER_PACKET>(MULTI_CONTROLLER_MAGIC_GEN5);
        Fixed<SS_TOUCH_PACKET>(SS_TOUCH_MAGIC);
        Fixed<SS_PEN_PACKET>(SS_PEN_MAGIC);
        Fixed<SS_CONTROLLER_ARRIVAL_PACKET>(SS_CONTROLLER_ARRIVAL_MAGIC);
        Fixed<SS_CONTROLLER_TOUCH_PACKET>(SS_CONTROLLER_TOUCH_MAGIC);
        Fixed<SS_CONTROLLER_MOTION_PACKET>(SS_CONTROLLER_MOTION_MAGIC);
        Fixed<SS_CONTROLLER_BATTERY_PACKET>(SS_CONTROLLER_BATTERY_MAGIC);
        for (unsigned count = 0; count <= UTF8_TEXT_EVENT_MAX_COUNT + 1; ++count) {
            auto packet = Packet(UTF8_TEXT_EVENT_MAGIC, sizeof(NV_INPUT_HEADER) + count);
            Check(validate_input_packet(packet) == (count <= UTF8_TEXT_EVENT_MAX_COUNT));
            packet.push_back(0); Check(!validate_input_packet(packet));
        }
        Check(!validate_input_packet(Packet(0xffffffffu, sizeof(NV_INPUT_HEADER))));
        const auto enter = rdc::MapKey(VK_RETURN, 0);
        const auto keypadEnter = rdc::MapKey(VK_RETURN, rdc::ExtendedKeyFlag);
        Check(enter.scan == 0x1c && !enter.extended && !enter.usage);
        Check(keypadEnter.scan == 0x1c && keypadEnter.extended && !keypadEnter.usage);
        Check(rdc::MapKey(VK_SNAPSHOT, 0).usage == 0x46);
        Check(rdc::MapKey(VK_PAUSE, 0).usage == 0x48);
        Check(rdc::MapKey(VK_RCONTROL, 0).extended);
        Check(!rdc::MapKey(VK_LCONTROL, 0).extended);
        std::vector<std::uint8_t> encrypted(26);encrypted[0]=24;
        Check(rdc::control::Encrypted(encrypted));
        for (std::size_t length=0;length<encrypted.size();++length)
            Check(!rdc::control::Encrypted(std::span(encrypted).first(length)));
        encrypted[0]=255;Check(!rdc::control::Encrypted(encrypted));
        encrypted[0]=24;encrypted.push_back(0);Check(!rdc::control::Encrypted(encrypted));
        std::vector<std::uint8_t> plain(4);Check(rdc::control::Plaintext(plain));
        for (std::size_t length=0;length<4;++length)Check(!rdc::control::Plaintext(std::span(plain).first(length)));
        plain[2]=1;Check(!rdc::control::Plaintext(plain));plain.push_back(0);Check(rdc::control::Plaintext(plain));
        std::vector<std::uint8_t> legacy(20);legacy[3]=16;Check(rdc::control::LegacyInput(legacy));
        for (std::size_t length=0;length<20;++length)Check(!rdc::control::LegacyInput(std::span(legacy).first(length)));
        legacy[0]=255;Check(!rdc::control::LegacyInput(legacy));
        legacy[0]=0;legacy.push_back(0);Check(!rdc::control::LegacyInput(legacy));
        std::mt19937 random(0x524443u);
        for (unsigned index = 0; index < 200000; ++index) {
            std::vector<std::uint8_t> bytes(random() % 128);
            for (auto& byte : bytes) byte = static_cast<std::uint8_t>(random());
            Check(!validate_input_packet(bytes));
        }
        std::cout << checks << " bounded input protocol checks passed.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
