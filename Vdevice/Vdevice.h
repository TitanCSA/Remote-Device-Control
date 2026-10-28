#ifndef VDEVICE_SDK_H
#define VDEVICE_SDK_H
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Copy this header and Vdevice.cpp into a Windows C++17 project. No other
// project files, external libraries, or context management are required.
namespace Vdevice {
constexpr std::uint32_t Infinite = 0xffffffffu;
constexpr std::uint32_t MaxTransfer = 4096;
enum class Speed : std::uint32_t { Low = 1, Full = 2, High = 3 };
enum class Descriptor_Kind : std::uint32_t { Standard = 1, Report = 2 };
enum class Rule_Action : std::uint32_t { Reply = 1, Accept = 2, Stall = 3 };
struct Result {
    std::uint32_t error = 0;
    std::string message;
    explicit operator bool() const noexcept { return error == 0; }
};
struct Descriptor {
    Descriptor_Kind kind = Descriptor_Kind::Standard;
    std::uint32_t index = 0, language = 0, interface_number = 0;
    std::vector<std::uint8_t> data;
};
struct Control_Rule {
    std::array<std::uint8_t, 8> setup{}, mask{};
    Rule_Action action = Rule_Action::Reply;
    std::vector<std::uint8_t> data;
};
// Exact USB/HID descriptor bytes are the only source of device identity,
// interfaces, endpoints, report formats, strings, power and polling intervals.
// Edit this configuration before creation; enumeration fixes it until deletion.
struct Device_Config {
    Speed speed = Speed::Full;
    std::uint32_t input_depth = 32;
    bool delegate_controls = false;
    std::vector<Descriptor> descriptors;
    std::vector<Control_Rule> rules;
};
struct Device_Details {
    std::string token;
    std::uint64_t id = 0;
    bool plugged = false, configured = false, powered = false;
    std::uint32_t endpoint_count = 0, queued_inputs = 0, queued_outputs = 0;
    std::uint64_t inputs_accepted = 0, inputs_completed = 0;
    std::uint64_t outputs_received = 0, outputs_dropped = 0;
    std::uint32_t error = 0;
};
struct Info : Result {
    std::uint32_t version = 0, max_devices = 0, max_transfer = 0;
    bool low_speed = false, full_speed = false, high_speed = false;
    bool trial_started = false, trial_expired = false;
    bool quiescing = false, removing = false;
    std::uint64_t trial_remaining_100ns = 0;
    // Full details for this library session's devices. This is an observational
    // snapshot; Windows may continue enumeration after it is returned.
    std::vector<Device_Details> devices;
};
namespace Detail { struct Device_State; }
class Device {
public:
    Device() noexcept = default;
    ~Device();
    Device(Device&&) noexcept;
    Device& operator=(Device&&) noexcept;
    Device(const Device&) = delete;
    Device& operator=(const Device&) = delete;
    std::string token;
    std::uint32_t error = 0;
    std::string message;
    explicit operator bool() const noexcept;
    std::uint64_t Id() const noexcept;
private:
    std::shared_ptr<Detail::Device_State> state_;
    friend Device Create_Device(const Device_Config&);
    friend Result Delete_Device(Device&);
    friend Result Send_Input(const Device&, std::uint8_t, const std::vector<std::uint8_t>&);
};
enum class Output_Kind : std::uint32_t { Data = 1, Control = 2, DeviceState = 3 };
struct Output : Result {
    std::string device_token;
    std::uint64_t device_id = 0, request_id = 0;
    Output_Kind kind = Output_Kind::Data;
    std::uint8_t endpoint = 0;
    std::array<std::uint8_t, 8> setup{};
    std::vector<std::uint8_t> data;
    bool timed_out = false;
};

// Seven operations, identical for every device protocol. Validation is offline;
// creation validates again before opening the driver. Sizes are inferred.
Result Validate_Device(const Device_Config&);
Info Get_Info();
Device Create_Device(const Device_Config&);
Result Delete_Device(Device&);
Result Send_Input(const Device&, std::uint8_t endpoint, const std::vector<std::uint8_t>& data);
Output Get_Output(std::uint32_t timeout = Infinite);
Result Respond_Output(const Output&, const std::vector<std::uint8_t>& data = {}, bool stall = false);
}
#endif
