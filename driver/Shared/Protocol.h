#ifndef VDEVICE_PROTOCOL_H
#define VDEVICE_PROTOCOL_H
#ifdef _KERNEL_MODE
typedef UCHAR uint8_t;
typedef ULONG uint32_t;
typedef ULONGLONG uint64_t;
#else
#include <stdint.h>
#endif

#define VD_VERSION 1u
#define VD_MAX_DEVICES 16u
#define VD_MAX_ENDPOINTS 30u
#define VD_MAX_DESCRIPTORS 64u
#define VD_MAX_RULES 32u
#define VD_MAX_CREATE 65536u
#define VD_MAX_TRANSFER 4096u
#define VD_MAX_DEPTH 256u
#define VD_DEFAULT_DEPTH 32u
#define VD_MAX_OUTPUTS 64u
#define VD_PATH L"\\\\.\\Vdevice"
#define VD_HARDWARE_ID L"ROOT\\Vdevice"
#define VD_SERVICE L"Vdevice"

/* Buffered, access-controlled IOCTLs. No pointers cross the user/kernel boundary. */
#define VD_IOCTL(n) ((0x8000u << 16) | (3u << 14) | ((n) << 2))
#define VD_QUERY VD_IOCTL(0x800u)
#define VD_CREATE_DEVICE VD_IOCTL(0x801u)
#define VD_DELETE_DEVICE VD_IOCTL(0x802u)
#define VD_SEND VD_IOCTL(0x803u)
#define VD_RECEIVE VD_IOCTL(0x804u)
#define VD_RESPOND VD_IOCTL(0x805u)
#define VD_LIST VD_IOCTL(0x806u)
/* Installer-only: stop all virtual devices and wake API readers before PnP removal. */
#define VD_QUIESCE VD_IOCTL(0x807u)

enum VD_SPEED { VdLowSpeed=1, VdFullSpeed=2, VdHighSpeed=3 };
enum VD_DESCRIPTOR_KIND { VdStandardDescriptor=1, VdReportDescriptor=2 };
enum VD_RULE_ACTION { VdReply=1, VdAccept=2, VdStall=3 };
enum VD_CREATE_FLAGS { VdDelegateControls=1 };
enum VD_OUTPUT_KIND { VdOutputData=1, VdControlRequest=2, VdDeviceState=3 };
enum VD_DEVICE_FLAGS { VdPlugged=1, VdConfigured=2, VdPowered=4 };
enum VD_CONTROLLER_FLAGS { VdControllerQuiescing=1, VdControllerRemoving=2 };

#pragma pack(push, 1)
typedef struct VD_DESCRIPTOR {
    uint32_t Kind, Index, Language, InterfaceNumber, Offset, Length;
} VD_DESCRIPTOR;
typedef struct VD_CONTROL_RULE {
    uint8_t Setup[8], Mask[8];
    uint32_t Action, DataOffset, DataLength;
} VD_CONTROL_RULE;
typedef struct VD_CREATE {
    uint32_t Version, TotalSize, Speed, Flags;
    uint32_t DescriptorCount, DescriptorsOffset, RuleCount, RulesOffset;
    uint32_t InputDepth;
} VD_CREATE;
typedef struct VD_ID { uint64_t Id; } VD_ID;
typedef struct VD_INFO {
    uint32_t Version, MaxDevices, MaxTransfer, MaxCreate;
    /* Reserved is the compiled trial duration in seconds; Reserved2 is VD_CONTROLLER_FLAGS. */
    uint32_t LowSpeed, FullSpeed, HighSpeed, Reserved;
    uint64_t TrialStarted100ns, TrialRemaining100ns;
    uint32_t TrialExpired, Reserved2;
} VD_INFO;
typedef struct VD_DEVICE_INFO {
    uint64_t Id;
    uint32_t Flags, EndpointCount, QueuedInputs, QueuedOutputs;
    uint64_t InputsAccepted, InputsCompleted, OutputsReceived, OutputsDropped;
} VD_DEVICE_INFO;
typedef struct VD_DEVICE_LIST {
    uint32_t Count, Reserved;
    VD_DEVICE_INFO Devices[VD_MAX_DEVICES];
} VD_DEVICE_LIST;
/* SEND: header then Length bytes. Endpoint is a USB IN address, e.g. 0x81. */
typedef struct VD_TRANSFER {
    uint64_t Id;
    uint32_t Endpoint, Length;
} VD_TRANSFER;
/* RECEIVE returns one whole packet; RequestId != 0 requires RESPOND within 5s. */
typedef struct VD_OUTPUT {
    uint64_t Id, RequestId;
    uint32_t Kind, Endpoint, Length, Reserved;
    uint8_t Setup[8], Data[VD_MAX_TRANSFER];
} VD_OUTPUT;
typedef struct VD_RESPONSE {
    uint64_t Id, RequestId;
    uint32_t Stall, Length;
} VD_RESPONSE;
#pragma pack(pop)

#endif
