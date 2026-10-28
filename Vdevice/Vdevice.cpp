#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Vdevice.h"
#include <atomic>
#include <cstring>
#include <mutex>
#include <sstream>
#include <utility>

// Private wire ABI. Kept here so the distributable SDK consists of two files.
#ifndef VDEVICE_PROTOCOL_H
#define VDEVICE_PROTOCOL_H
#define VD_VERSION 1u
#define VD_MAX_DEVICES 16u
#define VD_MAX_ENDPOINTS 30u
#define VD_MAX_DESCRIPTORS 64u
#define VD_MAX_RULES 32u
#define VD_MAX_CREATE 65536u
#define VD_MAX_TRANSFER 4096u
#define VD_MAX_DEPTH 256u
#define VD_DEFAULT_DEPTH 32u
#define VD_PATH L"\\\\.\\Vdevice"
#define VD_IOCTL(n) ((0x8000u << 16) | (3u << 14) | ((n) << 2))
#define VD_QUERY VD_IOCTL(0x800u)
#define VD_CREATE_DEVICE VD_IOCTL(0x801u)
#define VD_DELETE_DEVICE VD_IOCTL(0x802u)
#define VD_SEND VD_IOCTL(0x803u)
#define VD_RECEIVE VD_IOCTL(0x804u)
#define VD_RESPOND VD_IOCTL(0x805u)
#define VD_LIST VD_IOCTL(0x806u)
enum VD_SPEED { VdLowSpeed=1, VdFullSpeed=2, VdHighSpeed=3 };
enum VD_DESCRIPTOR_KIND { VdStandardDescriptor=1, VdReportDescriptor=2 };
enum VD_RULE_ACTION { VdReply=1, VdAccept=2, VdStall=3 };
enum VD_CREATE_FLAGS { VdDelegateControls=1 };
#pragma pack(push, 1)
struct VD_DESCRIPTOR { std::uint32_t Kind, Index, Language, InterfaceNumber, Offset, Length; };
struct VD_CONTROL_RULE { std::uint8_t Setup[8], Mask[8]; std::uint32_t Action, DataOffset, DataLength; };
struct VD_CREATE { std::uint32_t Version, TotalSize, Speed, Flags, DescriptorCount, DescriptorsOffset, RuleCount, RulesOffset, InputDepth; };
struct VD_ID { std::uint64_t Id; };
struct VD_INFO {
    std::uint32_t Version, MaxDevices, MaxTransfer, MaxCreate, LowSpeed, FullSpeed, HighSpeed, Reserved;
    std::uint64_t TrialStarted100ns, TrialRemaining100ns;
    std::uint32_t TrialExpired, Reserved2;
};
struct VD_DEVICE_INFO {
    std::uint64_t Id;
    std::uint32_t Flags, EndpointCount, QueuedInputs, QueuedOutputs;
    std::uint64_t InputsAccepted, InputsCompleted, OutputsReceived, OutputsDropped;
};
struct VD_DEVICE_LIST { std::uint32_t Count, Reserved; VD_DEVICE_INFO Devices[VD_MAX_DEVICES]; };
struct VD_TRANSFER { std::uint64_t Id; std::uint32_t Endpoint, Length; };
struct VD_OUTPUT { std::uint64_t Id, RequestId; std::uint32_t Kind, Endpoint, Length, Reserved; std::uint8_t Setup[8], Data[VD_MAX_TRANSFER]; };
struct VD_RESPONSE { std::uint64_t Id, RequestId; std::uint32_t Stall, Length; };
#pragma pack(pop)
#endif

// Amalgamated from Shared/Validate.h: keep this validator identical to the kernel.

/* Pointer-free, allocation-free USB/HID validation shared with the test suite.
   Supported topology: USB 1.1/2.x, one configuration, alternate setting zero,
   interrupt and bulk endpoints. Unsupported topologies are rejected. */
#define VD_MAX_REPORTS 256u
#define VD_NO_INDEX 0xffffffffu
typedef struct VD_ENDPOINT_LAYOUT {
    uint32_t Address, InterfaceNumber, Type, MaxPacket;
} VD_ENDPOINT_LAYOUT;
typedef struct VD_REPORT_LAYOUT {
    uint32_t InterfaceNumber, Type, Id, Bits, Length;
} VD_REPORT_LAYOUT;
typedef struct VD_LAYOUT {
    uint32_t DeviceDescriptor, ConfigurationDescriptor, EndpointCount, ReportCount;
    uint8_t Interfaces[256], UsesReportIds[256], BootProtocol[256];
    uint32_t ReportDescriptor[256], HidDescriptorOffset[256], HidDescriptorLength[256];
    VD_ENDPOINT_LAYOUT Endpoints[VD_MAX_ENDPOINTS];
    VD_REPORT_LAYOUT Reports[VD_MAX_REPORTS];
} VD_LAYOUT;
enum VD_VALIDATION { VdValid=0, VdInvalid=1, VdUnsupported=2, VdLimit=3 };
static uint32_t VdRead16(const uint8_t* p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8); }
static int VdRange(uint32_t total,uint32_t offset,uint32_t length) {
    return offset<=total && length<=total-offset;
}
static int VdParseReport(const uint8_t* p,uint32_t length,uint32_t iface,VD_LAYOUT* result) {
    struct VD_GLOBAL { uint32_t Size,Count,Id; } current={0,0,0},stack[16];
    uint32_t pos=0,depth=0,collections=0,seenCollection=0,base=result->ReportCount;
    while(pos<length) {
        uint32_t prefix=p[pos++],size,type,tag,value=0,i;
        if(prefix==254) {
            if(length-pos<2) return VdInvalid;
            size=p[pos]; pos+=2;
            if(size>length-pos) return VdInvalid;
            pos+=size; continue;
        }
        size=prefix&3u; if(size==3)size=4;
        type=(prefix>>2)&3u; tag=prefix>>4;
        if(size>length-pos) return VdInvalid;
        for(i=0;i<size;++i)value|=(uint32_t)p[pos+i]<<(8u*i);
        pos+=size;
        if(type==1) {
            if(tag==7)current.Size=value;
            else if(tag==9)current.Count=value;
            else if(tag==8) {
                if(!value || value>255)return VdInvalid;
                current.Id=value;result->UsesReportIds[iface]=1;
            } else if(tag==10) {
                if(depth==16)return VdLimit;
                stack[depth++]=current;
            } else if(tag==11) {
                if(!depth)return VdInvalid;
                current=stack[--depth];
            }
        } else if(type==0) {
            uint32_t reportType=tag==8?1u:tag==9?2u:tag==11?3u:0u;
            if(tag==10) { if(++collections>64)return VdLimit;seenCollection=1; }
            else if(tag==12) { if(!collections)return VdInvalid;--collections; }
            if(reportType) {
                VD_REPORT_LAYOUT* report=0;
                uint32_t bits;
                if(!collections || !current.Size || !current.Count || current.Size>VD_MAX_TRANSFER*8u ||
                   current.Count>(VD_MAX_TRANSFER*8u)/current.Size)return VdInvalid;
                bits=current.Size*current.Count;
                for(i=base;i<result->ReportCount;++i) {
                    if(result->Reports[i].Type==reportType && result->Reports[i].Id==current.Id) {
                        report=&result->Reports[i];break;
                    }
                }
                if(!report) {
                    if(result->ReportCount==VD_MAX_REPORTS)return VdLimit;
                    report=&result->Reports[result->ReportCount++];
                    report->InterfaceNumber=iface;report->Type=reportType;
                    report->Id=current.Id;report->Bits=0;
                }
                if(bits>VD_MAX_TRANSFER*8u-report->Bits)return VdLimit;
                report->Bits+=bits;
            }
        }
    }
    if(depth || collections || !seenCollection || base==result->ReportCount)return VdInvalid;
    for(;base<result->ReportCount;++base) {
        VD_REPORT_LAYOUT* report=&result->Reports[base];
        if(result->UsesReportIds[iface] && !report->Id)return VdInvalid;
        report->Length=(report->Bits+7u)/8u+(report->Id?1u:0u);
        if(report->Length>VD_MAX_TRANSFER)return VdLimit;
    }
    return VdValid;
}
static int VdValidateCreate(const void* memory,uint32_t size,VD_LAYOUT* result) {
    const uint8_t* data=(const uint8_t*)memory;
    const VD_CREATE* create=(const VD_CREATE*)memory;
    const VD_DESCRIPTOR* descriptors;
    uint32_t i,j,offset,iface=VD_NO_INDEX,expected=0,actual=0,interfaceCount=0;
    const uint8_t* device;const uint8_t* config;uint32_t configLength;
    if(!memory || !result || size<sizeof(VD_CREATE) || size>VD_MAX_CREATE)return VdInvalid;
    if(create->Version!=VD_VERSION || create->TotalSize!=size ||
       create->Speed<VdLowSpeed || create->Speed>VdHighSpeed || (create->Flags&~VdDelegateControls) ||
       !create->InputDepth || create->InputDepth>VD_MAX_DEPTH ||
       !create->DescriptorCount || create->DescriptorCount>VD_MAX_DESCRIPTORS ||
       create->RuleCount>VD_MAX_RULES || create->DescriptorsOffset<sizeof(VD_CREATE) ||
       !VdRange(size,create->DescriptorsOffset,create->DescriptorCount*(uint32_t)sizeof(VD_DESCRIPTOR)) ||
       (create->RuleCount && (create->RulesOffset<sizeof(VD_CREATE) ||
       !VdRange(size,create->RulesOffset,create->RuleCount*(uint32_t)sizeof(VD_CONTROL_RULE)))))return VdInvalid;
    /* No libc dependency in the kernel or users of this validator. */
    for(i=0;i<sizeof(*result);++i)((uint8_t*)result)[i]=0;
    result->DeviceDescriptor=result->ConfigurationDescriptor=VD_NO_INDEX;
    for(i=0;i<256;++i)result->ReportDescriptor[i]=VD_NO_INDEX;
    descriptors=(const VD_DESCRIPTOR*)(data+create->DescriptorsOffset);
    for(i=0;i<create->DescriptorCount;++i) {
        const VD_DESCRIPTOR* d=&descriptors[i];const uint8_t* bytes;
        if(!d->Length || !VdRange(size,d->Offset,d->Length) || d->Index>255 ||
           d->Language>65535 || d->InterfaceNumber>255)return VdInvalid;
        bytes=data+d->Offset;
        if(d->Kind==VdReportDescriptor) {
            if(d->Index || d->Language || result->ReportDescriptor[d->InterfaceNumber]!=VD_NO_INDEX)return VdInvalid;
            result->ReportDescriptor[d->InterfaceNumber]=i;
            continue;
        }
        if(d->Kind!=VdStandardDescriptor || d->Length<2 || bytes[0]<2)return VdInvalid;
        if(bytes[1]==1) {
            if(d->Index || d->Language || d->InterfaceNumber || d->Length!=18 || bytes[0]!=18 ||
               result->DeviceDescriptor!=VD_NO_INDEX)return VdInvalid;
            result->DeviceDescriptor=i;
        } else if(bytes[1]==2) {
            if(d->Index || d->Language || d->InterfaceNumber || d->Length<9 || bytes[0]!=9 ||
               result->ConfigurationDescriptor!=VD_NO_INDEX)return VdInvalid;
            result->ConfigurationDescriptor=i;
        } else if(bytes[1]==3) {
            if(d->Length>254 || d->Length!=bytes[0] || (d->Length&1u) || d->InterfaceNumber ||
               (!d->Index && (d->Language || d->Length<4)) ||
               (d->Index && !d->Language && d->Index!=238))return VdInvalid;
        } else if(bytes[1]==15) {
            if(d->Index || d->Language || d->InterfaceNumber || d->Length<5 || bytes[0]!=5 ||
               VdRead16(bytes+2)!=d->Length)return VdInvalid;
            offset=5;actual=0;
            while(offset<d->Length) {
                if(d->Length-offset<3 || bytes[offset]<3 || bytes[offset+1]!=16 || bytes[offset]>d->Length-offset)return VdInvalid;
                offset+=bytes[offset];++actual;
            }
            if(actual!=bytes[4])return VdInvalid;
        } else return VdUnsupported;
        for(j=0;j<i;++j) {
            const VD_DESCRIPTOR* previous=&descriptors[j];
            if(previous->Kind==VdStandardDescriptor && data[previous->Offset+1]==bytes[1] &&
               previous->Index==d->Index && previous->Language==d->Language)return VdInvalid;
        }
    }
    if(result->DeviceDescriptor==VD_NO_INDEX || result->ConfigurationDescriptor==VD_NO_INDEX)return VdInvalid;
    device=data+descriptors[result->DeviceDescriptor].Offset;
    if(VdRead16(device+2)<0x110 || VdRead16(device+2)>0x210 || device[17]!=1 ||
       (create->Speed==VdLowSpeed && device[7]!=8) || (create->Speed==VdHighSpeed && device[7]!=64) ||
       (create->Speed==VdHighSpeed && VdRead16(device+2)<0x200) ||
       (create->Speed==VdFullSpeed && device[7]!=8 && device[7]!=16 && device[7]!=32 && device[7]!=64))return VdInvalid;
    config=data+descriptors[result->ConfigurationDescriptor].Offset;
    configLength=descriptors[result->ConfigurationDescriptor].Length;
    if(VdRead16(config+2)!=configLength || !config[4] || !config[5] || (config[7]&159u)!=128u || config[8]>250)return VdInvalid;
    offset=9;
    while(offset<configLength) {
        const uint8_t* d=config+offset;uint32_t length,type;
        if(configLength-offset<2)return VdInvalid;
        length=d[0];type=d[1];if(length<2 || length>configLength-offset)return VdInvalid;
        if(type==4) {
            if(length!=9 || (iface!=VD_NO_INDEX && actual!=expected))return VdInvalid;
            if(d[3])return VdUnsupported;
            iface=d[2];if(iface>=config[4] || result->Interfaces[iface])return VdInvalid;
            result->Interfaces[iface]=(uint8_t)(d[5]==3?2:1);
            if(d[5]==3 && d[6]==1 && (d[7]==1 || d[7]==2))result->BootProtocol[iface]=d[7];
            ++interfaceCount;expected=d[4];actual=0;
        } else if(type==5) {
            VD_ENDPOINT_LAYOUT* endpoint;uint32_t address,transfer,packet;
            if(iface==VD_NO_INDEX || length!=7 || result->EndpointCount==VD_MAX_ENDPOINTS)return VdInvalid;
            address=d[2];transfer=d[3]&3u;packet=VdRead16(d+4);
            if((address&112u) || !(address&15u) || (d[3]&252u) || !packet || (packet&63488u))return VdInvalid;
            if(transfer!=2 && transfer!=3)return VdUnsupported;
            if(create->Speed==VdLowSpeed && (transfer!=3 || packet>8 || d[6]<10))return VdInvalid;
            if(transfer==3 && (!d[6] || (create->Speed==VdFullSpeed && packet>64) ||
               (create->Speed==VdHighSpeed && (packet>1024 || d[6]>16))))return VdInvalid;
            if(transfer==2 && ((create->Speed==VdHighSpeed && packet!=512) ||
               (create->Speed==VdFullSpeed && packet!=8 && packet!=16 && packet!=32 && packet!=64)))return VdInvalid;
            for(j=0;j<result->EndpointCount;++j)if(result->Endpoints[j].Address==address)return VdInvalid;
            endpoint=&result->Endpoints[result->EndpointCount++];endpoint->Address=address;
            endpoint->InterfaceNumber=iface;endpoint->Type=transfer;endpoint->MaxPacket=packet;
            ++actual;
        } else if(type==33 && iface!=VD_NO_INDEX && result->Interfaces[iface]==2) {
            if(length!=9 || d[5]!=1 || d[6]!=34 || !VdRead16(d+7) || result->HidDescriptorLength[iface])return VdUnsupported;
            result->HidDescriptorOffset[iface]=offset;
            result->HidDescriptorLength[iface]=length;
        }
        offset+=length;
    }
    if(iface==VD_NO_INDEX || actual!=expected || interfaceCount!=config[4])return VdInvalid;
    for(i=0;i<256;++i) {
        if(result->Interfaces[i]==2) {
            const VD_DESCRIPTOR* report;int code;uint32_t inputCount=0,outputCount=0;
            if(result->ReportDescriptor[i]==VD_NO_INDEX || !result->HidDescriptorLength[i])return VdInvalid;
            report=&descriptors[result->ReportDescriptor[i]];
            if(report->Length!=VdRead16(config+result->HidDescriptorOffset[i]+7))return VdInvalid;
            code=VdParseReport(data+report->Offset,report->Length,i,result);if(code)return code;
            for(j=0;j<result->EndpointCount;++j)if(result->Endpoints[j].InterfaceNumber==i) {
                if(result->Endpoints[j].Type!=3)return VdInvalid;
                if(result->Endpoints[j].Address&128u)++inputCount;else ++outputCount;
            }
            if(inputCount!=1 || outputCount>1)return VdInvalid;
        } else if(result->ReportDescriptor[i]!=VD_NO_INDEX)return VdInvalid;
    }
    for(i=0;i<create->RuleCount;++i) {
        const VD_CONTROL_RULE* rule=(const VD_CONTROL_RULE*)(data+create->RulesOffset+i*sizeof(VD_CONTROL_RULE));
        if(rule->Action<VdReply || rule->Action>VdStall || rule->DataLength>VD_MAX_TRANSFER ||
           !VdRange(size,rule->DataOffset,rule->DataLength) ||
           (rule->Action!=VdReply && rule->DataLength))return VdInvalid;
    }
    return VdValid;
}

namespace Vdevice {
namespace {
Result Failure(std::uint32_t code, const char* text) { return {code, text}; }
Result Windows_Error(DWORD code, const char* operation) {
    Result result{code, operation};
    wchar_t message[512]{};
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, message, static_cast<DWORD>(sizeof(message) / sizeof(message[0])), nullptr);
    if (length) {
        char utf8[2048]{};
        const int converted = WideCharToMultiByte(CP_UTF8,0,message,static_cast<int>(length),utf8,static_cast<int>(sizeof(utf8)),nullptr,nullptr);
        result.message += ": "; if (converted > 0) result.message.append(utf8,static_cast<std::size_t>(converted));
        while (!result.message.empty() && (result.message.back() == '\r' || result.message.back() == '\n')) result.message.pop_back();
    }
    return result;
}
std::uint16_t Read16(const std::uint8_t* data) noexcept { return static_cast<std::uint16_t>(data[0] | (static_cast<unsigned>(data[1]) << 8)); }
Result Validate_Report(const std::vector<std::uint8_t>& data) {
    if (data.empty() || data.size() > VD_MAX_TRANSFER) return Failure(ERROR_INVALID_DATA, "A HID report descriptor must contain 1..4096 bytes.");
    unsigned collections = 0, globalDepth = 0;
    for (std::size_t at = 0; at < data.size();) {
        const auto prefix = data[at++];
        if (prefix == 0xfe) {
            if (data.size() - at < 2) return Failure(ERROR_INVALID_DATA, "Truncated long HID item.");
            const auto length = data[at]; at += 2;
            if (length > data.size() - at) return Failure(ERROR_INVALID_DATA, "Truncated long HID item payload.");
            at += length; continue;
        }
        const unsigned length = (prefix & 3) == 3 ? 4 : prefix & 3;
        if (length > data.size() - at) return Failure(ERROR_INVALID_DATA, "Truncated HID report item.");
        switch (prefix & 0xfc) {
        case 0xa0: if (++collections > 64) return Failure(ERROR_INVALID_DATA, "Too many nested HID collections."); break;
        case 0xc0: if (collections == 0) return Failure(ERROR_INVALID_DATA, "HID End Collection without Collection."); --collections; break;
        case 0xa4: if (++globalDepth > 16) return Failure(ERROR_INVALID_DATA, "Too many HID global pushes."); break;
        case 0xb4: if (!globalDepth) return Failure(ERROR_INVALID_DATA, "HID global pop without push."); --globalDepth; break;
        default: break;
        }
        at += length;
    }
    if (collections || globalDepth) return Failure(ERROR_INVALID_DATA, "Unclosed HID collection or global push.");
    return {};
}
Result Validate_Descriptors(const Device_Config& config, const std::vector<Descriptor>& descriptors) {
    if (descriptors.empty() || descriptors.size() > VD_MAX_DESCRIPTORS) return Failure(ERROR_INVALID_PARAMETER, "Provide 1..64 descriptors.");
    const Descriptor* device = nullptr; const Descriptor* configuration = nullptr;
    bool interfaces[256]{}, reports[256]{};
    for (std::size_t i = 0; i < descriptors.size(); ++i) {
        const auto& item = descriptors[i];
        const auto fail = [i](DWORD code, const char* text) { return Result{code,"Descriptor #" + std::to_string(i) + ": " + text}; };
        if (item.index > 255 || item.interface_number > 255 || item.language > 65535 || item.data.empty() || item.data.size() > VD_MAX_CREATE)
            return fail(ERROR_INVALID_DATA, "Descriptor index, language, interface, or length is invalid.");
        for (std::size_t j = 0; j < i; ++j) {
            const auto& previous = descriptors[j];
            if (previous.kind == item.kind && previous.index == item.index && previous.language == item.language &&
                previous.interface_number == item.interface_number &&
                (item.kind == Descriptor_Kind::Report || (item.data.size() > 1 && previous.data.size() > 1 && previous.data[1] == item.data[1])))
                return fail(ERROR_INVALID_DATA, "Duplicate descriptor selector.");
        }
        if (item.kind == Descriptor_Kind::Report) {
            if (item.index || item.language) return fail(ERROR_INVALID_DATA, "Report descriptors use index 0 and language 0.");
            auto result = Validate_Report(item.data); if (!result) { result.message = "Descriptor #" + std::to_string(i) + ": " + result.message; return result; }
            reports[item.interface_number] = true; continue;
        }
        if (item.kind != Descriptor_Kind::Standard || item.data.size() < 2 || item.data[0] < 2 || item.data[0] > item.data.size())
            return fail(ERROR_INVALID_DATA, "Invalid standard descriptor header.");
        switch (item.data[1]) {
        case 1:
            if (device || item.index || item.data.size() != 18 || item.data[0] != 18)
                return fail(ERROR_INVALID_DATA, "Supply exactly one 18-byte USB device descriptor at index 0.");
            device = &item; break;
        case 2:
            if (configuration || item.index || item.data.size() < 9 || item.data[0] != 9 || Read16(item.data.data() + 2) != item.data.size())
                return fail(ERROR_INVALID_DATA, "Supply one configuration descriptor at index 0 with an exact wTotalLength.");
            configuration = &item; break;
        case 3:
            if (item.data.size() > 254 || item.data.size() % 2 || item.data[0] != item.data.size())
                return fail(ERROR_INVALID_DATA, "USB string descriptors must contain 2..254 bytes and UTF-16 code units.");
            if (item.index == 0 && (item.language != 0 || item.data.size() < 4))
                return fail(ERROR_INVALID_DATA, "String 0 must contain at least one LANGID with language selector 0.");
            break;
        default: break;
        }
    }
    if (!device || !configuration) return Failure(ERROR_INVALID_DATA, "Device and complete configuration descriptors are required.");
    if (device->data[17] != 1) return Failure(ERROR_NOT_SUPPORTED, "This version supports exactly one USB configuration.");
    const auto packet0 = device->data[7];
    if ((config.speed == Speed::Low && packet0 != 8) || (config.speed == Speed::High && packet0 != 64) ||
        (config.speed == Speed::Full && packet0 != 8 && packet0 != 16 && packet0 != 32 && packet0 != 64))
        return Failure(ERROR_INVALID_DATA, "Endpoint 0 packet size is invalid for the selected USB speed.");
    const auto& data = configuration->data;
    if (!data[5] || !(data[7] & 0x80) || (data[7] & 0x1f)) return Failure(ERROR_INVALID_DATA, "Invalid USB configuration value or attributes.");
    bool endpoints[256]{}; unsigned interfaceCount = 0, endpointCount = 0, expected = 0, actual = 0;
    int current = -1; bool currentHid = false;
    for (std::size_t at = 9; at < data.size();) {
        const auto fail = [at](DWORD code, const char* text) { return Result{code,"Configuration byte " + std::to_string(at) + ": " + text}; };
        if (data.size() - at < 2 || data[at] < 2 || data[at] > data.size() - at)
            return fail(ERROR_INVALID_DATA, "Truncated or zero-length configuration child descriptor.");
        const auto length = data[at], type = data[at + 1]; const auto* child = data.data() + at;
        if (type == 4) {
            if (length != 9 || child[3] != 0) return fail(ERROR_NOT_SUPPORTED, "Only 9-byte interface descriptors with alternate setting 0 are supported.");
            if (current >= 0 && actual != expected) return fail(ERROR_INVALID_DATA, "Interface endpoint count does not match its descriptors.");
            if (interfaces[child[2]]) return fail(ERROR_INVALID_DATA, "Duplicate interface number.");
            interfaces[child[2]] = true; ++interfaceCount; current = child[2]; currentHid = child[5] == 3; expected = child[4]; actual = 0;
        } else if (type == 5) {
            if (current < 0 || length < 7 || (child[2] & 0x70) || !(child[2] & 0x0f) || endpoints[child[2]])
                return fail(ERROR_INVALID_DATA, "Invalid, duplicate, or orphan endpoint descriptor.");
            const auto transfer = child[3] & 3; const auto packet = Read16(child + 4);
            if ((transfer != 2 && transfer != 3) || (packet & 0xf800) || !packet)
                return fail(ERROR_NOT_SUPPORTED, "Only bulk and interrupt endpoints without high-bandwidth transactions are supported.");
            if ((config.speed == Speed::Low && (transfer != 3 || packet > 8 || child[6] < 10)) ||
                (config.speed == Speed::Full && packet > 64) ||
                (config.speed == Speed::High && (packet > (transfer == 2 ? 512 : 1024) || (transfer == 3 && (child[6] < 1 || child[6] > 16)))) ||
                (transfer == 3 && child[6] == 0))
                return fail(ERROR_INVALID_DATA, "Endpoint packet size or polling interval is invalid for the selected USB speed.");
            endpoints[child[2]] = true; ++endpointCount; ++actual;
        } else if (type == 0x21 && currentHid) {
            if (current < 0 || length < 9 || child[5] < 1 || child[6] != 0x22)
                return fail(ERROR_INVALID_DATA, "Invalid HID class descriptor.");
            bool found = false;
            for (const auto& report : descriptors) if (report.kind == Descriptor_Kind::Report && report.interface_number == static_cast<unsigned>(current)) {
                if (Read16(child + 7) != report.data.size()) return fail(ERROR_INVALID_DATA, "HID report length differs from the supplied report descriptor.");
                found = true;
            }
            if (!found) return fail(ERROR_INVALID_DATA, "HID interface is missing its report descriptor.");
        }
        at += length;
    }
    if (current < 0 || actual != expected || interfaceCount != data[4] || endpointCount > VD_MAX_ENDPOINTS)
        return Failure(ERROR_INVALID_DATA, "Configuration interface or endpoint count is inconsistent.");
    for (unsigned i = 0; i < 256; ++i) if (reports[i] && !interfaces[i]) return Failure(ERROR_INVALID_DATA, "Report descriptor references an absent interface.");
    return {};
}

struct Thread_Io {
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ~Thread_Io() { if (event) CloseHandle(event); }
};
Result Ioctl(HANDLE handle, DWORD code, const void* input, DWORD inputSize,
    void* output, DWORD outputSize, DWORD& transferred, DWORD timeout = INFINITE) {
    thread_local Thread_Io io;
    if (!io.event) return Windows_Error(GetLastError(), "Create I/O event");
    ResetEvent(io.event); OVERLAPPED overlapped{}; overlapped.hEvent = io.event;
    transferred = 0;
    if (DeviceIoControl(handle, code, const_cast<void*>(input), inputSize, output, outputSize, &transferred, &overlapped)) return {};
    DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) return Windows_Error(error, "Vdevice request");
    const DWORD wait = WaitForSingleObject(io.event, timeout);
    if (wait != WAIT_OBJECT_0) {
        const DWORD waitError = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        CancelIoEx(handle, &overlapped);
        // OVERLAPPED storage must remain valid until cancellation completes.
        const BOOL completed = GetOverlappedResult(handle, &overlapped, &transferred, TRUE);
        const DWORD completionError = completed ? ERROR_SUCCESS : GetLastError();
        if (completed) return {}; // completion won the timeout race; preserve the packet.
        if (completionError != ERROR_OPERATION_ABORTED) return Windows_Error(completionError, "Complete Vdevice request");
        return Windows_Error(waitError, "Wait for Vdevice output");
    }
    if (!GetOverlappedResult(handle, &overlapped, &transferred, FALSE)) return Windows_Error(GetLastError(), "Complete Vdevice request");
    return {};
}
struct Session {
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::string prefix;
    explicit Session(HANDLE value) : handle(value) {
        LARGE_INTEGER ticks{}; QueryPerformanceCounter(&ticks);
        static std::atomic<std::uint64_t> sequence{0};
        std::ostringstream text; text << "vd-" << std::hex << GetCurrentProcessId() << '-' << ticks.QuadPart << '-' << ++sequence << '-';
        prefix = text.str();
    }
    ~Session() { if (handle != INVALID_HANDLE_VALUE) { CancelIoEx(handle, nullptr); CloseHandle(handle); } }
    std::string Token(std::uint64_t id) const { return prefix + std::to_string(id); }
};
std::shared_ptr<Session> Acquire(Result& result) {
    static std::mutex mutex; static std::weak_ptr<Session> current;
    std::lock_guard<std::mutex> lock(mutex);
    auto session = current.lock();
    if (session) return session;
    HANDLE handle = CreateFileW(VD_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { result = Windows_Error(GetLastError(), "Open Vdevice (install the driver and run this process elevated)"); return {}; }
    // Preserve handle ownership even if allocating the session or token prefix
    // throws: no raw Windows handle is leaked on allocation failure.
    struct Handle_Guard {
        HANDLE value;
        ~Handle_Guard() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    } guard{handle};
    session = std::make_shared<Session>(handle); guard.value = INVALID_HANDLE_VALUE;
    current = session; return session;
}
}

namespace Detail {
struct Device_State {
    std::shared_ptr<Session> session;
    std::uint64_t id = 0;
    std::atomic<bool> deleted{false};
    ~Device_State() {
        if (!deleted.exchange(true) && session && id) {
            VD_ID request{id}; DWORD transferred = 0;
            try { (void)Ioctl(session->handle, VD_DELETE_DEVICE, &request, sizeof(request), nullptr, 0, transferred); } catch (...) {}
        }
    }
};
}

namespace Detail {
Result Serialize(const Device_Config& config, std::vector<std::uint8_t>& output) {
    output.clear();
    if (config.speed != Speed::Low && config.speed != Speed::Full && config.speed != Speed::High)
        return Failure(ERROR_INVALID_PARAMETER, "USB speed must be Low, Full, or High.");
    if (!config.input_depth || config.input_depth > VD_MAX_DEPTH) return Failure(ERROR_INVALID_PARAMETER, "Input queue depth must be 1..256.");
    const auto& descriptors = config.descriptors;
    auto result = Validate_Descriptors(config, descriptors); if (!result) return result;
    const auto& rules = config.rules;
    // Static responses are copied verbatim; the kernel retains generic HID state.
    if (rules.size() > VD_MAX_RULES) return Failure(ERROR_INVALID_PARAMETER, "At most 32 control rules are supported.");
    std::size_t size = sizeof(VD_CREATE) + descriptors.size() * sizeof(VD_DESCRIPTOR) + rules.size() * sizeof(VD_CONTROL_RULE);
    for (const auto& descriptor : descriptors) size += descriptor.data.size();
    for (const auto& rule : rules) {
        if (rule.data.size() > VD_MAX_TRANSFER || (rule.action != Rule_Action::Reply && rule.action != Rule_Action::Accept && rule.action != Rule_Action::Stall) ||
            (rule.action != Rule_Action::Reply && !rule.data.empty())) return Failure(ERROR_INVALID_PARAMETER, "Invalid control-rule action or response payload.");
        size += rule.data.size();
    }
    if (size > VD_MAX_CREATE) return Failure(ERROR_BUFFER_OVERFLOW, "Serialized device exceeds 64 KiB.");
    output.resize(size); VD_CREATE header{}; header.Version = VD_VERSION; header.TotalSize = static_cast<std::uint32_t>(size);
    header.Speed = static_cast<std::uint32_t>(config.speed); header.Flags = config.delegate_controls ? 1u : 0u;
    header.DescriptorCount = static_cast<std::uint32_t>(descriptors.size()); header.DescriptorsOffset = sizeof(header);
    header.RuleCount = static_cast<std::uint32_t>(rules.size()); header.RulesOffset = header.DescriptorsOffset + header.DescriptorCount * sizeof(VD_DESCRIPTOR);
    header.InputDepth = config.input_depth;
    std::memcpy(output.data(), &header, sizeof(header));
    std::size_t cursor = header.RulesOffset + rules.size() * sizeof(VD_CONTROL_RULE);
    for (std::size_t i = 0; i < descriptors.size(); ++i) {
        const auto& source = descriptors[i]; VD_DESCRIPTOR descriptor{static_cast<std::uint32_t>(source.kind),source.index,source.language,source.interface_number,
            static_cast<std::uint32_t>(cursor),static_cast<std::uint32_t>(source.data.size())};
        std::memcpy(output.data() + header.DescriptorsOffset + i * sizeof(descriptor), &descriptor, sizeof(descriptor));
        std::memcpy(output.data() + cursor, source.data.data(), source.data.size()); cursor += source.data.size();
    }
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& source = rules[i]; VD_CONTROL_RULE rule{}; std::memcpy(rule.Setup,source.setup.data(),8); std::memcpy(rule.Mask,source.mask.data(),8);
        rule.Action = static_cast<std::uint32_t>(source.action); rule.DataOffset = static_cast<std::uint32_t>(cursor); rule.DataLength = static_cast<std::uint32_t>(source.data.size());
        std::memcpy(output.data() + header.RulesOffset + i * sizeof(rule), &rule, sizeof(rule));
        if (!source.data.empty()) std::memcpy(output.data() + cursor,source.data.data(),source.data.size()); cursor += source.data.size();
    }
    VD_LAYOUT layout{};
    const int validation = VdValidateCreate(output.data(),static_cast<std::uint32_t>(output.size()),&layout);
    if (validation != VdValid) {
        output.clear();
        if (validation == VdUnsupported) return Failure(ERROR_NOT_SUPPORTED,"Descriptor topology is not supported: use USB 1.1/2.x, one configuration, alternate setting 0, interrupt/bulk endpoints and device/configuration/string/BOS/report descriptors.");
        if (validation == VdLimit) return Failure(ERROR_BUFFER_OVERFLOW,"USB/HID layout exceeds a bounded limit: 256 report layouts, 4096 bytes per transfer, or HID global stack depth 16.");
        return Failure(ERROR_INVALID_DATA,"Invalid USB/HID layout: check USB version, string selectors, endpoint packet sizes, HID report sizes/counts/IDs and collection balance.");
    }
    return {};
}
} // namespace Detail
Result Validate_Device(const Device_Config& config) { std::vector<std::uint8_t> bytes; return Detail::Serialize(config, bytes); }

namespace {
template<std::size_t Capacity>
Result Send_Bytes(const std::shared_ptr<Detail::Device_State>& state, std::uint8_t endpoint, const std::uint8_t* data, std::size_t length) {
    static_assert(Capacity <= VD_MAX_TRANSFER, "Transfer storage must respect the kernel limit.");
    if (!state || state->deleted.load()) return Failure(ERROR_INVALID_HANDLE, "Device is not active.");
    if (!(endpoint & 0x80) || !(endpoint & 0x0f) || (endpoint & 0x70) || length > Capacity)
        return Failure(ERROR_INVALID_PARAMETER, "Send_Input requires an IN endpoint (e.g. 0x81) and at most 4096 bytes.");
    std::array<std::uint8_t,sizeof(VD_TRANSFER) + Capacity> packet;
    const VD_TRANSFER request{state->id,endpoint,static_cast<std::uint32_t>(length)};
    std::memcpy(packet.data(),&request,sizeof(request));
    if (length) std::memcpy(packet.data() + sizeof(request),data,length);
    DWORD transferred = 0;
    return Ioctl(state->session->handle,VD_SEND,packet.data(),static_cast<DWORD>(sizeof(request) + length),nullptr,0,transferred);
}
}
Device::~Device() = default;
Device::Device(Device&&) noexcept = default;
Device& Device::operator=(Device&&) noexcept = default;
Device::operator bool() const noexcept { return state_ && !state_->deleted.load() && !error; }
std::uint64_t Device::Id() const noexcept { return state_ ? state_->id : 0; }
Info Get_Info() {
    Info result; Result status; auto session = Acquire(status);
    if (!session) { result.error = status.error; result.message = status.message; return result; }
    VD_INFO info{}; DWORD transferred = 0; status = Ioctl(session->handle,VD_QUERY,nullptr,0,&info,sizeof(info),transferred);
    if (!status || transferred != sizeof(info) || info.Version != VD_VERSION) {
        result.error = status ? ERROR_REVISION_MISMATCH : status.error; result.message = status ? "Vdevice SDK/driver protocol version differs." : status.message; return result;
    }
    result.version = info.Version; result.max_devices = info.MaxDevices; result.max_transfer = info.MaxTransfer;
    result.low_speed = info.LowSpeed != 0; result.full_speed = info.FullSpeed != 0; result.high_speed = info.HighSpeed != 0;
    result.trial_started = info.TrialStarted100ns != 0; result.trial_expired = info.TrialExpired != 0; result.trial_remaining_100ns = info.TrialRemaining100ns;
    result.quiescing = (info.Reserved2 & 1u) != 0; result.removing = (info.Reserved2 & 2u) != 0;
    VD_DEVICE_LIST list{}; status = Ioctl(session->handle,VD_LIST,nullptr,0,&list,sizeof(list),transferred);
    if (status && (transferred < offsetof(VD_DEVICE_LIST,Devices) || list.Count > VD_MAX_DEVICES ||
        transferred < offsetof(VD_DEVICE_LIST,Devices) + list.Count * sizeof(VD_DEVICE_INFO)))
        status = Failure(ERROR_INVALID_DATA,"Driver returned an invalid device list.");
    if (!status) { result.error = status.error; result.message = status.message; return result; }
    result.devices.reserve(list.Count);
    for (std::uint32_t i = 0; i < list.Count; ++i) {
        const auto& source = list.Devices[i]; Device_Details target; target.id = source.Id; target.token = session->Token(source.Id);
        target.plugged = (source.Flags & 1) != 0; target.configured = (source.Flags & 2) != 0; target.powered = (source.Flags & 4) != 0;
        target.endpoint_count = source.EndpointCount; target.queued_inputs = source.QueuedInputs; target.queued_outputs = source.QueuedOutputs;
        target.inputs_accepted = source.InputsAccepted; target.inputs_completed = source.InputsCompleted;
        target.outputs_received = source.OutputsReceived; target.outputs_dropped = source.OutputsDropped;
        result.devices.push_back(std::move(target));
    }
    return result;
}
Device Create_Device(const Device_Config& config) {
    Device result; std::vector<std::uint8_t> bytes; auto status = Detail::Serialize(config,bytes);
    if (!status) { result.error = status.error; result.message = status.message; return result; }
    auto state = std::make_shared<Detail::Device_State>(); state->session = Acquire(status);
    if (!state->session) { result.error = status.error; result.message = status.message; return result; }
    VD_ID created{}; DWORD transferred = 0;
    status = Ioctl(state->session->handle,VD_CREATE_DEVICE,bytes.data(),static_cast<DWORD>(bytes.size()),&created,sizeof(created),transferred);
    if (!status || transferred != sizeof(created) || !created.Id) {
        result.error = status ? ERROR_INVALID_DATA : status.error; result.message = status ? "Driver returned an invalid device identity." : status.message; return result;
    }
    state->id = created.Id; result.token = state->session->Token(state->id); result.state_ = std::move(state); return result;
}
Result Delete_Device(Device& device) {
    if (!device.state_) return Failure(ERROR_INVALID_HANDLE, "Device is not active.");
    auto state = device.state_; if (state->deleted.load()) return {};
    VD_ID request{state->id}; DWORD transferred = 0;
    auto result = Ioctl(state->session->handle,VD_DELETE_DEVICE,&request,sizeof(request),nullptr,0,transferred);
    if (result || result.error == ERROR_DEVICE_NOT_CONNECTED || result.error == ERROR_NOT_FOUND) state->deleted.store(true);
    return result;
}
Result Send_Input(const Device& device, std::uint8_t endpoint, const std::vector<std::uint8_t>& bytes) {
    // Small reports use an 80-byte stack packet; larger raw transfers stay
    // bounded. Neither path allocates or needs to identify a device family.
    return bytes.size() <= 64 ? Send_Bytes<64>(device.state_,endpoint,bytes.data(),bytes.size()) :
        Send_Bytes<VD_MAX_TRANSFER>(device.state_,endpoint,bytes.data(),bytes.size());
}
Output Get_Output(std::uint32_t timeout) {
    Output result; Result status; auto session = Acquire(status);
    if (!session) { result.error = status.error; result.message = status.message; return result; }
    VD_OUTPUT packet{}; DWORD transferred = 0;
    status = Ioctl(session->handle,VD_RECEIVE,nullptr,0,&packet,sizeof(packet),transferred,timeout);
    if (!status) { result.error = status.error; result.message = status.message; result.timed_out = status.error == ERROR_TIMEOUT; return result; }
    if (transferred < offsetof(VD_OUTPUT,Data) || packet.Length > VD_MAX_TRANSFER || packet.Length > transferred - offsetof(VD_OUTPUT,Data) ||
        packet.Kind < 1 || packet.Kind > 3 || packet.Endpoint > 255) {
        result.error = ERROR_INVALID_DATA; result.message = "Driver returned an invalid output packet."; return result;
    }
    result.device_id = packet.Id; result.device_token = session->Token(packet.Id); result.request_id = packet.RequestId;
    result.kind = static_cast<Output_Kind>(packet.Kind); result.endpoint = static_cast<std::uint8_t>(packet.Endpoint);
    std::memcpy(result.setup.data(),packet.Setup,8); result.data.assign(packet.Data,packet.Data + packet.Length); return result;
}
Result Respond_Output(const Output& output, const std::vector<std::uint8_t>& data, bool stall) {
    if (output.error || !output.request_id || output.kind != Output_Kind::Control || data.size() > VD_MAX_TRANSFER || (stall && !data.empty()))
        return Failure(ERROR_INVALID_PARAMETER, "Respond only to a pending control request, with at most 4096 reply bytes or an empty stall.");
    Result status; auto session = Acquire(status); if (!session) return status;
    if (session->Token(output.device_id) != output.device_token) return Failure(ERROR_INVALID_HANDLE, "Output belongs to a different Vdevice session.");
    std::array<std::uint8_t,sizeof(VD_RESPONSE) + VD_MAX_TRANSFER> bytes;
    const VD_RESPONSE request{output.device_id,output.request_id,stall ? 1u : 0u,static_cast<std::uint32_t>(data.size())};
    std::memcpy(bytes.data(),&request,sizeof(request)); if (!data.empty()) std::memcpy(bytes.data() + sizeof(request),data.data(),data.size());
    DWORD transferred = 0; return Ioctl(session->handle,VD_RESPOND,bytes.data(),static_cast<DWORD>(sizeof(request) + data.size()),nullptr,0,transferred);
}
} // namespace Vdevice
