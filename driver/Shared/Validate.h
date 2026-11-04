#ifndef VDEVICE_VALIDATE_H
#define VDEVICE_VALIDATE_H
#include "Protocol.h"

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
#endif
