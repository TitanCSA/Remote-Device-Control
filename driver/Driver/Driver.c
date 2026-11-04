// Vdevice: an owner-scoped, configurable USB 2 emulation controller.
#include <ntifs.h>
#include <wdf.h>
#include <usb.h>
#include <wdfusb.h>
#include <udecx.h>
#include <ntstrsafe.h>
#include "../Shared/Validate.h"

#define VD_TAG 'veDV'
#define VD_NONE 0xffffffffu
#define VD_MAX_FILES 32u
#define VD_MAX_CONTROLS 32u
#define VD_CONTROL_TIMEOUT (5ull*10000000ull)
#ifdef VD_LAB_TRIAL_SECONDS
#if VD_LAB_TRIAL_SECONDS<1 || VD_LAB_TRIAL_SECONDS>120
#error The lab-only trial must be between 1 and 120 seconds.
#endif
#define VD_TRIAL_SECONDS VD_LAB_TRIAL_SECONDS
#define TITAN_TRIAL_LAB_SECONDS VD_LAB_TRIAL_SECONDS
#else
#define VD_TRIAL_SECONDS 3600u
#endif
#define VD_TRIAL_DURATION ((ULONGLONG)VD_TRIAL_SECONDS*10000000ull)
#include "../TrialClock/Client.h"

typedef struct CONTROLLER CONTROLLER;
typedef struct VIRTUAL_DEVICE VIRTUAL_DEVICE;
typedef struct COMPLETION {
    LIST_ENTRY Link;
    WDFREQUEST Request;
    NTSTATUS Status;
    ULONG Length;
    PUCHAR Buffer;
    ULONG Capacity;
    WDF_USB_CONTROL_SETUP_PACKET Setup;
} COMPLETION;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(COMPLETION, CompletionGet)
typedef struct FILE_CONTEXT {
    CONTROLLER* Controller;
    WDFFILEOBJECT Self;
    LIST_ENTRY Link;
    WDFQUEUE Events;
    UCHAR* Outputs;
    ULONG OutputHead,OutputCount,OutputReserved,OutputStride,OutputCapacity;
    ULONG PumpUsers;
    KEVENT PumpIdle;
    BOOLEAN Closing,Listed;
} FILE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FILE_CONTEXT, FileGet)

typedef struct PACKET { ULONG Next,Length; UCHAR Data[1]; } PACKET;
typedef struct ENDPOINT {
    VIRTUAL_DEVICE* Device;
    UDECXUSBENDPOINT Usb;
    WDFQUEUE Queue;
    WDFQUEUE Reads;
    ULONG Address,InterfaceNumber,Head,Tail;
    BOOLEAN Started,Purging;
} ENDPOINT;
typedef struct REPORT_CACHE { ULONG Offset; BOOLEAN Valid; } REPORT_CACHE;
struct VIRTUAL_DEVICE {
    WDFOBJECT Self;
    CONTROLLER* Controller;
    WDFFILEOBJECT Owner;
    UDECXUSBDEVICE Usb;
    WDFQUEUE Controls;
    WDFWAITLOCK ControlForward;
    WDFTIMER ControlTimer;
    VD_LAYOUT Layout;
    VD_CREATE* Description;
    PACKET* Packets;
    UCHAR* ReportData;
    REPORT_CACHE Cache[VD_MAX_REPORTS];
    UCHAR Idle[VD_MAX_REPORTS],Protocol[256];
    UCHAR BootInput[256][8],BootOutput[256],BootValid[256],BootOutputValid[256],IdleDelegated[256];
    ENDPOINT Endpoints[VD_MAX_ENDPOINTS+1];
    VD_DEVICE_INFO Info;
    ULONG Slot,FreeHead,InputDepth,InputCapacity,PacketStride,PendingControls,NextEndpoint;
    ULONG PumpUsers;
    KEVENT PumpIdle;
    ULONG SourceUsers;
    KEVENT SourceIdle;
    KEVENT EnumerationReady;
    BOOLEAN Active,WasPlugged;
};
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(VIRTUAL_DEVICE, VirtualGet)
typedef struct USB_CONTEXT { VIRTUAL_DEVICE* Device; } USB_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(USB_CONTEXT, UsbGet)
typedef struct ENDPOINT_CONTEXT { ENDPOINT* Endpoint; } ENDPOINT_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(ENDPOINT_CONTEXT, EndpointGet)
typedef struct QUEUE_CONTEXT {
    CONTROLLER* Controller;
    VIRTUAL_DEVICE* Device;
    WDFFILEOBJECT Owner;
    ENDPOINT* Endpoint;
} QUEUE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, QueueGet)
typedef struct CONTROL_CONTEXT {
    ULONGLONG Id,Deadline;
    ULONG Capacity;
    UCHAR Setup[8];
    BOOLEAN Pending;
} CONTROL_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CONTROL_CONTEXT, ControlGet)
typedef struct TIMER_CONTEXT { VIRTUAL_DEVICE* Device; CONTROLLER* Controller; } TIMER_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TIMER_CONTEXT, TimerGet)
struct CONTROLLER {
    WDFDEVICE Device;
    WDFSPINLOCK Lock;
    WDFWAITLOCK Management;
    WDFDPC Dpc;
    WDFTIMER TrialTimer;
    WDFWORKITEM ExpireWork;
    LIST_ENTRY Files;
    LIST_ENTRY Completions;
    LIST_ENTRY EmergencyCompletions;
    VIRTUAL_DEVICE* Devices[VD_MAX_DEVICES];
    ULONG FileCount;
    ULONG NextDeviceSlot,DispatchPhase;
    ULONGLONG NextDeviceId,NextRequestId,TrialStart;
    TC_CLIENT TrialClock;
    BOOLEAN Removing,Quiescing,Expired,Pumping,PumpAgain;
};
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CONTROLLER, ControllerGet)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD VdAdd;
EVT_WDF_DEVICE_FILE_CREATE VdFileCreate;
EVT_WDF_FILE_CLEANUP VdFileCleanup;
EVT_WDF_OBJECT_CONTEXT_DESTROY VdFileDestroy;
EVT_WDF_OBJECT_CONTEXT_DESTROY VdVirtualDestroy;
EVT_WDF_OBJECT_CONTEXT_DESTROY VdQueueDestroy;
EVT_WDF_OBJECT_CONTEXT_DESTROY VdUsbDestroy;
EVT_WDF_OBJECT_CONTEXT_CLEANUP VdControllerCleanup;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP VdRemoving;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL VdIoctl;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL VdUrb;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE VdCancel;
EVT_WDF_IO_QUEUE_STATE VdReady;
EVT_WDF_IO_QUEUE_STATE VdPurged;
EVT_WDF_DPC VdDpc;
EVT_WDF_TIMER VdControlTimeout;
EVT_WDF_TIMER VdTrialTimeout;
EVT_WDF_WORKITEM VdExpire;
EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY VdCapability;
EVT_UDECX_USB_ENDPOINT_RESET VdEndpointReset;
EVT_UDECX_USB_ENDPOINT_START VdEndpointStart;
EVT_UDECX_USB_ENDPOINT_PURGE VdEndpointPurge;
EVT_UDECX_USB_DEVICE_D0_ENTRY VdPowerEntry;
EVT_UDECX_USB_DEVICE_D0_EXIT VdPowerExit;

/* UdeCx requires completion at DISPATCH_LEVEL, including cancellation invoked
   by a passive queue purge. Never call this function with our lock held. */
static VOID CompleteAtDispatch(WDFREQUEST request,NTSTATUS status,ULONG length) {
    KIRQL previous=KeGetCurrentIrql();
    if(previous<DISPATCH_LEVEL)KeRaiseIrql(DISPATCH_LEVEL,&previous);
    if(NT_SUCCESS(status))UdecxUrbSetBytesCompleted(request,length);
    if(status==STATUS_NOT_SUPPORTED)UdecxUrbComplete(request,USBD_STATUS_STALL_PID);
    else UdecxUrbCompleteWithNtStatus(request,status);
    if(previous<DISPATCH_LEVEL)KeLowerIrql(previous);
}
/* A separate DPC is required, not merely raised IRQL on the submitting or
   cancellation thread: an upper USB driver can hold locks during submission. */
static VOID CompleteUrb(CONTROLLER* c,WDFREQUEST request,NTSTATUS status,ULONG length) {
    COMPLETION* completion=CompletionGet(request);
    if(!completion) {
        WDF_OBJECT_ATTRIBUTES attrs;NTSTATUS allocated;
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,COMPLETION);
        allocated=WdfObjectAllocateContext(request,&attrs,(PVOID*)&completion);
        if(!NT_SUCCESS(allocated) && allocated!=STATUS_OBJECT_NAME_EXISTS) {
            /* Received URBs are IRP-backed. Once dequeued/cancelled and owned
               by this driver, their public IRP list entry is available for a
               private queue. This allocation-free emergency path preserves
               the separate-DPC rule even under complete pool exhaustion.
               Do not borrow DriverContext slots owned by another WDF driver. */
            PIRP irp=WdfRequestWdmGetIrp(request);
            irp->IoStatus.Status=allocated;irp->IoStatus.Information=(ULONG_PTR)request;
            WdfSpinLockAcquire(c->Lock);InsertTailList(&c->EmergencyCompletions,&irp->Tail.Overlay.ListEntry);
            WdfSpinLockRelease(c->Lock);WdfDpcEnqueue(c->Dpc);return;
        }
    }
    completion->Request=request;completion->Status=status;completion->Length=length;
    WdfSpinLockAcquire(c->Lock);InsertTailList(&c->Completions,&completion->Link);WdfSpinLockRelease(c->Lock);
    WdfDpcEnqueue(c->Dpc);
}
static ULONGLONG Now(VOID) { ULONGLONG qpc;return KeQueryInterruptTimePrecise(&qpc); }
static PACKET* PacketAt(VIRTUAL_DEVICE* d,ULONG index) { return (PACKET*)((UCHAR*)d->Packets+(SIZE_T)index*d->PacketStride); }
static VD_OUTPUT* OutputAt(FILE_CONTEXT* file,ULONG index) { return (VD_OUTPUT*)(file->Outputs+(SIZE_T)index*file->OutputStride); }
static ULONG OutputSize(const VD_OUTPUT* packet) { return FIELD_OFFSET(VD_OUTPUT,Data)+packet->Length; }
static NTSTATUS EnsureOutputRing(FILE_CONTEXT* file,ULONG capacity) {
    UCHAR* previous;UCHAR* replacement;ULONG stride=(FIELD_OFFSET(VD_OUTPUT,Data)+capacity+7u)&~7u,i;
    if(capacity<=file->OutputCapacity && file->Outputs)return STATUS_SUCCESS;
    replacement=ExAllocatePool2(POOL_FLAG_NON_PAGED,(SIZE_T)stride*VD_MAX_OUTPUTS,VD_TAG);
    if(!replacement)return STATUS_INSUFFICIENT_RESOURCES;
    WdfSpinLockAcquire(file->Controller->Lock);previous=file->Outputs;
    for(i=0;i<file->OutputCount;++i) {
        VD_OUTPUT* packet=OutputAt(file,(file->OutputHead+i)%VD_MAX_OUTPUTS);
        RtlCopyMemory(replacement+(SIZE_T)i*stride,packet,OutputSize(packet));
    }
    file->Outputs=replacement;file->OutputHead=0;file->OutputStride=stride;file->OutputCapacity=capacity;
    WdfSpinLockRelease(file->Controller->Lock);if(previous)ExFreePoolWithTag(previous,VD_TAG);
    return STATUS_SUCCESS;
}
static BOOLEAN TrialExpiredLocked(CONTROLLER* c) {
    if(!c->Expired && c->TrialStart && Now()-c->TrialStart>=VD_TRIAL_DURATION) {
        c->Expired=TRUE;WdfWorkItemEnqueue(c->ExpireWork);
    }
    return c->Expired;
}
static NTSTATUS TrialOpen(CONTROLLER* c) {
    TC_RESULT result;NTSTATUS status=TcRead(&c->TrialClock,3,TC_QUERY,&result);
    if(!NT_SUCCESS(status))return status;
    if(result.duration!=VD_TRIAL_DURATION)return STATUS_REVISION_MISMATCH;
    c->TrialStart=result.first;c->Expired=(BOOLEAN)result.expired;return STATUS_SUCCESS;
}
/* Called only with the passive management lock, after PlugIn succeeds. */
static NTSTATUS TrialStart(CONTROLLER* c) {
    NTSTATUS status=STATUS_SUCCESS;ULONGLONG start;
    if(!c->TrialStart) {
        TC_RESULT result;status=TcRead(&c->TrialClock,3,TC_COMMIT,&result);
        if(!NT_SUCCESS(status))return status;
        if(!result.started || result.duration!=VD_TRIAL_DURATION)return STATUS_DATA_ERROR;
        WdfSpinLockAcquire(c->Lock);c->TrialStart=result.first;c->Expired=(BOOLEAN)result.expired;WdfSpinLockRelease(c->Lock);
    }
    start=Now()-c->TrialStart;
    if(start>=VD_TRIAL_DURATION)return STATUS_ACCESS_DENIED;
    WdfTimerStart(c->TrialTimer,-(LONGLONG)(VD_TRIAL_DURATION-start));
    return status;
}
static VIRTUAL_DEVICE* FindLocked(CONTROLLER* c,WDFFILEOBJECT owner,ULONGLONG id) {
    ULONG i;
    for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i] && c->Devices[i]->Info.Id==id &&
       c->Devices[i]->Owner==owner && c->Devices[i]->Active)return c->Devices[i];
    return NULL;
}
static LONG FindReport(VIRTUAL_DEVICE* d,ULONG iface,ULONG type,ULONG id) {
    ULONG i;for(i=0;i<d->Layout.ReportCount;++i) {
        const VD_REPORT_LAYOUT* r=&d->Layout.Reports[i];
        if(r->InterfaceNumber==iface && r->Type==type && r->Id==id)return (LONG)i;
    }
    return -1;
}
static VOID DropInputsLocked(VIRTUAL_DEVICE* d) {
    ULONG i;d->FreeHead=d->Packets?0:VD_NONE;d->Info.QueuedInputs=0;
    if(d->Packets)for(i=0;i<d->InputDepth;++i)PacketAt(d,i)->Next=i+1<d->InputDepth?i+1:VD_NONE;
    for(i=0;i<=d->Layout.EndpointCount;++i)d->Endpoints[i].Head=d->Endpoints[i].Tail=VD_NONE;
}
static BOOLEAN OutputLocked(VIRTUAL_DEVICE* d,ULONG kind,ULONG endpoint,ULONGLONG id,
    const UCHAR* setup,const UCHAR* bytes,ULONG length) {
    FILE_CONTEXT* file=FileGet(d->Owner);VD_OUTPUT* packet;
    if(!d->Active || d->Controller->Quiescing || d->Controller->Removing)return FALSE;
    ++d->Info.OutputsReceived;
    if(file->Closing || !file->Outputs || file->OutputCount+file->OutputReserved>=VD_MAX_OUTPUTS || length>file->OutputCapacity) {
        ++d->Info.OutputsDropped;return FALSE;
    }
    packet=OutputAt(file,(file->OutputHead+file->OutputCount++)%VD_MAX_OUTPUTS);
    RtlZeroMemory(packet,FIELD_OFFSET(VD_OUTPUT,Data));
    packet->Id=d->Info.Id;packet->RequestId=id;packet->Kind=kind;
    packet->Endpoint=endpoint;packet->Length=length;
    if(setup)RtlCopyMemory(packet->Setup,setup,8);
    if(length)RtlCopyMemory(packet->Data,bytes,length);
    ++d->Info.QueuedOutputs;return TRUE;
}
static VOID StateLocked(VIRTUAL_DEVICE* d) {
    ULONG flags=d->Info.Flags;
    OutputLocked(d,VdDeviceState,0,0,NULL,(const UCHAR*)&flags,sizeof(flags));
}
static VOID ForgetOutputsLocked(VIRTUAL_DEVICE* d) {
    FILE_CONTEXT* file=FileGet(d->Owner);ULONG i,count=file->OutputCount,write=0;
    for(i=0;i<count;++i) {
        VD_OUTPUT* source=OutputAt(file,(file->OutputHead+i)%VD_MAX_OUTPUTS);
        if(source->Id==d->Info.Id)continue;
        if(write!=i)RtlCopyMemory(OutputAt(file,(file->OutputHead+write)%VD_MAX_OUTPUTS),source,OutputSize(source));
        ++write;
    }
    file->OutputCount=write;d->Info.QueuedOutputs=0;
}
static VOID ForgetControlOutputLocked(VIRTUAL_DEVICE* d,ULONGLONG id) {
    FILE_CONTEXT* file=FileGet(d->Owner);ULONG i,count=file->OutputCount,write=0;
    for(i=0;i<count;++i) {
        VD_OUTPUT* source=OutputAt(file,(file->OutputHead+i)%VD_MAX_OUTPUTS);
        if(source->Id==d->Info.Id && source->Kind==VdControlRequest && source->RequestId==id) {
            if(d->Info.QueuedOutputs)--d->Info.QueuedOutputs;continue;
        }
        if(write!=i)RtlCopyMemory(OutputAt(file,(file->OutputHead+write)%VD_MAX_OUTPUTS),source,OutputSize(source));
        ++write;
    }
    file->OutputCount=write;
}
VOID VdReady(WDFQUEUE queue,WDFCONTEXT context) {
    UNREFERENCED_PARAMETER(context);WdfDpcEnqueue(QueueGet(queue)->Controller->Dpc);
}
VOID VdCancel(WDFQUEUE queue,WDFREQUEST request) {
    QUEUE_CONTEXT* q=QueueGet(queue);
    if(q->Device && !q->Endpoint) {
        CONTROL_CONTEXT* control=ControlGet(request);
        WdfSpinLockAcquire(q->Controller->Lock);
        if(control->Pending) { control->Pending=FALSE;if(q->Device->PendingControls)--q->Device->PendingControls; }
        ForgetControlOutputLocked(q->Device,control->Id);
        WdfSpinLockRelease(q->Controller->Lock);
    }
    if(q->Owner)WdfRequestComplete(request,STATUS_CANCELLED);
    else CompleteUrb(q->Controller,request,STATUS_CANCELLED,0);
}
VOID VdQueueDestroy(WDFOBJECT object) {
    QUEUE_CONTEXT* q=QueueGet(object);
    if(q->Device)WdfObjectDereference(q->Device->Self);
    if(q->Owner)WdfObjectDereference(q->Owner);
}
VOID VdUsbDestroy(WDFOBJECT object) {
    VIRTUAL_DEVICE* d=UsbGet(object)->Device;if(d)WdfObjectDereference(d->Self);
}
VOID VdVirtualDestroy(WDFOBJECT object) {
    VIRTUAL_DEVICE* d=VirtualGet(object);
    if(d->Packets)ExFreePoolWithTag(d->Packets,VD_TAG);
    if(d->Description)ExFreePoolWithTag(d->Description,VD_TAG);
    if(d->ReportData)ExFreePoolWithTag(d->ReportData,VD_TAG);
    if(d->Owner)WdfObjectDereference(d->Owner);
}
VOID VdFileDestroy(WDFOBJECT object) {
    FILE_CONTEXT* file=FileGet(object);if(file->Outputs)ExFreePoolWithTag(file->Outputs,VD_TAG);
}
static BOOLEAN SelectInputLocked(CONTROLLER* c,WDFQUEUE* queue,VIRTUAL_DEVICE** device,ENDPOINT** endpoint) {
    ULONG i,j;
    for(i=0;i<VD_MAX_DEVICES;++i) {
        ULONG slot=(c->NextDeviceSlot+i)%VD_MAX_DEVICES;VIRTUAL_DEVICE* d=c->Devices[slot];
        if(!d || !d->Active || !(d->Info.Flags&VdPowered) || c->Expired || c->Quiescing || c->Removing)continue;
        for(j=0;j<d->Layout.EndpointCount;++j) {
            ULONG index=(d->NextEndpoint+j)%d->Layout.EndpointCount+1;ENDPOINT* e=&d->Endpoints[index];
            if((e->Address&128) && e->Started && e->Head!=VD_NONE) {
                ULONG requests=0;(void)WdfIoQueueGetState(e->Reads,&requests,NULL);
                if(!requests)continue;
                *queue=e->Reads;*device=d;*endpoint=e;c->NextDeviceSlot=(slot+1)%VD_MAX_DEVICES;
                d->NextEndpoint=index%d->Layout.EndpointCount;
                WdfObjectReference(*queue);WdfObjectReference(d->Self);
                if(!d->PumpUsers++)KeClearEvent(&d->PumpIdle);return TRUE;
            }
        }
    }
    return FALSE;
}
static BOOLEAN SelectOutputLocked(CONTROLLER* c,WDFQUEUE* queue,WDFFILEOBJECT* owner) {
    LIST_ENTRY* link;
    for(link=c->Files.Flink;link!=&c->Files;link=link->Flink) {
        FILE_CONTEXT* file=CONTAINING_RECORD(link,FILE_CONTEXT,Link);ULONG requests=0;
        if(file->Closing || (!file->OutputCount && !c->Expired && !c->Removing && !c->Quiescing) || !file->Events)continue;
        (void)WdfIoQueueGetState(file->Events,&requests,NULL);if(!requests)continue;
        *queue=file->Events;*owner=file->Self;
        RemoveEntryList(&file->Link);InsertTailList(&c->Files,&file->Link);
        WdfObjectReference(*queue);WdfObjectReference(*owner);
        if(!file->PumpUsers++)KeClearEvent(&file->PumpIdle);return TRUE;
    }
    return FALSE;
}
/* Only one DPC drains the shared rings. All storage and request buffers are
   nonpaged. A 128-operation budget prevents a producer monopolising a CPU. */
VOID VdDpc(WDFDPC dpc) {
    CONTROLLER* c=ControllerGet(WdfDpcGetParentObject(dpc));ULONG budget=0;BOOLEAN repeat=FALSE;
    WdfSpinLockAcquire(c->Lock);
    if(c->Pumping) { c->PumpAgain=TRUE;WdfSpinLockRelease(c->Lock);return; }
    c->Pumping=TRUE;WdfSpinLockRelease(c->Lock);
    for(;;) {
        WDFQUEUE queue=NULL;WDFREQUEST request=NULL;VIRTUAL_DEVICE* device=NULL;
        WDFFILEOBJECT owner=NULL;ENDPOINT* endpoint=NULL;ULONG i,attempt;
        COMPLETION* completion=NULL;PIRP emergency=NULL;
        NTSTATUS status;PUCHAR target=NULL;ULONG capacity=0,completed=0;
        WdfSpinLockAcquire(c->Lock);
        for(attempt=0;attempt<3;++attempt) {
            ULONG phase=(c->DispatchPhase+attempt)%3;BOOLEAN selected=FALSE;
            if(!phase) {
                if(!IsListEmpty(&c->EmergencyCompletions)) {
                    emergency=CONTAINING_RECORD(RemoveHeadList(&c->EmergencyCompletions),IRP,Tail.Overlay.ListEntry);selected=TRUE;
                } else if(!IsListEmpty(&c->Completions)) {
                    completion=CONTAINING_RECORD(RemoveHeadList(&c->Completions),COMPLETION,Link);selected=TRUE;
                }
            } else if(phase==1)selected=SelectInputLocked(c,&queue,&device,&endpoint);
            else selected=SelectOutputLocked(c,&queue,&owner);
            if(selected) { c->DispatchPhase=(phase+1)%3;break; }
        }
        WdfSpinLockRelease(c->Lock);
        if(completion || emergency) {
            if(emergency) {
                WDFREQUEST failed=(WDFREQUEST)(ULONG_PTR)emergency->IoStatus.Information;
                NTSTATUS failure=emergency->IoStatus.Status;emergency->IoStatus.Information=0;
                CompleteAtDispatch(failed,failure,0);
            } else {
                CompleteAtDispatch(completion->Request,completion->Status,completion->Length);
            }
            if(++budget>=128) { repeat=TRUE;break; }continue;
        }
        if(!queue)break;
        status=WdfIoQueueRetrieveNextRequest(queue,&request);WdfObjectDereference(queue);
        if(!NT_SUCCESS(status)) {
            WdfSpinLockAcquire(c->Lock);
            if(device && !--device->PumpUsers)KeSetEvent(&device->PumpIdle,IO_NO_INCREMENT,FALSE);
            if(owner && !--FileGet(owner)->PumpUsers)KeSetEvent(&FileGet(owner)->PumpIdle,IO_NO_INCREMENT,FALSE);
            WdfSpinLockRelease(c->Lock);
            if(device)WdfObjectDereference(device->Self);if(owner)WdfObjectDereference(owner);
            /* Cancellation consumed the only request: re-evaluate the rings. */
            if(++budget>=128) { repeat=TRUE;break; }continue;
        }
        if(owner) {
            VD_OUTPUT* output=NULL;FILE_CONTEXT* file=FileGet(owner);
            status=WdfRequestRetrieveOutputBuffer(request,sizeof(VD_OUTPUT),(PVOID*)&output,NULL);
            WdfSpinLockAcquire(c->Lock);
            if(c->Removing || c->Quiescing)status=STATUS_DELETE_PENDING;
            else if(c->Expired)status=STATUS_EVALUATION_EXPIRATION;
            else if(NT_SUCCESS(status) && !file->Closing && file->OutputCount) {
                completed=OutputSize(OutputAt(file,file->OutputHead));
                RtlCopyMemory(output,OutputAt(file,file->OutputHead),completed);
                file->OutputHead=(file->OutputHead+1)%VD_MAX_OUTPUTS;--file->OutputCount;
                for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i] && c->Devices[i]->Info.Id==output->Id &&
                    c->Devices[i]->Info.QueuedOutputs) { --c->Devices[i]->Info.QueuedOutputs;break; }
            } else if(NT_SUCCESS(status))status=STATUS_CANCELLED;
            WdfSpinLockRelease(c->Lock);
            WdfRequestCompleteWithInformation(request,status,completed);
            WdfSpinLockAcquire(c->Lock);if(!--file->PumpUsers)KeSetEvent(&file->PumpIdle,IO_NO_INCREMENT,FALSE);
            WdfSpinLockRelease(c->Lock);WdfObjectDereference(owner);
        } else {
            target=CompletionGet(request)->Buffer;capacity=CompletionGet(request)->Capacity;status=STATUS_SUCCESS;
            WdfSpinLockAcquire(c->Lock);
            if(!device->Active || !endpoint->Started || c->Expired || c->Quiescing || c->Removing)status=STATUS_CANCELLED;
            else if(NT_SUCCESS(status) && endpoint->Head!=VD_NONE) {
                ULONG index=endpoint->Head;PACKET* packet=PacketAt(device,index);
                if(capacity<packet->Length)status=STATUS_BUFFER_TOO_SMALL;
                else {
                    completed=packet->Length;
                    if(completed)RtlCopyMemory(target,packet->Data,completed);
                    endpoint->Head=packet->Next;
                    if(endpoint->Head==VD_NONE)endpoint->Tail=VD_NONE;
                    packet->Next=device->FreeHead;device->FreeHead=index;
                    --device->Info.QueuedInputs;++device->Info.InputsCompleted;
                }
            } else if(NT_SUCCESS(status))status=STATUS_CANCELLED;
            WdfSpinLockRelease(c->Lock);
            CompleteAtDispatch(request,status,completed);
            WdfSpinLockAcquire(c->Lock);if(!--device->PumpUsers)KeSetEvent(&device->PumpIdle,IO_NO_INCREMENT,FALSE);
            WdfSpinLockRelease(c->Lock);WdfObjectDereference(device->Self);
        }
        if(++budget>=128) { repeat=TRUE;break; }
    }
    WdfSpinLockAcquire(c->Lock);repeat=repeat||c->PumpAgain;c->PumpAgain=FALSE;c->Pumping=FALSE;
    if(repeat)WdfDpcEnqueue(dpc);WdfSpinLockRelease(c->Lock);
}

static VOID ArmControlTimer(VIRTUAL_DEVICE* d) {
    WDFREQUEST found;NTSTATUS status=WdfIoQueueFindRequest(d->Controls,NULL,NULL,NULL,&found);
    if(NT_SUCCESS(status)) {
        ULONGLONG deadline=ControlGet(found)->Deadline,now=Now();
        WdfSpinLockAcquire(d->Controller->Lock);
        if(d->Active)WdfTimerStart(d->ControlTimer,-(LONGLONG)(deadline>now?deadline-now:1));
        WdfSpinLockRelease(d->Controller->Lock);
        WdfObjectDereference(found);
    }
}
VOID VdControlTimeout(WDFTIMER timer) {
    VIRTUAL_DEVICE* d=TimerGet(timer)->Device;WDFREQUEST found,request;ULONG count=0;
    while(count++<VD_MAX_CONTROLS && NT_SUCCESS(WdfIoQueueFindRequest(d->Controls,NULL,NULL,NULL,&found))) {
        ULONGLONG deadline=ControlGet(found)->Deadline;
        if(deadline>Now()) { WdfObjectDereference(found);break; }
        if(NT_SUCCESS(WdfIoQueueRetrieveFoundRequest(d->Controls,found,&request))) {
            WdfSpinLockAcquire(d->Controller->Lock);ControlGet(request)->Pending=FALSE;
            if(d->PendingControls)--d->PendingControls;ForgetControlOutputLocked(d,ControlGet(request)->Id);
            WdfSpinLockRelease(d->Controller->Lock);CompleteUrb(d->Controller,request,STATUS_IO_TIMEOUT,0);
        }
        WdfObjectDereference(found);
    }
    ArmControlTimer(d);
}
/* On success ownership belongs to the cancellable KMDF manual queue. */
static NTSTATUS DelegateControl(VIRTUAL_DEVICE* d,WDFREQUEST request,const UCHAR* setup,
    const UCHAR* data,ULONG length,ULONG capacity) {
    CONTROL_CONTEXT* context;WDF_OBJECT_ATTRIBUTES attrs;NTSTATUS status;ULONGLONG id;CONTROLLER* c=d->Controller;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,CONTROL_CONTEXT);
    status=WdfObjectAllocateContext(request,&attrs,(PVOID*)&context);
    if(!NT_SUCCESS(status) && status!=STATUS_OBJECT_NAME_EXISTS)return status;
    /* Only control setup forwarding takes this passive lock. It preserves
       FIFO deadline order when independent callers submit controls together;
       timer cancellation and the input/report fast path never acquire it. */
    WdfWaitLockAcquire(d->ControlForward,NULL);
    WdfSpinLockAcquire(c->Lock);
    if(!d->Active || d->Endpoints[0].Purging || c->Expired || c->Quiescing || c->Removing || d->PendingControls==VD_MAX_CONTROLS ||
       FileGet(d->Owner)->OutputCount+FileGet(d->Owner)->OutputReserved>=VD_MAX_OUTPUTS || c->NextRequestId==MAXULONGLONG) {
        WdfSpinLockRelease(c->Lock);WdfWaitLockRelease(d->ControlForward);return STATUS_DEVICE_BUSY;
    }
    id=++c->NextRequestId;++d->PendingControls;++FileGet(d->Owner)->OutputReserved;context->Pending=TRUE;
    context->Id=id;context->Deadline=Now()+VD_CONTROL_TIMEOUT;context->Capacity=capacity;
    RtlCopyMemory(context->Setup,setup,8);WdfSpinLockRelease(c->Lock);
    WdfObjectReference(request);
    status=WdfRequestForwardToIoQueue(request,d->Controls);
    if(!NT_SUCCESS(status)) {
        WdfSpinLockAcquire(c->Lock);context->Pending=FALSE;--d->PendingControls;--FileGet(d->Owner)->OutputReserved;
        WdfSpinLockRelease(c->Lock);WdfObjectDereference(request);
        WdfWaitLockRelease(d->ControlForward);return status;
    }
    WdfSpinLockAcquire(c->Lock);--FileGet(d->Owner)->OutputReserved;
    if(context->Pending)OutputLocked(d,VdControlRequest,0,id,setup,data,length);
    WdfSpinLockRelease(c->Lock);WdfObjectDereference(request);ArmControlTimer(d);WdfDpcEnqueue(c->Dpc);
    WdfWaitLockRelease(d->ControlForward);
    return STATUS_PENDING;
}
static NTSTATUS ControlTransfer(VIRTUAL_DEVICE* d,WDFREQUEST request,PUCHAR buffer,ULONG capacity,ULONG* completed) {
    WDF_USB_CONTROL_SETUP_PACKET setup;NTSTATUS status;ULONG i,iface,value,length;
    const UCHAR* response=NULL;ULONG responseLength=0;UCHAR tiny[2];BOOLEAN handled=FALSE;
    const VD_DESCRIPTOR* descriptors=(const VD_DESCRIPTOR*)((const UCHAR*)d->Description+d->Description->DescriptorsOffset);
    setup=CompletionGet(request)->Setup;status=STATUS_SUCCESS;
    iface=setup.Packet.wIndex.Value;value=setup.Packet.wValue.Value;length=setup.Packet.wLength;
    if(length>VD_MAX_TRANSFER)return STATUS_NOT_SUPPORTED;
    for(i=0;i<d->Description->RuleCount;++i) {
        const VD_CONTROL_RULE* rule=(const VD_CONTROL_RULE*)((const UCHAR*)d->Description+d->Description->RulesOffset+i*sizeof(VD_CONTROL_RULE));
        ULONG n;for(n=0;n<8;++n)if((setup.Generic.Bytes[n]&rule->Mask[n])!=(rule->Setup[n]&rule->Mask[n]))break;
        if(n!=8)continue;
        if(rule->Action==VdStall)return STATUS_NOT_SUPPORTED;
        if(rule->Action==VdAccept) { *completed=(setup.Packet.bm.Byte&128)?0:min(capacity,length);return STATUS_SUCCESS; }
        if(!(setup.Packet.bm.Byte&128))return STATUS_NOT_SUPPORTED;
        response=(const UCHAR*)d->Description+rule->DataOffset;responseLength=rule->DataLength;handled=TRUE;break;
    }
    if(!handled && iface<256 && d->Layout.Interfaces[iface]==2) {
        if(setup.Packet.bm.Byte==0x81 && setup.Packet.bRequest==USB_REQUEST_GET_DESCRIPTOR) {
            if((value>>8)==34 && !(value&255)) {
                const VD_DESCRIPTOR* report=&descriptors[d->Layout.ReportDescriptor[iface]];
                response=(const UCHAR*)d->Description+report->Offset;responseLength=report->Length;handled=TRUE;
            } else if((value>>8)==33 && !(value&255)) {
                const VD_DESCRIPTOR* config=&descriptors[d->Layout.ConfigurationDescriptor];
                response=(const UCHAR*)d->Description+config->Offset+d->Layout.HidDescriptorOffset[iface];
                responseLength=d->Layout.HidDescriptorLength[iface];handled=TRUE;
            }
        } else if(setup.Packet.bm.Byte==0xa1 && setup.Packet.bRequest==1) { // GET_REPORT
            LONG index=FindReport(d,iface,value>>8,value&255);
            if(!d->Protocol[iface] && d->Layout.BootProtocol[iface] && !(value&255)) {
                WdfSpinLockAcquire(d->Controller->Lock);
                if((value>>8)==1 && d->BootValid[iface]) {
                    responseLength=min(capacity,min(length,d->Layout.BootProtocol[iface]==1?8u:3u));
                    RtlCopyMemory(buffer,d->BootInput[iface],responseLength);handled=TRUE;*completed=responseLength;
                } else if((value>>8)==2 && d->Layout.BootProtocol[iface]==1 && d->BootOutputValid[iface]) {
                    responseLength=min(capacity,min(length,1u));if(responseLength)buffer[0]=d->BootOutput[iface];
                    handled=TRUE;*completed=responseLength;
                }
                WdfSpinLockRelease(d->Controller->Lock);if(handled)return STATUS_SUCCESS;
            }
            if(index>=0) {
                WdfSpinLockAcquire(d->Controller->Lock);
                if(d->Cache[index].Valid) {
                    responseLength=min(capacity,min(length,d->Layout.Reports[index].Length));
                    RtlCopyMemory(buffer,d->ReportData+d->Cache[index].Offset,responseLength);handled=TRUE;
                    *completed=responseLength;
                }
                WdfSpinLockRelease(d->Controller->Lock);
                if(handled)return STATUS_SUCCESS;
            }
        } else if(setup.Packet.bm.Byte==0x21 && setup.Packet.bRequest==9) { // SET_REPORT
            LONG index=FindReport(d,iface,value>>8,value&255);
            if(!d->Protocol[iface] && d->Layout.BootProtocol[iface]==1 && value==0x0200 && capacity==1 && length==1) {
                WdfSpinLockAcquire(d->Controller->Lock);
                if(OutputLocked(d,VdOutputData,0,0,setup.Generic.Bytes,buffer,1)) {
                    d->BootOutput[iface]=buffer[0];d->BootOutputValid[iface]=TRUE;status=STATUS_SUCCESS;*completed=1;
                } else status=STATUS_DEVICE_BUSY;
                WdfSpinLockRelease(d->Controller->Lock);WdfDpcEnqueue(d->Controller->Dpc);return status;
            }
            if(index>=0 && (value>>8)!=1 && capacity==length && length==d->Layout.Reports[index].Length &&
               (!d->Layout.UsesReportIds[iface] || (length && buffer[0]==(value&255)))) {
                WdfSpinLockAcquire(d->Controller->Lock);
                if(!OutputLocked(d,VdOutputData,0,0,setup.Generic.Bytes,buffer,length))status=STATUS_DEVICE_BUSY;
                else {
                    RtlCopyMemory(d->ReportData+d->Cache[index].Offset,buffer,length);d->Cache[index].Valid=TRUE;
                    status=STATUS_SUCCESS;*completed=length;
                }
                WdfSpinLockRelease(d->Controller->Lock);WdfDpcEnqueue(d->Controller->Dpc);return status;
            }
        } else if(setup.Packet.bm.Byte==0xa1 && setup.Packet.bRequest==2 && !(value&0xff00) && length==1 && !d->IdleDelegated[iface]) {
            LONG index=FindReport(d,iface,1,value&255);
            if(index>=0) { WdfSpinLockAcquire(d->Controller->Lock);tiny[0]=d->Idle[index];
                WdfSpinLockRelease(d->Controller->Lock);response=tiny;responseLength=1;handled=TRUE; }
        } else if(setup.Packet.bm.Byte==0x21 && setup.Packet.bRequest==10 && !length &&
                  !(value>>8) && !d->IdleDelegated[iface]) {
            WdfSpinLockAcquire(d->Controller->Lock);
            for(i=0;i<d->Layout.ReportCount;++i)if(d->Layout.Reports[i].InterfaceNumber==iface &&
                d->Layout.Reports[i].Type==1 && (!(value&255) || d->Layout.Reports[i].Id==(value&255))) {
                d->Idle[i]=(UCHAR)(value>>8);handled=TRUE;
            }
            WdfSpinLockRelease(d->Controller->Lock);if(handled)return STATUS_SUCCESS;
        } else if(setup.Packet.bm.Byte==0xa1 && setup.Packet.bRequest==3 && !value && length==1 && d->Layout.BootProtocol[iface]) {
            WdfSpinLockAcquire(d->Controller->Lock);tiny[0]=d->Protocol[iface];WdfSpinLockRelease(d->Controller->Lock);
            response=tiny;responseLength=1;handled=TRUE;
        } else if(setup.Packet.bm.Byte==0x21 && setup.Packet.bRequest==11 && value<=1 && !length && d->Layout.BootProtocol[iface]) {
            WdfSpinLockAcquire(d->Controller->Lock);
            if(d->Protocol[iface]!=(UCHAR)value) {
                for(i=1;i<=d->Layout.EndpointCount;++i)if(d->Endpoints[i].InterfaceNumber==iface) {
                    ENDPOINT* e=&d->Endpoints[i];
                    while(e->Head!=VD_NONE) { ULONG n=e->Head;e->Head=PacketAt(d,n)->Next;
                        PacketAt(d,n)->Next=d->FreeHead;d->FreeHead=n;--d->Info.QueuedInputs; }
                    e->Tail=VD_NONE;
                }
                for(i=0;i<d->Layout.ReportCount;++i)if(d->Layout.Reports[i].InterfaceNumber==iface)d->Cache[i].Valid=FALSE;
                d->BootValid[iface]=d->BootOutputValid[iface]=FALSE;d->Protocol[iface]=(UCHAR)value;
            }
            (void)OutputLocked(d,VdOutputData,0,0,setup.Generic.Bytes,NULL,0);
            WdfSpinLockRelease(d->Controller->Lock);WdfDpcEnqueue(d->Controller->Dpc);return STATUS_SUCCESS;
        }
    }
    if(handled) {
        *completed=min(capacity,min(length,responseLength));
        if(*completed)RtlCopyMemory(buffer,response,*completed);return STATUS_SUCCESS;
    }
    /* Standard requests for absent descriptors (notably Microsoft OS string
       0xEE) must fail immediately so Windows can continue enumeration. Static
       rules above may explicitly implement them. Only class/vendor requests
       have a user-mode protocol responder. */
    if((setup.Packet.bm.Byte&0x60)!=0x20 && (setup.Packet.bm.Byte&0x60)!=0x40)return STATUS_NOT_SUPPORTED;
    if(d->Description->Flags&VdDelegateControls) {
        ULONG outputLength=(setup.Packet.bm.Byte&128)?0:min(capacity,length);
        if(iface<256 && d->Layout.Interfaces[iface]==2 && setup.Packet.bm.Byte==0x21 &&
           setup.Packet.bRequest==10 && !length) {
            WdfSpinLockAcquire(d->Controller->Lock);d->IdleDelegated[iface]=TRUE;WdfSpinLockRelease(d->Controller->Lock);
        }
        return DelegateControl(d,request,setup.Generic.Bytes,buffer,outputLength,min(capacity,length));
    }
    return STATUS_NOT_SUPPORTED;
}
VOID VdUrb(WDFQUEUE queue,WDFREQUEST request,size_t output,size_t input,ULONG code) {
    ENDPOINT* endpoint=QueueGet(queue)->Endpoint;VIRTUAL_DEVICE* d=endpoint->Device;
    CONTROLLER* c=d->Controller;NTSTATUS status;PUCHAR buffer=NULL;ULONG capacity=0,completed=0;
    UNREFERENCED_PARAMETER(output);UNREFERENCED_PARAMETER(input);UNREFERENCED_PARAMETER(code);
    COMPLETION* context;
    WdfSpinLockAcquire(c->Lock);
    status=(!d->Active || c->Removing || c->Quiescing || c->Expired)?STATUS_DEVICE_NOT_CONNECTED:STATUS_SUCCESS;
    if(NT_SUCCESS(status) && endpoint->Address) {
        /* Initial simple-endpoint activation does not always invoke a link
           power transition callback. A real host data URB is concrete proof
           that Windows configured and is using this endpoint. Respect UdeCx
           purging: a callback delivered after purge must not reactivate it. */
        if(endpoint->Purging || !WDF_IO_QUEUE_READY(WdfIoQueueGetState(queue,NULL,NULL)))status=STATUS_CANCELLED;
        else {
            ULONG previous=d->Info.Flags;endpoint->Started=TRUE;
            d->Info.Flags|=VdConfigured|VdPowered;
            if(previous!=d->Info.Flags)StateLocked(d);
        }
    }
    if(NT_SUCCESS(status) && !d->SourceUsers++)KeClearEvent(&d->SourceIdle);
    WdfSpinLockRelease(c->Lock);
    if(!NT_SUCCESS(status)) { CompleteUrb(c,request,status,0);return; }
    context=CompletionGet(request);
    if(!context) {
        WDF_OBJECT_ATTRIBUTES attrs;
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,COMPLETION);
        status=WdfObjectAllocateContext(request,&attrs,(PVOID*)&context);
        if(!NT_SUCCESS(status) && status!=STATUS_OBJECT_NAME_EXISTS) { CompleteUrb(c,request,status,0);goto exit; }
    }
    if(NT_SUCCESS(status) && !endpoint->Address) {
        status=UdecxUrbRetrieveControlSetupPacket(request,&context->Setup);
        if(NT_SUCCESS(status) && context->Setup.Packet.wLength)status=UdecxUrbRetrieveBuffer(request,&buffer,&capacity);
    } else if(NT_SUCCESS(status))status=UdecxUrbRetrieveBuffer(request,&buffer,&capacity);
    context->Buffer=buffer;context->Capacity=capacity;
    if(NT_SUCCESS(status) && (endpoint->Address&128)) {
        status=WdfRequestForwardToIoQueue(request,endpoint->Reads);
        if(NT_SUCCESS(status)) { WdfDpcEnqueue(c->Dpc);goto exit; }
    } else if(NT_SUCCESS(status) && !endpoint->Address)status=ControlTransfer(d,request,buffer,capacity,&completed);
    else if(NT_SUCCESS(status)) {
        if(capacity>VD_MAX_TRANSFER)status=STATUS_BUFFER_OVERFLOW;
        else {
            LONG report=-1;BOOLEAN boot=FALSE;
            WdfSpinLockAcquire(c->Lock);
            if(d->Layout.Interfaces[endpoint->InterfaceNumber]==2) {
                ULONG iface=endpoint->InterfaceNumber;
                boot=!d->Protocol[iface] && d->Layout.BootProtocol[iface]==1;
                if(boot) { if(capacity!=1)status=STATUS_INVALID_PARAMETER; }
                else {
                    ULONG id=d->Layout.UsesReportIds[iface]?(capacity?buffer[0]:256):0;
                    report=FindReport(d,iface,2,id);
                    if(report<0 || capacity!=d->Layout.Reports[report].Length)status=STATUS_INVALID_PARAMETER;
                }
            }
            if(NT_SUCCESS(status)) {
                if(!OutputLocked(d,VdOutputData,endpoint->Address,0,NULL,buffer,capacity))status=STATUS_DEVICE_BUSY;
                else {
                    completed=capacity;
                    if(report>=0) { RtlCopyMemory(d->ReportData+d->Cache[report].Offset,buffer,capacity);d->Cache[report].Valid=TRUE; }
                    if(boot) { d->BootOutput[endpoint->InterfaceNumber]=buffer[0];d->BootOutputValid[endpoint->InterfaceNumber]=TRUE; }
                }
            }
            WdfSpinLockRelease(c->Lock);WdfDpcEnqueue(c->Dpc);
        }
    }
    if(status!=STATUS_PENDING)CompleteUrb(c,request,status,completed);
exit:
    WdfSpinLockAcquire(c->Lock);if(!--d->SourceUsers)KeSetEvent(&d->SourceIdle,IO_NO_INCREMENT,FALSE);WdfSpinLockRelease(c->Lock);
}

VOID VdEndpointReset(UDECXUSBENDPOINT endpoint,WDFREQUEST request) {
    ENDPOINT* e=EndpointGet(endpoint)->Endpoint;CONTROLLER* c=e->Device->Controller;
    WdfSpinLockAcquire(c->Lock);
    while(e->Head!=VD_NONE) {
        ULONG index=e->Head;e->Head=PacketAt(e->Device,index)->Next;
        PacketAt(e->Device,index)->Next=e->Device->FreeHead;e->Device->FreeHead=index;
        --e->Device->Info.QueuedInputs;
    }
    e->Tail=VD_NONE;WdfSpinLockRelease(c->Lock);WdfRequestComplete(request,STATUS_SUCCESS);
}
VOID VdEndpointStart(UDECXUSBENDPOINT endpoint) {
    ENDPOINT* e=EndpointGet(endpoint)->Endpoint;VIRTUAL_DEVICE* d=e->Device;CONTROLLER* c=d->Controller;
    BOOLEAN orphan;
    WdfSpinLockAcquire(c->Lock);
    if(d->Active && !c->Expired && !c->Removing && !c->Quiescing) {
        e->Started=TRUE;e->Purging=FALSE;
        if(e->Address && (d->Info.Flags&(VdConfigured|VdPowered))!=(VdConfigured|VdPowered)) {
            d->Info.Flags|=VdConfigured|VdPowered;StateLocked(d);
        }
    }
    orphan=FileGet(d->Owner)->Closing && !c->Removing;
    WdfSpinLockRelease(c->Lock);
    if(e->Reads)WdfIoQueueStart(e->Reads);
    if(!e->Address) {
        WdfIoQueueStart(d->Controls);
        KeSetEvent(&d->EnumerationReady,IO_NO_INCREMENT,FALSE);
        if(orphan)WdfWorkItemEnqueue(c->ExpireWork);
    }
    WdfDpcEnqueue(c->Dpc);
}
VOID VdPurged(WDFQUEUE queue,WDFCONTEXT context) {
    ENDPOINT* e=(ENDPOINT*)context;
    UNREFERENCED_PARAMETER(queue);UdecxUsbEndpointPurgeComplete(e->Usb);
}
VOID VdEndpointPurge(UDECXUSBENDPOINT endpoint) {
    ENDPOINT* e=EndpointGet(endpoint)->Endpoint;VIRTUAL_DEVICE* d=e->Device;CONTROLLER* c=d->Controller;
    ULONG i;BOOLEAN any=FALSE;
    WdfSpinLockAcquire(c->Lock);e->Started=FALSE;e->Purging=TRUE;
    while(e->Head!=VD_NONE) {
        ULONG index=e->Head;e->Head=PacketAt(d,index)->Next;PacketAt(d,index)->Next=d->FreeHead;d->FreeHead=index;
        --d->Info.QueuedInputs;
    }
    e->Tail=VD_NONE;
    for(i=1;i<=d->Layout.EndpointCount;++i)if(d->Endpoints[i].Started)any=TRUE;
    if(!any && (d->Info.Flags&VdConfigured)) { d->Info.Flags&=~VdConfigured;StateLocked(d); }
    WdfSpinLockRelease(c->Lock);
    if(e->Reads)WdfIoQueuePurge(e->Reads,VdPurged,e);
    else if(!e->Address)WdfIoQueuePurge(d->Controls,VdPurged,e);
    else UdecxUsbEndpointPurgeComplete(endpoint);
    WdfDpcEnqueue(c->Dpc);
}
NTSTATUS VdPowerEntry(WDFDEVICE controller,UDECXUSBDEVICE usb) {
    VIRTUAL_DEVICE* d=UsbGet(usb)->Device;CONTROLLER* c=ControllerGet(controller);
    WdfSpinLockAcquire(c->Lock);
    if(d->Active && !TrialExpiredLocked(c) && !c->Removing && !c->Quiescing) { d->Info.Flags|=VdPowered;StateLocked(d); }
    WdfSpinLockRelease(c->Lock);WdfDpcEnqueue(c->Dpc);return STATUS_SUCCESS;
}
NTSTATUS VdPowerExit(WDFDEVICE controller,UDECXUSBDEVICE usb,UDECX_USB_DEVICE_WAKE_SETTING wake) {
    VIRTUAL_DEVICE* d=UsbGet(usb)->Device;CONTROLLER* c=ControllerGet(controller);
    UNREFERENCED_PARAMETER(wake);
    WdfSpinLockAcquire(c->Lock);d->Info.Flags&=~VdPowered;StateLocked(d);WdfSpinLockRelease(c->Lock);
    WdfDpcEnqueue(c->Dpc);return STATUS_SUCCESS;
}
static NTSTATUS CreateQueue(CONTROLLER* c,VIRTUAL_DEVICE* d,WDFFILEOBJECT owner,ENDPOINT* endpoint,BOOLEAN reads,WDFQUEUE* queue) {
    WDF_IO_QUEUE_CONFIG config;WDF_OBJECT_ATTRIBUTES attrs;NTSTATUS status;BOOLEAN manual=owner || !endpoint || reads;
    WDF_IO_QUEUE_CONFIG_INIT(&config,manual?WdfIoQueueDispatchManual:WdfIoQueueDispatchParallel);
    config.PowerManaged=WdfFalse;config.EvtIoCanceledOnQueue=VdCancel;
    if(!manual)config.EvtIoInternalDeviceControl=VdUrb;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,QUEUE_CONTEXT);
    attrs.ExecutionLevel=manual?WdfExecutionLevelDispatch:WdfExecutionLevelPassive;attrs.SynchronizationScope=WdfSynchronizationScopeNone;
    attrs.EvtDestroyCallback=VdQueueDestroy;
    status=WdfIoQueueCreate(c->Device,&config,&attrs,queue);if(!NT_SUCCESS(status))return status;
    QueueGet(*queue)->Controller=c;QueueGet(*queue)->Device=d;QueueGet(*queue)->Owner=owner;
    QueueGet(*queue)->Endpoint=endpoint;
    if(d)WdfObjectReference(d->Self);if(owner)WdfObjectReference(owner);
    if(manual && (endpoint || owner))return WdfIoQueueReadyNotify(*queue,VdReady,NULL);
    return STATUS_SUCCESS;
}
static NTSTATUS CreateEndpoint(VIRTUAL_DEVICE* d,ULONG index,ULONG address,ULONG iface) {
    PUDECXUSBENDPOINT_INIT init;WDF_OBJECT_ATTRIBUTES attrs;UDECX_USB_ENDPOINT_CALLBACKS callbacks;
    ENDPOINT* e=&d->Endpoints[index];NTSTATUS status;
    e->Device=d;e->Address=address;e->InterfaceNumber=iface;e->Head=e->Tail=VD_NONE;
    init=UdecxUsbSimpleEndpointInitAllocate(d->Usb);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
    UdecxUsbEndpointInitSetEndpointAddress(init,(UCHAR)address);
    UDECX_USB_ENDPOINT_CALLBACKS_INIT(&callbacks,VdEndpointReset);
    callbacks.EvtUsbEndpointStart=VdEndpointStart;callbacks.EvtUsbEndpointPurge=VdEndpointPurge;
    UdecxUsbEndpointInitSetCallbacks(init,&callbacks);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,ENDPOINT_CONTEXT);
    status=UdecxUsbEndpointCreate(&init,&attrs,&e->Usb);
    if(!NT_SUCCESS(status)) { if(init)UdecxUsbEndpointInitFree(init);return status; }
    EndpointGet(e->Usb)->Endpoint=e;
    status=CreateQueue(d->Controller,d,NULL,e,FALSE,&e->Queue);
    if(NT_SUCCESS(status) && (address&128))status=CreateQueue(d->Controller,d,NULL,e,TRUE,&e->Reads);
    if(NT_SUCCESS(status))UdecxUsbEndpointSetWdfIoQueue(e->Usb,e->Queue);
    return status;
}
/* PASSIVE_LEVEL, management lock held. References held by USB/queue objects
   postpone freeing backing storage until the last callback and DPC retire. */
static NTSTATUS DeleteVirtual(VIRTUAL_DEVICE* d,BOOLEAN controllerRemoval) {
    CONTROLLER* c=d->Controller;ULONG i;NTSTATUS status=STATUS_SUCCESS;
    if(d->WasPlugged && !controllerRemoval) {
        LARGE_INTEGER due;due.QuadPart=-5ll*10000000ll;
        // UDE can retain an object unplugged before its first EP0 start.
        // Synchronize deletion with the real event, without polling or a
        // fixed delay. A timeout preserves the live object and its port so
        // DELETE can be retried; no successful removal is reported early.
        if(KeWaitForSingleObject(&d->EnumerationReady,Executive,KernelMode,FALSE,&due)!=STATUS_SUCCESS)
            return STATUS_DEVICE_BUSY;
    }
    WdfSpinLockAcquire(c->Lock);d->Active=FALSE;
    DropInputsLocked(d);ForgetOutputsLocked(d);d->Info.Flags=0;
    WdfSpinLockRelease(c->Lock);
    KeWaitForSingleObject(&d->PumpIdle,Executive,KernelMode,FALSE,NULL);
    KeWaitForSingleObject(&d->SourceIdle,Executive,KernelMode,FALSE,NULL);
    if(d->ControlTimer)WdfTimerStop(d->ControlTimer,TRUE);
    if(d->Controls)WdfIoQueuePurgeSynchronously(d->Controls);
    for(i=0;i<=d->Layout.EndpointCount;++i)if(d->Endpoints[i].Reads)WdfIoQueuePurgeSynchronously(d->Endpoints[i].Reads);
    if(!controllerRemoval && d->Usb) {
        if(d->WasPlugged)status=UdecxUsbDevicePlugOutAndDelete(d->Usb);
        else WdfObjectDelete(d->Usb);
        /* A failed unplug must keep all backing objects and reserve its port.
           The owner can retry DELETE, or controller PnP removal retires it. */
        if(!NT_SUCCESS(status))return status;
        d->Usb=NULL;
    }
    WdfSpinLockAcquire(c->Lock);if(c->Devices[d->Slot]==d)c->Devices[d->Slot]=NULL;WdfSpinLockRelease(c->Lock);
    for(i=0;i<=d->Layout.EndpointCount;++i)if(d->Endpoints[i].Queue)WdfIoQueuePurgeSynchronously(d->Endpoints[i].Queue);
    if(controllerRemoval)return STATUS_SUCCESS; // UdeCx owns child removal during controller PnP teardown.
    for(i=0;i<=d->Layout.EndpointCount;++i) {
        if(d->Endpoints[i].Queue)WdfObjectDelete(d->Endpoints[i].Queue);
        if(d->Endpoints[i].Reads)WdfObjectDelete(d->Endpoints[i].Reads);
    }
    if(d->Controls)WdfObjectDelete(d->Controls);
    if(d->ControlTimer)WdfObjectDelete(d->ControlTimer);
    if(d->ControlForward)WdfObjectDelete(d->ControlForward);
    WdfObjectDelete(d->Self);
    return STATUS_SUCCESS;
}
static NTSTATUS Plug(CONTROLLER* c,WDFFILEOBJECT owner,const VD_CREATE* description,VIRTUAL_DEVICE** returned) {
    VIRTUAL_DEVICE* d;WDFOBJECT object;WDF_OBJECT_ATTRIBUTES attrs;NTSTATUS status;ULONG slot,i,cacheLength=0,outputCapacity=4;
    PUDECXUSBDEVICE_INIT init=NULL;UDECX_USB_DEVICE_STATE_CHANGE_CALLBACKS callbacks;
    UDECX_USB_DEVICE_PLUG_IN_OPTIONS options;WDF_TIMER_CONFIG timer;const VD_DESCRIPTOR* descriptors;int validation;
    WdfSpinLockAcquire(c->Lock);
    if(c->Removing || c->Quiescing || TrialExpiredLocked(c) || FileGet(owner)->Closing || c->NextDeviceId==MAXULONGLONG) {
        WdfSpinLockRelease(c->Lock);return STATUS_ACCESS_DENIED;
    }
    for(slot=0;slot<VD_MAX_DEVICES && c->Devices[slot];++slot) { }
    WdfSpinLockRelease(c->Lock);if(slot==VD_MAX_DEVICES)return STATUS_TOO_MANY_NAMES;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,VIRTUAL_DEVICE);attrs.ParentObject=c->Device;attrs.EvtDestroyCallback=VdVirtualDestroy;
    status=WdfObjectCreate(&attrs,&object);if(!NT_SUCCESS(status))return status;
    d=VirtualGet(object);d->Self=object;d->Controller=c;d->Owner=owner;WdfObjectReference(owner);d->Slot=slot;
    KeInitializeEvent(&d->PumpIdle,NotificationEvent,TRUE);
    KeInitializeEvent(&d->SourceIdle,NotificationEvent,TRUE);
    KeInitializeEvent(&d->EnumerationReady,NotificationEvent,FALSE);
    d->Description=ExAllocatePool2(POOL_FLAG_NON_PAGED,description->TotalSize,VD_TAG);
    if(!d->Description) { status=STATUS_INSUFFICIENT_RESOURCES;goto fail; }
    RtlCopyMemory(d->Description,description,description->TotalSize);
    validation=VdValidateCreate(d->Description,d->Description->TotalSize,&d->Layout);
    if(validation) { status=validation==VdUnsupported?STATUS_NOT_SUPPORTED:STATUS_INVALID_PARAMETER;goto fail; }
    d->InputDepth=description->InputDepth;
    for(i=0;i<d->Layout.ReportCount;++i) {
        const VD_REPORT_LAYOUT* report=&d->Layout.Reports[i];
        d->Cache[i].Offset=cacheLength;cacheLength+=report->Length;
        if(report->Type==1)d->InputCapacity=max(d->InputCapacity,report->Length);
        else outputCapacity=max(outputCapacity,report->Length);
    }
    for(i=0;i<256;++i)if(d->Layout.BootProtocol[i])d->InputCapacity=max(d->InputCapacity,d->Layout.BootProtocol[i]==1?8u:3u);
    for(i=0;i<d->Layout.EndpointCount;++i)if(d->Layout.Interfaces[d->Layout.Endpoints[i].InterfaceNumber]!=2) {
        if(d->Layout.Endpoints[i].Address&128)d->InputCapacity=VD_MAX_TRANSFER;else outputCapacity=VD_MAX_TRANSFER;
    }
    if(description->Flags&VdDelegateControls)outputCapacity=VD_MAX_TRANSFER;
    if(d->InputCapacity) {
        d->PacketStride=(FIELD_OFFSET(PACKET,Data)+d->InputCapacity+7u)&~7u;
        d->Packets=ExAllocatePool2(POOL_FLAG_NON_PAGED,(SIZE_T)d->InputDepth*d->PacketStride,VD_TAG);
        if(!d->Packets) { status=STATUS_INSUFFICIENT_RESOURCES;goto fail; }
    }
    status=EnsureOutputRing(FileGet(owner),outputCapacity);if(!NT_SUCCESS(status))goto fail;
    if(cacheLength) {
        d->ReportData=ExAllocatePool2(POOL_FLAG_NON_PAGED,cacheLength,VD_TAG);
        if(!d->ReportData) { status=STATUS_INSUFFICIENT_RESOURCES;goto fail; }
    }
    RtlFillMemory(d->Protocol,sizeof(d->Protocol),1);DropInputsLocked(d);
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);attrs.ParentObject=c->Device;
    status=WdfWaitLockCreate(&attrs,&d->ControlForward);if(!NT_SUCCESS(status))goto fail;
    status=CreateQueue(c,d,NULL,NULL,FALSE,&d->Controls);if(!NT_SUCCESS(status))goto fail;
    WDF_TIMER_CONFIG_INIT(&timer,VdControlTimeout);timer.AutomaticSerialization=FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,TIMER_CONTEXT);attrs.ParentObject=c->Device;
    status=WdfTimerCreate(&timer,&attrs,&d->ControlTimer);if(!NT_SUCCESS(status))goto fail;
    TimerGet(d->ControlTimer)->Device=d;
    init=UdecxUsbDeviceInitAllocate(c->Device);if(!init) { status=STATUS_INSUFFICIENT_RESOURCES;goto fail; }
    UDECX_USB_DEVICE_CALLBACKS_INIT(&callbacks);callbacks.EvtUsbDeviceLinkPowerEntry=VdPowerEntry;
    callbacks.EvtUsbDeviceLinkPowerExit=VdPowerExit;
    UdecxUsbDeviceInitSetStateChangeCallbacks(init,&callbacks);
    UdecxUsbDeviceInitSetSpeed(init,description->Speed==VdLowSpeed?UdecxUsbLowSpeed:
        description->Speed==VdHighSpeed?UdecxUsbHighSpeed:UdecxUsbFullSpeed);
    UdecxUsbDeviceInitSetEndpointsType(init,UdecxEndpointTypeSimple);
    descriptors=(const VD_DESCRIPTOR*)((const UCHAR*)d->Description+d->Description->DescriptorsOffset);
    for(i=0;i<description->DescriptorCount;++i) {
        const VD_DESCRIPTOR* descriptor=&descriptors[i];PUCHAR bytes=(PUCHAR)d->Description+descriptor->Offset;
        if(descriptor->Kind!=VdStandardDescriptor)continue;
        if(bytes[1]==3 && descriptor->Index && descriptor->Language)
            status=UdecxUsbDeviceInitAddStringDescriptorRaw(init,bytes,(USHORT)descriptor->Length,(UCHAR)descriptor->Index,(USHORT)descriptor->Language);
        else status=UdecxUsbDeviceInitAddDescriptorWithIndex(init,bytes,(USHORT)descriptor->Length,(UCHAR)descriptor->Index);
        if(!NT_SUCCESS(status))goto fail;
    }
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,USB_CONTEXT);attrs.EvtDestroyCallback=VdUsbDestroy;
    status=UdecxUsbDeviceCreate(&init,&attrs,&d->Usb);if(!NT_SUCCESS(status))goto fail;
    UsbGet(d->Usb)->Device=d;WdfObjectReference(object);
    status=CreateEndpoint(d,0,0,0);if(!NT_SUCCESS(status))goto fail;
    for(i=0;i<d->Layout.EndpointCount;++i) {
        status=CreateEndpoint(d,i+1,d->Layout.Endpoints[i].Address,d->Layout.Endpoints[i].InterfaceNumber);
        if(!NT_SUCCESS(status))goto fail;
    }
    WdfSpinLockAcquire(c->Lock);d->Info.Id=++c->NextDeviceId;d->Info.EndpointCount=d->Layout.EndpointCount;
    d->Active=TRUE;d->Info.Flags=VdPlugged;c->Devices[slot]=d;WdfSpinLockRelease(c->Lock);
    UDECX_USB_DEVICE_PLUG_IN_OPTIONS_INIT(&options);options.Usb20PortNumber=(USHORT)(slot+1);
    status=UdecxUsbDevicePlugIn(d->Usb,&options);if(!NT_SUCCESS(status))goto fail;
    d->WasPlugged=TRUE;status=TrialStart(c);if(!NT_SUCCESS(status))goto fail;
    *returned=d;return STATUS_SUCCESS;
fail:
    if(init)UdecxUsbDeviceInitFree(init);
    (void)DeleteVirtual(d,FALSE);return status;
}

VOID VdFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT object) {
    CONTROLLER* c=ControllerGet(device);FILE_CONTEXT* file=FileGet(object);NTSTATUS status;
    file->Controller=c;file->Self=object;InitializeListHead(&file->Link);
    KeInitializeEvent(&file->PumpIdle,NotificationEvent,TRUE);
    WdfSpinLockAcquire(c->Lock);
    if(c->Removing || c->FileCount==VD_MAX_FILES)status=STATUS_DEVICE_BUSY;
    else { ++c->FileCount;file->Listed=TRUE;InsertTailList(&c->Files,&file->Link);status=STATUS_SUCCESS; }
    WdfSpinLockRelease(c->Lock);
    if(NT_SUCCESS(status))status=CreateQueue(c,NULL,object,NULL,FALSE,&file->Events);
    if(!NT_SUCCESS(status)) {
        WdfSpinLockAcquire(c->Lock);file->Closing=TRUE;
        if(file->Listed) { file->Listed=FALSE;RemoveEntryList(&file->Link);--c->FileCount; }
        WdfSpinLockRelease(c->Lock);
        if(file->Events) { WdfObjectDelete(file->Events);file->Events=NULL; }
    }
    WdfRequestComplete(request,status);
}
VOID VdFileCleanup(WDFFILEOBJECT object) {
    FILE_CONTEXT* file=FileGet(object);CONTROLLER* c=file->Controller;ULONG i;
    WdfSpinLockAcquire(c->Lock);file->Closing=TRUE;
    if(file->Listed) { file->Listed=FALSE;RemoveEntryList(&file->Link);--c->FileCount; }
    WdfSpinLockRelease(c->Lock);
    WdfWaitLockAcquire(c->Management,NULL);
    for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i] && c->Devices[i]->Owner==object)(void)DeleteVirtual(c->Devices[i],c->Removing);
    WdfWaitLockRelease(c->Management);
    KeWaitForSingleObject(&file->PumpIdle,Executive,KernelMode,FALSE,NULL);
    if(file->Events) { WdfIoQueuePurgeSynchronously(file->Events);WdfObjectDelete(file->Events); }
}
/* Management lock held. New RECEIVE requests are already rejected by the
   shutdown flag. Snapshot references keep queues valid during cancellation. */
static VOID PurgeOwnerEvents(CONTROLLER* c) {
    WDFQUEUE events[VD_MAX_FILES];ULONG count=0,i;LIST_ENTRY* link;
    WdfSpinLockAcquire(c->Lock);
    for(link=c->Files.Flink;link!=&c->Files && count<VD_MAX_FILES;link=link->Flink) {
        FILE_CONTEXT* file=CONTAINING_RECORD(link,FILE_CONTEXT,Link);
        if(file->Events) { events[count++]=file->Events;WdfObjectReference(file->Events); }
    }
    WdfSpinLockRelease(c->Lock);
    for(i=0;i<count;++i) { WdfIoQueuePurgeSynchronously(events[i]);WdfObjectDereference(events[i]); }
}
static NTSTATUS Send(CONTROLLER* c,WDFFILEOBJECT owner,const VD_TRANSFER* transfer,const UCHAR* bytes) {
    VIRTUAL_DEVICE* d;ENDPOINT* endpoint=NULL;ULONG i,index;LONG report=-1;NTSTATUS status=STATUS_SUCCESS;BOOLEAN boot=FALSE;
    WdfSpinLockAcquire(c->Lock);d=FindLocked(c,owner,transfer->Id);
    if(!d)status=STATUS_NOT_FOUND;
    else if(c->Removing || c->Quiescing)status=STATUS_DELETE_PENDING;
    else if(TrialExpiredLocked(c))status=STATUS_ACCESS_DENIED;
    else {
        for(i=1;i<=d->Layout.EndpointCount;++i)if(d->Endpoints[i].Address==transfer->Endpoint) { endpoint=&d->Endpoints[i];break; }
        if(!endpoint || !(endpoint->Address&128))status=STATUS_INVALID_PARAMETER;
        else {
            if(d->Layout.Interfaces[endpoint->InterfaceNumber]==2) {
                ULONG iface=endpoint->InterfaceNumber;
                boot=!d->Protocol[iface] && d->Layout.BootProtocol[iface];
                if(boot) { if(transfer->Length!=(d->Layout.BootProtocol[iface]==1?8u:3u))status=STATUS_INVALID_PARAMETER; }
                else {
                    ULONG id=d->Layout.UsesReportIds[iface]?(transfer->Length?bytes[0]:256):0;
                    report=FindReport(d,iface,1,id);
                    if(report<0 || transfer->Length!=d->Layout.Reports[report].Length)status=STATUS_INVALID_PARAMETER;
                }
            }
            if(transfer->Length>d->InputCapacity)status=STATUS_INVALID_PARAMETER;
            if(NT_SUCCESS(status) && d->FreeHead==VD_NONE)status=STATUS_DEVICE_BUSY;
            if(NT_SUCCESS(status)) {
                PACKET* packet;index=d->FreeHead;packet=PacketAt(d,index);d->FreeHead=packet->Next;
                packet->Next=VD_NONE;packet->Length=transfer->Length;
                if(transfer->Length)RtlCopyMemory(packet->Data,bytes,transfer->Length);
                if(endpoint->Tail!=VD_NONE)PacketAt(d,endpoint->Tail)->Next=index;else endpoint->Head=index;
                endpoint->Tail=index;++d->Info.InputsAccepted;++d->Info.QueuedInputs;
                if(report>=0) { RtlCopyMemory(d->ReportData+d->Cache[report].Offset,bytes,transfer->Length);d->Cache[report].Valid=TRUE; }
                if(boot) { RtlCopyMemory(d->BootInput[endpoint->InterfaceNumber],bytes,transfer->Length);d->BootValid[endpoint->InterfaceNumber]=TRUE; }
            }
        }
    }
    WdfSpinLockRelease(c->Lock);if(NT_SUCCESS(status))WdfDpcEnqueue(c->Dpc);return status;
}
static NTSTATUS Respond(VIRTUAL_DEVICE* d,const VD_RESPONSE* response,const UCHAR* bytes) {
    WDFREQUEST found=NULL,previous=NULL,request;NTSTATUS status;ULONG completed=0;PUCHAR buffer;ULONG capacity;
    do {
        status=WdfIoQueueFindRequest(d->Controls,previous,NULL,NULL,&found);
        if(previous)WdfObjectDereference(previous);previous=NULL;
        if(!NT_SUCCESS(status))return STATUS_NOT_FOUND;
        if(ControlGet(found)->Id==response->RequestId)break;
        previous=found;found=NULL;
    } while(TRUE);
    status=WdfIoQueueRetrieveFoundRequest(d->Controls,found,&request);WdfObjectDereference(found);
    if(!NT_SUCCESS(status))return STATUS_NOT_FOUND;
    WdfSpinLockAcquire(d->Controller->Lock);ControlGet(request)->Pending=FALSE;
    if(d->PendingControls)--d->PendingControls;ForgetControlOutputLocked(d,ControlGet(request)->Id);
    WdfSpinLockRelease(d->Controller->Lock);
    if(response->Stall)status=STATUS_NOT_SUPPORTED;
    else if(!(ControlGet(request)->Setup[0]&128) && response->Length)status=STATUS_INVALID_PARAMETER;
    else if(response->Length>ControlGet(request)->Capacity)status=STATUS_INVALID_PARAMETER;
    else {
        buffer=CompletionGet(request)->Buffer;capacity=CompletionGet(request)->Capacity;status=STATUS_SUCCESS;
        if(NT_SUCCESS(status)) {
            completed=(ControlGet(request)->Setup[0]&128)?response->Length:ControlGet(request)->Capacity;
            if(response->Length)RtlCopyMemory(buffer,bytes,response->Length);
        }
    }
    CompleteUrb(d->Controller,request,status,completed);ArmControlTimer(d);
    return status==STATUS_NOT_SUPPORTED && response->Stall?STATUS_SUCCESS:status;
}
VOID VdIoctl(WDFQUEUE queue,WDFREQUEST request,size_t outSize,size_t inSize,ULONG code) {
    CONTROLLER* c=ControllerGet(WdfIoQueueGetDevice(queue));WDFFILEOBJECT owner=WdfRequestGetFileObject(request);
    PVOID input=NULL,output=NULL;size_t information=0;NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;BOOLEAN locked=FALSE;
    if(UdecxWdfDeviceTryHandleUserIoctl(c->Device,request))return;
    if(!owner) { WdfRequestComplete(request,STATUS_ACCESS_DENIED);return; }
    if(inSize) { status=WdfRequestRetrieveInputBuffer(request,1,&input,NULL);if(!NT_SUCCESS(status))goto done; }
    if(outSize) { status=WdfRequestRetrieveOutputBuffer(request,1,&output,NULL);if(!NT_SUCCESS(status))goto done; }
    if(code==VD_QUERY && !inSize && outSize>=sizeof(VD_INFO)) {
        VD_INFO info;RtlZeroMemory(&info,sizeof(info));info.Version=VD_VERSION;info.MaxDevices=VD_MAX_DEVICES;
        info.MaxTransfer=VD_MAX_TRANSFER;info.MaxCreate=VD_MAX_CREATE;info.LowSpeed=info.FullSpeed=info.HighSpeed=1;
        info.Reserved=VD_TRIAL_SECONDS;
        WdfSpinLockAcquire(c->Lock);info.Reserved2=(c->Quiescing?VdControllerQuiescing:0)|(c->Removing?VdControllerRemoving:0);
        WdfSpinLockRelease(c->Lock);
        WdfSpinLockAcquire(c->Lock);info.TrialExpired=TrialExpiredLocked(c);info.TrialStarted100ns=c->TrialStart;
        { ULONGLONG elapsed=c->TrialStart?Now()-c->TrialStart:0;
          info.TrialRemaining100ns=(c->Expired || elapsed>=VD_TRIAL_DURATION)?0:VD_TRIAL_DURATION-elapsed; }
        WdfSpinLockRelease(c->Lock);RtlCopyMemory(output,&info,sizeof(info));information=sizeof(info);status=STATUS_SUCCESS;
    } else if(code==VD_SEND && inSize>=sizeof(VD_TRANSFER)) {
        VD_TRANSFER transfer=*(VD_TRANSFER*)input;
        if(transfer.Length>VD_MAX_TRANSFER || inSize!=sizeof(transfer)+transfer.Length || transfer.Endpoint>255)status=STATUS_INVALID_PARAMETER;
        else status=Send(c,owner,&transfer,(const UCHAR*)input+sizeof(transfer));
    } else if(code==VD_RECEIVE && !inSize && outSize>=sizeof(VD_OUTPUT)) {
        WdfSpinLockAcquire(c->Lock);status=(c->Removing || c->Quiescing || FileGet(owner)->Closing)?STATUS_DELETE_PENDING:
            TrialExpiredLocked(c)?STATUS_EVALUATION_EXPIRATION:STATUS_SUCCESS;
        WdfSpinLockRelease(c->Lock);
        if(NT_SUCCESS(status)) {
            status=WdfRequestForwardToIoQueue(request,FileGet(owner)->Events);
            if(NT_SUCCESS(status)) { WdfDpcEnqueue(c->Dpc);return; }
        }
    } else if(code==VD_LIST && !inSize && outSize>=sizeof(VD_DEVICE_LIST)) {
        VD_DEVICE_LIST* list=output;ULONG i;RtlZeroMemory(list,sizeof(*list));
        WdfSpinLockAcquire(c->Lock);
        for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i] && c->Devices[i]->Owner==owner && c->Devices[i]->Active)
            list->Devices[list->Count++]=c->Devices[i]->Info;
        WdfSpinLockRelease(c->Lock);information=sizeof(*list);status=STATUS_SUCCESS;
    } else if(code==VD_QUIESCE && !inSize && !outSize) {
        ULONG i;NTSTATUS failure=STATUS_SUCCESS;
        WdfWaitLockAcquire(c->Management,NULL);locked=TRUE;
        WdfSpinLockAcquire(c->Lock);c->Quiescing=TRUE;WdfSpinLockRelease(c->Lock);
        WdfTimerStop(c->TrialTimer,TRUE);
        for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i]) {
            NTSTATUS deleted=DeleteVirtual(c->Devices[i],c->Removing);
            if(!NT_SUCCESS(deleted) && NT_SUCCESS(failure))failure=deleted;
        }
        PurgeOwnerEvents(c);status=failure;
    } else if(code==VD_CREATE_DEVICE || code==VD_DELETE_DEVICE || code==VD_RESPOND) {
        VIRTUAL_DEVICE* d=NULL;WdfWaitLockAcquire(c->Management,NULL);locked=TRUE;
        if(code==VD_CREATE_DEVICE && inSize>=sizeof(VD_CREATE) && inSize<=VD_MAX_CREATE &&
           ((VD_CREATE*)input)->TotalSize==inSize && outSize>=sizeof(VD_ID)) {
            status=Plug(c,owner,input,&d);if(NT_SUCCESS(status)) { ((VD_ID*)output)->Id=d->Info.Id;information=sizeof(VD_ID); }
        } else if(code==VD_DELETE_DEVICE && inSize==sizeof(VD_ID)) {
            ULONG i;
            WdfSpinLockAcquire(c->Lock);
            for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i] && c->Devices[i]->Info.Id==((VD_ID*)input)->Id &&
                c->Devices[i]->Owner==owner) { d=c->Devices[i];break; }
            WdfSpinLockRelease(c->Lock);
            status=d?DeleteVirtual(d,c->Removing):STATUS_NOT_FOUND;
        } else if(code==VD_RESPOND && inSize>=sizeof(VD_RESPONSE)) {
            const VD_RESPONSE* response=input;
            if(response->Stall>1 || response->Length>VD_MAX_TRANSFER || inSize!=sizeof(*response)+response->Length)status=STATUS_INVALID_PARAMETER;
            else {
                WdfSpinLockAcquire(c->Lock);
                if(TrialExpiredLocked(c)){d=NULL;status=STATUS_EVALUATION_EXPIRATION;}
                else {d=FindLocked(c,owner,response->Id);status=d?STATUS_SUCCESS:STATUS_NOT_FOUND;}
                WdfSpinLockRelease(c->Lock);
                if(NT_SUCCESS(status))status=Respond(d,response,(const UCHAR*)input+sizeof(*response));
            }
        } else status=STATUS_INVALID_PARAMETER;
    } else status=STATUS_INVALID_PARAMETER;
done:
    if(locked)WdfWaitLockRelease(c->Management);
    WdfRequestCompleteWithInformation(request,status,information);
}
VOID VdTrialTimeout(WDFTIMER timer) {
    CONTROLLER* c=TimerGet(timer)->Controller;
    WdfSpinLockAcquire(c->Lock);
    if(!c->Removing && c->TrialStart) {
        ULONGLONG elapsed=Now()-c->TrialStart;
        if(elapsed>=VD_TRIAL_DURATION) { c->Expired=TRUE;WdfWorkItemEnqueue(c->ExpireWork); }
        else WdfTimerStart(timer,-(LONGLONG)(VD_TRIAL_DURATION-elapsed));
    }
    WdfSpinLockRelease(c->Lock);
}
VOID VdExpire(WDFWORKITEM work) {
    CONTROLLER* c=ControllerGet(WdfWorkItemGetParentObject(work));ULONG i;
    WdfWaitLockAcquire(c->Management,NULL);
    if(!c->Removing)for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i]) {
        VIRTUAL_DEVICE* d=c->Devices[i];BOOLEAN retire;
        WdfSpinLockAcquire(c->Lock);retire=!c->Removing && (c->Expired || FileGet(d->Owner)->Closing);WdfSpinLockRelease(c->Lock);
        // Also retire an orphan whose first EP0 start arrived after its
        // closing owner's bounded DELETE wait. Active owners are preserved.
        if(retire)(void)DeleteVirtual(d,FALSE);
    }
    WdfWaitLockRelease(c->Management);
    WdfDpcEnqueue(c->Dpc);
}
VOID VdRemoving(WDFDEVICE device) {
    CONTROLLER* c=ControllerGet(device);ULONG i;
    WdfSpinLockAcquire(c->Lock);c->Removing=TRUE;WdfSpinLockRelease(c->Lock);
    WdfTimerStop(c->TrialTimer,TRUE);WdfWorkItemFlush(c->ExpireWork);
    WdfWaitLockAcquire(c->Management,NULL);
    for(i=0;i<VD_MAX_DEVICES;++i)if(c->Devices[i])(void)DeleteVirtual(c->Devices[i],TRUE);
    PurgeOwnerEvents(c);
    WdfWaitLockRelease(c->Management);WdfDpcCancel(c->Dpc,TRUE);
}
VOID VdControllerCleanup(WDFOBJECT object) {
    CONTROLLER* c=ControllerGet(object);TcClose(&c->TrialClock);
}
NTSTATUS VdCapability(WDFDEVICE device,PGUID capability,ULONG size,PVOID buffer,PULONG returned) {
    UNREFERENCED_PARAMETER(device);UNREFERENCED_PARAMETER(capability);UNREFERENCED_PARAMETER(size);UNREFERENCED_PARAMETER(buffer);
    *returned=0;return STATUS_NOT_SUPPORTED;
}
static VOID InitDiagnostic(WDFDRIVER driver,ULONG stage,NTSTATUS result) {
    WDFKEY key;
    DECLARE_CONST_UNICODE_STRING(stageName,L"VdeviceInitStage");
    DECLARE_CONST_UNICODE_STRING(statusName,L"VdeviceInitStatus");
    if(NT_SUCCESS(WdfDriverOpenParametersRegistryKey(driver,KEY_SET_VALUE,WDF_NO_OBJECT_ATTRIBUTES,&key))) {
        (void)WdfRegistryAssignULong(key,&stageName,stage);
        (void)WdfRegistryAssignULong(key,&statusName,(ULONG)result);WdfRegistryClose(key);
    }
}
NTSTATUS VdAdd(WDFDRIVER driver,PWDFDEVICE_INIT init) {
    WDFDEVICE device;CONTROLLER* c;NTSTATUS status;WDF_OBJECT_ATTRIBUTES attrs;
    WDF_FILEOBJECT_CONFIG files;WDF_PNPPOWER_EVENT_CALLBACKS pnp;WDF_IO_QUEUE_CONFIG queue;
    WDF_DPC_CONFIG dpc;WDF_TIMER_CONFIG timer;WDF_WORKITEM_CONFIG work;UDECX_WDF_DEVICE_CONFIG emulation;
    const GUID interfaceId={0x3abf6f2d,0x71c4,0x462a,{0x8a,0x92,0x1e,0x68,0x61,0xe6,0xaf,0x27}};
    DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\Vdevice");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\Vdevice");
    DECLARE_CONST_UNICODE_STRING(security,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
#define STEP(call) do { status=(call);InitDiagnostic(driver,__LINE__,status);if(!NT_SUCCESS(status))return status; } while(0)
    STEP(UdecxInitializeWdfDeviceInit(init));
    STEP(WdfDeviceInitAssignName(init,&name));
    STEP(WdfDeviceInitAssignSDDLString(init,&security));
    WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,COMPLETION);WdfDeviceInitSetRequestAttributes(init,&attrs);
    WDF_FILEOBJECT_CONFIG_INIT(&files,VdFileCreate,WDF_NO_EVENT_CALLBACK,VdFileCleanup);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,FILE_CONTEXT);attrs.ExecutionLevel=WdfExecutionLevelPassive;
    attrs.SynchronizationScope=WdfSynchronizationScopeNone;
    attrs.EvtDestroyCallback=VdFileDestroy;WdfDeviceInitSetFileObjectConfig(init,&files,&attrs);
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);pnp.EvtDeviceSelfManagedIoCleanup=VdRemoving;
    WdfDeviceInitSetPnpPowerEventCallbacks(init,&pnp);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,CONTROLLER);attrs.ExecutionLevel=WdfExecutionLevelDispatch;
    attrs.SynchronizationScope=WdfSynchronizationScopeNone;attrs.EvtCleanupCallback=VdControllerCleanup;
    STEP(WdfDeviceCreate(&init,&attrs,&device));
    c=ControllerGet(device);c->Device=device;InitializeListHead(&c->Files);InitializeListHead(&c->Completions);
    InitializeListHead(&c->EmergencyCompletions);
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);attrs.ParentObject=device;
    STEP(WdfSpinLockCreate(&attrs,&c->Lock));
    STEP(WdfWaitLockCreate(&attrs,&c->Management));
    WDF_DPC_CONFIG_INIT(&dpc,VdDpc);dpc.AutomaticSerialization=FALSE;
    STEP(WdfDpcCreate(&dpc,&attrs,&c->Dpc));
    WDF_WORKITEM_CONFIG_INIT(&work,VdExpire);work.AutomaticSerialization=FALSE;
    STEP(WdfWorkItemCreate(&work,&attrs,&c->ExpireWork));
    WDF_TIMER_CONFIG_INIT(&timer,VdTrialTimeout);timer.AutomaticSerialization=FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs,TIMER_CONTEXT);attrs.ParentObject=device;
    STEP(WdfTimerCreate(&timer,&attrs,&c->TrialTimer));
    TimerGet(c->TrialTimer)->Controller=c;
    STEP(TrialOpen(c));
    if(c->TrialStart && !c->Expired)WdfTimerStart(c->TrialTimer,-(LONGLONG)(VD_TRIAL_DURATION-(Now()-c->TrialStart)));
    STEP(WdfDeviceCreateSymbolicLink(device,&link));
    STEP(WdfDeviceCreateDeviceInterface(device,&interfaceId,NULL));
    /* UdeCx requires a nonempty USB3 root-hub side even for a USB2-only
       emulator. Its single unused USB3 port does not advertise USB3 devices. */
    UDECX_WDF_DEVICE_CONFIG_INIT(&emulation,VdCapability);emulation.NumberOfUsb20Ports=VD_MAX_DEVICES;emulation.NumberOfUsb30Ports=1;
    STEP(UdecxWdfDeviceAddUsbDeviceEmulation(device,&emulation));
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchParallel);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=VdIoctl;
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);attrs.ExecutionLevel=WdfExecutionLevelPassive;attrs.SynchronizationScope=WdfSynchronizationScopeNone;
    STEP(WdfIoQueueCreate(device,&queue,&attrs,WDF_NO_HANDLE));
    return STATUS_SUCCESS;
#undef STEP
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path) {
    WDF_DRIVER_CONFIG config;WDF_DRIVER_CONFIG_INIT(&config,VdAdd);
    return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
