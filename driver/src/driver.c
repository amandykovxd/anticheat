/* ntifs.h declares PsLookupProcessByProcessId and must precede ntddk.h. */
#include <ntifs.h>
#include <ntddk.h>
#include <wdmsec.h>

#include "ac_driver_protocol.h"

AC_DRIVER_STATIC_ASSERT(
    sizeof(WCHAR) == sizeof(uint16_t),
    "driver protocol requires 16-bit WCHAR");

/*
 * wdm.h defines PROCESS_DUP_HANDLE, but the remaining process access rights
 * this driver treats as dangerous are declared only in the user-mode winnt.h.
 */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001u
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002u
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008u
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010u
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020u
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800u
#endif

#if defined(__MINGW32__)
NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    HANDLE process_id,
    PEPROCESS *process);
#endif

typedef struct AcDeviceExtension {
    KSPIN_LOCK lock;
    AcDriverEvent events[AC_DRIVER_QUEUE_CAPACITY];
    ULONG head;
    ULONG count;
    ULONG target_pid;
    ULONGLONG session_id;
    ULONGLONG next_sequence;
    ULONGLONG events_generated;
    ULONGLONG events_dropped;
    BOOLEAN process_callback_registered;
    BOOLEAN image_callback_registered;
    BOOLEAN thread_callback_registered;
    PVOID handle_callback_registration;
} AcDeviceExtension;

static AcDeviceExtension *g_extension;

static const GUID g_device_class_guid = {
    0xd329269a,
    0x8b93,
    0x4fc5,
    {0xa0, 0x74, 0xf1, 0xb3, 0x53, 0x7b, 0x66, 0x29}
};

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AcDriverUnload;

DRIVER_DISPATCH AcDispatchCreateClose;

DRIVER_DISPATCH AcDispatchDeviceControl;

static NTSTATUS AcCompleteIrp(
    PIRP irp,
    NTSTATUS status,
    ULONG_PTR information);

static NTSTATUS AcDispatchUnsupported(
    PDEVICE_OBJECT device_object,
    PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);
    return AcCompleteIrp(
        irp,
        STATUS_INVALID_DEVICE_REQUEST,
        0);
}

static NTSTATUS AcCompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static ULONG AcHandleToPid(HANDLE process_id)
{
    return (ULONG)(ULONG_PTR)process_id;
}

static ACCESS_MASK AcDangerousProcessAccessMask(VOID)
{
    return PROCESS_TERMINATE |
           PROCESS_CREATE_THREAD |
           PROCESS_VM_OPERATION |
           PROCESS_VM_READ |
           PROCESS_VM_WRITE |
           PROCESS_DUP_HANDLE |
           PROCESS_SUSPEND_RESUME;
}

static VOID AcCopyUnicodePath(
    AcDriverEvent *event,
    PCUNICODE_STRING path)
{
    USHORT characters;
    USHORT copy_characters;

    if (path == NULL || path->Buffer == NULL || path->Length == 0) {
        event->flags |= AC_DRIVER_EVENT_FLAG_PATH_UNAVAILABLE;
        return;
    }

    characters = path->Length / (USHORT)sizeof(WCHAR);
    copy_characters = characters;
    if (copy_characters >= AC_DRIVER_IMAGE_PATH_CHARS) {
        copy_characters = (USHORT)(AC_DRIVER_IMAGE_PATH_CHARS - 1u);
        event->flags |= AC_DRIVER_EVENT_FLAG_PATH_TRUNCATED;
    }

    RtlCopyMemory(
        event->image_path,
        path->Buffer,
        (SIZE_T)copy_characters * sizeof(WCHAR));
    event->image_path[copy_characters] = 0;
}

static ULONG AcGetTargetPid(VOID)
{
    KIRQL old_irql;
    ULONG target_pid;

    if (g_extension == NULL) {
        return 0;
    }

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    target_pid = g_extension->target_pid;
    KeReleaseSpinLock(&g_extension->lock, old_irql);
    return target_pid;
}

static VOID AcDeactivateTarget(ULONG process_id)
{
    KIRQL old_irql;

    if (g_extension == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    if (g_extension->target_pid == process_id) {
        g_extension->target_pid = 0;
    }
    KeReleaseSpinLock(&g_extension->lock, old_irql);
}

static VOID AcEnqueueEvent(
    AcDriverEvent *event,
    ULONG required_target_pid)
{
    KIRQL old_irql;
    ULONG tail;
    LARGE_INTEGER timestamp;

    if (g_extension == NULL || event == NULL) {
        return;
    }

    KeQuerySystemTime(&timestamp);
    event->size = (uint32_t)sizeof(*event);
    event->protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    event->timestamp_100ns = (uint64_t)timestamp.QuadPart;

    KeAcquireSpinLock(&g_extension->lock, &old_irql);

    if (required_target_pid != 0 &&
        g_extension->target_pid != required_target_pid) {
        KeReleaseSpinLock(&g_extension->lock, old_irql);
        return;
    }

    ++g_extension->next_sequence;
    event->sequence = g_extension->next_sequence;
    ++g_extension->events_generated;

    if (g_extension->count == AC_DRIVER_QUEUE_CAPACITY) {
        g_extension->head =
            (g_extension->head + 1u) % AC_DRIVER_QUEUE_CAPACITY;
        --g_extension->count;
        ++g_extension->events_dropped;
    }

    tail = (g_extension->head + g_extension->count) %
           AC_DRIVER_QUEUE_CAPACITY;
    g_extension->events[tail] = *event;
    ++g_extension->count;

    KeReleaseSpinLock(&g_extension->lock, old_irql);
}

static VOID AcProcessNotify(
    PEPROCESS process,
    HANDLE process_id,
    PPS_CREATE_NOTIFY_INFO create_info)
{
    AcDriverEvent event;
    const ULONG pid = AcHandleToPid(process_id);
    const ULONG target_pid = AcGetTargetPid();

    UNREFERENCED_PARAMETER(process);

    if (target_pid == 0) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.process_id = pid;

    if (create_info != NULL) {
        const ULONG parent_pid =
            AcHandleToPid(create_info->ParentProcessId);

        if (pid != target_pid && parent_pid != target_pid) {
            return;
        }
        event.type = AC_DRIVER_EVENT_PROCESS_CREATED;
        event.parent_process_id = parent_pid;
        event.status = (int32_t)create_info->CreationStatus;
        AcCopyUnicodePath(&event, create_info->ImageFileName);
    } else {
        if (pid != target_pid) {
            return;
        }
        event.type = AC_DRIVER_EVENT_PROCESS_EXITED;
    }

    AcEnqueueEvent(&event, target_pid);
    if (create_info == NULL) {
        AcDeactivateTarget(pid);
    }
}

static VOID AcImageNotify(
    PUNICODE_STRING full_image_name,
    HANDLE process_id,
    PIMAGE_INFO image_info)
{
    AcDriverEvent event;
    const ULONG pid = AcHandleToPid(process_id);
    const ULONG target_pid = AcGetTargetPid();
    BOOLEAN system_image;

    if (image_info == NULL || target_pid == 0) {
        return;
    }
    system_image = image_info->SystemModeImage != 0;
    if (!system_image && pid != target_pid) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.type = AC_DRIVER_EVENT_IMAGE_LOADED;
    event.process_id = system_image ? 0 : pid;
    event.image_base = (uint64_t)(ULONG_PTR)image_info->ImageBase;
    event.image_size = (uint64_t)image_info->ImageSize;
    if (system_image) {
        event.flags |= AC_DRIVER_EVENT_FLAG_SYSTEM_IMAGE;
    }
    AcCopyUnicodePath(&event, full_image_name);
    AcEnqueueEvent(&event, target_pid);
}

static VOID AcThreadNotify(
    HANDLE process_id,
    HANDLE thread_id,
    BOOLEAN create)
{
    AcDriverEvent event;
    const ULONG pid = AcHandleToPid(process_id);
    const ULONG target_pid = AcGetTargetPid();

    if (target_pid == 0 || pid != target_pid) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.type = create
        ? AC_DRIVER_EVENT_THREAD_CREATED
        : AC_DRIVER_EVENT_THREAD_EXITED;
    event.process_id = pid;
    event.parent_process_id = AcHandleToPid(thread_id);
    event.reserved = AcHandleToPid(PsGetCurrentProcessId());
    event.status = create ? 1 : 0;
    AcEnqueueEvent(&event, target_pid);
}

static OB_PREOP_CALLBACK_STATUS AcProcessHandlePreOperation(
    PVOID registration_context,
    POB_PRE_OPERATION_INFORMATION operation_information)
{
    AcDriverEvent event;
    ACCESS_MASK original_access;
    ACCESS_MASK desired_access;
    const ULONG target_pid = AcGetTargetPid();
    ULONG object_pid;
    ULONG requestor_pid;

    UNREFERENCED_PARAMETER(registration_context);

    if (target_pid == 0 || operation_information == NULL ||
        operation_information->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    object_pid = AcHandleToPid(PsGetProcessId(
        (PEPROCESS)operation_information->Object));
    requestor_pid = AcHandleToPid(PsGetCurrentProcessId());
    if (object_pid != target_pid || requestor_pid == target_pid) {
        return OB_PREOP_SUCCESS;
    }

    if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
        original_access = operation_information->Parameters
            ->CreateHandleInformation.OriginalDesiredAccess;
        desired_access = operation_information->Parameters
            ->CreateHandleInformation.DesiredAccess;
    } else if (operation_information->Operation ==
               OB_OPERATION_HANDLE_DUPLICATE) {
        original_access = operation_information->Parameters
            ->DuplicateHandleInformation.OriginalDesiredAccess;
        desired_access = operation_information->Parameters
            ->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if ((original_access & AcDangerousProcessAccessMask()) == 0) {
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.type = AC_DRIVER_EVENT_PROCESS_HANDLE;
    event.process_id = requestor_pid;
    event.parent_process_id = target_pid;
    event.status = (int32_t)operation_information->Operation;
    event.image_base = (uint64_t)original_access;
    event.image_size = (uint64_t)desired_access;
    event.flags |= AC_DRIVER_EVENT_FLAG_PATH_UNAVAILABLE;
    if (operation_information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        event.flags |= AC_DRIVER_EVENT_FLAG_HANDLE_DUPLICATE;
    }
    if (operation_information->KernelHandle) {
        event.flags |= AC_DRIVER_EVENT_FLAG_KERNEL_HANDLE;
    }
    AcEnqueueEvent(&event, target_pid);
    return OB_PREOP_SUCCESS;
}

static NTSTATUS AcRegisterHandleCallback(VOID)
{
    OB_OPERATION_REGISTRATION operation;
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385200");

    RtlZeroMemory(&operation, sizeof(operation));
    operation.ObjectType = PsProcessType;
    operation.Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation.PreOperation = AcProcessHandlePreOperation;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = altitude;
    registration.RegistrationContext = g_extension;
    registration.OperationRegistration = &operation;

    return ObRegisterCallbacks(
        &registration,
        &g_extension->handle_callback_registration);
}

static NTSTATUS AcSetTarget(
    const AcDriverTargetRequest *request)
{
    PEPROCESS process = NULL;
    KIRQL old_irql;
    AcDriverEvent event;
    NTSTATUS status;

    if (request->session_id == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    if (g_extension->session_id != 0 &&
        g_extension->session_id != request->session_id) {
        KeReleaseSpinLock(&g_extension->lock, old_irql);
        return STATUS_ACCESS_DENIED;
    }
    KeReleaseSpinLock(&g_extension->lock, old_irql);

    if (request->target_pid != 0) {
        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)request->target_pid,
            &process);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ObDereferenceObject(process);
    }

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    if (g_extension->session_id != 0 &&
        g_extension->session_id != request->session_id) {
        KeReleaseSpinLock(&g_extension->lock, old_irql);
        return STATUS_ACCESS_DENIED;
    }
    if (g_extension->session_id == 0 && request->target_pid != 0) {
        g_extension->head = 0;
        g_extension->count = 0;
        g_extension->next_sequence = 0;
        g_extension->events_generated = 0;
        g_extension->events_dropped = 0;
    }
    g_extension->session_id = request->session_id;
    g_extension->target_pid = request->target_pid;
    if (request->target_pid == 0) {
        g_extension->session_id = 0;
    }
    KeReleaseSpinLock(&g_extension->lock, old_irql);

    RtlZeroMemory(&event, sizeof(event));
    event.type = AC_DRIVER_EVENT_TARGET_CHANGED;
    event.process_id = request->target_pid;
    AcEnqueueEvent(&event, 0);
    return STATUS_SUCCESS;
}

static ULONG AcReadEvents(AcDriverEvent *output, ULONG output_length)
{
    KIRQL old_irql;
    ULONG capacity;
    ULONG copied = 0;

    capacity = output_length / (ULONG)sizeof(AcDriverEvent);
    if (capacity > AC_DRIVER_MAX_BATCH_EVENTS) {
        capacity = AC_DRIVER_MAX_BATCH_EVENTS;
    }

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    while (copied < capacity && g_extension->count > 0) {
        output[copied] = g_extension->events[g_extension->head];
        g_extension->head =
            (g_extension->head + 1u) % AC_DRIVER_QUEUE_CAPACITY;
        --g_extension->count;
        ++copied;
    }
    KeReleaseSpinLock(&g_extension->lock, old_irql);

    return copied;
}

static VOID AcGetStats(AcDriverStats *stats)
{
    KIRQL old_irql;

    RtlZeroMemory(stats, sizeof(*stats));
    stats->size = (uint32_t)sizeof(*stats);
    stats->protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    stats->queue_capacity = AC_DRIVER_QUEUE_CAPACITY;

    KeAcquireSpinLock(&g_extension->lock, &old_irql);
    stats->events_generated = g_extension->events_generated;
    stats->events_dropped = g_extension->events_dropped;
    stats->next_sequence = g_extension->next_sequence + 1u;
    stats->target_pid = g_extension->target_pid;
    stats->queue_depth = g_extension->count;
    stats->callbacks_active =
        (g_extension->process_callback_registered
            ? AC_DRIVER_CALLBACK_PROCESS : 0u) |
        (g_extension->image_callback_registered
            ? AC_DRIVER_CALLBACK_IMAGE : 0u) |
        (g_extension->thread_callback_registered
            ? AC_DRIVER_CALLBACK_THREAD : 0u) |
        (g_extension->handle_callback_registration != NULL
            ? AC_DRIVER_CALLBACK_HANDLE : 0u);
    stats->session_id = g_extension->session_id;
    KeReleaseSpinLock(&g_extension->lock, old_irql);
}

NTSTATUS AcDispatchCreateClose(
    PDEVICE_OBJECT device_object,
    PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);
    return AcCompleteIrp(irp, STATUS_SUCCESS, 0);
}

NTSTATUS AcDispatchDeviceControl(
    PDEVICE_OBJECT device_object,
    PIRP irp)
{
    PIO_STACK_LOCATION stack;
    ULONG input_length;
    ULONG output_length;
    ULONG code;
    PVOID buffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(device_object);

    stack = IoGetCurrentIrpStackLocation(irp);
    input_length =
        stack->Parameters.DeviceIoControl.InputBufferLength;
    output_length =
        stack->Parameters.DeviceIoControl.OutputBufferLength;
    code = stack->Parameters.DeviceIoControl.IoControlCode;
    buffer = irp->AssociatedIrp.SystemBuffer;

    switch (code) {
        case IOCTL_AC_GET_VERSION:
            if (buffer == NULL ||
                output_length < (ULONG)sizeof(AcDriverVersion)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            {
                AcDriverVersion *version = (AcDriverVersion *)buffer;
                RtlZeroMemory(version, sizeof(*version));
                version->size = (uint32_t)sizeof(*version);
                version->protocol_version =
                    AC_DRIVER_PROTOCOL_VERSION;
                version->event_size =
                    (uint32_t)sizeof(AcDriverEvent);
                version->queue_capacity =
                    AC_DRIVER_QUEUE_CAPACITY;
                information = (ULONG_PTR)sizeof(*version);
                status = STATUS_SUCCESS;
            }
            break;

        case IOCTL_AC_SET_TARGET:
            if (buffer == NULL ||
                input_length <
                    (ULONG)sizeof(AcDriverTargetRequest)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            {
                const AcDriverTargetRequest *request =
                    (const AcDriverTargetRequest *)buffer;
                if (request->size !=
                        (uint32_t)sizeof(*request) ||
                    request->protocol_version !=
                        AC_DRIVER_PROTOCOL_VERSION ||
                    request->reserved != 0) {
                    status = STATUS_REVISION_MISMATCH;
                    break;
                }
                status = AcSetTarget(request);
            }
            break;

        case IOCTL_AC_READ_EVENTS:
            if (buffer == NULL ||
                output_length < (ULONG)sizeof(AcDriverEvent)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            {
                const ULONG count = AcReadEvents(
                    (AcDriverEvent *)buffer,
                    output_length);
                information =
                    (ULONG_PTR)count * sizeof(AcDriverEvent);
                status = STATUS_SUCCESS;
            }
            break;

        case IOCTL_AC_GET_STATS:
            if (buffer == NULL ||
                output_length < (ULONG)sizeof(AcDriverStats)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            AcGetStats((AcDriverStats *)buffer);
            information = (ULONG_PTR)sizeof(AcDriverStats);
            status = STATUS_SUCCESS;
            break;

        default:
            break;
    }

    return AcCompleteIrp(irp, status, information);
}

VOID AcDriverUnload(PDRIVER_OBJECT driver_object)
{
    UNICODE_STRING symbolic_link =
        RTL_CONSTANT_STRING(AC_DRIVER_DOS_DEVICE_NAME);

    if (g_extension != NULL &&
        g_extension->handle_callback_registration != NULL) {
        ObUnRegisterCallbacks(
            g_extension->handle_callback_registration);
        g_extension->handle_callback_registration = NULL;
    }
    if (g_extension != NULL &&
        g_extension->thread_callback_registered) {
        (void)PsRemoveCreateThreadNotifyRoutine(AcThreadNotify);
        g_extension->thread_callback_registered = FALSE;
    }
    if (g_extension != NULL &&
        g_extension->image_callback_registered) {
        (void)PsRemoveLoadImageNotifyRoutine(AcImageNotify);
        g_extension->image_callback_registered = FALSE;
    }
    if (g_extension != NULL &&
        g_extension->process_callback_registered) {
        (void)PsSetCreateProcessNotifyRoutineEx(
            AcProcessNotify,
            TRUE);
        g_extension->process_callback_registered = FALSE;
    }

    (void)IoDeleteSymbolicLink(&symbolic_link);
    g_extension = NULL;
    if (driver_object->DeviceObject != NULL) {
        IoDeleteDevice(driver_object->DeviceObject);
    }
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT driver_object,
    PUNICODE_STRING registry_path)
{
    UNICODE_STRING device_name =
        RTL_CONSTANT_STRING(AC_DRIVER_NT_DEVICE_NAME);
    UNICODE_STRING symbolic_link =
        RTL_CONSTANT_STRING(AC_DRIVER_DOS_DEVICE_NAME);
    UNICODE_STRING security_descriptor =
        RTL_CONSTANT_STRING(
            L"D:P(A;;GA;;;SY)");
    PDEVICE_OBJECT device_object = NULL;
    NTSTATUS status;
    ULONG index;

    UNREFERENCED_PARAMETER(registry_path);

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver_object->MajorFunction[index] =
            AcDispatchUnsupported;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] =
        AcDispatchCreateClose;
    driver_object->MajorFunction[IRP_MJ_CLOSE] =
        AcDispatchCreateClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        AcDispatchDeviceControl;
    driver_object->DriverUnload = AcDriverUnload;

    status = IoCreateDeviceSecure(
        driver_object,
        (ULONG)sizeof(AcDeviceExtension),
        &device_name,
        AC_DRIVER_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &security_descriptor,
        &g_device_class_guid,
        &device_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_extension =
        (AcDeviceExtension *)device_object->DeviceExtension;
    RtlZeroMemory(g_extension, sizeof(*g_extension));
    KeInitializeSpinLock(&g_extension->lock);
    device_object->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(
        &symbolic_link,
        &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        g_extension = NULL;
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        AcProcessNotify,
        FALSE);
    if (!NT_SUCCESS(status)) {
        (void)IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(device_object);
        g_extension = NULL;
        return status;
    }
    g_extension->process_callback_registered = TRUE;

    status = PsSetLoadImageNotifyRoutine(AcImageNotify);
    if (!NT_SUCCESS(status)) {
        (void)PsSetCreateProcessNotifyRoutineEx(
            AcProcessNotify,
            TRUE);
        g_extension->process_callback_registered = FALSE;
        (void)IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(device_object);
        g_extension = NULL;
        return status;
    }
    g_extension->image_callback_registered = TRUE;

    status = PsSetCreateThreadNotifyRoutine(AcThreadNotify);
    if (NT_SUCCESS(status)) {
        g_extension->thread_callback_registered = TRUE;
    }

    status = AcRegisterHandleCallback();
    if (!NT_SUCCESS(status)) {
        g_extension->handle_callback_registration = NULL;
    }

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
