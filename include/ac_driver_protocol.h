#ifndef AC_DRIVER_PROTOCOL_H
#define AC_DRIVER_PROTOCOL_H

#include <stdint.h>

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define AC_DRIVER_PROTOCOL_VERSION 4u
#define AC_DRIVER_QUEUE_CAPACITY 512u
#define AC_DRIVER_MAX_BATCH_EVENTS 32u
#define AC_DRIVER_IMAGE_PATH_CHARS 260u

#define AC_DRIVER_NT_DEVICE_NAME L"\\Device\\AcTelemetry"
#define AC_DRIVER_DOS_DEVICE_NAME L"\\DosDevices\\AcTelemetry"
#define AC_DRIVER_WIN32_DEVICE_NAME L"\\\\.\\AcTelemetry"

#define AC_DRIVER_DEVICE_TYPE 0x8337u

#define IOCTL_AC_GET_VERSION                                                  \
    CTL_CODE(AC_DRIVER_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AC_SET_TARGET                                                   \
    CTL_CODE(AC_DRIVER_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AC_READ_EVENTS                                                  \
    CTL_CODE(AC_DRIVER_DEVICE_TYPE, 0x802u, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AC_GET_STATS                                                    \
    CTL_CODE(AC_DRIVER_DEVICE_TYPE, 0x803u, METHOD_BUFFERED, FILE_READ_DATA)

typedef enum AcDriverEventType {
    AC_DRIVER_EVENT_TARGET_CHANGED = 1,
    AC_DRIVER_EVENT_PROCESS_CREATED = 2,
    AC_DRIVER_EVENT_PROCESS_EXITED = 3,
    AC_DRIVER_EVENT_IMAGE_LOADED = 4,
    AC_DRIVER_EVENT_PROCESS_HANDLE = 5,
    AC_DRIVER_EVENT_THREAD_CREATED = 6,
    AC_DRIVER_EVENT_THREAD_EXITED = 7
} AcDriverEventType;

enum {
    AC_DRIVER_EVENT_FLAG_PATH_TRUNCATED = 0x00000001u,
    AC_DRIVER_EVENT_FLAG_SYSTEM_IMAGE = 0x00000002u,
    AC_DRIVER_EVENT_FLAG_PATH_UNAVAILABLE = 0x00000004u,
    AC_DRIVER_EVENT_FLAG_HANDLE_DUPLICATE = 0x00000008u,
    AC_DRIVER_EVENT_FLAG_KERNEL_HANDLE = 0x00000010u
};

enum {
    AC_DRIVER_CALLBACK_PROCESS = 0x00000001u,
    AC_DRIVER_CALLBACK_IMAGE = 0x00000002u,
    AC_DRIVER_CALLBACK_THREAD = 0x00000004u,
    AC_DRIVER_CALLBACK_HANDLE = 0x00000008u,
    AC_DRIVER_CALLBACK_REQUIRED =
        AC_DRIVER_CALLBACK_PROCESS |
        AC_DRIVER_CALLBACK_IMAGE |
        AC_DRIVER_CALLBACK_THREAD |
        AC_DRIVER_CALLBACK_HANDLE
};

#pragma pack(push, 8)

typedef struct AcDriverVersion {
    uint32_t size;
    uint32_t protocol_version;
    uint32_t event_size;
    uint32_t queue_capacity;
} AcDriverVersion;

typedef struct AcDriverTargetRequest {
    uint32_t size;
    uint32_t protocol_version;
    uint32_t target_pid;
    uint32_t reserved;
    uint64_t session_id;
} AcDriverTargetRequest;

typedef struct AcDriverStats {
    uint32_t size;
    uint32_t protocol_version;
    uint64_t events_generated;
    uint64_t events_dropped;
    uint64_t next_sequence;
    uint32_t target_pid;
    uint32_t queue_depth;
    uint32_t queue_capacity;
    uint32_t callbacks_active;
    uint64_t session_id;
} AcDriverStats;

typedef struct AcDriverEvent {
    uint32_t size;
    uint32_t protocol_version;
    uint64_t sequence;
    uint64_t timestamp_100ns;
    uint32_t type;
    uint32_t flags;
    uint32_t process_id;
    uint32_t parent_process_id;
    int32_t status;
    uint32_t reserved;
    uint64_t image_base;
    uint64_t image_size;
    uint16_t image_path[AC_DRIVER_IMAGE_PATH_CHARS];
} AcDriverEvent;

#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(AcDriverVersion) == 16u, "protocol layout mismatch");
static_assert(sizeof(AcDriverTargetRequest) == 24u, "protocol layout mismatch");
static_assert(sizeof(AcDriverStats) == 56u, "protocol layout mismatch");
static_assert(sizeof(AcDriverEvent) == 584u, "protocol layout mismatch");
static_assert(IOCTL_AC_GET_VERSION != IOCTL_AC_SET_TARGET,
              "IOCTL values must be unique");
static_assert(IOCTL_AC_SET_TARGET != IOCTL_AC_READ_EVENTS,
              "IOCTL values must be unique");
static_assert(IOCTL_AC_READ_EVENTS != IOCTL_AC_GET_STATS,
              "IOCTL values must be unique");
#elif defined(_MSC_VER) || \
      (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(AcDriverVersion) == 16u, "protocol layout mismatch");
_Static_assert(sizeof(AcDriverTargetRequest) == 24u, "protocol layout mismatch");
_Static_assert(sizeof(AcDriverStats) == 56u, "protocol layout mismatch");
_Static_assert(sizeof(AcDriverEvent) == 584u, "protocol layout mismatch");
_Static_assert(IOCTL_AC_GET_VERSION != IOCTL_AC_SET_TARGET,
               "IOCTL values must be unique");
_Static_assert(IOCTL_AC_SET_TARGET != IOCTL_AC_READ_EVENTS,
               "IOCTL values must be unique");
_Static_assert(IOCTL_AC_READ_EVENTS != IOCTL_AC_GET_STATS,
               "IOCTL values must be unique");
#endif

#endif
