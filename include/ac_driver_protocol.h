#ifndef AC_DRIVER_PROTOCOL_H
#define AC_DRIVER_PROTOCOL_H

#if defined(_KERNEL_MODE)
#include <ntddk.h>

/*
 * The kernel-mode include set ships no <stdint.h>, so including it here pulls
 * in the user-mode CRT copy, which redefines macros the WDK headers own. Take
 * the fixed-width types from basetsd.h instead; the wire layout below is then
 * identical on both sides of the IOCTL boundary.
 */
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#else
#include <stdint.h>

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

/*
 * The kernel-mode toolset compiles this header as legacy C, where neither
 * static_assert nor _Static_assert exists. Fall back to a declaration whose
 * type is only valid when the condition holds, so the layout contract is
 * still enforced at compile time on every side of the boundary.
 */
#if defined(__cplusplus)
#define AC_DRIVER_STATIC_ASSERT(condition, message) \
    static_assert(condition, message)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define AC_DRIVER_STATIC_ASSERT(condition, message) \
    _Static_assert(condition, message)
#else
#define AC_DRIVER_STATIC_ASSERT_NAMED(condition, line) \
    typedef char ac_driver_static_assert_##line[(condition) ? 1 : -1]
#define AC_DRIVER_STATIC_ASSERT_EXPAND(condition, line) \
    AC_DRIVER_STATIC_ASSERT_NAMED(condition, line)
#define AC_DRIVER_STATIC_ASSERT(condition, message) \
    AC_DRIVER_STATIC_ASSERT_EXPAND(condition, __LINE__)
#endif

AC_DRIVER_STATIC_ASSERT(
    sizeof(AcDriverVersion) == 16u, "protocol layout mismatch");
AC_DRIVER_STATIC_ASSERT(
    sizeof(AcDriverTargetRequest) == 24u, "protocol layout mismatch");
AC_DRIVER_STATIC_ASSERT(
    sizeof(AcDriverStats) == 56u, "protocol layout mismatch");
AC_DRIVER_STATIC_ASSERT(
    sizeof(AcDriverEvent) == 584u, "protocol layout mismatch");
AC_DRIVER_STATIC_ASSERT(
    IOCTL_AC_GET_VERSION != IOCTL_AC_SET_TARGET,
    "IOCTL values must be unique");
AC_DRIVER_STATIC_ASSERT(
    IOCTL_AC_SET_TARGET != IOCTL_AC_READ_EVENTS,
    "IOCTL values must be unique");
AC_DRIVER_STATIC_ASSERT(
    IOCTL_AC_READ_EVENTS != IOCTL_AC_GET_STATS,
    "IOCTL values must be unique");

#endif
