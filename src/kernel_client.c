#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define AC_KERNEL_DRAIN_BATCH_LIMIT 32u
#define AC_THREAD_QUERY_SET_WIN32_START_ADDRESS 9u

static void ac_kernel_client_reset_health(AcKernelClient *client)
{
    client->last_dropped = 0;
    client->last_sequence = 0;
    client->sequence_events_missing = 0;
    client->image_observations_omitted = 0;
    client->image_observation_count = 0;
    client->thread_observations_omitted = 0;
    client->thread_observation_count = 0;
    client->last_callbacks_active = 0;
    client->callback_state_initialized = false;
    client->queue_saturated = false;
    client->telemetry_complete = true;
    client->correlation_random_source_available = true;
}

static size_t ac_kernel_reservoir_index(
    uint64_t observations_seen,
    uint64_t fallback,
    bool *secure_out)
{
    uint64_t random_value = 0;

    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&random_value,
            (ULONG)sizeof(random_value),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        random_value = fallback ^ observations_seen;
        random_value ^= random_value >> 12;
        random_value ^= random_value << 25;
        random_value ^= random_value >> 27;
        random_value *= UINT64_C(2685821657736338717);
        *secure_out = false;
    } else {
        *secure_out = true;
    }
    return (size_t)(random_value % observations_seen);
}

void ac_kernel_client_init(AcKernelClient *client)
{
    if (client == NULL) {
        return;
    }

    memset(client, 0, sizeof(*client));
    client->device = INVALID_HANDLE_VALUE;
    client->telemetry_complete = true;
    client->correlation_random_source_available = true;
}

bool ac_kernel_client_open(AcKernelClient *client)
{
    DWORD returned = 0;

    if (client == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    ac_kernel_client_init(client);
    client->device = CreateFileW(
        AC_DRIVER_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (client->device == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&client->session_id,
            (ULONG)sizeof(client->session_id),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        client->session_id == 0) {
        const DWORD error = ERROR_GEN_FAILURE;
        ac_kernel_client_close(client);
        SetLastError(error);
        return false;
    }

    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_GET_VERSION,
            NULL,
            0,
            &client->version,
            (DWORD)sizeof(client->version),
            &returned,
            NULL)) {
        const DWORD error = GetLastError();
        ac_kernel_client_close(client);
        SetLastError(error);
        return false;
    }

    if (returned != (DWORD)sizeof(client->version) ||
        client->version.size !=
            (uint32_t)sizeof(client->version) ||
        client->version.protocol_version !=
            AC_DRIVER_PROTOCOL_VERSION ||
        client->version.event_size != sizeof(AcDriverEvent)) {
        ac_kernel_client_close(client);
        SetLastError(ERROR_REVISION_MISMATCH);
        return false;
    }

    return true;
}

void ac_kernel_client_close(AcKernelClient *client)
{
    if (client == NULL) {
        return;
    }

    if (client->device != NULL &&
        client->device != INVALID_HANDLE_VALUE) {
        if (client->session_id != 0 && client->session_registered) {
            (void)ac_kernel_client_set_target(client, 0);
        }
        CloseHandle(client->device);
    }
    ac_kernel_client_init(client);
}

bool ac_kernel_client_set_target(AcKernelClient *client, DWORD pid)
{
    AcDriverTargetRequest request;
    DWORD returned = 0;

    if (client == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    memset(&request, 0, sizeof(request));
    request.size = (uint32_t)sizeof(request);
    request.protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    request.target_pid = (uint32_t)pid;
    request.session_id = client->session_id;

    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_SET_TARGET,
            &request,
            (DWORD)sizeof(request),
            NULL,
            0,
            &returned,
            NULL)) {
        return false;
    }
    if (pid != 0) {
        ac_kernel_client_reset_health(client);
        client->session_registered = true;
    } else {
        client->session_registered = false;
    }
    return true;
}

bool ac_kernel_client_get_stats(
    AcKernelClient *client,
    AcDriverStats *stats_out)
{
    DWORD returned = 0;

    if (client == NULL || stats_out == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    memset(stats_out, 0, sizeof(*stats_out));
    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_GET_STATS,
            NULL,
            0,
            stats_out,
            (DWORD)sizeof(*stats_out),
            &returned,
            NULL)) {
        return false;
    }

    if (returned != (DWORD)sizeof(*stats_out) ||
        stats_out->size != (uint32_t)sizeof(*stats_out) ||
        stats_out->protocol_version !=
            AC_DRIVER_PROTOCOL_VERSION ||
        stats_out->queue_capacity != client->version.queue_capacity ||
        (client->session_registered &&
         stats_out->session_id != client->session_id) ||
        (!client->session_registered &&
         stats_out->session_id != 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

bool ac_kernel_client_observe_sequence(
    AcKernelClient *client,
    uint64_t sequence,
    uint64_t *missing_out)
{
    uint64_t expected;

    if (client == NULL || sequence == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    if (client->last_sequence == UINT64_MAX) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    expected = client->last_sequence == 0
        ? 1u
        : client->last_sequence + 1u;
    if (sequence < expected) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    if (missing_out != NULL) {
        *missing_out = sequence - expected;
    }
    if (sequence > expected) {
        client->sequence_events_missing += sequence - expected;
        client->telemetry_complete = false;
    }
    client->last_sequence = sequence;
    return true;
}

bool ac_kernel_client_observe_drop_counter(
    AcKernelClient *client,
    uint64_t events_dropped,
    uint64_t *newly_dropped_out)
{
    uint64_t newly_dropped;

    if (client == NULL || events_dropped < client->last_dropped) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    newly_dropped = events_dropped - client->last_dropped;
    client->last_dropped = events_dropped;
    if (newly_dropped > 0) {
        client->telemetry_complete = false;
    }
    if (newly_dropped_out != NULL) {
        *newly_dropped_out = newly_dropped;
    }
    return true;
}

static const char *ac_kernel_event_name(uint32_t type, uint32_t flags)
{
    switch (type) {
        case AC_DRIVER_EVENT_TARGET_CHANGED:
            return "kernel_target_changed";
        case AC_DRIVER_EVENT_PROCESS_CREATED:
            return "kernel_process_created";
        case AC_DRIVER_EVENT_PROCESS_EXITED:
            return "kernel_process_exited";
        case AC_DRIVER_EVENT_IMAGE_LOADED:
            return (flags & AC_DRIVER_EVENT_FLAG_SYSTEM_IMAGE) != 0
                ? "kernel_system_image_loaded"
                : "kernel_image_loaded";
        case AC_DRIVER_EVENT_PROCESS_HANDLE:
            return "kernel_process_handle_requested";
        case AC_DRIVER_EVENT_THREAD_CREATED:
            return "kernel_thread_created";
        case AC_DRIVER_EVENT_THREAD_EXITED:
            return "kernel_thread_exited";
        default:
            return "kernel_event_unknown";
    }
}

static bool ac_kernel_process_path(
    DWORD pid,
    char *escaped_path,
    size_t escaped_capacity)
{
    HANDLE process;
    wchar_t *wide_path = NULL;
    char path_utf8[MAX_PATH * 3u];
    bool result = false;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) {
        return false;
    }
    if (ac_get_process_path(process, &wide_path) &&
        ac_wide_to_utf8(wide_path, path_utf8, sizeof(path_utf8))) {
        result = ac_json_escape(
            path_utf8,
            escaped_path,
            escaped_capacity);
    }
    free(wide_path);
    CloseHandle(process);
    return result;
}

static uint64_t ac_kernel_query_thread_start(uint32_t thread_id)
{
    typedef LONG (NTAPI *AcNtQueryInformationThread)(
        HANDLE,
        ULONG,
        PVOID,
        ULONG,
        PULONG);
    HMODULE ntdll;
    AcNtQueryInformationThread query;
    FARPROC procedure;
    HANDLE thread;
    PVOID start_address = NULL;
    uint64_t result = 0;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return 0;
    }
    procedure = GetProcAddress(
        ntdll,
        "NtQueryInformationThread");
    if (procedure == NULL || sizeof(query) != sizeof(procedure)) {
        return 0;
    }
    memcpy(&query, &procedure, sizeof(query));

    thread = OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE,
        thread_id);
    if (thread == NULL) {
        return 0;
    }
    if (query(
            thread,
            AC_THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &start_address,
            (ULONG)sizeof(start_address),
            NULL) >= 0) {
        result = (uint64_t)(uintptr_t)start_address;
    }
    CloseHandle(thread);
    return result;
}

static void ac_kernel_event_path(
    const AcDriverEvent *event,
    char *escaped_path,
    size_t escaped_capacity)
{
    wchar_t wide_path[AC_DRIVER_IMAGE_PATH_CHARS];
    char path_utf8[AC_DRIVER_IMAGE_PATH_CHARS * 3u];
    size_t index;

    for (index = 0; index < AC_DRIVER_IMAGE_PATH_CHARS; ++index) {
        wide_path[index] = (wchar_t)event->image_path[index];
    }
    wide_path[AC_DRIVER_IMAGE_PATH_CHARS - 1u] = L'\0';

    if (!ac_wide_to_utf8(
            wide_path,
            path_utf8,
            sizeof(path_utf8))) {
        (void)strcpy_s(
            path_utf8,
            sizeof(path_utf8),
            "<conversion-failed>");
    }
    (void)ac_json_escape(
        path_utf8,
        escaped_path,
        escaped_capacity);
}

static void ac_log_kernel_event(
    AcLogger *logger,
    const AcDriverEvent *event)
{
    char escaped_path[AC_DRIVER_IMAGE_PATH_CHARS * 6u];
    char details[4096];

    if (event->type == AC_DRIVER_EVENT_PROCESS_HANDLE) {
        const ACCESS_MASK original_access = (ACCESS_MASK)event->image_base;
        const ACCESS_MASK observed_access = (ACCESS_MASK)event->image_size;
        const ACCESS_MASK write_access =
            PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_DUP_HANDLE |
            PROCESS_SUSPEND_RESUME;
        const AcSeverity severity = (original_access & write_access) != 0
            ? AC_SEVERITY_HIGH
            : AC_SEVERITY_MEDIUM;

        if (!ac_kernel_process_path(
                event->process_id,
                escaped_path,
                sizeof(escaped_path))) {
            (void)strcpy_s(
                escaped_path,
                sizeof(escaped_path),
                "<unavailable>");
        }
        (void)snprintf(
            details,
            sizeof(details),
            "{\"driver_sequence\":%" PRIu64
            ",\"kernel_timestamp_100ns\":%" PRIu64
            ",\"requestor_pid\":%u,\"target_pid\":%u,"
            "\"operation\":\"%s\",\"original_access\":\"0x%08lx\","
            "\"observed_access\":\"0x%08lx\",\"kernel_handle\":%s,"
            "\"requestor_path\":\"%s\",\"source\":\"ob_callback\","
            "\"verdict\":\"telemetry_only\"}",
            event->sequence,
            event->timestamp_100ns,
            event->process_id,
            event->parent_process_id,
            (event->flags & AC_DRIVER_EVENT_FLAG_HANDLE_DUPLICATE) != 0
                ? "duplicate" : "create",
            (unsigned long)original_access,
            (unsigned long)observed_access,
            (event->flags & AC_DRIVER_EVENT_FLAG_KERNEL_HANDLE) != 0
                ? "true" : "false",
            escaped_path);
        ac_log_event(
            logger,
            severity,
            ac_kernel_event_name(event->type, event->flags),
            event->parent_process_id,
            details);
        return;
    }

    if (event->type == AC_DRIVER_EVENT_THREAD_CREATED ||
        event->type == AC_DRIVER_EVENT_THREAD_EXITED) {
        (void)snprintf(
            details,
            sizeof(details),
            "{\"driver_sequence\":%" PRIu64
            ",\"kernel_timestamp_100ns\":%" PRIu64
            ",\"thread_id\":%u,\"creator_pid\":%u,"
            "\"start_address\":\"0x%" PRIx64
            "\",\"source\":\"kernel_thread_callback\","
            "\"verdict\":\"telemetry_only\"}",
            event->sequence,
            event->timestamp_100ns,
            event->parent_process_id,
            event->reserved,
            event->image_base);
        ac_log_event(
            logger,
            AC_SEVERITY_INFO,
            ac_kernel_event_name(event->type, event->flags),
            event->process_id,
            details);
        return;
    }

    ac_kernel_event_path(
        event,
        escaped_path,
        sizeof(escaped_path));

    (void)snprintf(
        details,
        sizeof(details),
        "{\"driver_sequence\":%" PRIu64
        ",\"kernel_timestamp_100ns\":%" PRIu64
        ",\"type\":%u,\"flags\":%u,\"parent_pid\":%u,"
        "\"status\":\"0x%08x\",\"image_base\":\"0x%" PRIx64
        "\",\"image_size\":%" PRIu64 ",\"path\":\"%s\","
        "\"source\":\"kernel_callback\",\"verdict\":\"telemetry_only\"}",
        event->sequence,
        event->timestamp_100ns,
        event->type,
        event->flags,
        event->parent_process_id,
        (unsigned int)(uint32_t)event->status,
        event->image_base,
        event->image_size,
        escaped_path);

    ac_log_event(
        logger,
        AC_SEVERITY_INFO,
        ac_kernel_event_name(event->type, event->flags),
        event->process_id,
        details);
}

static void ac_kernel_client_observe_thread(
    AcKernelClient *client,
    AcDriverEvent *event,
    DWORD target_pid)
{
    AcKernelThreadObservation *observation;

    if (event->type != AC_DRIVER_EVENT_THREAD_CREATED ||
        event->process_id != (uint32_t)target_pid) {
        return;
    }

    event->image_base = ac_kernel_query_thread_start(
        event->parent_process_id);
    if (client->thread_observation_count >=
        AC_KERNEL_MAX_THREAD_OBSERVATIONS) {
        bool secure = false;
        const uint64_t observations_seen =
            (uint64_t)client->thread_observation_count +
            client->thread_observations_omitted + 1u;
        const size_t selected = ac_kernel_reservoir_index(
            observations_seen,
            event->sequence,
            &secure);

        ++client->thread_observations_omitted;
        client->telemetry_complete = false;
        if (!secure) {
            client->correlation_random_source_available = false;
        }
        if (selected >= AC_KERNEL_MAX_THREAD_OBSERVATIONS) {
            return;
        }
        observation = &client->thread_observations[selected];
    } else {
        observation = &client->thread_observations[
            client->thread_observation_count++];
    }
    observation->sequence = event->sequence;
    observation->start_address = event->image_base;
    observation->thread_id = event->parent_process_id;
    observation->creator_pid = event->reserved;
}

static void ac_kernel_client_observe_image(
    AcKernelClient *client,
    const AcDriverEvent *event,
    DWORD target_pid)
{
    AcKernelImageObservation *observation;

    if (event->type != AC_DRIVER_EVENT_IMAGE_LOADED ||
        event->process_id != (uint32_t)target_pid) {
        return;
    }

    if (client->image_observation_count >=
        AC_KERNEL_MAX_IMAGE_OBSERVATIONS) {
        bool secure = false;
        const uint64_t observations_seen =
            (uint64_t)client->image_observation_count +
            client->image_observations_omitted + 1u;
        const size_t selected = ac_kernel_reservoir_index(
            observations_seen,
            event->sequence,
            &secure);

        ++client->image_observations_omitted;
        client->telemetry_complete = false;
        if (!secure) {
            client->correlation_random_source_available = false;
        }
        if (selected >= AC_KERNEL_MAX_IMAGE_OBSERVATIONS) {
            return;
        }
        observation = &client->image_observations[selected];
    } else {
        observation = &client->image_observations[
            client->image_observation_count++];
    }
    observation->sequence = event->sequence;
    observation->image_base = event->image_base;
    observation->image_size = event->image_size;
}

bool ac_kernel_client_process_stats(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    const AcDriverStats *stats)
{
    uint64_t newly_dropped = 0;

    if (client == NULL || logger == NULL || stats == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (stats->queue_capacity == 0 ||
        stats->queue_depth > stats->queue_capacity) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    if (stats->next_sequence <= client->last_sequence) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    if (!ac_kernel_client_observe_drop_counter(
            client,
            stats->events_dropped,
            &newly_dropped)) {
        return false;
    }

    if (newly_dropped > 0) {
        char details[640];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"events_dropped\":%" PRIu64
            ",\"newly_dropped\":%" PRIu64
            ",\"queue_depth\":%u,\"queue_capacity\":%u,"
            "\"telemetry_complete\":false,"
            "\"possible_attack\":\"event_flooding\","
            "\"required_action\":\"invalidate_session_evidence\"}",
            stats->events_dropped,
            newly_dropped,
            stats->queue_depth,
            stats->queue_capacity);
        ac_log_event(
            logger,
            AC_SEVERITY_HIGH,
            "kernel_event_queue_overflow",
            target_pid,
            details);
    }

    if (!client->callback_state_initialized ||
        client->last_callbacks_active != stats->callbacks_active) {
        if (stats->callbacks_active != AC_DRIVER_CALLBACK_REQUIRED) {
            char details[256];
            (void)snprintf(
                details,
                sizeof(details),
                "{\"callbacks_active\":%u,\"expected_mask\":%u,"
                "\"telemetry_complete\":false}",
                stats->callbacks_active,
                (unsigned int)AC_DRIVER_CALLBACK_REQUIRED);
            ac_log_event(
                logger,
                AC_SEVERITY_HIGH,
                "kernel_callback_health_degraded",
                target_pid,
                details);
            client->telemetry_complete = false;
        } else if (client->callback_state_initialized) {
            ac_log_event(
                logger,
                AC_SEVERITY_INFO,
                "kernel_callback_health_restored",
                target_pid,
                "{\"callbacks_active\":15}");
        }
        client->last_callbacks_active = stats->callbacks_active;
        client->callback_state_initialized = true;
    }

    if (stats->queue_depth >= stats->queue_capacity) {
        if (!client->queue_saturated) {
            char details[256];
            (void)snprintf(
                details,
                sizeof(details),
                "{\"queue_depth\":%u,\"queue_capacity\":%u,"
                "\"events_dropped\":%" PRIu64 "}",
                stats->queue_depth,
                stats->queue_capacity,
                stats->events_dropped);
            ac_log_event(
                logger,
                AC_SEVERITY_MEDIUM,
                "kernel_event_queue_saturated",
                target_pid,
                details);
            client->queue_saturated = true;
        }
    } else {
        client->queue_saturated = false;
    }

    return true;
}

static bool ac_kernel_client_check_health(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid)
{
    AcDriverStats stats;

    if (!ac_kernel_client_get_stats(client, &stats)) {
        return false;
    }
    return ac_kernel_client_process_stats(
        client,
        logger,
        target_pid,
        &stats);
}

bool ac_kernel_client_drain(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t *events_out)
{
    AcDriverEvent *events;
    uint64_t total = 0;
    unsigned int batch;

    if (client == NULL || logger == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    events = (AcDriverEvent *)malloc(
        (size_t)AC_DRIVER_MAX_BATCH_EVENTS * sizeof(*events));
    if (events == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }

    if (!ac_kernel_client_check_health(client, logger, target_pid)) {
        free(events);
        return false;
    }

    for (batch = 0; batch < AC_KERNEL_DRAIN_BATCH_LIMIT; ++batch) {
        DWORD returned = 0;
        size_t count;
        size_t index;

        if (!DeviceIoControl(
                client->device,
                IOCTL_AC_READ_EVENTS,
                NULL,
                0,
                events,
                (DWORD)((size_t)AC_DRIVER_MAX_BATCH_EVENTS * sizeof(*events)),
                &returned,
                NULL)) {
            free(events);
            return false;
        }

        if (returned % (DWORD)sizeof(AcDriverEvent) != 0) {
            SetLastError(ERROR_INVALID_DATA);
            free(events);
            return false;
        }

        count = returned / (DWORD)sizeof(AcDriverEvent);
        for (index = 0; index < count; ++index) {
            uint64_t missing = 0;

            if (events[index].size !=
                    (uint32_t)sizeof(AcDriverEvent) ||
                events[index].protocol_version !=
                    AC_DRIVER_PROTOCOL_VERSION) {
                SetLastError(ERROR_INVALID_DATA);
                free(events);
                return false;
            }
            if (!ac_kernel_client_observe_sequence(
                    client,
                    events[index].sequence,
                    &missing)) {
                free(events);
                return false;
            }
            if (missing > 0) {
                char details[384];
                (void)snprintf(
                    details,
                    sizeof(details),
                    "{\"expected_sequence\":%" PRIu64
                    ",\"observed_sequence\":%" PRIu64
                    ",\"events_missing\":%" PRIu64
                    ",\"telemetry_complete\":false}",
                    events[index].sequence - missing,
                    events[index].sequence,
                    missing);
                ac_log_event(
                    logger,
                    AC_SEVERITY_HIGH,
                    "kernel_event_sequence_gap",
                    target_pid,
                    details);
            }
            ac_kernel_client_observe_image(
                client,
                &events[index],
                target_pid);
            ac_kernel_client_observe_thread(
                client,
                &events[index],
                target_pid);
            ac_log_kernel_event(logger, &events[index]);
            ++total;
        }

        if (count < AC_DRIVER_MAX_BATCH_EVENTS) {
            break;
        }
    }

    if (!ac_kernel_client_check_health(client, logger, target_pid)) {
        free(events);
        return false;
    }

    if (events_out != NULL) {
        *events_out += total;
    }
    free(events);
    return true;
}

void ac_kernel_client_correlate_scan(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const AcRangeIndex *module_ranges,
    uint64_t *mismatches_out)
{
    size_t index;
    size_t mismatches = 0;
    size_t image_reported = 0;
    size_t suspicious_threads = 0;
    size_t thread_reported = 0;
    const size_t observations = client != NULL
        ? client->image_observation_count
        : 0;
    const uint64_t omitted = client != NULL
        ? client->image_observations_omitted
        : 0;
    const size_t thread_observations = client != NULL
        ? client->thread_observation_count
        : 0;
    const uint64_t thread_omitted = client != NULL
        ? client->thread_observations_omitted
        : 0;

    if (client == NULL || logger == NULL || module_ranges == NULL) {
        return;
    }

    for (index = 0; index < observations; ++index) {
        const AcKernelImageObservation *observation =
            &client->image_observations[index];

        if (observation->image_base != 0 &&
            observation->image_base <= (uint64_t)UINTPTR_MAX &&
            ac_range_index_contains(
                module_ranges,
                (uintptr_t)observation->image_base,
                1u)) {
            continue;
        }

        ++mismatches;
        if (image_reported < AC_KERNEL_MAX_MISMATCH_EVENTS) {
            char details[512];
            (void)snprintf(
                details,
                sizeof(details),
                "{\"scan_id\":%" PRIu64
                ",\"driver_sequence\":%" PRIu64
                ",\"image_base\":\"0x%" PRIx64
                "\",\"image_size\":%" PRIu64
                ",\"reason\":\"kernel_image_missing_from_user_snapshot\","
                "\"user_mode_source\":\"toolhelp32\","
                "\"possible_causes\":[\"transient_unload\","
                "\"user_mode_api_interception\"]}",
                scan_id,
                observation->sequence,
                observation->image_base,
                observation->image_size);
            ac_log_event(
                logger,
                AC_SEVERITY_MEDIUM,
                "kernel_user_module_mismatch",
                target_pid,
                details);
            ++image_reported;
        }
    }

    for (index = 0; index < thread_observations; ++index) {
        const AcKernelThreadObservation *observation =
            &client->thread_observations[index];

        if (observation->start_address != 0 &&
            observation->start_address <= (uint64_t)UINTPTR_MAX &&
            ac_range_index_contains(
                module_ranges,
                (uintptr_t)observation->start_address,
                1u)) {
            continue;
        }

        ++suspicious_threads;
        if (thread_reported < AC_KERNEL_MAX_MISMATCH_EVENTS) {
            char details[512];
            (void)snprintf(
                details,
                sizeof(details),
                "{\"scan_id\":%" PRIu64
                ",\"driver_sequence\":%" PRIu64
                ",\"thread_id\":%u,\"creator_pid\":%u,"
                "\"start_address\":\"0x%" PRIx64
                "\",\"reason\":\"thread_start_outside_loader_modules\","
                "\"start_address_available\":%s}",
                scan_id,
                observation->sequence,
                observation->thread_id,
                observation->creator_pid,
                observation->start_address,
                observation->start_address != 0 ? "true" : "false");
            ac_log_event(
                logger,
                observation->start_address != 0
                    ? AC_SEVERITY_HIGH : AC_SEVERITY_LOW,
                observation->start_address != 0
                    ? "kernel_thread_start_unlinked"
                    : "kernel_thread_start_unavailable",
                target_pid,
                details);
            ++thread_reported;
        }
    }

    if (omitted > 0 || thread_omitted > 0 ||
        mismatches > image_reported ||
        suspicious_threads > thread_reported) {
        char details[384];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64
            ",\"observations_omitted\":%" PRIu64
            ",\"thread_observations_omitted\":%" PRIu64
            ",\"mismatch_events_omitted\":%zu,"
            "\"thread_events_omitted\":%zu,"
            "\"random_source_available\":%s,"
            "\"telemetry_complete\":false}",
            scan_id,
            omitted,
            thread_omitted,
            mismatches - image_reported,
            suspicious_threads - thread_reported,
            client->correlation_random_source_available ? "true" : "false");
        ac_log_event(
            logger,
            AC_SEVERITY_HIGH,
            "kernel_correlation_coverage_gap",
            target_pid,
            details);
        client->telemetry_complete = false;
    }

    if (observations > 0 || omitted > 0) {
        char details[512];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64
            ",\"kernel_images_observed\":%zu,"
            "\"visible_in_user_snapshot\":%zu,"
            "\"missing_from_user_snapshot\":%zu,"
            "\"observations_omitted\":%" PRIu64
            ",\"user_mode_trust\":\"untrusted\"}",
            scan_id,
            observations,
            observations - mismatches,
            mismatches,
            omitted);
        ac_log_event(
            logger,
            AC_SEVERITY_INFO,
            "kernel_user_scan_correlation",
            target_pid,
            details);
    }

    if (thread_observations > 0 || thread_omitted > 0) {
        char details[512];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64
            ",\"threads_observed\":%zu,"
            "\"starts_inside_loader_modules\":%zu,"
            "\"starts_suspicious_or_unavailable\":%zu,"
            "\"observations_omitted\":%" PRIu64 "}",
            scan_id,
            thread_observations,
            thread_observations - suspicious_threads,
            suspicious_threads,
            thread_omitted);
        ac_log_event(
            logger,
            AC_SEVERITY_INFO,
            "kernel_thread_scan_correlation",
            target_pid,
            details);
    }

    if (mismatches > 0 || suspicious_threads > 0 ||
        thread_omitted > 0) {
        client->telemetry_complete = false;
    }
    if (mismatches_out != NULL) {
        *mismatches_out += mismatches;
    }
    client->image_observation_count = 0;
    client->image_observations_omitted = 0;
    client->thread_observation_count = 0;
    client->thread_observations_omitted = 0;
    client->correlation_random_source_available = true;
}
