#include "ac.h"

#include <inttypes.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <wchar.h>

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011u
#endif

#define AC_THREAT_INDICATOR_SET \
    "dragonburn-6c718998_valthrun-ac08b2d7"
#define AC_DEVICE_BUFFER_INITIAL 65536u
#define AC_DEVICE_BUFFER_MAX 1048576u
#define AC_OVERLAY_MIN_OVERLAP_PER_MILLE 850u
#define AC_NATIVE_DEVICE_BUFFER_SIZE 65536u
#define AC_DRIVER_SNAPSHOT_INITIAL 256u
#define AC_DRIVER_SNAPSHOT_MAX 4096u
#define AC_DRIVER_PATH_WIDE_CAPACITY 1024u
#define AC_DRIVER_PATH_UTF8_CAPACITY 3072u
#define AC_DRIVER_PATH_ESCAPED_CAPACITY 6144u
#define AC_DRIVER_DETAILS_CAPACITY 6656u
#define AC_STATUS_NO_MORE_ENTRIES ((LONG)0x8000001aL)
#define AC_SYSTEM_CODE_INTEGRITY_INFORMATION 103u
#define AC_CI_OPTION_ENABLED 0x00000001u
#define AC_CI_OPTION_TESTSIGN 0x00000002u
#define AC_CI_OPTION_DEBUGMODE_ENABLED 0x00000080u
#define AC_CI_OPTION_HVCI_KMCI_ENABLED 0x00000400u

typedef struct AcSystemCodeIntegrityInformation {
    ULONG length;
    ULONG options;
} AcSystemCodeIntegrityInformation;

typedef NTSTATUS (NTAPI *AcNtQuerySystemInformationFn)(
    ULONG information_class,
    PVOID information,
    ULONG information_length,
    PULONG return_length);

typedef struct AcObjectDirectoryInformation {
    UNICODE_STRING name;
    UNICODE_STRING type_name;
} AcObjectDirectoryInformation;

typedef struct AcTargetWindowSearch {
    DWORD target_pid;
    HWND window;
    uint64_t area;
} AcTargetWindowSearch;

typedef struct AcOverlaySearch {
    AcThreatSensor *sensor;
    AcLogger *logger;
    DWORD target_pid;
    HWND target_window;
    RECT target_rect;
    uint64_t scan_id;
    AcThreatScanStats *stats;
} AcOverlaySearch;

typedef struct AcDriverSnapshotBuffers {
    wchar_t kernel_path[AC_DRIVER_PATH_WIDE_CAPACITY];
    wchar_t file_path[AC_DRIVER_PATH_WIDE_CAPACITY];
    char path_utf8[AC_DRIVER_PATH_UTF8_CAPACITY];
    char escaped_path[AC_DRIVER_PATH_ESCAPED_CAPACITY];
    char details[AC_DRIVER_DETAILS_CAPACITY];
} AcDriverSnapshotBuffers;

static const char *ac_configured_state_name(AcConfiguredState state)
{
    switch (state) {
        case AC_CONFIGURED_DISABLED: return "disabled";
        case AC_CONFIGURED_ENABLED: return "enabled";
        default: return "unknown";
    }
}

static AcConfiguredState ac_read_configured_dword(
    const wchar_t *subkey,
    const wchar_t *value_name)
{
    DWORD value = 0;
    DWORD size = (DWORD)sizeof(value);
    const LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        subkey,
        value_name,
        RRF_RT_REG_DWORD,
        NULL,
        &value,
        &size);

    if (status != ERROR_SUCCESS || size != (DWORD)sizeof(value)) {
        return AC_CONFIGURED_UNKNOWN;
    }
    return value == 0 ? AC_CONFIGURED_DISABLED : AC_CONFIGURED_ENABLED;
}

const char *ac_known_threat_process_indicator(
    const wchar_t *image_name,
    AcSeverity *severity_out)
{
    if (severity_out != NULL) {
        *severity_out = AC_SEVERITY_INFO;
    }
    if (image_name == NULL) {
        return NULL;
    }

    if (_wcsicmp(image_name, L"DragonBurn-kernel.exe") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_HIGH;
        }
        return "dragonburn_kernel_mapper_image";
    }
    if (_wcsicmp(image_name, L"DragonBurn-usermode.exe") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_HIGH;
        }
        return "dragonburn_user_client_image";
    }
    if (_wcsicmp(image_name, L"DragonBurn.exe") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_MEDIUM;
        }
        return "dragonburn_release_image";
    }
    return NULL;
}

const char *ac_known_threat_device_indicator(
    const wchar_t *device_name,
    AcSeverity *severity_out)
{
    if (severity_out != NULL) {
        *severity_out = AC_SEVERITY_INFO;
    }
    if (device_name == NULL) {
        return NULL;
    }

    if (_wcsicmp(device_name, L"DragonBurn-kmd") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_HIGH;
        }
        return "dragonburn_kernel_device";
    }
    if (_wcsicmp(device_name, L"Nal") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_MEDIUM;
        }
        return "intel_vulnerable_driver_device";
    }
    if (_wcsicmp(device_name, L"valthrun") == 0) {
        if (severity_out != NULL) {
            *severity_out = AC_SEVERITY_HIGH;
        }
        return "valthrun_native_kernel_device";
    }
    return NULL;
}

AcSeverity ac_security_posture_severity(
    AcConfiguredState vulnerable_driver_blocklist,
    AcConfiguredState hvci,
    AcConfiguredState vbs,
    AcConfiguredState run_as_ppl)
{
    if (vulnerable_driver_blocklist == AC_CONFIGURED_DISABLED) {
        return AC_SEVERITY_HIGH;
    }
    if (hvci == AC_CONFIGURED_DISABLED ||
        vbs == AC_CONFIGURED_DISABLED) {
        return AC_SEVERITY_MEDIUM;
    }
    if (run_as_ppl == AC_CONFIGURED_DISABLED) {
        return AC_SEVERITY_LOW;
    }
    return AC_SEVERITY_INFO;
}

bool ac_query_runtime_kernel_posture(AcRuntimeKernelPosture *posture)
{
    HMODULE ntdll;
    AcNtQuerySystemInformationFn query;
    AcSystemCodeIntegrityInformation information;
    NTSTATUS status;

    if (posture == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    memset(posture, 0, sizeof(*posture));
    posture->secure_boot = ac_read_configured_dword(
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled");
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    query = (AcNtQuerySystemInformationFn)(uintptr_t)GetProcAddress(
        ntdll, "NtQuerySystemInformation");
    if (query == NULL) {
        return false;
    }
    memset(&information, 0, sizeof(information));
    information.length = (ULONG)sizeof(information);
    status = query(
        AC_SYSTEM_CODE_INTEGRITY_INFORMATION,
        &information,
        (ULONG)sizeof(information),
        NULL);
    if (status < 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    posture->code_integrity_options = information.options;
    posture->code_integrity_enabled =
        (information.options & AC_CI_OPTION_ENABLED) != 0u;
    posture->test_signing_allowed =
        (information.options & AC_CI_OPTION_TESTSIGN) != 0u;
    posture->debug_mode_enabled =
        (information.options & AC_CI_OPTION_DEBUGMODE_ENABLED) != 0u;
    posture->hvci_kernel_enforced =
        (information.options & AC_CI_OPTION_HVCI_KMCI_ENABLED) != 0u;
    posture->query_complete = true;
    return true;
}

bool ac_runtime_kernel_posture_secure(const AcRuntimeKernelPosture *posture)
{
    return posture != NULL &&
           posture->query_complete &&
           posture->secure_boot == AC_CONFIGURED_ENABLED &&
           posture->code_integrity_enabled &&
           posture->hvci_kernel_enforced &&
           !posture->test_signing_allowed &&
           !posture->debug_mode_enabled;
}

void ac_log_runtime_kernel_posture(
    AcLogger *logger,
    DWORD target_pid,
    const AcRuntimeKernelPosture *posture)
{
    char details[512];
    bool secure;

    if (logger == NULL || posture == NULL) {
        return;
    }
    secure = ac_runtime_kernel_posture_secure(posture);
    (void)snprintf(
        details,
        sizeof(details),
        "{\"query_complete\":%s,\"secure_boot\":\"%s\","
        "\"code_integrity_options\":\"0x%08" PRIx32 "\","
        "\"code_integrity_enabled\":%s,\"test_signing_allowed\":%s,"
        "\"debug_mode_enabled\":%s,\"hvci_kernel_enforced\":%s,"
        "\"secure_kernel_policy_satisfied\":%s,"
        "\"source_trust\":\"local_kernel_reported\"}",
        posture->query_complete ? "true" : "false",
        ac_configured_state_name(posture->secure_boot),
        posture->code_integrity_options,
        posture->code_integrity_enabled ? "true" : "false",
        posture->test_signing_allowed ? "true" : "false",
        posture->debug_mode_enabled ? "true" : "false",
        posture->hvci_kernel_enforced ? "true" : "false",
        secure ? "true" : "false");
    ac_log_event(
        logger,
        secure ? AC_SEVERITY_INFO : AC_SEVERITY_HIGH,
        "kernel_runtime_trust_posture",
        target_pid,
        details);
}

bool ac_overlay_features_suspicious(const AcOverlayFeatures *features)
{
    if (features == NULL) {
        return false;
    }

    return features->topmost &&
           features->transparent &&
           features->overlap_per_mille >= AC_OVERLAY_MIN_OVERLAP_PER_MILLE &&
           (features->layered || features->no_activate) &&
           (features->ui_access || features->capture_excluded);
}

bool ac_threat_sensor_init(AcThreatSensor *sensor, uint64_t repeat_interval_ms)
{
    if (sensor == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    memset(sensor, 0, sizeof(*sensor));
    if (!ac_dedup_init(
            &sensor->dedup,
            AC_THREAT_DEDUP_CAPACITY,
            repeat_interval_ms)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    return true;
}

void ac_threat_sensor_free(AcThreatSensor *sensor)
{
    if (sensor == NULL) {
        return;
    }
    ac_dedup_free(&sensor->dedup);
    memset(sensor, 0, sizeof(*sensor));
}

void ac_threat_sensor_report_posture(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid)
{
    AcConfiguredState blocklist;
    AcConfiguredState hvci;
    AcConfiguredState vbs;
    AcConfiguredState run_as_ppl;
    AcSeverity severity;
    char details[768];

    if (sensor == NULL || logger == NULL || sensor->posture_reported) {
        return;
    }

    blocklist = ac_read_configured_dword(
        L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        L"VulnerableDriverBlocklistEnable");
    hvci = ac_read_configured_dword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled");
    vbs = ac_read_configured_dword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        L"EnableVirtualizationBasedSecurity");
    run_as_ppl = ac_read_configured_dword(
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RunAsPPL");
    severity = ac_security_posture_severity(blocklist, hvci, vbs, run_as_ppl);

    (void)snprintf(
        details,
        sizeof(details),
        "{\"configured_vulnerable_driver_blocklist\":\"%s\"," 
        "\"configured_hvci\":\"%s\",\"configured_vbs\":\"%s\"," 
        "\"configured_run_as_ppl\":\"%s\",\"source\":\"registry\"," 
        "\"source_trust\":\"untrusted_user_mode\"," 
        "\"verdict\":\"telemetry_only\"}",
        ac_configured_state_name(blocklist),
        ac_configured_state_name(hvci),
        ac_configured_state_name(vbs),
        ac_configured_state_name(run_as_ppl));
    ac_log_event(
        logger,
        severity,
        "kernel_attack_surface_posture",
        target_pid,
        details);
    sensor->posture_reported = true;
}

static bool ac_normalize_driver_path(
    const wchar_t *source,
    wchar_t *destination,
    size_t destination_count)
{
    if (source == NULL || destination == NULL || destination_count == 0) {
        return false;
    }

    if (_wcsnicmp(source, L"\\SystemRoot", 11u) == 0) {
        wchar_t windows_directory[MAX_PATH];
        const UINT length = GetWindowsDirectoryW(
            windows_directory,
            (UINT)(sizeof(windows_directory) /
                   sizeof(windows_directory[0])));
        if (length == 0 || length >=
            (UINT)(sizeof(windows_directory) /
                   sizeof(windows_directory[0]))) {
            return false;
        }
        return swprintf_s(
            destination,
            destination_count,
            L"%ls%ls",
            windows_directory,
            source + 11u) > 0;
    }

    if (wcsncmp(source, L"\\??\\", 4u) == 0) {
        source += 4u;
    }
    return wcscpy_s(destination, destination_count, source) == 0;
}

void ac_threat_sensor_report_driver_snapshot(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    const AcManifest *manifest)
{
    LPVOID *drivers = NULL;
    DWORD capacity = AC_DRIVER_SNAPSHOT_INITIAL;
    DWORD bytes_needed = 0;
    size_t driver_count = 0;
    size_t paths_available = 0;
    size_t hashes_available = 0;
    bool complete = false;
    AcDriverSnapshotBuffers *buffers;
    DWORD index;

    if (sensor == NULL || logger == NULL ||
        sensor->driver_snapshot_reported) {
        return;
    }
    sensor->driver_snapshot_reported = true;

    buffers = (AcDriverSnapshotBuffers *)calloc(1u, sizeof(*buffers));
    if (buffers == NULL) {
        return;
    }

    while (capacity <= AC_DRIVER_SNAPSHOT_MAX) {
        LPVOID *candidate = (LPVOID *)realloc(
            drivers,
            (size_t)capacity * sizeof(*drivers));
        if (candidate == NULL) {
            break;
        }
        drivers = candidate;
        if (!EnumDeviceDrivers(
                drivers,
                capacity * (DWORD)sizeof(*drivers),
                &bytes_needed)) {
            break;
        }
        if (bytes_needed <= capacity * (DWORD)sizeof(*drivers)) {
            driver_count = bytes_needed / sizeof(*drivers);
            complete = true;
            break;
        }
        capacity = bytes_needed / (DWORD)sizeof(*drivers) + 32u;
    }

    for (index = 0; index < (DWORD)driver_count; ++index) {
        char digest[AC_SHA256_HEX_SIZE];
        uint64_t file_size = 0;
        bool hash_available = false;
        const DWORD path_length = GetDeviceDriverFileNameW(
            drivers[index],
            buffers->kernel_path,
            AC_DRIVER_PATH_WIDE_CAPACITY);

        if (path_length == 0 || path_length >=
            AC_DRIVER_PATH_WIDE_CAPACITY) {
            continue;
        }
        ++paths_available;
        if (!ac_normalize_driver_path(
                buffers->kernel_path,
                buffers->file_path,
                AC_DRIVER_PATH_WIDE_CAPACITY)) {
            (void)wcscpy_s(
                buffers->file_path,
                AC_DRIVER_PATH_WIDE_CAPACITY,
                buffers->kernel_path);
        }
        hash_available = ac_hash_file(buffers->file_path, digest, &file_size);
        if (hash_available) {
            ++hashes_available;
        }
        if (!ac_wide_to_utf8(
                buffers->file_path,
                buffers->path_utf8,
                AC_DRIVER_PATH_UTF8_CAPACITY)) {
            (void)strcpy_s(
                buffers->path_utf8,
                AC_DRIVER_PATH_UTF8_CAPACITY,
                "<conversion-failed>");
        }
        (void)ac_json_escape(
            buffers->path_utf8,
            buffers->escaped_path,
            AC_DRIVER_PATH_ESCAPED_CAPACITY);
        (void)snprintf(
            buffers->details,
            AC_DRIVER_DETAILS_CAPACITY,
            "{\"image_base\":\"0x%" PRIxPTR
            "\",\"path\":\"%s\",\"file_sha256\":%s%s%s,"
            "\"file_size\":%" PRIu64
            ",\"source\":\"psapi_startup_snapshot\","
            "\"verdict\":\"manifest_input\"}",
            (uintptr_t)drivers[index],
            buffers->escaped_path,
            hash_available ? "\"" : "null",
            hash_available ? digest : "",
            hash_available ? "\"" : "",
            file_size);
        ac_log_event(
            logger,
            AC_SEVERITY_INFO,
            "loaded_kernel_driver_observed",
            target_pid,
            buffers->details);

        if (manifest != NULL && manifest->trusted) {
            const AcManifestMatch match = hash_available
                ? ac_manifest_match_hex(
                    manifest,
                    AC_MANIFEST_DRIVER,
                    buffers->file_path,
                    digest)
                : AC_MANIFEST_HASH_MISMATCH;
            if (match != AC_MANIFEST_AUTHORIZED) {
                (void)snprintf(
                    buffers->details,
                    AC_DRIVER_DETAILS_CAPACITY,
                    "{\"image_base\":\"0x%" PRIxPTR
                    "\",\"path\":\"%s\",\"file_sha256\":%s%s%s,"
                    "\"manifest_sha256\":\"%s\",\"reason\":\"%s\","
                    "\"verdict\":\"signal_only\"}",
                    (uintptr_t)drivers[index],
                    buffers->escaped_path,
                    hash_available ? "\"" : "null",
                    hash_available ? digest : "",
                    hash_available ? "\"" : "",
                    manifest->file_sha256,
                    !hash_available
                        ? "driver_hash_unavailable"
                        : match == AC_MANIFEST_HASH_MISMATCH
                            ? "manifest_hash_mismatch"
                            : "driver_not_in_manifest");
                ac_log_event(
                    logger,
                    hash_available
                        ? AC_SEVERITY_HIGH : AC_SEVERITY_MEDIUM,
                    "kernel_driver_manifest_violation",
                    target_pid,
                    buffers->details);
            }
        }
    }

    if (driver_count == 0 || paths_available != driver_count) {
        complete = false;
    }

    {
        char details[512];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"drivers_observed\":%zu,\"paths_available\":%zu,"
            "\"hashes_available\":%zu,\"complete\":%s,"
            "\"source\":\"psapi_startup_snapshot\","
            "\"requires_pinned_manifest\":true}",
            driver_count,
            paths_available,
            hashes_available,
            complete ? "true" : "false");
        ac_log_event(
            logger,
            complete ? AC_SEVERITY_INFO : AC_SEVERITY_MEDIUM,
            "loaded_kernel_driver_snapshot_completed",
            target_pid,
            details);
    }
    free(drivers);
    free(buffers);
}

void ac_threat_sensor_report_input_posture(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid)
{
    if (sensor == NULL || logger == NULL || sensor->input_posture_reported) {
        return;
    }

    ac_log_event(
        logger,
        AC_SEVERITY_MEDIUM,
        "input_provenance_posture",
        target_pid,
        "{\"direct_packet_attribution\":false,"
        "\"documented_windows_api_available\":false,"
        "\"kernel_driver_manifest_correlation\":true,"
        "\"raw_input_behavior_correlation_required\":true,"
        "\"verdict\":\"capability_gap\"}");
    sensor->input_posture_reported = true;
}

static bool ac_emit_indicator(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const char *category,
    const char *indicator,
    const wchar_t *observed_name,
    DWORD observed_pid,
    AcSeverity severity,
    AcThreatScanStats *stats)
{
    AcDedupDecision decision;
    uint64_t fingerprint;
    char name_utf8[512];
    char escaped_name[1024];
    char details[1536];

    fingerprint = ac_fnv1a64_text(AC_FNV1A64_OFFSET, "known_threat_indicator");
    fingerprint = ac_fnv1a64_text(fingerprint, category);
    fingerprint = ac_fnv1a64_text(fingerprint, indicator);
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &observed_pid,
        sizeof(observed_pid));
    ac_dedup_observe(
        &sensor->dedup,
        fingerprint,
        scan_id,
        GetTickCount64(),
        &decision);

    if (!decision.emit) {
        ++stats->events_suppressed;
        return false;
    }

    if (!ac_wide_to_utf8(
            observed_name != NULL ? observed_name : L"",
            name_utf8,
            sizeof(name_utf8))) {
        (void)strcpy_s(name_utf8, sizeof(name_utf8), "<conversion-failed>");
    }
    (void)ac_json_escape(name_utf8, escaped_name, sizeof(escaped_name));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"indicator_set\":\"%s\",\"category\":\"%s\"," 
        "\"indicator\":\"%s\",\"observed_name\":\"%s\"," 
        "\"observed_pid\":%lu,\"first_seen\":%s," 
        "\"occurrences\":%" PRIu64 ",\"source_trust\":\"untrusted_user_mode\"," 
        "\"verdict\":\"signal_only\"}",
        AC_THREAT_INDICATOR_SET,
        category,
        indicator,
        escaped_name,
        (unsigned long)observed_pid,
        decision.first_seen ? "true" : "false",
        decision.occurrences);
    ac_log_event(
        logger,
        severity,
        "known_threat_indicator_observed",
        target_pid,
        details);
    ++stats->events_emitted;
    return true;
}

static void ac_scan_process_indicators(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    AcThreatScanStats *stats)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        AcSeverity severity;
        const char *indicator;

        ++stats->processes_visited;
        indicator = ac_known_threat_process_indicator(entry.szExeFile, &severity);
        if (indicator == NULL) {
            continue;
        }
        ++stats->indicators_observed;
        (void)ac_emit_indicator(
            sensor,
            logger,
            target_pid,
            scan_id,
            "process_image",
            indicator,
            entry.szExeFile,
            entry.th32ProcessID,
            severity,
            stats);
    } while (Process32NextW(snapshot, &entry));

    stats->process_inventory_complete = GetLastError() == ERROR_NO_MORE_FILES;
    CloseHandle(snapshot);
}

static void ac_scan_device_indicators(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    AcThreatScanStats *stats)
{
    DWORD capacity = AC_DEVICE_BUFFER_INITIAL;
    wchar_t *buffer = NULL;
    DWORD length = 0;

    while (capacity <= AC_DEVICE_BUFFER_MAX) {
        wchar_t *candidate = (wchar_t *)realloc(
            buffer,
            (size_t)capacity * sizeof(wchar_t));

        if (candidate == NULL) {
            free(buffer);
            return;
        }
        buffer = candidate;
        length = QueryDosDeviceW(NULL, buffer, capacity);
        if (length != 0) {
            break;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            free(buffer);
            return;
        }
        capacity *= 2u;
    }

    if (length == 0) {
        free(buffer);
        return;
    }

    {
        const wchar_t *name = buffer;
        const wchar_t *end = buffer + length;

        while (name < end && *name != L'\0') {
            AcSeverity severity;
            const char *indicator;
            const size_t name_length = wcslen(name);

            ++stats->device_names_visited;
            indicator = ac_known_threat_device_indicator(name, &severity);
            if (indicator != NULL) {
                ++stats->indicators_observed;
                (void)ac_emit_indicator(
                    sensor,
                    logger,
                    target_pid,
                    scan_id,
                    "dos_device",
                    indicator,
                    name,
                    0,
                    severity,
                    stats);
            }
            name += name_length + 1u;
        }
    }

    stats->device_inventory_complete = true;
    free(buffer);
}

static bool ac_unicode_string_equals(
    const UNICODE_STRING *value,
    const wchar_t *expected)
{
    const size_t expected_length = expected != NULL ? wcslen(expected) : 0;

    return value != NULL && value->Buffer != NULL &&
           value->Length == expected_length * sizeof(wchar_t) &&
           _wcsnicmp(
               value->Buffer,
               expected,
               expected_length) == 0;
}

static void ac_scan_native_device_indicators(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    AcThreatScanStats *stats)
{
    typedef LONG (NTAPI *AcNtOpenDirectoryObject)(
        PHANDLE,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES);
    typedef LONG (NTAPI *AcNtQueryDirectoryObject)(
        HANDLE,
        PVOID,
        ULONG,
        BOOLEAN,
        BOOLEAN,
        PULONG,
        PULONG);
    HMODULE ntdll;
    AcNtOpenDirectoryObject open_directory;
    AcNtQueryDirectoryObject query_directory;
    FARPROC open_procedure;
    FARPROC query_procedure;
    UNICODE_STRING directory_name;
    OBJECT_ATTRIBUTES attributes;
    HANDLE directory = NULL;
    ULONG context = 0;
    bool restart_scan = true;
    void *buffer = NULL;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return;
    }
    open_procedure = GetProcAddress(
        ntdll,
        "NtOpenDirectoryObject");
    query_procedure = GetProcAddress(
        ntdll,
        "NtQueryDirectoryObject");
    if (open_procedure == NULL || query_procedure == NULL ||
        sizeof(open_directory) != sizeof(open_procedure) ||
        sizeof(query_directory) != sizeof(query_procedure)) {
        return;
    }
    memcpy(&open_directory, &open_procedure, sizeof(open_directory));
    memcpy(&query_directory, &query_procedure, sizeof(query_directory));

    directory_name.Buffer = L"\\Device";
    directory_name.Length = (USHORT)(7u * sizeof(wchar_t));
    directory_name.MaximumLength =
        (USHORT)(8u * sizeof(wchar_t));
    InitializeObjectAttributes(
        &attributes,
        &directory_name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    if (open_directory(&directory, 0x0001u, &attributes) < 0) {
        return;
    }

    buffer = malloc(AC_NATIVE_DEVICE_BUFFER_SIZE);
    if (buffer == NULL) {
        CloseHandle(directory);
        return;
    }

    for (;;) {
        AcObjectDirectoryInformation *entry;
        ULONG returned = 0;
        const LONG status = query_directory(
            directory,
            buffer,
            AC_NATIVE_DEVICE_BUFFER_SIZE,
            TRUE,
            restart_scan ? TRUE : FALSE,
            &context,
            &returned);
        wchar_t name[512];
        size_t characters;
        AcSeverity severity;
        const char *indicator;

        restart_scan = false;
        if (status == AC_STATUS_NO_MORE_ENTRIES) {
            stats->native_device_inventory_complete = true;
            break;
        }
        if (status < 0) {
            break;
        }

        entry = (AcObjectDirectoryInformation *)buffer;
        if (!ac_unicode_string_equals(&entry->type_name, L"Device") ||
            entry->name.Buffer == NULL || entry->name.Length == 0) {
            continue;
        }
        characters = entry->name.Length / sizeof(wchar_t);
        if (characters >= sizeof(name) / sizeof(name[0])) {
            characters = sizeof(name) / sizeof(name[0]) - 1u;
        }
        wmemcpy(name, entry->name.Buffer, characters);
        name[characters] = L'\0';
        ++stats->native_device_names_visited;

        indicator = ac_known_threat_device_indicator(name, &severity);
        if (indicator == NULL) {
            continue;
        }
        ++stats->indicators_observed;
        (void)ac_emit_indicator(
            sensor,
            logger,
            target_pid,
            scan_id,
            "native_device",
            indicator,
            name,
            0,
            severity,
            stats);
    }

    free(buffer);
    CloseHandle(directory);
}

static uint64_t ac_rect_area(const RECT *rect)
{
    const int64_t width = (int64_t)rect->right - rect->left;
    const int64_t height = (int64_t)rect->bottom - rect->top;

    if (width <= 0 || height <= 0) {
        return 0;
    }
    return (uint64_t)width * (uint64_t)height;
}

static BOOL CALLBACK ac_find_target_window(HWND window, LPARAM parameter)
{
    AcTargetWindowSearch *search = (AcTargetWindowSearch *)parameter;
    DWORD owner_pid = 0;
    RECT rect;
    uint64_t area;

    (void)GetWindowThreadProcessId(window, &owner_pid);
    if (owner_pid != search->target_pid || !IsWindowVisible(window) ||
        !GetWindowRect(window, &rect)) {
        return TRUE;
    }

    area = ac_rect_area(&rect);
    if (area > search->area) {
        search->window = window;
        search->area = area;
    }
    return TRUE;
}

static uint32_t ac_rect_overlap_per_mille(
    const RECT *target,
    const RECT *candidate)
{
    RECT intersection;
    uint64_t target_area;
    uint64_t intersection_area;

    if (!IntersectRect(&intersection, target, candidate)) {
        return 0;
    }
    target_area = ac_rect_area(target);
    intersection_area = ac_rect_area(&intersection);
    if (target_area == 0) {
        return 0;
    }
    return (uint32_t)((intersection_area * 1000u) / target_area);
}

static bool ac_process_has_ui_access(DWORD pid)
{
    HANDLE process;
    HANDLE token;
    BOOL ui_access = FALSE;
    DWORD returned = 0;
    bool result = false;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) {
        return false;
    }
    if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
        if (GetTokenInformation(
                token,
                TokenUIAccess,
                &ui_access,
                (DWORD)sizeof(ui_access),
                &returned)) {
            result = ui_access != FALSE;
        }
        CloseHandle(token);
    }
    CloseHandle(process);
    return result;
}

static BOOL CALLBACK ac_find_overlay_candidate(HWND window, LPARAM parameter)
{
    AcOverlaySearch *search = (AcOverlaySearch *)parameter;
    AcOverlayFeatures features;
    AcDedupDecision decision;
    DWORD owner_pid = 0;
    DWORD affinity = WDA_NONE;
    LONG_PTR style;
    RECT rect;
    uint64_t fingerprint;
    char details[768];

    ++search->stats->windows_visited;
    if (window == search->target_window || !IsWindowVisible(window) ||
        !GetWindowRect(window, &rect)) {
        return TRUE;
    }

    (void)GetWindowThreadProcessId(window, &owner_pid);
    if (owner_pid == 0 || owner_pid == search->target_pid ||
        owner_pid == GetCurrentProcessId()) {
        return TRUE;
    }

    style = GetWindowLongPtrW(window, GWL_EXSTYLE);
    memset(&features, 0, sizeof(features));
    features.topmost = (style & WS_EX_TOPMOST) != 0;
    features.transparent = (style & WS_EX_TRANSPARENT) != 0;
    features.layered = (style & WS_EX_LAYERED) != 0;
    features.no_activate = (style & WS_EX_NOACTIVATE) != 0;
    features.overlap_per_mille = ac_rect_overlap_per_mille(
        &search->target_rect,
        &rect);
    if (!features.topmost ||
        !features.transparent ||
        features.overlap_per_mille < AC_OVERLAY_MIN_OVERLAP_PER_MILLE ||
        (!features.layered && !features.no_activate)) {
        return TRUE;
    }

    features.ui_access = ac_process_has_ui_access(owner_pid);
    features.capture_excluded =
        GetWindowDisplayAffinity(window, &affinity) &&
        (affinity & WDA_EXCLUDEFROMCAPTURE) == WDA_EXCLUDEFROMCAPTURE;

    if (!ac_overlay_features_suspicious(&features)) {
        return TRUE;
    }

    ++search->stats->overlay_candidates;
    fingerprint = ac_fnv1a64_text(
        AC_FNV1A64_OFFSET,
        "external_overlay_candidate");
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &owner_pid,
        sizeof(owner_pid));
    ac_dedup_observe(
        &search->sensor->dedup,
        fingerprint,
        search->scan_id,
        GetTickCount64(),
        &decision);
    if (!decision.emit) {
        ++search->stats->events_suppressed;
        return TRUE;
    }

    (void)snprintf(
        details,
        sizeof(details),
        "{\"owner_pid\":%lu,\"target_pid\":%lu," 
        "\"topmost\":%s,\"transparent\":%s,\"layered\":%s," 
        "\"no_activate\":%s,\"ui_access\":%s," 
        "\"capture_excluded\":%s,\"overlap_per_mille\":%u," 
        "\"source_trust\":\"untrusted_user_mode\"," 
        "\"verdict\":\"signal_only\"}",
        (unsigned long)owner_pid,
        (unsigned long)search->target_pid,
        features.topmost ? "true" : "false",
        features.transparent ? "true" : "false",
        features.layered ? "true" : "false",
        features.no_activate ? "true" : "false",
        features.ui_access ? "true" : "false",
        features.capture_excluded ? "true" : "false",
        features.overlap_per_mille);
    ac_log_event(
        search->logger,
        AC_SEVERITY_MEDIUM,
        "external_overlay_candidate",
        search->target_pid,
        details);
    ++search->stats->events_emitted;
    return TRUE;
}

static void ac_scan_overlay_candidates(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    AcThreatScanStats *stats)
{
    AcTargetWindowSearch target_search;
    AcOverlaySearch overlay_search;

    memset(&target_search, 0, sizeof(target_search));
    target_search.target_pid = target_pid;
    if (!EnumWindows(ac_find_target_window, (LPARAM)&target_search)) {
        return;
    }
    if (target_search.window == NULL) {
        return;
    }

    memset(&overlay_search, 0, sizeof(overlay_search));
    overlay_search.sensor = sensor;
    overlay_search.logger = logger;
    overlay_search.target_pid = target_pid;
    overlay_search.target_window = target_search.window;
    overlay_search.scan_id = scan_id;
    overlay_search.stats = stats;
    if (!GetWindowRect(target_search.window, &overlay_search.target_rect)) {
        return;
    }

    if (EnumWindows(ac_find_overlay_candidate, (LPARAM)&overlay_search)) {
        stats->window_inventory_complete = true;
    }
}

static void ac_scan_target_wndproc(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const AcRangeIndex *module_ranges,
    AcThreatScanStats *stats)
{
    AcTargetWindowSearch target_search;
    LONG_PTR window_proc;
    AcDedupDecision decision;
    uint64_t fingerprint;
    char details[512];

    if (module_ranges == NULL) {
        return;
    }
    memset(&target_search, 0, sizeof(target_search));
    target_search.target_pid = target_pid;
    if (!EnumWindows(ac_find_target_window, (LPARAM)&target_search) ||
        target_search.window == NULL) {
        return;
    }

    SetLastError(ERROR_SUCCESS);
    window_proc = GetWindowLongPtrW(target_search.window, GWLP_WNDPROC);
    if (window_proc == 0 || ac_range_index_contains(
            module_ranges,
            (uintptr_t)window_proc,
            1u)) {
        return;
    }

    ++stats->indirect_dispatch_candidates;
    fingerprint = ac_fnv1a64_text(
        AC_FNV1A64_OFFSET,
        "target_wndproc_outside_loader_modules");
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &window_proc,
        sizeof(window_proc));
    ac_dedup_observe(
        &sensor->dedup,
        fingerprint,
        scan_id,
        GetTickCount64(),
        &decision);
    if (!decision.emit) {
        ++stats->events_suppressed;
        return;
    }

    (void)snprintf(
        details,
        sizeof(details),
        "{\"target_pid\":%lu,\"wndproc\":\"0x%" PRIxPTR
        "\",\"reason\":\"dispatch_target_outside_loader_modules\","
        "\"source_trust\":\"untrusted_user_mode\","
        "\"verdict\":\"signal_only\"}",
        (unsigned long)target_pid,
        (uintptr_t)window_proc);
    ac_log_event(
        logger,
        AC_SEVERITY_HIGH,
        "target_wndproc_outside_loader_modules",
        target_pid,
        details);
    ++stats->events_emitted;
}

void ac_threat_sensor_scan(
    AcThreatSensor *sensor,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const AcRangeIndex *module_ranges,
    AcThreatScanStats *stats_out)
{
    AcThreatScanStats stats;
    char details[768];

    memset(&stats, 0, sizeof(stats));
    if (sensor == NULL || logger == NULL || target_pid == 0) {
        if (stats_out != NULL) {
            *stats_out = stats;
        }
        return;
    }

    ac_scan_process_indicators(sensor, logger, target_pid, scan_id, &stats);
    ac_scan_device_indicators(sensor, logger, target_pid, scan_id, &stats);
    ac_scan_native_device_indicators(
        sensor,
        logger,
        target_pid,
        scan_id,
        &stats);
    ac_scan_overlay_candidates(sensor, logger, target_pid, scan_id, &stats);
    ac_scan_target_wndproc(
        sensor,
        logger,
        target_pid,
        scan_id,
        module_ranges,
        &stats);

    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"processes_visited\":%zu," 
        "\"device_names_visited\":%zu,"
        "\"native_device_names_visited\":%zu,\"windows_visited\":%zu,"
        "\"indicators_observed\":%zu,\"overlay_candidates\":%zu,"
        "\"indirect_dispatch_candidates\":%zu,"
        "\"events_emitted\":%zu,\"events_suppressed\":%zu," 
        "\"process_inventory_complete\":%s," 
        "\"device_inventory_complete\":%s," 
        "\"native_device_inventory_complete\":%s,"
        "\"window_inventory_complete\":%s," 
        "\"source_trust\":\"untrusted_user_mode\"}",
        scan_id,
        stats.processes_visited,
        stats.device_names_visited,
        stats.native_device_names_visited,
        stats.windows_visited,
        stats.indicators_observed,
        stats.overlay_candidates,
        stats.indirect_dispatch_candidates,
        stats.events_emitted,
        stats.events_suppressed,
        stats.process_inventory_complete ? "true" : "false",
        stats.device_inventory_complete ? "true" : "false",
        stats.native_device_inventory_complete ? "true" : "false",
        stats.window_inventory_complete ? "true" : "false");
    ac_log_event(
        logger,
        AC_SEVERITY_INFO,
        "threat_sensor_scan_completed",
        target_pid,
        details);

    if (stats_out != NULL) {
        *stats_out = stats;
    }
}
