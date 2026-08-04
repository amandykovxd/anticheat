#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>

#include "schedule.h"

#define AC_MAX_REGION_EVENTS_PER_SCAN 64u
#define AC_FILE_HASH_LIMIT (256ull * 1024ull * 1024ull)
#define AC_FILE_HASH_CHUNK (64u * 1024u)

typedef struct AcRegionFinding {
    const char *reason;
    AcSeverity severity;
    bool backed_by_module;
    bool pe_header;
    bool content_hashed;
    uint16_t pe_machine;
    char content_sha256[AC_SHA256_HEX_SIZE];
} AcRegionFinding;

typedef struct AcRegionSample {
    MEMORY_BASIC_INFORMATION memory;
    AcRegionFinding finding;
} AcRegionSample;

static uint64_t ac_random_u64(uint64_t fallback, bool *secure_out)
{
    uint64_t value = 0;

    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&value,
            (ULONG)sizeof(value),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        if (secure_out != NULL) {
            *secure_out = false;
        }
        value = fallback ^ GetTickCount64();
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value *= UINT64_C(2685821657736338717);
    } else if (secure_out != NULL) {
        *secure_out = true;
    }
    return value;
}

static bool ac_is_executable_protection(DWORD protection)
{
    const DWORD base = protection & 0xffu;

    return base == PAGE_EXECUTE ||
           base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

static bool ac_is_writable_executable(DWORD protection)
{
    return (protection & 0xffu) == PAGE_EXECUTE_READWRITE;
}

static const char *ac_memory_type_name(DWORD type)
{
    switch (type) {
        case MEM_IMAGE: return "image";
        case MEM_MAPPED: return "mapped";
        case MEM_PRIVATE: return "private";
        default: return "unknown";
    }
}

static unsigned int ac_size_bucket(uint64_t size)
{
    unsigned int bucket = 0;

    while (size > 1u && bucket < 63u) {
        size >>= 1;
        ++bucket;
    }
    return bucket;
}

void ac_module_list_init(AcModuleList *modules)
{
    if (modules == NULL) {
        return;
    }
    modules->items = NULL;
    modules->count = 0;
    modules->capacity = 0;
    modules->truncated = false;
}

void ac_module_list_free(AcModuleList *modules)
{
    if (modules == NULL) {
        return;
    }
    free(modules->items);
    ac_module_list_init(modules);
}

bool ac_module_list_push(
    AcModuleList *modules,
    uintptr_t base,
    size_t size,
    const wchar_t *path)
{
    AcModule *module;

    if (modules == NULL) {
        return false;
    }

    if (modules->count >= AC_MAX_MODULES) {
        modules->truncated = true;
        return false;
    }

    if (modules->count == modules->capacity) {
        const size_t capacity = modules->capacity == 0 ? 128u : modules->capacity * 2u;
        AcModule *items;

        if (capacity > SIZE_MAX / sizeof(AcModule)) {
            return false;
        }
        items = (AcModule *)realloc(modules->items, capacity * sizeof(AcModule));
        if (items == NULL) {
            return false;
        }
        modules->items = items;
        modules->capacity = capacity;
    }

    module = &modules->items[modules->count];
    module->base = base;
    module->size = size;
    module->path[0] = L'\0';
    if (path != NULL) {
        (void)wcsncpy_s(
            module->path,
            sizeof(module->path) / sizeof(module->path[0]),
            path,
            _TRUNCATE);
    }
    ++modules->count;
    return true;
}

bool ac_collect_modules(DWORD pid, AcModuleList *modules, DWORD *error_out)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W entry;
    DWORD error = ERROR_SUCCESS;
    unsigned int attempt;

    if (modules == NULL) {
        if (error_out != NULL) {
            *error_out = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    modules->count = 0;
    modules->truncated = false;

    for (attempt = 0; attempt < AC_MAX_SNAPSHOT_RETRIES; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid);
        if (snapshot != INVALID_HANDLE_VALUE) {
            break;
        }

        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) {
            if (error_out != NULL) {
                *error_out = error;
            }
            return false;
        }
        Sleep(attempt < 4u ? 0u : 10u);
    }

    if (snapshot == INVALID_HANDLE_VALUE) {
        if (error_out != NULL) {
            *error_out = error;
        }
        return false;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        if (error_out != NULL) {
            *error_out = error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : error;
        }
        return error == ERROR_NO_MORE_FILES;
    }

    do {
        if (!ac_module_list_push(
                modules,
                (uintptr_t)entry.modBaseAddr,
                (size_t)entry.modBaseSize,
                entry.szExePath)) {
            if (!modules->truncated) {
                CloseHandle(snapshot);
                if (error_out != NULL) {
                    *error_out = ERROR_NOT_ENOUGH_MEMORY;
                }
                return false;
            }
            break;
        }
    } while (Module32NextW(snapshot, &entry));

    error = modules->truncated ? ERROR_NO_MORE_FILES : GetLastError();
    CloseHandle(snapshot);

    if (error != ERROR_NO_MORE_FILES) {
        if (error_out != NULL) {
            *error_out = error;
        }
        return false;
    }

    if (error_out != NULL) {
        *error_out = ERROR_SUCCESS;
    }
    return true;
}

bool ac_path_is_under(const wchar_t *path, const wchar_t *directory)
{
    size_t directory_length;

    if (path == NULL || directory == NULL) {
        return false;
    }

    directory_length = wcslen(directory);
    while (directory_length > 0 &&
           (directory[directory_length - 1] == L'\\' ||
            directory[directory_length - 1] == L'/')) {
        --directory_length;
    }

    if (directory_length == 0 ||
        _wcsnicmp(path, directory, directory_length) != 0) {
        return false;
    }

    return path[directory_length] == L'\0' ||
           path[directory_length] == L'\\' ||
           path[directory_length] == L'/';
}

bool ac_path_is_under_any(
    const wchar_t *path,
    const wchar_t **directories,
    size_t directory_count)
{
    size_t index;

    if (path == NULL || directories == NULL) {
        return false;
    }

    for (index = 0; index < directory_count; ++index) {
        if (ac_path_is_under(path, directories[index])) {
            return true;
        }
    }
    return false;
}

bool ac_dispatch_watch_parse(
    const wchar_t *specification,
    AcDispatchWatchKind kind,
    AcDispatchWatch *watch_out)
{
    const wchar_t *plus;
    const wchar_t *colon;
    const wchar_t *rva_end;
    wchar_t number[32];
    wchar_t *end = NULL;
    unsigned long long value;
    size_t module_length;
    size_t number_length;

    if (specification == NULL || watch_out == NULL ||
        (kind != AC_DISPATCH_FUNCTION_POINTER &&
         kind != AC_DISPATCH_OBJECT_VTABLE)) {
        return false;
    }
    plus = wcschr(specification, L'+');
    colon = wcsrchr(specification, L':');
    if (plus == NULL || plus == specification ||
        wcschr(plus + 1u, L'+') != NULL) {
        return false;
    }
    if (kind == AC_DISPATCH_OBJECT_VTABLE) {
        if (colon == NULL || colon <= plus + 1u || colon[1] == L'\0') {
            return false;
        }
        rva_end = colon;
    } else {
        if (colon != NULL) {
            return false;
        }
        rva_end = specification + wcslen(specification);
    }

    module_length = (size_t)(plus - specification);
    if (module_length >=
            sizeof(watch_out->module_name) /
                sizeof(watch_out->module_name[0]) ||
        wmemchr(specification, L'\\', module_length) != NULL ||
        wmemchr(specification, L'/', module_length) != NULL ||
        wmemchr(specification, L':', module_length) != NULL) {
        return false;
    }

    number_length = (size_t)(rva_end - (plus + 1u));
    if (number_length == 0 ||
        number_length >= sizeof(number) / sizeof(number[0])) {
        return false;
    }
    wmemcpy(number, plus + 1u, number_length);
    number[number_length] = L'\0';
    value = wcstoull(number, &end, 0);
    if (end == number || *end != L'\0' || value > UINT32_MAX) {
        return false;
    }

    memset(watch_out, 0, sizeof(*watch_out));
    wmemcpy(watch_out->module_name, specification, module_length);
    watch_out->module_name[module_length] = L'\0';
    watch_out->slot_rva = (uint32_t)value;
    watch_out->kind = kind;

    if (kind == AC_DISPATCH_OBJECT_VTABLE) {
        value = wcstoull(colon + 1u, &end, 10);
        if (end == colon + 1u || *end != L'\0' || value == 0 ||
            value > AC_MAX_VTABLE_ENTRIES) {
            memset(watch_out, 0, sizeof(*watch_out));
            return false;
        }
        watch_out->entry_count = (uint32_t)value;
    } else {
        watch_out->entry_count = 1u;
    }
    return true;
}

void ac_policy_init_defaults(AcPolicy *policy)
{
    if (policy == NULL) {
        return;
    }

    memset(policy, 0, sizeof(*policy));
    policy->probe_budget_bytes = 4ull * 1024ull * 1024ull;
    policy->scan_budget_ms = 250u;
    policy->repeat_interval_ms = 300000u;
    policy->integrity_budget_bytes = 16ull * 1024ull * 1024ull;
    policy->integrity_max_file_bytes = 64ull * 1024ull * 1024ull;
    policy->integrity_baseline_budget_bytes = 64ull * 1024ull * 1024ull;
    policy->max_regions = 200000u;
    policy->hash_unknown_modules = true;
    policy->probe_region_content = true;
    policy->verify_module_integrity = true;
}

bool ac_context_init(AcContext *context, AcLogger *logger, const AcPolicy *policy)
{
    if (context == NULL || logger == NULL || policy == NULL) {
        return false;
    }

    memset(context, 0, sizeof(*context));
    context->logger = logger;
    context->policy = *policy;
    context->coverage_random_source_available = true;
    ac_module_list_init(&context->modules);
    ac_range_index_init(&context->module_ranges);
    ac_integrity_cache_init(&context->integrity);

    return ac_dedup_init(&context->dedup, AC_DEDUP_CAPACITY, policy->repeat_interval_ms);
}

void ac_context_free(AcContext *context)
{
    if (context == NULL) {
        return;
    }
    ac_module_list_free(&context->modules);
    ac_range_index_free(&context->module_ranges);
    ac_integrity_cache_free(&context->integrity);
    ac_dedup_free(&context->dedup);
    context->logger = NULL;
}

bool ac_hash_file(const wchar_t *path, char hex_out[AC_SHA256_HEX_SIZE], uint64_t *size_out)
{
    HANDLE file;
    AcSha256 hash;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    uint8_t *buffer;
    uint64_t total = 0;
    bool ok = true;

    if (path == NULL || hex_out == NULL) {
        return false;
    }
    hex_out[0] = '\0';
    if (size_out != NULL) {
        *size_out = 0;
    }

    file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    buffer = (uint8_t *)malloc(AC_FILE_HASH_CHUNK);
    if (buffer == NULL) {
        CloseHandle(file);
        return false;
    }

    ac_sha256_init(&hash);
    for (;;) {
        DWORD read_bytes = 0;

        if (!ReadFile(file, buffer, AC_FILE_HASH_CHUNK, &read_bytes, NULL)) {
            ok = false;
            break;
        }
        if (read_bytes == 0) {
            break;
        }

        ac_sha256_update(&hash, buffer, (size_t)read_bytes);
        total += read_bytes;
        if (total > AC_FILE_HASH_LIMIT) {
            ok = false;
            break;
        }
    }

    free(buffer);
    CloseHandle(file);

    if (!ok) {
        return false;
    }

    ac_sha256_final(&hash, digest);
    ac_sha256_to_hex(digest, hex_out);
    if (size_out != NULL) {
        *size_out = total;
    }
    return true;
}

static void ac_report_module(
    AcContext *context,
    DWORD pid,
    uint64_t scan_id,
    const AcModule *module,
    AcScanStats *stats)
{
    AcDedupDecision decision;
    char path_utf8[MAX_PATH * 3];
    char escaped_path[MAX_PATH * 6];
    char file_hash[AC_SHA256_HEX_SIZE];
    char details[MAX_PATH * 6 + 512];
    uint64_t fingerprint;
    uint64_t file_size = 0;
    bool hashed = false;

    if (!ac_wide_to_utf8(module->path, path_utf8, sizeof(path_utf8))) {
        (void)strcpy_s(path_utf8, sizeof(path_utf8), "<path-conversion-failed>");
    }

    fingerprint = ac_fnv1a64_text(AC_FNV1A64_OFFSET, "module_outside_allowed_roots");
    fingerprint = ac_fnv1a64_text_ci(fingerprint, path_utf8);
    ac_dedup_observe(&context->dedup, fingerprint, scan_id, GetTickCount64(), &decision);
    if (!decision.emit) {
        ++stats->suppressed;
        return;
    }

    file_hash[0] = '\0';
    if (context->policy.hash_unknown_modules && module->path[0] != L'\0') {
        hashed = ac_hash_file(module->path, file_hash, &file_size);
    }

    (void)ac_json_escape(path_utf8, escaped_path, sizeof(escaped_path));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"path\":\"%s\",\"base\":\"0x%" PRIxPTR "\","
        "\"size\":%zu,\"file_sha256\":%s%s%s,\"file_size\":%" PRIu64 ","
        "\"reason\":\"outside_allowed_roots\",\"verdict\":\"signal_only\","
        "\"first_seen_scan_id\":%" PRIu64 ",\"occurrences\":%" PRIu64 ","
        "\"suppressed_since_last_report\":%" PRIu64 "}",
        scan_id,
        escaped_path,
        module->base,
        module->size,
        hashed ? "\"" : "",
        hashed ? file_hash : "null",
        hashed ? "\"" : "",
        file_size,
        decision.first_scan_id,
        decision.occurrences,
        decision.suppressed_since_last_emit);

    ac_log_event(
        context->logger,
        AC_SEVERITY_LOW,
        "module_outside_allowed_roots",
        pid,
        details);
    ++stats->emitted;
}

static bool ac_classify_region(
    const MEMORY_BASIC_INFORMATION *memory,
    bool backed_by_module,
    AcRegionFinding *finding)
{
    memset(finding, 0, sizeof(*finding));
    finding->backed_by_module = backed_by_module;

    if (!backed_by_module) {
        switch (memory->Type) {
            case MEM_IMAGE:
                finding->reason = "image_not_in_loader_list";
                finding->severity = AC_SEVERITY_HIGH;
                return true;
            case MEM_MAPPED:
                finding->reason = "mapped_executable_outside_module";
                finding->severity = AC_SEVERITY_MEDIUM;
                return true;
            case MEM_PRIVATE:
                finding->reason = ac_is_writable_executable(memory->Protect)
                    ? "private_writable_executable"
                    : "private_executable";
                finding->severity = AC_SEVERITY_MEDIUM;
                return true;
            default:
                finding->reason = "executable_memory_unknown_type";
                finding->severity = AC_SEVERITY_MEDIUM;
                return true;
        }
    }

    if (ac_is_writable_executable(memory->Protect)) {
        finding->reason = "writable_executable_inside_module";
        finding->severity = AC_SEVERITY_LOW;
        return true;
    }

    return false;
}

static void ac_probe_region(
    AcContext *context,
    HANDLE process,
    const MEMORY_BASIC_INFORMATION *memory,
    AcRegionFinding *finding,
    AcScanStats *stats)
{
    SIZE_T requested;
    SIZE_T read_bytes = 0;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];

    if (!context->policy.probe_region_content ||
        stats->probe_bytes >= context->policy.probe_budget_bytes) {
        return;
    }

    requested = memory->RegionSize < (SIZE_T)AC_PROBE_BYTES
        ? memory->RegionSize
        : (SIZE_T)AC_PROBE_BYTES;
    if (requested == 0) {
        return;
    }

    if (!ReadProcessMemory(
            process,
            memory->BaseAddress,
            context->probe_buffer,
            requested,
            &read_bytes)) {
        if (read_bytes == 0) {
            ++stats->read_failures;
            return;
        }
    }

    if (read_bytes == 0) {
        ++stats->read_failures;
        return;
    }

    stats->probe_bytes += (uint64_t)read_bytes;

    ac_sha256(context->probe_buffer, (size_t)read_bytes, digest);
    ac_sha256_to_hex(digest, finding->content_sha256);
    finding->content_hashed = true;

    if (read_bytes >= 0x40u &&
        context->probe_buffer[0] == 'M' && context->probe_buffer[1] == 'Z') {
        const uint32_t pe_offset =
            (uint32_t)context->probe_buffer[0x3c] |
            ((uint32_t)context->probe_buffer[0x3d] << 8) |
            ((uint32_t)context->probe_buffer[0x3e] << 16) |
            ((uint32_t)context->probe_buffer[0x3f] << 24);

        if ((uint64_t)pe_offset + 6u <= (uint64_t)read_bytes &&
            context->probe_buffer[pe_offset] == 'P' &&
            context->probe_buffer[pe_offset + 1u] == 'E' &&
            context->probe_buffer[pe_offset + 2u] == '\0' &&
            context->probe_buffer[pe_offset + 3u] == '\0') {
            finding->pe_header = true;
            finding->pe_machine = (uint16_t)(
                (uint32_t)context->probe_buffer[pe_offset + 4u] |
                ((uint32_t)context->probe_buffer[pe_offset + 5u] << 8));
        }
    }

    if (finding->pe_header && !finding->backed_by_module) {
        finding->severity = AC_SEVERITY_HIGH;
    }
}

static void ac_report_region(
    AcContext *context,
    DWORD pid,
    uint64_t scan_id,
    const MEMORY_BASIC_INFORMATION *memory,
    const AcRegionFinding *finding,
    AcScanStats *stats)
{
    AcDedupDecision decision;
    char details[1536];
    uint64_t fingerprint;

    fingerprint = ac_fnv1a64_text(AC_FNV1A64_OFFSET, "suspicious_executable_region");
    fingerprint = ac_fnv1a64_text(fingerprint, finding->reason);
    fingerprint = ac_fnv1a64_continue(fingerprint, &memory->Protect, sizeof(memory->Protect));

    if (finding->pe_header && finding->content_hashed) {
        fingerprint = ac_fnv1a64_text(fingerprint, finding->content_sha256);
    } else {
        const unsigned int bucket = ac_size_bucket((uint64_t)memory->RegionSize);
        fingerprint = ac_fnv1a64_continue(fingerprint, &bucket, sizeof(bucket));
    }

    ac_dedup_observe(&context->dedup, fingerprint, scan_id, GetTickCount64(), &decision);
    if (!decision.emit) {
        ++stats->suppressed;
        return;
    }

    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"base\":\"0x%" PRIxPTR "\",\"size\":%zu,"
        "\"protect\":%lu,\"type\":\"%s\",\"backed_by_loaded_module\":%s,"
        "\"pe_header\":%s,\"pe_machine\":\"0x%04x\",\"content_sha256_4k\":%s%s%s,"
        "\"reason\":\"%s\",\"verdict\":\"signal_only\","
        "\"first_seen_scan_id\":%" PRIu64 ",\"occurrences\":%" PRIu64 ","
        "\"suppressed_since_last_report\":%" PRIu64 "}",
        scan_id,
        (uintptr_t)memory->BaseAddress,
        (size_t)memory->RegionSize,
        (unsigned long)memory->Protect,
        ac_memory_type_name(memory->Type),
        finding->backed_by_module ? "true" : "false",
        finding->pe_header ? "true" : "false",
        (unsigned int)finding->pe_machine,
        finding->content_hashed ? "\"" : "",
        finding->content_hashed ? finding->content_sha256 : "null",
        finding->content_hashed ? "\"" : "",
        finding->reason,
        decision.first_scan_id,
        decision.occurrences,
        decision.suppressed_since_last_emit);

    ac_log_event(
        context->logger,
        finding->severity,
        "suspicious_executable_region",
        pid,
        details);
    ++stats->emitted;
}

static void ac_scan_memory_regions(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats)
{
    SYSTEM_INFO system_info;
    uintptr_t address;
    uintptr_t boundary;
    uintptr_t minimum_address;
    uintptr_t maximum_address;
    AcRegionSample *sample_storage;
    AcRegionSample *samples;
    AcRegionSample *prefix_samples;
    size_t sample_count = 0;
    size_t prefix_count = 0;
    uint64_t suspicious_seen = 0;
    uint64_t finding_start;
    size_t sample_index;
    bool epoch_complete = false;

    GetNativeSystemInfo(&system_info);
    minimum_address = (uintptr_t)system_info.lpMinimumApplicationAddress;
    maximum_address = (uintptr_t)system_info.lpMaximumApplicationAddress;
    if (minimum_address >= maximum_address || system_info.dwPageSize == 0) {
        stats->query_failures = 1u;
        return;
    }

    if (!context->region_cursor_initialized) {
        bool secure = false;
        bool all_secure;
        const uint64_t random_value = ac_random_u64(scan_id, &secure);
        const uint64_t address_span =
            (uint64_t)(maximum_address - minimum_address);
        uintptr_t anchor = minimum_address +
            (uintptr_t)(random_value % address_span);

        anchor -= anchor % (uintptr_t)system_info.dwPageSize;
        if (anchor < minimum_address || anchor >= maximum_address) {
            anchor = minimum_address;
        }
        context->region_cursor = anchor;
        context->region_epoch_anchor = anchor;
        context->region_epoch_wrapped = false;
        context->region_cursor_initialized = true;
        context->coverage_epoch = 1u;
        context->coverage_epoch_started_ms = GetTickCount64();
        all_secure = secure;
        context->region_finding_cursor = ac_random_u64(
            random_value ^ UINT64_C(0x9e3779b97f4a7c15),
            &secure);
        if (!secure || !all_secure) {
            context->coverage_random_source_available = false;
        }
    }

    if (context->region_cursor < minimum_address ||
        context->region_cursor >= maximum_address ||
        context->region_epoch_anchor < minimum_address ||
        context->region_epoch_anchor >= maximum_address) {
        context->region_cursor = minimum_address;
        context->region_epoch_anchor = minimum_address;
        context->region_epoch_wrapped = false;
    }

    sample_storage = (AcRegionSample *)calloc(
        AC_MAX_REGION_EVENTS_PER_SCAN * 2u,
        sizeof(*sample_storage));
    if (sample_storage == NULL) {
        stats->read_failures = 1u;
        return;
    }
    samples = sample_storage;
    prefix_samples = sample_storage + AC_MAX_REGION_EVENTS_PER_SCAN;
    finding_start = context->region_finding_cursor;
    address = context->region_cursor;

    for (;;) {
        MEMORY_BASIC_INFORMATION memory;
        uintptr_t next_address;

        boundary = context->region_epoch_wrapped
            ? context->region_epoch_anchor
            : maximum_address;
        if (address >= boundary) {
            if (!context->region_epoch_wrapped &&
                context->region_epoch_anchor > minimum_address) {
                address = minimum_address;
                context->region_cursor = address;
                context->region_epoch_wrapped = true;
                continue;
            }
            epoch_complete = true;
            break;
        }
        if (stats->regions_visited >= context->policy.max_regions) {
            stats->region_scan_truncated = true;
            stats->regions_deferred = 1u;
            context->region_cursor = address;
            break;
        }

        memset(&memory, 0, sizeof(memory));
        if (VirtualQueryEx(target->process, (LPCVOID)address, &memory, sizeof(memory)) == 0) {
            const DWORD error = GetLastError();

            if (error == ERROR_INVALID_PARAMETER) {
                if (boundary - address >
                    (uintptr_t)system_info.dwPageSize) {
                    ++stats->query_failures;
                }
                address = boundary;
                context->region_cursor = address;
                continue;
            }
            ++stats->query_failures;
            if (error == ERROR_ACCESS_DENIED) {
                break;
            }
            next_address = address + system_info.dwPageSize;
            if (next_address <= address) {
                break;
            }
            address = next_address;
            context->region_cursor = address;
            continue;
        }

        ++stats->regions_visited;
        ++context->coverage_epoch_regions_visited;

        if ((uintptr_t)memory.RegionSize > UINTPTR_MAX - (uintptr_t)memory.BaseAddress) {
            break;
        }
        next_address = (uintptr_t)memory.BaseAddress + (uintptr_t)memory.RegionSize;
        if (next_address <= address) {
            break;
        }
        if (next_address > boundary) {
            next_address = boundary;
        }

        if (memory.State == MEM_COMMIT &&
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            ac_is_executable_protection(memory.Protect)) {
            AcRegionFinding finding;
            const bool backed = ac_range_index_contains(
                &context->module_ranges,
                (uintptr_t)memory.BaseAddress,
                (size_t)memory.RegionSize);

            ++stats->executable_region_count;

            if (ac_classify_region(&memory, backed, &finding)) {
                const uint64_t finding_index = suspicious_seen;

                ++stats->suspicious_region_count;
                ++suspicious_seen;

                if (finding_index < finding_start &&
                    prefix_count < AC_MAX_REGION_EVENTS_PER_SCAN) {
                    prefix_samples[prefix_count].memory = memory;
                    prefix_samples[prefix_count].finding = finding;
                    ++prefix_count;
                }
                if (finding_index >= finding_start &&
                    sample_count < AC_MAX_REGION_EVENTS_PER_SCAN) {
                    samples[sample_count].memory = memory;
                    samples[sample_count].finding = finding;
                    ++sample_count;
                }
            }
        }

        address = next_address;
        context->region_cursor = address;
    }

    for (sample_index = 0;
         sample_count < AC_MAX_REGION_EVENTS_PER_SCAN &&
         sample_index < prefix_count;
         ++sample_index) {
        samples[sample_count++] = prefix_samples[sample_index];
    }
    if (suspicious_seen > sample_count) {
        stats->region_events_omitted = (size_t)(suspicious_seen - sample_count);
    }
    if (suspicious_seen > 0) {
        const uint64_t effective_start = finding_start < suspicious_seen
            ? finding_start : 0;
        context->region_finding_cursor =
            (effective_start + sample_count) % suspicious_seen;
    } else {
        context->region_finding_cursor = 0;
    }
    for (sample_index = 0; sample_index < sample_count; ++sample_index) {
        ac_probe_region(
            context,
            target->process,
            &samples[sample_index].memory,
            &samples[sample_index].finding,
            stats);
        ac_report_region(
            context,
            target->pid,
            scan_id,
            &samples[sample_index].memory,
            &samples[sample_index].finding,
            stats);
    }

    stats->coverage_epoch = context->coverage_epoch;
    stats->coverage_epoch_regions_visited =
        context->coverage_epoch_regions_visited;
    stats->coverage_oldest_unvisited_ms =
        GetTickCount64() - context->coverage_epoch_started_ms;
    stats->coverage_random_source_available =
        context->coverage_random_source_available;

    if (epoch_complete) {
        bool secure = false;
        const uint64_t random_value = ac_random_u64(
            scan_id ^ context->coverage_epoch,
            &secure);
        const uint64_t address_span =
            (uint64_t)(maximum_address - minimum_address);
        uintptr_t next_anchor = minimum_address +
            (uintptr_t)(random_value % address_span);

        next_anchor -= next_anchor % (uintptr_t)system_info.dwPageSize;
        if (next_anchor < minimum_address || next_anchor >= maximum_address) {
            next_anchor = minimum_address;
        }
        if (!secure) {
            context->coverage_random_source_available = false;
            stats->coverage_random_source_available = false;
        }
        ++context->coverage_epoch;
        context->coverage_epoch_started_ms = GetTickCount64();
        context->coverage_epoch_regions_visited = 0;
        context->region_epoch_anchor = next_anchor;
        context->region_cursor = next_anchor;
        context->region_epoch_wrapped = false;
    }
    free(sample_storage);
}

static const wchar_t *ac_module_base_name(const wchar_t *path)
{
    const wchar_t *separator;

    separator = path != NULL ? wcsrchr(path, L'\\') : NULL;
    return separator != NULL ? separator + 1u : path;
}

static const AcModule *ac_find_module_by_name(
    const AcModuleList *modules,
    const wchar_t *module_name)
{
    size_t index;

    for (index = 0; index < modules->count; ++index) {
        const wchar_t *base_name = ac_module_base_name(
            modules->items[index].path);
        if (base_name != NULL &&
            _wcsicmp(base_name, module_name) == 0) {
            return &modules->items[index];
        }
    }
    return NULL;
}

static bool ac_read_remote_pointer(
    HANDLE process,
    uintptr_t address,
    uintptr_t *value_out)
{
    SIZE_T read_bytes = 0;

    *value_out = 0;
    return ReadProcessMemory(
               process,
               (LPCVOID)address,
               value_out,
               sizeof(*value_out),
               &read_bytes) &&
           read_bytes == sizeof(*value_out);
}

static void ac_report_dispatch_watch(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    const AcDispatchWatch *watch,
    const char *event,
    const char *reason,
    uintptr_t slot,
    uintptr_t table,
    uint32_t entry,
    uintptr_t destination,
    AcSeverity severity,
    AcScanStats *stats)
{
    AcDedupDecision decision;
    char module_utf8[384];
    char escaped_module[768];
    char details[1536];
    uint64_t fingerprint;

    if (!ac_wide_to_utf8(
            watch->module_name,
            module_utf8,
            sizeof(module_utf8))) {
        (void)strcpy_s(
            module_utf8,
            sizeof(module_utf8),
            "<conversion-failed>");
    }
    fingerprint = ac_fnv1a64_text(AC_FNV1A64_OFFSET, event);
    fingerprint = ac_fnv1a64_text_ci(fingerprint, module_utf8);
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &watch->slot_rva,
        sizeof(watch->slot_rva));
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &entry,
        sizeof(entry));
    fingerprint = ac_fnv1a64_continue(
        fingerprint,
        &destination,
        sizeof(destination));
    ac_dedup_observe(
        &context->dedup,
        fingerprint,
        scan_id,
        GetTickCount64(),
        &decision);
    if (!decision.emit) {
        ++stats->suppressed;
        return;
    }

    (void)ac_json_escape(
        module_utf8,
        escaped_module,
        sizeof(escaped_module));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"module\":\"%s\","
        "\"slot_rva\":\"0x%08x\",\"slot\":\"0x%" PRIxPTR
        "\",\"table\":\"0x%" PRIxPTR "\",\"entry\":%u,"
        "\"destination\":\"0x%" PRIxPTR "\",\"reason\":\"%s\","
        "\"verdict\":\"signal_only\"}",
        scan_id,
        escaped_module,
        watch->slot_rva,
        slot,
        table,
        entry,
        destination,
        reason);
    ac_log_event(
        context->logger,
        severity,
        event,
        target->pid,
        details);
    ++stats->emitted;
}

static void ac_scan_dispatch_watches(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats)
{
    size_t watch_index;
    size_t findings_reported = 0;

    for (watch_index = 0;
         watch_index < context->policy.dispatch_watch_count;
         ++watch_index) {
        const AcDispatchWatch *watch =
            &context->policy.dispatch_watches[watch_index];
        const AcModule *module = ac_find_module_by_name(
            &context->modules,
            watch->module_name);
        uintptr_t slot;
        uintptr_t first_pointer;

        if (module == NULL || watch->slot_rva > module->size ||
            module->size - watch->slot_rva < sizeof(uintptr_t)) {
            ++stats->dispatch_targets_unavailable;
            if (findings_reported < AC_INTEGRITY_MAX_HOOK_EVENTS) {
                ac_report_dispatch_watch(
                    context,
                    target,
                    scan_id,
                    watch,
                    "dispatch_watch_unavailable",
                    module == NULL
                        ? "module_not_loaded"
                        : "slot_outside_module",
                    0,
                    0,
                    0,
                    0,
                    AC_SEVERITY_LOW,
                    stats);
                ++findings_reported;
            }
            continue;
        }

        slot = module->base + watch->slot_rva;
        if (!ac_read_remote_pointer(
                target->process,
                slot,
                &first_pointer)) {
            ++stats->dispatch_targets_unavailable;
            continue;
        }
        ++stats->dispatch_slots_checked;

        if (watch->kind == AC_DISPATCH_FUNCTION_POINTER) {
            if (first_pointer != 0 && !ac_range_index_contains(
                    &context->module_ranges,
                    first_pointer,
                    1u)) {
                ++stats->dispatch_targets_suspicious;
                if (findings_reported < AC_INTEGRITY_MAX_HOOK_EVENTS) {
                    ac_report_dispatch_watch(
                        context,
                        target,
                        scan_id,
                        watch,
                        "dispatch_pointer_outside_loader_modules",
                        "function_pointer_target_unlinked",
                        slot,
                        0,
                        0,
                        first_pointer,
                        AC_SEVERITY_HIGH,
                        stats);
                    ++findings_reported;
                }
            }
            continue;
        }

        if (first_pointer != 0) {
            uintptr_t table;
            uint32_t entry;

            if (!ac_read_remote_pointer(
                    target->process,
                    first_pointer,
                    &table) || table == 0) {
                ++stats->dispatch_targets_unavailable;
                continue;
            }
            if (!ac_range_index_contains(
                    &context->module_ranges,
                    table,
                    sizeof(uintptr_t))) {
                ++stats->dispatch_targets_suspicious;
                if (findings_reported < AC_INTEGRITY_MAX_HOOK_EVENTS) {
                    ac_report_dispatch_watch(
                        context,
                        target,
                        scan_id,
                        watch,
                        "vtable_storage_outside_loader_modules",
                        "object_vtable_relocated_to_private_memory",
                        slot,
                        table,
                        0,
                        table,
                        AC_SEVERITY_HIGH,
                        stats);
                    ++findings_reported;
                }
            }

            for (entry = 0; entry < watch->entry_count; ++entry) {
                uintptr_t destination;
                if (table > UINTPTR_MAX -
                        (uintptr_t)entry * sizeof(uintptr_t) ||
                    !ac_read_remote_pointer(
                        target->process,
                        table + (uintptr_t)entry * sizeof(uintptr_t),
                        &destination)) {
                    ++stats->dispatch_targets_unavailable;
                    break;
                }
                ++stats->dispatch_slots_checked;
                if (destination == 0 || ac_range_index_contains(
                        &context->module_ranges,
                        destination,
                        1u)) {
                    continue;
                }
                ++stats->dispatch_targets_suspicious;
                if (findings_reported < AC_INTEGRITY_MAX_HOOK_EVENTS) {
                    ac_report_dispatch_watch(
                        context,
                        target,
                        scan_id,
                        watch,
                        "vtable_entry_outside_loader_modules",
                        "vtable_entry_target_unlinked",
                        slot,
                        table,
                        entry,
                        destination,
                        AC_SEVERITY_HIGH,
                        stats);
                    ++findings_reported;
                }
            }
        }
    }

    if (stats->dispatch_targets_suspicious > findings_reported) {
        char details[384];
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"findings\":%zu,"
            "\"events_emitted_or_deduplicated\":%zu,"
            "\"reason\":\"dispatch_event_budget_exhausted\"}",
            scan_id,
            stats->dispatch_targets_suspicious,
            findings_reported);
        ac_log_event(
            context->logger,
            AC_SEVERITY_MEDIUM,
            "dispatch_watch_coverage_gap",
            target->pid,
            details);
        ++stats->emitted;
    }
}

bool ac_scan_process(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats_out)
{
    AcScanStats stats;
    DWORD error = ERROR_SUCCESS;
    ULONGLONG started_ms;
    size_t index;
    char details[2048];

    if (context == NULL || target == NULL || target->process == NULL || stats_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    memset(&stats, 0, sizeof(stats));
    started_ms = GetTickCount64();

    if (!ac_collect_modules(target->pid, &context->modules, &error)) {
        SetLastError(error);
        return false;
    }

    ac_range_index_clear(&context->module_ranges);
    for (index = 0; index < context->modules.count; ++index) {
        (void)ac_range_index_add(
            &context->module_ranges,
            context->modules.items[index].base,
            context->modules.items[index].size);
    }
    ac_range_index_finalize(&context->module_ranges);

    stats.module_count = context->modules.count;
    if (context->modules.count > 0) {
        bool secure = false;
        const uint64_t random_value = ac_random_u64(scan_id, &secure);
        const size_t module_start =
            (size_t)(random_value % context->modules.count);
        const size_t module_step = ac_schedule_coprime_step(
            context->modules.count,
            random_value >> 17u);

        if (!secure) {
            context->coverage_random_source_available = false;
        }
        for (index = 0; index < context->modules.count; ++index) {
            const size_t module_index = ac_schedule_permutation_index(
                index,
                context->modules.count,
                module_start,
                module_step);
            const AcModule *module = &context->modules.items[module_index];

            if (ac_path_is_under_any(
                    module->path,
                    context->policy.allow_roots,
                    context->policy.allow_root_count)) {
                continue;
            }

            ++stats.modules_outside_roots;
            ac_report_module(context, target->pid, scan_id, module, &stats);
        }
    }

    ac_scan_memory_regions(context, target, scan_id, &stats);
    if (!context->coverage_random_source_available &&
        !context->coverage_random_failure_reported) {
        ac_log_event(
            context->logger,
            AC_SEVERITY_HIGH,
            "scan_random_source_unavailable",
            target->pid,
            "{\"fallback\":\"bounded_early_scan_and_deterministic_continuation\","
            "\"coverage_continues\":true}");
        context->coverage_random_failure_reported = true;
        ++stats.emitted;
    }
    ac_scan_dispatch_watches(context, target, scan_id, &stats);
    ac_verify_module_integrity(context, target, scan_id, &stats);

    stats.duration_ms = (uint64_t)(GetTickCount64() - started_ms);
    stats.coverage_complete =
        context->modules.count > 0 &&
        !context->modules.truncated &&
        !stats.region_scan_truncated &&
        stats.region_events_omitted == 0 &&
        stats.query_failures == 0 &&
        stats.read_failures == 0 &&
        context->policy.verify_module_integrity &&
        stats.integrity_modules_unavailable == 0 &&
        stats.integrity_unreadable_blocks == 0 &&
        stats.integrity_modules_partial == 0 &&
        stats.integrity_modules_skipped == 0;
    if (context->policy.dispatch_watch_count > 0 &&
        stats.dispatch_targets_unavailable > 0) {
        stats.coverage_complete = false;
    }
    ++context->scans_completed;

    if (!stats.coverage_complete) {
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"module_list_truncated\":%s,"
            "\"module_snapshot_empty\":%s,"
            "\"region_scan_truncated\":%s,\"region_events_omitted\":%zu,"
            "\"coverage_epoch\":%" PRIu64
            ",\"coverage_epoch_regions_visited\":%" PRIu64
            ",\"coverage_oldest_unvisited_ms\":%" PRIu64
            ",\"regions_deferred\":%zu,"
            "\"query_failures\":%zu,\"read_failures\":%zu,"
            "\"integrity_disabled\":%s,"
            "\"integrity_modules_unavailable\":%zu,"
            "\"integrity_unreadable_blocks\":%zu,"
            "\"integrity_modules_partial\":%zu,"
            "\"integrity_modules_skipped\":%zu,"
            "\"dispatch_targets_unavailable\":%zu,"
            "\"possible_user_mode_api_interference\":%s,"
            "\"reason\":\"scan_coverage_incomplete\"}",
            scan_id,
            context->modules.truncated ? "true" : "false",
            context->modules.count == 0 ? "true" : "false",
            stats.region_scan_truncated ? "true" : "false",
            stats.region_events_omitted,
            stats.coverage_epoch,
            stats.coverage_epoch_regions_visited,
            stats.coverage_oldest_unvisited_ms,
            stats.regions_deferred,
            stats.query_failures,
            stats.read_failures,
            context->policy.verify_module_integrity ? "false" : "true",
            stats.integrity_modules_unavailable,
            stats.integrity_unreadable_blocks,
            stats.integrity_modules_partial,
            stats.integrity_modules_skipped,
            stats.dispatch_targets_unavailable,
            (context->modules.count == 0 ||
             stats.query_failures > 0 ||
             stats.read_failures > 0 ||
             stats.integrity_modules_unavailable > 0 ||
             stats.integrity_unreadable_blocks > 0)
                ? "true"
                : "false");
        ac_log_event(
            context->logger,
            AC_SEVERITY_MEDIUM,
            "scan_coverage_gap",
            target->pid,
            details);
        ++stats.emitted;
    }

    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"duration_ms\":%" PRIu64 ",\"modules\":%zu,"
        "\"module_list_truncated\":%s,\"modules_outside_allowed_roots\":%zu,"
        "\"regions_visited\":%zu,\"executable_regions\":%zu,"
        "\"suspicious_regions\":%zu,\"query_failures\":%zu,\"read_failures\":%zu,"
        "\"probe_bytes\":%" PRIu64 ",\"events_emitted\":%" PRIu64 ","
        "\"events_suppressed\":%" PRIu64 ",\"dedup_entries\":%zu,"
        "\"dedup_saturated_events\":%" PRIu64 ",\"integrity_modules_checked\":%zu,"
        "\"integrity_modules_unavailable\":%zu,\"integrity_blocks_checked\":%zu,"
        "\"integrity_blocks_modified\":%zu,\"integrity_unreadable_blocks\":%zu,"
        "\"integrity_iat_slots_checked\":%zu,\"integrity_iat_hooks\":%zu,"
        "\"integrity_export_slots_checked\":%zu,\"integrity_export_hooks\":%zu,"
        "\"integrity_modules_partial\":%zu,\"integrity_modules_skipped\":%zu,"
        "\"integrity_file_changes\":%zu,\"region_events_omitted\":%zu,"
        "\"coverage_epoch\":%" PRIu64
        ",\"coverage_epoch_regions_visited\":%" PRIu64
        ",\"coverage_oldest_unvisited_ms\":%" PRIu64
        ",\"regions_deferred\":%zu,\"random_source_available\":%s,"
        "\"dispatch_slots_checked\":%zu,"
        "\"dispatch_targets_suspicious\":%zu,"
        "\"dispatch_targets_unavailable\":%zu,"
        "\"region_scan_truncated\":%s,\"integrity_bytes\":%" PRIu64
        ",\"integrity_baselines\":%zu,\"complete\":%s,"
        "\"source\":\"user_mode_win32_api\","
        "\"source_trust\":\"untrusted\"}",
        scan_id,
        stats.duration_ms,
        stats.module_count,
        context->modules.truncated ? "true" : "false",
        stats.modules_outside_roots,
        stats.regions_visited,
        stats.executable_region_count,
        stats.suspicious_region_count,
        stats.query_failures,
        stats.read_failures,
        stats.probe_bytes,
        stats.emitted,
        stats.suppressed,
        context->dedup.used,
        context->dedup.saturated_events,
        stats.integrity_modules_checked,
        stats.integrity_modules_unavailable,
        stats.integrity_blocks_checked,
        stats.integrity_blocks_modified,
        stats.integrity_unreadable_blocks,
        stats.integrity_iat_slots_checked,
        stats.integrity_iat_hooks,
        stats.integrity_export_slots_checked,
        stats.integrity_export_hooks,
        stats.integrity_modules_partial,
        stats.integrity_modules_skipped,
        stats.integrity_file_changes,
        stats.region_events_omitted,
        stats.coverage_epoch,
        stats.coverage_epoch_regions_visited,
        stats.coverage_oldest_unvisited_ms,
        stats.regions_deferred,
        stats.coverage_random_source_available ? "true" : "false",
        stats.dispatch_slots_checked,
        stats.dispatch_targets_suspicious,
        stats.dispatch_targets_unavailable,
        stats.region_scan_truncated ? "true" : "false",
        stats.integrity_bytes,
        context->integrity.count,
        stats.coverage_complete ? "true" : "false");
    ac_log_event(context->logger, AC_SEVERITY_INFO, "scan_completed", target->pid, details);

    if (context->policy.scan_budget_ms > 0 &&
        stats.duration_ms > context->policy.scan_budget_ms) {
        ++context->perf_budget_breaches;
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"duration_ms\":%" PRIu64 ",\"budget_ms\":%" PRIu64
            ",\"breaches\":%" PRIu64 "}",
            scan_id,
            stats.duration_ms,
            context->policy.scan_budget_ms,
            context->perf_budget_breaches);
        ac_log_event(
            context->logger,
            AC_SEVERITY_LOW,
            "scan_budget_exceeded",
            target->pid,
            details);
    }

    *stats_out = stats;
    return true;
}
