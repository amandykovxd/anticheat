#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>

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

static uint64_t ac_random_u64(uint64_t fallback)
{
    uint64_t value = 0;

    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&value,
            (ULONG)sizeof(value),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        value = fallback ^ GetTickCount64();
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value *= UINT64_C(2685821657736338717);
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
    uintptr_t maximum_address;
    AcRegionSample samples[AC_MAX_REGION_EVENTS_PER_SCAN];
    size_t sample_count = 0;
    uint64_t suspicious_seen = 0;
    size_t sample_index;

    GetNativeSystemInfo(&system_info);
    address = (uintptr_t)system_info.lpMinimumApplicationAddress;
    maximum_address = (uintptr_t)system_info.lpMaximumApplicationAddress;

    while (address < maximum_address) {
        MEMORY_BASIC_INFORMATION memory;
        uintptr_t next_address;

        if (stats->regions_visited >= context->policy.max_regions) {
            stats->region_scan_truncated = true;
            break;
        }

        memset(&memory, 0, sizeof(memory));
        if (VirtualQueryEx(target->process, (LPCVOID)address, &memory, sizeof(memory)) == 0) {
            const DWORD error = GetLastError();

            if (error == ERROR_INVALID_PARAMETER) {
                if (maximum_address - address >
                    (uintptr_t)system_info.dwPageSize) {
                    ++stats->query_failures;
                }
                break;
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
            continue;
        }

        ++stats->regions_visited;

        if ((uintptr_t)memory.RegionSize > UINTPTR_MAX - (uintptr_t)memory.BaseAddress) {
            break;
        }
        next_address = (uintptr_t)memory.BaseAddress + (uintptr_t)memory.RegionSize;
        if (next_address <= address) {
            break;
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
                size_t selected;

                ++stats->suspicious_region_count;
                ++suspicious_seen;

                if (sample_count < AC_MAX_REGION_EVENTS_PER_SCAN) {
                    selected = sample_count++;
                } else {
                    selected = (size_t)(ac_random_u64(
                        (uint64_t)(uintptr_t)memory.BaseAddress) % suspicious_seen);
                    if (selected >= AC_MAX_REGION_EVENTS_PER_SCAN) {
                        address = next_address;
                        continue;
                    }
                }
                samples[selected].memory = memory;
                samples[selected].finding = finding;
            }
        }

        address = next_address;
    }

    if (suspicious_seen > sample_count) {
        stats->region_events_omitted = (size_t)(suspicious_seen - sample_count);
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
    for (index = 0; index < context->modules.count; ++index) {
        const AcModule *module = &context->modules.items[index];

        if (ac_path_is_under_any(
                module->path,
                context->policy.allow_roots,
                context->policy.allow_root_count)) {
            continue;
        }

        ++stats.modules_outside_roots;
        ac_report_module(context, target->pid, scan_id, module, &stats);
    }

    ac_scan_memory_regions(context, target, scan_id, &stats);
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
    ++context->scans_completed;

    if (!stats.coverage_complete) {
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"module_list_truncated\":%s,"
            "\"module_snapshot_empty\":%s,"
            "\"region_scan_truncated\":%s,\"region_events_omitted\":%zu,"
            "\"query_failures\":%zu,\"read_failures\":%zu,"
            "\"integrity_disabled\":%s,"
            "\"integrity_modules_unavailable\":%zu,"
            "\"integrity_unreadable_blocks\":%zu,"
            "\"integrity_modules_partial\":%zu,"
            "\"integrity_modules_skipped\":%zu,"
            "\"possible_user_mode_api_interference\":%s,"
            "\"reason\":\"scan_coverage_incomplete\"}",
            scan_id,
            context->modules.truncated ? "true" : "false",
            context->modules.count == 0 ? "true" : "false",
            stats.region_scan_truncated ? "true" : "false",
            stats.region_events_omitted,
            stats.query_failures,
            stats.read_failures,
            context->policy.verify_module_integrity ? "false" : "true",
            stats.integrity_modules_unavailable,
            stats.integrity_unreadable_blocks,
            stats.integrity_modules_partial,
            stats.integrity_modules_skipped,
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
