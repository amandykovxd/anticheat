#include "ac.h"

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int g_failures = 0;

#define AC_CHECK(expression)                                                   \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(                                                           \
                stderr,                                                        \
                "check failed at %s:%d: %s\n",                                 \
                __FILE__,                                                      \
                __LINE__,                                                      \
                #expression);                                                  \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

static void test_path_boundaries(void)
{
    AC_CHECK(ac_path_is_under(
        L"C:\\Games\\Example\\bin\\game.dll",
        L"C:\\Games\\Example"));
    AC_CHECK(ac_path_is_under(
        L"c:\\windows\\system32\\kernel32.dll",
        L"C:\\Windows\\"));
    AC_CHECK(ac_path_is_under(L"C:\\Games\\Example", L"C:\\Games\\Example"));
    AC_CHECK(!ac_path_is_under(
        L"C:\\Games\\Example-Evil\\payload.dll",
        L"C:\\Games\\Example"));
    AC_CHECK(!ac_path_is_under(L"C:\\Games\\Example", L""));
    AC_CHECK(!ac_path_is_under(NULL, L"C:\\Games"));
}

static void test_allow_roots(void)
{
    const wchar_t *roots[3];

    roots[0] = L"C:\\Games\\Example";
    roots[1] = L"C:\\Windows";
    roots[2] = L"C:\\Program Files";

    AC_CHECK(ac_path_is_under_any(L"C:\\Windows\\System32\\ntdll.dll", roots, 3u));
    AC_CHECK(ac_path_is_under_any(L"C:\\Program Files\\Overlay\\hook.dll", roots, 3u));
    AC_CHECK(!ac_path_is_under_any(L"C:\\Users\\a\\AppData\\cheat.dll", roots, 3u));
    AC_CHECK(!ac_path_is_under_any(L"C:\\Windows\\System32\\ntdll.dll", roots, 0));
}

static void test_module_list_and_ranges(void)
{
    AcModuleList modules;
    AcRangeIndex index;
    size_t position;

    ac_module_list_init(&modules);
    AC_CHECK(ac_module_list_push(&modules, 0x10000000u, 0x10000u, L"C:\\Games\\game.exe"));
    AC_CHECK(ac_module_list_push(&modules, 0x20000000u, 0x2000u, L"C:\\Windows\\ntdll.dll"));
    AC_CHECK(modules.count == 2u);
    AC_CHECK(wcscmp(modules.items[0].path, L"C:\\Games\\game.exe") == 0);

    for (position = 0; position < 500u; ++position) {
        AC_CHECK(ac_module_list_push(
            &modules,
            (uintptr_t)0x40000000u + position * 0x10000u,
            0x1000u,
            L"C:\\Windows\\System32\\filler.dll"));
    }
    AC_CHECK(modules.count == 502u);
    AC_CHECK(!modules.truncated);

    ac_range_index_init(&index);
    for (position = 0; position < modules.count; ++position) {
        AC_CHECK(ac_range_index_add(
            &index,
            modules.items[position].base,
            modules.items[position].size));
    }
    ac_range_index_finalize(&index);

    AC_CHECK(ac_range_index_contains(&index, 0x10000000u, 0x1000u));
    AC_CHECK(ac_range_index_contains(&index, 0x1000f000u, 0x1000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x0ffff000u, 0x2000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x1000f000u, 0x2000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x30000000u, 0x1000u));

    ac_range_index_free(&index);
    ac_module_list_free(&modules);
    AC_CHECK(modules.items == NULL);
    AC_CHECK(modules.count == 0);
}

static void test_parent_directory(void)
{
    wchar_t *directory = NULL;

    AC_CHECK(ac_get_parent_directory(L"C:\\Games\\Example\\game.exe", &directory));
    if (directory != NULL) {
        AC_CHECK(wcscmp(directory, L"C:\\Games\\Example") == 0);
        free(directory);
        directory = NULL;
    }

    AC_CHECK(ac_get_parent_directory(L"C:\\game.exe", &directory));
    if (directory != NULL) {
        AC_CHECK(wcscmp(directory, L"C:\\") == 0);
        free(directory);
        directory = NULL;
    }

    AC_CHECK(!ac_get_parent_directory(L"game.exe", &directory));
    AC_CHECK(directory == NULL);
}

static void test_image_name_matching(void)
{
    AC_CHECK(ac_process_image_matches_name(L"C:\\Games\\Example\\game.exe", L"game.exe"));
    AC_CHECK(ac_process_image_matches_name(L"C:\\Games\\Example\\GAME.EXE", L"game.exe"));
    AC_CHECK(!ac_process_image_matches_name(L"C:\\Games\\Example\\other.exe", L"game.exe"));
    AC_CHECK(!ac_process_image_matches_name(L"C:\\Games\\game.exe.bak", L"game.exe"));
}

static void test_wide_to_utf8(void)
{
    char buffer[64];

    AC_CHECK(ac_wide_to_utf8(L"C:\\Games", buffer, sizeof(buffer)));
    AC_CHECK(strcmp(buffer, "C:\\Games") == 0);
    AC_CHECK(!ac_wide_to_utf8(NULL, buffer, sizeof(buffer)));
}

static bool ac_hex_to_bytes(const char *hex, uint8_t *output, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        unsigned int value = 0;

        if (sscanf(hex + index * 2u, "%2x", &value) != 1) {
            return false;
        }
        output[index] = (uint8_t)value;
    }
    return true;
}

static bool ac_temp_log_path(wchar_t *buffer, size_t capacity, const wchar_t *stem)
{
    wchar_t directory[MAX_PATH];
    const DWORD length =
        GetTempPathW((DWORD)(sizeof(directory) / sizeof(directory[0])), directory);

    if (length == 0 || length >= sizeof(directory) / sizeof(directory[0])) {
        return false;
    }
    return swprintf(
               buffer,
               capacity,
               L"%ls%ls-%lu.jsonl",
               directory,
               stem,
               (unsigned long)GetCurrentProcessId()) > 0;
}

static void test_log_chain_is_verifiable(void)
{
    AcLogger logger;
    wchar_t path[MAX_PATH];
    char line[32768];
    uint8_t chain[AC_SHA256_DIGEST_SIZE];
    FILE *file;
    unsigned int line_count = 0;
    uint64_t expected_sequence = 1u;
    bool seeded = false;

    if (!ac_temp_log_path(path, sizeof(path) / sizeof(path[0]), L"ac-chain")) {
        AC_CHECK(false);
        return;
    }
    (void)_wremove(path);

    AC_CHECK(ac_logger_open(&logger, path, false, 0, 0));
    ac_log_event(&logger, AC_SEVERITY_LOW, "unit_test", 4321u, "{\"index\":1}");
    ac_log_event(&logger, AC_SEVERITY_HIGH, "unit_test", 4321u, "{\"index\":2,\"q\":\"a b\"}");
    ac_log_win32_error(&logger, "unit_test_error", 4321u, ERROR_ACCESS_DENIED);
    ac_logger_close(&logger);

    file = _wfopen(path, L"rb");
    AC_CHECK(file != NULL);
    if (file == NULL) {
        return;
    }

    while (fgets(line, (int)sizeof(line), file) != NULL) {
        AcSha256 hash;
        uint8_t computed[AC_SHA256_DIGEST_SIZE];
        char computed_hex[AC_SHA256_HEX_SIZE];
        char *marker;
        char *sequence_field;
        size_t length = strlen(line);

        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        if (length == 0) {
            continue;
        }

        AC_CHECK(line[0] == '{');
        AC_CHECK(line[length - 1] == '}');

        sequence_field = strstr(line, "\"seq\":");
        AC_CHECK(sequence_field != NULL);
        if (sequence_field != NULL) {
            AC_CHECK(strtoull(sequence_field + 6u, NULL, 10) == expected_sequence);
        }

        marker = strstr(line, ",\"chain\":\"");
        AC_CHECK(marker != NULL);
        if (marker == NULL) {
            break;
        }

        if (!seeded) {
            char *seed = strstr(line, "\"chain_seed\":\"");

            AC_CHECK(seed != NULL);
            if (seed == NULL) {
                break;
            }
            AC_CHECK(ac_hex_to_bytes(seed + 14u, chain, sizeof(chain)));
            seeded = true;
        }

        ac_sha256_init(&hash);
        ac_sha256_update(&hash, chain, sizeof(chain));
        ac_sha256_update(&hash, line, (size_t)(marker - line));
        ac_sha256_final(&hash, computed);
        ac_sha256_to_hex(computed, computed_hex);

        AC_CHECK(strncmp(marker + 10u, computed_hex, AC_SHA256_DIGEST_SIZE * 2u) == 0);
        memcpy(chain, computed, sizeof(chain));

        ++line_count;
        ++expected_sequence;
    }

    (void)fclose(file);
    AC_CHECK(line_count == 4u);
    (void)_wremove(path);
}

static void test_log_rotation(void)
{
    AcLogger logger;
    wchar_t path[MAX_PATH];
    wchar_t rotated[MAX_PATH + 8];
    unsigned int index;

    if (!ac_temp_log_path(path, sizeof(path) / sizeof(path[0]), L"ac-rotate")) {
        AC_CHECK(false);
        return;
    }
    (void)swprintf(rotated, sizeof(rotated) / sizeof(rotated[0]), L"%ls.1", path);
    (void)_wremove(path);
    (void)_wremove(rotated);

    AC_CHECK(ac_logger_open(&logger, path, false, 2048u, 2u));
    for (index = 0; index < 200u; ++index) {
        ac_log_event(
            &logger,
            AC_SEVERITY_INFO,
            "rotation_probe",
            index,
            "{\"filler\":\"xxxxxxxxxxxxxxxx\"}");
    }
    AC_CHECK(logger.bytes_written <= 4096u);
    ac_logger_close(&logger);

    AC_CHECK(_waccess(rotated, 0) == 0);
    AC_CHECK(_waccess(path, 0) == 0);

    (void)_wremove(path);
    (void)_wremove(rotated);
    (void)swprintf(rotated, sizeof(rotated) / sizeof(rotated[0]), L"%ls.2", path);
    (void)_wremove(rotated);
}

static void test_policy_defaults(void)
{
    AcPolicy policy;

    ac_policy_init_defaults(&policy);
    AC_CHECK(policy.allow_root_count == 0);
    AC_CHECK(policy.probe_budget_bytes > 0);
    AC_CHECK(policy.scan_budget_ms > 0);
    AC_CHECK(policy.max_regions > 0);
    AC_CHECK(policy.hash_unknown_modules);
    AC_CHECK(policy.probe_region_content);
    AC_CHECK(policy.verify_module_integrity);
    AC_CHECK(policy.integrity_budget_bytes > 0);
    AC_CHECK(policy.integrity_max_file_bytes > 0);
    AC_CHECK(policy.integrity_baseline_budget_bytes > 0);
}

static void test_open_process_uses_read_only_access(void)
{
    DWORD granted = 0;
    HANDLE process = ac_open_process_for_scan(GetCurrentProcessId(), &granted);

    AC_CHECK(process != NULL);
    if (process == NULL) {
        return;
    }

    AC_CHECK((granted & PROCESS_VM_WRITE) == 0);
    AC_CHECK((granted & PROCESS_VM_OPERATION) == 0);
    AC_CHECK((granted & PROCESS_TERMINATE) == 0);
    AC_CHECK((granted & PROCESS_CREATE_THREAD) == 0);
    AC_CHECK((granted & SYNCHRONIZE) != 0);
    AC_CHECK((granted & PROCESS_VM_READ) != 0);
    AC_CHECK(WaitForSingleObject(process, 0) == WAIT_TIMEOUT);

    CloseHandle(process);
}

static void test_scan_of_self_produces_events(void)
{
    AcLogger logger;
    AcContext context;
    AcPolicy policy;
    AcTarget target;
    AcScanStats stats;
    wchar_t path[MAX_PATH];
    wchar_t windows_directory[MAX_PATH];

    if (!ac_temp_log_path(path, sizeof(path) / sizeof(path[0]), L"ac-scan")) {
        AC_CHECK(false);
        return;
    }
    (void)_wremove(path);

    memset(&target, 0, sizeof(target));
    target.pid = GetCurrentProcessId();
    target.process = ac_open_process_for_scan(target.pid, &target.granted_access);
    AC_CHECK(target.process != NULL);
    if (target.process == NULL) {
        return;
    }

    AC_CHECK(ac_get_process_path(target.process, &target.image_path));
    AC_CHECK(ac_get_parent_directory(target.image_path, &target.directory));

    windows_directory[0] = L'\0';
    (void)GetWindowsDirectoryW(
        windows_directory,
        (UINT)(sizeof(windows_directory) / sizeof(windows_directory[0])));

    ac_policy_init_defaults(&policy);
    policy.allow_root_count = 2u;
    policy.allow_roots[0] = target.directory;
    policy.allow_roots[1] = windows_directory;

    AC_CHECK(ac_logger_open(&logger, path, false, 0, 0));
    AC_CHECK(ac_context_init(&context, &logger, &policy));

    memset(&stats, 0, sizeof(stats));
    AC_CHECK(ac_scan_process(&context, &target, 1u, &stats));
    AC_CHECK(stats.module_count > 0);
    AC_CHECK(stats.regions_visited > 0);
    AC_CHECK(stats.executable_region_count > 0);
    AC_CHECK(stats.duration_ms < 60000u);
    AC_CHECK(logger.write_failures == 0);

    ac_context_free(&context);
    ac_logger_close(&logger);
    CloseHandle(target.process);
    free(target.image_path);
    free(target.directory);
    (void)_wremove(path);
}

/* External linkage keeps the compiler from discarding the function whose
   first byte the integrity test deliberately corrupts. */
int ac_test_patch_victim(int value);

int ac_test_patch_victim(int value)
{
    return (value * 7) + 13;
}

typedef struct AcIntegrityFixture {
    AcLogger logger;
    AcContext context;
    AcPolicy policy;
    AcTarget target;
    wchar_t log_path[MAX_PATH];
    wchar_t windows_directory[MAX_PATH];
    bool ready;
} AcIntegrityFixture;

static bool ac_test_integrity_setup(AcIntegrityFixture *fixture, const wchar_t *stem)
{
    memset(fixture, 0, sizeof(*fixture));

    if (!ac_temp_log_path(
            fixture->log_path,
            sizeof(fixture->log_path) / sizeof(fixture->log_path[0]),
            stem)) {
        return false;
    }
    (void)_wremove(fixture->log_path);

    fixture->target.pid = GetCurrentProcessId();
    fixture->target.process = ac_open_process_for_scan(
        fixture->target.pid,
        &fixture->target.granted_access);
    if (fixture->target.process == NULL) {
        return false;
    }

    if (!ac_get_process_path(fixture->target.process, &fixture->target.image_path) ||
        !ac_get_parent_directory(fixture->target.image_path, &fixture->target.directory)) {
        return false;
    }

    fixture->windows_directory[0] = L'\0';
    (void)GetWindowsDirectoryW(
        fixture->windows_directory,
        (UINT)(sizeof(fixture->windows_directory) /
               sizeof(fixture->windows_directory[0])));

    ac_policy_init_defaults(&fixture->policy);
    fixture->policy.allow_root_count = 2u;
    fixture->policy.allow_roots[0] = fixture->target.directory;
    fixture->policy.allow_roots[1] = fixture->windows_directory;
    fixture->policy.integrity_budget_bytes = 256ull * 1024ull * 1024ull;
    fixture->policy.probe_region_content = false;
    fixture->policy.hash_unknown_modules = false;
    fixture->policy.repeat_interval_ms = 0;

    if (!ac_logger_open(&fixture->logger, fixture->log_path, false, 0, 0)) {
        return false;
    }
    if (!ac_context_init(&fixture->context, &fixture->logger, &fixture->policy)) {
        return false;
    }

    fixture->ready = true;
    return true;
}

static void ac_test_integrity_teardown(AcIntegrityFixture *fixture)
{
    if (fixture->ready) {
        ac_context_free(&fixture->context);
        ac_logger_close(&fixture->logger);
    }
    if (fixture->target.process != NULL) {
        CloseHandle(fixture->target.process);
    }
    free(fixture->target.image_path);
    free(fixture->target.directory);
    (void)_wremove(fixture->log_path);
}

static bool ac_test_log_contains(const wchar_t *path, const char *needle)
{
    FILE *file = _wfopen(path, L"rb");
    char line[32768];

    if (file == NULL) {
        return false;
    }
    while (fgets(line, (int)sizeof(line), file) != NULL) {
        if (strstr(line, needle) != NULL) {
            (void)fclose(file);
            return true;
        }
    }
    (void)fclose(file);
    return false;
}

static bool ac_test_log_contains_both(
    const wchar_t *path,
    const char *first,
    const char *second)
{
    FILE *file = _wfopen(path, L"rb");
    char line[32768];

    if (file == NULL) {
        return false;
    }
    while (fgets(line, (int)sizeof(line), file) != NULL) {
        if (strstr(line, first) != NULL && strstr(line, second) != NULL) {
            (void)fclose(file);
            return true;
        }
    }
    (void)fclose(file);
    return false;
}

static const AcIntegrityBaseline *ac_test_find_integrity_baseline(
    const AcContext *context,
    uintptr_t base,
    const wchar_t *path)
{
    size_t index;

    for (index = 0; index < context->integrity.count; ++index) {
        const AcIntegrityBaseline *baseline = &context->integrity.items[index];

        if (baseline->base == base && _wcsicmp(baseline->path, path) == 0) {
            return baseline;
        }
    }
    return NULL;
}

/* A clean process must produce no section findings: this is the false-positive
   guard for relocation, import and delay-import normalisation. */
static void test_integrity_clean_process_has_no_findings(void)
{
    AcIntegrityFixture fixture;
    AcScanStats stats;
    char path_utf8[MAX_PATH * 3];
    char escaped_path[MAX_PATH * 6];
    char path_needle[MAX_PATH * 6 + 16];

    if (!ac_test_integrity_setup(&fixture, L"ac-int-clean")) {
        AC_CHECK(false);
        ac_test_integrity_teardown(&fixture);
        return;
    }

    memset(&stats, 0, sizeof(stats));
    AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 1u, &stats));

    AC_CHECK(stats.integrity_modules_checked > 0);
    AC_CHECK(stats.integrity_blocks_checked > 0);
    AC_CHECK(stats.integrity_bytes > 0);
    AC_CHECK(stats.integrity_iat_slots_checked > 0);
    AC_CHECK(stats.integrity_iat_hooks == 0);
    AC_CHECK(stats.integrity_export_hooks == 0);
    AC_CHECK(fixture.context.integrity.count > 0);
    AC_CHECK(ac_wide_to_utf8(
        fixture.target.image_path,
        path_utf8,
        sizeof(path_utf8)));
    AC_CHECK(ac_json_escape(path_utf8, escaped_path, sizeof(escaped_path)));
    (void)snprintf(
        path_needle,
        sizeof(path_needle),
        "\"path\":\"%s\"",
        escaped_path);
    AC_CHECK(!ac_test_log_contains_both(
        fixture.log_path,
        "\"event\":\"module_section_modified\"",
        path_needle));

    /* Baselines are cached, so a second pass must not re-read any file. */
    {
        const uintptr_t image_base = (uintptr_t)GetModuleHandleW(NULL);
        const AcIntegrityBaseline *baseline = ac_test_find_integrity_baseline(
            &fixture.context,
            image_base,
            fixture.target.image_path);
        uint8_t file_sha256[AC_SHA256_DIGEST_SIZE];
        uint64_t allocated = 0;
        AcScanStats second;

        AC_CHECK(baseline != NULL);
        if (baseline != NULL) {
            allocated = baseline->allocated_bytes;
            memcpy(file_sha256, baseline->file_sha256, sizeof(file_sha256));
        } else {
            memset(file_sha256, 0, sizeof(file_sha256));
        }

        memset(&second, 0, sizeof(second));
        AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 2u, &second));
        baseline = ac_test_find_integrity_baseline(
            &fixture.context,
            image_base,
            fixture.target.image_path);
        AC_CHECK(baseline != NULL);
        if (baseline != NULL) {
            AC_CHECK(baseline->allocated_bytes == allocated);
            AC_CHECK(memcmp(
                baseline->file_sha256,
                file_sha256,
                sizeof(file_sha256)) == 0);
        }
        AC_CHECK(second.integrity_blocks_checked > 0);
    }

    ac_test_integrity_teardown(&fixture);
}

/* Acceptance criterion: a single modified instruction byte in .text must be
   reported with the exact RVA it occupies. */
static void test_integrity_reports_patched_text_rva(void)
{
    AcIntegrityFixture fixture;
    AcScanStats before;
    AcScanStats after;
    int (*volatile victim_pointer)(int) = ac_test_patch_victim;
    uint8_t *victim = (uint8_t *)(void *)(uintptr_t)victim_pointer;
    const uintptr_t module_base = (uintptr_t)GetModuleHandleW(NULL);
    const uint32_t victim_rva = (uint32_t)((uintptr_t)victim - module_base);
    DWORD original_protection = 0;
    uint8_t original_byte;
    bool patched = false;
    char needle[64];
    char line[32768];
    FILE *file;
    bool found_rva = false;
    bool found_event = false;

    if (!ac_test_integrity_setup(&fixture, L"ac-int-patch")) {
        AC_CHECK(false);
        ac_test_integrity_teardown(&fixture);
        return;
    }

    memset(&before, 0, sizeof(before));
    AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 1u, &before));
    AC_CHECK(before.integrity_blocks_checked > 0);

    if (VirtualProtect(victim, 1u, PAGE_EXECUTE_READWRITE, &original_protection)) {
        original_byte = victim[0];
        victim[0] = (uint8_t)(original_byte ^ 0xffu);
        FlushInstructionCache(GetCurrentProcess(), victim, 1u);
        patched = true;

        memset(&after, 0, sizeof(after));
        AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 2u, &after));

        victim[0] = original_byte;
        FlushInstructionCache(GetCurrentProcess(), victim, 1u);
        {
            DWORD restored = 0;
            (void)VirtualProtect(victim, 1u, original_protection, &restored);
        }

        AC_CHECK(after.integrity_blocks_modified > before.integrity_blocks_modified);
    }

    AC_CHECK(patched);
    if (!patched) {
        ac_test_integrity_teardown(&fixture);
        return;
    }

    AC_CHECK(ac_test_patch_victim(3) == 34);

    (void)snprintf(needle, sizeof(needle), "\"modified_rva\":\"0x%08x\"", victim_rva);

    file = _wfopen(fixture.log_path, L"rb");
    AC_CHECK(file != NULL);
    if (file != NULL) {
        while (fgets(line, (int)sizeof(line), file) != NULL) {
            if (strstr(line, "\"event\":\"module_section_modified\"") == NULL) {
                continue;
            }
            found_event = true;
            if (strstr(line, needle) != NULL) {
                found_rva = true;
                AC_CHECK(strstr(line, "\"severity\":\"high\"") != NULL);
                AC_CHECK(strstr(line, "\"expected_sha256\"") != NULL);
                AC_CHECK(strstr(line, "\"observed_sha256\"") != NULL);
                AC_CHECK(strstr(line, "\"verdict\":\"signal_only\"") != NULL);
                break;
            }
        }
        (void)fclose(file);
    }

    AC_CHECK(found_event);
    AC_CHECK(found_rva);

    ac_test_integrity_teardown(&fixture);
}

static void test_integrity_reports_every_module_identity(void)
{
    AcIntegrityFixture fixture;
    AcScanStats stats;

    if (!ac_test_integrity_setup(&fixture, L"ac-int-identity")) {
        AC_CHECK(false);
        ac_test_integrity_teardown(&fixture);
        return;
    }

    memset(&stats, 0, sizeof(stats));
    AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 1u, &stats));
    AC_CHECK(stats.integrity_modules_checked > 0);
    AC_CHECK(ac_test_log_contains(
        fixture.log_path,
        "\"event\":\"module_identity_observed\""));
    AC_CHECK(ac_test_log_contains(fixture.log_path, "\"file_sha256\":\""));
    AC_CHECK(ac_test_log_contains(fixture.log_path, "\"file_index\":"));

    ac_test_integrity_teardown(&fixture);
}

static void test_integrity_budget_exhaustion_is_reported(void)
{
    AcIntegrityFixture fixture;
    AcScanStats stats;

    if (!ac_test_integrity_setup(&fixture, L"ac-int-budget")) {
        AC_CHECK(false);
        ac_test_integrity_teardown(&fixture);
        return;
    }

    fixture.context.policy.integrity_budget_bytes = 0;
    memset(&stats, 0, sizeof(stats));
    AC_CHECK(ac_scan_process(&fixture.context, &fixture.target, 1u, &stats));
    AC_CHECK(stats.integrity_modules_skipped > 0);
    AC_CHECK(stats.integrity_modules_checked == 0);
    AC_CHECK(ac_test_log_contains(
        fixture.log_path,
        "\"event\":\"scan_coverage_gap\""));
    AC_CHECK(ac_test_log_contains(
        fixture.log_path,
        "\"reason\":\"scan_coverage_incomplete\""));

    ac_test_integrity_teardown(&fixture);
}

static void test_driver_protocol_session_layout(void)
{
    AcDriverTargetRequest request;
    AcDriverStats stats;
    volatile uint32_t protocol_version;
    volatile size_t request_size;
    volatile size_t stats_size;

    memset(&request, 0, sizeof(request));
    memset(&stats, 0, sizeof(stats));
    request.size = (uint32_t)sizeof(request);
    request.protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    request.target_pid = 42u;
    request.session_id = UINT64_C(0x0102030405060708);
    protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    request_size = sizeof(request);
    stats_size = sizeof(stats);

    AC_CHECK(protocol_version == 3u);
    AC_CHECK(request_size == 24u);
    AC_CHECK(stats_size == 56u);
    AC_CHECK(request.session_id != 0);
    AC_CHECK(request.reserved == 0);
}

static void test_kernel_sequence_gap_is_detected(void)
{
    AcKernelClient client;
    uint64_t missing = UINT64_MAX;

    ac_kernel_client_init(&client);
    AC_CHECK(client.telemetry_complete);
    AC_CHECK(ac_kernel_client_observe_sequence(&client, 1u, &missing));
    AC_CHECK(missing == 0);
    AC_CHECK(ac_kernel_client_observe_sequence(&client, 4u, &missing));
    AC_CHECK(missing == 2u);
    AC_CHECK(client.sequence_events_missing == 2u);
    AC_CHECK(!client.telemetry_complete);
    AC_CHECK(!ac_kernel_client_observe_sequence(&client, 4u, &missing));
}

static void test_kernel_drop_counter_is_monotonic(void)
{
    AcKernelClient client;
    AcDriverStats stats;
    AcLogger logger;
    wchar_t path[MAX_PATH];
    uint64_t newly_dropped = UINT64_MAX;

    if (!ac_temp_log_path(
            path,
            sizeof(path) / sizeof(path[0]),
            L"ac-kernel-drop")) {
        AC_CHECK(false);
        return;
    }
    (void)_wremove(path);

    ac_kernel_client_init(&client);
    memset(&stats, 0, sizeof(stats));
    stats.next_sequence = 1u;
    stats.events_dropped = 7u;
    stats.queue_depth = AC_DRIVER_QUEUE_CAPACITY;
    stats.queue_capacity = AC_DRIVER_QUEUE_CAPACITY;
    stats.callbacks_active = 3u;
    if (!ac_logger_open(&logger, path, false, 0, 0)) {
        AC_CHECK(false);
        return;
    }
    AC_CHECK(ac_kernel_client_process_stats(
        &client,
        &logger,
        GetCurrentProcessId(),
        &stats));
    AC_CHECK(client.last_dropped == 7u);
    AC_CHECK(!client.telemetry_complete);
    ac_logger_close(&logger);
    AC_CHECK(ac_test_log_contains_both(
        path,
        "\"severity\":\"high\"",
        "\"event\":\"kernel_event_queue_overflow\""));
    AC_CHECK(ac_test_log_contains_both(
        path,
        "\"possible_attack\":\"event_flooding\"",
        "\"required_action\":\"invalidate_session_evidence\""));
    AC_CHECK(!ac_kernel_client_observe_drop_counter(
        &client,
        6u,
        &newly_dropped));
    (void)_wremove(path);
}

static void test_kernel_user_module_correlation(void)
{
    AcKernelClient client;
    AcLogger logger;
    AcRangeIndex ranges;
    wchar_t path[MAX_PATH];
    uint64_t mismatches = 0;

    if (!ac_temp_log_path(
            path,
            sizeof(path) / sizeof(path[0]),
            L"ac-kernel-correlation")) {
        AC_CHECK(false);
        return;
    }
    (void)_wremove(path);

    ac_kernel_client_init(&client);
    client.image_observations[0].sequence = 2u;
    client.image_observations[0].image_base = 0x100000u;
    client.image_observations[0].image_size = 0x2000u;
    client.image_observations[1].sequence = 3u;
    client.image_observations[1].image_base = 0x900000u;
    client.image_observations[1].image_size = 0x3000u;
    client.image_observation_count = 2u;

    ac_range_index_init(&ranges);
    if (!ac_range_index_add(&ranges, 0x100000u, 0x2000u)) {
        AC_CHECK(false);
        ac_range_index_free(&ranges);
        return;
    }
    ac_range_index_finalize(&ranges);
    if (!ac_logger_open(&logger, path, false, 0, 0)) {
        AC_CHECK(false);
        ac_range_index_free(&ranges);
        return;
    }

    ac_kernel_client_correlate_scan(
        &client,
        &logger,
        GetCurrentProcessId(),
        9u,
        &ranges,
        &mismatches);

    AC_CHECK(mismatches == 1u);
    AC_CHECK(client.image_observation_count == 0);
    AC_CHECK(!client.telemetry_complete);
    ac_logger_close(&logger);
    AC_CHECK(ac_test_log_contains(
        path,
        "\"event\":\"kernel_user_module_mismatch\""));
    AC_CHECK(ac_test_log_contains_both(
        path,
        "\"event\":\"kernel_user_scan_correlation\"",
        "\"missing_from_user_snapshot\":1"));

    ac_range_index_free(&ranges);
    (void)_wremove(path);
}

typedef void (*AcCoreTestFunction)(void);

typedef struct AcCoreTestCase {
    const char *name;
    AcCoreTestFunction function;
} AcCoreTestCase;

static const AcCoreTestCase g_test_cases[] = {
    {"path_boundaries", test_path_boundaries},
    {"allow_roots", test_allow_roots},
    {"module_list_and_ranges", test_module_list_and_ranges},
    {"parent_directory", test_parent_directory},
    {"image_name_matching", test_image_name_matching},
    {"wide_to_utf8", test_wide_to_utf8},
    {"log_chain", test_log_chain_is_verifiable},
    {"log_rotation", test_log_rotation},
    {"policy_defaults", test_policy_defaults},
    {"least_privilege_process_access", test_open_process_uses_read_only_access},
    {"self_scan", test_scan_of_self_produces_events},
    {"integrity_clean_process", test_integrity_clean_process_has_no_findings},
    {"integrity_patched_text", test_integrity_reports_patched_text_rva},
    {"integrity_module_identity", test_integrity_reports_every_module_identity},
    {"integrity_budget_gap", test_integrity_budget_exhaustion_is_reported},
    {"driver_protocol_session", test_driver_protocol_session_layout},
    {"kernel_sequence_gap", test_kernel_sequence_gap_is_detected},
    {"kernel_drop_counter", test_kernel_drop_counter_is_monotonic},
    {"kernel_user_correlation", test_kernel_user_module_correlation}
};

int main(int argc, char **argv)
{
    size_t index;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <test-case>\n", argv[0]);
        return 2;
    }

    for (index = 0;
         index < sizeof(g_test_cases) / sizeof(g_test_cases[0]);
         ++index) {
        const AcCoreTestCase *test_case = &g_test_cases[index];

        if (strcmp(argv[1], test_case->name) != 0) {
            continue;
        }

        g_failures = 0;
        test_case->function();

        if (g_failures != 0) {
            fprintf(
                stderr,
                "%d check(s) failed in core.%s\n",
                g_failures,
                test_case->name);
            return 1;
        }

        printf("core.%s passed\n", test_case->name);
        return 0;
    }

    fprintf(stderr, "unknown core test case: %s\n", argv[1]);
    return 2;
}
