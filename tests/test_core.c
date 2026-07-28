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
    {"self_scan", test_scan_of_self_produces_events}
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
