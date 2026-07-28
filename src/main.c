#include "ac.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define AC_EXIT_OK 0
#define AC_EXIT_USAGE 2
#define AC_EXIT_LOG_FAILURE 3
#define AC_EXIT_TARGET_NOT_FOUND 4
#define AC_EXIT_ACCESS_DENIED 5
#define AC_EXIT_INTERNAL 6

typedef struct AcOptions {
    const wchar_t *process_name;
    const wchar_t *log_path;
    const wchar_t *extra_roots[AC_MAX_ALLOW_ROOTS];
    size_t extra_root_count;
    DWORD pid;
    DWORD interval_ms;
    DWORD wait_timeout_ms;
    uint64_t max_log_bytes;
    uint64_t repeat_interval_ms;
    uint64_t scan_budget_ms;
    unsigned int log_generations;
    bool once;
    bool quiet;
    bool skip_module_hashes;
    bool skip_region_probe;
    bool kernel_telemetry;
    bool require_kernel;
} AcOptions;

static HANDLE g_stop_event = NULL;

static BOOL WINAPI ac_console_handler(DWORD control_type)
{
    switch (control_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            if (g_stop_event != NULL) {
                (void)SetEvent(g_stop_event);
            }
            return TRUE;
        default:
            return FALSE;
    }
}

static bool ac_stop_requested(void)
{
    return g_stop_event != NULL &&
           WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0;
}

static void ac_print_usage(const wchar_t *program)
{
    fwprintf(
        stdout,
        L"%ls " L"%hs" L"\n"
        L"\n"
        L"Usage:\n"
        L"  %ls --process <game.exe> [options]\n"
        L"  %ls --pid <pid> [options]\n"
        L"\n"
        L"Target:\n"
        L"  --process <name>          image name to watch (e.g. game.exe)\n"
        L"  --pid <pid>               attach to an explicit process id\n"
        L"  --wait-timeout-ms <n>     give up waiting for the process (0 = forever)\n"
        L"\n"
        L"Scanning:\n"
        L"  --interval-ms <n>         scan period, 1000..3600000 (default 5000)\n"
        L"  --once                    perform a single scan and exit\n"
        L"  --allow-root <dir>        additional trusted module root (repeatable)\n"
        L"  --scan-budget-ms <n>      warn when one scan exceeds this (default 250)\n"
        L"  --repeat-interval-ms <n>  re-report an identical signal after this (default 300000)\n"
        L"  --no-module-hashes        do not SHA-256 unknown module files\n"
        L"  --no-region-probe         do not read suspicious region content\n"
        L"\n"
        L"Kernel telemetry:\n"
        L"  --kernel                  consume AcTelemetry driver events when available\n"
        L"  --require-kernel          fail if the driver cannot be opened or configured\n"
        L"\n"
        L"Output:\n"
        L"  --log <file>              JSON Lines output (default anticheat-events.jsonl)\n"
        L"  --max-log-bytes <n>       rotate above this size, 0 disables (default 33554432)\n"
        L"  --log-generations <n>     rotated files to keep (default 5)\n"
        L"  --quiet                   do not mirror events to stdout\n"
        L"  --version                 print version and exit\n"
        L"  --help                    print this help and exit\n"
        L"\n"
        L"Exit codes: 0 ok, 2 usage, 3 log failure, 4 target not found, "
        L"5 access denied, 6 internal error\n",
        program,
        AC_AGENT_VERSION,
        program,
        program);
}

static void ac_print_version(void)
{
    fwprintf(
        stdout,
        L"collector_version=%hs\n"
        L"event_schema_version=%u\n"
        L"driver_protocol_version=%u\n",
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION,
        AC_DRIVER_PROTOCOL_VERSION);
}

static bool ac_parse_u64(
    const wchar_t *text,
    uint64_t minimum,
    uint64_t maximum,
    uint64_t *value_out)
{
    wchar_t *end = NULL;
    unsigned long long value;

    if (text == NULL || value_out == NULL || text[0] == L'\0') {
        return false;
    }

    value = wcstoull(text, &end, 10);
    if (end == text || *end != L'\0' ||
        (uint64_t)value < minimum || (uint64_t)value > maximum) {
        return false;
    }

    *value_out = (uint64_t)value;
    return true;
}

static bool ac_parse_options(int argc, wchar_t **argv, AcOptions *options, bool *exit_now)
{
    int index;

    memset(options, 0, sizeof(*options));
    options->interval_ms = 5000u;
    options->log_path = L"anticheat-events.jsonl";
    options->max_log_bytes = 32ull * 1024ull * 1024ull;
    options->log_generations = 5u;
    options->repeat_interval_ms = 300000u;
    options->scan_budget_ms = 250u;
    *exit_now = false;

    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        ac_print_version();
        *exit_now = true;
        return true;
    }

    for (index = 1; index < argc; ++index) {
        const wchar_t *argument = argv[index];
        const bool has_value = index + 1 < argc;
        uint64_t number = 0;

        if (wcscmp(argument, L"--help") == 0 || wcscmp(argument, L"-h") == 0) {
            ac_print_usage(argv[0]);
            *exit_now = true;
            return true;
        }
        if (wcscmp(argument, L"--once") == 0) {
            options->once = true;
        } else if (wcscmp(argument, L"--quiet") == 0) {
            options->quiet = true;
        } else if (wcscmp(argument, L"--no-module-hashes") == 0) {
            options->skip_module_hashes = true;
        } else if (wcscmp(argument, L"--no-region-probe") == 0) {
            options->skip_region_probe = true;
        } else if (wcscmp(argument, L"--kernel") == 0) {
            options->kernel_telemetry = true;
        } else if (wcscmp(argument, L"--require-kernel") == 0) {
            options->kernel_telemetry = true;
            options->require_kernel = true;
        } else if (wcscmp(argument, L"--process") == 0 && has_value) {
            options->process_name = argv[++index];
        } else if (wcscmp(argument, L"--log") == 0 && has_value) {
            options->log_path = argv[++index];
        } else if (wcscmp(argument, L"--allow-root") == 0 && has_value) {
            if (options->extra_root_count >= AC_MAX_ALLOW_ROOTS - 4u) {
                return false;
            }
            options->extra_roots[options->extra_root_count++] = argv[++index];
        } else if (wcscmp(argument, L"--pid") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 1u, 0xffffffffull, &number)) {
                return false;
            }
            options->pid = (DWORD)number;
        } else if (wcscmp(argument, L"--interval-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 1000u, 3600000u, &number)) {
                return false;
            }
            options->interval_ms = (DWORD)number;
        } else if (wcscmp(argument, L"--wait-timeout-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 86400000u, &number)) {
                return false;
            }
            options->wait_timeout_ms = (DWORD)number;
        } else if (wcscmp(argument, L"--max-log-bytes") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 1024ull * 1024ull * 1024ull, &number)) {
                return false;
            }
            options->max_log_bytes = number;
        } else if (wcscmp(argument, L"--log-generations") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 64u, &number)) {
                return false;
            }
            options->log_generations = (unsigned int)number;
        } else if (wcscmp(argument, L"--repeat-interval-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 86400000u, &number)) {
                return false;
            }
            options->repeat_interval_ms = number;
        } else if (wcscmp(argument, L"--scan-budget-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 3600000u, &number)) {
                return false;
            }
            options->scan_budget_ms = number;
        } else {
            return false;
        }
    }

    if (options->pid != 0) {
        return true;
    }
    return options->process_name != NULL && options->process_name[0] != L'\0';
}

static void ac_log_text_event(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *key,
    const wchar_t *value)
{
    char value_utf8[1024];
    char escaped[2048];
    char details[2176];

    if (!ac_wide_to_utf8(value != NULL ? value : L"", value_utf8, sizeof(value_utf8))) {
        (void)strcpy_s(value_utf8, sizeof(value_utf8), "<conversion-failed>");
    }
    (void)ac_json_escape(value_utf8, escaped, sizeof(escaped));
    (void)snprintf(details, sizeof(details), "{\"%s\":\"%s\"}", key, escaped);
    ac_log_event(logger, severity, event, pid, details);
}

static bool ac_resolve_target_pid(
    const AcOptions *options,
    AcLogger *logger,
    DWORD *pid_out)
{
    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)options->wait_timeout_ms;
    bool announced = false;

    if (options->pid != 0) {
        *pid_out = options->pid;
        return true;
    }

    while (!ac_stop_requested()) {
        size_t matches = 0;

        if (ac_find_process_by_name(options->process_name, pid_out, &matches)) {
            if (matches > 1) {
                char details[256];

                (void)snprintf(
                    details,
                    sizeof(details),
                    "{\"matches\":%zu,\"selected_pid\":%lu,"
                    "\"hint\":\"use --pid to disambiguate\"}",
                    matches,
                    (unsigned long)*pid_out);
                ac_log_event(
                    logger,
                    AC_SEVERITY_LOW,
                    "multiple_process_matches",
                    *pid_out,
                    details);
            }
            return true;
        }

        if (!announced) {
            ac_log_text_event(
                logger,
                AC_SEVERITY_INFO,
                "waiting_for_process",
                0,
                "process_name",
                options->process_name);
            announced = true;
        }

        if (options->wait_timeout_ms != 0 && GetTickCount64() >= deadline) {
            ac_log_event(
                logger,
                AC_SEVERITY_INFO,
                "wait_for_process_timed_out",
                0,
                "{\"verdict\":\"no_target\"}");
            return false;
        }

        if (WaitForSingleObject(g_stop_event, 500u) == WAIT_OBJECT_0) {
            return false;
        }
    }

    return false;
}

static void ac_read_directory(
    wchar_t *buffer,
    DWORD capacity,
    const wchar_t *environment_variable)
{
    const DWORD length = environment_variable == NULL
        ? GetWindowsDirectoryW(buffer, (UINT)capacity)
        : GetEnvironmentVariableW(environment_variable, buffer, capacity);

    if (length == 0 || length >= capacity) {
        buffer[0] = L'\0';
    }
}

static size_t ac_build_allow_roots(
    const AcOptions *options,
    const wchar_t *game_directory,
    const wchar_t *windows_directory,
    const wchar_t *program_files,
    const wchar_t *program_files_x86,
    const wchar_t **roots)
{
    size_t count = 0;
    size_t index;

    if (game_directory != NULL && game_directory[0] != L'\0') {
        roots[count++] = game_directory;
    }
    if (windows_directory != NULL && windows_directory[0] != L'\0') {
        roots[count++] = windows_directory;
    }
    if (program_files != NULL && program_files[0] != L'\0') {
        roots[count++] = program_files;
    }
    if (program_files_x86 != NULL && program_files_x86[0] != L'\0') {
        roots[count++] = program_files_x86;
    }

    for (index = 0; index < options->extra_root_count && count < AC_MAX_ALLOW_ROOTS; ++index) {
        roots[count++] = options->extra_roots[index];
    }

    return count;
}

static void ac_log_allow_roots(
    AcLogger *logger,
    DWORD pid,
    const wchar_t **roots,
    size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        ac_log_text_event(
            logger,
            AC_SEVERITY_INFO,
            "allow_root_configured",
            pid,
            "path",
            roots[index]);
    }
}

int wmain(int argc, wchar_t **argv)
{
    AcOptions options;
    AcLogger logger;
    AcContext context;
    AcKernelClient kernel_client;
    AcPolicy policy;
    AcTarget target;
    const wchar_t *roots[AC_MAX_ALLOW_ROOTS];
    wchar_t windows_directory[MAX_PATH];
    wchar_t program_files[MAX_PATH];
    wchar_t program_files_x86[MAX_PATH];
    char details[1024];
    uint64_t scan_id = 0;
    uint64_t kernel_events = 0;
    size_t root_count = 0;
    size_t root_index;
    bool exit_now = false;
    bool context_ready = false;
    bool kernel_ready = false;
    int exit_code = AC_EXIT_INTERNAL;

    memset(&target, 0, sizeof(target));
    ac_kernel_client_init(&kernel_client);

    if (!ac_parse_options(argc, argv, &options, &exit_now)) {
        ac_print_usage(argv[0]);
        return AC_EXIT_USAGE;
    }
    if (exit_now) {
        return AC_EXIT_OK;
    }

    if (!ac_logger_open(
            &logger,
            options.log_path,
            !options.quiet,
            options.max_log_bytes,
            options.log_generations)) {
        fwprintf(stderr, L"Cannot open log file: %ls\n", options.log_path);
        return AC_EXIT_LOG_FAILURE;
    }

    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL) {
        ac_log_win32_error(&logger, "create_stop_event_failed", 0, GetLastError());
        ac_logger_close(&logger);
        return AC_EXIT_INTERNAL;
    }
    (void)SetConsoleCtrlHandler(ac_console_handler, TRUE);

    (void)snprintf(
        details,
        sizeof(details),
        "{\"agent\":\"%s\",\"version\":\"%s\",\"schema\":%u,\"mode\":\"%s\","
        "\"memory_write_access\":false,\"terminates_target\":false,"
        "\"interval_ms\":%lu,\"once\":%s,\"scan_budget_ms\":%" PRIu64 ","
        "\"repeat_interval_ms\":%" PRIu64 ",\"pointer_bits\":%zu}",
        AC_AGENT_NAME,
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION,
        options.kernel_telemetry
            ? "hybrid_kernel_user_telemetry"
            : "user_telemetry",
        (unsigned long)options.interval_ms,
        options.once ? "true" : "false",
        options.scan_budget_ms,
        options.repeat_interval_ms,
        sizeof(void *) * 8u);
    ac_log_event(&logger, AC_SEVERITY_INFO, "agent_started", 0, details);

    if (!ac_resolve_target_pid(&options, &logger, &target.pid)) {
        exit_code = ac_stop_requested() ? AC_EXIT_OK : AC_EXIT_TARGET_NOT_FOUND;
        goto cleanup;
    }

    target.process = ac_open_process_for_scan(target.pid, &target.granted_access);
    if (target.process == NULL) {
        ac_log_win32_error(&logger, "open_process_failed", target.pid, GetLastError());
        exit_code = AC_EXIT_ACCESS_DENIED;
        goto cleanup;
    }

    if (!ac_get_process_path(target.process, &target.image_path)) {
        ac_log_win32_error(&logger, "query_process_path_failed", target.pid, GetLastError());
        goto cleanup;
    }

    if (options.process_name != NULL &&
        !ac_process_image_matches_name(target.image_path, options.process_name)) {
        ac_log_text_event(
            &logger,
            AC_SEVERITY_MEDIUM,
            "target_identity_mismatch",
            target.pid,
            "image_path",
            target.image_path);
        exit_code = AC_EXIT_TARGET_NOT_FOUND;
        goto cleanup;
    }

    if (!ac_get_parent_directory(target.image_path, &target.directory)) {
        ac_log_win32_error(&logger, "derive_game_directory_failed", target.pid, GetLastError());
        goto cleanup;
    }

    (void)ac_get_process_start_time(target.process, &target.start_time);

    ac_read_directory(windows_directory, MAX_PATH, NULL);
    ac_read_directory(program_files, MAX_PATH, L"ProgramFiles");
    ac_read_directory(program_files_x86, MAX_PATH, L"ProgramFiles(x86)");

    root_count = ac_build_allow_roots(
        &options,
        target.directory,
        windows_directory,
        program_files,
        program_files_x86,
        roots);

    ac_policy_init_defaults(&policy);
    policy.allow_root_count = root_count;
    for (root_index = 0; root_index < root_count; ++root_index) {
        policy.allow_roots[root_index] = roots[root_index];
    }
    policy.repeat_interval_ms = options.repeat_interval_ms;
    policy.scan_budget_ms = options.scan_budget_ms;
    policy.hash_unknown_modules = !options.skip_module_hashes;
    policy.probe_region_content = !options.skip_region_probe;

    if (!ac_context_init(&context, &logger, &policy)) {
        ac_log_event(
            &logger,
            AC_SEVERITY_LOW,
            "context_init_failed",
            target.pid,
            "{\"reason\":\"out_of_memory\"}");
        goto cleanup;
    }
    context_ready = true;

    ac_log_allow_roots(&logger, target.pid, roots, root_count);

    {
        char image_utf8[1024];
        char escaped_image[2048];
        char target_details[3072];

        if (!ac_wide_to_utf8(target.image_path, image_utf8, sizeof(image_utf8))) {
            (void)strcpy_s(image_utf8, sizeof(image_utf8), "<conversion-failed>");
        }
        (void)ac_json_escape(image_utf8, escaped_image, sizeof(escaped_image));
        (void)snprintf(
            target_details,
            sizeof(target_details),
            "{\"path\":\"%s\",\"granted_access\":\"0x%08lx\","
            "\"least_privilege\":%s,\"start_time_filetime\":%" PRIu64 ","
            "\"allow_roots\":%zu}",
            escaped_image,
            (unsigned long)target.granted_access,
            (target.granted_access & PROCESS_QUERY_LIMITED_INFORMATION) != 0 &&
                    (target.granted_access & PROCESS_QUERY_INFORMATION) == 0
                ? "true"
                : "false",
            target.start_time,
            root_count);
        ac_log_event(&logger, AC_SEVERITY_INFO, "target_opened", target.pid, target_details);
    }

    if (options.kernel_telemetry) {
        if (!ac_kernel_client_open(&kernel_client)) {
            ac_log_win32_error(
                &logger,
                "kernel_driver_open_failed",
                target.pid,
                GetLastError());
            if (options.require_kernel) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else if (!ac_kernel_client_set_target(
                       &kernel_client,
                       target.pid)) {
            const DWORD error = GetLastError();
            ac_log_win32_error(
                &logger,
                "kernel_target_registration_failed",
                target.pid,
                error);
            ac_kernel_client_close(&kernel_client);
            if (options.require_kernel) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else {
            char kernel_details[512];
            kernel_ready = true;
            (void)snprintf(
                kernel_details,
                sizeof(kernel_details),
                "{\"protocol_version\":%u,\"event_size\":%u,"
                "\"queue_capacity\":%u,\"target_pid\":%lu}",
                kernel_client.version.protocol_version,
                kernel_client.version.event_size,
                kernel_client.version.queue_capacity,
                (unsigned long)target.pid);
            ac_log_event(
                &logger,
                AC_SEVERITY_INFO,
                "kernel_driver_connected",
                target.pid,
                kernel_details);
        }
    }

    for (;;) {
        AcScanStats stats;
        HANDLE wait_handles[2];
        DWORD wait_result;

        if (ac_stop_requested()) {
            exit_code = AC_EXIT_OK;
            break;
        }

        if (kernel_ready &&
            !ac_kernel_client_drain(
                &kernel_client,
                &logger,
                target.pid,
                &kernel_events)) {
            ac_log_win32_error(
                &logger,
                "kernel_event_read_failed",
                target.pid,
                GetLastError());
            ac_kernel_client_close(&kernel_client);
            kernel_ready = false;
            if (options.require_kernel) {
                exit_code = AC_EXIT_INTERNAL;
                break;
            }
        }

        ++scan_id;
        if (!ac_scan_process(&context, &target, scan_id, &stats)) {
            const DWORD error = GetLastError();

            if (WaitForSingleObject(target.process, 0) == WAIT_OBJECT_0) {
                ac_log_event(&logger, AC_SEVERITY_INFO, "target_exited", target.pid, "{}");
                exit_code = AC_EXIT_OK;
                break;
            }
            ac_log_win32_error(&logger, "scan_failed", target.pid, error);
        }

        if (options.once) {
            exit_code = AC_EXIT_OK;
            break;
        }

        wait_handles[0] = target.process;
        wait_handles[1] = g_stop_event;
        wait_result = WaitForMultipleObjects(2u, wait_handles, FALSE, options.interval_ms);

        if (wait_result == WAIT_OBJECT_0) {
            if (kernel_ready) {
                (void)ac_kernel_client_drain(
                    &kernel_client,
                    &logger,
                    target.pid,
                    &kernel_events);
            }
            ac_log_event(&logger, AC_SEVERITY_INFO, "target_exited", target.pid, "{}");
            exit_code = AC_EXIT_OK;
            break;
        }
        if (wait_result == WAIT_OBJECT_0 + 1u) {
            exit_code = AC_EXIT_OK;
            break;
        }
        if (wait_result == WAIT_FAILED) {
            ac_log_win32_error(&logger, "wait_failed", target.pid, GetLastError());
            Sleep(options.interval_ms);
        }
    }

cleanup:
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scans\":%" PRIu64 ",\"terminated_target\":false,"
        "\"kernel_events\":%" PRIu64 ","
        "\"log_write_failures\":%" PRIu64 ",\"log_truncated_lines\":%" PRIu64 ","
        "\"exit_code\":%d}",
        scan_id,
        kernel_events,
        logger.write_failures,
        logger.truncated_lines,
        exit_code);
    ac_log_event(&logger, AC_SEVERITY_INFO, "agent_stopped", target.pid, details);

    if (context_ready) {
        ac_context_free(&context);
    }
    if (kernel_ready) {
        (void)ac_kernel_client_set_target(&kernel_client, 0);
        ac_kernel_client_close(&kernel_client);
    }
    if (target.process != NULL) {
        CloseHandle(target.process);
    }
    free(target.image_path);
    free(target.directory);
    if (g_stop_event != NULL) {
        CloseHandle(g_stop_event);
        g_stop_event = NULL;
    }
    ac_logger_close(&logger);
    return exit_code;
}
