#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#include "schedule.h"

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
    DWORD interval_min_ms;
    DWORD interval_max_ms;
    DWORD wait_timeout_ms;
    uint64_t max_log_bytes;
    uint64_t repeat_interval_ms;
    uint64_t scan_budget_ms;
    unsigned int log_generations;
    bool once;
    bool quiet;
    bool skip_module_hashes;
    bool skip_region_probe;
    bool skip_module_integrity;
    uint64_t integrity_budget_bytes;
    uint64_t integrity_max_file_bytes;
    bool kernel_telemetry;
    bool require_kernel;
    const wchar_t *manifest_path;
    const wchar_t *manifest_sha256;
    uint8_t manifest_public_keys[AC_MANIFEST_ENVELOPE_MAX_KEYS][AC_ED25519_PUBLIC_KEY_SIZE];
    size_t manifest_public_key_count;
    uint64_t manifest_min_sequence;
    bool manifest_min_sequence_set;
    bool require_manifest;
    const wchar_t *attestation_challenge;
    const wchar_t *attestation_nonce;
    const wchar_t *attestation_session;
    bool require_attestation;
    bool require_secure_kernel;
    AcDispatchWatch dispatch_watches[AC_MAX_DISPATCH_WATCHES];
    size_t dispatch_watch_count;
} AcOptions;

static DWORD ac_randomized_interval(
    DWORD minimum_ms,
    DWORD maximum_ms,
    bool *random_available_out)
{
    uint64_t random_value = 0;

    if (random_available_out != NULL) {
        *random_available_out = false;
    }
    if (minimum_ms > maximum_ms) {
        return minimum_ms;
    }
    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&random_value,
            (ULONG)sizeof(random_value),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return minimum_ms;
    }
    if (random_available_out != NULL) {
        *random_available_out = true;
    }
    return ac_schedule_delay_from_random(
        minimum_ms,
        maximum_ms,
        random_value);
}

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
        L"  --interval-min-ms <n>     minimum randomized delay (default 4000)\n"
        L"  --interval-max-ms <n>     maximum randomized delay (default 6000)\n"
        L"  --once                    perform a single scan and exit\n"
        L"  --allow-root <dir>        additional trusted module root (repeatable)\n"
        L"  --scan-budget-ms <n>      warn when one scan exceeds this (default 250)\n"
        L"  --repeat-interval-ms <n>  re-report an identical signal after this (default 300000)\n"
        L"  --no-module-hashes        do not SHA-256 unknown module files\n"
        L"  --no-region-probe         do not read suspicious region content\n"
        L"  --watch-pointer <m+rva>   validate a critical function-pointer slot\n"
        L"  --watch-vtable <m+rva:n>  validate n entries of an object VMT\n"
        L"\n"
        L"Module integrity:\n"
        L"  --no-module-integrity     do not validate executable sections against disk\n"
        L"  --integrity-budget <n>    bytes hashed per scan (default 16777216)\n"
        L"  --integrity-max-file <n>  largest module file to validate (default 67108864)\n"
        L"  --manifest <file>         trusted module/driver manifest\n"
        L"  --manifest-sha256 <hex>   control-plane pin for the manifest file\n"
        L"  --manifest-public-key <hex>  Ed25519 key for ac-manifest-v2 (repeatable)\n"
        L"  --manifest-min-sequence <n>  reject signed manifests below this sequence\n"
        L"  --require-manifest        fail when the trusted manifest is unavailable\n"
        L"  --attestation-challenge <id>  server challenge id (32 hex)\n"
        L"  --attestation-nonce <hex>     server nonce (64 hex)\n"
        L"  --attestation-session <id>    reserved server session id (32 hex)\n"
        L"  --require-attestation     fail on missing or inconsistent self-attestation\n"
        L"\n"
        L"Kernel telemetry:\n"
        L"  --kernel                  consume AcTelemetry driver events when available\n"
        L"  --require-kernel          fail if the driver cannot be opened or configured\n"
        L"  --require-secure-kernel   require Secure Boot, CI, and enforced HVCI\n"
        L"\n"
        L"Output:\n"
        L"  --log <file>              JSON Lines output (default anticheat-events.jsonl)\n"
        L"  --max-log-bytes <n>       rotate above this size, 0 disables (default 33554432)\n"
        L"  --log-generations <n>     rotated files to keep (default 5)\n"
        L"  --quiet                   do not mirror events to stdout\n"
        L"  --version                 print version and exit\n"
        L"  --print-attestation-digest  print release attestation identity and exit\n"
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

static bool ac_print_attestation_digest(void)
{
    static const wchar_t challenge[] =
        L"00000000000000000000000000000000";
    static const wchar_t nonce[] =
        L"0000000000000000000000000000000000000000000000000000000000000000";
    static const wchar_t session[] =
        L"00000000000000000000000000000000";
    AcCollectorAttestation result;

    if (!ac_collector_attest(challenge, nonce, session, &result)) {
        fwprintf(
            stderr,
            L"Cannot calculate collector attestation identity: %lu\n",
            (unsigned long)GetLastError());
        return false;
    }
    printf(
        "collector_file_sha256=%s\n"
        "collector_expected_mapped_sha256=%s\n"
        "collector_observed_mapped_sha256=%s\n"
        "collector_mapped_matches_disk=%s\n",
        result.file_sha256,
        result.expected_mapped_sha256,
        result.observed_mapped_sha256,
        result.mapped_matches_disk ? "true" : "false");
    return result.mapped_matches_disk;
}

static bool ac_wide_hex_bytes(const wchar_t *text, uint8_t *bytes, size_t count)
{
    size_t index;

    if (text == NULL || wcslen(text) != count * 2u) {
        return false;
    }
    for (index = 0; index < count * 2u; ++index) {
        const wchar_t value = text[index];
        uint8_t digit;

        if (value >= L'0' && value <= L'9') {
            digit = (uint8_t)(value - L'0');
        } else if (value >= L'a' && value <= L'f') {
            digit = (uint8_t)(value - L'a' + 10);
        } else if (value >= L'A' && value <= L'F') {
            digit = (uint8_t)(value - L'A' + 10);
        } else {
            return false;
        }
        if ((index & 1u) == 0) {
            bytes[index / 2u] = (uint8_t)(digit << 4u);
        } else {
            bytes[index / 2u] = (uint8_t)(bytes[index / 2u] | digit);
        }
    }
    return true;
}

static bool ac_wide_hex_length(const wchar_t *text, size_t length)
{
    size_t index;

    if (text == NULL || wcslen(text) != length) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        const wchar_t value = text[index];
        if (!((value >= L'0' && value <= L'9') ||
              (value >= L'a' && value <= L'f') ||
              (value >= L'A' && value <= L'F'))) {
            return false;
        }
    }
    return true;
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
    options->interval_min_ms = 4000u;
    options->interval_max_ms = 6000u;
    options->log_path = L"anticheat-events.jsonl";
    options->max_log_bytes = 32ull * 1024ull * 1024ull;
    options->log_generations = 5u;
    options->repeat_interval_ms = 300000u;
    options->scan_budget_ms = 250u;
    options->integrity_budget_bytes = 16ull * 1024ull * 1024ull;
    options->integrity_max_file_bytes = 64ull * 1024ull * 1024ull;
    *exit_now = false;

    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        ac_print_version();
        *exit_now = true;
        return true;
    }
    if (argc == 2 &&
        wcscmp(argv[1], L"--print-attestation-digest") == 0) {
        *exit_now = true;
        return ac_print_attestation_digest();
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
        } else if (wcscmp(argument, L"--no-module-integrity") == 0) {
            options->skip_module_integrity = true;
        } else if (wcscmp(argument, L"--watch-pointer") == 0 && has_value) {
            if (options->dispatch_watch_count >= AC_MAX_DISPATCH_WATCHES ||
                !ac_dispatch_watch_parse(
                    argv[++index],
                    AC_DISPATCH_FUNCTION_POINTER,
                    &options->dispatch_watches[
                        options->dispatch_watch_count])) {
                return false;
            }
            ++options->dispatch_watch_count;
        } else if (wcscmp(argument, L"--watch-vtable") == 0 && has_value) {
            if (options->dispatch_watch_count >= AC_MAX_DISPATCH_WATCHES ||
                !ac_dispatch_watch_parse(
                    argv[++index],
                    AC_DISPATCH_OBJECT_VTABLE,
                    &options->dispatch_watches[
                        options->dispatch_watch_count])) {
                return false;
            }
            ++options->dispatch_watch_count;
        } else if (wcscmp(argument, L"--integrity-budget") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 4096ull * 1024ull * 1024ull, &number)) {
                return false;
            }
            options->integrity_budget_bytes = number;
        } else if (wcscmp(argument, L"--integrity-max-file") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 0u, 4096ull * 1024ull * 1024ull, &number)) {
                return false;
            }
            options->integrity_max_file_bytes = number;
        } else if (wcscmp(argument, L"--kernel") == 0) {
            options->kernel_telemetry = true;
        } else if (wcscmp(argument, L"--require-kernel") == 0) {
            options->kernel_telemetry = true;
            options->require_kernel = true;
        } else if (wcscmp(argument, L"--require-secure-kernel") == 0) {
            options->require_secure_kernel = true;
        } else if (wcscmp(argument, L"--manifest") == 0 && has_value) {
            options->manifest_path = argv[++index];
        } else if (wcscmp(argument, L"--manifest-sha256") == 0 && has_value) {
            options->manifest_sha256 = argv[++index];
        } else if (wcscmp(argument, L"--manifest-public-key") == 0 && has_value) {
            if (options->manifest_public_key_count >= AC_MANIFEST_ENVELOPE_MAX_KEYS ||
                !ac_wide_hex_bytes(
                    argv[++index],
                    options->manifest_public_keys[options->manifest_public_key_count],
                    AC_ED25519_PUBLIC_KEY_SIZE)) {
                return false;
            }
            ++options->manifest_public_key_count;
        } else if (wcscmp(argument, L"--manifest-min-sequence") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 1u, 9223372036854775807ull, &number)) {
                return false;
            }
            options->manifest_min_sequence = number;
            options->manifest_min_sequence_set = true;
        } else if (wcscmp(argument, L"--require-manifest") == 0) {
            options->require_manifest = true;
        } else if (wcscmp(argument, L"--attestation-challenge") == 0 &&
                   has_value) {
            options->attestation_challenge = argv[++index];
        } else if (wcscmp(argument, L"--attestation-nonce") == 0 &&
                   has_value) {
            options->attestation_nonce = argv[++index];
        } else if (wcscmp(argument, L"--attestation-session") == 0 &&
                   has_value) {
            options->attestation_session = argv[++index];
        } else if (wcscmp(argument, L"--require-attestation") == 0) {
            options->require_attestation = true;
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
            options->interval_min_ms = (DWORD)(number - number / 5u);
            options->interval_max_ms = (DWORD)(number + number / 5u);
            if (options->interval_min_ms < 1000u) {
                options->interval_min_ms = 1000u;
            }
            if (options->interval_max_ms > 3600000u) {
                options->interval_max_ms = 3600000u;
            }
        } else if (wcscmp(argument, L"--interval-min-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 1000u, 3600000u, &number)) {
                return false;
            }
            options->interval_min_ms = (DWORD)number;
        } else if (wcscmp(argument, L"--interval-max-ms") == 0 && has_value) {
            if (!ac_parse_u64(argv[++index], 1000u, 3600000u, &number)) {
                return false;
            }
            options->interval_max_ms = (DWORD)number;
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

    if (options->interval_min_ms > options->interval_max_ms ||
        (options->manifest_path == NULL) !=
            (options->manifest_sha256 == NULL &&
             options->manifest_public_key_count == 0) ||
        (options->manifest_min_sequence_set &&
         options->manifest_public_key_count == 0) ||
        (options->require_manifest && options->manifest_path == NULL) ||
        (options->attestation_challenge == NULL) !=
            (options->attestation_nonce == NULL) ||
        (options->attestation_challenge == NULL) !=
            (options->attestation_session == NULL) ||
        (options->require_attestation &&
         options->attestation_challenge == NULL) ||
        (options->attestation_challenge != NULL &&
         (!ac_wide_hex_length(
              options->attestation_challenge,
              AC_ATTESTATION_CHALLENGE_HEX_SIZE - 1u) ||
          !ac_wide_hex_length(
              options->attestation_nonce,
              AC_SHA256_HEX_SIZE - 1u) ||
          !ac_wide_hex_length(options->attestation_session, 32u)))) {
        return false;
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

static void ac_log_collector_identity(AcLogger *logger)
{
    wchar_t path[MAX_PATH];
    char path_utf8[MAX_PATH * 3];
    char escaped_path[MAX_PATH * 6];
    char digest[AC_SHA256_HEX_SIZE];
    char details[MAX_PATH * 6 + 256];
    uint64_t file_size = 0;
    const DWORD length = GetModuleFileNameW(
        NULL,
        path,
        (DWORD)(sizeof(path) / sizeof(path[0])));

    if (length == 0 ||
        length >= (DWORD)(sizeof(path) / sizeof(path[0])) ||
        !ac_hash_file(path, digest, &file_size) ||
        !ac_wide_to_utf8(path, path_utf8, sizeof(path_utf8))) {
        ac_log_event(
            logger,
            AC_SEVERITY_MEDIUM,
            "collector_identity_unavailable",
            GetCurrentProcessId(),
            "{\"reason\":\"collector_file_unreadable\"}");
        return;
    }

    (void)ac_json_escape(path_utf8, escaped_path, sizeof(escaped_path));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"path\":\"%s\",\"file_sha256\":\"%s\",\"file_size\":%" PRIu64
        ",\"reason\":\"collector_identity_observed\"}",
        escaped_path,
        digest,
        file_size);
    ac_log_event(
        logger,
        AC_SEVERITY_INFO,
        "collector_identity_observed",
        GetCurrentProcessId(),
        details);
}

int wmain(int argc, wchar_t **argv)
{
    AcOptions *options;
    AcLogger logger;
    AcContext *context = NULL;
    AcKernelClient *kernel_client = NULL;
    AcThreatSensor *threat_sensor = NULL;
    AcPolicy *policy = NULL;
    AcManifest manifest;
    AcCollectorAttestation attestation;
    AcRuntimeKernelPosture runtime_kernel_posture;
    AcTarget target;
    const wchar_t *roots[AC_MAX_ALLOW_ROOTS];
    wchar_t windows_directory[MAX_PATH];
    wchar_t program_files[MAX_PATH];
    wchar_t program_files_x86[MAX_PATH];
    char details[1024];
    uint64_t scan_id = 0;
    uint64_t kernel_events = 0;
    uint64_t kernel_events_dropped = 0;
    uint64_t kernel_sequence_events_missing = 0;
    uint64_t kernel_module_mismatches = 0;
    uint64_t threat_indicators_observed = 0;
    uint64_t threat_overlay_candidates = 0;
    uint64_t threat_events_emitted = 0;
    size_t root_count = 0;
    size_t root_index;
    bool exit_now = false;
    bool context_ready = false;
    bool kernel_ready = false;
    bool threat_sensor_ready = false;
    bool kernel_telemetry_complete = true;
    bool manifest_ready = false;
    bool attestation_complete = false;
    bool schedule_random_failure_reported = false;
    int exit_code = AC_EXIT_INTERNAL;

    options = (AcOptions *)calloc(1u, sizeof(*options));
    if (options == NULL) {
        return AC_EXIT_INTERNAL;
    }
    memset(&target, 0, sizeof(target));
    ac_manifest_init(&manifest);
    memset(&runtime_kernel_posture, 0, sizeof(runtime_kernel_posture));

    if (!ac_parse_options(argc, argv, options, &exit_now)) {
        ac_print_usage(argv[0]);
        free(options);
        return AC_EXIT_USAGE;
    }
    if (exit_now) {
        free(options);
        return AC_EXIT_OK;
    }

    if (!ac_logger_open(
            &logger,
            options->log_path,
            !options->quiet,
            options->max_log_bytes,
            options->log_generations)) {
        fwprintf(stderr, L"Cannot open log file: %ls\n", options->log_path);
        free(options);
        return AC_EXIT_LOG_FAILURE;
    }

    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL) {
        ac_log_win32_error(&logger, "create_stop_event_failed", 0, GetLastError());
        ac_logger_close(&logger);
        free(options);
        return AC_EXIT_INTERNAL;
    }
    (void)SetConsoleCtrlHandler(ac_console_handler, TRUE);

    context = (AcContext *)calloc(1u, sizeof(*context));
    kernel_client = (AcKernelClient *)calloc(1u, sizeof(*kernel_client));
    threat_sensor = (AcThreatSensor *)calloc(1u, sizeof(*threat_sensor));
    policy = (AcPolicy *)calloc(1u, sizeof(*policy));
    if (context == NULL || kernel_client == NULL || threat_sensor == NULL ||
        policy == NULL) {
        ac_log_event(
            &logger,
            AC_SEVERITY_HIGH,
            "runtime_state_allocation_failed",
            0,
            "{\"reason\":\"out_of_memory\"}");
        free(context);
        free(kernel_client);
        free(threat_sensor);
        free(policy);
        CloseHandle(g_stop_event);
        g_stop_event = NULL;
        ac_logger_close(&logger);
        free(options);
        return AC_EXIT_INTERNAL;
    }
    ac_kernel_client_init(kernel_client);

    (void)snprintf(
        details,
        sizeof(details),
        "{\"agent\":\"%s\",\"version\":\"%s\",\"schema\":%u,\"mode\":\"%s\","
        "\"memory_write_access\":false,\"terminates_target\":false,"
        "\"interval_ms\":%lu,\"interval_min_ms\":%lu,"
        "\"interval_max_ms\":%lu,\"once\":%s,\"scan_budget_ms\":%" PRIu64 ","
        "\"repeat_interval_ms\":%" PRIu64 ",\"pointer_bits\":%zu}",
        AC_AGENT_NAME,
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION,
        options->kernel_telemetry
            ? "hybrid_kernel_user_telemetry"
            : "user_telemetry",
        (unsigned long)options->interval_ms,
        (unsigned long)options->interval_min_ms,
        (unsigned long)options->interval_max_ms,
        options->once ? "true" : "false",
        options->scan_budget_ms,
        options->repeat_interval_ms,
        sizeof(void *) * 8u);
    ac_log_event(&logger, AC_SEVERITY_INFO, "agent_started", 0, details);
    ac_log_collector_identity(&logger);

    if (options->attestation_challenge != NULL) {
        if (!ac_collector_attest(
                options->attestation_challenge,
                options->attestation_nonce,
                options->attestation_session,
                &attestation)) {
            ac_log_win32_error_severity(
                &logger,
                AC_SEVERITY_HIGH,
                "collector_attestation_failed",
                0,
                GetLastError());
            if (options->require_attestation) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else {
            ac_log_collector_attestation(&logger, 0, 0, &attestation);
            attestation_complete = attestation.mapped_matches_disk;
            if (!attestation_complete && options->require_attestation) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        }
    } else {
        ac_log_event(
            &logger,
            AC_SEVERITY_MEDIUM,
            "collector_attestation_unavailable",
            0,
            "{\"reason\":\"server_challenge_not_supplied\","
            "\"freshness_proof\":false}");
    }

    if (options->manifest_path != NULL &&
        options->manifest_public_key_count != 0) {
        AcManifestTrust trust;

        trust.expected_sha256 = options->manifest_sha256;
        trust.public_keys =
            (const uint8_t (*)[AC_ED25519_PUBLIC_KEY_SIZE])options->manifest_public_keys;
        trust.public_key_count = options->manifest_public_key_count;
        trust.minimum_sequence = options->manifest_min_sequence;
        trust.now_unix = (uint64_t)_time64(NULL);
        if (!ac_manifest_load_signed(&manifest, options->manifest_path, &trust)) {
            char rejection_details[192];
            (void)snprintf(
                rejection_details,
                sizeof(rejection_details),
                "{\"reason\":\"%s\",\"manifest_format\":\"ac-manifest-v2\","
                "\"minimum_sequence\":%" PRIu64 ",\"trusted_keys\":%zu}",
                manifest.rejection_reason != NULL
                    ? manifest.rejection_reason : "unknown",
                options->manifest_min_sequence,
                options->manifest_public_key_count);
            ac_log_event(
                &logger,
                AC_SEVERITY_HIGH,
                "trusted_manifest_rejected",
                0,
                rejection_details);
            if (options->require_manifest) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else {
            char manifest_details[512];
            manifest_ready = true;
            (void)snprintf(
                manifest_details,
                sizeof(manifest_details),
                "{\"manifest_sha256\":\"%s\",\"entries\":%zu,"
                "\"trust_source\":\"%s\","
                "\"manifest_format\":\"ac-manifest-v2\","
                "\"application\":\"%s\",\"build_id\":\"%s\","
                "\"sequence\":%" PRIu64 ",\"not_before\":%" PRIu64 ","
                "\"not_after\":%" PRIu64 ",\"key_id\":\"%s\","
                "\"minimum_sequence\":%" PRIu64 "}",
                manifest.file_sha256,
                manifest.count,
                options->manifest_sha256 != NULL
                    ? "offline_signature_and_hash_pin" : "offline_signature",
                manifest.envelope.application,
                manifest.envelope.build_id,
                manifest.envelope.sequence,
                manifest.envelope.not_before,
                manifest.envelope.not_after,
                manifest.envelope.key_id,
                options->manifest_min_sequence);
            ac_log_event(
                &logger,
                AC_SEVERITY_INFO,
                "trusted_manifest_loaded",
                0,
                manifest_details);
        }
    } else if (options->manifest_path != NULL) {
        if (!ac_manifest_load_pinned(
                &manifest,
                options->manifest_path,
                options->manifest_sha256)) {
            ac_log_win32_error_severity(
                &logger,
                AC_SEVERITY_HIGH,
                "trusted_manifest_rejected",
                0,
                GetLastError());
            if (options->require_manifest) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else {
            char manifest_details[256];
            manifest_ready = true;
            (void)snprintf(
                manifest_details,
                sizeof(manifest_details),
                "{\"manifest_sha256\":\"%s\",\"entries\":%zu,"
                "\"trust_source\":\"control_plane_hash_pin\","
                "\"manifest_format\":\"ac-manifest-v1\"}",
                manifest.file_sha256,
                manifest.count);
            ac_log_event(
                &logger,
                AC_SEVERITY_INFO,
                "trusted_manifest_loaded",
                0,
                manifest_details);
        }
    } else {
        ac_log_event(
            &logger,
            AC_SEVERITY_MEDIUM,
            "trusted_manifest_unavailable",
            0,
            "{\"module_authorization\":false,"
            "\"driver_authorization\":false,"
            "\"required_action\":\"supply_control_plane_pin\"}");
    }

    if (!ac_query_runtime_kernel_posture(&runtime_kernel_posture)) {
        runtime_kernel_posture.query_complete = false;
    }
    ac_log_runtime_kernel_posture(&logger, 0, &runtime_kernel_posture);
    if (options->require_secure_kernel &&
        !ac_runtime_kernel_posture_secure(&runtime_kernel_posture)) {
        ac_log_event(
            &logger,
            AC_SEVERITY_HIGH,
            "secure_kernel_policy_rejected",
            0,
            "{\"required\":true,\"verdict\":\"fail_closed\"}");
        exit_code = AC_EXIT_ACCESS_DENIED;
        goto cleanup;
    }

    if (!ac_resolve_target_pid(options, &logger, &target.pid)) {
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

    if (options->process_name != NULL &&
        !ac_process_image_matches_name(target.image_path, options->process_name)) {
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
        options,
        target.directory,
        windows_directory,
        program_files,
        program_files_x86,
        roots);

    ac_policy_init_defaults(policy);
    policy->allow_root_count = root_count;
    for (root_index = 0; root_index < root_count; ++root_index) {
        policy->allow_roots[root_index] = roots[root_index];
    }
    policy->repeat_interval_ms = options->repeat_interval_ms;
    policy->scan_budget_ms = options->scan_budget_ms;
    policy->hash_unknown_modules = !options->skip_module_hashes;
    policy->probe_region_content = !options->skip_region_probe;
    policy->verify_module_integrity = !options->skip_module_integrity;
    policy->integrity_budget_bytes = options->integrity_budget_bytes;
    policy->integrity_max_file_bytes = options->integrity_max_file_bytes;
    policy->manifest = manifest_ready ? &manifest : NULL;
    policy->dispatch_watch_count = options->dispatch_watch_count;
    if (options->dispatch_watch_count > 0) {
        memcpy(
            policy->dispatch_watches,
            options->dispatch_watches,
            options->dispatch_watch_count * sizeof(options->dispatch_watches[0]));
    }

    if (!ac_context_init(context, &logger, policy)) {
        ac_log_event(
            &logger,
            AC_SEVERITY_LOW,
            "context_init_failed",
            target.pid,
            "{\"reason\":\"out_of_memory\"}");
        goto cleanup;
    }
    context_ready = true;

    if (!ac_threat_sensor_init(
            threat_sensor,
            options->repeat_interval_ms)) {
        ac_log_event(
            &logger,
            AC_SEVERITY_LOW,
            "threat_sensor_init_failed",
            target.pid,
            "{\"reason\":\"out_of_memory\",\"coverage_complete\":false}");
    } else {
        threat_sensor_ready = true;
        ac_threat_sensor_report_posture(
            threat_sensor,
            &logger,
            target.pid);
        ac_threat_sensor_report_driver_snapshot(
            threat_sensor,
            &logger,
            target.pid,
            manifest_ready ? &manifest : NULL);
        ac_threat_sensor_report_input_posture(
            threat_sensor,
            &logger,
            target.pid);
    }

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

    if (options->kernel_telemetry) {
        if (!ac_kernel_client_open(kernel_client)) {
            char kernel_error[128];
            const DWORD error = GetLastError();
            (void)snprintf(
                kernel_error,
                sizeof(kernel_error),
                "{\"win32_error\":%lu,\"reason\":\"required_sensor_unavailable\"}",
                (unsigned long)error);
            ac_log_event(
                &logger,
                options->require_kernel ? AC_SEVERITY_HIGH : AC_SEVERITY_MEDIUM,
                "kernel_driver_open_failed",
                target.pid,
                kernel_error);
            kernel_telemetry_complete = false;
            if (options->require_kernel) {
                exit_code = AC_EXIT_ACCESS_DENIED;
                goto cleanup;
            }
        } else if (!ac_kernel_client_set_target(
                       kernel_client,
                       target.pid)) {
            const DWORD error = GetLastError();
            char kernel_error[128];
            (void)snprintf(
                kernel_error,
                sizeof(kernel_error),
                "{\"win32_error\":%lu,\"reason\":\"session_registration_rejected\"}",
                (unsigned long)error);
            ac_log_event(
                &logger,
                AC_SEVERITY_HIGH,
                "kernel_target_registration_failed",
                target.pid,
                kernel_error);
            kernel_telemetry_complete = false;
            ac_kernel_client_close(kernel_client);
            if (options->require_kernel) {
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
                kernel_client->version.protocol_version,
                kernel_client->version.event_size,
                kernel_client->version.queue_capacity,
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
        AcThreatScanStats threat_stats;
        HANDLE wait_handles[2];
        DWORD wait_result;
        bool scan_succeeded;

        if (ac_stop_requested()) {
            exit_code = AC_EXIT_OK;
            break;
        }

        if (kernel_ready &&
            !ac_kernel_client_drain(
                kernel_client,
                &logger,
                target.pid,
                &kernel_events)) {
            kernel_telemetry_complete = false;
            kernel_events_dropped = kernel_client->last_dropped;
            kernel_sequence_events_missing =
                kernel_client->sequence_events_missing;
            ac_log_win32_error_severity(
                &logger,
                AC_SEVERITY_HIGH,
                "kernel_event_read_failed",
                target.pid,
                GetLastError());
            ac_kernel_client_close(kernel_client);
            kernel_ready = false;
            if (options->require_kernel) {
                exit_code = AC_EXIT_INTERNAL;
                break;
            }
        } else if (kernel_ready) {
            kernel_events_dropped = kernel_client->last_dropped;
            kernel_sequence_events_missing =
                kernel_client->sequence_events_missing;
            kernel_telemetry_complete =
                kernel_telemetry_complete &&
                kernel_client->telemetry_complete;
        }

        ++scan_id;
        scan_succeeded = ac_scan_process(
            context,
            &target,
            scan_id,
            &stats);
        if (!scan_succeeded) {
            const DWORD error = GetLastError();

            if (WaitForSingleObject(target.process, 0) == WAIT_OBJECT_0) {
                ac_log_event(&logger, AC_SEVERITY_INFO, "target_exited", target.pid, "{}");
                exit_code = AC_EXIT_OK;
                break;
            }
            ac_log_win32_error(&logger, "scan_failed", target.pid, error);
        }

        if (options->attestation_challenge != NULL) {
            if (!ac_collector_attest(
                    options->attestation_challenge,
                    options->attestation_nonce,
                    options->attestation_session,
                    &attestation)) {
                attestation_complete = false;
                ac_log_win32_error_severity(
                    &logger,
                    AC_SEVERITY_HIGH,
                    "collector_attestation_failed",
                    target.pid,
                    GetLastError());
                if (options->require_attestation) {
                    exit_code = AC_EXIT_INTERNAL;
                    break;
                }
            } else {
                ac_log_collector_attestation(
                    &logger,
                    target.pid,
                    scan_id,
                    &attestation);
                attestation_complete =
                    attestation_complete &&
                    attestation.mapped_matches_disk;
                if (!attestation.mapped_matches_disk &&
                    options->require_attestation) {
                    exit_code = AC_EXIT_ACCESS_DENIED;
                    break;
                }
            }
        }

        if (threat_sensor_ready) {
            ac_threat_sensor_scan(
                threat_sensor,
                &logger,
                target.pid,
                scan_id,
                &context->module_ranges,
                &threat_stats);
            threat_indicators_observed += threat_stats.indicators_observed;
            threat_overlay_candidates += threat_stats.overlay_candidates;
            threat_events_emitted += threat_stats.events_emitted;
        }

        if (kernel_ready &&
            !ac_kernel_client_drain(
                kernel_client,
                &logger,
                target.pid,
                &kernel_events)) {
            kernel_telemetry_complete = false;
            kernel_events_dropped = kernel_client->last_dropped;
            kernel_sequence_events_missing =
                kernel_client->sequence_events_missing;
            ac_log_win32_error_severity(
                &logger,
                AC_SEVERITY_HIGH,
                "kernel_event_read_failed",
                target.pid,
                GetLastError());
            ac_kernel_client_close(kernel_client);
            kernel_ready = false;
            if (options->require_kernel) {
                exit_code = AC_EXIT_INTERNAL;
                break;
            }
        } else if (kernel_ready) {
            kernel_events_dropped = kernel_client->last_dropped;
            kernel_sequence_events_missing =
                kernel_client->sequence_events_missing;
            if (scan_succeeded) {
                ac_kernel_client_correlate_scan(
                    kernel_client,
                    &logger,
                    target.pid,
                    scan_id,
                    &context->module_ranges,
                    &kernel_module_mismatches);
            }
            kernel_telemetry_complete =
                kernel_telemetry_complete &&
                kernel_client->telemetry_complete;
        }

        if (options->once) {
            exit_code = AC_EXIT_OK;
            break;
        }

        {
            bool schedule_random_available = false;
            const DWORD scan_delay = ac_randomized_interval(
                options->interval_min_ms,
                options->interval_max_ms,
                &schedule_random_available);
            const ULONGLONG deadline =
                GetTickCount64() + scan_delay;
            bool next_scan = false;

            if (!schedule_random_available &&
                !schedule_random_failure_reported) {
                ac_log_event(
                    &logger,
                    AC_SEVERITY_HIGH,
                    "scan_schedule_random_source_unavailable",
                    target.pid,
                    "{\"fallback\":\"minimum_interval\","
                    "\"fails_early\":true}");
                schedule_random_failure_reported = true;
            }

            wait_handles[0] = target.process;
            wait_handles[1] = g_stop_event;
            for (;;) {
                const ULONGLONG now = GetTickCount64();
                const ULONGLONG remaining = now < deadline ? deadline - now : 0;
                const DWORD wait_slice =
                    remaining > 250u ? 250u : (DWORD)remaining;

                if (remaining == 0) {
                    next_scan = true;
                    wait_result = WAIT_TIMEOUT;
                    break;
                }

                wait_result = WaitForMultipleObjects(
                    2u,
                    wait_handles,
                    FALSE,
                    wait_slice);
                if (wait_result != WAIT_TIMEOUT) {
                    break;
                }

                if (kernel_ready &&
                    !ac_kernel_client_drain(
                        kernel_client,
                        &logger,
                        target.pid,
                        &kernel_events)) {
                    kernel_telemetry_complete = false;
                    kernel_events_dropped = kernel_client->last_dropped;
                    kernel_sequence_events_missing =
                        kernel_client->sequence_events_missing;
                    ac_log_win32_error_severity(
                        &logger,
                        AC_SEVERITY_HIGH,
                        "kernel_event_read_failed",
                        target.pid,
                        GetLastError());
                    ac_kernel_client_close(kernel_client);
                    kernel_ready = false;
                    if (options->require_kernel) {
                        exit_code = AC_EXIT_INTERNAL;
                        goto cleanup;
                    }
                } else if (kernel_ready) {
                    kernel_events_dropped = kernel_client->last_dropped;
                    kernel_sequence_events_missing =
                        kernel_client->sequence_events_missing;
                    kernel_telemetry_complete =
                        kernel_telemetry_complete &&
                        kernel_client->telemetry_complete;
                }
            }

            if (next_scan) {
                continue;
            }
        }

        if (wait_result == WAIT_OBJECT_0) {
            if (kernel_ready) {
                if (ac_kernel_client_drain(
                        kernel_client,
                        &logger,
                        target.pid,
                        &kernel_events)) {
                    kernel_events_dropped = kernel_client->last_dropped;
                    kernel_sequence_events_missing =
                        kernel_client->sequence_events_missing;
                    kernel_telemetry_complete =
                        kernel_telemetry_complete &&
                        kernel_client->telemetry_complete;
                } else {
                    kernel_telemetry_complete = false;
                    kernel_events_dropped = kernel_client->last_dropped;
                    kernel_sequence_events_missing =
                        kernel_client->sequence_events_missing;
                    ac_log_win32_error_severity(
                        &logger,
                        AC_SEVERITY_HIGH,
                        "kernel_event_read_failed",
                        target.pid,
                        GetLastError());
                }
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
            bool schedule_random_available = false;
            ac_log_win32_error(&logger, "wait_failed", target.pid, GetLastError());
            Sleep(ac_randomized_interval(
                options->interval_min_ms,
                options->interval_max_ms,
                &schedule_random_available));
            if (!schedule_random_available) {
                schedule_random_failure_reported = true;
            }
        }
    }

cleanup:
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scans\":%" PRIu64 ",\"terminated_target\":false,"
        "\"kernel_events\":%" PRIu64 ","
        "\"kernel_events_dropped\":%" PRIu64 ","
        "\"kernel_sequence_events_missing\":%" PRIu64 ","
        "\"kernel_module_mismatches\":%" PRIu64 ","
        "\"threat_indicators_observed\":%" PRIu64 ","
        "\"threat_overlay_candidates\":%" PRIu64 ","
        "\"threat_events_emitted\":%" PRIu64 ","
        "\"collector_attestation_complete\":%s,"
        "\"kernel_telemetry_complete\":%s,"
        "\"log_write_failures\":%" PRIu64 ",\"log_truncated_lines\":%" PRIu64 ","
        "\"exit_code\":%d}",
        scan_id,
        kernel_events,
        kernel_events_dropped,
        kernel_sequence_events_missing,
        kernel_module_mismatches,
        threat_indicators_observed,
        threat_overlay_candidates,
        threat_events_emitted,
        (options->attestation_challenge != NULL && attestation_complete)
            ? "true" : "false",
        (options->kernel_telemetry && kernel_telemetry_complete)
            ? "true"
            : "false",
        logger.write_failures,
        logger.truncated_lines,
        exit_code);
    ac_log_event(&logger, AC_SEVERITY_INFO, "agent_stopped", target.pid, details);

    if (context_ready) {
        ac_context_free(context);
    }
    if (threat_sensor_ready) {
        ac_threat_sensor_free(threat_sensor);
    }
    if (kernel_ready) {
        (void)ac_kernel_client_set_target(kernel_client, 0);
        ac_kernel_client_close(kernel_client);
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
    ac_manifest_free(&manifest);
    ac_logger_close(&logger);
    free(threat_sensor);
    free(kernel_client);
    free(context);
    free(policy);
    free(options);
    return exit_code;
}
