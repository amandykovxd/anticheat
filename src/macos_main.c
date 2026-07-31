#include "sha256.h"
#include "text.h"

#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <mach/vm_prot.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <time.h>
#include <unistd.h>

#define AC_AGENT_VERSION "0.3.0"
#define AC_SCHEMA_VERSION 5u
#define AC_DRIVER_PROTOCOL_VERSION 3u
#define AC_MAX_REGION_EVENTS 64u

typedef struct AcMacLogger {
    FILE *file;
    bool mirror;
    uint64_t sequence;
    uint8_t chain[AC_SHA256_DIGEST_SIZE];
} AcMacLogger;

typedef struct AcMacOptions {
    const char *process_name;
    const char *log_path;
    pid_t pid;
    unsigned int interval_ms;
    bool self;
    bool once;
    bool quiet;
} AcMacOptions;

typedef struct AcMacScanStats {
    uint64_t regions;
    uint64_t executable;
    uint64_t anonymous_executable;
    uint64_t writable_executable;
    uint64_t emitted;
} AcMacScanStats;

static volatile sig_atomic_t g_stop_requested = 0;

static void ac_signal_handler(int signal_number)
{
    (void)signal_number;
    g_stop_requested = 1;
}

static void ac_print_version(void)
{
    printf(
        "collector_version=%s\n"
        "event_schema_version=%u\n"
        "driver_protocol_version=%u\n",
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION,
        AC_DRIVER_PROTOCOL_VERSION);
}

static void ac_print_usage(const char *program)
{
    printf(
        "%s %s (macOS)\n\n"
        "Usage:\n"
        "  %s --pid <pid> [options]\n"
        "  %s --process <name> [options]\n\n"
        "Options:\n"
        "  --self               scan the collector process (diagnostics/tests)\n"
        "  --once               perform one scan and exit\n"
        "  --interval-ms <n>    scan period, 1000..3600000 (default 5000)\n"
        "  --log <file>         JSON Lines output (default anticheat-events.jsonl)\n"
        "  --quiet              do not mirror events to stdout\n"
        "  --version            print compatibility versions and exit\n"
        "  --help               print this help and exit\n\n"
        "macOS does not support --kernel or --require-kernel.\n",
        program,
        AC_AGENT_VERSION,
        program,
        program);
}

static bool ac_parse_u32(
    const char *text,
    uint32_t minimum,
    uint32_t maximum,
    uint32_t *value_out)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || value_out == NULL || text[0] == '\0') {
        return false;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < minimum || value > maximum) {
        return false;
    }
    *value_out = (uint32_t)value;
    return true;
}

static bool ac_parse_options(
    int argc,
    char **argv,
    AcMacOptions *options,
    bool *exit_now)
{
    int index;

    memset(options, 0, sizeof(*options));
    options->interval_ms = 5000u;
    options->log_path = "anticheat-events.jsonl";
    *exit_now = false;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        ac_print_version();
        *exit_now = true;
        return true;
    }
    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        ac_print_usage(argv[0]);
        *exit_now = true;
        return true;
    }

    for (index = 1; index < argc; ++index) {
        const char *argument = argv[index];
        const bool has_value = index + 1 < argc;
        uint32_t number = 0;

        if (strcmp(argument, "--once") == 0) {
            options->once = true;
        } else if (strcmp(argument, "--self") == 0) {
            options->self = true;
        } else if (strcmp(argument, "--quiet") == 0) {
            options->quiet = true;
        } else if (strcmp(argument, "--pid") == 0 && has_value) {
            if (!ac_parse_u32(argv[++index], 1u, INT32_MAX, &number)) {
                return false;
            }
            options->pid = (pid_t)number;
        } else if (strcmp(argument, "--process") == 0 && has_value) {
            options->process_name = argv[++index];
        } else if (strcmp(argument, "--interval-ms") == 0 && has_value) {
            if (!ac_parse_u32(argv[++index], 1000u, 3600000u, &number)) {
                return false;
            }
            options->interval_ms = number;
        } else if (strcmp(argument, "--log") == 0 && has_value) {
            options->log_path = argv[++index];
        } else {
            return false;
        }
    }

    return (unsigned int)(options->pid > 0) +
               (unsigned int)(options->process_name != NULL) +
               (unsigned int)options->self ==
           1u;
}

static void ac_bytes_to_hex(const uint8_t *bytes, size_t count, char *output)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < count; ++index) {
        output[index * 2u] = digits[bytes[index] >> 4u];
        output[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
    }
    output[count * 2u] = '\0';
}

static void ac_logger_emit(
    AcMacLogger *logger,
    const char *severity,
    const char *event,
    pid_t pid,
    const char *details)
{
    struct timespec now;
    struct tm utc;
    AcSha256 hash;
    uint8_t next_chain[AC_SHA256_DIGEST_SIZE];
    char event_escaped[256];
    char body[16384];
    char line[16512];
    char chain_hex[AC_SHA256_HEX_SIZE];
    int body_length;
    int line_length;

    (void)clock_gettime(CLOCK_REALTIME, &now);
    (void)gmtime_r(&now.tv_sec, &utc);
    (void)ac_json_escape(event, event_escaped, sizeof(event_escaped));

    ++logger->sequence;
    body_length = snprintf(
        body,
        sizeof(body),
        "{\"seq\":%" PRIu64
        ",\"timestamp\":\"%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ\","
        "\"severity\":\"%s\",\"event\":\"%s\",\"pid\":%d,\"details\":%s",
        logger->sequence,
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        now.tv_nsec / 1000000L,
        severity,
        event_escaped,
        (int)pid,
        details != NULL ? details : "{}");
    if (body_length < 0 || (size_t)body_length >= sizeof(body)) {
        return;
    }

    ac_sha256_init(&hash);
    ac_sha256_update(&hash, logger->chain, sizeof(logger->chain));
    ac_sha256_update(&hash, body, (size_t)body_length);
    ac_sha256_final(&hash, next_chain);
    ac_bytes_to_hex(next_chain, sizeof(next_chain), chain_hex);
    memcpy(logger->chain, next_chain, sizeof(logger->chain));

    line_length = snprintf(
        line,
        sizeof(line),
        "%s,\"chain\":\"%s\"}",
        body,
        chain_hex);
    if (line_length < 0 || (size_t)line_length >= sizeof(line)) {
        return;
    }

    if (logger->file != NULL) {
        (void)fprintf(logger->file, "%s\n", line);
        (void)fflush(logger->file);
    }
    if (logger->mirror) {
        puts(line);
    }
}

static bool ac_logger_open(AcMacLogger *logger, const char *path, bool mirror)
{
    struct timespec now;
    AcSha256 hash;
    char seed_hex[AC_SHA256_HEX_SIZE];
    char details[256];
    const pid_t pid = getpid();

    memset(logger, 0, sizeof(*logger));
    logger->file = fopen(path, "ab");
    if (logger->file == NULL) {
        return false;
    }
    logger->mirror = mirror;
    (void)clock_gettime(CLOCK_REALTIME, &now);
    ac_sha256_init(&hash);
    ac_sha256_update(&hash, "ac-log-chain-v1", 15u);
    ac_sha256_update(&hash, &now, sizeof(now));
    ac_sha256_update(&hash, &pid, sizeof(pid));
    ac_sha256_update(&hash, path, strlen(path));
    ac_sha256_final(&hash, logger->chain);
    ac_bytes_to_hex(logger->chain, sizeof(logger->chain), seed_hex);
    (void)snprintf(
        details,
        sizeof(details),
        "{\"schema\":%u,\"chain_seed\":\"%s\",\"platform\":\"macos\"}",
        AC_SCHEMA_VERSION,
        seed_hex);
    ac_logger_emit(logger, "info", "log_segment_opened", 0, details);
    return true;
}

static bool ac_process_path(pid_t pid, char path[PROC_PIDPATHINFO_MAXSIZE])
{
    const int length =
        proc_pidpath(pid, path, (uint32_t)PROC_PIDPATHINFO_MAXSIZE);

    if (length <= 0) {
        path[0] = '\0';
        return false;
    }
    path[PROC_PIDPATHINFO_MAXSIZE - 1u] = '\0';
    return true;
}

static bool ac_find_process(const char *name, pid_t *pid_out, size_t *matches_out)
{
    int required = proc_listallpids(NULL, 0);
    pid_t *pids;
    int count;
    int index;
    size_t matches = 0;

    if (required <= 0 || name == NULL || pid_out == NULL) {
        return false;
    }
    pids = (pid_t *)calloc((size_t)required, sizeof(pid_t));
    if (pids == NULL) {
        return false;
    }
    count = proc_listallpids(pids, required * (int)sizeof(pid_t));
    for (index = 0; index < count; ++index) {
        char process_name[PROC_PIDPATHINFO_MAXSIZE];

        if (pids[index] <= 0 ||
            proc_name(pids[index], process_name, sizeof(process_name)) <= 0 ||
            strcmp(process_name, name) != 0) {
            continue;
        }
        if (matches == 0) {
            *pid_out = pids[index];
        }
        ++matches;
    }
    free(pids);
    if (matches_out != NULL) {
        *matches_out = matches;
    }
    return matches > 0;
}

static bool ac_scan_process(
    pid_t pid,
    AcMacLogger *logger,
    uint64_t scan_id,
    AcMacScanStats *stats)
{
    uint64_t address = 0;

    memset(stats, 0, sizeof(*stats));
    while (stats->regions < 65536u) {
        struct proc_regionwithpathinfo region;
        const struct proc_regioninfo *info = &region.prp_prinfo;
        int received;
        uint64_t next;

        memset(&region, 0, sizeof(region));
        received = proc_pidinfo(
            pid,
            PROC_PIDREGIONPATHINFO,
            address,
            &region,
            (int)sizeof(region));
        if (received != (int)sizeof(region)) {
            break;
        }
        if (info->pri_size == 0) {
            break;
        }
        ++stats->regions;
        if ((info->pri_protection & VM_PROT_EXECUTE) != 0) {
            const bool writable =
                (info->pri_protection & VM_PROT_WRITE) != 0;
            const bool anonymous = region.prp_vip.vip_path[0] == '\0';

            ++stats->executable;
            if (anonymous) {
                ++stats->anonymous_executable;
            }
            if (writable) {
                ++stats->writable_executable;
            }
            if ((anonymous || writable) &&
                stats->emitted < AC_MAX_REGION_EVENTS) {
                char path_escaped[PATH_MAX * 2u];
                char details[PATH_MAX * 2u + 384u];

                (void)ac_json_escape(
                    region.prp_vip.vip_path,
                    path_escaped,
                    sizeof(path_escaped));
                (void)snprintf(
                    details,
                    sizeof(details),
                    "{\"scan_id\":%" PRIu64
                    ",\"address\":\"0x%016" PRIx64 "\",\"size\":%" PRIu64
                    ",\"protection\":%u,\"anonymous\":%s,\"writable\":%s,"
                    "\"path\":\"%s\"}",
                    scan_id,
                    info->pri_address,
                    info->pri_size,
                    info->pri_protection,
                    anonymous ? "true" : "false",
                    writable ? "true" : "false",
                    path_escaped);
                ac_logger_emit(
                    logger,
                    writable ? "high" : "medium",
                    "executable_region_anomaly",
                    pid,
                    details);
                ++stats->emitted;
            }
        }

        next = info->pri_address + info->pri_size;
        if (next <= address) {
            break;
        }
        address = next;
    }
    return stats->regions > 0;
}

static void ac_sleep_ms(unsigned int milliseconds)
{
    struct timespec duration;

    duration.tv_sec = milliseconds / 1000u;
    duration.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
    while (!g_stop_requested && nanosleep(&duration, &duration) != 0 &&
           errno == EINTR) {
    }
}

int main(int argc, char **argv)
{
    AcMacOptions options;
    AcMacLogger logger;
    char image_path[PROC_PIDPATHINFO_MAXSIZE];
    char path_escaped[PROC_PIDPATHINFO_MAXSIZE * 2u];
    char details[PROC_PIDPATHINFO_MAXSIZE * 2u + 512u];
    struct proc_bsdinfo bsd;
    bool exit_now = false;
    uint64_t scan_id = 0;
    size_t matches = 0;

    if (!ac_parse_options(argc, argv, &options, &exit_now)) {
        ac_print_usage(argv[0]);
        return 2;
    }
    if (exit_now) {
        return 0;
    }
    if (options.process_name != NULL &&
        !ac_find_process(options.process_name, &options.pid, &matches)) {
        fprintf(stderr, "Target process not found: %s\n", options.process_name);
        return 4;
    }
    if (options.self) {
        options.pid = getpid();
        matches = 1u;
    }
    if (!ac_process_path(options.pid, image_path)) {
        fprintf(stderr, "Cannot query process %d: %s\n", options.pid, strerror(errno));
        return 5;
    }
    if (!ac_logger_open(&logger, options.log_path, !options.quiet)) {
        fprintf(stderr, "Cannot open log file: %s\n", options.log_path);
        return 3;
    }

    (void)signal(SIGINT, ac_signal_handler);
    (void)signal(SIGTERM, ac_signal_handler);
    (void)ac_json_escape(image_path, path_escaped, sizeof(path_escaped));
    memset(&bsd, 0, sizeof(bsd));
    (void)proc_pidinfo(
        options.pid,
        PROC_PIDTBSDINFO,
        0,
        &bsd,
        (int)sizeof(bsd));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"agent\":\"anticheat-collector\",\"version\":\"%s\","
        "\"schema\":%u,\"platform\":\"macos\",\"mode\":\"user_telemetry\","
        "\"memory_read\":false,\"memory_write\":false,\"kernel\":false}",
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION);
    ac_logger_emit(&logger, "info", "agent_started", 0, details);
    (void)snprintf(
        details,
        sizeof(details),
        "{\"path\":\"%s\",\"start_time_sec\":%" PRIu64
        ",\"matches\":%zu,\"metadata_api\":\"libproc\"}",
        path_escaped,
        bsd.pbi_start_tvsec,
        matches);
    ac_logger_emit(&logger, "info", "target_opened", options.pid, details);

    while (!g_stop_requested) {
        AcMacScanStats stats;
        const bool ok =
            ac_scan_process(options.pid, &logger, ++scan_id, &stats);

        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"regions\":%" PRIu64
            ",\"executable\":%" PRIu64 ",\"anonymous_executable\":%" PRIu64
            ",\"writable_executable\":%" PRIu64 ",\"emitted\":%" PRIu64
            ",\"complete\":%s}",
            scan_id,
            stats.regions,
            stats.executable,
            stats.anonymous_executable,
            stats.writable_executable,
            stats.emitted,
            ok ? "true" : "false");
        ac_logger_emit(
            &logger,
            ok ? "info" : "low",
            "scan_completed",
            options.pid,
            details);
        if (options.once) {
            break;
        }
        if (kill(options.pid, 0) != 0 && errno == ESRCH) {
            ac_logger_emit(&logger, "info", "target_exited", options.pid, "{}");
            break;
        }
        ac_sleep_ms(options.interval_ms);
    }

    (void)snprintf(
        details,
        sizeof(details),
        "{\"scans\":%" PRIu64 ",\"terminated_target\":false,\"exit_code\":0}",
        scan_id);
    ac_logger_emit(&logger, "info", "agent_stopped", options.pid, details);
    (void)fclose(logger.file);
    return 0;
}
