#define _POSIX_C_SOURCE 200809L

#include "sha256.h"
#include "text.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define AC_LINUX_VERSION "0.4.0"
#define AC_LINUX_SCHEMA 5u
#define AC_LINUX_MAX_FDS 32768u
#define AC_LINUX_JSON_PATH_CAPACITY (PATH_MAX * 6u + 1u)
#define AC_LINUX_LOG_BODY_CAPACITY 32768u

typedef struct AcLinuxLogger {
    FILE *file;
    bool mirror;
    uint64_t sequence;
    uint8_t chain[AC_SHA256_DIGEST_SIZE];
} AcLinuxLogger;

typedef struct AcLinuxOptions {
    const char *process_name;
    const char *log_path;
    const char *audit_log_path;
    pid_t pid;
    unsigned int interval_ms;
    bool once;
    bool self;
    bool quiet;
    bool require_kernel_audit;
} AcLinuxOptions;

typedef struct AcLinuxAuditSensor {
    FILE *file;
    const char *path;
    dev_t device;
    ino_t inode;
    bool available;
} AcLinuxAuditSensor;

static volatile sig_atomic_t g_stop;

static void ac_linux_signal(int signal_number)
{
    (void)signal_number;
    g_stop = 1;
}

static bool ac_linux_numeric(const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    if (text == NULL || *text == '\0') {
        return false;
    }
    while (*cursor != '\0') {
        if (!isdigit(*cursor)) {
            return false;
        }
        ++cursor;
    }
    return true;
}

static bool ac_linux_parse_pid(const char *text, pid_t *pid_out)
{
    char *end = NULL;
    long value;

    if (!ac_linux_numeric(text)) {
        return false;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value <= 0 || value > INT_MAX) {
        return false;
    }
    *pid_out = (pid_t)value;
    return true;
}

static void ac_linux_usage(const char *program)
{
    printf(
        "%s %s (Linux)\n\n"
        "Usage:\n"
        "  %s --pid <pid> [options]\n"
        "  %s --process <name> [options]\n"
        "  %s --self [options]\n\n"
        "Options:\n"
        "  --once               perform one scan and exit\n"
        "  --interval-ms <n>    scan period, 1000..3600000 (default 5000)\n"
        "  --log <file>         JSON Lines output\n"
        "  --audit-log <file>   consume auditd SYSCALL records tagged "
        "anticheat_process_vm\n"
        "  --require-kernel-audit\n"
        "                       fail closed when the audit stream is unavailable\n"
        "  --quiet              do not mirror events to stdout\n"
        "  --version            print version information\n"
        "  --help               print this help\n",
        program,
        AC_LINUX_VERSION,
        program,
        program,
        program);
}

static bool ac_linux_parse_options(
    int argc,
    char **argv,
    AcLinuxOptions *options,
    bool *exit_now)
{
    int index;

    memset(options, 0, sizeof(*options));
    options->log_path = "anticheat-events.jsonl";
    options->interval_ms = 5000u;
    *exit_now = false;

    for (index = 1; index < argc; ++index) {
        const char *argument = argv[index];
        if (strcmp(argument, "--help") == 0) {
            ac_linux_usage(argv[0]);
            *exit_now = true;
            return true;
        }
        if (strcmp(argument, "--version") == 0) {
            printf(
                "collector_version=%s\nevent_schema_version=%u\n"
                "driver_protocol_version=unsupported\n",
                AC_LINUX_VERSION,
                AC_LINUX_SCHEMA);
            *exit_now = true;
            return true;
        }
        if (strcmp(argument, "--once") == 0) {
            options->once = true;
        } else if (strcmp(argument, "--self") == 0) {
            options->self = true;
            options->pid = getpid();
        } else if (strcmp(argument, "--quiet") == 0) {
            options->quiet = true;
        } else if (strcmp(argument, "--pid") == 0 && index + 1 < argc) {
            if (!ac_linux_parse_pid(argv[++index], &options->pid)) {
                return false;
            }
        } else if (strcmp(argument, "--process") == 0 && index + 1 < argc) {
            options->process_name = argv[++index];
        } else if (strcmp(argument, "--log") == 0 && index + 1 < argc) {
            options->log_path = argv[++index];
        } else if (strcmp(argument, "--audit-log") == 0 && index + 1 < argc) {
            options->audit_log_path = argv[++index];
        } else if (strcmp(argument, "--require-kernel-audit") == 0) {
            options->require_kernel_audit = true;
        } else if (strcmp(argument, "--interval-ms") == 0 &&
                   index + 1 < argc) {
            char *end = NULL;
            const unsigned long value = strtoul(argv[++index], &end, 10);
            if (end == argv[index] || *end != '\0' ||
                value < 1000u || value > 3600000u) {
                return false;
            }
            options->interval_ms = (unsigned int)value;
        } else {
            return false;
        }
    }

    return options->pid > 0 ||
           (options->process_name != NULL && options->process_name[0] != '\0');
}

static void ac_linux_seed_chain(AcLinuxLogger *logger, const char *path)
{
    AcSha256 hash;
    struct timespec now;
    const pid_t pid = getpid();

    (void)clock_gettime(CLOCK_REALTIME, &now);
    ac_sha256_init(&hash);
    ac_sha256_update(&hash, "ac-log-chain-v1", 15u);
    ac_sha256_update(&hash, &now, sizeof(now));
    ac_sha256_update(&hash, &pid, sizeof(pid));
    ac_sha256_update(&hash, path, strlen(path));
    ac_sha256_final(&hash, logger->chain);
}

static void ac_linux_log(
    AcLinuxLogger *logger,
    const char *severity,
    const char *event,
    pid_t pid,
    const char *details)
{
    struct timespec now;
    struct tm utc;
    AcSha256 hash;
    char body[AC_LINUX_LOG_BODY_CAPACITY];
    char line[AC_LINUX_LOG_BODY_CAPACITY + 256u];
    char escaped_event[256];
    char chain_hex[AC_SHA256_HEX_SIZE];
    int body_length;
    int line_length;

    (void)clock_gettime(CLOCK_REALTIME, &now);
    (void)gmtime_r(&now.tv_sec, &utc);
    (void)ac_json_escape(
        event,
        escaped_event,
        sizeof(escaped_event));
    ++logger->sequence;
    body_length = snprintf(
        body,
        sizeof(body),
        "{\"seq\":%" PRIu64
        ",\"timestamp\":\"%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ\","
        "\"severity\":\"%s\",\"event\":\"%s\",\"pid\":%ld,"
        "\"details\":%s",
        logger->sequence,
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        now.tv_nsec / 1000000L,
        severity,
        escaped_event,
        (long)pid,
        details != NULL ? details : "{}");
    if (body_length < 0 || (size_t)body_length >= sizeof(body)) {
        return;
    }
    ac_sha256_init(&hash);
    ac_sha256_update(&hash, logger->chain, sizeof(logger->chain));
    ac_sha256_update(&hash, body, (size_t)body_length);
    ac_sha256_final(&hash, logger->chain);
    ac_sha256_to_hex(logger->chain, chain_hex);
    line_length = snprintf(
        line,
        sizeof(line),
        "%s,\"chain\":\"%s\"}",
        body,
        chain_hex);
    if (line_length < 0 || (size_t)line_length >= sizeof(line)) {
        return;
    }
    (void)fprintf(logger->file, "%s\n", line);
    (void)fflush(logger->file);
    if (logger->mirror) {
        (void)printf("%s\n", line);
        (void)fflush(stdout);
    }
}

static bool ac_linux_logger_open(
    AcLinuxLogger *logger,
    const char *path,
    bool mirror)
{
    char seed[AC_SHA256_HEX_SIZE];
    char details[384];

    memset(logger, 0, sizeof(*logger));
    logger->file = fopen(path, "ab");
    if (logger->file == NULL) {
        return false;
    }
    logger->mirror = mirror;
    ac_linux_seed_chain(logger, path);
    ac_sha256_to_hex(logger->chain, seed);
    (void)snprintf(
        details,
        sizeof(details),
        "{\"agent\":\"anticheat-collector\",\"version\":\"%s\","
        "\"schema\":%u,\"chain_algorithm\":\"sha256\","
        "\"chain_seed\":\"%s\",\"platform\":\"linux\"}",
        AC_LINUX_VERSION,
        AC_LINUX_SCHEMA,
        seed);
    ac_linux_log(logger, "info", "log_segment_opened", 0, details);
    return true;
}

static bool ac_linux_read_exe(pid_t pid, char *path, size_t capacity)
{
    char link_path[64];
    ssize_t length;

    (void)snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", (long)pid);
    length = readlink(link_path, path, capacity - 1u);
    if (length < 0 || (size_t)length >= capacity) {
        return false;
    }
    path[length] = '\0';
    return true;
}

static pid_t ac_linux_find_process(const char *name)
{
    DIR *directory = opendir("/proc");
    struct dirent *entry;

    if (directory == NULL) {
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        pid_t pid;
        char path[PATH_MAX];
        const char *base;
        if (!ac_linux_parse_pid(entry->d_name, &pid) ||
            !ac_linux_read_exe(pid, path, sizeof(path))) {
            continue;
        }
        base = strrchr(path, '/');
        base = base != NULL ? base + 1u : path;
        if (strcmp(base, name) == 0) {
            (void)closedir(directory);
            return pid;
        }
    }
    (void)closedir(directory);
    return -1;
}

static unsigned long ac_linux_tracer_pid(pid_t target_pid)
{
    char path[64];
    char line[512];
    FILE *file;
    unsigned long tracer = 0;

    (void)snprintf(path, sizeof(path), "/proc/%ld/status", (long)target_pid);
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "TracerPid:%lu", &tracer) == 1) {
            break;
        }
    }
    (void)fclose(file);
    return tracer;
}

static void ac_linux_scan_maps(
    AcLinuxLogger *logger,
    pid_t target_pid,
    uint64_t scan_id,
    size_t *regions_out,
    size_t *suspicious_out)
{
    char path[64];
    char line[PATH_MAX + 256];
    FILE *file;

    (void)snprintf(path, sizeof(path), "/proc/%ld/maps", (long)target_pid);
    file = fopen(path, "rb");
    if (file == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long start;
        unsigned long long end;
        char permissions[5];
        int consumed = 0;
        const int fields = sscanf(
            line,
            "%llx-%llx %4s %*s %*s %*s %n",
            &start,
            &end,
            permissions,
            &consumed);
        char *mapping;
        bool anonymous;
        bool writable_executable;

        if (fields != 3 || end <= start) {
            continue;
        }
        ++*regions_out;
        if (permissions[2] != 'x') {
            continue;
        }
        mapping = line + consumed;
        while (*mapping == ' ' || *mapping == '\t') {
            ++mapping;
        }
        mapping[strcspn(mapping, "\r\n")] = '\0';
        anonymous = *mapping == '\0';
        writable_executable = permissions[1] == 'w';
        if (anonymous || writable_executable) {
            char mapping_escaped[AC_LINUX_JSON_PATH_CAPACITY];
            char details[AC_LINUX_JSON_PATH_CAPACITY + 512u];
            if (!ac_json_escape(
                    mapping,
                    mapping_escaped,
                    sizeof(mapping_escaped))) {
                (void)snprintf(
                    mapping_escaped,
                    sizeof(mapping_escaped),
                    "%s",
                    "<path-escape-truncated>");
            }
            (void)snprintf(
                details,
                sizeof(details),
                "{\"scan_id\":%" PRIu64
                ",\"start\":\"0x%llx\",\"end\":\"0x%llx\","
                "\"permissions\":\"%s\",\"mapping\":\"%s\","
                "\"anonymous\":%s,\"writable_executable\":%s}",
                scan_id,
                start,
                end,
                permissions,
                mapping_escaped,
                anonymous ? "true" : "false",
                writable_executable ? "true" : "false");
            ac_linux_log(
                logger,
                writable_executable ? "high" : "medium",
                "linux_suspicious_executable_mapping",
                target_pid,
                details);
            ++*suspicious_out;
        }
    }
    (void)fclose(file);
}

static void ac_linux_scan_foreign_fds(
    AcLinuxLogger *logger,
    pid_t target_pid,
    uint64_t scan_id,
    size_t *fds_visited,
    size_t *signals)
{
    DIR *processes = opendir("/proc");
    struct dirent *process_entry;
    char target_mem[64];

    if (processes == NULL) {
        return;
    }
    (void)snprintf(
        target_mem,
        sizeof(target_mem),
        "/proc/%ld/mem",
        (long)target_pid);
    while ((process_entry = readdir(processes)) != NULL &&
           *fds_visited < AC_LINUX_MAX_FDS) {
        pid_t owner_pid;
        char directory_path[64];
        DIR *fds;
        struct dirent *fd_entry;

        if (!ac_linux_parse_pid(process_entry->d_name, &owner_pid) ||
            owner_pid == target_pid || owner_pid == getpid()) {
            continue;
        }
        (void)snprintf(
            directory_path,
            sizeof(directory_path),
            "/proc/%ld/fd",
            (long)owner_pid);
        fds = opendir(directory_path);
        if (fds == NULL) {
            continue;
        }
        while ((fd_entry = readdir(fds)) != NULL &&
               *fds_visited < AC_LINUX_MAX_FDS) {
            char fd_path[PATH_MAX];
            char destination[PATH_MAX];
            ssize_t length;

            if (!ac_linux_numeric(fd_entry->d_name)) {
                continue;
            }
            ++*fds_visited;
            (void)snprintf(
                fd_path,
                sizeof(fd_path),
                "/proc/%ld/fd/%s",
                (long)owner_pid,
                fd_entry->d_name);
            length = readlink(fd_path, destination, sizeof(destination) - 1u);
            if (length < 0 || (size_t)length >= sizeof(destination)) {
                continue;
            }
            destination[length] = '\0';
            if (strcmp(destination, target_mem) == 0 ||
                strcmp(destination, "/dev/uinput") == 0 ||
                strcmp(destination, "/dev/input/uinput") == 0) {
                char details[512];
                const bool target_memory = strcmp(destination, target_mem) == 0;
                /*
                 * The comparisons above pin destination to one of three known
                 * paths, none longer than target_mem and none carrying a
                 * character JSON has to escape, so the explicit precision only
                 * states the bound the compiler cannot infer from readlink.
                 */
                (void)snprintf(
                    details,
                    sizeof(details),
                    "{\"scan_id\":%" PRIu64
                    ",\"owner_pid\":%ld,\"fd\":%s,\"destination\":\"%.63s\","
                    "\"reason\":\"%s\",\"verdict\":\"signal_only\"}",
                    scan_id,
                    (long)owner_pid,
                    fd_entry->d_name,
                    destination,
                    target_memory
                        ? "foreign_target_mem_handle"
                        : "virtual_input_device_handle");
                ac_linux_log(
                    logger,
                    target_memory ? "high" : "medium",
                    target_memory
                        ? "linux_foreign_target_mem_open"
                        : "linux_uinput_owner_observed",
                    target_pid,
                    details);
                ++*signals;
            }
        }
        (void)closedir(fds);
    }
    (void)closedir(processes);
}

static bool ac_linux_audit_value(
    const char *line,
    const char *name,
    char *value,
    size_t capacity)
{
    const size_t name_length = strlen(name);
    const char *cursor = line;
    const char *end;
    size_t length;

    if (capacity == 0u) {
        return false;
    }
    while ((cursor = strstr(cursor, name)) != NULL) {
        if ((cursor == line || cursor[-1] == ' ') &&
            cursor[name_length] == '=') {
            cursor += name_length + 1u;
            break;
        }
        cursor += name_length;
    }
    if (cursor == NULL) {
        return false;
    }
    if (*cursor == '"') {
        ++cursor;
        end = strchr(cursor, '"');
    } else {
        end = cursor + strcspn(cursor, " \t\r\n");
    }
    if (end == NULL) {
        return false;
    }
    length = (size_t)(end - cursor);
    if (length == 0u || length >= capacity) {
        return false;
    }
    memcpy(value, cursor, length);
    value[length] = '\0';
    return true;
}

static int ac_linux_audit_operation(const char *arch, const char *syscall_name)
{
    char *end = NULL;
    unsigned long number;

    if (strcmp(syscall_name, "process_vm_readv") == 0) {
        return 1;
    }
    if (strcmp(syscall_name, "process_vm_writev") == 0) {
        return 2;
    }
    errno = 0;
    number = strtoul(syscall_name, &end, 10);
    if (errno != 0 || end == syscall_name || *end != '\0') {
        return 0;
    }
    if (strcmp(arch, "c000003e") == 0) {
        return number == 310u ? 1 : (number == 311u ? 2 : 0);
    }
    if (strcmp(arch, "40000003") == 0) {
        return number == 347u ? 1 : (number == 348u ? 2 : 0);
    }
    if (strcmp(arch, "c00000b7") == 0) {
        return number == 270u ? 1 : (number == 271u ? 2 : 0);
    }
    return 0;
}

static bool ac_linux_audit_open(AcLinuxAuditSensor *sensor)
{
    struct stat status;

    sensor->file = fopen(sensor->path, "rb");
    if (sensor->file == NULL || fstat(fileno(sensor->file), &status) != 0) {
        if (sensor->file != NULL) {
            (void)fclose(sensor->file);
            sensor->file = NULL;
        }
        sensor->available = false;
        return false;
    }
    sensor->device = status.st_dev;
    sensor->inode = status.st_ino;
    sensor->available = true;
    return true;
}

static bool ac_linux_audit_refresh(AcLinuxAuditSensor *sensor)
{
    struct stat status;

    if (sensor->path == NULL) {
        return true;
    }
    if (!sensor->available || sensor->file == NULL) {
        return ac_linux_audit_open(sensor);
    }
    if (stat(sensor->path, &status) != 0) {
        (void)fclose(sensor->file);
        sensor->file = NULL;
        sensor->available = false;
        return false;
    }
    if (status.st_dev == sensor->device && status.st_ino == sensor->inode) {
        return true;
    }
    (void)fclose(sensor->file);
    sensor->file = NULL;
    sensor->available = false;
    return ac_linux_audit_open(sensor);
}

static bool ac_linux_scan_audit(
    AcLinuxAuditSensor *sensor,
    AcLinuxLogger *logger,
    pid_t target_pid,
    uint64_t scan_id,
    size_t *signals_out)
{
    char line[8192];

    *signals_out = 0u;
    if (!ac_linux_audit_refresh(sensor)) {
        return false;
    }
    if (!sensor->available || sensor->file == NULL) {
        return true;
    }
    clearerr(sensor->file);
    while (fgets(line, sizeof(line), sensor->file) != NULL) {
        char key[64];
        char arch[32];
        char syscall_name[64];
        char target_hex[32];
        char actor_text[32];
        char success_text[16];
        char executable[PATH_MAX];
        char escaped_executable[AC_LINUX_JSON_PATH_CAPACITY];
        char details[AC_LINUX_JSON_PATH_CAPACITY + 512u];
        char *end = NULL;
        unsigned long target;
        unsigned long actor;
        int operation;
        bool success;

        if (strstr(line, "type=SYSCALL") == NULL ||
            !ac_linux_audit_value(line, "key", key, sizeof(key)) ||
            strcmp(key, "anticheat_process_vm") != 0 ||
            !ac_linux_audit_value(line, "arch", arch, sizeof(arch)) ||
            !ac_linux_audit_value(
                line, "syscall", syscall_name, sizeof(syscall_name)) ||
            !ac_linux_audit_value(line, "a0", target_hex, sizeof(target_hex)) ||
            !ac_linux_audit_value(line, "pid", actor_text, sizeof(actor_text))) {
            continue;
        }
        operation = ac_linux_audit_operation(arch, syscall_name);
        if (operation == 0) {
            continue;
        }
        errno = 0;
        target = strtoul(target_hex, &end, 16);
        if (errno != 0 || end == target_hex || *end != '\0' ||
            target != (unsigned long)target_pid) {
            continue;
        }
        errno = 0;
        actor = strtoul(actor_text, &end, 10);
        if (errno != 0 || end == actor_text || *end != '\0' || actor > INT_MAX) {
            continue;
        }
        success = ac_linux_audit_value(
                      line, "success", success_text, sizeof(success_text)) &&
                  strcmp(success_text, "yes") == 0;
        if (!ac_linux_audit_value(
                line, "exe", executable, sizeof(executable))) {
            (void)snprintf(executable, sizeof(executable), "%s", "<unavailable>");
        }
        if (!ac_json_escape(
                executable, escaped_executable, sizeof(escaped_executable))) {
            (void)snprintf(
                escaped_executable,
                sizeof(escaped_executable),
                "%s",
                "<path-escape-truncated>");
        }
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64
            ",\"actor_pid\":%lu,\"operation\":\"%s\","
            "\"success\":%s,\"executable\":\"%s\","
            "\"source\":\"linux_audit\",\"verdict\":\"signal_only\"}",
            scan_id,
            actor,
            operation == 2 ? "process_vm_writev" : "process_vm_readv",
            success ? "true" : "false",
            escaped_executable);
        ac_linux_log(
            logger,
            operation == 2 && success ? "high" : "medium",
            "linux_process_vm_access_observed",
            target_pid,
            details);
        ++*signals_out;
    }
    return true;
}

int main(int argc, char **argv)
{
    AcLinuxOptions options;
    AcLinuxLogger logger;
    AcLinuxAuditSensor audit_sensor;
    bool exit_now;
    char target_path[PATH_MAX];
    char escaped_path[AC_LINUX_JSON_PATH_CAPACITY];
    char details[AC_LINUX_JSON_PATH_CAPACITY + 256u];
    uint64_t scan_id = 0;
    int exit_code = 0;

    if (!ac_linux_parse_options(argc, argv, &options, &exit_now)) {
        ac_linux_usage(argv[0]);
        return 2;
    }
    if (exit_now) {
        return 0;
    }
    if (options.pid <= 0) {
        options.pid = ac_linux_find_process(options.process_name);
        if (options.pid <= 0) {
            return 4;
        }
    }
    if (!ac_linux_logger_open(&logger, options.log_path, !options.quiet)) {
        return 3;
    }
    memset(&audit_sensor, 0, sizeof(audit_sensor));
    audit_sensor.path = options.audit_log_path;
    (void)signal(SIGINT, ac_linux_signal);
    (void)signal(SIGTERM, ac_linux_signal);

    ac_linux_log(
        &logger,
        "info",
        "agent_started",
        0,
        "{\"agent\":\"anticheat-collector\",\"version\":\"0.4.0\","
        "\"schema\":5,\"platform\":\"linux\","
        "\"mode\":\"procfs_user_telemetry\"}");
    if (!ac_linux_read_exe(options.pid, target_path, sizeof(target_path))) {
        ac_linux_log(
            &logger,
            "high",
            "target_open_failed",
            options.pid,
            "{\"reason\":\"procfs_exe_unavailable\"}");
        exit_code = 5;
        goto cleanup;
    }
    if (!ac_json_escape(
            target_path,
            escaped_path,
            sizeof(escaped_path))) {
        (void)snprintf(
            escaped_path,
            sizeof(escaped_path),
            "%s",
            "<path-escape-truncated>");
    }
    (void)snprintf(
        details,
        sizeof(details),
        "{\"path\":\"%s\",\"metadata_api\":\"procfs\"}",
        escaped_path);
    ac_linux_log(&logger, "info", "target_opened", options.pid, details);
    if (options.audit_log_path != NULL) {
        (void)ac_linux_audit_open(&audit_sensor);
    }
    if (audit_sensor.available) {
        char escaped_audit_path[AC_LINUX_JSON_PATH_CAPACITY];
        if (!ac_json_escape(
                options.audit_log_path,
                escaped_audit_path,
                sizeof(escaped_audit_path))) {
            (void)snprintf(
                escaped_audit_path,
                sizeof(escaped_audit_path),
                "%s",
                "<path-escape-truncated>");
        }
        (void)snprintf(
            details,
            sizeof(details),
            "{\"source\":\"linux_audit\",\"path\":\"%s\","
            "\"key\":\"anticheat_process_vm\"}",
            escaped_audit_path);
        ac_linux_log(
            &logger, "info", "linux_kernel_audit_connected", options.pid, details);
    } else {
        ac_linux_log(
            &logger,
            options.require_kernel_audit ? "high" : "medium",
            "linux_kernel_audit_unavailable",
            options.pid,
            "{\"process_vm_readv_observed\":false,"
            "\"process_vm_writev_observed\":false,"
            "\"required_sensor\":\"linux_audit\","
            "\"verdict\":\"capability_gap\"}");
        if (options.require_kernel_audit) {
            exit_code = 6;
            goto cleanup;
        }
    }

    while (!g_stop) {
        size_t regions = 0;
        size_t suspicious = 0;
        size_t fds_visited = 0;
        size_t fd_signals = 0;
        size_t audit_signals;
        bool audit_scan_complete;
        const unsigned long tracer = ac_linux_tracer_pid(options.pid);
        struct timespec delay;

        ++scan_id;
        if (tracer != 0) {
            (void)snprintf(
                details,
                sizeof(details),
                "{\"scan_id\":%" PRIu64 ",\"tracer_pid\":%lu}",
                scan_id,
                tracer);
            ac_linux_log(
                &logger,
                "high",
                "linux_target_traced",
                options.pid,
                details);
        }
        ac_linux_scan_maps(
            &logger,
            options.pid,
            scan_id,
            &regions,
            &suspicious);
        ac_linux_scan_foreign_fds(
            &logger,
            options.pid,
            scan_id,
            &fds_visited,
            &fd_signals);
        audit_scan_complete = ac_linux_scan_audit(
            &audit_sensor, &logger, options.pid, scan_id, &audit_signals);
        if (!audit_scan_complete) {
            ac_linux_log(
                &logger,
                options.require_kernel_audit ? "high" : "medium",
                "linux_kernel_audit_lost",
                options.pid,
                "{\"source\":\"linux_audit\","
                "\"verdict\":\"capability_gap\"}");
            if (options.require_kernel_audit) {
                exit_code = 6;
            }
        }
        (void)snprintf(
            details,
            sizeof(details),
            "{\"scan_id\":%" PRIu64 ",\"regions\":%zu,"
            "\"suspicious_mappings\":%zu,\"fds_visited\":%zu,"
            "\"fd_signals\":%zu,\"tracer_pid\":%lu,"
            "\"audit_signals\":%zu,\"kernel_audit\":%s,"
            "\"complete\":%s}",
            scan_id,
            regions,
            suspicious,
            fds_visited,
            fd_signals,
            tracer,
            audit_signals,
            audit_sensor.available ? "true" : "false",
            (fds_visited < AC_LINUX_MAX_FDS && audit_scan_complete)
                ? "true" : "false");
        ac_linux_log(
            &logger,
            "info",
            "scan_completed",
            options.pid,
            details);
        if (exit_code != 0) {
            break;
        }
        if (options.once) {
            break;
        }
        delay.tv_sec = options.interval_ms / 1000u;
        delay.tv_nsec =
            (long)(options.interval_ms % 1000u) * 1000000L;
        (void)nanosleep(&delay, NULL);
    }

cleanup:
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scans\":%" PRIu64 ",\"exit_code\":%d}",
        scan_id,
        exit_code);
    ac_linux_log(
        &logger,
        "info",
        "agent_stopped",
        options.pid,
        details);
    if (audit_sensor.file != NULL) {
        (void)fclose(audit_sensor.file);
    }
    (void)fclose(logger.file);
    return exit_code;
}
