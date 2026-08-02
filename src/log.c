#include "ac.h"

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define AC_LOG_BODY_CAPACITY 16384u
#define AC_LOG_LINE_CAPACITY (AC_LOG_BODY_CAPACITY + 128u)

static void ac_logger_emit_locked(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json);

const char *ac_severity_name(AcSeverity severity)
{
    switch (severity) {
        case AC_SEVERITY_INFO: return "info";
        case AC_SEVERITY_LOW: return "low";
        case AC_SEVERITY_MEDIUM: return "medium";
        case AC_SEVERITY_HIGH: return "high";
        default: return "unknown";
    }
}

bool ac_wide_to_utf8(const wchar_t *input, char *output, size_t output_capacity)
{
    int result;

    if (input == NULL || output == NULL || output_capacity == 0 ||
        output_capacity > INT_MAX) {
        return false;
    }

    result = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input,
        -1,
        output,
        (int)output_capacity,
        NULL,
        NULL);
    return result > 0;
}

bool ac_wide_to_utf8_alloc(const wchar_t *input, char **output)
{
    int required;
    char *buffer;

    if (input == NULL || output == NULL) {
        return false;
    }
    *output = NULL;

    required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input,
        -1,
        NULL,
        0,
        NULL,
        NULL);
    if (required <= 0) {
        return false;
    }

    buffer = (char *)malloc((size_t)required);
    if (buffer == NULL) {
        return false;
    }

    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            input,
            -1,
            buffer,
            required,
            NULL,
            NULL) <= 0) {
        free(buffer);
        return false;
    }

    *output = buffer;
    return true;
}

static void ac_logger_seed_chain(AcLogger *logger)
{
    AcSha256 context;
    FILETIME now;
    const DWORD process_id = GetCurrentProcessId();
    char *path_utf8 = NULL;

    GetSystemTimeAsFileTime(&now);
    ac_sha256_init(&context);
    ac_sha256_update(&context, "ac-log-chain-v1", 15u);
    ac_sha256_update(&context, &now, sizeof(now));
    ac_sha256_update(&context, &process_id, sizeof(process_id));
    if (ac_wide_to_utf8_alloc(logger->path, &path_utf8)) {
        ac_sha256_update(&context, path_utf8, strlen(path_utf8));
        free(path_utf8);
    }
    ac_sha256_final(&context, logger->chain);
}

static bool ac_logger_reopen(AcLogger *logger, const wchar_t *mode)
{
    logger->file = _wfopen(logger->path, mode);
    if (logger->file == NULL) {
        return false;
    }

    if (_fseeki64(logger->file, 0, SEEK_END) == 0) {
        const __int64 size = _ftelli64(logger->file);
        logger->bytes_written = size > 0 ? (uint64_t)size : 0u;
    } else {
        logger->bytes_written = 0;
    }
    return true;
}

static void ac_logger_rotate_locked(AcLogger *logger)
{
    const size_t path_length = wcslen(logger->path);
    const size_t capacity = path_length + 24u;
    wchar_t *from;
    wchar_t *to;
    unsigned int index;

    if (logger->file != NULL) {
        (void)fclose(logger->file);
        logger->file = NULL;
    }

    from = (wchar_t *)malloc(capacity * sizeof(wchar_t));
    to = (wchar_t *)malloc(capacity * sizeof(wchar_t));
    if (from == NULL || to == NULL) {
        free(from);
        free(to);
        (void)ac_logger_reopen(logger, L"wb");
        logger->bytes_written = 0;
        return;
    }

    if (logger->generations > 0) {
        (void)swprintf(to, capacity, L"%ls.%u", logger->path, logger->generations);
        (void)_wremove(to);

        for (index = logger->generations; index > 1u; --index) {
            (void)swprintf(from, capacity, L"%ls.%u", logger->path, index - 1u);
            (void)swprintf(to, capacity, L"%ls.%u", logger->path, index);
            (void)_wremove(to);
            (void)_wrename(from, to);
        }

        (void)swprintf(to, capacity, L"%ls.1", logger->path);
        (void)_wremove(to);
        (void)_wrename(logger->path, to);
    }

    free(from);
    free(to);

    if (!ac_logger_reopen(logger, L"wb")) {
        ++logger->write_failures;
    }
    logger->bytes_written = 0;
}

static bool ac_logger_write_raw_locked(AcLogger *logger, const char *line, size_t length)
{
    bool ok = true;

    if (logger->file != NULL) {
        if (fwrite(line, 1u, length, logger->file) != length ||
            fputc('\n', logger->file) == EOF ||
            fflush(logger->file) != 0) {
            ok = false;
            ++logger->write_failures;
        } else {
            logger->bytes_written += (uint64_t)length + 1u;
        }
    }

    if (logger->mirror_to_console) {
        (void)fwrite(line, 1u, length, stdout);
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
    }

    return ok;
}

static void ac_logger_emit_locked(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json)
{
    SYSTEMTIME timestamp;
    AcSha256 hash;
    char escaped_event[256];
    char *storage;
    char *body;
    char *line;
    char chain_hex[AC_SHA256_HEX_SIZE];
    const char *details = details_json != NULL ? details_json : "{}";
    int body_length;
    int line_length;

    storage = (char *)malloc(AC_LOG_BODY_CAPACITY + AC_LOG_LINE_CAPACITY);
    if (storage == NULL) {
        ++logger->write_failures;
        return;
    }
    body = storage;
    line = storage + AC_LOG_BODY_CAPACITY;

    if (logger->max_bytes > 0 && !logger->rotating &&
        logger->bytes_written >= logger->max_bytes) {
        char marker[256];

        logger->rotating = true;
        ac_logger_rotate_locked(logger);
        (void)snprintf(
            marker,
            sizeof(marker),
            "{\"reason\":\"size_limit\",\"max_bytes\":%" PRIu64
            ",\"generations\":%u}",
            logger->max_bytes,
            logger->generations);
        ac_logger_emit_locked(logger, AC_SEVERITY_INFO, "log_segment_opened", 0, marker);
        logger->rotating = false;
    }

    GetSystemTime(&timestamp);
    (void)ac_json_escape(event != NULL ? event : "unknown", escaped_event, sizeof(escaped_event));

    ++logger->sequence;
    body_length = snprintf(
        body,
        AC_LOG_BODY_CAPACITY,
        "{\"seq\":%" PRIu64 ",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
        "\"severity\":\"%s\",\"event\":\"%s\",\"pid\":%lu,\"details\":%s",
        logger->sequence,
        (unsigned int)timestamp.wYear,
        (unsigned int)timestamp.wMonth,
        (unsigned int)timestamp.wDay,
        (unsigned int)timestamp.wHour,
        (unsigned int)timestamp.wMinute,
        (unsigned int)timestamp.wSecond,
        (unsigned int)timestamp.wMilliseconds,
        ac_severity_name(severity),
        escaped_event,
        (unsigned long)pid,
        details);

    if (body_length < 0 || (size_t)body_length >= AC_LOG_BODY_CAPACITY) {
        ++logger->truncated_lines;
        body_length = snprintf(
            body,
            AC_LOG_BODY_CAPACITY,
            "{\"seq\":%" PRIu64 ",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
            "\"severity\":\"%s\",\"event\":\"%s\",\"pid\":%lu,"
            "\"details\":{\"dropped\":true,\"reason\":\"details_too_large\"}",
            logger->sequence,
            (unsigned int)timestamp.wYear,
            (unsigned int)timestamp.wMonth,
            (unsigned int)timestamp.wDay,
            (unsigned int)timestamp.wHour,
            (unsigned int)timestamp.wMinute,
            (unsigned int)timestamp.wSecond,
            (unsigned int)timestamp.wMilliseconds,
            ac_severity_name(severity),
            escaped_event,
            (unsigned long)pid);
        if (body_length < 0 || (size_t)body_length >= AC_LOG_BODY_CAPACITY) {
            ++logger->write_failures;
            free(storage);
            return;
        }
    }

    ac_sha256_init(&hash);
    ac_sha256_update(&hash, logger->chain, sizeof(logger->chain));
    ac_sha256_update(&hash, body, (size_t)body_length);
    ac_sha256_final(&hash, logger->chain);
    ac_sha256_to_hex(logger->chain, chain_hex);

    line_length = snprintf(
        line,
        AC_LOG_LINE_CAPACITY,
        "%s,\"chain\":\"%s\"}",
        body,
        chain_hex);
    if (line_length < 0 || (size_t)line_length >= AC_LOG_LINE_CAPACITY) {
        ++logger->write_failures;
        free(storage);
        return;
    }

    (void)ac_logger_write_raw_locked(logger, line, (size_t)line_length);
    free(storage);
}

bool ac_logger_open(
    AcLogger *logger,
    const wchar_t *path,
    bool mirror_to_console,
    uint64_t max_bytes,
    unsigned int generations)
{
    char details[512];
    char chain_hex[AC_SHA256_HEX_SIZE];

    if (logger == NULL || path == NULL || path[0] == L'\0') {
        return false;
    }

    memset(logger, 0, sizeof(*logger));
    logger->path = _wcsdup(path);
    if (logger->path == NULL) {
        return false;
    }

    InitializeCriticalSection(&logger->lock);
    logger->lock_initialized = true;
    logger->mirror_to_console = mirror_to_console;
    logger->max_bytes = max_bytes;
    logger->generations = generations;

    if (!ac_logger_reopen(logger, L"ab")) {
        ac_logger_close(logger);
        return false;
    }

    ac_logger_seed_chain(logger);
    ac_sha256_to_hex(logger->chain, chain_hex);
    (void)snprintf(
        details,
        sizeof(details),
        "{\"agent\":\"%s\",\"version\":\"%s\",\"schema\":%u,"
        "\"chain_algorithm\":\"sha256\",\"chain_seed\":\"%s\","
        "\"max_bytes\":%" PRIu64 ",\"generations\":%u}",
        AC_AGENT_NAME,
        AC_AGENT_VERSION,
        AC_SCHEMA_VERSION,
        chain_hex,
        max_bytes,
        generations);

    EnterCriticalSection(&logger->lock);
    ac_logger_emit_locked(logger, AC_SEVERITY_INFO, "log_segment_opened", 0, details);
    LeaveCriticalSection(&logger->lock);
    return true;
}

void ac_logger_close(AcLogger *logger)
{
    if (logger == NULL) {
        return;
    }

    if (logger->file != NULL) {
        (void)fclose(logger->file);
        logger->file = NULL;
    }

    free(logger->path);
    logger->path = NULL;

    if (logger->lock_initialized) {
        DeleteCriticalSection(&logger->lock);
        logger->lock_initialized = false;
    }
}

void ac_log_event(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json)
{
    if (logger == NULL || !logger->lock_initialized) {
        return;
    }

    EnterCriticalSection(&logger->lock);
    ac_logger_emit_locked(logger, severity, event, pid, details_json);
    LeaveCriticalSection(&logger->lock);
}

void ac_log_win32_error_severity(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    DWORD error_code)
{
    wchar_t wide_message[512];
    char utf8_message[1536];
    char escaped_message[3072];
    char details[4096];
    DWORD length;

    wide_message[0] = L'\0';
    length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        0,
        wide_message,
        (DWORD)(sizeof(wide_message) / sizeof(wide_message[0])),
        NULL);

    while (length > 0 &&
           (wide_message[length - 1] == L'\r' ||
            wide_message[length - 1] == L'\n' ||
            wide_message[length - 1] == L' ')) {
        wide_message[--length] = L'\0';
    }

    if (!ac_wide_to_utf8(
            length > 0 ? wide_message : L"Unknown Win32 error",
            utf8_message,
            sizeof(utf8_message))) {
        (void)strcpy_s(utf8_message, sizeof(utf8_message), "Unknown Win32 error");
    }

    (void)ac_json_escape(utf8_message, escaped_message, sizeof(escaped_message));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"win32_error\":%lu,\"message\":\"%s\"}",
        (unsigned long)error_code,
        escaped_message);
    ac_log_event(logger, severity, event, pid, details);
}

void ac_log_win32_error(
    AcLogger *logger,
    const char *event,
    DWORD pid,
    DWORD error_code)
{
    ac_log_win32_error_severity(
        logger,
        AC_SEVERITY_LOW,
        event,
        pid,
        error_code);
}
