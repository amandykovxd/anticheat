#ifndef AC_H
#define AC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "ac_driver_protocol.h"
#include "dedup.h"
#include "pe.h"
#include "ranges.h"
#include "sha256.h"
#include "text.h"

#define AC_AGENT_NAME "anticheat-collector"
#define AC_AGENT_VERSION "0.3.0"
#define AC_SCHEMA_VERSION 5u

#define AC_MAX_MODULES 8192u
#define AC_MAX_SNAPSHOT_RETRIES 16u
#define AC_MAX_ALLOW_ROOTS 24u
#define AC_PROBE_BYTES 4096u
#define AC_DEDUP_CAPACITY 4096u

#define AC_INTEGRITY_BLOCK_SIZE 4096u
#define AC_INTEGRITY_MAX_BASELINES 1024u
#define AC_INTEGRITY_MAX_EXPORTS 65536u
#define AC_INTEGRITY_MAX_IAT_SLOTS 65536u
#define AC_INTEGRITY_MAX_HOOK_EVENTS 16u
#define AC_KERNEL_MAX_IMAGE_OBSERVATIONS 256u
#define AC_KERNEL_MAX_MISMATCH_EVENTS 32u

typedef enum AcSeverity {
    AC_SEVERITY_INFO,
    AC_SEVERITY_LOW,
    AC_SEVERITY_MEDIUM,
    AC_SEVERITY_HIGH
} AcSeverity;

typedef struct AcLogger {
    FILE *file;
    wchar_t *path;
    bool mirror_to_console;
    bool rotating;
    CRITICAL_SECTION lock;
    bool lock_initialized;
    uint64_t sequence;
    uint64_t bytes_written;
    uint64_t max_bytes;
    unsigned int generations;
    uint64_t truncated_lines;
    uint64_t write_failures;
    uint8_t chain[AC_SHA256_DIGEST_SIZE];
} AcLogger;

typedef struct AcModule {
    uintptr_t base;
    size_t size;
    wchar_t path[MAX_PATH];
} AcModule;

typedef struct AcModuleList {
    AcModule *items;
    size_t count;
    size_t capacity;
    bool truncated;
} AcModuleList;

typedef struct AcPolicy {
    const wchar_t *allow_roots[AC_MAX_ALLOW_ROOTS];
    size_t allow_root_count;
    uint64_t probe_budget_bytes;
    uint64_t scan_budget_ms;
    uint64_t repeat_interval_ms;
    uint64_t integrity_budget_bytes;
    uint64_t integrity_max_file_bytes;
    uint64_t integrity_baseline_budget_bytes;
    size_t max_regions;
    bool hash_unknown_modules;
    bool probe_region_content;
    bool verify_module_integrity;
} AcPolicy;

typedef struct AcIntegritySection {
    char name[AC_PE_SECTION_NAME_SIZE];
    uint32_t rva;
    uint32_t size;
    uint32_t block_count;
    uint8_t *block_hashes;
} AcIntegritySection;

typedef struct AcIntegrityBaseline {
    wchar_t path[MAX_PATH];
    uint64_t path_hash;
    uintptr_t base;
    uint64_t file_size;
    uint64_t file_time;
    uint64_t file_index;
    uint64_t allocated_bytes;
    uint64_t unavailable_since_scan_id;
    uint32_t volume_serial;
    uint32_t size_of_image;
    uint32_t export_table_rva;
    uint32_t export_count;
    uint32_t *export_rvas;
    uint32_t *iat_slot_rvas;
    uint8_t *iat_delay_load;
    uint32_t iat_slot_count;
    AcIntegritySection *sections;
    size_t section_count;
    AcPeMask mask;
    uint8_t file_sha256[AC_SHA256_DIGEST_SIZE];
    bool is_64bit;
    bool ready;
    bool unavailable;
    bool identity_reported;
    const char *unavailable_reason;
} AcIntegrityBaseline;

typedef struct AcIntegrityCache {
    AcIntegrityBaseline *items;
    size_t count;
    size_t capacity;
    uint64_t bytes_allocated;
} AcIntegrityCache;

typedef struct AcScanStats {
    size_t module_count;
    size_t modules_outside_roots;
    size_t regions_visited;
    size_t executable_region_count;
    size_t suspicious_region_count;
    size_t query_failures;
    size_t read_failures;
    uint64_t probe_bytes;
    uint64_t duration_ms;
    uint64_t emitted;
    uint64_t suppressed;
    size_t integrity_modules_checked;
    size_t integrity_modules_unavailable;
    size_t integrity_blocks_checked;
    size_t integrity_blocks_modified;
    size_t integrity_unreadable_blocks;
    size_t integrity_iat_slots_checked;
    size_t integrity_iat_hooks;
    size_t integrity_export_slots_checked;
    size_t integrity_export_hooks;
    size_t integrity_modules_partial;
    size_t integrity_modules_skipped;
    size_t integrity_file_changes;
    size_t region_events_omitted;
    uint64_t integrity_bytes;
    bool region_scan_truncated;
    bool coverage_complete;
} AcScanStats;

typedef struct AcContext {
    AcLogger *logger;
    AcPolicy policy;
    AcModuleList modules;
    AcRangeIndex module_ranges;
    AcDedup dedup;
    AcIntegrityCache integrity;
    size_t integrity_cursor;
    uint8_t probe_buffer[AC_PROBE_BYTES];
    uint8_t integrity_block[AC_INTEGRITY_BLOCK_SIZE];
    uint8_t integrity_expected[AC_INTEGRITY_BLOCK_SIZE];
    uint64_t scans_completed;
    uint64_t perf_budget_breaches;
} AcContext;

typedef struct AcTarget {
    HANDLE process;
    DWORD pid;
    DWORD granted_access;
    uint64_t start_time;
    wchar_t *image_path;
    wchar_t *directory;
} AcTarget;

typedef struct AcKernelImageObservation {
    uint64_t sequence;
    uint64_t image_base;
    uint64_t image_size;
} AcKernelImageObservation;

typedef struct AcKernelClient {
    HANDLE device;
    AcDriverVersion version;
    uint64_t last_dropped;
    uint64_t last_sequence;
    uint64_t sequence_events_missing;
    uint64_t image_observations_omitted;
    uint64_t session_id;
    size_t image_observation_count;
    uint32_t last_callbacks_active;
    bool callback_state_initialized;
    bool queue_saturated;
    bool telemetry_complete;
    bool session_registered;
    AcKernelImageObservation image_observations[
        AC_KERNEL_MAX_IMAGE_OBSERVATIONS];
} AcKernelClient;

bool ac_logger_open(
    AcLogger *logger,
    const wchar_t *path,
    bool mirror_to_console,
    uint64_t max_bytes,
    unsigned int generations);
void ac_logger_close(AcLogger *logger);
void ac_log_event(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json);
void ac_log_win32_error(
    AcLogger *logger,
    const char *event,
    DWORD pid,
    DWORD error_code);
void ac_log_win32_error_severity(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    DWORD error_code);

bool ac_find_process_by_name(
    const wchar_t *name,
    DWORD *pid_out,
    size_t *match_count_out);
HANDLE ac_open_process_for_scan(DWORD pid, DWORD *granted_access_out);
bool ac_get_process_path(HANDLE process, wchar_t **path_out);
bool ac_get_process_start_time(HANDLE process, uint64_t *start_time_out);
bool ac_get_parent_directory(const wchar_t *path, wchar_t **directory_out);
bool ac_process_image_matches_name(const wchar_t *image_path, const wchar_t *name);

void ac_module_list_init(AcModuleList *modules);
void ac_module_list_free(AcModuleList *modules);
bool ac_module_list_push(
    AcModuleList *modules,
    uintptr_t base,
    size_t size,
    const wchar_t *path);
bool ac_collect_modules(DWORD pid, AcModuleList *modules, DWORD *error_out);
bool ac_path_is_under(const wchar_t *path, const wchar_t *directory);
bool ac_path_is_under_any(
    const wchar_t *path,
    const wchar_t **directories,
    size_t directory_count);

void ac_policy_init_defaults(AcPolicy *policy);
bool ac_context_init(AcContext *context, AcLogger *logger, const AcPolicy *policy);
void ac_context_free(AcContext *context);
bool ac_scan_process(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats_out);

void ac_integrity_cache_init(AcIntegrityCache *cache);
void ac_integrity_cache_free(AcIntegrityCache *cache);
void ac_verify_module_integrity(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats);

bool ac_hash_file(const wchar_t *path, char hex_out[AC_SHA256_HEX_SIZE], uint64_t *size_out);
bool ac_wide_to_utf8(const wchar_t *input, char *output, size_t output_capacity);
bool ac_wide_to_utf8_alloc(const wchar_t *input, char **output);
const char *ac_severity_name(AcSeverity severity);

void ac_kernel_client_init(AcKernelClient *client);
bool ac_kernel_client_open(AcKernelClient *client);
void ac_kernel_client_close(AcKernelClient *client);
bool ac_kernel_client_set_target(AcKernelClient *client, DWORD pid);
bool ac_kernel_client_get_stats(
    AcKernelClient *client,
    AcDriverStats *stats_out);
bool ac_kernel_client_observe_sequence(
    AcKernelClient *client,
    uint64_t sequence,
    uint64_t *missing_out);
bool ac_kernel_client_observe_drop_counter(
    AcKernelClient *client,
    uint64_t events_dropped,
    uint64_t *newly_dropped_out);
bool ac_kernel_client_process_stats(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    const AcDriverStats *stats);
bool ac_kernel_client_drain(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t *events_out);
void ac_kernel_client_correlate_scan(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const AcRangeIndex *module_ranges,
    uint64_t *mismatches_out);

#endif
