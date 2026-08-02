#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define AC_INTEGRITY_HEX_PREVIEW 16u
#define AC_INTEGRITY_UNAVAILABLE_RETRY_SCANS 12u

typedef struct AcFileIdentity {
    uint64_t size;
    uint64_t write_time;
    uint64_t file_index;
    uint32_t volume_serial;
} AcFileIdentity;

typedef struct AcIatCollector {
    uint32_t *slots;
    uint8_t *delay_flags;
    uint32_t count;
    uint32_t capacity;
    bool failed;
} AcIatCollector;

static void ac_bytes_to_hex(const uint8_t *bytes, size_t length, char *output)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < length; ++index) {
        output[index * 2u] = alphabet[(bytes[index] >> 4) & 0x0fu];
        output[index * 2u + 1u] = alphabet[bytes[index] & 0x0fu];
    }
    output[length * 2u] = '\0';
}

static bool ac_file_identity_from_handle(HANDLE file, AcFileIdentity *identity)
{
    BY_HANDLE_FILE_INFORMATION information;

    if (identity == NULL ||
        !GetFileInformationByHandle(file, &information)) {
        return false;
    }

    identity->size =
        ((uint64_t)information.nFileSizeHigh << 32) |
        (uint64_t)information.nFileSizeLow;
    identity->write_time =
        ((uint64_t)information.ftLastWriteTime.dwHighDateTime << 32) |
        (uint64_t)information.ftLastWriteTime.dwLowDateTime;
    identity->file_index =
        ((uint64_t)information.nFileIndexHigh << 32) |
        (uint64_t)information.nFileIndexLow;
    identity->volume_serial = information.dwVolumeSerialNumber;
    return true;
}

static bool ac_file_identity_equal(
    const AcFileIdentity *left,
    const AcFileIdentity *right)
{
    return left->size == right->size &&
           left->write_time == right->write_time &&
           left->file_index == right->file_index &&
           left->volume_serial == right->volume_serial;
}

static bool ac_query_file_identity(
    const wchar_t *path,
    AcFileIdentity *identity)
{
    HANDLE file;
    bool ok;

    file = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    ok = ac_file_identity_from_handle(file, identity);
    CloseHandle(file);
    return ok;
}

static bool ac_read_file_bounded(
    const wchar_t *path,
    uint64_t limit,
    uint8_t **data_out,
    size_t *size_out,
    AcFileIdentity *identity_out,
    uint8_t digest_out[AC_SHA256_DIGEST_SIZE])
{
    HANDLE file;
    LARGE_INTEGER size;
    AcFileIdentity before;
    AcFileIdentity after;
    uint8_t *buffer;
    uint64_t total = 0;

    if (path == NULL || data_out == NULL || size_out == NULL ||
        identity_out == NULL || digest_out == NULL) {
        return false;
    }
    *data_out = NULL;
    *size_out = 0;

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

    if (!GetFileSizeEx(file, &size) ||
        !ac_file_identity_from_handle(file, &before) ||
        size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > limit) {
        CloseHandle(file);
        return false;
    }

    buffer = (uint8_t *)malloc((size_t)size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        return false;
    }

    while (total < (uint64_t)size.QuadPart) {
        const uint64_t remaining = (uint64_t)size.QuadPart - total;
        const DWORD chunk = remaining > 0x100000ull ? 0x100000u : (DWORD)remaining;
        DWORD read_bytes = 0;

        if (!ReadFile(file, buffer + total, chunk, &read_bytes, NULL) ||
            read_bytes == 0) {
            free(buffer);
            CloseHandle(file);
            return false;
        }
        total += read_bytes;
    }

    if (!ac_file_identity_from_handle(file, &after) ||
        !ac_file_identity_equal(&before, &after) ||
        after.size != total) {
        free(buffer);
        CloseHandle(file);
        return false;
    }

    ac_sha256(buffer, (size_t)total, digest_out);
    CloseHandle(file);
    *data_out = buffer;
    *size_out = (size_t)total;
    *identity_out = after;
    return true;
}

void ac_integrity_cache_init(AcIntegrityCache *cache)
{
    if (cache == NULL) {
        return;
    }
    cache->items = NULL;
    cache->count = 0;
    cache->capacity = 0;
    cache->bytes_allocated = 0;
}

static void ac_integrity_baseline_release(AcIntegrityBaseline *baseline)
{
    size_t index;

    if (baseline == NULL) {
        return;
    }

    if (baseline->sections != NULL) {
        for (index = 0; index < baseline->section_count; ++index) {
            free(baseline->sections[index].block_hashes);
        }
    }
    free(baseline->sections);
    free(baseline->export_rvas);
    free(baseline->iat_slot_rvas);
    free(baseline->iat_delay_load);
    ac_pe_mask_free(&baseline->mask);

    baseline->sections = NULL;
    baseline->section_count = 0;
    baseline->export_rvas = NULL;
    baseline->export_count = 0;
    baseline->iat_slot_rvas = NULL;
    baseline->iat_delay_load = NULL;
    baseline->iat_slot_count = 0;
    baseline->allocated_bytes = 0;
    baseline->ready = false;
}

void ac_integrity_cache_free(AcIntegrityCache *cache)
{
    size_t index;

    if (cache == NULL) {
        return;
    }

    for (index = 0; index < cache->count; ++index) {
        ac_integrity_baseline_release(&cache->items[index]);
    }
    free(cache->items);
    ac_integrity_cache_init(cache);
}

static AcIntegrityBaseline *ac_integrity_lookup(
    AcIntegrityCache *cache,
    const AcModule *module,
    uint64_t path_hash)
{
    size_t index;

    for (index = 0; index < cache->count; ++index) {
        AcIntegrityBaseline *baseline = &cache->items[index];

        if (baseline->path_hash == path_hash &&
            baseline->base == module->base &&
            _wcsicmp(baseline->path, module->path) == 0) {
            return baseline;
        }
    }
    return NULL;
}

static AcIntegrityBaseline *ac_integrity_allocate(
    AcIntegrityCache *cache,
    const AcModule *module,
    uint64_t path_hash)
{
    AcIntegrityBaseline *baseline;

    if (cache->count >= AC_INTEGRITY_MAX_BASELINES) {
        return NULL;
    }

    if (cache->count == cache->capacity) {
        const size_t capacity = cache->capacity == 0 ? 64u : cache->capacity * 2u;
        AcIntegrityBaseline *items;

        if (capacity > SIZE_MAX / sizeof(AcIntegrityBaseline)) {
            return NULL;
        }
        items = (AcIntegrityBaseline *)realloc(
            cache->items,
            capacity * sizeof(AcIntegrityBaseline));
        if (items == NULL) {
            return NULL;
        }
        cache->items = items;
        cache->capacity = capacity;
    }

    baseline = &cache->items[cache->count];
    memset(baseline, 0, sizeof(*baseline));
    ac_pe_mask_init(&baseline->mask);
    baseline->base = module->base;
    baseline->path_hash = path_hash;
    (void)wcsncpy_s(
        baseline->path,
        sizeof(baseline->path) / sizeof(baseline->path[0]),
        module->path,
        _TRUNCATE);
    ++cache->count;
    return baseline;
}

static void ac_integrity_mark_unavailable(
    AcIntegrityBaseline *baseline,
    const char *reason)
{
    ac_integrity_baseline_release(baseline);
    ac_pe_mask_init(&baseline->mask);
    baseline->unavailable = true;
    baseline->unavailable_reason = reason;
}

static bool ac_integrity_collect_iat_slot(void *user, uint32_t slot_rva, bool delay_load)
{
    AcIatCollector *collector = (AcIatCollector *)user;

    (void)delay_load;

    if (collector->count >= AC_INTEGRITY_MAX_IAT_SLOTS) {
        return false;
    }

    if (collector->count == collector->capacity) {
        const uint32_t capacity = collector->capacity == 0 ? 64u : collector->capacity * 2u;
        uint32_t *slots = (uint32_t *)malloc(
            (size_t)capacity * sizeof(uint32_t));
        uint8_t *delay_flags = (uint8_t *)malloc(
            (size_t)capacity * sizeof(uint8_t));

        if (slots == NULL || delay_flags == NULL) {
            free(slots);
            free(delay_flags);
            collector->failed = true;
            return false;
        }
        if (collector->count > 0) {
            memcpy(
                slots,
                collector->slots,
                (size_t)collector->count * sizeof(uint32_t));
            memcpy(
                delay_flags,
                collector->delay_flags,
                (size_t)collector->count * sizeof(uint8_t));
        }
        free(collector->slots);
        free(collector->delay_flags);
        collector->slots = slots;
        collector->delay_flags = delay_flags;
        collector->capacity = capacity;
    }

    collector->slots[collector->count] = slot_rva;
    collector->delay_flags[collector->count] = delay_load ? 1u : 0u;
    ++collector->count;
    return true;
}

/* Rebuilds the expected in-memory bytes of every executable section from the
   file on disk, normalising the differences the loader legitimately
   introduces, and stores one SHA-256 per block.

   Mask ordering note: relocation and unbacked-range entries are always inside
   the section being processed, so hashing a section with a mask that is only
   partially populated for later sections is safe. */
static bool ac_integrity_build_baseline(
    AcContext *context,
    AcIntegrityBaseline *baseline,
    const AcModule *module)
{
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    AcFileIdentity identity;
    uint8_t file_digest[AC_SHA256_DIGEST_SIZE];
    AcPeImage image;
    AcPeStatus status;
    int64_t delta;
    uint16_t index;
    size_t section_capacity;
    bool ok = true;

    if (!ac_read_file_bounded(
            module->path,
            context->policy.integrity_max_file_bytes,
            &file_data,
            &file_size,
            &identity,
            file_digest)) {
        ac_integrity_mark_unavailable(baseline, "file_unreadable_or_too_large");
        return false;
    }

    status = ac_pe_parse(file_data, file_size, &image);
    if (status != AC_PE_OK) {
        free(file_data);
        ac_integrity_mark_unavailable(baseline, ac_pe_status_name(status));
        return false;
    }

    baseline->file_size = file_size;
    baseline->file_time = identity.write_time;
    baseline->file_index = identity.file_index;
    baseline->volume_serial = identity.volume_serial;
    memcpy(baseline->file_sha256, file_digest, sizeof(baseline->file_sha256));
    baseline->size_of_image = image.size_of_image;
    baseline->is_64bit = image.is_64bit;
    delta = (int64_t)((uint64_t)module->base - image.image_base);

    if (ac_pe_mask_import_tables(&image, &baseline->mask) != AC_PE_OK) {
        free(file_data);
        ac_integrity_mark_unavailable(baseline, "import_table_malformed");
        return false;
    }

    section_capacity = image.section_count;
    baseline->sections = (AcIntegritySection *)calloc(
        section_capacity == 0 ? 1u : section_capacity,
        sizeof(AcIntegritySection));
    if (baseline->sections == NULL) {
        free(file_data);
        ac_integrity_mark_unavailable(baseline, "out_of_memory");
        return false;
    }
    baseline->allocated_bytes =
        (uint64_t)section_capacity * sizeof(AcIntegritySection);

    for (index = 0; index < image.section_count && ok; ++index) {
        const AcPeSection *section = &image.sections[index];
        AcIntegritySection *target;
        uint8_t *materialized;
        uint32_t block_count;
        uint32_t block;

        if (!ac_pe_section_is_executable(section) || section->virtual_size == 0) {
            continue;
        }
        if (section->virtual_size > context->policy.integrity_max_file_bytes) {
            continue;
        }

        /* Bytes with no file backing are produced at runtime, not by the file. */
        if (section->raw_size < section->virtual_size) {
            (void)ac_pe_mask_add(
                &baseline->mask,
                section->virtual_address + section->raw_size,
                section->virtual_size - section->raw_size);
        }

        materialized = (uint8_t *)malloc(section->virtual_size);
        if (materialized == NULL) {
            ok = false;
            break;
        }

        if (ac_pe_materialize_section(
                &image,
                section,
                materialized,
                section->virtual_size) != AC_PE_OK) {
            free(materialized);
            continue;
        }

        if (ac_pe_apply_relocations(
                &image,
                section,
                materialized,
                delta,
                &baseline->mask) != AC_PE_OK) {
            free(materialized);
            ok = false;
            break;
        }

        ac_pe_mask_finalize(&baseline->mask);

        block_count = (section->virtual_size + AC_INTEGRITY_BLOCK_SIZE - 1u) /
                      AC_INTEGRITY_BLOCK_SIZE;
        target = &baseline->sections[baseline->section_count];
        memcpy(target->name, section->name, AC_PE_SECTION_NAME_SIZE);
        target->rva = section->virtual_address;
        target->size = section->virtual_size;
        target->block_count = block_count;
        target->block_hashes = (uint8_t *)malloc(
            (size_t)block_count * AC_SHA256_DIGEST_SIZE);
        if (target->block_hashes == NULL) {
            free(materialized);
            ok = false;
            break;
        }

        for (block = 0; block < block_count; ++block) {
            const uint32_t offset = block * AC_INTEGRITY_BLOCK_SIZE;
            const uint32_t length = section->virtual_size - offset < AC_INTEGRITY_BLOCK_SIZE
                ? section->virtual_size - offset
                : AC_INTEGRITY_BLOCK_SIZE;

            memcpy(context->integrity_expected, materialized + offset, length);
            ac_pe_mask_zero(
                &baseline->mask,
                context->integrity_expected,
                section->virtual_address + offset,
                length);
            ac_sha256(
                context->integrity_expected,
                length,
                target->block_hashes + (size_t)block * AC_SHA256_DIGEST_SIZE);
        }

        baseline->allocated_bytes +=
            (uint64_t)block_count * AC_SHA256_DIGEST_SIZE;
        ++baseline->section_count;
        free(materialized);
    }

    if (ok) {
        AcIatCollector collector;

        memset(&collector, 0, sizeof(collector));
        (void)ac_pe_for_each_iat_slot(&image, ac_integrity_collect_iat_slot, &collector);
        if (collector.failed) {
            free(collector.slots);
            free(collector.delay_flags);
        } else {
            baseline->iat_slot_rvas = collector.slots;
            baseline->iat_delay_load = collector.delay_flags;
            baseline->iat_slot_count = collector.count;
            baseline->allocated_bytes +=
                (uint64_t)collector.count *
                (sizeof(uint32_t) + sizeof(uint8_t));
        }
    }

    if (ok) {
        uint32_t export_rva = 0;
        uint32_t export_count = 0;

        if (ac_pe_export_functions(&image, &export_rva, &export_count) == AC_PE_OK &&
            export_count > 0 && export_count <= AC_INTEGRITY_MAX_EXPORTS) {
            baseline->export_rvas = (uint32_t *)malloc(
                (size_t)export_count * sizeof(uint32_t));
            if (baseline->export_rvas != NULL) {
                uint32_t entry;

                for (entry = 0; entry < export_count; ++entry) {
                    uint32_t value = 0;

                    if (!ac_pe_read_u32_rva(
                            &image,
                            export_rva + entry * 4u,
                            &value)) {
                        break;
                    }
                    baseline->export_rvas[entry] = value;
                }
                if (entry == export_count) {
                    baseline->export_table_rva = export_rva;
                    baseline->export_count = export_count;
                    baseline->allocated_bytes +=
                        (uint64_t)export_count * sizeof(uint32_t);
                } else {
                    free(baseline->export_rvas);
                    baseline->export_rvas = NULL;
                }
            }
        }
    }

    free(file_data);

    if (!ok) {
        ac_integrity_mark_unavailable(baseline, "out_of_memory");
        return false;
    }

    ac_pe_mask_finalize(&baseline->mask);
    baseline->allocated_bytes +=
        (uint64_t)baseline->mask.capacity * sizeof(AcPeRange);
    if (baseline->allocated_bytes >
        context->policy.integrity_baseline_budget_bytes -
            (context->integrity.bytes_allocated >
                    context->policy.integrity_baseline_budget_bytes
                ? context->policy.integrity_baseline_budget_bytes
                : context->integrity.bytes_allocated)) {
        ac_integrity_mark_unavailable(baseline, "baseline_budget_exceeded");
        return false;
    }
    context->integrity.bytes_allocated += baseline->allocated_bytes;
    baseline->ready = true;
    baseline->unavailable = false;
    return true;
}

static void ac_integrity_report_module_event(
    AcContext *context,
    DWORD pid,
    AcSeverity severity,
    const char *event,
    const AcIntegrityBaseline *baseline,
    uint64_t scan_id,
    const char *extra_json,
    AcScanStats *stats)
{
    AcDedupDecision decision;
    char path_utf8[MAX_PATH * 3];
    char escaped_path[MAX_PATH * 6];
    char details[MAX_PATH * 6 + 1024];
    uint64_t fingerprint;

    if (!ac_wide_to_utf8(baseline->path, path_utf8, sizeof(path_utf8))) {
        (void)strcpy_s(path_utf8, sizeof(path_utf8), "<path-conversion-failed>");
    }

    fingerprint = ac_fnv1a64_text(AC_FNV1A64_OFFSET, event);
    fingerprint = ac_fnv1a64_text_ci(fingerprint, path_utf8);
    fingerprint = ac_fnv1a64_text(fingerprint, extra_json != NULL ? extra_json : "");
    ac_dedup_observe(&context->dedup, fingerprint, scan_id, GetTickCount64(), &decision);
    if (!decision.emit) {
        ++stats->suppressed;
        return;
    }

    (void)ac_json_escape(path_utf8, escaped_path, sizeof(escaped_path));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"path\":\"%s\",\"module_base\":\"0x%" PRIxPTR "\",%s"
        "\"verdict\":\"signal_only\",\"first_seen_scan_id\":%" PRIu64 ","
        "\"occurrences\":%" PRIu64 ",\"suppressed_since_last_report\":%" PRIu64 "}",
        scan_id,
        escaped_path,
        baseline->base,
        extra_json != NULL ? extra_json : "",
        decision.first_scan_id,
        decision.occurrences,
        decision.suppressed_since_last_emit);

    ac_log_event(context->logger, severity, event, pid, details);
    ++stats->emitted;
}

static void ac_integrity_report_identity(
    AcContext *context,
    const AcTarget *target,
    AcIntegrityBaseline *baseline,
    uint64_t scan_id,
    AcScanStats *stats)
{
    char digest[AC_SHA256_HEX_SIZE];
    char extra[512];

    if (baseline->identity_reported) {
        return;
    }

    ac_sha256_to_hex(baseline->file_sha256, digest);
    (void)snprintf(
        extra,
        sizeof(extra),
        "\"file_sha256\":\"%s\",\"file_size\":%" PRIu64
        ",\"file_time\":%" PRIu64 ",\"volume_serial\":%u,"
        "\"file_index\":%" PRIu64 ",\"reason\":\"module_identity_observed\",",
        digest,
        baseline->file_size,
        baseline->file_time,
        baseline->volume_serial,
        baseline->file_index);
    ac_integrity_report_module_event(
        context,
        target->pid,
        AC_SEVERITY_INFO,
        "module_identity_observed",
        baseline,
        scan_id,
        extra,
        stats);
    baseline->identity_reported = true;

    if (context->policy.manifest != NULL &&
        context->policy.manifest->trusted &&
        !baseline->manifest_reported) {
        const AcManifestMatch match = ac_manifest_match(
            context->policy.manifest,
            AC_MANIFEST_MODULE,
            baseline->path,
            baseline->file_sha256);

        if (match != AC_MANIFEST_AUTHORIZED) {
            (void)snprintf(
                extra,
                sizeof(extra),
                "\"file_sha256\":\"%s\","
                "\"manifest_sha256\":\"%s\","
                "\"reason\":\"%s\",",
                digest,
                context->policy.manifest->file_sha256,
                match == AC_MANIFEST_HASH_MISMATCH
                    ? "manifest_hash_mismatch"
                    : "module_not_in_manifest");
            ac_integrity_report_module_event(
                context,
                target->pid,
                AC_SEVERITY_HIGH,
                "module_manifest_violation",
                baseline,
                scan_id,
                extra,
                stats);
        }
        baseline->manifest_reported = true;
    }
}

static bool ac_integrity_baseline_is_loaded(
    const AcIntegrityBaseline *baseline,
    const AcModuleList *modules)
{
    size_t index;

    for (index = 0; index < modules->count; ++index) {
        const AcModule *module = &modules->items[index];

        if (baseline->base == module->base &&
            _wcsicmp(baseline->path, module->path) == 0) {
            return true;
        }
    }
    return false;
}

static void ac_integrity_prune(
    AcIntegrityCache *cache,
    const AcModuleList *modules)
{
    size_t read_index;
    size_t write_index = 0;

    for (read_index = 0; read_index < cache->count; ++read_index) {
        AcIntegrityBaseline *baseline = &cache->items[read_index];

        if (!ac_integrity_baseline_is_loaded(baseline, modules)) {
            if (cache->bytes_allocated >= baseline->allocated_bytes) {
                cache->bytes_allocated -= baseline->allocated_bytes;
            } else {
                cache->bytes_allocated = 0;
            }
            ac_integrity_baseline_release(baseline);
            continue;
        }

        if (write_index != read_index) {
            cache->items[write_index] = *baseline;
            memset(baseline, 0, sizeof(*baseline));
        }
        ++write_index;
    }
    cache->count = write_index;
}

static void ac_integrity_reset_baseline(
    AcIntegrityCache *cache,
    AcIntegrityBaseline *baseline)
{
    if (cache->bytes_allocated >= baseline->allocated_bytes) {
        cache->bytes_allocated -= baseline->allocated_bytes;
    } else {
        cache->bytes_allocated = 0;
    }
    ac_integrity_baseline_release(baseline);
    ac_pe_mask_init(&baseline->mask);
    baseline->unavailable = false;
    baseline->unavailable_reason = NULL;
    baseline->unavailable_since_scan_id = 0;
    baseline->identity_reported = false;
    baseline->manifest_reported = false;
}

static bool ac_integrity_file_identity_matches(
    const AcIntegrityBaseline *baseline)
{
    AcFileIdentity identity;

    if (!ac_query_file_identity(baseline->path, &identity)) {
        return false;
    }
    return identity.size == baseline->file_size &&
           identity.write_time == baseline->file_time &&
           identity.file_index == baseline->file_index &&
           identity.volume_serial == baseline->volume_serial;
}

/* Re-derives the expected bytes of one block so the exact modified RVA and the
   surrounding bytes can be reported. Only runs when a block already mismatched. */
static bool ac_integrity_locate_difference(
    AcContext *context,
    const AcIntegrityBaseline *baseline,
    const AcIntegritySection *section,
    const AcModule *module,
    uint32_t block_offset,
    uint32_t block_length,
    const uint8_t *observed,
    uint32_t *diff_offset_out,
    uint8_t *expected_out)
{
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    AcFileIdentity identity;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    AcPeImage image;
    const AcPeSection *pe_section;
    uint8_t *materialized = NULL;
    bool located = false;
    uint32_t index;

    if (!ac_read_file_bounded(
            module->path,
            context->policy.integrity_max_file_bytes,
            &file_data,
            &file_size,
            &identity,
            digest)) {
        return false;
    }

    if (ac_pe_parse(file_data, file_size, &image) != AC_PE_OK) {
        free(file_data);
        return false;
    }

    pe_section = ac_pe_find_section_by_rva(&image, section->rva);
    if (pe_section == NULL || pe_section->virtual_size != section->size) {
        free(file_data);
        return false;
    }

    materialized = (uint8_t *)malloc(pe_section->virtual_size);
    if (materialized == NULL) {
        free(file_data);
        return false;
    }

    if (ac_pe_materialize_section(
            &image,
            pe_section,
            materialized,
            pe_section->virtual_size) == AC_PE_OK) {
        AcPeMask scratch_mask;

        ac_pe_mask_init(&scratch_mask);
        if (ac_pe_apply_relocations(
                &image,
                pe_section,
                materialized,
                (int64_t)((uint64_t)module->base - image.image_base),
                &scratch_mask) == AC_PE_OK) {
            memcpy(expected_out, materialized + block_offset, block_length);
            ac_pe_mask_zero(
                &baseline->mask,
                expected_out,
                section->rva + block_offset,
                block_length);

            for (index = 0; index < block_length; ++index) {
                if (expected_out[index] != observed[index]) {
                    *diff_offset_out = index;
                    located = true;
                    break;
                }
            }
        }
        ac_pe_mask_free(&scratch_mask);
    }

    free(materialized);
    free(file_data);
    return located;
}

static void ac_integrity_report_section_block(
    AcContext *context,
    const AcTarget *target,
    const AcIntegrityBaseline *baseline,
    const AcIntegritySection *section,
    const AcModule *module,
    uint32_t block_offset,
    uint32_t block_length,
    const uint8_t *observed,
    const uint8_t *expected_hash,
    const uint8_t *observed_hash,
    uint64_t scan_id,
    AcScanStats *stats)
{
    char expected_hash_hex[AC_SHA256_HEX_SIZE];
    char observed_hash_hex[AC_SHA256_HEX_SIZE];
    char expected_bytes[AC_INTEGRITY_HEX_PREVIEW * 2u + 1u];
    char observed_bytes[AC_INTEGRITY_HEX_PREVIEW * 2u + 1u];
    char extra[768];
    uint8_t expected_block[AC_INTEGRITY_BLOCK_SIZE];
    uint32_t diff_offset = 0;
    uint32_t preview;
    bool located;

    ac_sha256_to_hex(expected_hash, expected_hash_hex);
    ac_sha256_to_hex(observed_hash, observed_hash_hex);

    located = ac_integrity_locate_difference(
        context,
        baseline,
        section,
        module,
        block_offset,
        block_length,
        observed,
        &diff_offset,
        expected_block);

    preview = block_length - diff_offset < AC_INTEGRITY_HEX_PREVIEW
        ? block_length - diff_offset
        : AC_INTEGRITY_HEX_PREVIEW;
    if (located) {
        ac_bytes_to_hex(expected_block + diff_offset, preview, expected_bytes);
        ac_bytes_to_hex(observed + diff_offset, preview, observed_bytes);
    } else {
        (void)strcpy_s(expected_bytes, sizeof(expected_bytes), "");
        (void)strcpy_s(observed_bytes, sizeof(observed_bytes), "");
    }

    if (located) {
        (void)snprintf(
            extra,
            sizeof(extra),
            "\"section\":\"%s\",\"block_rva\":\"0x%08x\",\"block_size\":%u,"
            "\"modified_rva\":\"0x%08x\",\"expected_sha256\":\"%s\","
            "\"observed_sha256\":\"%s\",\"expected_bytes\":\"%s\","
            "\"observed_bytes\":\"%s\","
            "\"reason\":\"executable_section_modified\",",
            section->name,
            section->rva + block_offset,
            block_length,
            section->rva + block_offset + diff_offset,
            expected_hash_hex,
            observed_hash_hex,
            expected_bytes,
            observed_bytes);
    } else {
        (void)snprintf(
            extra,
            sizeof(extra),
            "\"section\":\"%s\",\"block_rva\":\"0x%08x\",\"block_size\":%u,"
            "\"modified_rva\":null,\"expected_sha256\":\"%s\","
            "\"observed_sha256\":\"%s\","
            "\"reason\":\"executable_section_modified\",",
            section->name,
            section->rva + block_offset,
            block_length,
            expected_hash_hex,
            observed_hash_hex);
    }

    ac_integrity_report_module_event(
        context,
        target->pid,
        AC_SEVERITY_HIGH,
        "module_section_modified",
        baseline,
        scan_id,
        extra,
        stats);
}

static bool ac_integrity_compare_sections(
    AcContext *context,
    const AcTarget *target,
    AcIntegrityBaseline *baseline,
    const AcModule *module,
    uint64_t scan_id,
    AcScanStats *stats)
{
    size_t section_index;

    for (section_index = 0; section_index < baseline->section_count; ++section_index) {
        const AcIntegritySection *section = &baseline->sections[section_index];
        uint32_t block;

        for (block = 0; block < section->block_count; ++block) {
            const uint32_t offset = block * AC_INTEGRITY_BLOCK_SIZE;
            const uint32_t length = section->size - offset < AC_INTEGRITY_BLOCK_SIZE
                ? section->size - offset
                : AC_INTEGRITY_BLOCK_SIZE;
            const uint8_t *expected_hash =
                section->block_hashes + (size_t)block * AC_SHA256_DIGEST_SIZE;
            uint8_t observed_hash[AC_SHA256_DIGEST_SIZE];
            SIZE_T read_bytes = 0;

            if (stats->integrity_bytes >= context->policy.integrity_budget_bytes) {
                return false;
            }

            if (!ReadProcessMemory(
                    target->process,
                    (LPCVOID)(baseline->base + section->rva + offset),
                    context->integrity_block,
                    length,
                    &read_bytes) ||
                read_bytes != (SIZE_T)length) {
                ++stats->integrity_unreadable_blocks;
                continue;
            }

            stats->integrity_bytes += length;
            ++stats->integrity_blocks_checked;

            ac_pe_mask_zero(
                &baseline->mask,
                context->integrity_block,
                section->rva + offset,
                length);
            ac_sha256(context->integrity_block, length, observed_hash);

            if (memcmp(observed_hash, expected_hash, AC_SHA256_DIGEST_SIZE) == 0) {
                continue;
            }

            ++stats->integrity_blocks_modified;
            ac_integrity_report_section_block(
                context,
                target,
                baseline,
                section,
                module,
                offset,
                length,
                context->integrity_block,
                expected_hash,
                observed_hash,
                scan_id,
                stats);
        }
    }

    return true;
}

/* Walks the import thunk RVAs captured when the baseline was built, so a
   steady-state scan touches process memory only. */
static bool ac_integrity_check_imports(
    AcContext *context,
    const AcTarget *target,
    const AcIntegrityBaseline *baseline,
    uint64_t scan_id,
    AcScanStats *stats)
{
    /* Slot width follows the module, not the collector: a 64-bit collector
       inspecting a WOW64 module must read 4-byte thunks. */
    const SIZE_T slot_size = baseline->is_64bit ? 8u : 4u;
    size_t reported = 0;
    uint32_t index;

    if (baseline->iat_slot_rvas == NULL || baseline->iat_slot_count == 0) {
        return true;
    }

    for (index = 0; index < baseline->iat_slot_count; ++index) {
        const uint32_t slot_rva = baseline->iat_slot_rvas[index];
        uint64_t pointer = 0;
        SIZE_T read_bytes = 0;

        if (stats->integrity_bytes >= context->policy.integrity_budget_bytes ||
            reported >= AC_INTEGRITY_MAX_HOOK_EVENTS) {
            return stats->integrity_bytes < context->policy.integrity_budget_bytes;
        }

        if (!ReadProcessMemory(
                target->process,
                (LPCVOID)(baseline->base + slot_rva),
                &pointer,
                slot_size,
                &read_bytes) ||
            read_bytes != slot_size) {
            continue;
        }

        stats->integrity_bytes += (uint64_t)slot_size;
        ++stats->integrity_iat_slots_checked;

        if (pointer == 0 ||
            ac_range_index_contains(
                &context->module_ranges,
                (uintptr_t)pointer,
                1u)) {
            continue;
        }

        {
            char extra[320];

            ++stats->integrity_iat_hooks;
            ++reported;
            (void)snprintf(
                extra,
                sizeof(extra),
                "\"slot_rva\":\"0x%08x\",\"target\":\"0x%" PRIx64 "\","
                "\"delay_load\":%s,"
                "\"reason\":\"iat_entry_outside_loaded_modules\",",
                slot_rva,
                pointer,
                baseline->iat_delay_load != NULL &&
                        baseline->iat_delay_load[index] != 0
                    ? "true"
                    : "false");
            ac_integrity_report_module_event(
                context,
                target->pid,
                AC_SEVERITY_HIGH,
                "import_table_hook",
                baseline,
                scan_id,
                extra,
                stats);
        }
    }
    return true;
}

static bool ac_integrity_check_exports(
    AcContext *context,
    const AcTarget *target,
    const AcIntegrityBaseline *baseline,
    uint64_t scan_id,
    AcScanStats *stats)
{
    uint32_t index;
    size_t reported = 0;

    if (baseline->export_rvas == NULL || baseline->export_count == 0) {
        return true;
    }

    for (index = 0; index < baseline->export_count; ++index) {
        uint32_t observed = 0;
        SIZE_T read_bytes = 0;

        if (stats->integrity_bytes >= context->policy.integrity_budget_bytes ||
            reported >= AC_INTEGRITY_MAX_HOOK_EVENTS) {
            return stats->integrity_bytes < context->policy.integrity_budget_bytes;
        }

        if (!ReadProcessMemory(
                target->process,
                (LPCVOID)(baseline->base + baseline->export_table_rva + index * 4u),
                &observed,
                sizeof(observed),
                &read_bytes) ||
            read_bytes != sizeof(observed)) {
            continue;
        }

        stats->integrity_bytes += sizeof(observed);
        ++stats->integrity_export_slots_checked;

        if (observed == baseline->export_rvas[index] &&
            (observed == 0 || observed < baseline->size_of_image)) {
            continue;
        }

        {
            char extra[320];

            ++stats->integrity_export_hooks;
            ++reported;
            (void)snprintf(
                extra,
                sizeof(extra),
                "\"export_index\":%u,\"expected_rva\":\"0x%08x\","
                "\"observed_rva\":\"0x%08x\",\"outside_image\":%s,"
                "\"reason\":\"export_entry_modified\",",
                index,
                baseline->export_rvas[index],
                observed,
                observed >= baseline->size_of_image ? "true" : "false");
            ac_integrity_report_module_event(
                context,
                target->pid,
                AC_SEVERITY_HIGH,
                "export_table_hook",
                baseline,
                scan_id,
                extra,
                stats);
        }
    }
    return true;
}

void ac_verify_module_integrity(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats)
{
    size_t visited;
    size_t module_count;

    if (context == NULL || target == NULL || stats == NULL ||
        !context->policy.verify_module_integrity) {
        return;
    }

    ac_integrity_prune(&context->integrity, &context->modules);
    module_count = context->modules.count;
    if (module_count == 0) {
        return;
    }
    if (context->scans_completed == 0) {
        uint64_t random_start = 0;

        if (BCryptGenRandom(
                NULL,
                (PUCHAR)&random_start,
                (ULONG)sizeof(random_start),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0) {
            context->integrity_cursor = (size_t)(random_start % module_count);
        }
    }

    for (visited = 0; visited < module_count; ++visited) {
        const size_t module_index =
            (context->integrity_cursor + visited) % module_count;
        const AcModule *module = &context->modules.items[module_index];
        AcIntegrityBaseline *baseline;
        char path_utf8[MAX_PATH * 3];
        uint64_t path_hash;
        bool complete;

        if (stats->integrity_bytes >= context->policy.integrity_budget_bytes) {
            stats->integrity_modules_skipped += module_count - visited;
            break;
        }
        if (module->path[0] == L'\0') {
            ++stats->integrity_modules_skipped;
            continue;
        }

        if (!ac_wide_to_utf8(module->path, path_utf8, sizeof(path_utf8))) {
            ++stats->integrity_modules_skipped;
            continue;
        }
        path_hash = ac_fnv1a64_text_ci(AC_FNV1A64_OFFSET, path_utf8);

        baseline = ac_integrity_lookup(&context->integrity, module, path_hash);
        if (baseline == NULL) {
            if (context->integrity.bytes_allocated >=
                context->policy.integrity_baseline_budget_bytes) {
                ++stats->integrity_modules_skipped;
                continue;
            }
            baseline = ac_integrity_allocate(&context->integrity, module, path_hash);
            if (baseline == NULL) {
                ++stats->integrity_modules_skipped;
                continue;
            }
        }

        if (baseline->unavailable) {
            if (baseline->unavailable_since_scan_id != 0 &&
                scan_id - baseline->unavailable_since_scan_id <
                    AC_INTEGRITY_UNAVAILABLE_RETRY_SCANS) {
                ++stats->integrity_modules_skipped;
                continue;
            }
            ac_integrity_reset_baseline(&context->integrity, baseline);
        }

        if (baseline->ready &&
            !ac_integrity_file_identity_matches(baseline)) {
            char extra[192];

            ++stats->integrity_file_changes;
            (void)snprintf(
                extra,
                sizeof(extra),
                "\"previous_file_time\":%" PRIu64
                ",\"previous_file_index\":%" PRIu64
                ",\"reason\":\"module_file_identity_changed\",",
                baseline->file_time,
                baseline->file_index);
            ac_integrity_report_module_event(
                context,
                target->pid,
                AC_SEVERITY_HIGH,
                "module_file_identity_changed",
                baseline,
                scan_id,
                extra,
                stats);
            ac_integrity_reset_baseline(&context->integrity, baseline);
        }

        if (!baseline->ready) {
            if (!ac_integrity_build_baseline(context, baseline, module)) {
                char extra[256];

                ++stats->integrity_modules_unavailable;
                baseline->unavailable_since_scan_id = scan_id;
                (void)snprintf(
                    extra,
                    sizeof(extra),
                    "\"reason\":\"%s\",",
                    baseline->unavailable_reason != NULL
                        ? baseline->unavailable_reason
                        : "unknown");
                ac_integrity_report_module_event(
                    context,
                    target->pid,
                    AC_SEVERITY_LOW,
                    "module_integrity_unavailable",
                    baseline,
                    scan_id,
                    extra,
                    stats);
                continue;
            }
        }

        ac_integrity_report_identity(context, target, baseline, scan_id, stats);
        complete = ac_integrity_compare_sections(
            context,
            target,
            baseline,
            module,
            scan_id,
            stats);
        if (complete) {
            complete = ac_integrity_check_exports(
                context,
                target,
                baseline,
                scan_id,
                stats);
        }
        if (complete) {
            complete = ac_integrity_check_imports(
                context,
                target,
                baseline,
                scan_id,
                stats);
        }
        if (complete) {
            ++stats->integrity_modules_checked;
        } else {
            ++stats->integrity_modules_partial;
        }
    }

    context->integrity_cursor =
        (context->integrity_cursor + (visited == 0 ? 1u : visited)) % module_count;
}
