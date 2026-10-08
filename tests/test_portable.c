#include "dedup.h"
#include "ed25519.h"
#include "manifest_envelope.h"
#include "pe.h"
#include "ranges.h"
#include "schedule.h"
#include "sha256.h"
#include "text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void test_sha256_vectors(void)
{
    static const char *const inputs[] = {
        "",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };
    static const char *const expected[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    };
    size_t index;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    char hex[AC_SHA256_HEX_SIZE];

    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); ++index) {
        ac_sha256(inputs[index], strlen(inputs[index]), digest);
        ac_sha256_to_hex(digest, hex);
        AC_CHECK(strcmp(hex, expected[index]) == 0);
    }
}

static void test_sha256_streaming(void)
{
    static const char *const expected =
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    AcSha256 context;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    uint8_t chunk[1000];
    char hex[AC_SHA256_HEX_SIZE];
    unsigned int iteration;

    memset(chunk, 'a', sizeof(chunk));
    ac_sha256_init(&context);
    for (iteration = 0; iteration < 1000u; ++iteration) {
        ac_sha256_update(&context, chunk, sizeof(chunk));
    }
    ac_sha256_final(&context, digest);
    ac_sha256_to_hex(digest, hex);
    AC_CHECK(strcmp(hex, expected) == 0);

    ac_sha256_init(&context);
    ac_sha256_update(&context, "a", 1u);
    ac_sha256_update(&context, "b", 1u);
    ac_sha256_update(&context, "c", 1u);
    ac_sha256_final(&context, digest);
    ac_sha256_to_hex(digest, hex);
    AC_CHECK(strcmp(
                 hex,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

static void test_json_escaping(void)
{
    char output[64];
    char small[8];

    AC_CHECK(ac_json_escape("C:\\Game\\line\n\"quoted\"", output, sizeof(output)));
    AC_CHECK(strcmp(output, "C:\\\\Game\\\\line\\n\\\"quoted\\\"") == 0);

    AC_CHECK(ac_json_escape("\x01\x1f", output, sizeof(output)));
    AC_CHECK(strcmp(output, "\\u0001\\u001f") == 0);

    AC_CHECK(!ac_json_escape("aaaaaaaaaaaaaaaa", small, sizeof(small)));
    AC_CHECK(strlen(small) < sizeof(small));

    AC_CHECK(ac_json_escape(NULL, output, sizeof(output)));
    AC_CHECK(output[0] == '\0');
}

static void test_fnv1a(void)
{
    AC_CHECK(ac_fnv1a64("", 0) == 0xcbf29ce484222325ull);
    AC_CHECK(ac_fnv1a64("a", 1u) == 0xaf63dc4c8601ec8cull);
    AC_CHECK(ac_fnv1a64("foobar", 6u) == 0x85944171f73967e8ull);
    AC_CHECK(ac_fnv1a64_text_ci(AC_FNV1A64_OFFSET, "ABC") ==
             ac_fnv1a64_text_ci(AC_FNV1A64_OFFSET, "abc"));
    AC_CHECK(ac_fnv1a64_text(AC_FNV1A64_OFFSET, "ABC") !=
             ac_fnv1a64_text(AC_FNV1A64_OFFSET, "abc"));
}

static void test_range_index(void)
{
    AcRangeIndex index;

    ac_range_index_init(&index);
    AC_CHECK(!ac_range_index_contains(&index, 0x1000u, 0x10u));

    AC_CHECK(ac_range_index_add(&index, 0x10000000u, 0x10000u));
    AC_CHECK(ac_range_index_add(&index, 0x20000000u, 0x1000u));
    AC_CHECK(!ac_range_index_add(&index, 0x30000000u, 0));

    AC_CHECK(!ac_range_index_contains(&index, 0x10000000u, 0x1000u));
    ac_range_index_finalize(&index);

    AC_CHECK(ac_range_index_contains(&index, 0x10000000u, 0x1000u));
    AC_CHECK(ac_range_index_contains(&index, 0x1000f000u, 0x1000u));
    AC_CHECK(ac_range_index_contains(&index, 0x20000000u, 0x1000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x0ffff000u, 0x2000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x1000f000u, 0x2000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x18000000u, 0x1000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x10000000u, 0));

    ac_range_index_free(&index);
}

static void test_range_index_merges_overlaps(void)
{
    AcRangeIndex index;

    ac_range_index_init(&index);
    AC_CHECK(ac_range_index_add(&index, 0x2000u, 0x1000u));
    AC_CHECK(ac_range_index_add(&index, 0x1000u, 0x1800u));
    AC_CHECK(ac_range_index_add(&index, 0x1000u, 0x400u));
    ac_range_index_finalize(&index);

    AC_CHECK(index.count == 1u);
    AC_CHECK(index.items[0].base == 0x1000u);
    AC_CHECK(index.items[0].end == 0x3000u);
    AC_CHECK(ac_range_index_contains(&index, 0x1000u, 0x2000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x1000u, 0x2001u));

    ac_range_index_free(&index);
}

static void test_range_index_many_entries(void)
{
    AcRangeIndex index;
    uintptr_t offset;

    ac_range_index_init(&index);
    for (offset = 0; offset < 5000u; ++offset) {
        AC_CHECK(ac_range_index_add(&index, 0x100000u + offset * 0x2000u, 0x1000u));
    }
    ac_range_index_finalize(&index);

    AC_CHECK(index.count == 5000u);
    AC_CHECK(ac_range_index_contains(&index, 0x100000u, 0x1000u));
    AC_CHECK(ac_range_index_contains(&index, 0x100000u + 4999u * 0x2000u, 0x1000u));
    AC_CHECK(!ac_range_index_contains(&index, 0x100000u + 0x1000u, 0x1000u));

    ac_range_index_free(&index);
}

static void test_dedup_suppresses_repeats(void)
{
    AcDedup dedup;
    AcDedupDecision decision;

    AC_CHECK(ac_dedup_init(&dedup, 64u, 1000u));

    ac_dedup_observe(&dedup, 0x1234u, 1u, 0u, &decision);
    AC_CHECK(decision.emit);
    AC_CHECK(decision.first_seen);
    AC_CHECK(decision.occurrences == 1u);

    ac_dedup_observe(&dedup, 0x1234u, 2u, 100u, &decision);
    AC_CHECK(!decision.emit);
    AC_CHECK(!decision.first_seen);
    AC_CHECK(decision.occurrences == 2u);
    AC_CHECK(decision.first_scan_id == 1u);

    ac_dedup_observe(&dedup, 0x1234u, 3u, 500u, &decision);
    AC_CHECK(!decision.emit);

    ac_dedup_observe(&dedup, 0x1234u, 4u, 1000u, &decision);
    AC_CHECK(decision.emit);
    AC_CHECK(decision.occurrences == 4u);
    AC_CHECK(decision.suppressed_since_last_emit == 2u);

    ac_dedup_observe(&dedup, 0x9999u, 5u, 1000u, &decision);
    AC_CHECK(decision.emit);
    AC_CHECK(decision.first_seen);

    AC_CHECK(dedup.suppressed_total == 2u);
    AC_CHECK(dedup.used == 2u);

    ac_dedup_free(&dedup);
}

static void test_dedup_never_repeats_with_zero_interval(void)
{
    AcDedup dedup;
    AcDedupDecision decision;

    AC_CHECK(ac_dedup_init(&dedup, 8u, 0u));

    ac_dedup_observe(&dedup, 7u, 1u, 0u, &decision);
    AC_CHECK(decision.emit);
    ac_dedup_observe(&dedup, 7u, 2u, 1000000u, &decision);
    AC_CHECK(!decision.emit);

    ac_dedup_free(&dedup);
}

static void test_dedup_fails_open_when_saturated(void)
{
    AcDedup dedup;
    AcDedupDecision decision;
    uint64_t fingerprint;
    size_t emitted = 0;

    AC_CHECK(ac_dedup_init(&dedup, 16u, 60000u));

    for (fingerprint = 1u; fingerprint <= 200u; ++fingerprint) {
        ac_dedup_observe(&dedup, fingerprint, 1u, 0u, &decision);
        if (decision.emit) {
            ++emitted;
        }
    }

    AC_CHECK(emitted == 200u);
    AC_CHECK(dedup.saturated_events > 0u);
    AC_CHECK(dedup.used <= dedup.capacity);

    ac_dedup_free(&dedup);
}

#define AC_TEST_PE_SIZE 0x800u
#define AC_TEST_PE_NT_OFFSET 0x40u
#define AC_TEST_PE_OPTIONAL_OFFSET 0x58u
#define AC_TEST_PE_TEXT_RAW 0x200u
#define AC_TEST_PE_TEXT_RVA 0x1000u
#define AC_TEST_PE_RDATA_RAW 0x400u
#define AC_TEST_PE_RDATA_RVA 0x2000u
#define AC_TEST_PE_RELOC_RAW 0x600u
#define AC_TEST_PE_RELOC_RVA 0x3000u
#define AC_TEST_PE_IAT_RVA 0x2100u
#define AC_TEST_PE_RELOC_TARGET 0x10u
#define AC_TEST_PE_IMAGE_BASE 0x140000000ull

static void ac_test_put16(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1u] = (uint8_t)(value >> 8);
}

static void ac_test_put32(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1u] = (uint8_t)(value >> 8);
    buffer[offset + 2u] = (uint8_t)(value >> 16);
    buffer[offset + 3u] = (uint8_t)(value >> 24);
}

static void ac_test_put64(uint8_t *buffer, size_t offset, uint64_t value)
{
    ac_test_put32(buffer, offset, (uint32_t)value);
    ac_test_put32(buffer, offset + 4u, (uint32_t)(value >> 32));
}

static uint64_t ac_test_get64(const uint8_t *buffer, size_t offset)
{
    uint64_t value = 0;
    unsigned int index;

    for (index = 0; index < 8u; ++index) {
        value |= (uint64_t)buffer[offset + index] << (8u * index);
    }
    return value;
}

static void ac_test_put_section(
    uint8_t *buffer,
    size_t offset,
    const char *name,
    uint32_t virtual_size,
    uint32_t virtual_address,
    uint32_t raw_size,
    uint32_t raw_offset,
    uint32_t characteristics)
{
    memset(buffer + offset, 0, 8u);
    memcpy(buffer + offset, name, strlen(name));
    ac_test_put32(buffer, offset + 8u, virtual_size);
    ac_test_put32(buffer, offset + 12u, virtual_address);
    ac_test_put32(buffer, offset + 16u, raw_size);
    ac_test_put32(buffer, offset + 20u, raw_offset);
    ac_test_put32(buffer, offset + 36u, characteristics);
}

/* Builds a minimal but structurally valid PE32+ image with one executable
   section, one import address table and one DIR64 base relocation. */
static void ac_test_build_pe(uint8_t *buffer)
{
    const size_t optional = AC_TEST_PE_OPTIONAL_OFFSET;
    const size_t directories = optional + 112u;
    const size_t sections = optional + 240u;
    unsigned int index;

    memset(buffer, 0, AC_TEST_PE_SIZE);

    ac_test_put16(buffer, 0, 0x5a4du);
    ac_test_put32(buffer, 0x3cu, AC_TEST_PE_NT_OFFSET);

    ac_test_put32(buffer, AC_TEST_PE_NT_OFFSET, 0x00004550u);
    ac_test_put16(buffer, AC_TEST_PE_NT_OFFSET + 4u, 0x8664u);
    ac_test_put16(buffer, AC_TEST_PE_NT_OFFSET + 6u, 3u);
    ac_test_put16(buffer, AC_TEST_PE_NT_OFFSET + 20u, 240u);

    ac_test_put16(buffer, optional, 0x020bu);
    ac_test_put32(buffer, optional + 16u, AC_TEST_PE_TEXT_RVA);
    ac_test_put64(buffer, optional + 24u, AC_TEST_PE_IMAGE_BASE);
    ac_test_put32(buffer, optional + 56u, 0x4000u);
    ac_test_put32(buffer, optional + 60u, 0x200u);
    ac_test_put32(buffer, optional + 108u, 16u);

    ac_test_put32(buffer, directories + 1u * 8u, AC_TEST_PE_RDATA_RVA);
    ac_test_put32(buffer, directories + 1u * 8u + 4u, 40u);
    ac_test_put32(buffer, directories + 5u * 8u, AC_TEST_PE_RELOC_RVA);
    ac_test_put32(buffer, directories + 5u * 8u + 4u, 12u);
    ac_test_put32(buffer, directories + 12u * 8u, AC_TEST_PE_IAT_RVA);
    ac_test_put32(buffer, directories + 12u * 8u + 4u, 16u);

    ac_test_put_section(
        buffer, sections, ".text",
        0x200u, AC_TEST_PE_TEXT_RVA, 0x200u, AC_TEST_PE_TEXT_RAW,
        AC_PE_SCN_CNT_CODE | AC_PE_SCN_MEM_EXECUTE);
    ac_test_put_section(
        buffer, sections + 40u, ".rdata",
        0x200u, AC_TEST_PE_RDATA_RVA, 0x200u, AC_TEST_PE_RDATA_RAW,
        0x40000040u);
    ac_test_put_section(
        buffer, sections + 80u, ".reloc",
        0x200u, AC_TEST_PE_RELOC_RVA, 0x200u, AC_TEST_PE_RELOC_RAW,
        0x42000040u);

    for (index = 0; index < 0x200u; ++index) {
        buffer[AC_TEST_PE_TEXT_RAW + index] = (uint8_t)(0x90u + (index & 0x0fu));
    }
    ac_test_put64(
        buffer,
        AC_TEST_PE_TEXT_RAW + AC_TEST_PE_RELOC_TARGET,
        AC_TEST_PE_IMAGE_BASE + AC_TEST_PE_TEXT_RVA);

    /* Import descriptor followed by the terminating zero descriptor. */
    ac_test_put32(buffer, AC_TEST_PE_RDATA_RAW + 12u, AC_TEST_PE_RDATA_RVA + 0x80u);
    ac_test_put32(buffer, AC_TEST_PE_RDATA_RAW + 16u, AC_TEST_PE_IAT_RVA);

    ac_test_put64(buffer, AC_TEST_PE_RDATA_RAW + 0x100u, 0x7ff800001234ull);
    ac_test_put64(buffer, AC_TEST_PE_RDATA_RAW + 0x108u, 0x7ff800005678ull);

    ac_test_put32(buffer, AC_TEST_PE_RELOC_RAW, AC_TEST_PE_TEXT_RVA);
    ac_test_put32(buffer, AC_TEST_PE_RELOC_RAW + 4u, 12u);
    ac_test_put16(buffer, AC_TEST_PE_RELOC_RAW + 8u, (uint16_t)((10u << 12) | AC_TEST_PE_RELOC_TARGET));
    ac_test_put16(buffer, AC_TEST_PE_RELOC_RAW + 10u, 0);
}

static void test_pe_parses_valid_image(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    AcPeImage image;
    const AcPeSection *section;
    uint32_t offset = 0;

    ac_test_build_pe(buffer);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);
    AC_CHECK(image.is_64bit);
    AC_CHECK(image.machine == 0x8664u);
    AC_CHECK(image.section_count == 3u);
    AC_CHECK(image.image_base == AC_TEST_PE_IMAGE_BASE);
    AC_CHECK(image.size_of_image == 0x4000u);
    AC_CHECK(image.entry_point == AC_TEST_PE_TEXT_RVA);
    AC_CHECK(image.directories[AC_PE_DIRECTORY_IAT].rva == AC_TEST_PE_IAT_RVA);

    section = ac_pe_find_section_by_rva(&image, AC_TEST_PE_TEXT_RVA + 0x20u);
    AC_CHECK(section != NULL);
    if (section != NULL) {
        AC_CHECK(strcmp(section->name, ".text") == 0);
        AC_CHECK(ac_pe_section_is_executable(section));
    }

    section = ac_pe_find_section_by_rva(&image, AC_TEST_PE_RDATA_RVA);
    AC_CHECK(section != NULL);
    if (section != NULL) {
        AC_CHECK(!ac_pe_section_is_executable(section));
    }

    AC_CHECK(ac_pe_find_section_by_rva(&image, 0x9000u) == NULL);

    AC_CHECK(ac_pe_rva_to_offset(&image, AC_TEST_PE_TEXT_RVA + 0x10u, &offset));
    AC_CHECK(offset == AC_TEST_PE_TEXT_RAW + 0x10u);
    AC_CHECK(!ac_pe_rva_to_offset(&image, 0x9000u, &offset));
}

static void test_pe_materializes_and_rebases_section(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    uint8_t section_image[0x200];
    AcPeImage image;
    AcPeMask mask;
    const AcPeSection *text;
    const int64_t delta = 0x1000000;

    ac_test_build_pe(buffer);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);

    text = ac_pe_find_section_by_rva(&image, AC_TEST_PE_TEXT_RVA);
    AC_CHECK(text != NULL);
    if (text == NULL) {
        return;
    }

    AC_CHECK(ac_pe_materialize_section(&image, text, section_image, sizeof(section_image)) == AC_PE_OK);
    AC_CHECK(memcmp(section_image, buffer + AC_TEST_PE_TEXT_RAW, sizeof(section_image)) == 0);
    AC_CHECK(ac_test_get64(section_image, AC_TEST_PE_RELOC_TARGET) ==
             AC_TEST_PE_IMAGE_BASE + AC_TEST_PE_TEXT_RVA);

    ac_pe_mask_init(&mask);
    AC_CHECK(ac_pe_apply_relocations(&image, text, section_image, delta, &mask) == AC_PE_OK);
    AC_CHECK(ac_test_get64(section_image, AC_TEST_PE_RELOC_TARGET) ==
             AC_TEST_PE_IMAGE_BASE + AC_TEST_PE_TEXT_RVA + (uint64_t)delta);
    AC_CHECK(section_image[0] == 0x90u);

    /* A zero delta must leave the section untouched. */
    AC_CHECK(ac_pe_materialize_section(&image, text, section_image, sizeof(section_image)) == AC_PE_OK);
    AC_CHECK(ac_pe_apply_relocations(&image, text, section_image, 0, &mask) == AC_PE_OK);
    AC_CHECK(memcmp(section_image, buffer + AC_TEST_PE_TEXT_RAW, sizeof(section_image)) == 0);

    ac_pe_mask_free(&mask);
}

static void test_pe_masks_import_tables(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    uint8_t window[32];
    AcPeImage image;
    AcPeMask mask;

    ac_test_build_pe(buffer);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);

    ac_pe_mask_init(&mask);
    AC_CHECK(ac_pe_mask_import_tables(&image, &mask) == AC_PE_OK);
    ac_pe_mask_finalize(&mask);

    AC_CHECK(ac_pe_mask_covers(&mask, AC_TEST_PE_IAT_RVA));
    AC_CHECK(ac_pe_mask_covers(&mask, AC_TEST_PE_IAT_RVA + 15u));
    AC_CHECK(!ac_pe_mask_covers(&mask, AC_TEST_PE_IAT_RVA + 16u));
    AC_CHECK(!ac_pe_mask_covers(&mask, AC_TEST_PE_TEXT_RVA));

    memset(window, 0xabu, sizeof(window));
    ac_pe_mask_zero(&mask, window, AC_TEST_PE_IAT_RVA - 8u, sizeof(window));
    AC_CHECK(window[0] == 0xabu);
    AC_CHECK(window[7] == 0xabu);
    AC_CHECK(window[8] == 0x00u);
    AC_CHECK(window[23] == 0x00u);
    AC_CHECK(window[24] == 0xabu);

    ac_pe_mask_free(&mask);
}

static bool ac_test_count_iat_slot(void *user, uint32_t slot_rva, bool delay_load)
{
    unsigned int *counter = (unsigned int *)user;

    (void)delay_load;
    if (slot_rva < AC_TEST_PE_IAT_RVA) {
        return false;
    }
    ++(*counter);
    return true;
}

static void test_pe_enumerates_iat_slots(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    AcPeImage image;
    unsigned int slots = 0;
    uint32_t table_rva = 0;
    uint32_t count = 0;

    ac_test_build_pe(buffer);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);
    AC_CHECK(ac_pe_for_each_iat_slot(&image, ac_test_count_iat_slot, &slots) == AC_PE_OK);
    AC_CHECK(slots == 2u);

    AC_CHECK(ac_pe_export_functions(&image, &table_rva, &count) == AC_PE_OK);
    AC_CHECK(table_rva == 0);
    AC_CHECK(count == 0);
}

/* Every prefix of a valid image, and a set of corrupted headers, must be
   rejected without reading outside the supplied buffer. Run under ASan this
   is the bounds proof required by the acceptance criteria. */
static void test_pe_rejects_malformed_input_without_overrun(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    AcPeImage image;
    size_t length;
    size_t position;

    ac_test_build_pe(buffer);

    for (length = 0; length < sizeof(buffer); ++length) {
        uint8_t *prefix = (uint8_t *)malloc(length == 0 ? 1u : length);

        AC_CHECK(prefix != NULL);
        if (prefix == NULL) {
            return;
        }
        if (length > 0) {
            memcpy(prefix, buffer, length);
        }

        if (ac_pe_parse(prefix, length, &image) == AC_PE_OK) {
            AcPeMask mask;
            uint16_t index;

            ac_pe_mask_init(&mask);
            (void)ac_pe_mask_import_tables(&image, &mask);
            for (index = 0; index < image.section_count; ++index) {
                uint8_t scratch[0x200];
                const AcPeSection *section = &image.sections[index];

                if (section->virtual_size <= sizeof(scratch)) {
                    if (ac_pe_materialize_section(
                            &image, section, scratch, sizeof(scratch)) == AC_PE_OK) {
                        (void)ac_pe_apply_relocations(&image, section, scratch, 0x1000, &mask);
                    }
                }
            }
            ac_pe_mask_free(&mask);
        }
        free(prefix);
    }

    for (position = 0; position < 0x200u; ++position) {
        uint8_t corrupted[AC_TEST_PE_SIZE];
        AcPeMask mask;

        ac_test_build_pe(corrupted);
        corrupted[position] = (uint8_t)(corrupted[position] ^ 0xffu);

        ac_pe_mask_init(&mask);
        if (ac_pe_parse(corrupted, sizeof(corrupted), &image) == AC_PE_OK) {
            uint8_t scratch[0x200];
            uint16_t index;

            (void)ac_pe_mask_import_tables(&image, &mask);
            for (index = 0; index < image.section_count; ++index) {
                const AcPeSection *section = &image.sections[index];

                if (section->virtual_size <= sizeof(scratch) &&
                    ac_pe_materialize_section(
                        &image, section, scratch, sizeof(scratch)) == AC_PE_OK) {
                    (void)ac_pe_apply_relocations(&image, section, scratch, -0x2000, &mask);
                }
            }
        }
        ac_pe_mask_free(&mask);
    }

    AC_CHECK(ac_pe_parse(NULL, 0, &image) == AC_PE_ERR_TRUNCATED);
    AC_CHECK(ac_pe_parse(buffer, 4u, &image) == AC_PE_ERR_TRUNCATED);
}

static void test_pe_rejects_non_pe_and_unsupported(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    AcPeImage image;

    ac_test_build_pe(buffer);
    buffer[0] = 'X';
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_NOT_PE);

    ac_test_build_pe(buffer);
    ac_test_put32(buffer, AC_TEST_PE_NT_OFFSET, 0x12345678u);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_NOT_PE);

    ac_test_build_pe(buffer);
    ac_test_put16(buffer, AC_TEST_PE_OPTIONAL_OFFSET, 0x0107u);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_UNSUPPORTED);

    ac_test_build_pe(buffer);
    ac_test_put16(buffer, AC_TEST_PE_NT_OFFSET + 6u, 0);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_UNSUPPORTED);

    ac_test_build_pe(buffer);
    ac_test_put16(buffer, AC_TEST_PE_NT_OFFSET + 6u, 4096u);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_UNSUPPORTED);

    ac_test_build_pe(buffer);
    ac_test_put32(buffer, 0x3cu, 0x7ffffff0u);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_ERR_TRUNCATED);
}

static void test_pe_relocation_block_loop_is_bounded(void)
{
    uint8_t buffer[AC_TEST_PE_SIZE];
    uint8_t section_image[0x200];
    AcPeImage image;
    AcPeMask mask;
    const AcPeSection *text;

    /* A zero-length relocation block must not loop forever. */
    ac_test_build_pe(buffer);
    ac_test_put32(buffer, AC_TEST_PE_RELOC_RAW + 4u, 0);
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);
    text = ac_pe_find_section_by_rva(&image, AC_TEST_PE_TEXT_RVA);
    AC_CHECK(text != NULL);
    if (text == NULL) {
        return;
    }

    ac_pe_mask_init(&mask);
    AC_CHECK(ac_pe_materialize_section(&image, text, section_image, sizeof(section_image)) == AC_PE_OK);
    AC_CHECK(ac_pe_apply_relocations(&image, text, section_image, 0x1000, &mask) ==
             AC_PE_ERR_MALFORMED);

    /* An unknown relocation type must be masked rather than applied. */
    ac_pe_mask_clear(&mask);
    ac_test_build_pe(buffer);
    ac_test_put16(
        buffer,
        AC_TEST_PE_RELOC_RAW + 8u,
        (uint16_t)((7u << 12) | AC_TEST_PE_RELOC_TARGET));
    AC_CHECK(ac_pe_parse(buffer, sizeof(buffer), &image) == AC_PE_OK);
    text = ac_pe_find_section_by_rva(&image, AC_TEST_PE_TEXT_RVA);
    AC_CHECK(text != NULL);
    if (text != NULL) {
        AC_CHECK(ac_pe_materialize_section(&image, text, section_image, sizeof(section_image)) == AC_PE_OK);
        AC_CHECK(ac_pe_apply_relocations(&image, text, section_image, 0x1000, &mask) == AC_PE_OK);
        ac_pe_mask_finalize(&mask);
        AC_CHECK(ac_pe_mask_covers(&mask, AC_TEST_PE_TEXT_RVA + AC_TEST_PE_RELOC_TARGET));
        AC_CHECK(ac_test_get64(section_image, AC_TEST_PE_RELOC_TARGET) ==
                 AC_TEST_PE_IMAGE_BASE + AC_TEST_PE_TEXT_RVA);
    }

    ac_pe_mask_free(&mask);
}

static void test_schedule_delay_bounds(void)
{
    AC_CHECK(ac_schedule_delay_from_random(4000u, 6000u, 0u) == 4000u);
    AC_CHECK(ac_schedule_delay_from_random(4000u, 6000u, 2000u) == 6000u);
    AC_CHECK(ac_schedule_delay_from_random(4000u, 6000u, 2001u) == 4000u);
    AC_CHECK(ac_schedule_delay_from_random(5000u, 4000u, 42u) == 5000u);
}

static void test_schedule_permutation(void)
{
    bool observed[65];
    size_t position;
    const size_t step = ac_schedule_coprime_step(65u, 10u);

    memset(observed, 0, sizeof(observed));
    AC_CHECK(step > 0u && step < 65u);
    for (position = 0; position < 65u; ++position) {
        const size_t index = ac_schedule_permutation_index(
            position, 65u, 37u, step);
        AC_CHECK(index < 65u);
        if (index >= 65u) {
            return;
        }
        AC_CHECK(!observed[index]);
        observed[index] = true;
    }
    for (position = 0; position < 65u; ++position) {
        AC_CHECK(observed[position]);
    }
}

static void test_schedule_singleton(void)
{
    AC_CHECK(ac_schedule_coprime_step(0u, 99u) == 1u);
    AC_CHECK(ac_schedule_coprime_step(1u, 99u) == 1u);
    AC_CHECK(ac_schedule_permutation_index(100u, 1u, 88u, 1u) == 0u);
    AC_CHECK(ac_schedule_permutation_index(100u, 0u, 88u, 1u) == 0u);
}

static void test_schedule_fair_windows(void)
{
    bool visited[129];
    size_t cursor = 73u;
    size_t epoch;

    memset(visited, 0, sizeof(visited));
    for (epoch = 0; epoch < 3u; ++epoch) {
        size_t position;
        for (position = 0; position < 64u; ++position) {
            visited[ac_schedule_cyclic_index(position, 129u, cursor)] = true;
        }
        cursor = ac_schedule_cyclic_index(64u, 129u, cursor);
    }
    for (epoch = 0; epoch < 129u; ++epoch) {
        AC_CHECK(visited[epoch]);
    }
    AC_CHECK(visited[128]); /* A high-address payload after 128 decoys is visited. */
}

static uint8_t ac_test_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    AC_CHECK(value >= 'a' && value <= 'f');
    return (uint8_t)(value - 'a' + 10);
}

static void ac_test_hex(const char *text, uint8_t *bytes, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        bytes[index] = (uint8_t)((ac_test_nibble(text[index * 2u]) << 4u) |
                                 ac_test_nibble(text[index * 2u + 1u]));
    }
}

static bool ac_test_sha512_matches(const void *data, size_t length, const char *expected)
{
    uint8_t digest[AC_SHA512_DIGEST_SIZE];
    uint8_t wanted[AC_SHA512_DIGEST_SIZE];

    ac_sha512(data, length, digest);
    ac_test_hex(expected, wanted, sizeof(wanted));
    return memcmp(digest, wanted, sizeof(digest)) == 0;
}

static void test_sha512_vectors(void)
{
    static const char two_block[] =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    AcSha512 context;
    uint8_t digest[AC_SHA512_DIGEST_SIZE];
    uint8_t wanted[AC_SHA512_DIGEST_SIZE];
    uint8_t chunk[1000];
    unsigned int iteration;

    AC_CHECK(ac_test_sha512_matches(
        "",
        0u,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
    AC_CHECK(ac_test_sha512_matches(
        two_block,
        sizeof(two_block) - 1u,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));

    memset(chunk, 'a', sizeof(chunk));
    ac_sha512_init(&context);
    for (iteration = 0; iteration < 1000u; ++iteration) {
        ac_sha512_update(&context, chunk, sizeof(chunk));
    }
    ac_sha512_final(&context, digest);
    ac_test_hex(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        wanted,
        sizeof(wanted));
    AC_CHECK(memcmp(digest, wanted, sizeof(digest)) == 0);
}

static void test_ed25519_rfc8032(void)
{
    static const struct {
        const char *public_key;
        const char *message;
        const char *signature;
    } vectors[] = {
        {
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        }
    };
    size_t index;

    for (index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE];
        uint8_t signature[AC_ED25519_SIGNATURE_SIZE];
        uint8_t message[2];
        const size_t message_length = strlen(vectors[index].message) / 2u;

        ac_test_hex(vectors[index].public_key, public_key, sizeof(public_key));
        ac_test_hex(vectors[index].signature, signature, sizeof(signature));
        ac_test_hex(vectors[index].message, message, message_length);
        AC_CHECK(ac_ed25519_verify(signature, message, message_length, public_key));

        signature[0] = (uint8_t)(signature[0] ^ 0x01u);
        AC_CHECK(!ac_ed25519_verify(signature, message, message_length, public_key));
        signature[0] = (uint8_t)(signature[0] ^ 0x01u);
        signature[40] = (uint8_t)(signature[40] ^ 0x80u);
        AC_CHECK(!ac_ed25519_verify(signature, message, message_length, public_key));
        signature[40] = (uint8_t)(signature[40] ^ 0x80u);
        if (message_length != 0) {
            message[0] = (uint8_t)(message[0] ^ 0x01u);
            AC_CHECK(!ac_ed25519_verify(signature, message, message_length, public_key));
            message[0] = (uint8_t)(message[0] ^ 0x01u);
        }
        public_key[3] = (uint8_t)(public_key[3] ^ 0x10u);
        AC_CHECK(!ac_ed25519_verify(signature, message, message_length, public_key));
    }
}

static void test_ed25519_rejects_malleable_scalar(void)
{
    /* Adding the group order L to S yields an equivalent but non-canonical signature. */
    static const uint8_t order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE];
    uint8_t signature[AC_ED25519_SIGNATURE_SIZE];
    unsigned int carry = 0;
    size_t index;

    ac_test_hex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        public_key,
        sizeof(public_key));
    ac_test_hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        signature,
        sizeof(signature));
    for (index = 0; index < 32u; ++index) {
        const unsigned int sum = signature[32u + index] + order[index] + carry;
        signature[32u + index] = (uint8_t)sum;
        carry = sum >> 8u;
    }
    AC_CHECK(carry == 0u);
    AC_CHECK(!ac_ed25519_verify(signature, NULL, 0u, public_key));
    AC_CHECK(!ac_ed25519_verify(signature, NULL, 1u, public_key));
}

/* Fixtures signed with tools/manifest_tool.py using seeds 00..1f (A) and 20..3f (B). */
static const char g_manifest_key_a[] =
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
static const char g_manifest_key_b[] =
    "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";

static const char g_manifest_v2_key_a[] =
    "ac-manifest-v2\n"
    "application game\n"
    "build-id ababababababababababababababababababababababababababababa"
    "bababab\n"
    "sequence 7\n"
    "not-before 1700000000\n"
    "not-after 1900000000\n"
    "module 11111111111111111111111111111111111111111111111111111111111"
    "11111 game.exe\n"
    "module 22222222222222222222222222222222222222222222222222222222222"
    "22222 client.dll\n"
    "driver 33333333333333333333333333333333333333333333333333333333333"
    "33333 AcTelemetry.sys\n"
    "signature ed25519 56475aa75463474c c4be9ee75ab389b6c6469d503f82c1e"
    "7e014b7d9d9329d2f570680d891a7d1b3863fde2f6265d87b4aa2f8740603e0439"
    "39b4785d8dcf3ec39387899bd40f30e\n";

static const char g_manifest_v2_key_b[] =
    "ac-manifest-v2\n"
    "application game\n"
    "build-id ababababababababababababababababababababababababababababa"
    "bababab\n"
    "sequence 8\n"
    "not-before 1700000000\n"
    "not-after 1900000000\n"
    "module 11111111111111111111111111111111111111111111111111111111111"
    "11111 game.exe\n"
    "signature ed25519 24f6ed6acbfe1009 71806e773139b9ea24efbfe1121bf1b"
    "d4a09063ae469de715a06433600a31e6f0770da1379be3fd35046409c7db1c8c01"
    "f94aaefce76a8dcd492449aeba0ba0b\n";

/* Correctly signed, but "sequence 07" is not a canonical decimal. */
static const char g_manifest_v2_noncanonical[] =
    "ac-manifest-v2\n"
    "application game\n"
    "build-id ababababababababababababababababababababababababababababa"
    "bababab\n"
    "sequence 07\n"
    "not-before 1700000000\n"
    "not-after 1900000000\n"
    "module 11111111111111111111111111111111111111111111111111111111111"
    "11111 game.exe\n"
    "signature ed25519 56475aa75463474c bbd99cae38bbfa56fb04e096f5a33f5"
    "770a48dae6a6fc7aab765f003a9aab5dc44a53b4b2d6cb8bb45dc75d8e054cda85"
    "d91e7d7be3ba51f76df1b13cb914708\n";

typedef struct AcTestManifestSink {
    size_t modules;
    size_t drivers;
    size_t reject_after;
    bool saw_driver_name;
    uint8_t first_digest[AC_SHA256_DIGEST_SIZE];
} AcTestManifestSink;

static bool ac_test_manifest_entry(
    void *user,
    AcManifestEnvelopeEntryKind kind,
    const uint8_t sha256[AC_SHA256_DIGEST_SIZE],
    const char *file_name)
{
    AcTestManifestSink *sink = (AcTestManifestSink *)user;
    const size_t seen = sink->modules + sink->drivers;

    if (seen == 0) {
        memcpy(sink->first_digest, sha256, AC_SHA256_DIGEST_SIZE);
    }
    if (sink->reject_after != 0 && seen >= sink->reject_after) {
        return false;
    }
    if (kind == AC_MANIFEST_ENVELOPE_DRIVER) {
        ++sink->drivers;
        sink->saw_driver_name = strcmp(file_name, "AcTelemetry.sys") == 0;
    } else {
        ++sink->modules;
    }
    return true;
}

static AcManifestEnvelopeStatus ac_test_verify_manifest(
    const char *text,
    size_t length,
    const char *const *keys,
    size_t key_count,
    uint64_t now,
    uint64_t minimum_sequence,
    AcManifestEnvelope *envelope,
    AcTestManifestSink *sink)
{
    uint8_t public_keys[2][AC_ED25519_PUBLIC_KEY_SIZE];
    AcManifestEnvelopeTrust trust;
    size_t index;

    for (index = 0; index < key_count && index < 2u; ++index) {
        ac_test_hex(keys[index], public_keys[index], AC_ED25519_PUBLIC_KEY_SIZE);
    }
    trust.public_keys = (const uint8_t (*)[AC_ED25519_PUBLIC_KEY_SIZE])public_keys;
    trust.key_count = key_count;
    trust.now_unix = now;
    trust.minimum_sequence = minimum_sequence;
    return ac_manifest_envelope_verify(
        (const uint8_t *)text,
        length,
        &trust,
        envelope,
        ac_test_manifest_entry,
        sink);
}

static void test_manifest_envelope_valid(void)
{
    const char *const keys[] = {g_manifest_key_a};
    AcManifestEnvelope envelope;
    AcTestManifestSink sink;
    char key_id[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE];
    uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE];

    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a,
                 sizeof(g_manifest_v2_key_a) - 1u,
                 keys,
                 1u,
                 1800000000u,
                 7u,
                 &envelope,
                 &sink) == AC_MANIFEST_ENVELOPE_OK);
    AC_CHECK(strcmp(envelope.application, "game") == 0);
    AC_CHECK(strcmp(
                 envelope.build_id,
                 "abababababababababababababababababababababababababababababababab") == 0);
    AC_CHECK(envelope.sequence == 7u);
    AC_CHECK(envelope.not_before == 1700000000u);
    AC_CHECK(envelope.not_after == 1900000000u);
    AC_CHECK(envelope.entry_count == 3u);
    AC_CHECK(sink.modules == 2u && sink.drivers == 1u && sink.saw_driver_name);
    AC_CHECK(sink.first_digest[0] == 0x11u && sink.first_digest[31] == 0x11u);

    ac_test_hex(g_manifest_key_a, public_key, sizeof(public_key));
    ac_manifest_envelope_key_id(public_key, key_id);
    AC_CHECK(strcmp(key_id, "56475aa75463474c") == 0);
    AC_CHECK(strcmp(envelope.key_id, key_id) == 0);
}

static void test_manifest_envelope_rotation(void)
{
    const char *const both[] = {g_manifest_key_a, g_manifest_key_b};
    const char *const old_only[] = {g_manifest_key_a};
    AcManifestEnvelope envelope;
    AcTestManifestSink sink;

    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_b,
                 sizeof(g_manifest_v2_key_b) - 1u,
                 both,
                 2u,
                 1800000000u,
                 7u,
                 &envelope,
                 &sink) == AC_MANIFEST_ENVELOPE_OK);
    AC_CHECK(envelope.sequence == 8u && strcmp(envelope.key_id, "24f6ed6acbfe1009") == 0);

    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a,
                 sizeof(g_manifest_v2_key_a) - 1u,
                 both,
                 2u,
                 1800000000u,
                 0u,
                 &envelope,
                 &sink) == AC_MANIFEST_ENVELOPE_OK);

    /* A retired key is removed from the trust set; its successor is unknown. */
    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_b,
                 sizeof(g_manifest_v2_key_b) - 1u,
                 old_only,
                 1u,
                 1800000000u,
                 0u,
                 &envelope,
                 &sink) == AC_MANIFEST_ENVELOPE_UNKNOWN_KEY);
    AC_CHECK(sink.modules == 0u && envelope.entry_count == 0u);
}

static void test_manifest_envelope_tamper(void)
{
    const char *const keys[] = {g_manifest_key_a};
    const size_t length = sizeof(g_manifest_v2_key_a) - 1u;
    const char *digit = strstr(g_manifest_v2_key_a, "module 2");
    const char *signature = strstr(g_manifest_v2_key_a, "signature ed25519 ");
    char copy[sizeof(g_manifest_v2_key_a)];
    AcManifestEnvelope envelope;
    AcTestManifestSink sink;

    AC_CHECK(digit != NULL && signature != NULL);
    if (digit == NULL || signature == NULL) {
        return;
    }

    memcpy(copy, g_manifest_v2_key_a, sizeof(copy));
    copy[(size_t)(digit - g_manifest_v2_key_a) + 7u] = '3';
    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 copy, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_BAD_SIGNATURE);
    AC_CHECK(sink.modules == 0u);

    memcpy(copy, g_manifest_v2_key_a, sizeof(copy));
    copy[length - 2u] = copy[length - 2u] == '0' ? '1' : '0';
    AC_CHECK(ac_test_verify_manifest(
                 copy, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_BAD_SIGNATURE);

    /* An uppercase digit is a malformed signature encoding, not a bad signature. */
    memcpy(copy, g_manifest_v2_key_a, sizeof(copy));
    copy[length - 2u] = 'E';
    AC_CHECK(ac_test_verify_manifest(
                 copy, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_MALFORMED);

    memcpy(copy, g_manifest_v2_key_a, sizeof(copy));
    copy[(size_t)(signature - g_manifest_v2_key_a) + 18u] = '0';
    AC_CHECK(ac_test_verify_manifest(
                 copy, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_UNKNOWN_KEY);
}

static void test_manifest_envelope_validity(void)
{
    const char *const keys[] = {g_manifest_key_a};
    const size_t length = sizeof(g_manifest_v2_key_a) - 1u;
    AcManifestEnvelope envelope;
    AcTestManifestSink sink;

    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 1u, 1699999999u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_NOT_YET_VALID);
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 1u, 1700000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_OK);
    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 1u, 1900000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_EXPIRED);
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 1u, 1800000000u, 8u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_ROLLBACK);
    AC_CHECK(sink.modules == 0u && sink.drivers == 0u);
    AC_CHECK(strcmp(ac_manifest_envelope_status_name(AC_MANIFEST_ENVELOPE_ROLLBACK), "rollback") == 0);
}

static void test_manifest_envelope_malformed(void)
{
    const char *const keys[] = {g_manifest_key_a};
    const size_t length = sizeof(g_manifest_v2_key_a) - 1u;
    char copy[sizeof(g_manifest_v2_key_a) + 1u];
    AcManifestEnvelope envelope;
    AcTestManifestSink sink;

    memset(&sink, 0, sizeof(sink));
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_noncanonical,
                 sizeof(g_manifest_v2_noncanonical) - 1u,
                 keys,
                 1u,
                 1800000000u,
                 0u,
                 &envelope,
                 &sink) == AC_MANIFEST_ENVELOPE_MALFORMED);
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length - 1u, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_MALFORMED);
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, 0u, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_MALFORMED);
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 0u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_MALFORMED);

    memcpy(copy, g_manifest_v2_key_a, length);
    copy[14] = '\r';
    AC_CHECK(ac_test_verify_manifest(
                 copy, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_MALFORMED);

    memset(&sink, 0, sizeof(sink));
    sink.reject_after = 2u;
    AC_CHECK(ac_test_verify_manifest(
                 g_manifest_v2_key_a, length, keys, 1u, 1800000000u, 0u, &envelope, &sink) ==
             AC_MANIFEST_ENVELOPE_ENTRY_REJECTED);
    AC_CHECK(envelope.entry_count == 0u);
}

typedef void (*AcPortableTestFunction)(void);

typedef struct AcPortableTestCase {
    const char *name;
    AcPortableTestFunction function;
} AcPortableTestCase;

static const AcPortableTestCase g_test_cases[] = {
    {"sha256_vectors", test_sha256_vectors},
    {"sha256_streaming", test_sha256_streaming},
    {"json_escaping", test_json_escaping},
    {"fnv1a", test_fnv1a},
    {"range_index", test_range_index},
    {"range_index_merges_overlaps", test_range_index_merges_overlaps},
    {"range_index_many_entries", test_range_index_many_entries},
    {"schedule_delay_bounds", test_schedule_delay_bounds},
    {"schedule_permutation", test_schedule_permutation},
    {"schedule_singleton", test_schedule_singleton},
    {"schedule_fair_windows", test_schedule_fair_windows},
    {"dedup_suppresses_repeats", test_dedup_suppresses_repeats},
    {"dedup_zero_interval", test_dedup_never_repeats_with_zero_interval},
    {"dedup_saturation", test_dedup_fails_open_when_saturated},
    {"pe_parse_valid", test_pe_parses_valid_image},
    {"pe_materialize_rebase", test_pe_materializes_and_rebases_section},
    {"pe_mask_imports", test_pe_masks_import_tables},
    {"pe_iat_slots", test_pe_enumerates_iat_slots},
    {"pe_malformed_bounds", test_pe_rejects_malformed_input_without_overrun},
    {"pe_rejects_non_pe", test_pe_rejects_non_pe_and_unsupported},
    {"pe_relocation_bounds", test_pe_relocation_block_loop_is_bounded},
    {"sha512_vectors", test_sha512_vectors},
    {"ed25519_rfc8032", test_ed25519_rfc8032},
    {"ed25519_malleability", test_ed25519_rejects_malleable_scalar},
    {"manifest_envelope_valid", test_manifest_envelope_valid},
    {"manifest_envelope_rotation", test_manifest_envelope_rotation},
    {"manifest_envelope_tamper", test_manifest_envelope_tamper},
    {"manifest_envelope_validity", test_manifest_envelope_validity},
    {"manifest_envelope_malformed", test_manifest_envelope_malformed}
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
        const AcPortableTestCase *test_case = &g_test_cases[index];

        if (strcmp(argv[1], test_case->name) != 0) {
            continue;
        }

        g_failures = 0;
        test_case->function();

        if (g_failures != 0) {
            fprintf(
                stderr,
                "%d check(s) failed in portable.%s\n",
                g_failures,
                test_case->name);
            return 1;
        }

        printf("portable.%s passed\n", test_case->name);
        return 0;
    }

    fprintf(stderr, "unknown portable test case: %s\n", argv[1]);
    return 2;
}
