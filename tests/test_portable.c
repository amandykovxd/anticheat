#include "dedup.h"
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
    {"pe_relocation_bounds", test_pe_relocation_block_loop_is_bounded}
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
