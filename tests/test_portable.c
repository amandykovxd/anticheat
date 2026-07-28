#include "dedup.h"
#include "ranges.h"
#include "sha256.h"
#include "text.h"

#include <stdio.h>
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
    {"dedup_suppresses_repeats", test_dedup_suppresses_repeats},
    {"dedup_zero_interval", test_dedup_never_repeats_with_zero_interval},
    {"dedup_saturation", test_dedup_fails_open_when_saturated}
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
