#ifndef AC_MANIFEST_H
#define AC_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#include "sha256.h"

typedef enum AcManifestKind {
    AC_MANIFEST_MODULE = 1,
    AC_MANIFEST_DRIVER = 2
} AcManifestKind;

typedef enum AcManifestMatch {
    AC_MANIFEST_NOT_LISTED = 0,
    AC_MANIFEST_AUTHORIZED = 1,
    AC_MANIFEST_HASH_MISMATCH = 2
} AcManifestMatch;

typedef struct AcManifestEntry {
    wchar_t file_name[260];
    uint8_t sha256[AC_SHA256_DIGEST_SIZE];
    AcManifestKind kind;
} AcManifestEntry;

typedef struct AcManifest {
    AcManifestEntry *entries;
    size_t count;
    size_t capacity;
    char file_sha256[AC_SHA256_HEX_SIZE];
    bool trusted;
} AcManifest;

void ac_manifest_init(AcManifest *manifest);
void ac_manifest_free(AcManifest *manifest);
bool ac_manifest_load_pinned(
    AcManifest *manifest,
    const wchar_t *path,
    const wchar_t *expected_sha256);
AcManifestMatch ac_manifest_match(
    const AcManifest *manifest,
    AcManifestKind kind,
    const wchar_t *path,
    const uint8_t sha256[AC_SHA256_DIGEST_SIZE]);
AcManifestMatch ac_manifest_match_hex(
    const AcManifest *manifest,
    AcManifestKind kind,
    const wchar_t *path,
    const char *sha256_hex);

#endif
