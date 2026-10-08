#include "ac.h"

#include <share.h>
#include <stdlib.h>
#include <string.h>

#define AC_MANIFEST_LINE_CAPACITY 2048u
#define AC_MANIFEST_MAX_ENTRIES 8192u

static bool ac_manifest_hex_digit(char value, uint8_t *digit_out)
{
    if (value >= '0' && value <= '9') {
        *digit_out = (uint8_t)(value - '0');
        return true;
    }
    if (value >= 'a' && value <= 'f') {
        *digit_out = (uint8_t)(value - 'a' + 10);
        return true;
    }
    if (value >= 'A' && value <= 'F') {
        *digit_out = (uint8_t)(value - 'A' + 10);
        return true;
    }
    return false;
}

static bool ac_manifest_parse_hex(
    const char *text,
    uint8_t output[AC_SHA256_DIGEST_SIZE])
{
    size_t index;

    if (text == NULL || strlen(text) != AC_SHA256_HEX_SIZE - 1u) {
        return false;
    }
    for (index = 0; index < AC_SHA256_DIGEST_SIZE; ++index) {
        uint8_t high;
        uint8_t low;
        if (!ac_manifest_hex_digit(text[index * 2u], &high) ||
            !ac_manifest_hex_digit(text[index * 2u + 1u], &low)) {
            return false;
        }
        output[index] = (uint8_t)((high << 4u) | low);
    }
    return true;
}

static bool ac_manifest_expected_pin(
    const wchar_t *expected,
    char pin[AC_SHA256_HEX_SIZE])
{
    size_t index;

    if (expected == NULL ||
        wcslen(expected) != AC_SHA256_HEX_SIZE - 1u) {
        return false;
    }
    for (index = 0; index < AC_SHA256_HEX_SIZE - 1u; ++index) {
        const wchar_t value = expected[index];
        if (!((value >= L'0' && value <= L'9') ||
              (value >= L'a' && value <= L'f') ||
              (value >= L'A' && value <= L'F'))) {
            return false;
        }
        pin[index] = (char)value;
    }
    pin[AC_SHA256_HEX_SIZE - 1u] = '\0';
    return true;
}

static bool ac_manifest_hash_stream(
    FILE *file,
    char observed[AC_SHA256_HEX_SIZE],
    uint64_t *size_out)
{
    AcSha256 hash;
    uint8_t buffer[4096];
    uint64_t size = 0;

    ac_sha256_init(&hash);
    for (;;) {
        const size_t read_count = fread(buffer, 1u, sizeof(buffer), file);
        if (read_count != 0) {
            if (UINT64_MAX - size < read_count) {
                return false;
            }
            ac_sha256_update(&hash, buffer, read_count);
            size += read_count;
        }
        if (read_count != sizeof(buffer)) {
            if (ferror(file)) {
                return false;
            }
            break;
        }
    }
    if (size == 0 || fseek(file, 0, SEEK_SET) != 0) {
        return false;
    }
    clearerr(file);
    ac_sha256_final(&hash, buffer);
    ac_sha256_to_hex(buffer, observed);
    *size_out = size;
    return true;
}

static const wchar_t *ac_manifest_base_name(const wchar_t *path)
{
    const wchar_t *backslash;
    const wchar_t *slash;
    const wchar_t *base;

    if (path == NULL) {
        return L"";
    }
    backslash = wcsrchr(path, L'\\');
    slash = wcsrchr(path, L'/');
    base = path;
    if (backslash != NULL && backslash + 1u > base) {
        base = backslash + 1u;
    }
    if (slash != NULL && slash + 1u > base) {
        base = slash + 1u;
    }
    return base;
}

static bool ac_manifest_push(
    AcManifest *manifest,
    AcManifestKind kind,
    const uint8_t digest[AC_SHA256_DIGEST_SIZE],
    const char *file_name_utf8)
{
    AcManifestEntry entry;
    int required;
    size_t index;

    if (manifest->count > manifest->capacity ||
        manifest->count >= AC_MANIFEST_MAX_ENTRIES ||
        file_name_utf8 == NULL || file_name_utf8[0] == '\0' ||
        strchr(file_name_utf8, '/') != NULL ||
        strchr(file_name_utf8, '\\') != NULL ||
        strchr(file_name_utf8, ':') != NULL) {
        return false;
    }

    memset(&entry, 0, sizeof(entry));
    entry.kind = kind;
    memcpy(entry.sha256, digest, sizeof(entry.sha256));
    required = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        file_name_utf8,
        -1,
        entry.file_name,
        (int)(sizeof(entry.file_name) / sizeof(entry.file_name[0])));
    if (required <= 0) {
        return false;
    }

    for (index = 0; index < manifest->count; ++index) {
        if (manifest->entries[index].kind == kind &&
            _wcsicmp(
                manifest->entries[index].file_name,
                entry.file_name) == 0) {
            return false;
        }
    }

    if (manifest->count == manifest->capacity) {
        const size_t new_capacity = manifest->capacity == 0
            ? 64u
            : manifest->capacity * 2u;
        AcManifestEntry *candidate = (AcManifestEntry *)realloc(
            manifest->entries,
            new_capacity * sizeof(*candidate));
        if (candidate == NULL) {
            return false;
        }
        manifest->entries = candidate;
        manifest->capacity = new_capacity;
    }
    if (manifest->entries == NULL || manifest->count >= manifest->capacity) {
        return false;
    }
    manifest->entries[manifest->count] = entry;
    ++manifest->count;
    return true;
}

void ac_manifest_init(AcManifest *manifest)
{
    if (manifest != NULL) {
        memset(manifest, 0, sizeof(*manifest));
    }
}

void ac_manifest_free(AcManifest *manifest)
{
    if (manifest == NULL) {
        return;
    }
    free(manifest->entries);
    ac_manifest_init(manifest);
}

bool ac_manifest_load_pinned(
    AcManifest *manifest,
    const wchar_t *path,
    const wchar_t *expected_sha256)
{
    FILE *file;
    char expected[AC_SHA256_HEX_SIZE];
    char observed[AC_SHA256_HEX_SIZE];
    char line[AC_MANIFEST_LINE_CAPACITY];
    bool header_seen = false;
    uint64_t file_size = 0;

    if (manifest == NULL || path == NULL ||
        !ac_manifest_expected_pin(expected_sha256, expected)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    ac_manifest_free(manifest);
    file = _wfsopen(path, L"rb", _SH_DENYWR);
    if (file == NULL) {
        return false;
    }
    if (!ac_manifest_hash_stream(file, observed, &file_size) ||
        _stricmp(expected, observed) != 0) {
        goto fail;
    }

    memset(line, 0, sizeof(line));
    while (fgets(line, (int)sizeof(line), file) != NULL) {
        char *context = NULL;
        char *kind_text;
        char *digest_text;
        char *file_name;
        char *extra;
        uint8_t digest[AC_SHA256_DIGEST_SIZE];
        const size_t length = strlen(line);
        const size_t offset = strspn(line, " \t");

        if (length == sizeof(line) - 1u && line[length - 1u] != '\n') {
            goto fail;
        }
        if (offset >= length || line[offset] == '\r' ||
            line[offset] == '\n' || line[offset] == '#') {
            continue;
        }
        line[offset + strcspn(line + offset, "\r\n")] = '\0';

        if (!header_seen) {
            if (strcmp(line + offset, "ac-manifest-v1") != 0) {
                goto fail;
            }
            header_seen = true;
            continue;
        }

        kind_text = strtok_s(line + offset, " \t", &context);
        digest_text = strtok_s(NULL, " \t", &context);
        file_name = strtok_s(NULL, " \t", &context);
        extra = strtok_s(NULL, " \t", &context);
        if (kind_text == NULL || digest_text == NULL ||
            file_name == NULL || extra != NULL ||
            !ac_manifest_parse_hex(digest_text, digest)) {
            goto fail;
        }
        if (strcmp(kind_text, "module") == 0) {
            if (!ac_manifest_push(
                    manifest,
                    AC_MANIFEST_MODULE,
                    digest,
                    file_name)) {
                goto fail;
            }
        } else if (strcmp(kind_text, "driver") == 0) {
            if (!ac_manifest_push(
                    manifest,
                    AC_MANIFEST_DRIVER,
                    digest,
                    file_name)) {
                goto fail;
            }
        } else {
            goto fail;
        }
    }

    if (ferror(file) || !header_seen || manifest->count == 0) {
        goto fail;
    }
    (void)fclose(file);
    (void)strcpy_s(
        manifest->file_sha256,
        sizeof(manifest->file_sha256),
        observed);
    manifest->trusted = true;
    return true;

fail:
    (void)fclose(file);
    ac_manifest_free(manifest);
    SetLastError(ERROR_INVALID_DATA);
    return false;
}

static bool ac_manifest_envelope_entry(
    void *user,
    AcManifestEnvelopeEntryKind kind,
    const uint8_t sha256[AC_SHA256_DIGEST_SIZE],
    const char *file_name)
{
    return ac_manifest_push(
        (AcManifest *)user,
        kind == AC_MANIFEST_ENVELOPE_DRIVER
            ? AC_MANIFEST_DRIVER : AC_MANIFEST_MODULE,
        sha256,
        file_name);
}

static bool ac_manifest_read_bounded(
    FILE *file,
    uint8_t **data_out,
    size_t *size_out)
{
    uint8_t *data;
    size_t size = 0;

    *data_out = NULL;
    *size_out = 0;
    /* One extra byte detects documents above the envelope limit. */
    data = (uint8_t *)malloc(AC_MANIFEST_ENVELOPE_MAX_BYTES + 1u);
    if (data == NULL) {
        return false;
    }
    for (;;) {
        const size_t read_count = fread(
            data + size,
            1u,
            AC_MANIFEST_ENVELOPE_MAX_BYTES + 1u - size,
            file);
        size += read_count;
        if (read_count == 0 || size > AC_MANIFEST_ENVELOPE_MAX_BYTES) {
            break;
        }
    }
    if (ferror(file) || size == 0 || size > AC_MANIFEST_ENVELOPE_MAX_BYTES) {
        free(data);
        return false;
    }
    *data_out = data;
    *size_out = size;
    return true;
}

bool ac_manifest_load_signed(
    AcManifest *manifest,
    const wchar_t *path,
    const AcManifestTrust *trust)
{
    FILE *file;
    uint8_t *data = NULL;
    size_t size = 0;
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    char expected[AC_SHA256_HEX_SIZE];
    char observed[AC_SHA256_HEX_SIZE];
    AcManifestEnvelopeTrust envelope_trust;
    AcManifestEnvelopeStatus status;

    if (manifest == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    ac_manifest_free(manifest);
    if (path == NULL || trust == NULL ||
        trust->public_keys == NULL || trust->public_key_count == 0 ||
        trust->public_key_count > AC_MANIFEST_ENVELOPE_MAX_KEYS ||
        (trust->expected_sha256 != NULL &&
         !ac_manifest_expected_pin(trust->expected_sha256, expected))) {
        manifest->rejection_reason = "invalid_trust_configuration";
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    file = _wfsopen(path, L"rb", _SH_DENYWR);
    if (file == NULL) {
        manifest->rejection_reason = "unreadable";
        return false;
    }
    if (!ac_manifest_read_bounded(file, &data, &size)) {
        (void)fclose(file);
        manifest->rejection_reason = "unreadable";
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    (void)fclose(file);

    ac_sha256(data, size, digest);
    ac_sha256_to_hex(digest, observed);
    if (trust->expected_sha256 != NULL && _stricmp(expected, observed) != 0) {
        free(data);
        manifest->rejection_reason = "hash_pin_mismatch";
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    envelope_trust.public_keys = trust->public_keys;
    envelope_trust.key_count = trust->public_key_count;
    envelope_trust.now_unix = trust->now_unix;
    envelope_trust.minimum_sequence = trust->minimum_sequence;
    status = ac_manifest_envelope_verify(
        data,
        size,
        &envelope_trust,
        &manifest->envelope,
        ac_manifest_envelope_entry,
        manifest);
    free(data);
    if (status != AC_MANIFEST_ENVELOPE_OK) {
        ac_manifest_free(manifest);
        manifest->rejection_reason = ac_manifest_envelope_status_name(status);
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    (void)strcpy_s(manifest->file_sha256, sizeof(manifest->file_sha256), observed);
    manifest->signed_envelope = true;
    manifest->trusted = true;
    return true;
}

AcManifestMatch ac_manifest_match(
    const AcManifest *manifest,
    AcManifestKind kind,
    const wchar_t *path,
    const uint8_t sha256[AC_SHA256_DIGEST_SIZE])
{
    const wchar_t *file_name = ac_manifest_base_name(path);
    size_t index;

    if (manifest == NULL || !manifest->trusted || sha256 == NULL) {
        return AC_MANIFEST_NOT_LISTED;
    }
    for (index = 0; index < manifest->count; ++index) {
        const AcManifestEntry *entry = &manifest->entries[index];
        if (entry->kind != kind ||
            _wcsicmp(entry->file_name, file_name) != 0) {
            continue;
        }
        return memcmp(
                   entry->sha256,
                   sha256,
                   AC_SHA256_DIGEST_SIZE) == 0
            ? AC_MANIFEST_AUTHORIZED
            : AC_MANIFEST_HASH_MISMATCH;
    }
    return AC_MANIFEST_NOT_LISTED;
}

AcManifestMatch ac_manifest_match_hex(
    const AcManifest *manifest,
    AcManifestKind kind,
    const wchar_t *path,
    const char *sha256_hex)
{
    uint8_t digest[AC_SHA256_DIGEST_SIZE];

    if (!ac_manifest_parse_hex(sha256_hex, digest)) {
        return AC_MANIFEST_HASH_MISMATCH;
    }
    return ac_manifest_match(manifest, kind, path, digest);
}
