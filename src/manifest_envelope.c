#include "manifest_envelope.h"

#include <string.h>

#define AC_MANIFEST_ENVELOPE_HEADER "ac-manifest-v2"
#define AC_MANIFEST_SIGNATURE_PREFIX "signature ed25519 "
#define AC_MANIFEST_MAX_DECIMAL 9223372036854775807ull

static const char g_signature_context[] = "ac-manifest-signature-v1";

typedef struct AcEnvelopeLine {
    const char *text;
    size_t length;
} AcEnvelopeLine;

typedef struct AcEnvelopeCursor {
    const char *data;
    size_t size;
    size_t offset;
} AcEnvelopeCursor;

/* Every line, including the last, is LF-terminated (checked by the caller). */
static bool ac_envelope_next_line(AcEnvelopeCursor *cursor, AcEnvelopeLine *line)
{
    const char *start;
    const char *newline;

    if (cursor->offset >= cursor->size) {
        return false;
    }
    start = cursor->data + cursor->offset;
    newline = (const char *)memchr(start, '\n', cursor->size - cursor->offset);
    if (newline == NULL) {
        return false;
    }
    line->text = start;
    line->length = (size_t)(newline - start);
    cursor->offset += line->length + 1u;
    return true;
}

static bool ac_envelope_lower_hex(
    const char *text,
    size_t byte_count,
    uint8_t *bytes_out)
{
    size_t index;

    for (index = 0; index < byte_count * 2u; ++index) {
        const char value = text[index];
        uint8_t digit;

        if (value >= '0' && value <= '9') {
            digit = (uint8_t)(value - '0');
        } else if (value >= 'a' && value <= 'f') {
            digit = (uint8_t)(value - 'a' + 10);
        } else {
            return false;
        }
        if (bytes_out != NULL) {
            if ((index & 1u) == 0) {
                bytes_out[index / 2u] = (uint8_t)(digit << 4u);
            } else {
                bytes_out[index / 2u] = (uint8_t)(bytes_out[index / 2u] | digit);
            }
        }
    }
    return true;
}

/* Canonical decimal: no sign, no leading zero, value <= 2^63 - 1. */
static bool ac_envelope_decimal(const char *text, size_t length, uint64_t *value_out)
{
    uint64_t value = 0;
    size_t index;

    if (length == 0 || length > 19u || (length > 1u && text[0] == '0')) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        const char digit = text[index];
        if (digit < '0' || digit > '9') {
            return false;
        }
        value = value * 10u + (uint64_t)(digit - '0');
    }
    if (value > AC_MANIFEST_MAX_DECIMAL) {
        return false;
    }
    *value_out = value;
    return true;
}

/* Matches "<name> <value>" exactly and returns the value slice. */
static bool ac_envelope_field(
    const AcEnvelopeLine *line,
    const char *name,
    const char **value_out,
    size_t *value_length_out)
{
    const size_t name_length = strlen(name);

    if (line->length <= name_length + 1u ||
        memcmp(line->text, name, name_length) != 0 ||
        line->text[name_length] != ' ' ||
        memchr(line->text + name_length + 1u, ' ', line->length - name_length - 1u) != NULL) {
        return false;
    }
    *value_out = line->text + name_length + 1u;
    *value_length_out = line->length - name_length - 1u;
    return true;
}

static bool ac_envelope_valid_utf8(const uint8_t *text, size_t length)
{
    size_t index = 0;

    while (index < length) {
        const uint8_t lead = text[index];
        size_t continuation;
        uint32_t code_point;
        uint32_t minimum;
        size_t offset;

        if (lead < 0x80u) {
            ++index;
            continue;
        }
        if ((lead & 0xe0u) == 0xc0u) {
            continuation = 1;
            code_point = lead & 0x1fu;
            minimum = 0x80u;
        } else if ((lead & 0xf0u) == 0xe0u) {
            continuation = 2;
            code_point = lead & 0x0fu;
            minimum = 0x800u;
        } else if ((lead & 0xf8u) == 0xf0u) {
            continuation = 3;
            code_point = lead & 0x07u;
            minimum = 0x10000u;
        } else {
            return false;
        }
        if (length - index <= continuation) {
            return false;
        }
        for (offset = 1; offset <= continuation; ++offset) {
            const uint8_t next = text[index + offset];
            if ((next & 0xc0u) != 0x80u) {
                return false;
            }
            code_point = (code_point << 6u) | (next & 0x3fu);
        }
        if (code_point < minimum || code_point > 0x10ffffu ||
            (code_point >= 0xd800u && code_point <= 0xdfffu)) {
            return false;
        }
        index += continuation + 1u;
    }
    return true;
}

static bool ac_envelope_file_name(const char *text, size_t length)
{
    size_t index;

    if (length == 0 || length >= AC_MANIFEST_ENVELOPE_FILE_NAME_SIZE) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        const uint8_t value = (uint8_t)text[index];
        if (value <= 0x20u || value == 0x7fu ||
            value == '/' || value == '\\' || value == ':') {
            return false;
        }
    }
    return ac_envelope_valid_utf8((const uint8_t *)text, length);
}

static bool ac_envelope_application(const char *text, size_t length)
{
    size_t index;

    if (length == 0 || length >= AC_MANIFEST_ENVELOPE_APPLICATION_SIZE) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        const char value = text[index];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') ||
              value == '.' || value == '_' || value == '-')) {
            return false;
        }
    }
    return true;
}

void ac_manifest_envelope_key_id(
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE],
    char key_id_out[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE])
{
    uint8_t digest[AC_SHA256_DIGEST_SIZE];
    char hex[AC_SHA256_HEX_SIZE];

    ac_sha256(public_key, AC_ED25519_PUBLIC_KEY_SIZE, digest);
    ac_sha256_to_hex(digest, hex);
    memcpy(key_id_out, hex, AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE - 1u);
    key_id_out[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE - 1u] = '\0';
}

const char *ac_manifest_envelope_status_name(AcManifestEnvelopeStatus status)
{
    switch (status) {
    case AC_MANIFEST_ENVELOPE_OK:
        return "ok";
    case AC_MANIFEST_ENVELOPE_MALFORMED:
        return "malformed";
    case AC_MANIFEST_ENVELOPE_UNKNOWN_KEY:
        return "unknown_key";
    case AC_MANIFEST_ENVELOPE_BAD_SIGNATURE:
        return "bad_signature";
    case AC_MANIFEST_ENVELOPE_NOT_YET_VALID:
        return "not_yet_valid";
    case AC_MANIFEST_ENVELOPE_EXPIRED:
        return "expired";
    case AC_MANIFEST_ENVELOPE_ROLLBACK:
        return "rollback";
    case AC_MANIFEST_ENVELOPE_ENTRY_REJECTED:
        return "entry_rejected";
    }
    return "unknown";
}

static AcManifestEnvelopeStatus ac_envelope_check_signature(
    const char *data,
    size_t body_size,
    size_t size,
    const AcManifestEnvelopeTrust *trust,
    char key_id_out[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE])
{
    const size_t prefix_length = sizeof(AC_MANIFEST_SIGNATURE_PREFIX) - 1u;
    const size_t trailer_length = size - body_size - 1u;
    const char *trailer = data + body_size;
    uint8_t signature[AC_ED25519_SIGNATURE_SIZE];
    size_t index;

    if (trailer_length != prefix_length + 16u + 1u + 128u ||
        memcmp(trailer, AC_MANIFEST_SIGNATURE_PREFIX, prefix_length) != 0 ||
        !ac_envelope_lower_hex(trailer + prefix_length, 8u, NULL) ||
        trailer[prefix_length + 16u] != ' ' ||
        !ac_envelope_lower_hex(
            trailer + prefix_length + 17u,
            AC_ED25519_SIGNATURE_SIZE,
            signature)) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    memcpy(key_id_out, trailer + prefix_length, 16u);
    key_id_out[16] = '\0';

    for (index = 0; index < trust->key_count; ++index) {
        char candidate[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE];

        ac_manifest_envelope_key_id(trust->public_keys[index], candidate);
        if (memcmp(candidate, key_id_out, 16u) != 0) {
            continue;
        }
        return ac_ed25519_verify_parts(
                   signature,
                   g_signature_context,
                   sizeof(g_signature_context),
                   data,
                   body_size,
                   trust->public_keys[index])
            ? AC_MANIFEST_ENVELOPE_OK
            : AC_MANIFEST_ENVELOPE_BAD_SIGNATURE;
    }
    return AC_MANIFEST_ENVELOPE_UNKNOWN_KEY;
}

AcManifestEnvelopeStatus ac_manifest_envelope_verify(
    const uint8_t *data,
    size_t size,
    const AcManifestEnvelopeTrust *trust,
    AcManifestEnvelope *envelope_out,
    AcManifestEnvelopeEntryCallback callback,
    void *user)
{
    static const char *const field_names[5] = {
        "application", "build-id", "sequence", "not-before", "not-after"
    };
    const char *text = (const char *)data;
    AcManifestEnvelope envelope;
    AcManifestEnvelopeStatus status;
    AcEnvelopeCursor cursor;
    AcEnvelopeLine line;
    const char *values[5];
    size_t value_lengths[5];
    size_t body_size;
    size_t index;

    if (envelope_out != NULL) {
        memset(envelope_out, 0, sizeof(*envelope_out));
    }
    if (data == NULL || trust == NULL || envelope_out == NULL ||
        callback == NULL || trust->public_keys == NULL ||
        trust->key_count == 0 ||
        trust->key_count > AC_MANIFEST_ENVELOPE_MAX_KEYS) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    if (size < 2u || size > AC_MANIFEST_ENVELOPE_MAX_BYTES ||
        text[size - 1u] != '\n' ||
        memchr(data, '\r', size) != NULL ||
        memchr(data, '\0', size) != NULL) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }

    /* The signature trailer is the final line; the body precedes it. */
    body_size = size - 1u;
    while (body_size != 0 && text[body_size - 1u] != '\n') {
        --body_size;
    }
    if (body_size == 0) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    memset(&envelope, 0, sizeof(envelope));
    status = ac_envelope_check_signature(
        text,
        body_size,
        size,
        trust,
        envelope.key_id);
    if (status != AC_MANIFEST_ENVELOPE_OK) {
        return status;
    }

    cursor.data = text;
    cursor.size = body_size;
    cursor.offset = 0;
    if (!ac_envelope_next_line(&cursor, &line) ||
        line.length != sizeof(AC_MANIFEST_ENVELOPE_HEADER) - 1u ||
        memcmp(line.text, AC_MANIFEST_ENVELOPE_HEADER, line.length) != 0) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    for (index = 0; index < 5u; ++index) {
        if (!ac_envelope_next_line(&cursor, &line) ||
            !ac_envelope_field(
                &line,
                field_names[index],
                &values[index],
                &value_lengths[index])) {
            return AC_MANIFEST_ENVELOPE_MALFORMED;
        }
    }
    if (!ac_envelope_application(values[0], value_lengths[0]) ||
        value_lengths[1] != AC_SHA256_HEX_SIZE - 1u ||
        !ac_envelope_lower_hex(values[1], AC_SHA256_DIGEST_SIZE, NULL) ||
        !ac_envelope_decimal(values[2], value_lengths[2], &envelope.sequence) ||
        !ac_envelope_decimal(values[3], value_lengths[3], &envelope.not_before) ||
        !ac_envelope_decimal(values[4], value_lengths[4], &envelope.not_after) ||
        envelope.sequence == 0 ||
        envelope.not_before >= envelope.not_after) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    memcpy(envelope.application, values[0], value_lengths[0]);
    memcpy(envelope.build_id, values[1], value_lengths[1]);

    if (trust->now_unix < envelope.not_before) {
        return AC_MANIFEST_ENVELOPE_NOT_YET_VALID;
    }
    if (trust->now_unix >= envelope.not_after) {
        return AC_MANIFEST_ENVELOPE_EXPIRED;
    }
    if (envelope.sequence < trust->minimum_sequence) {
        return AC_MANIFEST_ENVELOPE_ROLLBACK;
    }

    while (ac_envelope_next_line(&cursor, &line)) {
        const char *first_space = (const char *)memchr(line.text, ' ', line.length);
        const char *digest_text;
        const char *name_text;
        size_t kind_length;
        size_t name_length;
        AcManifestEnvelopeEntryKind kind;
        uint8_t digest[AC_SHA256_DIGEST_SIZE];
        char file_name[AC_MANIFEST_ENVELOPE_FILE_NAME_SIZE];

        if (first_space == NULL ||
            envelope.entry_count >= AC_MANIFEST_ENVELOPE_MAX_ENTRIES) {
            return AC_MANIFEST_ENVELOPE_MALFORMED;
        }
        kind_length = (size_t)(first_space - line.text);
        if (kind_length == 6u && memcmp(line.text, "module", 6u) == 0) {
            kind = AC_MANIFEST_ENVELOPE_MODULE;
        } else if (kind_length == 6u && memcmp(line.text, "driver", 6u) == 0) {
            kind = AC_MANIFEST_ENVELOPE_DRIVER;
        } else {
            return AC_MANIFEST_ENVELOPE_MALFORMED;
        }
        digest_text = first_space + 1u;
        if (line.length < kind_length + 1u + 64u + 2u ||
            digest_text[64] != ' ' ||
            !ac_envelope_lower_hex(digest_text, AC_SHA256_DIGEST_SIZE, digest)) {
            return AC_MANIFEST_ENVELOPE_MALFORMED;
        }
        name_text = digest_text + 65u;
        name_length = line.length - kind_length - 66u;
        if (!ac_envelope_file_name(name_text, name_length)) {
            return AC_MANIFEST_ENVELOPE_MALFORMED;
        }
        memcpy(file_name, name_text, name_length);
        file_name[name_length] = '\0';
        if (!callback(user, kind, digest, file_name)) {
            return AC_MANIFEST_ENVELOPE_ENTRY_REJECTED;
        }
        ++envelope.entry_count;
    }
    if (envelope.entry_count == 0) {
        return AC_MANIFEST_ENVELOPE_MALFORMED;
    }
    *envelope_out = envelope;
    return AC_MANIFEST_ENVELOPE_OK;
}
