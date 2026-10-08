#ifndef AC_MANIFEST_ENVELOPE_H
#define AC_MANIFEST_ENVELOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ed25519.h"
#include "sha256.h"

#define AC_MANIFEST_ENVELOPE_MAX_BYTES (4u * 1024u * 1024u)
#define AC_MANIFEST_ENVELOPE_MAX_ENTRIES 8192u
#define AC_MANIFEST_ENVELOPE_MAX_KEYS 8u
#define AC_MANIFEST_ENVELOPE_KEY_ID_BYTES 8u
#define AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE 17u
#define AC_MANIFEST_ENVELOPE_APPLICATION_SIZE 65u
#define AC_MANIFEST_ENVELOPE_FILE_NAME_SIZE 260u

typedef enum AcManifestEnvelopeStatus {
    AC_MANIFEST_ENVELOPE_OK = 0,
    AC_MANIFEST_ENVELOPE_MALFORMED,
    AC_MANIFEST_ENVELOPE_UNKNOWN_KEY,
    AC_MANIFEST_ENVELOPE_BAD_SIGNATURE,
    AC_MANIFEST_ENVELOPE_NOT_YET_VALID,
    AC_MANIFEST_ENVELOPE_EXPIRED,
    AC_MANIFEST_ENVELOPE_ROLLBACK,
    AC_MANIFEST_ENVELOPE_ENTRY_REJECTED
} AcManifestEnvelopeStatus;

typedef enum AcManifestEnvelopeEntryKind {
    AC_MANIFEST_ENVELOPE_MODULE = 1,
    AC_MANIFEST_ENVELOPE_DRIVER = 2
} AcManifestEnvelopeEntryKind;

typedef struct AcManifestEnvelopeTrust {
    const uint8_t (*public_keys)[AC_ED25519_PUBLIC_KEY_SIZE];
    size_t key_count;
    uint64_t now_unix;
    uint64_t minimum_sequence;
} AcManifestEnvelopeTrust;

typedef struct AcManifestEnvelope {
    char application[AC_MANIFEST_ENVELOPE_APPLICATION_SIZE];
    char build_id[AC_SHA256_HEX_SIZE];
    char key_id[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE];
    uint64_t sequence;
    uint64_t not_before;
    uint64_t not_after;
    size_t entry_count;
} AcManifestEnvelope;

/*
 * Receives one entry after the signature, validity window, and rollback floor
 * have been accepted. `file_name` is NUL-terminated UTF-8 without path
 * separators. Returning false aborts with AC_MANIFEST_ENVELOPE_ENTRY_REJECTED.
 */
typedef bool (*AcManifestEnvelopeEntryCallback)(
    void *user,
    AcManifestEnvelopeEntryKind kind,
    const uint8_t sha256[AC_SHA256_DIGEST_SIZE],
    const char *file_name);

/*
 * Verifies an ac-manifest-v2 document. The signature is checked before any
 * field of the signed body is interpreted. On any failure, entries already
 * delivered to the callback must be discarded by the caller.
 */
AcManifestEnvelopeStatus ac_manifest_envelope_verify(
    const uint8_t *data,
    size_t size,
    const AcManifestEnvelopeTrust *trust,
    AcManifestEnvelope *envelope_out,
    AcManifestEnvelopeEntryCallback callback,
    void *user);

void ac_manifest_envelope_key_id(
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE],
    char key_id_out[AC_MANIFEST_ENVELOPE_KEY_ID_HEX_SIZE]);

const char *ac_manifest_envelope_status_name(AcManifestEnvelopeStatus status);

#endif
