#ifndef AC_ED25519_H
#define AC_ED25519_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AC_SHA512_DIGEST_SIZE 64u
#define AC_SHA512_BLOCK_SIZE 128u
#define AC_ED25519_PUBLIC_KEY_SIZE 32u
#define AC_ED25519_SIGNATURE_SIZE 64u

typedef struct AcSha512 {
    uint64_t state[8];
    uint64_t byte_length;
    uint8_t buffer[AC_SHA512_BLOCK_SIZE];
    size_t buffer_length;
} AcSha512;

void ac_sha512_init(AcSha512 *context);
void ac_sha512_update(AcSha512 *context, const void *data, size_t length);
void ac_sha512_final(AcSha512 *context, uint8_t digest[AC_SHA512_DIGEST_SIZE]);
void ac_sha512(const void *data, size_t length, uint8_t digest[AC_SHA512_DIGEST_SIZE]);

/*
 * Verifies a pure Ed25519 signature (RFC 8032, section 5.1.7). Signatures
 * whose scalar S is not reduced modulo the group order and public keys that
 * do not decode to a curve point are rejected. Verification is not constant
 * time; it processes only public inputs.
 */
bool ac_ed25519_verify(
    const uint8_t signature[AC_ED25519_SIGNATURE_SIZE],
    const void *message,
    size_t message_length,
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE]);

/* Verifies a signature over the concatenation prefix || message. */
bool ac_ed25519_verify_parts(
    const uint8_t signature[AC_ED25519_SIGNATURE_SIZE],
    const void *prefix,
    size_t prefix_length,
    const void *message,
    size_t message_length,
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE]);

#endif
