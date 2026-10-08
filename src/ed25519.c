#include "ed25519.h"

#include <string.h>

/*
 * Field and group arithmetic follows the public-domain TweetNaCl layout:
 * GF(2^255 - 19) elements are sixteen signed 16-bit limbs held in int64_t.
 * Shifts of possibly negative values are expressed as floor division so the
 * code has no implementation-defined or undefined shift behavior.
 */

typedef int64_t AcGf[16];

static const uint64_t g_sha512_k[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
    0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
    0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
    0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
    0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
    0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
    0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull,
    0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
    0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
    0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull,
    0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static const AcGf g_gf0 = {0};
static const AcGf g_gf1 = {1};
static const AcGf g_d2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const AcGf g_d = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const AcGf g_base_x = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const AcGf g_base_y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const AcGf g_sqrt_m1 = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};
static const int64_t g_order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static uint64_t ac_load_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t index;

    for (index = 0; index < 8u; ++index) {
        value = (value << 8u) | bytes[index];
    }
    return value;
}

static uint64_t ac_rotr64(uint64_t value, unsigned int count)
{
    return (value >> count) | (value << (64u - count));
}

static void ac_sha512_block(AcSha512 *context, const uint8_t block[AC_SHA512_BLOCK_SIZE])
{
    uint64_t schedule[80];
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
    size_t index;

    for (index = 0; index < 16u; ++index) {
        schedule[index] = ac_load_be64(block + index * 8u);
    }
    for (index = 16; index < 80u; ++index) {
        const uint64_t s0 = ac_rotr64(schedule[index - 15u], 1u) ^
            ac_rotr64(schedule[index - 15u], 8u) ^ (schedule[index - 15u] >> 7u);
        const uint64_t s1 = ac_rotr64(schedule[index - 2u], 19u) ^
            ac_rotr64(schedule[index - 2u], 61u) ^ (schedule[index - 2u] >> 6u);
        schedule[index] = schedule[index - 16u] + s0 + schedule[index - 7u] + s1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (index = 0; index < 80u; ++index) {
        const uint64_t s1 = ac_rotr64(e, 14u) ^ ac_rotr64(e, 18u) ^ ac_rotr64(e, 41u);
        const uint64_t choice = (e & f) ^ (~e & g);
        const uint64_t t1 = h + s1 + choice + g_sha512_k[index] + schedule[index];
        const uint64_t s0 = ac_rotr64(a, 28u) ^ ac_rotr64(a, 34u) ^ ac_rotr64(a, 39u);
        const uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t t2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void ac_sha512_init(AcSha512 *context)
{
    static const uint64_t initial[8] = {
        0x6a09e667f3bcc908ull,
        0xbb67ae8584caa73bull,
        0x3c6ef372fe94f82bull,
        0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull,
        0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull,
        0x5be0cd19137e2179ull
    };

    memcpy(context->state, initial, sizeof(initial));
    context->byte_length = 0;
    context->buffer_length = 0;
}

void ac_sha512_update(AcSha512 *context, const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;

    context->byte_length += (uint64_t)length;
    while (length != 0) {
        size_t take = AC_SHA512_BLOCK_SIZE - context->buffer_length;
        if (take > length) {
            take = length;
        }
        memcpy(context->buffer + context->buffer_length, bytes, take);
        context->buffer_length += take;
        bytes += take;
        length -= take;
        if (context->buffer_length == AC_SHA512_BLOCK_SIZE) {
            ac_sha512_block(context, context->buffer);
            context->buffer_length = 0;
        }
    }
}

void ac_sha512_final(AcSha512 *context, uint8_t digest[AC_SHA512_DIGEST_SIZE])
{
    const uint64_t bit_length = context->byte_length * 8u;
    const uint64_t high_bits = context->byte_length >> 61u;
    size_t index;

    context->buffer[context->buffer_length++] = 0x80u;
    if (context->buffer_length > AC_SHA512_BLOCK_SIZE - 16u) {
        memset(
            context->buffer + context->buffer_length,
            0,
            AC_SHA512_BLOCK_SIZE - context->buffer_length);
        ac_sha512_block(context, context->buffer);
        context->buffer_length = 0;
    }
    memset(
        context->buffer + context->buffer_length,
        0,
        AC_SHA512_BLOCK_SIZE - context->buffer_length);
    for (index = 0; index < 8u; ++index) {
        context->buffer[AC_SHA512_BLOCK_SIZE - 16u + index] =
            (uint8_t)(high_bits >> (56u - index * 8u));
        context->buffer[AC_SHA512_BLOCK_SIZE - 8u + index] =
            (uint8_t)(bit_length >> (56u - index * 8u));
    }
    ac_sha512_block(context, context->buffer);
    for (index = 0; index < 64u; ++index) {
        digest[index] = (uint8_t)(context->state[index / 8u] >> (56u - (index % 8u) * 8u));
    }
    memset(context, 0, sizeof(*context));
}

void ac_sha512(const void *data, size_t length, uint8_t digest[AC_SHA512_DIGEST_SIZE])
{
    AcSha512 context;

    ac_sha512_init(&context);
    ac_sha512_update(&context, data, length);
    ac_sha512_final(&context, digest);
}

/* floor(value / 2^bits) without shifting a negative operand. */
static int64_t ac_floor_shift(int64_t value, unsigned int bits)
{
    if (value >= 0) {
        return value >> bits;
    }
    return -(((-(value + 1)) >> bits)) - 1;
}

static void ac_gf_copy(AcGf output, const AcGf input)
{
    memcpy(output, input, sizeof(AcGf));
}

static void ac_gf_carry(AcGf value)
{
    size_t index;

    for (index = 0; index < 16u; ++index) {
        int64_t carry;

        value[index] += 65536;
        carry = ac_floor_shift(value[index], 16u);
        if (index < 15u) {
            value[index + 1u] += carry - 1;
        } else {
            value[0] += 38 * (carry - 1);
        }
        value[index] -= carry * 65536;
    }
}

static void ac_gf_select(AcGf p, AcGf q, int64_t swap)
{
    const int64_t mask = ~(swap - 1);
    size_t index;

    for (index = 0; index < 16u; ++index) {
        const int64_t delta = mask & (p[index] ^ q[index]);
        p[index] ^= delta;
        q[index] ^= delta;
    }
}

static void ac_gf_pack(uint8_t output[32], const AcGf input)
{
    AcGf t;
    AcGf m;
    size_t round;
    size_t index;

    ac_gf_copy(t, input);
    ac_gf_carry(t);
    ac_gf_carry(t);
    ac_gf_carry(t);
    for (round = 0; round < 2u; ++round) {
        int64_t borrow;

        m[0] = t[0] - 0xffed;
        for (index = 1; index < 15u; ++index) {
            m[index] = t[index] - 0xffff -
                (int64_t)(((uint64_t)m[index - 1u] >> 16u) & 1u);
            m[index - 1u] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - (int64_t)(((uint64_t)m[14] >> 16u) & 1u);
        borrow = (int64_t)(((uint64_t)m[15] >> 16u) & 1u);
        m[14] &= 0xffff;
        ac_gf_select(t, m, 1 - borrow);
    }
    for (index = 0; index < 16u; ++index) {
        output[index * 2u] = (uint8_t)(t[index] & 0xff);
        output[index * 2u + 1u] = (uint8_t)((t[index] >> 8u) & 0xff);
    }
}

static bool ac_gf_equal(const AcGf a, const AcGf b)
{
    uint8_t packed_a[32];
    uint8_t packed_b[32];

    ac_gf_pack(packed_a, a);
    ac_gf_pack(packed_b, b);
    return memcmp(packed_a, packed_b, sizeof(packed_a)) == 0;
}

static uint8_t ac_gf_parity(const AcGf a)
{
    uint8_t packed[32];

    ac_gf_pack(packed, a);
    return (uint8_t)(packed[0] & 1u);
}

static void ac_gf_unpack(AcGf output, const uint8_t input[32])
{
    size_t index;

    for (index = 0; index < 16u; ++index) {
        output[index] = (int64_t)input[index * 2u] +
            ((int64_t)input[index * 2u + 1u] << 8u);
    }
    output[15] &= 0x7fff;
}

static void ac_gf_add(AcGf output, const AcGf a, const AcGf b)
{
    size_t index;

    for (index = 0; index < 16u; ++index) {
        output[index] = a[index] + b[index];
    }
}

static void ac_gf_sub(AcGf output, const AcGf a, const AcGf b)
{
    size_t index;

    for (index = 0; index < 16u; ++index) {
        output[index] = a[index] - b[index];
    }
}

static void ac_gf_mul(AcGf output, const AcGf a, const AcGf b)
{
    int64_t product[31];
    size_t i;
    size_t j;

    memset(product, 0, sizeof(product));
    for (i = 0; i < 16u; ++i) {
        for (j = 0; j < 16u; ++j) {
            product[i + j] += a[i] * b[j];
        }
    }
    for (i = 0; i < 15u; ++i) {
        product[i] += 38 * product[i + 16u];
    }
    for (i = 0; i < 16u; ++i) {
        output[i] = product[i];
    }
    ac_gf_carry(output);
    ac_gf_carry(output);
}

static void ac_gf_square(AcGf output, const AcGf a)
{
    ac_gf_mul(output, a, a);
}

static void ac_gf_invert(AcGf output, const AcGf input)
{
    AcGf c;
    int bit;

    ac_gf_copy(c, input);
    for (bit = 253; bit >= 0; --bit) {
        ac_gf_square(c, c);
        if (bit != 2 && bit != 4) {
            ac_gf_mul(c, c, input);
        }
    }
    ac_gf_copy(output, c);
}

/* input^((p - 5) / 8), used for the square root during point decoding. */
static void ac_gf_pow2523(AcGf output, const AcGf input)
{
    AcGf c;
    int bit;

    ac_gf_copy(c, input);
    for (bit = 250; bit >= 0; --bit) {
        ac_gf_square(c, c);
        if (bit != 1) {
            ac_gf_mul(c, c, input);
        }
    }
    ac_gf_copy(output, c);
}

/* Extended twisted Edwards coordinates (X, Y, Z, T). */
static void ac_point_add(AcGf p[4], AcGf q[4])
{
    AcGf a;
    AcGf b;
    AcGf c;
    AcGf d;
    AcGf t;
    AcGf e;
    AcGf f;
    AcGf g;
    AcGf h;

    ac_gf_sub(a, p[1], p[0]);
    ac_gf_sub(t, q[1], q[0]);
    ac_gf_mul(a, a, t);
    ac_gf_add(b, p[0], p[1]);
    ac_gf_add(t, q[0], q[1]);
    ac_gf_mul(b, b, t);
    ac_gf_mul(c, p[3], q[3]);
    ac_gf_mul(c, c, g_d2);
    ac_gf_mul(d, p[2], q[2]);
    ac_gf_add(d, d, d);
    ac_gf_sub(e, b, a);
    ac_gf_sub(f, d, c);
    ac_gf_add(g, d, c);
    ac_gf_add(h, b, a);
    ac_gf_mul(p[0], e, f);
    ac_gf_mul(p[1], h, g);
    ac_gf_mul(p[2], g, f);
    ac_gf_mul(p[3], e, h);
}

static void ac_point_swap(AcGf p[4], AcGf q[4], uint8_t swap)
{
    size_t index;

    for (index = 0; index < 4u; ++index) {
        ac_gf_select(p[index], q[index], swap);
    }
}

static void ac_point_pack(uint8_t output[32], AcGf p[4])
{
    AcGf zi;
    AcGf tx;
    AcGf ty;

    ac_gf_invert(zi, p[2]);
    ac_gf_mul(tx, p[0], zi);
    ac_gf_mul(ty, p[1], zi);
    ac_gf_pack(output, ty);
    output[31] = (uint8_t)(output[31] ^ (ac_gf_parity(tx) << 7u));
}

static void ac_point_scalarmult(AcGf p[4], AcGf q[4], const uint8_t scalar[32])
{
    int bit;

    ac_gf_copy(p[0], g_gf0);
    ac_gf_copy(p[1], g_gf1);
    ac_gf_copy(p[2], g_gf1);
    ac_gf_copy(p[3], g_gf0);
    for (bit = 255; bit >= 0; --bit) {
        const uint8_t value =
            (uint8_t)((scalar[bit / 8] >> (unsigned int)(bit & 7)) & 1u);
        ac_point_swap(p, q, value);
        ac_point_add(q, p);
        ac_point_add(p, p);
        ac_point_swap(p, q, value);
    }
}

static void ac_point_scalarbase(AcGf p[4], const uint8_t scalar[32])
{
    AcGf q[4];

    ac_gf_copy(q[0], g_base_x);
    ac_gf_copy(q[1], g_base_y);
    ac_gf_copy(q[2], g_gf1);
    ac_gf_mul(q[3], g_base_x, g_base_y);
    ac_point_scalarmult(p, q, scalar);
}

/* Decodes the negation of a compressed point; returns false off the curve. */
static bool ac_point_unpack_negated(AcGf r[4], const uint8_t encoded[32])
{
    AcGf t;
    AcGf check;
    AcGf num;
    AcGf den;
    AcGf den2;
    AcGf den4;
    AcGf den6;

    ac_gf_copy(r[2], g_gf1);
    ac_gf_unpack(r[1], encoded);
    ac_gf_square(num, r[1]);
    ac_gf_mul(den, num, g_d);
    ac_gf_sub(num, num, r[2]);
    ac_gf_add(den, r[2], den);

    ac_gf_square(den2, den);
    ac_gf_square(den4, den2);
    ac_gf_mul(den6, den4, den2);
    ac_gf_mul(t, den6, num);
    ac_gf_mul(t, t, den);

    ac_gf_pow2523(t, t);
    ac_gf_mul(t, t, num);
    ac_gf_mul(t, t, den);
    ac_gf_mul(t, t, den);
    ac_gf_mul(r[0], t, den);

    ac_gf_square(check, r[0]);
    ac_gf_mul(check, check, den);
    if (!ac_gf_equal(check, num)) {
        ac_gf_mul(r[0], r[0], g_sqrt_m1);
    }
    ac_gf_square(check, r[0]);
    ac_gf_mul(check, check, den);
    if (!ac_gf_equal(check, num)) {
        return false;
    }
    if (ac_gf_parity(r[0]) == (encoded[31] >> 7u)) {
        ac_gf_sub(r[0], g_gf0, r[0]);
    }
    ac_gf_mul(r[3], r[0], r[1]);
    return true;
}

static void ac_scalar_mod_order(uint8_t output[32], int64_t x[64])
{
    int64_t carry;
    size_t i;
    size_t j;

    for (i = 63; i >= 32u; --i) {
        carry = 0;
        for (j = i - 32u; j < i - 12u; ++j) {
            x[j] += carry - 16 * x[i] * g_order[j - (i - 32u)];
            carry = ac_floor_shift(x[j] + 128, 8u);
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32u; ++j) {
        x[j] += carry - ac_floor_shift(x[31], 4u) * g_order[j];
        carry = ac_floor_shift(x[j], 8u);
        x[j] &= 255;
    }
    for (j = 0; j < 32u; ++j) {
        x[j] -= carry * g_order[j];
    }
    for (i = 0; i < 32u; ++i) {
        x[i + 1u] += ac_floor_shift(x[i], 8u);
        output[i] = (uint8_t)(x[i] & 255);
    }
}

static void ac_scalar_reduce(uint8_t output[32], const uint8_t wide[64])
{
    int64_t x[64];
    size_t index;

    for (index = 0; index < 64u; ++index) {
        x[index] = wide[index];
    }
    ac_scalar_mod_order(output, x);
}

static bool ac_scalar_is_canonical(const uint8_t scalar[32])
{
    size_t index = 32;

    while (index-- != 0) {
        if ((int64_t)scalar[index] < g_order[index]) {
            return true;
        }
        if ((int64_t)scalar[index] > g_order[index]) {
            return false;
        }
    }
    return false;
}

bool ac_ed25519_verify_parts(
    const uint8_t signature[AC_ED25519_SIGNATURE_SIZE],
    const void *prefix,
    size_t prefix_length,
    const void *message,
    size_t message_length,
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE])
{
    AcSha512 hash;
    uint8_t digest[AC_SHA512_DIGEST_SIZE];
    uint8_t challenge[32];
    uint8_t encoded[32];
    AcGf p[4];
    AcGf q[4];

    if (signature == NULL || public_key == NULL ||
        (prefix == NULL && prefix_length != 0) ||
        (message == NULL && message_length != 0) ||
        !ac_scalar_is_canonical(signature + 32) ||
        !ac_point_unpack_negated(q, public_key)) {
        return false;
    }

    ac_sha512_init(&hash);
    ac_sha512_update(&hash, signature, 32u);
    ac_sha512_update(&hash, public_key, AC_ED25519_PUBLIC_KEY_SIZE);
    if (prefix_length != 0) {
        ac_sha512_update(&hash, prefix, prefix_length);
    }
    if (message_length != 0) {
        ac_sha512_update(&hash, message, message_length);
    }
    ac_sha512_final(&hash, digest);
    ac_scalar_reduce(challenge, digest);

    /* Accept iff [S]B - [k]A encodes to R. */
    ac_point_scalarmult(p, q, challenge);
    ac_point_scalarbase(q, signature + 32);
    ac_point_add(p, q);
    ac_point_pack(encoded, p);
    return memcmp(encoded, signature, sizeof(encoded)) == 0;
}

bool ac_ed25519_verify(
    const uint8_t signature[AC_ED25519_SIGNATURE_SIZE],
    const void *message,
    size_t message_length,
    const uint8_t public_key[AC_ED25519_PUBLIC_KEY_SIZE])
{
    return ac_ed25519_verify_parts(
        signature,
        NULL,
        0,
        message,
        message_length,
        public_key);
}
