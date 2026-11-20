#include "blake2s.h"
#include <string.h>

#define ROTR32(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

// Manual little-endian load (deliberate baseline for optimization)
// althought I will have to include this part on the report, because solving endianness is part of the optimization
#define LOAD32_LE(p) (               \
    ((uint32_t)((p)[0])      ) |     \
    ((uint32_t)((p)[1]) <<  8) |     \
    ((uint32_t)((p)[2]) << 16) |     \
    ((uint32_t)((p)[3]) << 24) )

#define G(a, b, c, d, x, y) do {     \
    (a) = (a) + (b) + (x);           \
    (d) = ROTR32((d) ^ (a), 16);     \
    (c) = (c) + (d);                 \
    (b) = ROTR32((b) ^ (c), 12);     \
    (a) = (a) + (b) + (y);           \
    (d) = ROTR32((d) ^ (a), 8);      \
    (c) = (c) + (d);                 \
    (b) = ROTR32((b) ^ (c), 7);      \
} while (0)

static const uint32_t blake2s_IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};

static const uint8_t blake2s_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static void blake2s_compress(BLAKE2S_CTX *ctx, int is_last) {
    uint32_t v[16];
    uint32_t m[16];
    size_t i;

    for (i = 0; i < 8; ++i) {
        v[i]     = ctx->h[i];
        v[i + 8] = blake2s_IV[i];
    }

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (is_last) {
        v[14] = ~v[14];
    }

    for (i = 0; i < 16; ++i) {
        m[i] = LOAD32_LE(ctx->buf + (i * 4));
    }

    for (i = 0; i < 10; ++i) {
        const uint8_t *s = blake2s_SIGMA[i];
        // Column step
        G(v[0], v[4], v[8],  v[12], m[s[0]],  m[s[1]]);
        G(v[1], v[5], v[9],  v[13], m[s[2]],  m[s[3]]);
        G(v[2], v[6], v[10], v[14], m[s[4]],  m[s[5]]);
        G(v[3], v[7], v[11], v[15], m[s[6]],  m[s[7]]);
        // Diagonal step
        G(v[0], v[5], v[10], v[15], m[s[8]],  m[s[9]]);
        G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        G(v[2], v[7], v[8],  v[13], m[s[12]], m[s[13]]);
        G(v[3], v[4], v[9],  v[14], m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8; ++i) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

void blake2s_init(BLAKE2S_CTX *ctx) {
    for (size_t i = 0; i < 8; ++i) {
        ctx->h[i] = blake2s_IV[i];
    }
    // Parameter block: digest_len = 32 (0x20), key_len = 0, fanout = 1, depth = 1
    ctx->h[0] ^= 0x01010020U;
    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->buflen = 0;
}

void blake2s_update(BLAKE2S_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // Compress ONLY when buffer is full AND more data is arriving,
        // so the final block always gets compressed in blake2s_final with is_last = 1.
        if (ctx->buflen == 64) {
            ctx->t[0] += 64;
            if (ctx->t[0] < 64) {
                ctx->t[1]++;
            }
            blake2s_compress(ctx, 0);
            ctx->buflen = 0;
        }
        ctx->buf[ctx->buflen++] = data[i];
    }
}

void blake2s_final(BLAKE2S_CTX *ctx, uint8_t hash[]) {
    ctx->t[0] += (uint32_t)ctx->buflen;
    if (ctx->t[0] < ctx->buflen) {
        ctx->t[1]++;
    }

    if (ctx->buflen < 64) {
        memset(ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);
    }

    blake2s_compress(ctx, 1);

    // Output hash in little-endian byte order
    for (size_t i = 0; i < 32; ++i) {
        hash[i] = (uint8_t)((ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFFU);
    }
}
