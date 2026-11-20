#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stdint.h>
#include <stddef.h>
// baseline blake2s implementation. Dunno how it will actually translate into real baseline, because
// it says " they follow the exact same uniform 3 function baremetal API( init, update, final ) as my sha256.c
typedef struct {
    uint8_t  buf[64];  // Placed first for natural alignment
    uint32_t h[8];     // Chained hash state
    uint32_t t[2];     // 64-bit byte counter (t[0] low, t[1] high)
    size_t   buflen;   // Bytes currently buffered
} BLAKE2S_CTX;

void blake2s_init(BLAKE2S_CTX *ctx);
void blake2s_update(BLAKE2S_CTX *ctx, const uint8_t data[], size_t len);
void blake2s_final(BLAKE2S_CTX *ctx, uint8_t hash[]);

#endif // BLAKE2S_H
