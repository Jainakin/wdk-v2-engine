/*
 * WDK v2 Native Engine — RIPEMD-160 Implementation
 *
 * Used for Bitcoin address generation: Hash160 = RIPEMD160(SHA256(pubkey)).
 * Based on the original specification by Hans Dobbertin, Antoon Bosselaers,
 * and Bart Preneel.
 */

#include "ripemd160.h"
#include <string.h>

/* ---------- helpers ------------------------------------------------------- */

static inline uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t load_le32(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void store_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* ---------- RIPEMD-160 nonlinear functions -------------------------------- */

static inline uint32_t f0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

/* ---------- round constants ---------------------------------------------- */

/* Left rounds: additive constants */
#define KL0 0x00000000u
#define KL1 0x5a827999u
#define KL2 0x6ed9eba1u
#define KL3 0x8f1bbcdcu
#define KL4 0xa953fd4eu

/* Right rounds: additive constants */
#define KR0 0x50a28be6u
#define KR1 0x5c4dd124u
#define KR2 0x6d703ef3u
#define KR3 0x7a6d76e9u
#define KR4 0x00000000u

/* Message word selection (left) */
static const int RL[80] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};

/* Message word selection (right) */
static const int RR[80] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

/* Shift amounts (left) */
static const unsigned SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};

/* Shift amounts (right) */
static const unsigned SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

/* ---------- compression function ----------------------------------------- */

static void ripemd160_compress(uint32_t state[5], const uint8_t block[64])
{
    uint32_t X[16];
    uint32_t al, bl, cl, dl, el;
    uint32_t ar, br, cr, dr, er;
    uint32_t t;
    int i;

    for (i = 0; i < 16; i++) {
        X[i] = load_le32(block + 4 * i);
    }

    al = ar = state[0];
    bl = br = state[1];
    cl = cr = state[2];
    dl = dr = state[3];
    el = er = state[4];

    for (i = 0; i < 80; i++) {
        /* Left strand */
        if (i < 16)      t = f0(bl, cl, dl) + KL0;
        else if (i < 32) t = f1(bl, cl, dl) + KL1;
        else if (i < 48) t = f2(bl, cl, dl) + KL2;
        else if (i < 64) t = f3(bl, cl, dl) + KL3;
        else              t = f4(bl, cl, dl) + KL4;
        t += al + X[RL[i]];
        t = rotl32(t, SL[i]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = t;

        /* Right strand */
        if (i < 16)      t = f4(br, cr, dr) + KR0;
        else if (i < 32) t = f3(br, cr, dr) + KR1;
        else if (i < 48) t = f2(br, cr, dr) + KR2;
        else if (i < 64) t = f1(br, cr, dr) + KR3;
        else              t = f0(br, cr, dr) + KR4;
        t += ar + X[RR[i]];
        t = rotl32(t, SR[i]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = t;
    }

    t = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = t;
}

/* ---------- public API ---------------------------------------------------- */

void wdk_ripemd160(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint32_t state[5];
    uint8_t  block[64];
    uint64_t total_bits;
    size_t   remaining;

    /* Initial hash values */
    state[0] = 0x67452301u;
    state[1] = 0xefcdab89u;
    state[2] = 0x98badcfeu;
    state[3] = 0x10325476u;
    state[4] = 0xc3d2e1f0u;

    total_bits = (uint64_t)len * 8;
    remaining = len;

    /* Process full blocks */
    while (remaining >= 64) {
        ripemd160_compress(state, data);
        data      += 64;
        remaining -= 64;
    }

    /* Final block with padding */
    memset(block, 0, 64);
    memcpy(block, data, remaining);
    block[remaining] = 0x80;

    if (remaining >= 56) {
        ripemd160_compress(state, block);
        memset(block, 0, 64);
    }

    store_le64(block + 56, total_bits);
    ripemd160_compress(state, block);

    /* Output */
    for (int i = 0; i < 5; i++) {
        store_le32(out + 4 * i, state[i]);
    }
}
