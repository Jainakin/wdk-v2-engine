/*
 * WDK v2 Native Engine — Keccak-256 Implementation
 *
 * Ethereum's Keccak-256 (NOT NIST SHA-3).
 * Sponge construction: rate=1088 bits (136 bytes), capacity=512 bits.
 * Domain separator: 0x01 (Keccak), NOT 0x06 (SHA-3).
 */

#include "keccak256.h"
#include <string.h>

#define KECCAK_ROUNDS  24
#define KECCAK_RATE    136  /* (1600 - 2*256) / 8 = 136 bytes */

/* ---------- rotation offsets ---------------------------------------------- */

static const unsigned keccak_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccak_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,
     8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1
};

/* ---------- round constants ---------------------------------------------- */

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* ---------- helpers ------------------------------------------------------- */

static inline uint64_t rotl64(uint64_t x, unsigned n)
{
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t load_le64(const uint8_t *p)
{
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
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

/* ---------- Keccak-f[1600] permutation ----------------------------------- */

static void keccakf(uint64_t st[25])
{
    uint64_t t, bc[5];
    int i, j, r;

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        /* Theta */
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        /* Rho and Pi */
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccak_piln[i];
            bc[0] = st[j];
            st[j] = rotl64(t, keccak_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota */
        st[0] ^= keccak_rc[r];
    }
}

/* ---------- public API ---------------------------------------------------- */

void wdk_keccak256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint64_t st[25];
    uint8_t  temp[KECCAK_RATE];
    size_t   i;

    memset(st, 0, sizeof(st));

    /* Absorb full blocks */
    while (len >= KECCAK_RATE) {
        for (i = 0; i < KECCAK_RATE / 8; i++) {
            st[i] ^= load_le64(data + 8 * i);
        }
        keccakf(st);
        data += KECCAK_RATE;
        len  -= KECCAK_RATE;
    }

    /* Absorb final partial block with padding */
    memset(temp, 0, KECCAK_RATE);
    memcpy(temp, data, len);

    /* Keccak padding: 0x01 domain separator (NOT 0x06 for SHA-3) */
    temp[len] = 0x01;
    temp[KECCAK_RATE - 1] |= 0x80;

    for (i = 0; i < KECCAK_RATE / 8; i++) {
        st[i] ^= load_le64(temp + 8 * i);
    }
    keccakf(st);

    /* Squeeze: output 32 bytes (256 bits) */
    for (i = 0; i < 4; i++) {
        store_le64(out + 8 * i, st[i]);
    }
}
