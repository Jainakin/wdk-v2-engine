/*
 * WDK v2 Native Engine — BLAKE2b Implementation (RFC 7693)
 *
 * Supports variable output length (1..64 bytes). No keying support.
 */

#include "blake2b.h"
#include <string.h>

#define BLAKE2B_BLOCK_SIZE 128

/* ---------- initialization vectors --------------------------------------- */

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* ---------- sigma permutation table -------------------------------------- */

static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

/* ---------- context ------------------------------------------------------ */

typedef struct {
    uint64_t h[8];
    uint64_t t[2];     /* total bytes counter */
    uint64_t f[2];     /* finalization flags */
    uint8_t  buf[BLAKE2B_BLOCK_SIZE];
    size_t   buflen;
    size_t   outlen;
} blake2b_state;

/* ---------- helpers ------------------------------------------------------- */

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

static inline uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

/* ---------- G mixing function -------------------------------------------- */

#define G(r, i, a, b, c, d) do {                           \
    a = a + b + m[blake2b_sigma[r][2*i+0]];                \
    d = rotr64(d ^ a, 32);                                 \
    c = c + d;                                             \
    b = rotr64(b ^ c, 24);                                 \
    a = a + b + m[blake2b_sigma[r][2*i+1]];                \
    d = rotr64(d ^ a, 16);                                 \
    c = c + d;                                             \
    b = rotr64(b ^ c, 63);                                 \
} while (0)

/* ---------- compression function ----------------------------------------- */

static void blake2b_compress(blake2b_state *S, const uint8_t block[128])
{
    uint64_t m[16];
    uint64_t v[16];
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = load_le64(block + 8 * i);
    }

    for (i = 0; i < 8; i++) {
        v[i] = S->h[i];
    }

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    for (i = 0; i < 12; i++) {
        G(i, 0, v[ 0], v[ 4], v[ 8], v[12]);
        G(i, 1, v[ 1], v[ 5], v[ 9], v[13]);
        G(i, 2, v[ 2], v[ 6], v[10], v[14]);
        G(i, 3, v[ 3], v[ 7], v[11], v[15]);
        G(i, 4, v[ 0], v[ 5], v[10], v[15]);
        G(i, 5, v[ 1], v[ 6], v[11], v[12]);
        G(i, 6, v[ 2], v[ 7], v[ 8], v[13]);
        G(i, 7, v[ 3], v[ 4], v[ 9], v[14]);
    }

    for (i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

/* ---------- incremental counter ------------------------------------------ */

static void blake2b_increment_counter(blake2b_state *S, uint64_t inc)
{
    S->t[0] += inc;
    if (S->t[0] < inc) {
        S->t[1]++;
    }
}

/* ---------- init --------------------------------------------------------- */

static int blake2b_init(blake2b_state *S, size_t outlen)
{
    if (outlen == 0 || outlen > 64) {
        return -1;
    }

    memset(S, 0, sizeof(*S));

    for (int i = 0; i < 8; i++) {
        S->h[i] = blake2b_IV[i];
    }

    /* Parameter block: fan-out=1, depth=1, digest length=outlen */
    /* P[0] = outlen, P[1] = 0 (key length), P[2] = 1 (fanout), P[3] = 1 (depth) */
    S->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;
    S->outlen = outlen;

    return 0;
}

/* ---------- update ------------------------------------------------------- */

static void blake2b_update(blake2b_state *S, const uint8_t *in, size_t inlen)
{
    if (inlen == 0) return;

    size_t left = S->buflen;
    size_t fill = BLAKE2B_BLOCK_SIZE - left;

    if (inlen > fill) {
        S->buflen = 0;
        if (left > 0) {
            memcpy(S->buf + left, in, fill);
            blake2b_increment_counter(S, BLAKE2B_BLOCK_SIZE);
            blake2b_compress(S, S->buf);
            in    += fill;
            inlen -= fill;
        }

        while (inlen > BLAKE2B_BLOCK_SIZE) {
            blake2b_increment_counter(S, BLAKE2B_BLOCK_SIZE);
            blake2b_compress(S, in);
            in    += BLAKE2B_BLOCK_SIZE;
            inlen -= BLAKE2B_BLOCK_SIZE;
        }
    }

    memcpy(S->buf + S->buflen, in, inlen);
    S->buflen += inlen;
}

/* ---------- final -------------------------------------------------------- */

static void blake2b_final(blake2b_state *S, uint8_t *out)
{
    uint8_t buffer[64];

    blake2b_increment_counter(S, (uint64_t)S->buflen);
    S->f[0] = ~(uint64_t)0; /* set finalization flag */

    /* Pad remaining buffer with zeros */
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCK_SIZE - S->buflen);
    blake2b_compress(S, S->buf);

    /* Extract output */
    for (int i = 0; i < 8; i++) {
        store_le64(buffer + 8 * i, S->h[i]);
    }

    memcpy(out, buffer, S->outlen);
    memset(buffer, 0, sizeof(buffer));
}

/* ---------- public API ---------------------------------------------------- */

int wdk_blake2b(const uint8_t *data, size_t len, uint8_t *out, size_t out_len)
{
    blake2b_state S;

    if (!out || out_len == 0 || out_len > 64) {
        return -1;
    }

    if (blake2b_init(&S, out_len) != 0) {
        return -1;
    }

    blake2b_update(&S, data, len);
    blake2b_final(&S, out);

    memset(&S, 0, sizeof(S));
    return 0;
}
