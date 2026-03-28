/*
 * aes_gcm.c — AES-256-GCM authenticated encryption
 *
 * Self-contained implementation with no external dependencies.
 * AES core: FIPS 197 (Rijndael with 256-bit key, 14 rounds)
 * GCM mode: NIST SP 800-38D
 *
 * This is a clean-room implementation suitable for embedded use.
 * Not side-channel resistant — use hardware AES on production platforms.
 */

#include "aes_gcm.h"
#include <string.h>

/* ── AES-256 Core ─────────────────────────────────────────────── */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiply by 2 */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* AES-256 key expansion: 32-byte key → 15 round keys (240 bytes) */
static void aes256_key_expand(const uint8_t key[32], uint8_t rk[240]) {
    int i;
    uint8_t temp[4];

    memcpy(rk, key, 32);

    for (i = 8; i < 60; i++) {
        memcpy(temp, rk + (i - 1) * 4, 4);

        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[i / 8 - 1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        rk[i * 4 + 0] = rk[(i - 8) * 4 + 0] ^ temp[0];
        rk[i * 4 + 1] = rk[(i - 8) * 4 + 1] ^ temp[1];
        rk[i * 4 + 2] = rk[(i - 8) * 4 + 2] ^ temp[2];
        rk[i * 4 + 3] = rk[(i - 8) * 4 + 3] ^ temp[3];
    }
}

/* Single AES block encrypt (in-place, 16 bytes) */
static void aes256_encrypt_block(const uint8_t rk[240], uint8_t block[16]) {
    int round, i;
    uint8_t tmp[16];

    /* AddRoundKey (initial) */
    for (i = 0; i < 16; i++) block[i] ^= rk[i];

    for (round = 1; round <= 14; round++) {
        /* SubBytes */
        for (i = 0; i < 16; i++) block[i] = sbox[block[i]];

        /* ShiftRows */
        uint8_t t;
        t = block[1]; block[1] = block[5]; block[5] = block[9]; block[9] = block[13]; block[13] = t;
        t = block[2]; block[2] = block[10]; block[10] = t; t = block[6]; block[6] = block[14]; block[14] = t;
        t = block[15]; block[15] = block[11]; block[11] = block[7]; block[7] = block[3]; block[3] = t;

        /* MixColumns (skip on last round) */
        if (round < 14) {
            for (i = 0; i < 4; i++) {
                int c = i * 4;
                uint8_t a0 = block[c], a1 = block[c+1], a2 = block[c+2], a3 = block[c+3];
                uint8_t x0 = xtime(a0), x1 = xtime(a1), x2 = xtime(a2), x3 = xtime(a3);
                tmp[c+0] = x0 ^ x1 ^ a1 ^ a2 ^ a3;
                tmp[c+1] = a0 ^ x1 ^ x2 ^ a2 ^ a3;
                tmp[c+2] = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                tmp[c+3] = x0 ^ a0 ^ a1 ^ a2 ^ x3;
            }
            memcpy(block, tmp, 16);
        }

        /* AddRoundKey */
        for (i = 0; i < 16; i++) block[i] ^= rk[round * 16 + i];
    }
}

/* ── GCM mode ─────────────────────────────────────────────────── */

/* GF(2^128) multiplication (schoolbook, not constant-time) */
static void ghash_mult(const uint8_t H[16], const uint8_t X[16], uint8_t out[16]) {
    uint8_t V[16];
    uint8_t Z[16];

    memcpy(V, H, 16);
    memset(Z, 0, 16);

    for (int i = 0; i < 128; i++) {
        if (X[i / 8] & (1 << (7 - (i % 8)))) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }

        /* V = V >> 1 in GF(2^128) with reduction polynomial */
        uint8_t carry = V[15] & 1;
        for (int j = 15; j > 0; j--) {
            V[j] = (V[j] >> 1) | (V[j-1] << 7);
        }
        V[0] >>= 1;
        if (carry) V[0] ^= 0xe1; /* reduction: x^128 + x^7 + x^2 + x + 1 */
    }

    memcpy(out, Z, 16);
}

/* GHASH: incremental hash of data blocks */
static void ghash_update(const uint8_t H[16], uint8_t state[16],
                          const uint8_t *data, size_t len) {
    uint8_t block[16];

    while (len >= 16) {
        for (int i = 0; i < 16; i++) state[i] ^= data[i];
        ghash_mult(H, state, state);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        memset(block, 0, 16);
        memcpy(block, data, len);
        for (int i = 0; i < 16; i++) state[i] ^= block[i];
        ghash_mult(H, state, state);
    }
}

/* Compute GCTR: AES-CTR encryption with 32-bit big-endian counter in last 4 bytes */
static void gctr(const uint8_t rk[240], const uint8_t icb[16],
                  const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t counter[16];
    uint8_t keystream[16];

    memcpy(counter, icb, 16);

    while (len > 0) {
        size_t chunk = len < 16 ? len : 16;
        memcpy(keystream, counter, 16);
        aes256_encrypt_block(rk, keystream);

        for (size_t i = 0; i < chunk; i++) {
            out[i] = in[i] ^ keystream[i];
        }

        /* Increment counter (last 4 bytes, big-endian) */
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }

        in += chunk;
        out += chunk;
        len -= chunk;
    }
}

/* Store 64-bit value as big-endian */
static void put_be64(uint8_t *dst, uint64_t val) {
    dst[0] = (uint8_t)(val >> 56);
    dst[1] = (uint8_t)(val >> 48);
    dst[2] = (uint8_t)(val >> 40);
    dst[3] = (uint8_t)(val >> 32);
    dst[4] = (uint8_t)(val >> 24);
    dst[5] = (uint8_t)(val >> 16);
    dst[6] = (uint8_t)(val >> 8);
    dst[7] = (uint8_t)(val);
}

int wdk_aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                         const uint8_t *plaintext, size_t pt_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *out) {
    uint8_t rk[240];
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t J0_inc[16];
    uint8_t ghash_state[16];
    uint8_t len_block[16];

    if (!key || !iv || !out) return -1;
    if (pt_len > 0 && !plaintext) return -1;

    /* Key expansion */
    aes256_key_expand(key, rk);

    /* H = AES_K(0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(rk, H);

    /* J0 = IV || 0^31 || 1 (for 96-bit IV) */
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* inc32(J0) for GCTR of plaintext */
    memcpy(J0_inc, J0, 16);
    for (int i = 15; i >= 12; i--) {
        if (++J0_inc[i] != 0) break;
    }

    /* Encrypt plaintext: C = GCTR_K(inc32(J0), P) */
    gctr(rk, J0_inc, plaintext, pt_len, out);

    /* GHASH: process AAD, then ciphertext, then length block */
    memset(ghash_state, 0, 16);

    if (aad && aad_len > 0) {
        ghash_update(H, ghash_state, aad, aad_len);
    }

    ghash_update(H, ghash_state, out, pt_len);

    /* Length block: len(A) || len(C) in bits, as 64-bit big-endian */
    memset(len_block, 0, 16);
    put_be64(len_block, (uint64_t)aad_len * 8);
    put_be64(len_block + 8, (uint64_t)pt_len * 8);
    ghash_update(H, ghash_state, len_block, 16);

    /* Tag = GCTR_K(J0, GHASH) */
    uint8_t tag[16];
    memcpy(tag, ghash_state, 16);
    uint8_t j0_keystream[16];
    memcpy(j0_keystream, J0, 16);
    aes256_encrypt_block(rk, j0_keystream);
    for (int i = 0; i < 16; i++) tag[i] ^= j0_keystream[i];

    /* Append tag after ciphertext */
    memcpy(out + pt_len, tag, 16);

    /* Wipe round keys */
    memset(rk, 0, sizeof(rk));

    return 0;
}

int wdk_aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *out) {
    uint8_t rk[240];
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t J0_inc[16];
    uint8_t ghash_state[16];
    uint8_t len_block[16];
    uint8_t computed_tag[16];

    if (!key || !iv || !out) return -1;
    if (ct_len < 16) return -1; /* Must have at least a 16-byte tag */
    if (ct_len > 16 && !ciphertext) return -1;

    size_t data_len = ct_len - 16;
    const uint8_t *tag = ciphertext + data_len;

    /* Key expansion */
    aes256_key_expand(key, rk);

    /* H = AES_K(0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(rk, H);

    /* J0 = IV || 0^31 || 1 */
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* Verify tag BEFORE decrypting (GHASH over ciphertext, not plaintext) */
    memset(ghash_state, 0, 16);
    if (aad && aad_len > 0) {
        ghash_update(H, ghash_state, aad, aad_len);
    }
    ghash_update(H, ghash_state, ciphertext, data_len);

    memset(len_block, 0, 16);
    put_be64(len_block, (uint64_t)aad_len * 8);
    put_be64(len_block + 8, (uint64_t)data_len * 8);
    ghash_update(H, ghash_state, len_block, 16);

    /* computed_tag = GCTR_K(J0, GHASH) */
    memcpy(computed_tag, ghash_state, 16);
    uint8_t j0_keystream[16];
    memcpy(j0_keystream, J0, 16);
    aes256_encrypt_block(rk, j0_keystream);
    for (int i = 0; i < 16; i++) computed_tag[i] ^= j0_keystream[i];

    /* Constant-time tag comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(rk, 0, sizeof(rk));
        return -1; /* Authentication failed */
    }

    /* Decrypt: P = GCTR_K(inc32(J0), C) */
    memcpy(J0_inc, J0, 16);
    for (int i = 15; i >= 12; i--) {
        if (++J0_inc[i] != 0) break;
    }
    gctr(rk, J0_inc, ciphertext, data_len, out);

    memset(rk, 0, sizeof(rk));
    return 0;
}
