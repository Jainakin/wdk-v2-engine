/*
 * pbkdf2.c — PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
 *
 * RFC 2898 / RFC 8018 implementation using our HMAC primitives.
 */

#include "pbkdf2.h"
#include "hmac.h"
#include <string.h>

/* Generic PBKDF2 with configurable PRF */
static int pbkdf2_generic(const uint8_t *password, size_t pw_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations, uint8_t *out, size_t key_len,
                           size_t h_len,
                           void (*hmac_fn)(const uint8_t *, size_t,
                                           const uint8_t *, size_t,
                                           uint8_t *))
{
    uint8_t U[64];  /* max HMAC output (SHA-512 = 64) */
    uint8_t T[64];
    uint8_t salt_block[512]; /* salt + 4-byte counter */
    uint32_t block_num = 1;
    size_t remaining = key_len;
    size_t offset = 0;

    if (!password || !salt || !out || iterations == 0)
        return -1;
    if (salt_len > sizeof(salt_block) - 4)
        return -1;
    if (h_len > 64)
        return -1;

    while (remaining > 0) {
        size_t copy_len = remaining < h_len ? remaining : h_len;

        /* Construct salt || INT_32_BE(block_num) */
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (uint8_t)(block_num >> 24);
        salt_block[salt_len + 1] = (uint8_t)(block_num >> 16);
        salt_block[salt_len + 2] = (uint8_t)(block_num >> 8);
        salt_block[salt_len + 3] = (uint8_t)(block_num);

        /* U_1 = PRF(password, salt || INT_32_BE(i)) */
        hmac_fn(password, pw_len, salt_block, salt_len + 4, U);
        memcpy(T, U, h_len);

        /* U_2 .. U_c */
        for (uint32_t j = 1; j < iterations; j++) {
            hmac_fn(password, pw_len, U, h_len, U);
            for (size_t k = 0; k < h_len; k++) {
                T[k] ^= U[k];
            }
        }

        memcpy(out + offset, T, copy_len);
        offset += copy_len;
        remaining -= copy_len;
        block_num++;
    }

    /* Wipe sensitive intermediates */
    memset(U, 0, sizeof(U));
    memset(T, 0, sizeof(T));

    return 0;
}

int wdk_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t key_len)
{
    return pbkdf2_generic(password, pw_len, salt, salt_len,
                          iterations, out, key_len, 32, wdk_hmac_sha256);
}

int wdk_pbkdf2_sha512(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t key_len)
{
    return pbkdf2_generic(password, pw_len, salt, salt_len,
                          iterations, out, key_len, 64, wdk_hmac_sha512);
}
