/*
 * hkdf.c — HKDF (RFC 5869) using HMAC-SHA256 and HMAC-SHA512
 *
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
 * HKDF-Expand:  OKM = T(1) || T(2) || ... where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 */

#include "hkdf.h"
#include "hmac.h"
#include <string.h>

static int hkdf_generic(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *out, size_t out_len,
                         size_t h_len,
                         void (*hmac_fn)(const uint8_t *, size_t,
                                         const uint8_t *, size_t,
                                         uint8_t *))
{
    uint8_t prk[64];       /* pseudo-random key (max SHA-512 = 64) */
    uint8_t t_prev[64];    /* T(i-1) */
    uint8_t hmac_input[64 + 256 + 1]; /* T(i-1) || info || counter */

    if (!ikm || !out || h_len > 64)
        return -1;

    /* Max output: 255 * h_len */
    if (out_len > 255 * h_len)
        return -1;

    /* Info must fit in our buffer */
    if (info_len > 256)
        return -1;

    /* Extract: PRK = HMAC-Hash(salt, IKM) */
    if (salt && salt_len > 0) {
        hmac_fn(salt, salt_len, ikm, ikm_len, prk);
    } else {
        /* If no salt, use h_len zeros as salt */
        uint8_t zero_salt[64];
        memset(zero_salt, 0, h_len);
        hmac_fn(zero_salt, h_len, ikm, ikm_len, prk);
    }

    /* Expand */
    size_t remaining = out_len;
    size_t offset = 0;
    uint8_t counter = 1;
    size_t t_prev_len = 0;

    while (remaining > 0) {
        size_t input_len = 0;

        /* Build HMAC input: T(i-1) || info || counter */
        if (t_prev_len > 0) {
            memcpy(hmac_input, t_prev, t_prev_len);
            input_len += t_prev_len;
        }
        if (info && info_len > 0) {
            memcpy(hmac_input + input_len, info, info_len);
            input_len += info_len;
        }
        hmac_input[input_len] = counter;
        input_len += 1;

        /* T(i) = HMAC-Hash(PRK, T(i-1) || info || i) */
        hmac_fn(prk, h_len, hmac_input, input_len, t_prev);
        t_prev_len = h_len;

        size_t copy_len = remaining < h_len ? remaining : h_len;
        memcpy(out + offset, t_prev, copy_len);
        offset += copy_len;
        remaining -= copy_len;
        counter++;
    }

    /* Wipe sensitive intermediates */
    memset(prk, 0, sizeof(prk));
    memset(t_prev, 0, sizeof(t_prev));

    return 0;
}

int wdk_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    return hkdf_generic(ikm, ikm_len, salt, salt_len, info, info_len,
                        out, out_len, 32, wdk_hmac_sha256);
}

int wdk_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    return hkdf_generic(ikm, ikm_len, salt, salt_len, info, info_len,
                        out, out_len, 64, wdk_hmac_sha512);
}
