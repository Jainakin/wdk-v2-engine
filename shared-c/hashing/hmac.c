/*
 * WDK v2 Native Engine — HMAC-SHA256 and HMAC-SHA512 (RFC 2104)
 */

#include "hmac.h"
#include "sha256.h"
#include "sha512.h"
#include <string.h>

/* ---------- HMAC-SHA256 --------------------------------------------------- */

void wdk_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32])
{
    uint8_t k_pad[WDK_SHA256_BLOCK_SIZE];
    uint8_t i_pad[WDK_SHA256_BLOCK_SIZE];
    uint8_t o_pad[WDK_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[WDK_SHA256_DIGEST_SIZE];
    wdk_sha256_ctx ctx;
    size_t i;

    /* If key is longer than block size, hash it first */
    if (key_len > WDK_SHA256_BLOCK_SIZE) {
        wdk_sha256(key, key_len, k_pad);
        memset(k_pad + WDK_SHA256_DIGEST_SIZE, 0,
               WDK_SHA256_BLOCK_SIZE - WDK_SHA256_DIGEST_SIZE);
    } else {
        memcpy(k_pad, key, key_len);
        memset(k_pad + key_len, 0, WDK_SHA256_BLOCK_SIZE - key_len);
    }

    /* Compute i_pad = k_pad XOR 0x36, o_pad = k_pad XOR 0x5c */
    for (i = 0; i < WDK_SHA256_BLOCK_SIZE; i++) {
        i_pad[i] = k_pad[i] ^ 0x36;
        o_pad[i] = k_pad[i] ^ 0x5c;
    }

    /* Inner hash: SHA256(i_pad || data) */
    wdk_sha256_init(&ctx);
    wdk_sha256_update(&ctx, i_pad, WDK_SHA256_BLOCK_SIZE);
    wdk_sha256_update(&ctx, data, data_len);
    wdk_sha256_final(&ctx, inner_hash);

    /* Outer hash: SHA256(o_pad || inner_hash) */
    wdk_sha256_init(&ctx);
    wdk_sha256_update(&ctx, o_pad, WDK_SHA256_BLOCK_SIZE);
    wdk_sha256_update(&ctx, inner_hash, WDK_SHA256_DIGEST_SIZE);
    wdk_sha256_final(&ctx, out);

    /* Clear sensitive intermediates */
    memset(k_pad, 0, sizeof(k_pad));
    memset(i_pad, 0, sizeof(i_pad));
    memset(o_pad, 0, sizeof(o_pad));
    memset(inner_hash, 0, sizeof(inner_hash));
}

/* ---------- HMAC-SHA512 --------------------------------------------------- */

void wdk_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64])
{
    uint8_t k_pad[WDK_SHA512_BLOCK_SIZE];
    uint8_t i_pad[WDK_SHA512_BLOCK_SIZE];
    uint8_t o_pad[WDK_SHA512_BLOCK_SIZE];
    uint8_t inner_hash[WDK_SHA512_DIGEST_SIZE];
    wdk_sha512_ctx ctx;
    size_t i;

    /* If key is longer than block size, hash it first */
    if (key_len > WDK_SHA512_BLOCK_SIZE) {
        wdk_sha512(key, key_len, k_pad);
        memset(k_pad + WDK_SHA512_DIGEST_SIZE, 0,
               WDK_SHA512_BLOCK_SIZE - WDK_SHA512_DIGEST_SIZE);
    } else {
        memcpy(k_pad, key, key_len);
        memset(k_pad + key_len, 0, WDK_SHA512_BLOCK_SIZE - key_len);
    }

    for (i = 0; i < WDK_SHA512_BLOCK_SIZE; i++) {
        i_pad[i] = k_pad[i] ^ 0x36;
        o_pad[i] = k_pad[i] ^ 0x5c;
    }

    /* Inner hash: SHA512(i_pad || data) */
    wdk_sha512_init(&ctx);
    wdk_sha512_update(&ctx, i_pad, WDK_SHA512_BLOCK_SIZE);
    wdk_sha512_update(&ctx, data, data_len);
    wdk_sha512_final(&ctx, inner_hash);

    /* Outer hash: SHA512(o_pad || inner_hash) */
    wdk_sha512_init(&ctx);
    wdk_sha512_update(&ctx, o_pad, WDK_SHA512_BLOCK_SIZE);
    wdk_sha512_update(&ctx, inner_hash, WDK_SHA512_DIGEST_SIZE);
    wdk_sha512_final(&ctx, out);

    memset(k_pad, 0, sizeof(k_pad));
    memset(i_pad, 0, sizeof(i_pad));
    memset(o_pad, 0, sizeof(o_pad));
    memset(inner_hash, 0, sizeof(inner_hash));
}
