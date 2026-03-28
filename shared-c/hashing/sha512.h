/*
 * WDK v2 Native Engine — SHA-512 (FIPS 180-4)
 */

#ifndef WDK_SHA512_H
#define WDK_SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_SHA512_DIGEST_SIZE  64
#define WDK_SHA512_BLOCK_SIZE  128

typedef struct {
    uint64_t state[8];
    uint8_t  buffer[WDK_SHA512_BLOCK_SIZE];
    uint64_t count_lo; /* total bytes processed (low 64 bits) */
    uint64_t count_hi; /* total bytes processed (high 64 bits) */
} wdk_sha512_ctx;

/**
 * One-shot SHA-512 hash.
 */
void wdk_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/**
 * Streaming interface.
 */
void wdk_sha512_init(wdk_sha512_ctx *ctx);
void wdk_sha512_update(wdk_sha512_ctx *ctx, const uint8_t *data, size_t len);
void wdk_sha512_final(wdk_sha512_ctx *ctx, uint8_t out[64]);

#ifdef __cplusplus
}
#endif

#endif /* WDK_SHA512_H */
