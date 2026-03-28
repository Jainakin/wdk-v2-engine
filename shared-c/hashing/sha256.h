/*
 * WDK v2 Native Engine — SHA-256 (FIPS 180-4)
 */

#ifndef WDK_SHA256_H
#define WDK_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_SHA256_DIGEST_SIZE  32
#define WDK_SHA256_BLOCK_SIZE   64

typedef struct {
    uint32_t state[8];
    uint8_t  buffer[WDK_SHA256_BLOCK_SIZE];
    uint64_t count; /* total bytes processed */
} wdk_sha256_ctx;

/**
 * One-shot SHA-256 hash.
 */
void wdk_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * Streaming interface.
 */
void wdk_sha256_init(wdk_sha256_ctx *ctx);
void wdk_sha256_update(wdk_sha256_ctx *ctx, const uint8_t *data, size_t len);
void wdk_sha256_final(wdk_sha256_ctx *ctx, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* WDK_SHA256_H */
