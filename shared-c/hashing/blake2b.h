/*
 * WDK v2 Native Engine — BLAKE2b
 *
 * Supports variable output length (1..64 bytes). No keying.
 */

#ifndef WDK_BLAKE2B_H
#define WDK_BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_BLAKE2B_MAX_DIGEST_SIZE  64

/**
 * One-shot BLAKE2b hash.
 *
 * @param data     Input data.
 * @param len      Length of input data.
 * @param out      Output buffer (must be at least out_len bytes).
 * @param out_len  Desired digest length (1..64).
 * @return         0 on success, -1 on invalid parameters.
 */
int wdk_blake2b(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* WDK_BLAKE2B_H */
