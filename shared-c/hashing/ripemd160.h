/*
 * WDK v2 Native Engine — RIPEMD-160
 *
 * Used for Bitcoin address generation: Hash160 = RIPEMD160(SHA256(pubkey)).
 */

#ifndef WDK_RIPEMD160_H
#define WDK_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_RIPEMD160_DIGEST_SIZE  20

/**
 * One-shot RIPEMD-160 hash.
 */
void wdk_ripemd160(const uint8_t *data, size_t len, uint8_t out[20]);

#ifdef __cplusplus
}
#endif

#endif /* WDK_RIPEMD160_H */
