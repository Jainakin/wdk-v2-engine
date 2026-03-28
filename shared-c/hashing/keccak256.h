/*
 * WDK v2 Native Engine — Keccak-256
 *
 * This is Ethereum's Keccak-256, NOT NIST SHA-3.
 * Uses domain separator 0x01 (Keccak) rather than 0x06 (SHA-3).
 * rate = 1088 bits (136 bytes), capacity = 512 bits.
 */

#ifndef WDK_KECCAK256_H
#define WDK_KECCAK256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_KECCAK256_DIGEST_SIZE  32

/**
 * One-shot Keccak-256 hash.
 */
void wdk_keccak256(const uint8_t *data, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* WDK_KECCAK256_H */
