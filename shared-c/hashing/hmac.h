/*
 * WDK v2 Native Engine — HMAC-SHA256 and HMAC-SHA512 (RFC 2104)
 */

#ifndef WDK_HMAC_H
#define WDK_HMAC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC-SHA256. Output is 32 bytes.
 */
void wdk_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]);

/**
 * HMAC-SHA512. Output is 64 bytes.
 */
void wdk_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]);

#ifdef __cplusplus
}
#endif

#endif /* WDK_HMAC_H */
