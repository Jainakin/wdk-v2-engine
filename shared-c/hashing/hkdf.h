/*
 * hkdf.h — HKDF (HMAC-based Key Derivation Function) per RFC 5869
 */

#ifndef WDK_HKDF_H
#define WDK_HKDF_H

#include <stdint.h>
#include <stddef.h>

/* HKDF-SHA256: extract + expand. out_len must be <= 255 * 32 */
int wdk_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

/* HKDF-SHA512: extract + expand. out_len must be <= 255 * 64 */
int wdk_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

#endif /* WDK_HKDF_H */
