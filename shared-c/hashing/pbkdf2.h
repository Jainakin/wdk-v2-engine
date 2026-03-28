/*
 * pbkdf2.h — PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
 */

#ifndef WDK_PBKDF2_H
#define WDK_PBKDF2_H

#include <stdint.h>
#include <stddef.h>

/* PBKDF2-HMAC-SHA256: derives key_len bytes into out */
int wdk_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t key_len);

/* PBKDF2-HMAC-SHA512: derives key_len bytes into out */
int wdk_pbkdf2_sha512(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t key_len);

#endif /* WDK_PBKDF2_H */
