/*
 * aes_gcm.h — AES-256-GCM authenticated encryption
 *
 * Encrypt: plaintext + key + iv → ciphertext || 16-byte tag
 * Decrypt: ciphertext || tag + key + iv → plaintext (or error if tag mismatch)
 */

#ifndef WDK_AES_GCM_H
#define WDK_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

/*
 * AES-256-GCM Encrypt
 *
 * key:        32 bytes (AES-256 key)
 * iv:         12 bytes (standard GCM nonce)
 * plaintext:  input data
 * pt_len:     plaintext length
 * aad:        additional authenticated data (can be NULL)
 * aad_len:    AAD length
 * out:        output buffer, must be at least pt_len + 16 bytes (ciphertext + tag)
 *
 * Returns 0 on success, -1 on error.
 */
int wdk_aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                         const uint8_t *plaintext, size_t pt_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *out);

/*
 * AES-256-GCM Decrypt
 *
 * key:        32 bytes
 * iv:         12 bytes
 * ciphertext: input data (ciphertext + 16-byte tag appended)
 * ct_len:     total length including tag (must be >= 16)
 * aad:        additional authenticated data (can be NULL)
 * aad_len:    AAD length
 * out:        output buffer, must be at least ct_len - 16 bytes
 *
 * Returns 0 on success, -1 if authentication fails.
 */
int wdk_aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *out);

#endif /* WDK_AES_GCM_H */
