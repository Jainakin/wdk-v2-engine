/*
 * WDK v2 Native Engine — Key Store
 *
 * Opaque key handle table for managing cryptographic key material.
 * Supports up to 256 concurrent keys. All key material is securely
 * zeroed on release or destruction.
 */

#ifndef WDK_KEY_STORE_H
#define WDK_KEY_STORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_KEY_STORE_MAX_KEYS   256
#define WDK_KEY_STORE_MAX_BYTES   64

/* Curve identifiers */
#define WDK_CURVE_SECP256K1  0
#define WDK_CURVE_ED25519    1

/**
 * Initialize the key store. Zeros out the entire table.
 * Must be called before any other key_store function.
 */
void wdk_key_store_init(void);

/**
 * Add a key to the store.
 *
 * @param bytes   Key material (copied into the store).
 * @param len     Length of key material in bytes (1..64).
 * @param curve   Curve identifier (WDK_CURVE_SECP256K1 or WDK_CURVE_ED25519).
 * @return        Handle (0..255) on success, -1 if the store is full or
 *                parameters are invalid.
 */
int32_t wdk_key_store_add(const uint8_t *bytes, size_t len, int curve);

/**
 * Retrieve a pointer to key material for a given handle.
 *
 * @param handle    Handle returned by wdk_key_store_add.
 * @param out_len   If non-NULL, receives the key length.
 * @param out_curve If non-NULL, receives the curve identifier.
 * @return          Pointer to key bytes, or NULL if the handle is invalid.
 *                  The pointer is valid until the entry is released.
 */
const uint8_t *wdk_key_store_get(int32_t handle, size_t *out_len, int *out_curve);

/**
 * Release a key. Securely zeros the key material and marks the slot inactive.
 *
 * @param handle  Handle to release.
 */
void wdk_key_store_release(int32_t handle);

/**
 * Check whether a handle refers to an active key.
 *
 * @param handle  Handle to check.
 * @return        1 if valid and active, 0 otherwise.
 */
int wdk_key_store_is_valid(int32_t handle);

/**
 * Destroy the entire key store. Securely zeros ALL entries.
 */
void wdk_key_store_destroy(void);

/**
 * Count the number of active keys in the store.
 *
 * @return  Number of active entries.
 */
int wdk_key_store_count(void);

#ifdef __cplusplus
}
#endif

#endif /* WDK_KEY_STORE_H */
