/*
 * bridge_storage.h — native.storage.* platform interface
 *
 * The platform wrapper (Swift/Kotlin) must implement these functions.
 *
 * Two tiers:
 *   - Secure: hardware-backed (iOS Keychain, Android Keystore)
 *   - Regular: app-level (UserDefaults, SharedPreferences)
 */

#ifndef WDK_BRIDGE_STORAGE_H
#define WDK_BRIDGE_STORAGE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Secure storage function pointers (set by platform wrapper)
 *
 * All functions return 0 on success, -1 on failure.
 * secure_get allocates *out_value — caller must free.
 */
typedef int  (*WDKSecureSetFn)(const char *key, const uint8_t *value,
                                size_t value_len);
typedef int  (*WDKSecureGetFn)(const char *key, uint8_t **out_value,
                                size_t *out_len);
typedef int  (*WDKSecureDeleteFn)(const char *key);
typedef int  (*WDKSecureHasFn)(const char *key);

/*
 * Regular storage function pointers
 *
 * regular_get returns allocated string — caller must free. NULL if not found.
 */
typedef int   (*WDKRegularSetFn)(const char *key, const char *value);
typedef char *(*WDKRegularGetFn)(const char *key);
typedef int   (*WDKRegularDeleteFn)(const char *key);

#endif /* WDK_BRIDGE_STORAGE_H */
