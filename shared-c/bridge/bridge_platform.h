/*
 * bridge_platform.h — native.platform.* interface
 *
 * Platform-specific utilities: OS detection, random bytes, biometrics, logging.
 * The platform wrapper (Swift/Kotlin) must provide implementations.
 */

#ifndef WDK_BRIDGE_PLATFORM_H
#define WDK_BRIDGE_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

/* Log levels */
#define WDK_LOG_DEBUG 0
#define WDK_LOG_INFO  1
#define WDK_LOG_WARN  2
#define WDK_LOG_ERROR 3

/*
 * Cryptographically secure random bytes.
 * Must use platform CSPRNG (SecRandomCopyBytes on iOS, /dev/urandom on Android).
 *
 * @param buf   Output buffer
 * @param len   Number of random bytes to generate
 * @return      0 on success, -1 on failure
 */
typedef int (*WDKGetRandomBytesFn)(uint8_t *buf, size_t len);

/*
 * Log a message at a given level.
 * Routed to os_log (iOS) or android.util.Log (Android).
 */
typedef void (*WDKLogFn)(int level, const char *message);

/*
 * Biometric authentication.
 * Triggers Face ID / Touch ID / Fingerprint.
 *
 * @param reason   Reason string shown to user
 * @param context  Opaque pointer for callback
 * @param callback Called with 1 (success) or 0 (failure/cancel)
 */
typedef void (*WDKBiometricAuthFn)(const char *reason, void *context,
                                     void (*callback)(void *context, int success));

#endif /* WDK_BRIDGE_PLATFORM_H */
