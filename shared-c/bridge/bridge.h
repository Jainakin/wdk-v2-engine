/*
 * bridge.h — Public C API for the WDK v2 Engine
 *
 * This is the top-level header that platform wrappers (Swift/Kotlin) include.
 * It re-exports engine.h and declares all bridge registration functions.
 */

#ifndef WDK_BRIDGE_H
#define WDK_BRIDGE_H

#include "engine.h"
#include "key_store.h"

/* Forward declare JSContext for bridge registration */
struct JSContext;
typedef struct JSContext JSContext;

/*
 * Register native.crypto.* functions into the JS context.
 * Must be called after wdk_engine_create(), before wdk_engine_eval().
 * No platform provider required — pure C implementation.
 */
void wdk_register_crypto_bridge(JSContext *ctx);

/*
 * Register native.encoding.* functions into the JS context.
 * Must be called after wdk_engine_create(), before wdk_engine_eval().
 * No platform provider required — pure C implementation.
 */
void wdk_register_encoding_bridge(JSContext *ctx);

/*
 * Platform-provided callbacks for native.net.*
 * The platform wrapper must set these before loading bytecode.
 */
typedef void (*WDKFetchCallback)(void *context, int status_code,
                                  const char *headers_json,
                                  const uint8_t *body, size_t body_len,
                                  const char *error);

typedef struct {
    void (*fetch)(const char *url, const char *method,
                  const char *headers_json,
                  const uint8_t *body, size_t body_len,
                  int timeout_ms, void *context,
                  WDKFetchCallback callback);
} WDKNetProvider;

/*
 * Platform-provided callbacks for native.storage.*
 */
typedef struct {
    int  (*secure_set)(const char *key, const uint8_t *value, size_t value_len);
    int  (*secure_get)(const char *key, uint8_t **out_value, size_t *out_len);
    int  (*secure_delete)(const char *key);
    int  (*secure_has)(const char *key);
    int  (*regular_set)(const char *key, const char *value);
    char *(*regular_get)(const char *key);
    int  (*regular_delete)(const char *key);
} WDKStorageProvider;

/*
 * Platform-provided callbacks for native.platform.*
 */
typedef struct {
    const char *os_name;          /* "ios", "android", "web", etc. */
    const char *engine_version;
    int  (*get_random_bytes)(uint8_t *buf, size_t len);
    void (*log_message)(int level, const char *message);
} WDKPlatformProvider;

/*
 * Register platform-specific bridges.
 * Called by the platform wrapper (Swift/Kotlin) after engine creation.
 */
void wdk_register_net_bridge(JSContext *ctx, const WDKNetProvider *provider);
void wdk_register_storage_bridge(JSContext *ctx, const WDKStorageProvider *provider);
void wdk_register_platform_bridge(JSContext *ctx, const WDKPlatformProvider *provider);

#endif /* WDK_BRIDGE_H */
