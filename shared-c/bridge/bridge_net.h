/*
 * bridge_net.h — native.net.* platform interface
 *
 * The platform wrapper (Swift/Kotlin) must implement these functions.
 * The C bridge calls them when JS invokes native.net.fetch() etc.
 */

#ifndef WDK_BRIDGE_NET_H
#define WDK_BRIDGE_NET_H

#include <stdint.h>
#include <stddef.h>

/*
 * Callback invoked when a fetch request completes.
 *
 * @param context   Opaque pointer passed to wdk_platform_fetch
 * @param status    HTTP status code (0 on network error)
 * @param headers   JSON-encoded response headers, or NULL
 * @param body      Response body bytes, or NULL
 * @param body_len  Length of body
 * @param error     Error message string, or NULL on success
 */
typedef void (*WDKFetchCallback)(void *context, int status,
                                  const char *headers_json,
                                  const uint8_t *body, size_t body_len,
                                  const char *error);

/*
 * Start an async HTTP request.
 * Must return immediately. Invokes callback when done (from any thread).
 *
 * @param url           Request URL
 * @param method        HTTP method ("GET", "POST", etc.)
 * @param headers_json  JSON-encoded request headers, or NULL
 * @param body          Request body bytes, or NULL
 * @param body_len      Length of request body
 * @param timeout_ms    Request timeout in milliseconds
 * @param context       Opaque pointer passed back to callback
 * @param callback      Completion callback
 */
typedef void (*WDKPlatformFetchFn)(const char *url, const char *method,
                                    const char *headers_json,
                                    const uint8_t *body, size_t body_len,
                                    int timeout_ms, void *context,
                                    WDKFetchCallback callback);

/*
 * WebSocket callbacks
 */
typedef void (*WDKWSMessageCallback)(void *context, const char *message,
                                      const char *error);

typedef void *(*WDKPlatformWSConnectFn)(const char *url, void *context,
                                         WDKWSMessageCallback on_message);
typedef void (*WDKPlatformWSSendFn)(void *ws_handle, const char *data);
typedef void (*WDKPlatformWSCloseFn)(void *ws_handle);

#endif /* WDK_BRIDGE_NET_H */
