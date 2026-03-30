/*
 * bridge_net.c -- native.net.* bridge implementation
 *
 * Registers native.net.fetch() into the QuickJS context.
 * fetch() returns a Promise. The platform provider's fetch function is called
 * with a callback, which fires on a platform thread. Results are queued and
 * resolved on the JS thread during wdk_engine_pump().
 */

#include "../vendor/quickjs-ng/quickjs.h"
#include "bridge.h"

#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

/* ── Static provider ─────────────────────────────────────────── */

static const WDKNetProvider *s_net_provider = NULL;

/* ── Pending fetch queue (thread-safe via atomics) ───────────── */
/*
 * Design: each PendingFetch is heap-allocated so the pointer given to the
 * platform callback is stable for its lifetime.  The pointer array
 * (pending_fetch_ptrs) lives only on the JS thread, so pending_count and
 * the pointer slots need no synchronisation.  The only cross-thread state
 * is the per-entry `completed` atomic flag — written by the platform thread
 * with release semantics, read by the JS thread with acquire semantics,
 * which guarantees that all non-atomic fields written before the flag are
 * visible after the flag is observed as set.
 */

typedef struct {
    JSValue resolve;
    JSValue reject;
    JSContext *ctx;
    int status;
    char *headers_json;
    char *body;
    size_t body_len;
    char *error;
    atomic_int completed;  /* written from platform thread, read from JS thread */
} PendingFetch;

#define MAX_PENDING_FETCHES 64
/* Array of POINTERS — each PendingFetch is heap-allocated so the pointer
 * passed to the platform callback remains valid even if this array is
 * compacted.  Accessed only from the JS engine thread. */
static PendingFetch *pending_fetch_ptrs[MAX_PENDING_FETCHES];
static int pending_count = 0;

/* ── Helpers ─────────────────────────────────────────────────── */

static uint8_t *js_net_get_uint8array(JSContext *ctx, JSValueConst val,
                                       size_t *out_len) {
    size_t len = 0;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &len, val);
    if (buf) { *out_len = len; return buf; }

    JSValue buffer = JS_GetPropertyStr(ctx, val, "buffer");
    if (JS_IsException(buffer)) { *out_len = 0; return NULL; }

    buf = JS_GetArrayBuffer(ctx, &len, buffer);
    if (buf) {
        JSValue offset_val = JS_GetPropertyStr(ctx, val, "byteOffset");
        JSValue length_val = JS_GetPropertyStr(ctx, val, "byteLength");
        int32_t offset = 0, length = (int32_t)len;
        JS_ToInt32(ctx, &offset, offset_val);
        JS_ToInt32(ctx, &length, length_val);
        JS_FreeValue(ctx, offset_val);
        JS_FreeValue(ctx, length_val);

        if (offset < 0 || length < 0 ||
            (size_t)offset + (size_t)length > len) {
            JS_FreeValue(ctx, buffer);
            *out_len = 0;
            return NULL;
        }
        buf = buf + offset;
        *out_len = (size_t)length;
    } else {
        *out_len = 0;
    }

    JS_FreeValue(ctx, buffer);
    return buf;
}

static JSValue js_net_new_uint8array(JSContext *ctx, const uint8_t *data,
                                      size_t len) {
    JSValue ab = JS_NewArrayBufferCopy(ctx, data, len);
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue uint8_ctor = JS_GetPropertyStr(ctx, global, "Uint8Array");
    JSValue result = JS_CallConstructor(ctx, uint8_ctor, 1, &ab);
    JS_FreeValue(ctx, uint8_ctor);
    JS_FreeValue(ctx, global);
    JS_FreeValue(ctx, ab);
    return result;
}

/* ── Platform callback (called from platform thread) ─────────── */

static void fetch_completion_callback(void *context, int status_code,
                                       const char *headers_json,
                                       const uint8_t *body, size_t body_len,
                                       const char *error) {
    PendingFetch *pf = (PendingFetch *)context;

    pf->status = status_code;
    pf->headers_json = headers_json ? strdup(headers_json) : NULL;

    if (body && body_len > 0) {
        pf->body = (char *)malloc(body_len);
        if (pf->body) {
            memcpy(pf->body, body, body_len);
            pf->body_len = body_len;
        } else {
            pf->body_len = 0;
        }
    } else {
        pf->body = NULL;
        pf->body_len = 0;
    }

    pf->error = error ? strdup(error) : NULL;

    /* Signal completion -- must be last write (release semantics) */
    atomic_store_explicit(&pf->completed, 1, memory_order_release);
}

/* ── native.net.fetch(url, options?) ─────────────────────────── */

static JSValue js_net_fetch(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_net_provider || !s_net_provider->fetch) {
        return JS_ThrowInternalError(ctx, "Net provider not registered");
    }

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "url required");
    }

    if (pending_count >= MAX_PENDING_FETCHES) {
        return JS_ThrowInternalError(ctx, "Too many pending fetch requests");
    }

    /* Extract URL */
    const char *url = JS_ToCString(ctx, argv[0]);
    if (!url) return JS_EXCEPTION;

    /* Extract options */
    const char *method = "GET";
    const char *method_str = NULL;
    const char *headers_json = NULL;
    const uint8_t *body_data = NULL;
    size_t body_len = 0;
    int32_t timeout_ms = 30000;

    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue opts = argv[1];

        /* method */
        JSValue method_val = JS_GetPropertyStr(ctx, opts, "method");
        if (!JS_IsUndefined(method_val) && !JS_IsNull(method_val)) {
            method_str = JS_ToCString(ctx, method_val);
            if (method_str) method = method_str;
        }
        JS_FreeValue(ctx, method_val);

        /* headers (expect JSON string) */
        JSValue headers_val = JS_GetPropertyStr(ctx, opts, "headers");
        if (!JS_IsUndefined(headers_val) && !JS_IsNull(headers_val)) {
            /* If headers is a string, use directly. If object, stringify it. */
            if (JS_IsString(headers_val)) {
                headers_json = JS_ToCString(ctx, headers_val);
            } else if (JS_IsObject(headers_val)) {
                JSValue global = JS_GetGlobalObject(ctx);
                JSValue json_obj = JS_GetPropertyStr(ctx, global, "JSON");
                JSValue stringify = JS_GetPropertyStr(ctx, json_obj, "stringify");
                JSValue json_str = JS_Call(ctx, stringify, json_obj, 1, &headers_val);
                if (!JS_IsException(json_str)) {
                    headers_json = JS_ToCString(ctx, json_str);
                }
                JS_FreeValue(ctx, json_str);
                JS_FreeValue(ctx, stringify);
                JS_FreeValue(ctx, json_obj);
                JS_FreeValue(ctx, global);
            }
        }
        JS_FreeValue(ctx, headers_val);

        /* body (Uint8Array or string) */
        JSValue body_val = JS_GetPropertyStr(ctx, opts, "body");
        if (!JS_IsUndefined(body_val) && !JS_IsNull(body_val)) {
            if (JS_IsString(body_val)) {
                const char *body_str = JS_ToCString(ctx, body_val);
                if (body_str) {
                    body_data = (const uint8_t *)body_str;
                    body_len = strlen(body_str);
                    /* Note: body_str pointer valid until JS_FreeCString */
                }
            } else {
                size_t blen = 0;
                uint8_t *bptr = js_net_get_uint8array(ctx, body_val, &blen);
                if (bptr) {
                    body_data = bptr;
                    body_len = blen;
                }
            }
        }
        JS_FreeValue(ctx, body_val);

        /* timeout */
        JSValue timeout_val = JS_GetPropertyStr(ctx, opts, "timeout");
        if (!JS_IsUndefined(timeout_val) && !JS_IsNull(timeout_val)) {
            JS_ToInt32(ctx, &timeout_ms, timeout_val);
        }
        JS_FreeValue(ctx, timeout_val);
    }

    /* Create Promise */
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise)) {
        JS_FreeCString(ctx, url);
        if (method_str) JS_FreeCString(ctx, method_str);
        if (headers_json) JS_FreeCString(ctx, headers_json);
        return JS_EXCEPTION;
    }

    /* Allocate a stable heap slot — the pointer is given directly to the
     * platform callback, so it must not be invalidated by queue compaction. */
    PendingFetch *pf = (PendingFetch *)calloc(1, sizeof(PendingFetch));
    if (!pf) {
        JS_FreeValue(ctx, promise);
        JS_FreeValue(ctx, resolving_funcs[0]);
        JS_FreeValue(ctx, resolving_funcs[1]);
        JS_FreeCString(ctx, url);
        if (method_str) JS_FreeCString(ctx, method_str);
        if (headers_json) JS_FreeCString(ctx, headers_json);
        return JS_ThrowInternalError(ctx, "Out of memory for fetch slot");
    }
    pf->resolve = JS_DupValue(ctx, resolving_funcs[0]);
    pf->reject  = JS_DupValue(ctx, resolving_funcs[1]);
    pf->ctx     = ctx;
    atomic_store(&pf->completed, 0);
    pending_fetch_ptrs[pending_count] = pf;
    pending_count++;

    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);

    /* Invoke platform fetch */
    s_net_provider->fetch(url, method, headers_json,
                          body_data, body_len, timeout_ms,
                          pf, fetch_completion_callback);

    /* Clean up C strings */
    JS_FreeCString(ctx, url);
    if (method_str) JS_FreeCString(ctx, method_str);
    if (headers_json) JS_FreeCString(ctx, headers_json);

    return promise;
}

/* ── Pump: resolve completed fetches (called from JS thread) ── */

void wdk_net_pump(JSContext *ctx) {
    int i = 0;
    while (i < pending_count) {
        PendingFetch *pf = pending_fetch_ptrs[i];

        /* Check with acquire semantics — also guarantees all non-atomic
         * fields written before the release store are now visible. */
        if (!atomic_load_explicit(&pf->completed, memory_order_acquire)) {
            i++;
            continue;
        }

        /* Resolve or reject on the JS thread */
        if (pf->error) {
            JSValue err_msg = JS_NewString(ctx, pf->error);
            JS_Call(ctx, pf->reject, JS_UNDEFINED, 1, &err_msg);
            JS_FreeValue(ctx, err_msg);
        } else {
            /* Build response object: { status, headers, body } */
            JSValue response = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, response, "status",
                              JS_NewInt32(ctx, pf->status));

            if (pf->headers_json) {
                JS_SetPropertyStr(ctx, response, "headers",
                                  JS_NewString(ctx, pf->headers_json));
            } else {
                JS_SetPropertyStr(ctx, response, "headers", JS_NULL);
            }

            if (pf->body && pf->body_len > 0) {
                JS_SetPropertyStr(ctx, response, "body",
                                  js_net_new_uint8array(ctx,
                                      (const uint8_t *)pf->body, pf->body_len));
            } else {
                JS_SetPropertyStr(ctx, response, "body", JS_NULL);
            }

            JS_Call(ctx, pf->resolve, JS_UNDEFINED, 1, &response);
            JS_FreeValue(ctx, response);
        }

        /* Free heap-allocated entry and its dynamic fields */
        JS_FreeValue(ctx, pf->resolve);
        JS_FreeValue(ctx, pf->reject);
        free(pf->headers_json);
        free(pf->body);
        free(pf->error);
        free(pf);  /* release the stable heap allocation */

        /* Compact: move last POINTER into this slot — safe because the
         * platform callback holds a direct pointer to the PendingFetch
         * heap object, not an index or a pointer-to-slot. */
        pending_count--;
        if (i < pending_count) {
            pending_fetch_ptrs[i] = pending_fetch_ptrs[pending_count];
        }
        /* Don't increment i — re-check this slot (now holds a different entry) */
    }
}

/* ── Query: are there any in-flight fetches? ─────────────────── */

int wdk_net_has_pending(void) {
    return pending_count > 0;
}

/* ═══════════════════════════════════════════════════════════════
 * WebSocket Bridge
 *
 * Unlike HTTP (one-shot request→response), WebSocket connections
 * are long-lived and receive multiple messages. We use:
 *   - PendingWSConnection: per-connection state (heap-allocated)
 *   - PendingWSMessage: per-message ring buffer (SPSC lock-free)
 *
 * Platform thread enqueues messages; JS thread dequeues during pump.
 * ═══════════════════════════════════════════════════════════════ */

/* ── WebSocket connection state ──────────────────────────────── */

typedef struct {
    int32_t handle_id;
    void *platform_handle;        /* opaque, from ws_connect */
    JSValue on_message_cb;        /* JS callback, DupValue'd */
    JSValue on_close_cb;          /* JS callback, DupValue'd */
    JSContext *ctx;
    atomic_int state;             /* 0=connecting, 1=open, 2=closed */
} PendingWSConnection;

#define MAX_WS_CONNECTIONS 16
static PendingWSConnection *ws_connections[MAX_WS_CONNECTIONS];
static int ws_count = 0;
static int32_t ws_next_handle = 1;

/* ── WebSocket message ring buffer ───────────────────────────── */

typedef struct {
    int32_t connection_handle;
    char *message;                /* heap-allocated, or NULL on error */
    char *error;                  /* heap-allocated, or NULL on success */
} PendingWSMessage;

#define MAX_WS_MESSAGES 256
static PendingWSMessage ws_messages[MAX_WS_MESSAGES];
static atomic_uint ws_write_head = 0;
static atomic_uint ws_read_head = 0;

/* ── Find connection by handle ───────────────────────────────── */

static PendingWSConnection *ws_find(int32_t handle) {
    for (int i = 0; i < ws_count; i++) {
        if (ws_connections[i] && ws_connections[i]->handle_id == handle)
            return ws_connections[i];
    }
    return NULL;
}

/* ── Platform callback: enqueue message to ring buffer ────────── */

static void ws_message_callback(void *context, const char *message,
                                 const char *error) {
    PendingWSConnection *conn = (PendingWSConnection *)context;

    unsigned int wh = atomic_load_explicit(&ws_write_head, memory_order_relaxed);
    unsigned int rh = atomic_load_explicit(&ws_read_head, memory_order_acquire);
    unsigned int next = (wh + 1) % MAX_WS_MESSAGES;

    if (next == rh) {
        /* Ring buffer full — drop message (should be rare) */
        return;
    }

    ws_messages[wh].connection_handle = conn->handle_id;
    ws_messages[wh].message = message ? strdup(message) : NULL;
    ws_messages[wh].error = error ? strdup(error) : NULL;

    atomic_store_explicit(&ws_write_head, next, memory_order_release);
}

/* ── native.net.wsConnect(url) → handle (int) ────────────────── */

static JSValue js_net_ws_connect(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_net_provider || !s_net_provider->ws_connect) {
        return JS_ThrowInternalError(ctx, "WebSocket not supported on this platform");
    }
    if (argc < 1) return JS_ThrowTypeError(ctx, "url required");
    if (ws_count >= MAX_WS_CONNECTIONS) {
        return JS_ThrowInternalError(ctx, "Too many WebSocket connections");
    }

    const char *url = JS_ToCString(ctx, argv[0]);
    if (!url) return JS_EXCEPTION;

    PendingWSConnection *conn = (PendingWSConnection *)calloc(1, sizeof(PendingWSConnection));
    if (!conn) {
        JS_FreeCString(ctx, url);
        return JS_ThrowInternalError(ctx, "Out of memory for WebSocket");
    }

    conn->handle_id = ws_next_handle++;
    conn->ctx = ctx;
    conn->on_message_cb = JS_UNDEFINED;
    conn->on_close_cb = JS_UNDEFINED;
    atomic_store(&conn->state, 0); /* connecting */

    /* Call platform to create the WebSocket */
    conn->platform_handle = s_net_provider->ws_connect(
        url, conn, ws_message_callback);

    JS_FreeCString(ctx, url);

    if (!conn->platform_handle) {
        free(conn);
        return JS_ThrowInternalError(ctx, "WebSocket connect failed");
    }

    atomic_store(&conn->state, 1); /* open */
    ws_connections[ws_count++] = conn;

    return JS_NewInt32(ctx, conn->handle_id);
}

/* ── native.net.wsSend(handle, data) ─────────────────────────── */

static JSValue js_net_ws_send(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_net_provider || !s_net_provider->ws_send) {
        return JS_ThrowInternalError(ctx, "WebSocket not supported");
    }
    if (argc < 2) return JS_ThrowTypeError(ctx, "handle and data required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    PendingWSConnection *conn = ws_find(handle);
    if (!conn || atomic_load(&conn->state) != 1) {
        return JS_ThrowInternalError(ctx, "WebSocket not open");
    }

    const char *data = JS_ToCString(ctx, argv[1]);
    if (!data) return JS_EXCEPTION;

    s_net_provider->ws_send(conn->platform_handle, data);
    JS_FreeCString(ctx, data);

    return JS_UNDEFINED;
}

/* ── native.net.wsClose(handle) ──────────────────────────────── */

static JSValue js_net_ws_close(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    (void)this_val;
    if (argc < 1) return JS_ThrowTypeError(ctx, "handle required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    PendingWSConnection *conn = ws_find(handle);
    if (!conn) return JS_UNDEFINED; /* already closed */

    atomic_store(&conn->state, 2); /* closed */

    if (s_net_provider && s_net_provider->ws_close && conn->platform_handle) {
        s_net_provider->ws_close(conn->platform_handle);
    }

    return JS_UNDEFINED;
}

/* ── native.net.wsOnMessage(handle, callback) ────────────────── */

static JSValue js_net_ws_on_message(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    (void)this_val;
    if (argc < 2) return JS_ThrowTypeError(ctx, "handle and callback required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    PendingWSConnection *conn = ws_find(handle);
    if (!conn) return JS_ThrowInternalError(ctx, "WebSocket not found");

    if (!JS_IsUndefined(conn->on_message_cb)) {
        JS_FreeValue(ctx, conn->on_message_cb);
    }
    conn->on_message_cb = JS_DupValue(ctx, argv[1]);

    return JS_UNDEFINED;
}

/* ── native.net.wsOnClose(handle, callback) ──────────────────── */

static JSValue js_net_ws_on_close(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    (void)this_val;
    if (argc < 2) return JS_ThrowTypeError(ctx, "handle and callback required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    PendingWSConnection *conn = ws_find(handle);
    if (!conn) return JS_ThrowInternalError(ctx, "WebSocket not found");

    if (!JS_IsUndefined(conn->on_close_cb)) {
        JS_FreeValue(ctx, conn->on_close_cb);
    }
    conn->on_close_cb = JS_DupValue(ctx, argv[1]);

    return JS_UNDEFINED;
}

/* ── WebSocket pump: deliver queued messages on JS thread ─────── */

void wdk_ws_pump(JSContext *ctx) {
    unsigned int rh = atomic_load_explicit(&ws_read_head, memory_order_relaxed);
    unsigned int wh = atomic_load_explicit(&ws_write_head, memory_order_acquire);

    while (rh != wh) {
        PendingWSMessage *msg = &ws_messages[rh];
        PendingWSConnection *conn = ws_find(msg->connection_handle);

        if (conn && !JS_IsUndefined(conn->on_message_cb)) {
            if (msg->error) {
                /* Error — deliver to onClose if available, else onMessage */
                if (!JS_IsUndefined(conn->on_close_cb)) {
                    JSValue err_str = JS_NewString(ctx, msg->error);
                    JS_Call(ctx, conn->on_close_cb, JS_UNDEFINED, 1, &err_str);
                    JS_FreeValue(ctx, err_str);
                } else {
                    JSValue args[2];
                    args[0] = JS_NULL;
                    args[1] = JS_NewString(ctx, msg->error);
                    /* onMessage(null, error) */
                    /* Actually we call with (data) where data is the error string
                     * since our TS layer expects onMessage(data: string) */
                }
                /* Mark connection as closed */
                atomic_store(&conn->state, 2);
            } else if (msg->message) {
                /* Normal message — deliver to onMessage callback */
                JSValue data_str = JS_NewString(ctx, msg->message);
                JS_Call(ctx, conn->on_message_cb, JS_UNDEFINED, 1, &data_str);
                JS_FreeValue(ctx, data_str);
            }
        }

        /* Free message data */
        free(msg->message);
        free(msg->error);
        msg->message = NULL;
        msg->error = NULL;

        rh = (rh + 1) % MAX_WS_MESSAGES;
        atomic_store_explicit(&ws_read_head, rh, memory_order_release);
    }

    /* Clean up closed connections */
    int i = 0;
    while (i < ws_count) {
        PendingWSConnection *conn = ws_connections[i];
        if (atomic_load(&conn->state) == 2) {
            /* Fire onClose callback if not already fired */
            if (!JS_IsUndefined(conn->on_close_cb)) {
                JS_Call(ctx, conn->on_close_cb, JS_UNDEFINED, 0, NULL);
            }
            /* Free JS callbacks */
            if (!JS_IsUndefined(conn->on_message_cb))
                JS_FreeValue(ctx, conn->on_message_cb);
            if (!JS_IsUndefined(conn->on_close_cb))
                JS_FreeValue(ctx, conn->on_close_cb);
            free(conn);

            /* Compact */
            ws_count--;
            if (i < ws_count) {
                ws_connections[i] = ws_connections[ws_count];
            }
        } else {
            i++;
        }
    }
}

/* ── Query: are there any active WebSocket connections? ────────── */

int wdk_ws_has_pending(void) {
    return ws_count > 0;
}

/* ── Registration ────────────────────────────────────────────── */

void wdk_register_net_bridge(JSContext *ctx, const WDKNetProvider *provider) {
    s_net_provider = provider;

    JSValue global = JS_GetGlobalObject(ctx);

    /* Create or get native object */
    JSValue native_obj = JS_GetPropertyStr(ctx, global, "native");
    if (JS_IsUndefined(native_obj)) {
        native_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "native", JS_DupValue(ctx, native_obj));
    }

    /* Create native.net object */
    JSValue net = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, net, "fetch",
        JS_NewCFunction(ctx, js_net_fetch, "fetch", 2));

    /* WebSocket functions (only if platform supports them) */
    if (provider->ws_connect) {
        JS_SetPropertyStr(ctx, net, "wsConnect",
            JS_NewCFunction(ctx, js_net_ws_connect, "wsConnect", 1));
        JS_SetPropertyStr(ctx, net, "wsSend",
            JS_NewCFunction(ctx, js_net_ws_send, "wsSend", 2));
        JS_SetPropertyStr(ctx, net, "wsClose",
            JS_NewCFunction(ctx, js_net_ws_close, "wsClose", 1));
        JS_SetPropertyStr(ctx, net, "wsOnMessage",
            JS_NewCFunction(ctx, js_net_ws_on_message, "wsOnMessage", 2));
        JS_SetPropertyStr(ctx, net, "wsOnClose",
            JS_NewCFunction(ctx, js_net_ws_on_close, "wsOnClose", 2));
    }

    JS_SetPropertyStr(ctx, native_obj, "net", net);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
