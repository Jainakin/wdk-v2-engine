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
static PendingFetch pending_fetches[MAX_PENDING_FETCHES];
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

    /* Set up pending fetch slot */
    PendingFetch *pf = &pending_fetches[pending_count];
    memset(pf, 0, sizeof(PendingFetch));
    pf->resolve = JS_DupValue(ctx, resolving_funcs[0]);
    pf->reject = JS_DupValue(ctx, resolving_funcs[1]);
    pf->ctx = ctx;
    atomic_store(&pf->completed, 0);
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
        PendingFetch *pf = &pending_fetches[i];

        /* Check with acquire semantics */
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

        /* Clean up */
        JS_FreeValue(ctx, pf->resolve);
        JS_FreeValue(ctx, pf->reject);
        free(pf->headers_json);
        free(pf->body);
        free(pf->error);

        /* Compact: move last entry into this slot */
        pending_count--;
        if (i < pending_count) {
            pending_fetches[i] = pending_fetches[pending_count];
        }
        /* Don't increment i -- re-check same slot */
    }
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

    JS_SetPropertyStr(ctx, native_obj, "net", net);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
