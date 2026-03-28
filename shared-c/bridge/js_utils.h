/*
 * js_utils.h — Shared JS helper functions for bridge implementations
 *
 * Provides:
 * - js_new_uint8array: Create Uint8Array from C bytes (cached constructor)
 * - js_get_uint8array: Extract bytes from a JS Uint8Array argument
 */

#ifndef WDK_JS_UTILS_H
#define WDK_JS_UTILS_H

#include "../vendor/quickjs-ng/quickjs.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Cached Uint8Array constructor — looked up once, reused for all calls.
 * Must call js_utils_init(ctx) before using js_new_uint8array.
 */
static JSValue g_uint8array_ctor = {0};
static int g_uint8array_ctor_initialized = 0;

static inline void js_utils_init(JSContext *ctx) {
    if (g_uint8array_ctor_initialized) return;
    JSValue global = JS_GetGlobalObject(ctx);
    g_uint8array_ctor = JS_GetPropertyStr(ctx, global, "Uint8Array");
    JS_FreeValue(ctx, global);
    g_uint8array_ctor_initialized = 1;
}

/*
 * Create a JS Uint8Array from C bytes.
 * Uses cached constructor — no global lookup per call.
 */
static inline JSValue js_new_uint8array(JSContext *ctx, const uint8_t *data,
                                          size_t len) {
    if (!g_uint8array_ctor_initialized) js_utils_init(ctx);
    JSValue ab = JS_NewArrayBufferCopy(ctx, data, len);
    JSValue result = JS_CallConstructor(ctx, g_uint8array_ctor, 1, &ab);
    JS_FreeValue(ctx, ab);
    return result;
}

/*
 * Extract bytes from a JS Uint8Array (or ArrayBuffer) argument.
 * Returns pointer to internal buffer — caller must NOT free.
 * Sets *out_len to the byte length.
 */
static inline uint8_t *js_get_uint8array(JSContext *ctx, JSValueConst val,
                                           size_t *out_len) {
    /* Try direct ArrayBuffer first */
    size_t len = 0;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &len, val);
    if (buf) {
        *out_len = len;
        return buf;
    }

    /* Try typed array: get .buffer property */
    JSValue buffer = JS_GetPropertyStr(ctx, val, "buffer");
    if (JS_IsException(buffer)) {
        *out_len = 0;
        return NULL;
    }

    buf = JS_GetArrayBuffer(ctx, &len, buffer);

    if (buf) {
        JSValue offset_val = JS_GetPropertyStr(ctx, val, "byteOffset");
        JSValue length_val = JS_GetPropertyStr(ctx, val, "byteLength");
        int32_t offset = 0, length = (int32_t)len;
        JS_ToInt32(ctx, &offset, offset_val);
        JS_ToInt32(ctx, &length, length_val);
        JS_FreeValue(ctx, offset_val);
        JS_FreeValue(ctx, length_val);

        /* Bounds validation */
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

#endif /* WDK_JS_UTILS_H */
