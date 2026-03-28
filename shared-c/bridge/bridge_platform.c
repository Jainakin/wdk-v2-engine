/*
 * bridge_platform.c -- native.platform.* bridge implementation
 *
 * Registers:
 *   native.platform.os         (string property)
 *   native.platform.version    (string property)
 *   native.platform.getRandomBytes(length)  -> Uint8Array
 *   native.platform.log(level, message)     -> undefined
 *
 * Delegates to function pointers provided by the platform wrapper.
 */

#include "../vendor/quickjs-ng/quickjs.h"
#include "bridge.h"

#include <string.h>
#include <stdlib.h>

/* ── Static provider ─────────────────────────────────────────── */

static const WDKPlatformProvider *s_platform_provider = NULL;

/* ── Helpers ─────────────────────────────────────────────────── */

static JSValue js_platform_new_uint8array(JSContext *ctx, const uint8_t *data,
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

/* ── native.platform.getRandomBytes(length) ──────────────────── */

static JSValue js_platform_get_random_bytes(JSContext *ctx,
                                             JSValueConst this_val,
                                             int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_platform_provider || !s_platform_provider->get_random_bytes)
        return JS_ThrowInternalError(ctx, "Platform provider not registered");

    if (argc < 1) return JS_ThrowTypeError(ctx, "length required");

    int32_t length = 0;
    JS_ToInt32(ctx, &length, argv[0]);

    if (length <= 0 || length > 65536)
        return JS_ThrowRangeError(ctx, "length must be 1-65536");

    uint8_t *buf = (uint8_t *)malloc((size_t)length);
    if (!buf) return JS_ThrowInternalError(ctx, "Out of memory");

    int ret = s_platform_provider->get_random_bytes(buf, (size_t)length);
    if (ret != 0) {
        free(buf);
        return JS_ThrowInternalError(ctx, "getRandomBytes failed");
    }

    JSValue result = js_platform_new_uint8array(ctx, buf, (size_t)length);
    free(buf);
    return result;
}

/* ── native.platform.log(level, message) ─────────────────────── */

static JSValue js_platform_log(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_platform_provider || !s_platform_provider->log_message)
        return JS_UNDEFINED;  /* silently ignore if no logger */

    if (argc < 2) return JS_ThrowTypeError(ctx, "level and message required");

    int32_t level = 0;
    JS_ToInt32(ctx, &level, argv[0]);

    const char *message = JS_ToCString(ctx, argv[1]);
    if (!message) return JS_EXCEPTION;

    s_platform_provider->log_message(level, message);
    JS_FreeCString(ctx, message);

    return JS_UNDEFINED;
}

/* ── Registration ────────────────────────────────────────────── */

void wdk_register_platform_bridge(JSContext *ctx, const WDKPlatformProvider *provider) {
    s_platform_provider = provider;

    JSValue global = JS_GetGlobalObject(ctx);

    /* Create or get native object */
    JSValue native_obj = JS_GetPropertyStr(ctx, global, "native");
    if (JS_IsUndefined(native_obj)) {
        native_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "native", JS_DupValue(ctx, native_obj));
    }

    /* Create native.platform object */
    JSValue platform = JS_NewObject(ctx);

    /* String properties */
    if (provider->os_name) {
        JS_SetPropertyStr(ctx, platform, "os",
                          JS_NewString(ctx, provider->os_name));
    } else {
        JS_SetPropertyStr(ctx, platform, "os",
                          JS_NewString(ctx, "unknown"));
    }

    if (provider->engine_version) {
        JS_SetPropertyStr(ctx, platform, "version",
                          JS_NewString(ctx, provider->engine_version));
    } else {
        JS_SetPropertyStr(ctx, platform, "version",
                          JS_NewString(ctx, "0.0.0"));
    }

    /* Functions */
    JS_SetPropertyStr(ctx, platform, "getRandomBytes",
        JS_NewCFunction(ctx, js_platform_get_random_bytes, "getRandomBytes", 1));
    JS_SetPropertyStr(ctx, platform, "log",
        JS_NewCFunction(ctx, js_platform_log, "log", 2));

    JS_SetPropertyStr(ctx, native_obj, "platform", platform);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
