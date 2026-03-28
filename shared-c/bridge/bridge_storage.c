/*
 * bridge_storage.c -- native.storage.* bridge implementation
 *
 * Registers native.storage.secure.{set,get,delete,has} and
 * native.storage.regular.{set,get,delete} into the QuickJS context.
 *
 * All operations are synchronous -- Keychain/Keystore calls are fast enough.
 * Delegates to function pointers provided by the platform wrapper.
 */

#include "../vendor/quickjs-ng/quickjs.h"
#include "bridge.h"

#include <string.h>
#include <stdlib.h>

/* ── Static provider ─────────────────────────────────────────── */

static const WDKStorageProvider *s_storage_provider = NULL;

/* ── Helpers ─────────────────────────────────────────────────── */

static uint8_t *js_storage_get_uint8array(JSContext *ctx, JSValueConst val,
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

static JSValue js_storage_new_uint8array(JSContext *ctx, const uint8_t *data,
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

/* ── native.storage.secure.set(key, value) ───────────────────── */

static JSValue js_secure_set(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->secure_set)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 2) return JS_ThrowTypeError(ctx, "key and value required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    size_t val_len = 0;
    uint8_t *val_data = js_storage_get_uint8array(ctx, argv[1], &val_len);
    if (!val_data) {
        JS_FreeCString(ctx, key);
        return JS_ThrowTypeError(ctx, "value must be Uint8Array");
    }

    int ret = s_storage_provider->secure_set(key, val_data, val_len);
    JS_FreeCString(ctx, key);

    if (ret != 0)
        return JS_ThrowInternalError(ctx, "secure_set failed");

    return JS_UNDEFINED;
}

/* ── native.storage.secure.get(key) ──────────────────────────── */

static JSValue js_secure_get(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->secure_get)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 1) return JS_ThrowTypeError(ctx, "key required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    uint8_t *out_value = NULL;
    size_t out_len = 0;
    int ret = s_storage_provider->secure_get(key, &out_value, &out_len);
    JS_FreeCString(ctx, key);

    if (ret != 0 || !out_value)
        return JS_NULL;

    JSValue result = js_storage_new_uint8array(ctx, out_value, out_len);
    free(out_value);
    return result;
}

/* ── native.storage.secure.delete(key) ───────────────────────── */

static JSValue js_secure_delete(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->secure_delete)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 1) return JS_ThrowTypeError(ctx, "key required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    int ret = s_storage_provider->secure_delete(key);
    JS_FreeCString(ctx, key);

    if (ret != 0)
        return JS_ThrowInternalError(ctx, "secure_delete failed");

    return JS_UNDEFINED;
}

/* ── native.storage.secure.has(key) ──────────────────────────── */

static JSValue js_secure_has(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->secure_has)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 1) return JS_ThrowTypeError(ctx, "key required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    int ret = s_storage_provider->secure_has(key);
    JS_FreeCString(ctx, key);

    return JS_NewBool(ctx, ret > 0);
}

/* ── native.storage.regular.set(key, value) ──────────────────── */

static JSValue js_regular_set(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->regular_set)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 2) return JS_ThrowTypeError(ctx, "key and value required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    const char *value = JS_ToCString(ctx, argv[1]);
    if (!value) {
        JS_FreeCString(ctx, key);
        return JS_EXCEPTION;
    }

    int ret = s_storage_provider->regular_set(key, value);
    JS_FreeCString(ctx, key);
    JS_FreeCString(ctx, value);

    if (ret != 0)
        return JS_ThrowInternalError(ctx, "regular_set failed");

    return JS_UNDEFINED;
}

/* ── native.storage.regular.get(key) ─────────────────────────── */

static JSValue js_regular_get(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->regular_get)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 1) return JS_ThrowTypeError(ctx, "key required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    char *value = s_storage_provider->regular_get(key);
    JS_FreeCString(ctx, key);

    if (!value)
        return JS_NULL;

    JSValue result = JS_NewString(ctx, value);
    free(value);
    return result;
}

/* ── native.storage.regular.delete(key) ──────────────────────── */

static JSValue js_regular_delete(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    (void)this_val;
    if (!s_storage_provider || !s_storage_provider->regular_delete)
        return JS_ThrowInternalError(ctx, "Storage provider not registered");
    if (argc < 1) return JS_ThrowTypeError(ctx, "key required");

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) return JS_EXCEPTION;

    int ret = s_storage_provider->regular_delete(key);
    JS_FreeCString(ctx, key);

    if (ret != 0)
        return JS_ThrowInternalError(ctx, "regular_delete failed");

    return JS_UNDEFINED;
}

/* ── Registration ────────────────────────────────────────────── */

void wdk_register_storage_bridge(JSContext *ctx, const WDKStorageProvider *provider) {
    s_storage_provider = provider;

    JSValue global = JS_GetGlobalObject(ctx);

    /* Create or get native object */
    JSValue native_obj = JS_GetPropertyStr(ctx, global, "native");
    if (JS_IsUndefined(native_obj)) {
        native_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "native", JS_DupValue(ctx, native_obj));
    }

    /* Create native.storage object */
    JSValue storage = JS_NewObject(ctx);

    /* native.storage.secure */
    JSValue secure = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, secure, "set",
        JS_NewCFunction(ctx, js_secure_set, "set", 2));
    JS_SetPropertyStr(ctx, secure, "get",
        JS_NewCFunction(ctx, js_secure_get, "get", 1));
    JS_SetPropertyStr(ctx, secure, "delete",
        JS_NewCFunction(ctx, js_secure_delete, "delete", 1));
    JS_SetPropertyStr(ctx, secure, "has",
        JS_NewCFunction(ctx, js_secure_has, "has", 1));
    JS_SetPropertyStr(ctx, storage, "secure", secure);

    /* native.storage.regular */
    JSValue regular = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, regular, "set",
        JS_NewCFunction(ctx, js_regular_set, "set", 2));
    JS_SetPropertyStr(ctx, regular, "get",
        JS_NewCFunction(ctx, js_regular_get, "get", 1));
    JS_SetPropertyStr(ctx, regular, "delete",
        JS_NewCFunction(ctx, js_regular_delete, "delete", 1));
    JS_SetPropertyStr(ctx, storage, "regular", regular);

    JS_SetPropertyStr(ctx, native_obj, "storage", storage);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
