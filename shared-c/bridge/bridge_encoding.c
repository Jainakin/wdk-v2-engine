/*
 * bridge_encoding.c — native.encoding.* bridge implementation
 *
 * Registers C functions into the QuickJS context for:
 *   native.encoding.hexEncode(data) → string
 *   native.encoding.hexDecode(hex) → Uint8Array
 *   native.encoding.base58Encode(data) → string
 *   native.encoding.base58Decode(str) → Uint8Array
 *   native.encoding.base58CheckEncode(data) → string
 *   native.encoding.base58CheckDecode(str) → Uint8Array
 *   native.encoding.bech32Encode(hrp, data) → string
 *   native.encoding.bech32Decode(str) → { hrp, data }
 *   native.encoding.bech32mEncode(hrp, data) → string
 *   native.encoding.bech32mDecode(str) → { hrp, data }
 *   native.encoding.base64Encode(data) → string
 *   native.encoding.base64Decode(str) → Uint8Array
 */

#include "../vendor/quickjs-ng/quickjs.h"
#include "../encoding/hex.h"
#include "../encoding/base58.h"
#include "../encoding/base58check.h"
#include "../encoding/bech32.h"
#include "../encoding/base64.h"

#include <string.h>
#include <stdlib.h>

/* ── Shared helpers (cached Uint8Array constructor) ─────────── */
#include "js_utils.h"

/* Aliases so existing code doesn't need renaming */
#define js_enc_get_uint8array js_get_uint8array
#define js_enc_new_uint8array js_new_uint8array

/* ── Hex ───────────────────────────────────────────────────── */

static JSValue js_enc_hex_encode(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_enc_get_uint8array(ctx, argv[0], &len);
    if (!data && len > 0) return JS_ThrowTypeError(ctx, "data must be Uint8Array");

    size_t out_size = len * 2 + 1;
    char *out = malloc(out_size);
    if (!out) return JS_ThrowInternalError(ctx, "Out of memory");

    wdk_hex_encode(data, len, out, out_size);
    JSValue result = JS_NewString(ctx, out);
    free(out);
    return result;
}

static JSValue js_enc_hex_decode(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "hex string required");
    const char *hex = JS_ToCString(ctx, argv[0]);
    if (!hex) return JS_EXCEPTION;

    size_t hex_len = strlen(hex);
    size_t out_size = hex_len / 2;
    uint8_t *out = malloc(out_size > 0 ? out_size : 1);
    if (!out) { JS_FreeCString(ctx, hex); return JS_ThrowInternalError(ctx, "Out of memory"); }

    size_t out_len;
    int ret = wdk_hex_decode(hex, out, &out_len, out_size);
    JS_FreeCString(ctx, hex);

    if (ret != 0) { free(out); return JS_ThrowTypeError(ctx, "Invalid hex string"); }

    JSValue result = js_enc_new_uint8array(ctx, out, out_len);
    free(out);
    return result;
}

/* ── Base58 ────────────────────────────────────────────────── */

static JSValue js_enc_base58_encode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_enc_get_uint8array(ctx, argv[0], &len);
    if (!data && len > 0) return JS_ThrowTypeError(ctx, "data must be Uint8Array");

    char out[256];
    size_t out_len;
    if (wdk_base58_encode(data, len, out, &out_len) != 0) {
        return JS_ThrowInternalError(ctx, "Base58 encode failed");
    }
    return JS_NewString(ctx, out);
}

static JSValue js_enc_base58_decode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "string required");
    const char *str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;

    uint8_t out[256];
    size_t out_len;
    int ret = wdk_base58_decode(str, out, &out_len, sizeof(out));
    JS_FreeCString(ctx, str);

    if (ret != 0) return JS_ThrowTypeError(ctx, "Invalid Base58 string");
    return js_enc_new_uint8array(ctx, out, out_len);
}

/* ── Base58Check ───────────────────────────────────────────── */

static JSValue js_enc_base58check_encode(JSContext *ctx, JSValueConst this_val,
                                           int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_enc_get_uint8array(ctx, argv[0], &len);
    if (!data && len > 0) return JS_ThrowTypeError(ctx, "data must be Uint8Array");

    char out[256];
    size_t out_len;
    if (wdk_base58check_encode(data, len, out, &out_len) != 0) {
        return JS_ThrowInternalError(ctx, "Base58Check encode failed");
    }
    return JS_NewString(ctx, out);
}

static JSValue js_enc_base58check_decode(JSContext *ctx, JSValueConst this_val,
                                           int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "string required");
    const char *str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;

    uint8_t out[256];
    size_t out_len;
    int ret = wdk_base58check_decode(str, out, &out_len, sizeof(out));
    JS_FreeCString(ctx, str);

    if (ret != 0) return JS_ThrowTypeError(ctx, "Invalid Base58Check string");
    return js_enc_new_uint8array(ctx, out, out_len);
}

/* ── Bech32 / Bech32m ──────────────────────────────────────── */

static JSValue js_enc_bech32_encode_impl(JSContext *ctx, int argc,
                                           JSValueConst *argv, int bech32m) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "hrp and data required");
    const char *hrp = JS_ToCString(ctx, argv[0]);
    if (!hrp) return JS_EXCEPTION;

    size_t data_len;
    uint8_t *data = js_enc_get_uint8array(ctx, argv[1], &data_len);
    if (!data && data_len > 0) {
        JS_FreeCString(ctx, hrp);
        return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    }

    char out[256];
    int ret = wdk_bech32_encode(out, sizeof(out), hrp, data, data_len, bech32m);
    JS_FreeCString(ctx, hrp);

    if (ret != 0) return JS_ThrowInternalError(ctx, "Bech32 encode failed");
    return JS_NewString(ctx, out);
}

static JSValue js_enc_bech32_encode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    return js_enc_bech32_encode_impl(ctx, argc, argv, 0);
}

static JSValue js_enc_bech32m_encode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    return js_enc_bech32_encode_impl(ctx, argc, argv, 1);
}

static JSValue js_enc_bech32_decode_impl(JSContext *ctx, int argc,
                                           JSValueConst *argv,
                                           int expected_bech32m) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "string required");
    const char *str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;

    char hrp[64];
    uint8_t data[256];
    size_t data_len;
    int is_bech32m;

    int ret = wdk_bech32_decode(hrp, sizeof(hrp), data, &data_len,
                                 sizeof(data), str, &is_bech32m);
    JS_FreeCString(ctx, str);

    if (ret != 0) return JS_ThrowTypeError(ctx, "Invalid bech32 string");

    /* Return { hrp, data } */
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "hrp", JS_NewString(ctx, hrp));
    JS_SetPropertyStr(ctx, result, "data",
                       js_enc_new_uint8array(ctx, data, data_len));
    return result;
}

static JSValue js_enc_bech32_decode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    return js_enc_bech32_decode_impl(ctx, argc, argv, 0);
}

static JSValue js_enc_bech32m_decode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    return js_enc_bech32_decode_impl(ctx, argc, argv, 1);
}

/* ── Base64 ────────────────────────────────────────────────── */

static JSValue js_enc_base64_encode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_enc_get_uint8array(ctx, argv[0], &len);
    if (!data && len > 0) return JS_ThrowTypeError(ctx, "data must be Uint8Array");

    size_t out_size = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(out_size);
    if (!out) return JS_ThrowInternalError(ctx, "Out of memory");

    size_t out_len;
    wdk_base64_encode(data, len, out, &out_len);
    out[out_len] = '\0';
    JSValue result = JS_NewString(ctx, out);
    free(out);
    return result;
}

static JSValue js_enc_base64_decode(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "string required");
    const char *str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;

    size_t str_len = strlen(str);
    size_t out_size = (str_len / 4) * 3 + 3;
    uint8_t *out = malloc(out_size);
    if (!out) { JS_FreeCString(ctx, str); return JS_ThrowInternalError(ctx, "Out of memory"); }

    size_t out_len;
    int ret = wdk_base64_decode(str, out, &out_len, out_size);
    JS_FreeCString(ctx, str);

    if (ret != 0) { free(out); return JS_ThrowTypeError(ctx, "Invalid Base64 string"); }

    JSValue result = js_enc_new_uint8array(ctx, out, out_len);
    free(out);
    return result;
}

/* ── Registration ──────────────────────────────────────────── */

void wdk_register_encoding_bridge(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);

    JSValue native_obj = JS_GetPropertyStr(ctx, global, "native");
    if (JS_IsUndefined(native_obj)) {
        native_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "native", JS_DupValue(ctx, native_obj));
    }

    JSValue encoding = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, encoding, "hexEncode",
        JS_NewCFunction(ctx, js_enc_hex_encode, "hexEncode", 1));
    JS_SetPropertyStr(ctx, encoding, "hexDecode",
        JS_NewCFunction(ctx, js_enc_hex_decode, "hexDecode", 1));
    JS_SetPropertyStr(ctx, encoding, "base58Encode",
        JS_NewCFunction(ctx, js_enc_base58_encode, "base58Encode", 1));
    JS_SetPropertyStr(ctx, encoding, "base58Decode",
        JS_NewCFunction(ctx, js_enc_base58_decode, "base58Decode", 1));
    JS_SetPropertyStr(ctx, encoding, "base58CheckEncode",
        JS_NewCFunction(ctx, js_enc_base58check_encode, "base58CheckEncode", 1));
    JS_SetPropertyStr(ctx, encoding, "base58CheckDecode",
        JS_NewCFunction(ctx, js_enc_base58check_decode, "base58CheckDecode", 1));
    JS_SetPropertyStr(ctx, encoding, "bech32Encode",
        JS_NewCFunction(ctx, js_enc_bech32_encode, "bech32Encode", 2));
    JS_SetPropertyStr(ctx, encoding, "bech32Decode",
        JS_NewCFunction(ctx, js_enc_bech32_decode, "bech32Decode", 1));
    JS_SetPropertyStr(ctx, encoding, "bech32mEncode",
        JS_NewCFunction(ctx, js_enc_bech32m_encode, "bech32mEncode", 2));
    JS_SetPropertyStr(ctx, encoding, "bech32mDecode",
        JS_NewCFunction(ctx, js_enc_bech32m_decode, "bech32mDecode", 1));
    JS_SetPropertyStr(ctx, encoding, "base64Encode",
        JS_NewCFunction(ctx, js_enc_base64_encode, "base64Encode", 1));
    JS_SetPropertyStr(ctx, encoding, "base64Decode",
        JS_NewCFunction(ctx, js_enc_base64_decode, "base64Decode", 1));

    JS_SetPropertyStr(ctx, native_obj, "encoding", encoding);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
