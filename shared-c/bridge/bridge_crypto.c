/*
 * bridge_crypto.c — native.crypto.* bridge implementation
 *
 * Registers C functions into the QuickJS context that JavaScript calls as:
 *   native.crypto.generateMnemonic(wordCount)
 *   native.crypto.mnemonicToSeed(mnemonic, passphrase)
 *   native.crypto.deriveKey(seedHandle, path)
 *   native.crypto.signSecp256k1(keyHandle, hash)
 *   native.crypto.signEd25519(keyHandle, message)
 *   native.crypto.getPublicKey(keyHandle, curve)
 *   native.crypto.sha256(data)
 *   native.crypto.sha512(data)
 *   native.crypto.keccak256(data)
 *   native.crypto.ripemd160(data)
 *   native.crypto.blake2b(data, outLen)
 *   native.crypto.hmacSha256(key, data)
 *   native.crypto.hmacSha512(key, data)
 *   native.crypto.pbkdf2(password, salt, iterations, keyLen, hash)
 *   native.crypto.releaseKey(handle)
 */

#include "../vendor/quickjs-ng/quickjs.h"
#include "key_store.h"
#include "../hashing/sha256.h"
#include "../hashing/sha512.h"
#include "../hashing/hmac.h"
#include "../hashing/keccak256.h"
#include "../hashing/ripemd160.h"
#include "../hashing/blake2b.h"
#include "../bip/bip39.h"
#include "../bip/bip32.h"

#include <secp256k1.h>
#include <string.h>
#include <stdlib.h>

#include "ed25519_derive.h"

/* Alias key store types to match our naming convention */
typedef int32_t WDKKeyHandle;
#define WDK_KEY_CURVE_SECP256K1  WDK_CURVE_SECP256K1
#define WDK_KEY_CURVE_ED25519    WDK_CURVE_ED25519

/* ── secp256k1 public key from private key (used by BIP-32) ── */

/*
 * Compute compressed (33-byte) public key from 32-byte private key.
 * This function is extern-declared by bip32.c.
 * Returns 0 on success, -1 on error.
 */
int wdk_secp256k1_pubkey_from_privkey(const uint8_t privkey[32],
                                        uint8_t pubkey[33]) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, privkey)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pk,
                                   SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return 0;
}

/* ── Shared helpers (cached Uint8Array constructor) ─────────── */
#include "js_utils.h"

/* ── native.crypto.generateMnemonic(wordCount) ─────────────── */

static JSValue js_crypto_generate_mnemonic(JSContext *ctx,
                                             JSValueConst this_val,
                                             int argc, JSValueConst *argv) {
    int32_t word_count = 12;
    if (argc > 0) JS_ToInt32(ctx, &word_count, argv[0]);

    if (word_count != 12 && word_count != 24) {
        return JS_ThrowRangeError(ctx, "wordCount must be 12 or 24");
    }

    char mnemonic[256];
    if (wdk_bip39_generate_mnemonic(word_count, mnemonic, sizeof(mnemonic)) != 0) {
        return JS_ThrowInternalError(ctx, "Failed to generate mnemonic");
    }

    return JS_NewString(ctx, mnemonic);
}

/* ── native.crypto.mnemonicToSeed(mnemonic, passphrase?) ───── */

static JSValue js_crypto_mnemonic_to_seed(JSContext *ctx,
                                            JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "mnemonic required");

    const char *mnemonic = JS_ToCString(ctx, argv[0]);
    if (!mnemonic) return JS_EXCEPTION;

    const char *passphrase = "";
    if (argc > 1 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        passphrase = JS_ToCString(ctx, argv[1]);
        if (!passphrase) {
            JS_FreeCString(ctx, mnemonic);
            return JS_EXCEPTION;
        }
    }

    uint8_t seed[64];
    int ret = wdk_bip39_mnemonic_to_seed(mnemonic, passphrase, seed);

    JS_FreeCString(ctx, mnemonic);
    if (passphrase[0] != '\0') JS_FreeCString(ctx, passphrase);

    if (ret != 0) {
        return JS_ThrowInternalError(ctx, "Failed to derive seed");
    }

    /* Store seed in key store, return handle */
    WDKKeyHandle handle = wdk_key_store_add(seed, 64, WDK_KEY_CURVE_SECP256K1);

    /* Secure-wipe local copy */
    volatile uint8_t *vs = (volatile uint8_t *)seed;
    for (int i = 0; i < 64; i++) vs[i] = 0;

    if (handle < 0) {
        return JS_ThrowInternalError(ctx, "Key store full");
    }

    return JS_NewInt32(ctx, handle);
}

/* ── native.crypto.deriveKey(seedHandle, path) ─────────────── */

static JSValue js_crypto_derive_key(JSContext *ctx,
                                      JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "seedHandle and path required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    const char *path = JS_ToCString(ctx, argv[1]);
    if (!path) return JS_EXCEPTION;

    /* Get seed/key bytes from key store */
    size_t key_len;
    int curve;
    const uint8_t *key_bytes = wdk_key_store_get(handle, &key_len, &curve);
    if (!key_bytes) {
        JS_FreeCString(ctx, path);
        return JS_ThrowRangeError(ctx, "Invalid key handle");
    }

    /* Derive using BIP-32 */
    wdk_bip32_key master;
    if (key_len == 64) {
        /* It's a seed — derive master key first */
        if (wdk_bip32_from_seed(key_bytes, key_len, &master) != 0) {
            JS_FreeCString(ctx, path);
            return JS_ThrowInternalError(ctx, "Failed to derive master key");
        }
    } else if (key_len == 32) {
        /* It's already a private key — need chain code too */
        /* For now, only support seed → derive path */
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Handle must be a seed (64 bytes) for path derivation");
    } else {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Unexpected key length");
    }

    wdk_bip32_key derived;
    if (wdk_bip32_derive_path(&master, path, &derived) != 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowInternalError(ctx, "Failed to derive key at path");
    }
    JS_FreeCString(ctx, path);

    /* Store derived private key + chain code (64 bytes total) in key store */
    uint8_t combined[64];
    memcpy(combined, derived.private_key, 32);
    memcpy(combined + 32, derived.chain_code, 32);

    /* Determine curve from path — paths starting with m/44'/501' or m/44'/607' are Ed25519 */
    int derived_curve = WDK_KEY_CURVE_SECP256K1; /* default */
    /* Simple heuristic: check coin type in path */
    if (strstr(path, "/501'") || strstr(path, "/607'")) {
        derived_curve = WDK_KEY_CURVE_ED25519;
    }

    WDKKeyHandle new_handle = wdk_key_store_add(combined, 64, derived_curve);

    /* Secure-wipe local copies */
    volatile uint8_t *vm = (volatile uint8_t *)&master;
    for (size_t i = 0; i < sizeof(master); i++) vm[i] = 0;
    volatile uint8_t *vd = (volatile uint8_t *)&derived;
    for (size_t i = 0; i < sizeof(derived); i++) vd[i] = 0;
    volatile uint8_t *vc = (volatile uint8_t *)combined;
    for (size_t i = 0; i < 64; i++) vc[i] = 0;

    if (new_handle < 0) {
        return JS_ThrowInternalError(ctx, "Key store full");
    }

    return JS_NewInt32(ctx, new_handle);
}

/* ── native.crypto.signSecp256k1(keyHandle, hash32) ────────── */

static JSValue js_crypto_sign_secp256k1(JSContext *ctx,
                                          JSValueConst this_val,
                                          int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "keyHandle and hash required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    size_t hash_len;
    uint8_t *hash = js_get_uint8array(ctx, argv[1], &hash_len);
    if (!hash || hash_len != 32) {
        return JS_ThrowTypeError(ctx, "Hash must be 32 bytes");
    }

    size_t key_len;
    int curve;
    const uint8_t *key_bytes = wdk_key_store_get(handle, &key_len, &curve);
    if (!key_bytes) {
        return JS_ThrowRangeError(ctx, "Invalid key handle");
    }

    /* First 32 bytes are always the private key */
    const uint8_t *privkey = key_bytes;

    secp256k1_context *secp_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature sig;

    int ret = secp256k1_ecdsa_sign(secp_ctx, &sig, hash, privkey,
                                     NULL, NULL);
    if (!ret) {
        secp256k1_context_destroy(secp_ctx);
        return JS_ThrowInternalError(ctx, "secp256k1 sign failed");
    }

    uint8_t sig_compact[64];
    secp256k1_ecdsa_signature_serialize_compact(secp_ctx, sig_compact, &sig);
    secp256k1_context_destroy(secp_ctx);

    return js_new_uint8array(ctx, sig_compact, 64);
}

/* ── native.crypto.signEd25519(keyHandle, message) ─────────── */

static JSValue js_crypto_sign_ed25519(JSContext *ctx,
                                        JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "keyHandle and message required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    size_t msg_len;
    uint8_t *msg = js_get_uint8array(ctx, argv[1], &msg_len);
    if (!msg) return JS_ThrowTypeError(ctx, "message must be Uint8Array");

    size_t key_len;
    int curve;
    const uint8_t *key_bytes = wdk_key_store_get(handle, &key_len, &curve);
    if (!key_bytes) {
        return JS_ThrowRangeError(ctx, "Invalid key handle");
    }

    /*
     * TweetNaCl expects a 64-byte secret key: sk[0..31] = seed, sk[32..63] = public key.
     * Our key store has 32-byte private key (seed) in first 32 bytes.
     * We derive the public key from the seed, then construct the full 64-byte sk.
     */
    extern int crypto_sign_ed25519_tweet(unsigned char *sm,
                                          unsigned long long *smlen_p,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *sk);

    /* Build full 64-byte secret key: seed || pubkey */
    uint8_t pk[32], sk[64];
    memcpy(sk, key_bytes, 32);  /* seed into sk[0..31] */
    wdk_ed25519_pubkey_from_seed(key_bytes, pk);
    memcpy(sk + 32, pk, 32);   /* pubkey into sk[32..63] */

    /* Sign: output is signature (64 bytes) prepended to message */
    size_t sm_len = msg_len + 64;
    uint8_t *sm = malloc(sm_len);
    if (!sm) return JS_ThrowInternalError(ctx, "Out of memory");

    unsigned long long smlen;
    int ret = crypto_sign_ed25519_tweet(sm, &smlen, msg, msg_len, sk);

    /* Secure-wipe local key material */
    volatile uint8_t *vsk = (volatile uint8_t *)sk;
    for (int i = 0; i < 64; i++) vsk[i] = 0;

    if (ret != 0) {
        free(sm);
        return JS_ThrowInternalError(ctx, "Ed25519 sign failed");
    }

    /* Extract just the 64-byte signature (first 64 bytes of sm) */
    JSValue result = js_new_uint8array(ctx, sm, 64);
    free(sm);
    return result;
}

/* ── native.crypto.getPublicKey(keyHandle, curve) ──────────── */

static JSValue js_crypto_get_public_key(JSContext *ctx,
                                          JSValueConst this_val,
                                          int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "keyHandle and curve required");

    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);

    const char *curve_str = JS_ToCString(ctx, argv[1]);
    if (!curve_str) return JS_EXCEPTION;

    size_t key_len;
    int curve;
    const uint8_t *key_bytes = wdk_key_store_get(handle, &key_len, &curve);
    if (!key_bytes) {
        JS_FreeCString(ctx, curve_str);
        return JS_ThrowRangeError(ctx, "Invalid key handle");
    }

    if (strcmp(curve_str, "secp256k1") == 0) {
        JS_FreeCString(ctx, curve_str);

        secp256k1_context *secp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pubkey;

        if (!secp256k1_ec_pubkey_create(secp_ctx, &pubkey, key_bytes)) {
            secp256k1_context_destroy(secp_ctx);
            return JS_ThrowInternalError(ctx, "Invalid private key");
        }

        uint8_t pubkey_compressed[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(secp_ctx, pubkey_compressed,
                                       &pubkey_len, &pubkey,
                                       SECP256K1_EC_COMPRESSED);
        secp256k1_context_destroy(secp_ctx);

        return js_new_uint8array(ctx, pubkey_compressed, 33);

    } else if (strcmp(curve_str, "ed25519") == 0) {
        JS_FreeCString(ctx, curve_str);

        /* Derive Ed25519 public key from 32-byte seed */
        uint8_t pk[32];
        wdk_ed25519_pubkey_from_seed(key_bytes, pk);

        return js_new_uint8array(ctx, pk, 32);
    }

    JS_FreeCString(ctx, curve_str);
    return JS_ThrowTypeError(ctx, "Unknown curve. Use 'secp256k1' or 'ed25519'");
}

/* ── Hash functions ────────────────────────────────────────── */

static JSValue js_crypto_sha256(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_get_uint8array(ctx, argv[0], &len);
    if (!data) return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    uint8_t out[32];
    wdk_sha256(data, len, out);
    return js_new_uint8array(ctx, out, 32);
}

static JSValue js_crypto_sha512(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_get_uint8array(ctx, argv[0], &len);
    if (!data) return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    uint8_t out[64];
    wdk_sha512(data, len, out);
    return js_new_uint8array(ctx, out, 64);
}

static JSValue js_crypto_keccak256(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_get_uint8array(ctx, argv[0], &len);
    if (!data) return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    uint8_t out[32];
    wdk_keccak256(data, len, out);
    return js_new_uint8array(ctx, out, 32);
}

static JSValue js_crypto_ripemd160(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "data required");
    size_t len;
    uint8_t *data = js_get_uint8array(ctx, argv[0], &len);
    if (!data) return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    uint8_t out[20];
    wdk_ripemd160(data, len, out);
    return js_new_uint8array(ctx, out, 20);
}

static JSValue js_crypto_blake2b(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "data and outLen required");
    size_t len;
    uint8_t *data = js_get_uint8array(ctx, argv[0], &len);
    if (!data) return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    int32_t out_len;
    JS_ToInt32(ctx, &out_len, argv[1]);
    if (out_len < 1 || out_len > 64) {
        return JS_ThrowRangeError(ctx, "outLen must be 1-64");
    }
    uint8_t out[64];
    wdk_blake2b(data, len, out, (size_t)out_len);
    return js_new_uint8array(ctx, out, (size_t)out_len);
}

/* ── HMAC functions ────────────────────────────────────────── */

static JSValue js_crypto_hmac_sha256(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "key and data required");
    size_t key_len, data_len;
    uint8_t *key = js_get_uint8array(ctx, argv[0], &key_len);
    uint8_t *data = js_get_uint8array(ctx, argv[1], &data_len);
    if (!key || !data) return JS_ThrowTypeError(ctx, "key and data must be Uint8Array");
    uint8_t out[32];
    wdk_hmac_sha256(key, key_len, data, data_len, out);
    return js_new_uint8array(ctx, out, 32);
}

static JSValue js_crypto_hmac_sha512(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "key and data required");
    size_t key_len, data_len;
    uint8_t *key = js_get_uint8array(ctx, argv[0], &key_len);
    uint8_t *data = js_get_uint8array(ctx, argv[1], &data_len);
    if (!key || !data) return JS_ThrowTypeError(ctx, "key and data must be Uint8Array");
    uint8_t out[64];
    wdk_hmac_sha512(key, key_len, data, data_len, out);
    return js_new_uint8array(ctx, out, 64);
}

/* ── native.crypto.releaseKey(handle) ──────────────────────── */

static JSValue js_crypto_release_key(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "handle required");
    int32_t handle;
    JS_ToInt32(ctx, &handle, argv[0]);
    wdk_key_store_release(handle);
    return JS_UNDEFINED;
}

/* ── Registration ──────────────────────────────────────────── */

void wdk_register_crypto_bridge(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);

    /* Create native object if it doesn't exist */
    JSValue native_obj = JS_GetPropertyStr(ctx, global, "native");
    if (JS_IsUndefined(native_obj)) {
        native_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "native", JS_DupValue(ctx, native_obj));
    }

    /* Create native.crypto object */
    JSValue crypto = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, crypto, "generateMnemonic",
        JS_NewCFunction(ctx, js_crypto_generate_mnemonic, "generateMnemonic", 1));
    JS_SetPropertyStr(ctx, crypto, "mnemonicToSeed",
        JS_NewCFunction(ctx, js_crypto_mnemonic_to_seed, "mnemonicToSeed", 2));
    JS_SetPropertyStr(ctx, crypto, "deriveKey",
        JS_NewCFunction(ctx, js_crypto_derive_key, "deriveKey", 2));
    JS_SetPropertyStr(ctx, crypto, "signSecp256k1",
        JS_NewCFunction(ctx, js_crypto_sign_secp256k1, "signSecp256k1", 2));
    JS_SetPropertyStr(ctx, crypto, "signEd25519",
        JS_NewCFunction(ctx, js_crypto_sign_ed25519, "signEd25519", 2));
    JS_SetPropertyStr(ctx, crypto, "getPublicKey",
        JS_NewCFunction(ctx, js_crypto_get_public_key, "getPublicKey", 2));
    JS_SetPropertyStr(ctx, crypto, "sha256",
        JS_NewCFunction(ctx, js_crypto_sha256, "sha256", 1));
    JS_SetPropertyStr(ctx, crypto, "sha512",
        JS_NewCFunction(ctx, js_crypto_sha512, "sha512", 1));
    JS_SetPropertyStr(ctx, crypto, "keccak256",
        JS_NewCFunction(ctx, js_crypto_keccak256, "keccak256", 1));
    JS_SetPropertyStr(ctx, crypto, "ripemd160",
        JS_NewCFunction(ctx, js_crypto_ripemd160, "ripemd160", 1));
    JS_SetPropertyStr(ctx, crypto, "blake2b",
        JS_NewCFunction(ctx, js_crypto_blake2b, "blake2b", 2));
    JS_SetPropertyStr(ctx, crypto, "hmacSha256",
        JS_NewCFunction(ctx, js_crypto_hmac_sha256, "hmacSha256", 2));
    JS_SetPropertyStr(ctx, crypto, "hmacSha512",
        JS_NewCFunction(ctx, js_crypto_hmac_sha512, "hmacSha512", 2));
    JS_SetPropertyStr(ctx, crypto, "releaseKey",
        JS_NewCFunction(ctx, js_crypto_release_key, "releaseKey", 1));

    JS_SetPropertyStr(ctx, native_obj, "crypto", crypto);

    JS_FreeValue(ctx, native_obj);
    JS_FreeValue(ctx, global);
}
