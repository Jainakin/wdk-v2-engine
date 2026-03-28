/*
 * test_btc_integration.c — Bitcoin address generation end-to-end test
 *
 * Tests the FULL stack: JS bundle → QuickJS → native.crypto → C crypto
 *
 * Known test vector (BIP-84):
 *   Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *   Path: m/84'/0'/0'/0/0
 *   Expected address: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
 *
 * This test loads the wdk-bundle.js (which includes the BTC module),
 * calls the address generation, and verifies the result.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared-c/vendor/quickjs-ng/quickjs.h"
#include "../shared-c/bridge/key_store.h"

/* Bridge registration functions */
extern void wdk_register_crypto_bridge(JSContext *ctx);
extern void wdk_register_encoding_bridge(JSContext *ctx);

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    *out_len = (size_t)len;
    return buf;
}

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%02d] %-55s ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/*
 * Helper: evaluate JS and return the string result.
 * Caller must free the returned string.
 */
static char *eval_js(JSContext *ctx, const char *code) {
    JSValue result = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        JSValue exc = JS_GetException(ctx);
        const char *msg = JS_ToCString(ctx, exc);
        fprintf(stderr, "JS Error: %s\n", msg ? msg : "(unknown)");
        JS_FreeCString(ctx, msg);
        JS_FreeValue(ctx, exc);
        JS_FreeValue(ctx, result);
        return NULL;
    }

    const char *str = JS_ToCString(ctx, result);
    char *ret = str ? strdup(str) : NULL;
    JS_FreeCString(ctx, str);
    JS_FreeValue(ctx, result);
    return ret;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("\n=== WDK v2 — Bitcoin Integration Tests ===\n\n");

    const char *bundle_path = argc > 1 ? argv[1] :
        "/Users/hardik/Desktop/wdk-v2/working/wdk-v2-core/dist/wdk-bundle.js";

    /* Setup QuickJS */
    JSRuntime *rt = JS_NewRuntime();
    JS_SetMemoryLimit(rt, 32 * 1024 * 1024);
    JS_SetMaxStackSize(rt, 1024 * 1024);
    JSContext *ctx = JS_NewContext(rt);

    wdk_key_store_init();
    wdk_register_crypto_bridge(ctx);
    wdk_register_encoding_bridge(ctx);

    /* Load main bundle */
    size_t js_len;
    char *js_code = read_file(bundle_path, &js_len);
    if (js_code) {
        JSValue r = JS_Eval(ctx, js_code, js_len, "wdk-bundle.js", JS_EVAL_TYPE_GLOBAL);
        JS_FreeValue(ctx, r);
        free(js_code);
    }

    /* Also load BTC bundle if separate */
    if (argc > 2) {
        char *btc_code = read_file(argv[2], &js_len);
        if (btc_code) {
            JSValue r = JS_Eval(ctx, btc_code, js_len, "btc-bundle.js", JS_EVAL_TYPE_GLOBAL);
            JS_FreeValue(ctx, r);
            free(btc_code);
        }
    }

    /* ── Test 1: Direct crypto test — derive key and generate address in C+JS ── */

    TEST("BTC: derive key m/84'/0'/0'/0/0 from known seed");
    {
        /* Use the known BIP-39 test mnemonic's seed */
        char *result = eval_js(ctx,
            "(() => {"
            "  const seedHandle = native.crypto.mnemonicToSeed("
            "    'abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about', '');"
            "  const keyHandle = native.crypto.deriveKey(seedHandle, \"m/84'/0'/0'/0/0\");"
            "  const pubkey = native.crypto.getPublicKey(keyHandle, 'secp256k1');"
            "  return native.encoding.hexEncode(pubkey);"
            "})()");

        if (result) {
            /* Expected compressed pubkey for this path:
             * 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c */
            if (strcmp(result, "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c") == 0) {
                PASS();
            } else {
                char msg[128];
                snprintf(msg, sizeof(msg), "pubkey = %.40s...", result);
                FAIL(msg);
            }
            free(result);
        } else {
            FAIL("JS eval failed");
        }
    }

    TEST("BTC: hash160 of pubkey");
    {
        char *result = eval_js(ctx,
            "(() => {"
            "  const seedHandle = native.crypto.mnemonicToSeed("
            "    'abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about', '');"
            "  const keyHandle = native.crypto.deriveKey(seedHandle, \"m/84'/0'/0'/0/0\");"
            "  const pubkey = native.crypto.getPublicKey(keyHandle, 'secp256k1');"
            "  const sha = native.crypto.sha256(pubkey);"
            "  const hash160 = native.crypto.ripemd160(sha);"
            "  return native.encoding.hexEncode(hash160);"
            "})()");

        if (result) {
            /* Expected hash160: c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2 */
            if (strcmp(result, "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2") == 0) {
                PASS();
            } else {
                char msg[128];
                snprintf(msg, sizeof(msg), "hash160 = %s", result);
                FAIL(msg);
            }
            free(result);
        } else {
            FAIL("JS eval failed");
        }
    }

    TEST("BTC: bech32 SegWit address from hash160");
    {
        /*
         * Build a SegWit address manually:
         * 1. Convert 20-byte hash160 from 8-bit to 5-bit
         * 2. Prepend witness version 0
         * 3. Bech32 encode with "bc" HRP
         *
         * Expected: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
         */
        char *result = eval_js(ctx,
            "(() => {"
            "  const seedHandle = native.crypto.mnemonicToSeed("
            "    'abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about', '');"
            "  const keyHandle = native.crypto.deriveKey(seedHandle, \"m/84'/0'/0'/0/0\");"
            "  const pubkey = native.crypto.getPublicKey(keyHandle, 'secp256k1');"
            "  const sha = native.crypto.sha256(pubkey);"
            "  const hash160 = native.crypto.ripemd160(sha);"
            ""
            "  /* Convert 8-bit to 5-bit */"
            "  function convertBits(data, fromBits, toBits, pad) {"
            "    let acc = 0, bits = 0;"
            "    const result = [];"
            "    const maxv = (1 << toBits) - 1;"
            "    for (let i = 0; i < data.length; i++) {"
            "      acc = (acc << fromBits) | data[i];"
            "      bits += fromBits;"
            "      while (bits >= toBits) {"
            "        bits -= toBits;"
            "        result.push((acc >> bits) & maxv);"
            "      }"
            "    }"
            "    if (pad && bits > 0) {"
            "      result.push((acc << (toBits - bits)) & maxv);"
            "    }"
            "    return new Uint8Array(result);"
            "  }"
            ""
            "  const data5 = convertBits(hash160, 8, 5, true);"
            "  /* Prepend witness version 0 */"
            "  const witnessData = new Uint8Array(1 + data5.length);"
            "  witnessData[0] = 0;"
            "  witnessData.set(data5, 1);"
            ""
            "  return native.encoding.bech32Encode('bc', witnessData);"
            "})()");

        if (result) {
            if (strcmp(result, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu") == 0) {
                PASS();
            } else {
                char msg[256];
                snprintf(msg, sizeof(msg), "got '%s'", result);
                FAIL(msg);
            }
            free(result);
        } else {
            FAIL("JS eval failed");
        }
    }

    TEST("BTC: wdk.createWallet() generates valid mnemonic");
    {
        char *result = eval_js(ctx,
            "JSON.stringify(wdk.createWallet({ wordCount: 12 }))");
        if (result) {
            if (strstr(result, "mnemonic") != NULL) { PASS(); }
            else { FAIL("no mnemonic in result"); }
            free(result);
        } else {
            FAIL("JS eval failed");
        }
    }

    /* Cleanup */
    wdk_key_store_destroy();
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
