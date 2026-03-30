/*
 * test_bridges.c — Test the platform bridges (net, storage, platform)
 *
 * Verifies that native.platform.*, native.storage.*, and the engine
 * eval/eval_string functions work correctly through the JS layer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared-c/vendor/quickjs-ng/quickjs.h"
#include "../shared-c/bridge/engine.h"
#include "../shared-c/bridge/bridge.h"

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%02d] %-55s ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* Mock platform provider for testing */
static int mock_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xFF);
    return 0;
}

static void mock_log(int level, const char *msg) {
    (void)level; (void)msg;
}

/* Mock storage for testing */
static uint8_t stored_value[256];
static size_t stored_len = 0;
static int storage_has_value = 0;

static int mock_secure_set(const char *key, const uint8_t *value, size_t len) {
    (void)key;
    if (len > sizeof(stored_value)) return -1;
    memcpy(stored_value, value, len);
    stored_len = len;
    storage_has_value = 1;
    return 0;
}

static int mock_secure_get(const char *key, uint8_t **out, size_t *out_len) {
    (void)key;
    if (!storage_has_value) { *out = NULL; *out_len = 0; return -1; }
    *out = malloc(stored_len);
    memcpy(*out, stored_value, stored_len);
    *out_len = stored_len;
    return 0;
}

static int mock_secure_delete(const char *key) {
    (void)key;
    storage_has_value = 0;
    return 0;
}

static int mock_secure_has(const char *key) {
    (void)key;
    return storage_has_value;
}

static int mock_regular_set(const char *key, const char *value) {
    (void)key; (void)value;
    return 0;
}

static char *mock_regular_get(const char *key) {
    (void)key;
    return NULL;
}

static int mock_regular_delete(const char *key) {
    (void)key;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("\n=== WDK v2 — Bridge Tests ===\n\n");

    /* Test 1: Engine create + eval */
    TEST("Engine: create and eval basic JS");
    WDKEngine *engine = wdk_engine_create();
    if (!engine) { FAIL("create failed"); return 1; }

    /* Register pure-C bridges explicitly — wdk_engine_create() no longer
     * does this automatically. Platform wrappers (Swift/Kotlin) do it in
     * their initialize() before eval. C tests must do it manually. */
    JSContext *ctx = wdk_engine_get_context(engine);
    wdk_register_crypto_bridge(ctx);
    wdk_register_encoding_bridge(ctx);

    int ret = wdk_engine_eval(engine, "var x = 1 + 2;");
    if (ret == 0) { PASS(); } else { FAIL(wdk_engine_get_error(engine)); }

    /* Test 2: eval_string */
    TEST("Engine: eval_string returns result");
    char *result = wdk_engine_eval_string(engine, "'hello' + ' ' + 'world'");
    if (result && strcmp(result, "hello world") == 0) { PASS(); }
    else { FAIL(result ? result : "null"); }
    if (result) wdk_free_string(result);

    /* Test 3: eval_string with native.crypto */
    TEST("Engine: eval native.crypto.generateMnemonic via JS");
    result = wdk_engine_eval_string(engine,
        "native.crypto.generateMnemonic(12)");
    if (result) {
        int words = 1;
        for (char *p = result; *p; p++) if (*p == ' ') words++;
        if (words == 12) { PASS(); } else {
            char msg[64]; snprintf(msg, sizeof(msg), "%d words", words);
            FAIL(msg);
        }
        wdk_free_string(result);
    } else {
        FAIL(wdk_engine_get_error(engine));
    }

    /* Test 4: Register platform bridge and test */
    TEST("Platform: register and call native.platform.os");
    {
        JSContext *ctx = wdk_engine_get_context(engine);
        WDKPlatformProvider plat = {
            .os_name = "test_os",
            .engine_version = "0.1.0",
            .get_random_bytes = mock_random,
            .log_message = mock_log,
        };
        wdk_register_platform_bridge(ctx, &plat);

        result = wdk_engine_eval_string(engine, "native.platform.os");
        if (result && strcmp(result, "test_os") == 0) { PASS(); }
        else { FAIL(result ? result : "null"); }
        if (result) wdk_free_string(result);
    }

    /* Test 5: Platform getRandomBytes */
    TEST("Platform: native.platform.getRandomBytes(4)");
    result = wdk_engine_eval_string(engine,
        "native.encoding.hexEncode(native.platform.getRandomBytes(4))");
    if (result && strcmp(result, "00010203") == 0) { PASS(); }
    else { FAIL(result ? result : "null"); }
    if (result) wdk_free_string(result);

    /* Test 6: Register storage bridge */
    TEST("Storage: register and test secure set/get");
    {
        JSContext *ctx = wdk_engine_get_context(engine);
        WDKStorageProvider stor = {
            .secure_set = mock_secure_set,
            .secure_get = mock_secure_get,
            .secure_delete = mock_secure_delete,
            .secure_has = mock_secure_has,
            .regular_set = mock_regular_set,
            .regular_get = mock_regular_get,
            .regular_delete = mock_regular_delete,
        };
        wdk_register_storage_bridge(ctx, &stor);

        /* Set a value */
        ret = wdk_engine_eval(engine,
            "native.storage.secure.set('test', new Uint8Array([0xDE, 0xAD]))");
        /* Get it back */
        result = wdk_engine_eval_string(engine,
            "(() => { var v = native.storage.secure.get('test');"
            " return v ? native.encoding.hexEncode(v) : 'null'; })()");
        if (result && strcmp(result, "dead") == 0) { PASS(); }
        else { FAIL(result ? result : "null"); }
        if (result) wdk_free_string(result);
    }

    /* Test 7: Load JS bundle and call wdk.createWallet */
    TEST("Full: load wdk-bundle.js + call wdk.createWallet()");
    {
        /* Try to load the JS bundle.
         * WDK_BUNDLE_PATH env var overrides the default path relative to this file. */
        const char *bundle_path = getenv("WDK_BUNDLE_PATH");
        if (!bundle_path) {
            /* Default: relative to this test file's directory */
            bundle_path = __FILE__;
            /* Strip filename from __FILE__ and append relative path */
            static char resolved_path[1024];
            const char *last_slash = strrchr(bundle_path, '/');
            if (last_slash) {
                size_t dir_len = (size_t)(last_slash - bundle_path);
                snprintf(resolved_path, sizeof(resolved_path),
                         "%.*s/../../wdk-v2-core/dist/wdk-bundle.js",
                         (int)dir_len, bundle_path);
            } else {
                snprintf(resolved_path, sizeof(resolved_path),
                         "../../wdk-v2-core/dist/wdk-bundle.js");
            }
            bundle_path = resolved_path;
        }
        FILE *f = fopen(bundle_path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long len = ftell(f);
            fseek(f, 0, SEEK_SET);
            char *js = malloc(len + 1);
            fread(js, 1, len, f);
            js[len] = '\0';
            fclose(f);

            ret = wdk_engine_eval(engine, js);
            free(js);

            if (ret == 0) {
                result = wdk_engine_call(engine, "createWallet", "{}");
                if (result && strstr(result, "mnemonic")) { PASS(); }
                else { FAIL(result ? result : wdk_engine_get_error(engine)); }
                if (result) wdk_free_string(result);
            } else {
                FAIL(wdk_engine_get_error(engine));
            }
        } else {
            FAIL("wdk-bundle.js not found");
        }
    }

    /* Test 8: utf8Encode — ASCII string → hex bytes */
    TEST("Encoding: utf8Encode('hello') → 68656c6c6f");
    result = wdk_engine_eval_string(engine,
        "native.encoding.hexEncode(native.encoding.utf8Encode('hello'))");
    if (result && strcmp(result, "68656c6c6f") == 0) { PASS(); }
    else { FAIL(result ? result : wdk_engine_get_error(engine)); }
    if (result) wdk_free_string(result);

    /* Test 9: utf8Decode — bytes back to string */
    TEST("Encoding: utf8Decode(utf8Encode(str)) roundtrip");
    result = wdk_engine_eval_string(engine,
        "native.encoding.utf8Decode(native.encoding.utf8Encode('WDK v2 \xc3\xa9\xc3\xa0'))");
    /* \xc3\xa9 = é, \xc3\xa0 = à in UTF-8 */
    if (result && strcmp(result, "WDK v2 \xc3\xa9\xc3\xa0") == 0) { PASS(); }
    else { FAIL(result ? result : wdk_engine_get_error(engine)); }
    if (result) wdk_free_string(result);

    /* Test 10: Full BTC address derivation through JS */
    TEST("Full: BTC address via JS eval (known mnemonic)");
    result = wdk_engine_eval_string(engine,
        "(() => {"
        "  const s = native.crypto.mnemonicToSeed("
        "    'stock art merge family various matter cost banner "
        "switch illegal obvious decline', '');"
        "  const k = native.crypto.deriveKey(s, \"m/84'/0'/0'/0/0\");"
        "  const pub = native.crypto.getPublicKey(k, 'secp256k1');"
        "  const sha = native.crypto.sha256(pub);"
        "  const h160 = native.crypto.ripemd160(sha);"
        "  function cb(d,fb,tb,p){"
        "    let a=0,b=0,r=[],m=(1<<tb)-1;"
        "    for(let i=0;i<d.length;i++){a=(a<<fb)|d[i];b+=fb;"
        "      while(b>=tb){b-=tb;r.push((a>>b)&m);}}"
        "    if(p&&b>0)r.push((a<<(tb-b))&m);"
        "    return new Uint8Array(r);}"
        "  const d5=cb(h160,8,5,true);"
        "  const wd=new Uint8Array(1+d5.length);"
        "  wd[0]=0;wd.set(d5,1);"
        "  native.crypto.releaseKey(k);"
        "  native.crypto.releaseKey(s);"
        "  return native.encoding.bech32Encode('bc',wd);"
        "})()");
    /* P2WPKH address: 42 chars, starts with bc1q */
    if (result && strlen(result) == 42 && strncmp(result, "bc1q", 4) == 0) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "got '%s'", result ? result : "null");
        FAIL(msg);
    }
    if (result) wdk_free_string(result);

    /* Test 11: Async dispatch — wdk_engine_call awaits Promise from async dispatch() */
    /* This test exercises the Group-C fix: wdk_engine_call must detect a Promise
     * result, attach .then/.catch handlers, pump until resolved, and return the
     * actual address string — not "{}" or "undefined". */
    TEST("Async: wdk_engine_call getAddress resolves Promise → bc1q...");
    {
        /* The bundle was already eval'd in test 7. Use the known mnemonic so the
         * address is deterministic. */
        static const char *abandon_mnemonic =
            "stock art merge family various matter cost banner "
            "switch illegal obvious decline";

        /* createWallet with the known mnemonic is not possible via the JS API
         * (createWallet generates its own mnemonic). Use unlockWallet directly
         * with the known mnemonic to put engine2 into the "ready" state. */
        char unlock_args[256];
        snprintf(unlock_args, sizeof(unlock_args),
                 "{\"mnemonic\":\"%s\"}", abandon_mnemonic);

        char *unlock_result = wdk_engine_call(engine, "unlockWallet", unlock_args);
        if (!unlock_result) {
            FAIL(wdk_engine_get_error(engine) ? wdk_engine_get_error(engine) : "unlockWallet failed");
            goto test11_done;
        }
        wdk_free_string(unlock_result);

        /* Now call getAddress — this goes through async dispatch() */
        char *addr = wdk_engine_call(engine, "getAddress", "{\"chain\":\"btc\"}");
        if (!addr) {
            FAIL(wdk_engine_get_error(engine) ? wdk_engine_get_error(engine) : "getAddress returned NULL");
            goto test11_done;
        }

        /* JSON.stringify wraps the string in quotes: "\"bc1q...\"" */
        /* After JSON.parse on the TS side it becomes the plain address.
         * In the C test, addr is the raw JSON-stringified value. */
        int ok = (addr[0] == '"' && strstr(addr, "bc1q") != NULL);
        if (ok) {
            PASS();
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "got '%s'", addr);
            FAIL(msg);
        }
        wdk_free_string(addr);
    }
    test11_done:;

    /* Test 12: Account model — getAccount returns address + publicKey */
    TEST("Account: wdk.getAccount returns address and publicKey");
    {
        char *acct = wdk_engine_call(engine, "getAccount", "{\"chain\":\"btc\",\"index\":0}");
        if (acct) {
            /* Result should contain "address" and "publicKey" fields */
            int has_addr = (strstr(acct, "address") != NULL);
            int has_pubkey = (strstr(acct, "publicKey") != NULL);
            if (has_addr && has_pubkey) {
                PASS();
            } else {
                char msg[256];
                snprintf(msg, sizeof(msg), "missing fields: addr=%d pub=%d", has_addr, has_pubkey);
                FAIL(msg);
            }
            wdk_free_string(acct);
        } else {
            FAIL(wdk_engine_get_error(engine) ? wdk_engine_get_error(engine) : "getAccount returned NULL");
        }
    }

    /* Cleanup */
    wdk_engine_destroy(engine);

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
