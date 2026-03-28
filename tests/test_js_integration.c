/*
 * test_js_integration.c — Load the wdk-bundle.js in QuickJS and call wdk.createWallet()
 *
 * This is the Phase 2 integration test: does the JS SDK work inside the native engine?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared-c/vendor/quickjs-ng/quickjs.h"
#include "../shared-c/bridge/key_store.h"

/* Bridge registration functions */
extern void wdk_register_crypto_bridge(JSContext *ctx);
extern void wdk_register_encoding_bridge(JSContext *ctx);

/* Read a file into a malloc'd buffer */
static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open: %s\n", path); return NULL; }
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

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%02d] %-55s ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("\n=== WDK v2 — JS Integration Tests ===\n\n");

    /* Determine bundle path */
    const char *bundle_path = "../../wdk-v2-core/dist/wdk-bundle.js";
    if (argc > 1) bundle_path = argv[1];

    /* 1. Create QuickJS runtime + context */
    TEST("Create QuickJS runtime");
    JSRuntime *rt = JS_NewRuntime();
    if (!rt) { FAIL("JS_NewRuntime"); return 1; }
    JS_SetMemoryLimit(rt, 32 * 1024 * 1024);
    JS_SetMaxStackSize(rt, 1024 * 1024);
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) { FAIL("JS_NewContext"); return 1; }
    PASS();

    /* 2. Initialize key store + register bridges */
    TEST("Register native bridges");
    wdk_key_store_init();
    wdk_register_crypto_bridge(ctx);
    wdk_register_encoding_bridge(ctx);
    PASS();

    /* 3. Load the JS bundle */
    TEST("Load wdk-bundle.js");
    size_t js_len;
    char *js_code = read_file(bundle_path, &js_len);
    if (!js_code) { FAIL("file not found"); return 1; }

    JSValue result = JS_Eval(ctx, js_code, js_len, "wdk-bundle.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        JSValue exc = JS_GetException(ctx);
        const char *msg = JS_ToCString(ctx, exc);
        printf("FAIL: JS exception: %s\n", msg ? msg : "(unknown)");
        JS_FreeCString(ctx, msg);
        JS_FreeValue(ctx, exc);
        JS_FreeValue(ctx, result);
        free(js_code);
        return 1;
    }
    JS_FreeValue(ctx, result);
    free(js_code);
    PASS();

    /* 4. Check globalThis.wdk exists */
    TEST("globalThis.wdk is defined");
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue wdk = JS_GetPropertyStr(ctx, global, "wdk");
    if (JS_IsUndefined(wdk)) { FAIL("wdk is undefined"); }
    else { PASS(); }

    /* 5. Check wdk.createWallet is a function */
    TEST("wdk.createWallet is a function");
    JSValue createWallet = JS_GetPropertyStr(ctx, wdk, "createWallet");
    if (JS_IsFunction(ctx, createWallet)) { PASS(); }
    else { FAIL("not a function"); }

    /* 6. Call wdk.createWallet() */
    TEST("wdk.createWallet() returns mnemonic");
    JSValue args = JS_NewObject(ctx);
    JSValue cw_result = JS_Call(ctx, createWallet, wdk, 1, &args);
    JS_FreeValue(ctx, args);

    if (JS_IsException(cw_result)) {
        JSValue exc = JS_GetException(ctx);
        const char *msg = JS_ToCString(ctx, exc);
        char err[256];
        snprintf(err, sizeof(err), "exception: %s", msg ? msg : "(unknown)");
        FAIL(err);
        JS_FreeCString(ctx, msg);
        JS_FreeValue(ctx, exc);
    } else {
        /* Result should be { mnemonic: "word1 word2 ..." } */
        JSValue mnemonic_val = JS_GetPropertyStr(ctx, cw_result, "mnemonic");
        const char *mnemonic = JS_ToCString(ctx, mnemonic_val);
        if (mnemonic && strlen(mnemonic) > 10) {
            /* Count words */
            int words = 1;
            for (const char *p = mnemonic; *p; p++) if (*p == ' ') words++;
            if (words == 12) {
                printf("PASS (\"%.*s...\")\n", 30, mnemonic);
                tests_passed++;
            } else {
                char err[64];
                snprintf(err, sizeof(err), "expected 12 words, got %d", words);
                FAIL(err);
            }
        } else {
            FAIL("no mnemonic in result");
        }
        JS_FreeCString(ctx, mnemonic);
        JS_FreeValue(ctx, mnemonic_val);
    }
    JS_FreeValue(ctx, cw_result);

    /* 7. Call wdk.getState() — should be "created" */
    TEST("wdk.getState() returns 'created'");
    JSValue getState = JS_GetPropertyStr(ctx, wdk, "getState");
    JSValue state = JS_Call(ctx, getState, wdk, 0, NULL);
    const char *state_str = JS_ToCString(ctx, state);
    if (state_str && strcmp(state_str, "created") == 0) { PASS(); }
    else {
        char err[128];
        snprintf(err, sizeof(err), "got '%s'", state_str ? state_str : "(null)");
        FAIL(err);
    }
    JS_FreeCString(ctx, state_str);
    JS_FreeValue(ctx, state);
    JS_FreeValue(ctx, getState);

    /* 8. Check key store count (should be 0 — no keys derived yet) */
    TEST("Key store empty after createWallet (no keys derived)");
    if (wdk_key_store_count() == 0) { PASS(); }
    else {
        char err[64];
        snprintf(err, sizeof(err), "expected 0, got %d", wdk_key_store_count());
        FAIL(err);
    }

    /* Cleanup */
    JS_FreeValue(ctx, createWallet);
    JS_FreeValue(ctx, wdk);
    JS_FreeValue(ctx, global);
    wdk_key_store_destroy();
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
