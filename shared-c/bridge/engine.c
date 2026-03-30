/*
 * WDK v2 Native Engine — QuickJS Engine Lifecycle
 *
 * Creates and manages the QuickJS runtime, loads bytecode, and provides
 * a JSON call interface between the native layer and the JS bundle.
 */

#include "engine.h"
#include "key_store.h"
#include "../vendor/quickjs-ng/quickjs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * Engine limits
 * -------------------------------------------------------------------------- */

#define WDK_ENGINE_MEMORY_LIMIT    (32 * 1024 * 1024)  /* 32 MB */
#define WDK_ENGINE_STACK_SIZE      (16 * 1024 * 1024)  /* 16 MB — increased for larger bundles with Electrum transport */
#define WDK_ENGINE_MAX_JOBS        10000                /* pump safety limit */
#define WDK_ENGINE_ERROR_BUF_SIZE  1024

/* --------------------------------------------------------------------------
 * Forward declarations for bridge registration functions.
 * These are implemented in separate bridge_*.c files and register
 * native functions into the QuickJS context.
 * -------------------------------------------------------------------------- */

extern void wdk_register_crypto_bridge(JSContext *ctx);
extern void wdk_register_encoding_bridge(JSContext *ctx);

/* Net bridge pump — resolves completed async fetches on the JS thread */
extern void wdk_net_pump(JSContext *ctx);

/* WebSocket bridge pump — delivers queued WS messages on the JS thread */
extern void wdk_ws_pump(JSContext *ctx);

/* Returns non-zero if there are in-flight fetch requests pending */
extern int wdk_net_has_pending(void);

/* Returns non-zero if there are active WebSocket connections */
extern int wdk_ws_has_pending(void);

/* --------------------------------------------------------------------------
 * Engine structure
 * -------------------------------------------------------------------------- */

struct WDKEngine {
    JSRuntime *rt;
    JSContext *ctx;
    char error_buf[WDK_ENGINE_ERROR_BUF_SIZE];
    int has_error;
};

/* --------------------------------------------------------------------------
 * Internal: capture a JS exception into the error buffer
 * -------------------------------------------------------------------------- */

static void engine_capture_exception(WDKEngine *engine)
{
    JSValue exception = JS_GetException(engine->ctx);

    if (JS_IsError(exception)) {
        /* Try to get the message and stack properties */
        JSValue msg_val = JS_GetPropertyStr(engine->ctx, exception, "message");
        JSValue stack_val = JS_GetPropertyStr(engine->ctx, exception, "stack");

        const char *msg = JS_ToCString(engine->ctx, msg_val);
        const char *stack = JS_ToCString(engine->ctx, stack_val);

        if (msg && stack && stack[0] != '\0') {
            snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE,
                     "%s\n%s", msg, stack);
        } else if (msg) {
            snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE, "%s", msg);
        } else {
            snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE, "Unknown JS error");
        }

        if (msg) JS_FreeCString(engine->ctx, msg);
        if (stack) JS_FreeCString(engine->ctx, stack);
        JS_FreeValue(engine->ctx, msg_val);
        JS_FreeValue(engine->ctx, stack_val);
    } else {
        const char *str = JS_ToCString(engine->ctx, exception);
        if (str) {
            snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE, "%s", str);
            JS_FreeCString(engine->ctx, str);
        } else {
            snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE, "Unknown JS exception");
        }
    }

    JS_FreeValue(engine->ctx, exception);
    engine->has_error = 1;
}

static void engine_set_error(WDKEngine *engine, const char *msg)
{
    snprintf(engine->error_buf, WDK_ENGINE_ERROR_BUF_SIZE, "%s", msg);
    engine->has_error = 1;
}

static void engine_clear_error(WDKEngine *engine)
{
    engine->error_buf[0] = '\0';
    engine->has_error = 0;
}

/* --------------------------------------------------------------------------
 * Create engine
 * -------------------------------------------------------------------------- */

WDKEngine *wdk_engine_create(void)
{
    WDKEngine *engine = (WDKEngine *)calloc(1, sizeof(WDKEngine));
    if (!engine)
        return NULL;

    /* Create JS runtime */
    engine->rt = JS_NewRuntime();
    if (!engine->rt) {
        free(engine);
        return NULL;
    }

    JS_SetMemoryLimit(engine->rt, WDK_ENGINE_MEMORY_LIMIT);
    JS_SetMaxStackSize(engine->rt, WDK_ENGINE_STACK_SIZE);

    /* Create JS context */
    engine->ctx = JS_NewContext(engine->rt);
    if (!engine->ctx) {
        JS_FreeRuntime(engine->rt);
        free(engine);
        return NULL;
    }

    /* Initialize key store */
    wdk_key_store_init();

    /* NOTE: Bridge registration is intentionally NOT done here.
     * All six bridges (crypto, encoding, platform, storage, net) are
     * registered together by the platform wrapper (Swift/Kotlin) in its
     * initialize() call, before any JS is evaluated.
     * This ensures all of native.* is available when the bundle runs,
     * and that provider structs (platform/storage/net) are heap-allocated
     * with lifetimes the platform wrapper controls. */

    return engine;
}

/* --------------------------------------------------------------------------
 * Load bytecode
 * -------------------------------------------------------------------------- */

int wdk_engine_load_bytecode(WDKEngine *engine, const uint8_t *buf, size_t len)
{
    if (!engine || !buf || len == 0) {
        if (engine) engine_set_error(engine, "Invalid parameters for load_bytecode");
        return -1;
    }

    engine_clear_error(engine);

    /* Read the bytecode object */
    JSValue obj = JS_ReadObject(engine->ctx, buf, len, JS_READ_OBJ_BYTECODE);
    if (JS_IsException(obj)) {
        engine_capture_exception(engine);
        return -1;
    }

    /* Evaluate the bytecode (this executes the module/function) */
    JSValue result = JS_EvalFunction(engine->ctx, obj);
    /* Note: JS_EvalFunction takes ownership of obj, do not free it */

    if (JS_IsException(result)) {
        engine_capture_exception(engine);
        return -1;
    }

    JS_FreeValue(engine->ctx, result);

    /* Pump any pending jobs from module initialization */
    wdk_engine_pump(engine);

    return 0;
}

/* --------------------------------------------------------------------------
 * Internal: pump the event loop until __wdk_done is set or timeout.
 *
 * Used by wdk_engine_call to await async (Promise-returning) JS functions.
 * Returns 0 on success, -1 if a job threw an exception or timeout.
 *
 * Key design: when JS_ExecutePendingJob returns 0 (no pending JS jobs) but
 * there are still in-flight network requests (wdk_net_has_pending()), we
 * must keep looping so wdk_net_pump() can resolve those fetches when they
 * complete.  A 1 ms sleep avoids busy-waiting while yielding the thread.
 * -------------------------------------------------------------------------- */

#ifdef _WIN32
#include <windows.h>
#define wdk_sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define wdk_sleep_ms(ms) usleep((ms) * 1000)
#endif

/* Timeout for async calls: 30 seconds */
#define WDK_ASYNC_TIMEOUT_MS 30000

static int engine_pump_until_done(WDKEngine *engine)
{
    JSContext *ctx = engine->ctx;
    int elapsed_ms = 0;

    for (int i = 0; i < WDK_ENGINE_MAX_JOBS; i++) {
        /* Check globalThis.__wdk_done */
        JSValue g = JS_GetGlobalObject(ctx);
        JSValue done_val = JS_GetPropertyStr(ctx, g, "__wdk_done");
        JS_FreeValue(ctx, g);
        int done = JS_ToBool(ctx, done_val);
        JS_FreeValue(ctx, done_val);
        if (done)
            return 0;

        /* Process any completed native async operations (e.g., network) */
        wdk_net_pump(ctx);
        wdk_ws_pump(ctx);

        /* Run one pending microtask/job */
        JSContext *ctx_out;
        int rc = JS_ExecutePendingJob(engine->rt, &ctx_out);

        if (rc < 0) {
            /* JS job threw an exception */
            engine_capture_exception(engine);
            return -1;
        }

        if (rc == 0) {
            /* No pending JS jobs right now.
             * If there are in-flight network fetches, sleep briefly and
             * retry — the fetch callback will set pf->completed, and the
             * next wdk_net_pump() will resolve the Promise, creating new
             * pending JS jobs.
             * If there are NO pending fetches and no pending JS jobs,
             * there is nothing to wait for — the async chain is broken
             * or already resolved (and __wdk_done wasn't set). */
            if (!wdk_net_has_pending() && !wdk_ws_has_pending()) {
                /* Nothing async in flight — check one more time in case
                 * the last wdk_net_pump resolved something but the
                 * JS jobs haven't been queued yet. */
                wdk_net_pump(ctx);
        wdk_ws_pump(ctx);
                rc = JS_ExecutePendingJob(engine->rt, &ctx_out);
                if (rc <= 0) {
                    /* Truly nothing pending. __wdk_done may still be
                     * false if the Promise resolved synchronously and
                     * the handlers haven't run yet — this is unexpected
                     * but return 0 to let the caller check. */
                    return rc < 0 ? (engine_capture_exception(engine), -1) : 0;
                }
                /* A job appeared — continue the main loop */
                continue;
            }

            /* Network requests in flight — yield briefly to avoid
             * burning CPU while URLSession / OkHttp does its work. */
            wdk_sleep_ms(1);
            elapsed_ms += 1;

            if (elapsed_ms >= WDK_ASYNC_TIMEOUT_MS) {
                engine_set_error(engine,
                    "async call timed out: network request did not "
                    "complete within 30 seconds");
                return -1;
            }
        }
        /* rc > 0: a job ran, loop back to check __wdk_done */
    }

    /* Ran out of iteration budget */
    engine_set_error(engine,
        "async call timed out: __wdk_done not set after 10000 job iterations");
    return -1;
}

/* --------------------------------------------------------------------------
 * Call a function on the global wdk object
 *
 * Handles both synchronous and async (Promise-returning) JS functions.
 * For async functions the engine is pumped until the Promise resolves or
 * rejects, and the resolved value is JSON-stringified and returned.
 * -------------------------------------------------------------------------- */

char *wdk_engine_call(WDKEngine *engine, const char *func_name, const char *json_args)
{
    if (!engine || !func_name) {
        if (engine) engine_set_error(engine, "Invalid parameters for call");
        return NULL;
    }

    engine_clear_error(engine);

    JSContext *ctx = engine->ctx;

    /* Get globalThis */
    JSValue global = JS_GetGlobalObject(ctx);

    /* Get globalThis.wdk */
    JSValue wdk_obj = JS_GetPropertyStr(ctx, global, "wdk");
    if (JS_IsUndefined(wdk_obj) || JS_IsNull(wdk_obj)) {
        JS_FreeValue(ctx, wdk_obj);
        JS_FreeValue(ctx, global);
        engine_set_error(engine, "Global 'wdk' object not found");
        return NULL;
    }

    /* Get the function */
    JSValue func = JS_GetPropertyStr(ctx, wdk_obj, func_name);
    if (!JS_IsFunction(ctx, func)) {
        JS_FreeValue(ctx, func);
        JS_FreeValue(ctx, wdk_obj);
        JS_FreeValue(ctx, global);
        engine_set_error(engine, "Function not found on wdk object");
        return NULL;
    }

    /* Parse JSON arguments */
    JSValue args_val;
    if (json_args && json_args[0] != '\0') {
        args_val = JS_ParseJSON(ctx, json_args, strlen(json_args), "<args>");
        if (JS_IsException(args_val)) {
            JS_FreeValue(ctx, func);
            JS_FreeValue(ctx, wdk_obj);
            JS_FreeValue(ctx, global);
            engine_capture_exception(engine);
            return NULL;
        }
    } else {
        args_val = JS_UNDEFINED;
    }

    /* Call the function with the parsed args */
    JSValue result = JS_Call(ctx, func, wdk_obj, 1, &args_val);

    JS_FreeValue(ctx, args_val);
    JS_FreeValue(ctx, func);
    JS_FreeValue(ctx, wdk_obj);
    JS_FreeValue(ctx, global);

    if (JS_IsException(result)) {
        engine_capture_exception(engine);
        return NULL;
    }

    /* ── Async Promise support ──────────────────────────────────────────
     * If the function returned a Promise (thenable), attach .then/.catch
     * handlers that write the settled value to well-known globals, then
     * pump the job queue until __wdk_done is true.  This lets C code
     * await any async JS function without blocking threads or callbacks.
     * ─────────────────────────────────────────────────────────────────── */

    JSValue then_prop = JS_GetPropertyStr(ctx, result, "then");
    int is_promise = JS_IsFunction(ctx, then_prop);
    JS_FreeValue(ctx, then_prop);

    if (is_promise) {
        /* Store the Promise in a global so the setup eval can reach it. */
        JSValue g2 = JS_GetGlobalObject(ctx);
        /* JS_SetPropertyStr takes ownership of the value — result is consumed. */
        JS_SetPropertyStr(ctx, g2, "__wdk_promise", result);
        JS_FreeValue(ctx, g2);

        /* Attach .then/.catch handlers; reset sentinel globals. */
        static const char setup[] =
            "globalThis.__wdk_done=false;"
            "globalThis.__wdk_result=undefined;"
            "globalThis.__wdk_error=undefined;"
            "globalThis.__wdk_promise"
            ".then(function(v){"
            "  globalThis.__wdk_result=v;"
            "  globalThis.__wdk_done=true;"
            "})"
            ".catch(function(e){"
            "  globalThis.__wdk_error=(e&&e.message)?e.message:String(e);"
            "  globalThis.__wdk_done=true;"
            "});";

        JSValue sv = JS_Eval(ctx, setup, sizeof(setup) - 1,
                             "<wdk_await>", JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(sv)) {
            engine_capture_exception(engine);
            return NULL;
        }
        JS_FreeValue(ctx, sv);

        /* Pump until resolved/rejected. */
        if (engine_pump_until_done(engine) < 0)
            return NULL;  /* error already captured */

        /* Collect settled result or rejection reason. */
        JSValue g3 = JS_GetGlobalObject(ctx);
        JSValue error_val  = JS_GetPropertyStr(ctx, g3, "__wdk_error");
        JSValue result_val = JS_GetPropertyStr(ctx, g3, "__wdk_result");

        /* Release the stored Promise so it can be GC'd. */
        JS_SetPropertyStr(ctx, g3, "__wdk_promise", JS_UNDEFINED);
        JS_FreeValue(ctx, g3);

        if (!JS_IsUndefined(error_val)) {
            /* Promise was rejected — propagate as a C error. */
            const char *estr = JS_ToCString(ctx, error_val);
            engine_set_error(engine, estr ? estr : "Promise rejected");
            if (estr) JS_FreeCString(ctx, estr);
            JS_FreeValue(ctx, error_val);
            JS_FreeValue(ctx, result_val);
            return NULL;
        }

        JS_FreeValue(ctx, error_val);

        /* Use the resolved value as the result to stringify. */
        result = result_val;  /* ownership transferred; freed below */

    } else {
        /* Synchronous result — pump any residual microtasks and proceed. */
        wdk_engine_pump(engine);
    }

    /* ── JSON.stringify the result ──────────────────────────────────── */

    JSValue json_global = JS_GetGlobalObject(ctx);
    JSValue json_obj = JS_GetPropertyStr(ctx, json_global, "JSON");
    JSValue stringify_func = JS_GetPropertyStr(ctx, json_obj, "stringify");

    JSValue json_result = JS_Call(ctx, stringify_func, json_obj, 1, &result);

    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, stringify_func);
    JS_FreeValue(ctx, json_obj);
    JS_FreeValue(ctx, json_global);

    if (JS_IsException(json_result)) {
        engine_capture_exception(engine);
        return NULL;
    }

    /* JSON.stringify(undefined) returns JS_UNDEFINED, not a string.
     * Return "null" so callers always get valid JSON. */
    if (JS_IsUndefined(json_result)) {
        JS_FreeValue(ctx, json_result);
        char *out = (char *)malloc(5);
        if (out) memcpy(out, "null", 5);
        return out;
    }

    /* Convert to C string */
    const char *str = JS_ToCString(ctx, json_result);
    JS_FreeValue(ctx, json_result);

    if (!str) {
        engine_set_error(engine, "Failed to stringify result");
        return NULL;
    }

    /* Duplicate the string so it outlives the JS context GC */
    size_t len = strlen(str);
    char *out = (char *)malloc(len + 1);
    if (out) {
        memcpy(out, str, len + 1);
    }

    JS_FreeCString(ctx, str);

    return out;
}

/* --------------------------------------------------------------------------
 * Get error
 * -------------------------------------------------------------------------- */

const char *wdk_engine_get_error(WDKEngine *engine)
{
    if (!engine || !engine->has_error)
        return NULL;
    return engine->error_buf;
}

/* --------------------------------------------------------------------------
 * Pump the job queue
 * -------------------------------------------------------------------------- */

int wdk_engine_pump(WDKEngine *engine)
{
    if (!engine)
        return -1;

    /* Process completed async fetch requests first */
    wdk_net_pump(engine->ctx);

    JSContext *ctx_out;
    int jobs_executed = 0;

    for (int i = 0; i < WDK_ENGINE_MAX_JOBS; i++) {
        int rc = JS_ExecutePendingJob(engine->rt, &ctx_out);
        if (rc <= 0) {
            /* rc == 0: no more jobs; rc < 0: error */
            if (rc < 0) {
                engine_capture_exception(engine);
                return -1;
            }
            break;
        }
        jobs_executed++;
    }

    return jobs_executed;
}

/* --------------------------------------------------------------------------
 * Destroy engine
 * -------------------------------------------------------------------------- */

void wdk_engine_destroy(WDKEngine *engine)
{
    if (!engine)
        return;

    /* Destroy the key store (securely wipes all keys) */
    wdk_key_store_destroy();

    /* Free the JS context and runtime */
    if (engine->ctx) {
        JS_FreeContext(engine->ctx);
        engine->ctx = NULL;
    }

    if (engine->rt) {
        JS_FreeRuntime(engine->rt);
        engine->rt = NULL;
    }

    free(engine);
}

/* --------------------------------------------------------------------------
 * Get JSContext from engine
 * -------------------------------------------------------------------------- */

JSContext *wdk_engine_get_context(WDKEngine *engine)
{
    return engine ? engine->ctx : NULL;
}

/* --------------------------------------------------------------------------
 * Evaluate raw JavaScript source
 * -------------------------------------------------------------------------- */

int wdk_engine_eval(WDKEngine *engine, const char *js_source)
{
    if (!engine || !js_source) {
        if (engine) engine_set_error(engine, "Invalid parameters for eval");
        return -1;
    }

    engine_clear_error(engine);

    JSValue result = JS_Eval(engine->ctx, js_source, strlen(js_source),
                              "<eval>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        engine_capture_exception(engine);
        return -1;
    }

    JS_FreeValue(engine->ctx, result);

    /* Pump any pending jobs */
    wdk_engine_pump(engine);

    return 0;
}

/* --------------------------------------------------------------------------
 * Evaluate raw JavaScript source and return string result
 * -------------------------------------------------------------------------- */

char *wdk_engine_eval_string(WDKEngine *engine, const char *js_source)
{
    if (!engine || !js_source) {
        if (engine) engine_set_error(engine, "Invalid parameters for eval_string");
        return NULL;
    }

    engine_clear_error(engine);

    JSValue result = JS_Eval(engine->ctx, js_source, strlen(js_source),
                              "<eval>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        engine_capture_exception(engine);
        return NULL;
    }

    const char *str = JS_ToCString(engine->ctx, result);
    char *ret = str ? strdup(str) : NULL;
    JS_FreeCString(engine->ctx, str);
    JS_FreeValue(engine->ctx, result);

    /* Pump any pending jobs */
    wdk_engine_pump(engine);

    return ret;
}

/* --------------------------------------------------------------------------
 * Free a string allocated by engine_call
 * -------------------------------------------------------------------------- */

void wdk_free_string(char *str)
{
    free(str);
}
