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
#define WDK_ENGINE_STACK_SIZE      (8 * 1024 * 1024)   /* 8 MB */
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

    /* Register native bridge functions */
    wdk_register_crypto_bridge(engine->ctx);
    wdk_register_encoding_bridge(engine->ctx);

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
 * Call a function on the global wdk object
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

    /* Pump pending jobs (in case the function kicked off async work) */
    wdk_engine_pump(engine);

    /* JSON.stringify the result */
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
