/*
 * WDK v2 Native Engine — QuickJS Engine Lifecycle
 *
 * Creates and manages a QuickJS runtime/context, loads compiled bytecode,
 * and provides a JSON-based call interface for the JavaScript layer.
 */

#ifndef WDK_ENGINE_H
#define WDK_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WDKEngine WDKEngine;

/**
 * Create a new WDK engine instance.
 *
 * Initializes a QuickJS runtime (32 MB memory limit, 1 MB stack),
 * creates a context, initializes the key store, and registers
 * all native bridge functions.
 *
 * @return  Engine instance, or NULL on failure.
 */
WDKEngine *wdk_engine_create(void);

/**
 * Load and evaluate QuickJS bytecode.
 *
 * The bytecode is typically produced by `qjsc` from the bundled JS sources.
 *
 * @param engine  Engine instance.
 * @param buf     Bytecode buffer.
 * @param len     Bytecode length in bytes.
 * @return        0 on success, -1 on error (call wdk_engine_get_error for details).
 */
int wdk_engine_load_bytecode(WDKEngine *engine, const uint8_t *buf, size_t len);

/**
 * Call a function on the global `wdk` object.
 *
 * Looks up `globalThis.wdk[func_name]`, parses json_args via JSON.parse,
 * calls the function, and returns JSON.stringify of the result.
 *
 * @param engine     Engine instance.
 * @param func_name  Name of the function on the `wdk` object.
 * @param json_args  JSON string of arguments (parsed and passed as single arg).
 * @return           JSON string of the result (caller must free with wdk_free_string),
 *                   or NULL on error (call wdk_engine_get_error for details).
 */
char *wdk_engine_call(WDKEngine *engine, const char *func_name, const char *json_args);

/**
 * Get the last error message.
 *
 * @param engine  Engine instance.
 * @return        Error string (valid until next engine call), or NULL if no error.
 */
const char *wdk_engine_get_error(WDKEngine *engine);

/**
 * Pump the QuickJS job queue.
 *
 * Executes pending microtasks (Promise continuations, etc.) up to a
 * safety limit of 10000 iterations.
 *
 * @param engine  Engine instance.
 * @return        Number of jobs executed, or -1 on error.
 */
int wdk_engine_pump(WDKEngine *engine);

/**
 * Destroy the engine and release all resources.
 *
 * Destroys the key store, frees the JS context and runtime.
 *
 * @param engine  Engine instance (NULL is safe).
 */
void wdk_engine_destroy(WDKEngine *engine);

/**
 * Free a string returned by wdk_engine_call.
 *
 * @param str  String to free (NULL is safe).
 */
void wdk_free_string(char *str);

/**
 * Get the JSContext from an engine instance.
 *
 * Used by platform wrappers to register bridges after engine creation.
 *
 * @param engine  Engine instance.
 * @return        JSContext pointer, or NULL if engine is NULL.
 */
struct JSContext *wdk_engine_get_context(WDKEngine *engine);

/**
 * Evaluate raw JavaScript source code.
 *
 * @param engine     Engine instance.
 * @param js_source  JavaScript source code string.
 * @return           0 on success, -1 on error.
 */
int wdk_engine_eval(WDKEngine *engine, const char *js_source);

/**
 * Evaluate raw JavaScript source and return the result as a string.
 *
 * @param engine     Engine instance.
 * @param js_source  JavaScript source code string.
 * @return           String result (caller must free with wdk_free_string),
 *                   or NULL on error.
 */
char *wdk_engine_eval_string(WDKEngine *engine, const char *js_source);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENGINE_H */
