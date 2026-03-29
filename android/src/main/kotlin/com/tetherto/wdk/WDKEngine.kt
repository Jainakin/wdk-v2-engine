package com.tetherto.wdk

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/**
 * Exception thrown when a WDK engine operation fails.
 */
class WDKException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Kotlin wrapper around the WDK v2 native QuickJS engine.
 *
 * All public methods are suspend functions that run native calls on
 * [Dispatchers.Default]. A [Mutex] ensures that only one coroutine
 * accesses the native engine at a time.
 *
 * Usage:
 * ```kotlin
 * val engine = WDKEngine()
 * engine.loadBytecode(context, "wdk_bundle.bin")
 * val result = engine.call("createWallet", mapOf("network" to "bitcoin"))
 * engine.destroy()
 * ```
 */
class WDKEngine {

    companion object {
        init {
            System.loadLibrary("wdk_engine")
        }
    }

    private val nativePtr = AtomicLong(0L)
    private val mutex = Mutex()

    init {
        val ptr = nativeCreate()
        if (ptr == 0L) {
            throw WDKException("Failed to create native WDK engine")
        }
        nativePtr.set(ptr)
    }

    // ── Native method declarations ──────────────────────────────

    private external fun nativeCreate(): Long
    private external fun nativeLoadBytecode(ptr: Long, bytecode: ByteArray): Int
    private external fun nativeCall(ptr: Long, method: String, jsonArgs: String): String?
    private external fun nativeEval(ptr: Long, code: String): Int
    private external fun nativePump(ptr: Long): Int
    private external fun nativeDestroy(ptr: Long)
    private external fun nativeGetError(ptr: Long): String?

    // ── Public API ──────────────────────────────────────────────

    /**
     * Load bytecode from an Android asset file.
     *
     * @param context Android context to access assets.
     * @param assetName File name within the assets directory (e.g., "wdk_bundle.bin").
     * @throws WDKException if the asset cannot be read or the bytecode fails to load.
     */
    suspend fun loadBytecode(context: Context, assetName: String) {
        val bytecode = withContext(Dispatchers.IO) {
            try {
                context.assets.open(assetName).use { it.readBytes() }
            } catch (e: Exception) {
                throw WDKException("Failed to read asset '$assetName'", e)
            }
        }
        loadBytecode(bytecode)
    }

    /**
     * Load bytecode from a raw byte array.
     *
     * @param bytecode Compiled QuickJS bytecode.
     * @throws WDKException if the bytecode fails to load.
     */
    suspend fun loadBytecode(bytecode: ByteArray) {
        withNative("loadBytecode") { ptr ->
            val result = nativeLoadBytecode(ptr, bytecode)
            if (result != 0) {
                val error = nativeGetError(ptr) ?: "Unknown error"
                throw WDKException("Failed to load bytecode: $error")
            }
        }
    }

    /**
     * Call a function on the global `wdk` JavaScript object.
     *
     * @param method Function name (e.g., "createWallet").
     * @param params Parameters serialized as JSON. Supports String, Number, Boolean,
     *               null, and nested Map/List values.
     * @return JSON string of the function result.
     * @throws WDKException if the call fails.
     */
    suspend fun call(method: String, params: Map<String, Any?> = emptyMap()): String {
        return withNative("call") { ptr ->
            val jsonArgs = toJson(params)
            val result = nativeCall(ptr, method, jsonArgs)
            // Pump the job queue to resolve any pending promises.
            nativePump(ptr)

            if (result == null) {
                val error = nativeGetError(ptr) ?: "Unknown error"
                throw WDKException("Engine call '$method' failed: $error")
            }
            result
        }
    }

    /**
     * Evaluate raw JavaScript source code in the engine context.
     *
     * Uses wdk_engine_eval (JS_Eval) directly — does NOT require globalThis.wdk
     * to exist. Used to load the JS bundle before any wdk.* calls are possible.
     *
     * @param code JavaScript source code.
     * @throws WDKException if evaluation fails.
     */
    suspend fun eval(code: String) {
        withNative("eval") { ptr ->
            val result = nativeEval(ptr, code)
            nativePump(ptr)
            if (result != 0) {
                val error = nativeGetError(ptr) ?: "JS eval failed"
                throw WDKException("Engine eval failed: $error")
            }
        }
    }

    /**
     * Pump the QuickJS job queue to process pending microtasks.
     *
     * This is automatically called after [call] and [eval], but can be invoked
     * explicitly if needed (e.g., after registering async callbacks).
     *
     * @return Number of jobs executed.
     * @throws WDKException if pumping fails.
     */
    suspend fun pump(): Int {
        return withNative("pump") { ptr ->
            val result = nativePump(ptr)
            if (result < 0) {
                val error = nativeGetError(ptr) ?: "Unknown error"
                throw WDKException("Failed to pump job queue: $error")
            }
            result
        }
    }

    /**
     * Destroy the native engine and release all resources.
     *
     * After calling this method, any further operations on this instance
     * will throw [WDKException]. This method is idempotent.
     */
    fun destroy() {
        val ptr = nativePtr.getAndSet(0L)
        if (ptr != 0L) {
            nativeDestroy(ptr)
        }
    }

    /**
     * Safety net: destroy the engine if the caller forgets.
     */
    @Suppress("removal")
    protected fun finalize() {
        destroy()
    }

    // ── Internal helpers ────────────────────────────────────────

    /**
     * Acquire the mutex, verify the engine is alive, and run [block]
     * on [Dispatchers.Default].
     */
    private suspend fun <T> withNative(operation: String, block: (Long) -> T): T {
        return mutex.withLock {
            withContext(Dispatchers.Default) {
                val ptr = nativePtr.get()
                if (ptr == 0L) {
                    throw WDKException("Engine already destroyed (during '$operation')")
                }
                block(ptr)
            }
        }
    }

    /**
     * Convert a Map to a JSON string using [JSONObject].
     */
    private fun toJson(params: Map<String, Any?>): String {
        return JSONObject(params).toString()
    }
}
