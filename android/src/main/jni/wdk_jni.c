/*
 * WDK v2 Engine -- JNI Bridge
 *
 * Bridges the Kotlin WDKEngine class to the C wdk_engine_* API.
 * Each JNI function converts Java types, calls the C function,
 * and releases JNI resources before returning.
 *
 * Bridge registration: nativeRegisterBridges, nativeRegisterPlatformBridge,
 * nativeRegisterStorageBridge, nativeRegisterNetBridge wire the Kotlin
 * provider objects to C callback structs so the JS bundle can call
 * native.crypto.*, native.encoding.*, native.platform.*, native.storage.*,
 * and native.net.fetch from inside QuickJS.
 */

#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "engine.h"
#include "bridge.h"

/* ── Global JVM reference (captured in JNI_OnLoad) ──────────── */

static JavaVM *g_jvm = NULL;

/* ── Provider object global refs ─────────────────────────────── */

static jobject g_platform_provider = NULL;
static jobject g_storage_provider  = NULL;
static jobject g_net_provider      = NULL;

/* ── Platform provider method IDs ────────────────────────────── */

static jmethodID g_platform_getRandomBytes = NULL;
static jmethodID g_platform_log            = NULL;

/* ── Storage provider method IDs ─────────────────────────────── */

static jmethodID g_storage_secureSetBytes  = NULL;
static jmethodID g_storage_secureGetBytes  = NULL;
static jmethodID g_storage_secureDelete    = NULL;
static jmethodID g_storage_regularSet      = NULL;
static jmethodID g_storage_regularGet      = NULL;
static jmethodID g_storage_regularDelete   = NULL;

/* ── Net provider method ID ───────────────────────────────────── */

static jmethodID g_net_fetchJni = NULL;
/* nativeCompleteNetRequest method on WDKEngineModule — used by Kotlin net callback */
static jclass    g_engine_module_class   = NULL;
static jmethodID g_complete_net_request  = NULL;

/* ── Struct for pending async net callbacks ───────────────────── */

typedef struct {
    WDKFetchCallback callback;
    void *context;
} JNIPendingNet;

/* ── JNI helper: get env, attach if called from non-JVM thread ── */

static JNIEnv *jni_get_env(void) {
    JNIEnv *env = NULL;
    if (!g_jvm) return NULL;
    jint rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
    }
    return env;
}

/* ── Platform callbacks ───────────────────────────────────────── */

static int jni_get_random_bytes(uint8_t *buf, size_t len) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_platform_provider) return -1;
    jbyteArray arr = (jbyteArray)(*env)->CallObjectMethod(
        env, g_platform_provider, g_platform_getRandomBytes, (jint)len);
    if (!arr) return -1;
    (*env)->GetByteArrayRegion(env, arr, 0, (jsize)len, (jbyte *)buf);
    (*env)->DeleteLocalRef(env, arr);
    return 0;
}

static void jni_log_message(int level, const char *message) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_platform_provider) return;
    jstring jmsg = (*env)->NewStringUTF(env, message);
    (*env)->CallVoidMethod(env, g_platform_provider, g_platform_log,
                            (jint)level, jmsg);
    (*env)->DeleteLocalRef(env, jmsg);
}

/* ── Storage callbacks ────────────────────────────────────────── */

static int jni_secure_set(const char *key, const uint8_t *value, size_t value_len) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return -1;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jbyteArray jval = (*env)->NewByteArray(env, (jsize)value_len);
    (*env)->SetByteArrayRegion(env, jval, 0, (jsize)value_len, (const jbyte *)value);
    jboolean ok = (*env)->CallBooleanMethod(
        env, g_storage_provider, g_storage_secureSetBytes, jkey, jval);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jval);
    return ok ? 0 : -1;
}

static int jni_secure_get(const char *key, uint8_t **out_value, size_t *out_len) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return -1;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jbyteArray result = (jbyteArray)(*env)->CallObjectMethod(
        env, g_storage_provider, g_storage_secureGetBytes, jkey);
    (*env)->DeleteLocalRef(env, jkey);
    if (!result) { *out_value = NULL; *out_len = 0; return -1; }
    jsize len = (*env)->GetArrayLength(env, result);
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) { (*env)->DeleteLocalRef(env, result); return -1; }
    (*env)->GetByteArrayRegion(env, result, 0, len, (jbyte *)buf);
    (*env)->DeleteLocalRef(env, result);
    *out_value = buf;
    *out_len = (size_t)len;
    return 0;
}

static int jni_secure_delete(const char *key) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return -1;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jboolean ok = (*env)->CallBooleanMethod(
        env, g_storage_provider, g_storage_secureDelete, jkey);
    (*env)->DeleteLocalRef(env, jkey);
    return ok ? 0 : -1;
}

static int jni_secure_has(const char *key) {
    /* Reuse secure_get: if non-null result, key exists */
    uint8_t *val; size_t len;
    int rc = jni_secure_get(key, &val, &len);
    if (rc == 0) { free(val); return 1; }
    return 0;
}

static int jni_regular_set(const char *key, const char *value) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return -1;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jstring jval = (*env)->NewStringUTF(env, value);
    jboolean ok = (*env)->CallBooleanMethod(
        env, g_storage_provider, g_storage_regularSet, jkey, jval);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jval);
    return ok ? 0 : -1;
}

static char *jni_regular_get(const char *key) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return NULL;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jstring result = (jstring)(*env)->CallObjectMethod(
        env, g_storage_provider, g_storage_regularGet, jkey);
    (*env)->DeleteLocalRef(env, jkey);
    if (!result) return NULL;
    const char *cstr = (*env)->GetStringUTFChars(env, result, NULL);
    char *copy = strdup(cstr);
    (*env)->ReleaseStringUTFChars(env, result, cstr);
    (*env)->DeleteLocalRef(env, result);
    return copy;
}

static int jni_regular_delete(const char *key) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_storage_provider) return -1;
    jstring jkey = (*env)->NewStringUTF(env, key);
    jboolean ok = (*env)->CallBooleanMethod(
        env, g_storage_provider, g_storage_regularDelete, jkey);
    (*env)->DeleteLocalRef(env, jkey);
    return ok ? 0 : -1;
}

/* ── Net fetch callback ───────────────────────────────────────── */

static void jni_net_fetch(const char *url, const char *method,
                           const char *headers_json,
                           const uint8_t *body, size_t body_len,
                           int timeout_ms, void *context,
                           WDKFetchCallback callback) {
    JNIEnv *env = jni_get_env();
    if (!env || !g_net_provider) {
        callback(context, 0, "{}", NULL, 0, "net provider not registered");
        return;
    }

    /* Heap-allocate pending struct — freed in nativeCompleteNetRequest */
    JNIPendingNet *pending = (JNIPendingNet *)malloc(sizeof(JNIPendingNet));
    if (!pending) {
        callback(context, 0, "{}", NULL, 0, "out of memory");
        return;
    }
    pending->callback = callback;
    pending->context  = context;
    jlong pending_ptr = (jlong)(intptr_t)pending;

    jstring jurl     = (*env)->NewStringUTF(env, url);
    jstring jmethod  = (*env)->NewStringUTF(env, method ? method : "GET");
    jstring jheaders = (*env)->NewStringUTF(env, headers_json ? headers_json : "{}");

    jbyteArray jbody = NULL;
    if (body && body_len > 0) {
        jbody = (*env)->NewByteArray(env, (jsize)body_len);
        (*env)->SetByteArrayRegion(env, jbody, 0, (jsize)body_len,
                                    (const jbyte *)body);
    }

    (*env)->CallVoidMethod(env, g_net_provider, g_net_fetchJni,
                            jurl, jmethod, jheaders, jbody,
                            (jint)timeout_ms, pending_ptr);

    (*env)->DeleteLocalRef(env, jurl);
    (*env)->DeleteLocalRef(env, jmethod);
    (*env)->DeleteLocalRef(env, jheaders);
    if (jbody) (*env)->DeleteLocalRef(env, jbody);
}

/* ---------- helpers ---------- */

static inline WDKEngine *get_engine(jlong ptr) {
    return (WDKEngine *)(intptr_t)ptr;
}

/* ── JNI_OnLoad: capture JavaVM ──────────────────────────────── */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

/* ---------- JNI exports ---------- */

JNIEXPORT jlong JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeCreate(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    WDKEngine *engine = wdk_engine_create();
    return (jlong)(intptr_t)engine;
}

JNIEXPORT jint JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeLoadBytecode(JNIEnv *env, jobject thiz,
                                                    jlong ptr,
                                                    jbyteArray bytecode) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return -1;

    jsize len = (*env)->GetArrayLength(env, bytecode);
    jbyte *buf = (*env)->GetByteArrayElements(env, bytecode, NULL);
    if (!buf) return -1;

    int result = wdk_engine_load_bytecode(engine, (const uint8_t *)buf, (size_t)len);

    (*env)->ReleaseByteArrayElements(env, bytecode, buf, JNI_ABORT);
    return (jint)result;
}

JNIEXPORT jstring JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeCall(JNIEnv *env, jobject thiz,
                                            jlong ptr,
                                            jstring method,
                                            jstring jsonArgs) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return NULL;

    const char *c_method = (*env)->GetStringUTFChars(env, method, NULL);
    if (!c_method) return NULL;

    const char *c_args = (*env)->GetStringUTFChars(env, jsonArgs, NULL);
    if (!c_args) {
        (*env)->ReleaseStringUTFChars(env, method, c_method);
        return NULL;
    }

    char *result = wdk_engine_call(engine, c_method, c_args);

    (*env)->ReleaseStringUTFChars(env, method, c_method);
    (*env)->ReleaseStringUTFChars(env, jsonArgs, c_args);

    if (!result) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    wdk_free_string(result);
    return jresult;
}

JNIEXPORT jint JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeEval(JNIEnv *env, jobject thiz,
                                            jlong ptr,
                                            jstring code) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return -1;

    const char *c_code = (*env)->GetStringUTFChars(env, code, NULL);
    if (!c_code) return -1;

    /*
     * Use wdk_engine_eval to evaluate raw JS source directly via JS_Eval.
     * This is the correct way to load the bundle — globalThis.wdk does NOT
     * exist before the bundle is evaluated, so wdk_engine_call cannot be
     * used here.
     */
    int result = wdk_engine_eval(engine, c_code);

    (*env)->ReleaseStringUTFChars(env, code, c_code);
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_com_tetherto_wdk_WDKEngine_nativePump(JNIEnv *env, jobject thiz,
                                            jlong ptr) {
    (void)env;
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return -1;
    return (jint)wdk_engine_pump(engine);
}

JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeDestroy(JNIEnv *env, jobject thiz,
                                               jlong ptr) {
    (void)env;
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (engine) {
        wdk_engine_destroy(engine);
    }
}

JNIEXPORT jstring JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeGetError(JNIEnv *env, jobject thiz,
                                                jlong ptr) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return NULL;

    const char *err = wdk_engine_get_error(engine);
    if (!err) return NULL;

    return (*env)->NewStringUTF(env, err);
}

/* ── Bridge registration JNI functions ──────────────────────── */

/*
 * Register the pure-C crypto and encoding bridges.
 * No platform callbacks required.
 */
JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKEngineModule_nativeRegisterBridges(JNIEnv *env,
                                                              jobject thiz,
                                                              jlong ptr) {
    (void)env; (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return;
    JSContext *ctx = wdk_engine_get_context(engine);
    if (!ctx) return;
    wdk_register_crypto_bridge(ctx);
    wdk_register_encoding_bridge(ctx);
}

/*
 * Register the platform bridge.
 * platformProvider: instance of WDKPlatformProvider Kotlin class.
 */
JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKEngineModule_nativeRegisterPlatformBridge(JNIEnv *env,
                                                                     jobject thiz,
                                                                     jlong ptr,
                                                                     jobject platform_provider) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine || !platform_provider) return;

    /* Cache global ref to provider */
    if (g_platform_provider) (*env)->DeleteGlobalRef(env, g_platform_provider);
    g_platform_provider = (*env)->NewGlobalRef(env, platform_provider);

    /* Cache method IDs */
    jclass cls = (*env)->GetObjectClass(env, platform_provider);
    g_platform_getRandomBytes = (*env)->GetMethodID(env, cls, "getRandomBytes", "(I)[B");
    g_platform_log            = (*env)->GetMethodID(env, cls, "log", "(ILjava/lang/String;)V");
    (*env)->DeleteLocalRef(env, cls);

    /* Build and register the provider struct */
    static WDKPlatformProvider s_platform = {0};
    s_platform.os_name         = "android";
    s_platform.engine_version  = "2.0.0";
    s_platform.get_random_bytes = jni_get_random_bytes;
    s_platform.log_message      = jni_log_message;

    JSContext *ctx = wdk_engine_get_context(engine);
    if (ctx) wdk_register_platform_bridge(ctx, &s_platform);
}

/*
 * Register the storage bridge.
 * storageProvider: instance of WDKStorageProvider Kotlin class.
 */
JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKEngineModule_nativeRegisterStorageBridge(JNIEnv *env,
                                                                    jobject thiz,
                                                                    jlong ptr,
                                                                    jobject storage_provider) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine || !storage_provider) return;

    if (g_storage_provider) (*env)->DeleteGlobalRef(env, g_storage_provider);
    g_storage_provider = (*env)->NewGlobalRef(env, storage_provider);

    jclass cls = (*env)->GetObjectClass(env, storage_provider);
    g_storage_secureSetBytes = (*env)->GetMethodID(env, cls, "secureSetBytes",
                                                    "(Ljava/lang/String;[B)Z");
    g_storage_secureGetBytes = (*env)->GetMethodID(env, cls, "secureGetBytes",
                                                    "(Ljava/lang/String;)[B");
    g_storage_secureDelete   = (*env)->GetMethodID(env, cls, "secureDelete",
                                                    "(Ljava/lang/String;)Z");
    g_storage_regularSet     = (*env)->GetMethodID(env, cls, "regularSet",
                                                    "(Ljava/lang/String;Ljava/lang/String;)Z");
    g_storage_regularGet     = (*env)->GetMethodID(env, cls, "regularGet",
                                                    "(Ljava/lang/String;)Ljava/lang/String;");
    g_storage_regularDelete  = (*env)->GetMethodID(env, cls, "regularDelete",
                                                    "(Ljava/lang/String;)Z");
    (*env)->DeleteLocalRef(env, cls);

    static WDKStorageProvider s_storage = {0};
    s_storage.secure_set    = jni_secure_set;
    s_storage.secure_get    = jni_secure_get;
    s_storage.secure_delete = jni_secure_delete;
    s_storage.secure_has    = jni_secure_has;
    s_storage.regular_set   = jni_regular_set;
    s_storage.regular_get   = jni_regular_get;
    s_storage.regular_delete = jni_regular_delete;

    JSContext *ctx = wdk_engine_get_context(engine);
    if (ctx) wdk_register_storage_bridge(ctx, &s_storage);
}

/*
 * Register the network bridge.
 * netProvider: instance of WDKNetworkProvider Kotlin class.
 */
JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKEngineModule_nativeRegisterNetBridge(JNIEnv *env,
                                                               jobject thiz,
                                                               jlong ptr,
                                                               jobject net_provider) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine || !net_provider) return;

    if (g_net_provider) (*env)->DeleteGlobalRef(env, g_net_provider);
    g_net_provider = (*env)->NewGlobalRef(env, net_provider);

    jclass cls = (*env)->GetObjectClass(env, net_provider);
    /* fetchJni(url, method, headersJson, body, timeoutMs, callbackPtr) */
    g_net_fetchJni = (*env)->GetMethodID(env, cls, "fetchJni",
                                          "(Ljava/lang/String;Ljava/lang/String;"
                                          "Ljava/lang/String;[BIJ)V");
    (*env)->DeleteLocalRef(env, cls);

    static WDKNetProvider s_net = {0};
    s_net.fetch = jni_net_fetch;

    JSContext *ctx = wdk_engine_get_context(engine);
    if (ctx) wdk_register_net_bridge(ctx, &s_net);
}

/*
 * Called by WDKNetworkProvider.fetchJni() Kotlin lambda when the HTTP
 * response arrives (on OkHttp's background thread). Invokes the stored
 * WDKFetchCallback and frees the pending struct.
 *
 * callbackPtr: the JNIPendingNet* cast to Long, passed to fetchJni
 */
JNIEXPORT void JNICALL
Java_com_tetherto_wdk_WDKNetworkProvider_nativeCompleteNetRequest(JNIEnv *env,
                                                                    jobject thiz,
                                                                    jlong callback_ptr,
                                                                    jint status,
                                                                    jstring headers_json,
                                                                    jbyteArray body,
                                                                    jstring error) {
    (void)thiz;
    JNIPendingNet *pending = (JNIPendingNet *)(intptr_t)callback_ptr;
    if (!pending) return;

    const char *c_headers = headers_json
        ? (*env)->GetStringUTFChars(env, headers_json, NULL) : "{}";
    const char *c_error   = error
        ? (*env)->GetStringUTFChars(env, error, NULL) : NULL;

    jbyte  *body_bytes = NULL;
    jsize   body_len   = 0;
    if (body) {
        body_len   = (*env)->GetArrayLength(env, body);
        body_bytes = (*env)->GetByteArrayElements(env, body, NULL);
    }

    pending->callback(pending->context, (int)status,
                       c_headers,
                       (const uint8_t *)body_bytes, (size_t)body_len,
                       c_error);

    if (body_bytes) (*env)->ReleaseByteArrayElements(env, body, body_bytes, JNI_ABORT);
    if (headers_json) (*env)->ReleaseStringUTFChars(env, headers_json, c_headers);
    if (error)        (*env)->ReleaseStringUTFChars(env, error, c_error);

    free(pending);
}
