/*
 * WDK v2 Engine -- JNI Bridge
 *
 * Bridges the Kotlin WDKEngine class to the C wdk_engine_* API.
 * Each JNI function converts Java types, calls the C function,
 * and releases JNI resources before returning.
 */

#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include "engine.h"

/* ---------- helpers ---------- */

static inline WDKEngine *get_engine(jlong ptr) {
    return (WDKEngine *)(intptr_t)ptr;
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

JNIEXPORT jstring JNICALL
Java_com_tetherto_wdk_WDKEngine_nativeEval(JNIEnv *env, jobject thiz,
                                            jlong ptr,
                                            jstring code) {
    (void)thiz;
    WDKEngine *engine = get_engine(ptr);
    if (!engine) return NULL;

    const char *c_code = (*env)->GetStringUTFChars(env, code, NULL);
    if (!c_code) return NULL;

    /*
     * The C API does not expose a direct eval function.
     * We wrap the code in a call to a helper on the wdk object
     * that evaluates arbitrary JS via: globalThis.wdk.__eval(code)
     *
     * As a fallback when __eval is not defined, we pass the code
     * through wdk_engine_call with "__eval" as the function name
     * and the code string as the JSON argument.
     */
    /* Build a JSON string: the code wrapped in quotes for JSON.parse */
    size_t code_len = (*env)->GetStringUTFLength(env, code);
    /* Allocate enough for JSON-escaped string with quotes */
    size_t json_buf_size = code_len * 2 + 3; /* worst case: every char escaped + quotes + null */
    char *json_arg = (char *)malloc(json_buf_size);
    if (!json_arg) {
        (*env)->ReleaseStringUTFChars(env, code, c_code);
        return NULL;
    }

    /* Simple JSON string encoding */
    size_t pos = 0;
    json_arg[pos++] = '"';
    for (const char *p = c_code; *p; p++) {
        switch (*p) {
            case '"':  json_arg[pos++] = '\\'; json_arg[pos++] = '"';  break;
            case '\\': json_arg[pos++] = '\\'; json_arg[pos++] = '\\'; break;
            case '\n': json_arg[pos++] = '\\'; json_arg[pos++] = 'n';  break;
            case '\r': json_arg[pos++] = '\\'; json_arg[pos++] = 'r';  break;
            case '\t': json_arg[pos++] = '\\'; json_arg[pos++] = 't';  break;
            default:   json_arg[pos++] = *p;                           break;
        }
    }
    json_arg[pos++] = '"';
    json_arg[pos] = '\0';

    char *result = wdk_engine_call(engine, "__eval", json_arg);

    free(json_arg);
    (*env)->ReleaseStringUTFChars(env, code, c_code);

    if (!result) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    wdk_free_string(result);
    return jresult;
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
