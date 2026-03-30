/*
 * WDK v2 Native Engine — Key Store Implementation
 *
 * Provides an opaque handle table for cryptographic key material with
 * secure zeroing on release. Thread safety is NOT provided; the caller
 * must serialize access if needed.
 */

#include "bridge.h"  /* includes key_store.h + secure_zero() */

/* ---------- internal data ------------------------------------------------- */

typedef struct {
    uint8_t bytes[WDK_KEY_STORE_MAX_BYTES];
    size_t  key_len;
    int     curve;
    int     active;
} wdk_key_entry_t;

static wdk_key_entry_t g_key_table[WDK_KEY_STORE_MAX_KEYS];

/* ---------- public API ---------------------------------------------------- */

void wdk_key_store_init(void)
{
    secure_zero(g_key_table, sizeof(g_key_table));
}

int32_t wdk_key_store_add(const uint8_t *bytes, size_t len, int curve)
{
    if (!bytes || len == 0 || len > WDK_KEY_STORE_MAX_BYTES) {
        return -1;
    }

    if (curve != WDK_CURVE_SECP256K1 && curve != WDK_CURVE_ED25519) {
        return -1;
    }

    for (int i = 0; i < WDK_KEY_STORE_MAX_KEYS; i++) {
        if (!g_key_table[i].active) {
            memcpy(g_key_table[i].bytes, bytes, len);
            g_key_table[i].key_len = len;
            g_key_table[i].curve   = curve;
            g_key_table[i].active  = 1;
            return (int32_t)i;
        }
    }

    return -1; /* table full */
}

const uint8_t *wdk_key_store_get(int32_t handle, size_t *out_len, int *out_curve)
{
    if (handle < 0 || handle >= WDK_KEY_STORE_MAX_KEYS) {
        return NULL;
    }

    wdk_key_entry_t *e = &g_key_table[handle];
    if (!e->active) {
        return NULL;
    }

    if (out_len)   *out_len   = e->key_len;
    if (out_curve)  *out_curve = e->curve;

    return e->bytes;
}

void wdk_key_store_release(int32_t handle)
{
    if (handle < 0 || handle >= WDK_KEY_STORE_MAX_KEYS) {
        return;
    }

    wdk_key_entry_t *e = &g_key_table[handle];
    if (e->active) {
        secure_zero(e->bytes, WDK_KEY_STORE_MAX_BYTES);
        e->key_len = 0;
        e->curve   = 0;
        e->active  = 0;
    }
}

int wdk_key_store_is_valid(int32_t handle)
{
    if (handle < 0 || handle >= WDK_KEY_STORE_MAX_KEYS) {
        return 0;
    }
    return g_key_table[handle].active ? 1 : 0;
}

void wdk_key_store_destroy(void)
{
    for (int i = 0; i < WDK_KEY_STORE_MAX_KEYS; i++) {
        if (g_key_table[i].active) {
            secure_zero(g_key_table[i].bytes, WDK_KEY_STORE_MAX_BYTES);
        }
    }
    secure_zero(g_key_table, sizeof(g_key_table));
}

int wdk_key_store_count(void)
{
    int count = 0;
    for (int i = 0; i < WDK_KEY_STORE_MAX_KEYS; i++) {
        if (g_key_table[i].active) {
            count++;
        }
    }
    return count;
}
