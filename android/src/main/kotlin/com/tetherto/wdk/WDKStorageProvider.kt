package com.tetherto.wdk

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Storage provider for the WDK engine.
 *
 * Provides two storage tiers:
 * - **Secure**: Encrypted with AES-256-GCM via AndroidX Security's
 *   [EncryptedSharedPreferences]. Suitable for keys, tokens, and secrets.
 * - **Regular**: Standard [SharedPreferences]. Suitable for non-sensitive
 *   configuration and cached data.
 *
 * Both tiers use synchronous `commit()` for writes to ensure data is
 * persisted before returning.
 *
 * Usage:
 * ```kotlin
 * val storage = WDKStorageProvider(context)
 * storage.secureSet("master_key", encodedKeyBytes)
 * val key = storage.secureGet("master_key")
 * ```
 */
class WDKStorageProvider(context: Context) {

    private val securePrefs: SharedPreferences
    private val regularPrefs: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        securePrefs = EncryptedSharedPreferences.create(
            context,
            SECURE_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        regularPrefs = context.getSharedPreferences(REGULAR_PREFS_NAME, Context.MODE_PRIVATE)
    }

    // ── Secure storage ──────────────────────────────────────────

    /**
     * Store a value in encrypted storage.
     *
     * @param key   Storage key.
     * @param value Value to store.
     * @return true if the write was committed successfully.
     */
    fun secureSet(key: String, value: String): Boolean {
        return securePrefs.edit().putString(key, value).commit()
    }

    /**
     * Retrieve a value from encrypted storage.
     *
     * @param key Storage key.
     * @return The stored value, or null if not found.
     */
    fun secureGet(key: String): String? {
        return securePrefs.getString(key, null)
    }

    /**
     * Remove a value from encrypted storage.
     *
     * @param key Storage key.
     * @return true if the removal was committed successfully.
     */
    fun secureDelete(key: String): Boolean {
        return securePrefs.edit().remove(key).commit()
    }

    /**
     * Store binary bytes in encrypted storage (base64-encoded internally).
     * Called from the JNI bridge when the C engine writes binary key material.
     */
    fun secureSetBytes(key: String, value: ByteArray): Boolean {
        val encoded = Base64.encodeToString(value, Base64.NO_WRAP)
        return securePrefs.edit().putString(key, encoded).commit()
    }

    /**
     * Retrieve binary bytes from encrypted storage.
     * Returns null if the key does not exist.
     * Called from the JNI bridge when the C engine reads binary key material.
     */
    fun secureGetBytes(key: String): ByteArray? {
        val encoded = securePrefs.getString(key, null) ?: return null
        return try {
            Base64.decode(encoded, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    // ── Regular storage ─────────────────────────────────────────

    /**
     * Store a value in regular (unencrypted) storage.
     *
     * @param key   Storage key.
     * @param value Value to store.
     * @return true if the write was committed successfully.
     */
    fun regularSet(key: String, value: String): Boolean {
        return regularPrefs.edit().putString(key, value).commit()
    }

    /**
     * Retrieve a value from regular storage.
     *
     * @param key Storage key.
     * @return The stored value, or null if not found.
     */
    fun regularGet(key: String): String? {
        return regularPrefs.getString(key, null)
    }

    /**
     * Remove a value from regular storage.
     *
     * @param key Storage key.
     * @return true if the removal was committed successfully.
     */
    fun regularDelete(key: String): Boolean {
        return regularPrefs.edit().remove(key).commit()
    }

    companion object {
        private const val SECURE_PREFS_NAME = "wdk_secure_storage"
        private const val REGULAR_PREFS_NAME = "wdk_regular_storage"
    }
}
