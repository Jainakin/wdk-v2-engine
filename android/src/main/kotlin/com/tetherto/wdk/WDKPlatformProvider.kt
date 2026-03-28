package com.tetherto.wdk

import android.util.Log
import java.security.SecureRandom

/**
 * Platform utilities for the WDK engine on Android.
 *
 * Provides cryptographically secure random bytes, structured logging,
 * and platform identification.
 */
class WDKPlatformProvider {

    private val secureRandom = SecureRandom()

    /**
     * The platform identifier string.
     */
    val os: String = "android"

    /**
     * Generate cryptographically secure random bytes.
     *
     * Uses [SecureRandom], which on Android is backed by `/dev/urandom`
     * and the Linux kernel CSPRNG.
     *
     * @param count Number of random bytes to generate.
     * @return Byte array of the requested size.
     * @throws IllegalArgumentException if [count] is negative.
     */
    fun getRandomBytes(count: Int): ByteArray {
        require(count >= 0) { "Byte count must be non-negative, got $count" }
        val bytes = ByteArray(count)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * Log a message using Android's [Log] facility.
     *
     * Log levels map to Android levels:
     * - 0: VERBOSE
     * - 1: DEBUG
     * - 2: INFO
     * - 3: WARN
     * - 4: ERROR
     * - 5+: ASSERT (WTF)
     *
     * @param level Severity level (0-5).
     * @param message Log message.
     */
    fun log(level: Int, message: String) {
        when (level) {
            0 -> Log.v(TAG, message)
            1 -> Log.d(TAG, message)
            2 -> Log.i(TAG, message)
            3 -> Log.w(TAG, message)
            4 -> Log.e(TAG, message)
            else -> Log.wtf(TAG, message)
        }
    }

    companion object {
        private const val TAG = "WDK"
    }
}
