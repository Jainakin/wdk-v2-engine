package com.tetherto.wdk

import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers.Companion.toHeaders
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Network provider for the WDK engine.
 *
 * Implements HTTP fetch using OkHttp with configurable timeouts.
 * Requests are executed asynchronously on OkHttp's thread pool.
 *
 * Usage:
 * ```kotlin
 * val network = WDKNetworkProvider()
 * network.fetch(
 *     url = "https://api.example.com/data",
 *     method = "GET",
 *     headers = mapOf("Authorization" to "Bearer token"),
 *     body = null,
 *     timeout = 30
 * ) { statusCode, responseHeaders, responseBody, error ->
 *     // handle result
 * }
 * ```
 */
class WDKNetworkProvider {

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    /**
     * Execute an HTTP request asynchronously.
     *
     * @param url       Full URL to fetch.
     * @param method    HTTP method (GET, POST, PUT, DELETE, PATCH, etc.).
     * @param headers   Optional request headers.
     * @param body      Optional request body bytes.
     * @param timeout   Per-request timeout in seconds. If different from the default (30s),
     *                  a per-call client is created.
     * @param callback  Invoked on completion with status code, response headers,
     *                  response body bytes, and an optional error string.
     */
    fun fetch(
        url: String,
        method: String,
        headers: Map<String, String>?,
        body: ByteArray?,
        timeout: Int,
        callback: (statusCode: Int, headers: Map<String, String>, body: ByteArray?, error: String?) -> Unit
    ) {
        val effectiveClient = if (timeout > 0 && timeout != 30) {
            client.newBuilder()
                .connectTimeout(timeout.toLong(), TimeUnit.SECONDS)
                .readTimeout(timeout.toLong(), TimeUnit.SECONDS)
                .writeTimeout(timeout.toLong(), TimeUnit.SECONDS)
                .build()
        } else {
            client
        }

        val requestBody = if (body != null && method.uppercase() !in listOf("GET", "HEAD")) {
            val contentType = headers?.entries
                ?.firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
                ?.value
                ?.toMediaTypeOrNull()
            body.toRequestBody(contentType)
        } else {
            // Some methods (POST, PUT) require a body even if empty.
            if (method.uppercase() in listOf("POST", "PUT", "PATCH")) {
                ByteArray(0).toRequestBody(null)
            } else {
                null
            }
        }

        val requestBuilder = Request.Builder()
            .url(url)
            .method(method.uppercase(), requestBody)

        headers?.let { requestBuilder.headers(it.toHeaders()) }

        val request = requestBuilder.build()

        effectiveClient.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                callback(0, emptyMap(), null, e.message ?: "Network request failed")
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    val responseHeaders = mutableMapOf<String, String>()
                    for (name in response.headers.names()) {
                        // If multiple values exist for a header, join them.
                        responseHeaders[name] = response.headers.values(name).joinToString(", ")
                    }

                    val responseBody = response.body?.bytes()

                    callback(response.code, responseHeaders, responseBody, null)
                } catch (e: Exception) {
                    callback(0, emptyMap(), null, e.message ?: "Failed to read response")
                } finally {
                    response.close()
                }
            }
        })
    }

    /**
     * Cancel all pending requests.
     */
    fun cancelAll() {
        client.dispatcher.cancelAll()
    }
}
