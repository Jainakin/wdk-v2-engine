// WDKNetworkProvider.swift
// WDK v2 — Network bridge implementation using URLSession
//
// Implements the `native.net.fetch` callback for the C engine bridge.

import Foundation
#if canImport(WDKEngineC)
import WDKEngineC
#endif

/// Provides HTTP networking for the WDK engine via `URLSession`.
///
/// This class bridges the C engine's `WDKNetProvider.fetch` callback to
/// Swift's `URLSession`. Requests are executed asynchronously and results
/// are delivered back to the C engine via the provided callback pointer.
public final class WDKNetworkProvider: Sendable {

    /// Shared URLSession configured for WDK network requests.
    private static let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["User-Agent": "WDKEngine/2.0"]
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        return URLSession(configuration: config)
    }()

    // MARK: - Public API

    /// Performs an HTTP fetch request.
    ///
    /// - Parameters:
    ///   - url: The request URL string.
    ///   - method: HTTP method (GET, POST, PUT, DELETE, etc.).
    ///   - headers: Optional dictionary of HTTP headers.
    ///   - body: Optional request body data.
    ///   - timeout: Request timeout interval in seconds.
    ///   - completion: Callback with (statusCode, responseHeaders, responseBody, errorMessage).
    ///                 `errorMessage` is non-nil only on failure; `statusCode` is 0 on network error.
    public static func fetch(
        url: String,
        method: String,
        headers: [String: String]?,
        body: Data?,
        timeout: TimeInterval,
        completion: @escaping @Sendable (Int, [String: String], Data?, String?) -> Void
    ) {
        guard let requestURL = URL(string: url) else {
            completion(0, [:], nil, "Invalid URL: \(url)")
            return
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = method
        request.timeoutInterval = timeout

        if let headers = headers {
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }

        if let body = body {
            request.httpBody = body
        }

        let task = session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(0, [:], nil, error.localizedDescription)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(0, [:], nil, "Response is not an HTTP response")
                return
            }

            // Convert response headers to [String: String]
            var responseHeaders: [String: String] = [:]
            for (key, value) in httpResponse.allHeaderFields {
                if let keyStr = key as? String, let valStr = value as? String {
                    responseHeaders[keyStr] = valStr
                }
            }

            completion(httpResponse.statusCode, responseHeaders, data, nil)
        }

        task.resume()
    }

    // MARK: - C Bridge Registration

    /// Creates a `WDKNetProvider` C struct that routes fetch calls through `URLSession`.
    ///
    /// The returned struct can be passed to `wdk_register_net_bridge()`.
    /// The fetch function pointer is a C-compatible closure that unpacks the
    /// C arguments, performs the request via `URLSession`, and invokes the
    /// C callback with the response.
    internal static func makeCProvider() -> WDKNetProvider {
        var provider = WDKNetProvider()

        provider.fetch = { (
            urlPtr: UnsafePointer<CChar>?,
            methodPtr: UnsafePointer<CChar>?,
            headersJsonPtr: UnsafePointer<CChar>?,
            bodyPtr: UnsafePointer<UInt8>?,
            bodyLen: Int,
            timeoutMs: Int32,
            context: UnsafeMutableRawPointer?,
            callback: WDKFetchCallback?
        ) in
            guard let urlPtr = urlPtr,
                  let methodPtr = methodPtr,
                  let callback = callback else {
                return
            }

            let url = String(cString: urlPtr)
            let method = String(cString: methodPtr)
            let timeout = TimeInterval(timeoutMs) / 1000.0

            // Parse request headers from JSON
            var headers: [String: String]?
            if let headersJsonPtr = headersJsonPtr {
                let headersJson = String(cString: headersJsonPtr)
                if let data = headersJson.data(using: .utf8),
                   let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
                    headers = parsed
                }
            }

            // Copy request body
            var body: Data?
            if let bodyPtr = bodyPtr, bodyLen > 0 {
                body = Data(bytes: bodyPtr, count: bodyLen)
            }

            fetch(url: url, method: method, headers: headers, body: body, timeout: timeout) {
                statusCode, responseHeaders, responseData, error in

                // Serialize response headers to JSON
                let headersJsonString: String?
                if let jsonData = try? JSONSerialization.data(withJSONObject: responseHeaders),
                   let jsonStr = String(data: jsonData, encoding: .utf8) {
                    headersJsonString = jsonStr
                } else {
                    headersJsonString = nil
                }

                // Call back into the C engine
                headersJsonString?.withCString { headersCStr in
                    if let responseData = responseData {
                        responseData.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
                            let bodyBase = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            if let error = error {
                                error.withCString { errorCStr in
                                    callback(context, Int32(statusCode), headersCStr,
                                             bodyBase, rawBuffer.count, errorCStr)
                                }
                            } else {
                                callback(context, Int32(statusCode), headersCStr,
                                         bodyBase, rawBuffer.count, nil)
                            }
                        }
                    } else if let error = error {
                        error.withCString { errorCStr in
                            callback(context, Int32(statusCode), headersCStr,
                                     nil, 0, errorCStr)
                        }
                    } else {
                        callback(context, Int32(statusCode), headersCStr,
                                 nil, 0, nil)
                    }
                } ?? {
                    // No headers JSON — still need to deliver the callback
                    if let error = error {
                        error.withCString { errorCStr in
                            callback(context, Int32(statusCode), nil, nil, 0, errorCStr)
                        }
                    } else {
                        callback(context, Int32(statusCode), nil, nil, 0, nil)
                    }
                }()
            }
        }

        return provider
    }
}
