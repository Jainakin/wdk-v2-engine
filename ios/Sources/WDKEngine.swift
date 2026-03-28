// WDKEngine.swift
// WDK v2 — iOS Swift wrapper for the native C engine
//
// Thread-safe wrapper around the QuickJS-based WDK engine.
// All C engine access is serialized on a dedicated background queue.
// Platform bridges (net, storage, platform) are wired to real iOS APIs.

import Foundation
import Security

// MARK: - Error Types

public enum WDKError: Error, LocalizedError, Sendable {
    case engineCreationFailed
    case bytecodeLoadFailed(String)
    case callFailed(String)
    case invalidParams
    case engineDestroyed

    public var errorDescription: String? {
        switch self {
        case .engineCreationFailed: return "WDK engine creation failed"
        case .bytecodeLoadFailed(let msg): return "Bytecode load failed: \(msg)"
        case .callFailed(let msg): return "Call failed: \(msg)"
        case .invalidParams: return "Invalid parameters"
        case .engineDestroyed: return "Engine has been destroyed"
        }
    }
}

// MARK: - WDKEngine

public final class WDKEngine: @unchecked Sendable {

    private var engine: OpaquePointer?
    private let engineQueue: DispatchQueue
    private var isDestroyed = false

    // Keep static strings alive for the C provider struct
    private static let osNameCStr = strdup("ios")!
    private static let versionCStr = strdup("0.1.0")!

    public init() async throws {
        self.engineQueue = DispatchQueue(
            label: "com.tetherto.wdk.engine",
            qos: .userInitiated
        )

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.engineQueue.async {
                guard let ptr = wdk_engine_create() else {
                    cont.resume(throwing: WDKError.engineCreationFailed)
                    return
                }
                self.engine = ptr

                // Register platform bridges with real iOS implementations
                let ctx = wdk_engine_get_context(ptr)

                // Platform bridge (os, random, log)
                var platformProvider = WDKPlatformProvider(
                    os_name: WDKEngine.osNameCStr,
                    engine_version: WDKEngine.versionCStr,
                    get_random_bytes: iosGetRandomBytes,
                    log_message: iosLogMessage
                )
                wdk_register_platform_bridge(ctx, &platformProvider)

                // Storage bridge (Keychain + UserDefaults)
                var storageProvider = WDKStorageProvider(
                    secure_set: iosSecureSet,
                    secure_get: iosSecureGet,
                    secure_delete: iosSecureDelete,
                    secure_has: iosSecureHas,
                    regular_set: iosRegularSet,
                    regular_get: iosRegularGet,
                    regular_delete: iosRegularDelete
                )
                wdk_register_storage_bridge(ctx, &storageProvider)

                // Network bridge (URLSession)
                var netProvider = WDKNetProvider(
                    fetch: iosFetch
                )
                wdk_register_net_bridge(ctx, &netProvider)

                cont.resume()
            }
        }
    }

    deinit {
        let engine = self.engine
        let queue = self.engineQueue
        self.engine = nil
        self.isDestroyed = true
        queue.async {
            if let engine = engine { wdk_engine_destroy(engine) }
        }
    }

    // MARK: - Public API

    public func loadBytecode(fromBundle name: String) async throws {
        guard let url = Bundle.main.url(forResource: name, withExtension: "qbc") else {
            throw WDKError.bytecodeLoadFailed("Resource '\(name).qbc' not found")
        }
        try await loadBytecode(data: Data(contentsOf: url))
    }

    public func loadBytecode(data: Data) async throws {
        try await onEngineQueue { engine in
            let result = data.withUnsafeBytes { buf -> Int32 in
                guard let base = buf.baseAddress else { return -1 }
                return wdk_engine_load_bytecode(engine, base.assumingMemoryBound(to: UInt8.self), buf.count)
            }
            if result != 0 {
                throw WDKError.bytecodeLoadFailed(self.getError(engine))
            }
            _ = wdk_engine_pump(engine)
        }
    }

    public func loadJS(source: String) async throws {
        try await onEngineQueue { engine in
            let result = wdk_engine_eval(engine, source)
            if result != 0 {
                throw WDKError.bytecodeLoadFailed(self.getError(engine))
            }
        }
    }

    public func call(_ method: String, params: [String: Any]? = nil) async throws -> Any {
        let jsonArgs: String
        if let params = params {
            guard JSONSerialization.isValidJSONObject(params) else { throw WDKError.invalidParams }
            jsonArgs = String(data: try JSONSerialization.data(withJSONObject: params), encoding: .utf8) ?? "{}"
        } else {
            jsonArgs = "{}"
        }

        return try await onEngineQueue { engine in
            guard let resultPtr = wdk_engine_call(engine, method, jsonArgs) else {
                throw WDKError.callFailed(self.getError(engine))
            }
            let resultString = String(cString: resultPtr)
            wdk_free_string(resultPtr)
            _ = wdk_engine_pump(engine)

            if let data = resultString.data(using: .utf8),
               let parsed = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) {
                return parsed
            }
            return resultString as Any
        }
    }

    public func evalString(_ js: String) async throws -> String? {
        try await onEngineQueue { engine in
            guard let resultPtr = wdk_engine_eval_string(engine, js) else {
                return nil
            }
            let result = String(cString: resultPtr)
            wdk_free_string(resultPtr)
            return result
        }
    }

    // MARK: - Private Helpers

    private func onEngineQueue<T>(_ work: @escaping (OpaquePointer) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            engineQueue.async {
                guard !self.isDestroyed, let engine = self.engine else {
                    cont.resume(throwing: WDKError.engineDestroyed); return
                }
                do { cont.resume(returning: try work(engine)) }
                catch { cont.resume(throwing: error) }
            }
        }
    }

    private func getError(_ engine: OpaquePointer) -> String {
        if let p = wdk_engine_get_error(engine) { return String(cString: p) }
        return "Unknown error"
    }
}

// ════════════════════════════════════════════════════════════════════
// MARK: - Platform Bridge: Random + Log
// ════════════════════════════════════════════════════════════════════

private func iosGetRandomBytes(_ buf: UnsafeMutablePointer<UInt8>?, _ len: Int) -> Int32 {
    guard let buf = buf, len > 0 else { return -1 }
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess ? 0 : -1
}

private func iosLogMessage(_ level: Int32, _ message: UnsafePointer<CChar>?) {
    guard let message = message else { return }
    let msg = String(cString: message)
    switch level {
    case 0: print("[WDK DEBUG] \(msg)")
    case 1: print("[WDK INFO] \(msg)")
    case 2: print("[WDK WARN] \(msg)")
    case 3: print("[WDK ERROR] \(msg)")
    default: print("[WDK] \(msg)")
    }
}

// ════════════════════════════════════════════════════════════════════
// MARK: - Storage Bridge: Keychain (secure) + UserDefaults (regular)
// ════════════════════════════════════════════════════════════════════

private let keychainService = "com.tetherto.wdk"
private let defaultsSuite = "com.tetherto.wdk.storage"

// -- Secure: Keychain --

private func iosSecureSet(_ key: UnsafePointer<CChar>?, _ value: UnsafePointer<UInt8>?, _ valueLen: Int) -> Int32 {
    guard let key = key, let value = value, valueLen > 0 else { return -1 }
    let keyStr = String(cString: key)
    let data = Data(bytes: value, count: valueLen)

    // Delete existing first
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keyStr,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Add new
    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keyStr,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    return status == errSecSuccess ? 0 : -1
}

private func iosSecureGet(_ key: UnsafePointer<CChar>?,
                           _ outValue: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                           _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let key = key, let outValue = outValue, let outLen = outLen else { return -1 }
    let keyStr = String(cString: key)

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keyStr,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: buf, count: data.count)
        outValue.pointee = buf
        outLen.pointee = data.count
        return 0
    }

    outValue.pointee = nil
    outLen.pointee = 0
    return -1
}

private func iosSecureDelete(_ key: UnsafePointer<CChar>?) -> Int32 {
    guard let key = key else { return -1 }
    let keyStr = String(cString: key)

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keyStr,
    ]
    let status = SecItemDelete(query as CFDictionary)
    return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : -1
}

private func iosSecureHas(_ key: UnsafePointer<CChar>?) -> Int32 {
    guard let key = key else { return 0 }
    let keyStr = String(cString: key)

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keyStr,
        kSecReturnData as String: false,
    ]
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess ? 1 : 0
}

// -- Regular: UserDefaults --

private func iosRegularSet(_ key: UnsafePointer<CChar>?, _ value: UnsafePointer<CChar>?) -> Int32 {
    guard let key = key, let value = value else { return -1 }
    let defaults = UserDefaults(suiteName: defaultsSuite) ?? UserDefaults.standard
    defaults.set(String(cString: value), forKey: String(cString: key))
    return defaults.synchronize() ? 0 : -1
}

private func iosRegularGet(_ key: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let key = key else { return nil }
    let defaults = UserDefaults(suiteName: defaultsSuite) ?? UserDefaults.standard
    guard let value = defaults.string(forKey: String(cString: key)) else { return nil }
    return strdup(value)
}

private func iosRegularDelete(_ key: UnsafePointer<CChar>?) -> Int32 {
    guard let key = key else { return -1 }
    let defaults = UserDefaults(suiteName: defaultsSuite) ?? UserDefaults.standard
    defaults.removeObject(forKey: String(cString: key))
    return 0
}

// ════════════════════════════════════════════════════════════════════
// MARK: - Network Bridge: URLSession
// ════════════════════════════════════════════════════════════════════

private func iosFetch(
    _ url: UnsafePointer<CChar>?,
    _ method: UnsafePointer<CChar>?,
    _ headersJson: UnsafePointer<CChar>?,
    _ body: UnsafePointer<UInt8>?,
    _ bodyLen: Int,
    _ timeoutMs: Int32,
    _ context: UnsafeMutableRawPointer?,
    _ callback: (@convention(c) (UnsafeMutableRawPointer?, Int32,
                                  UnsafePointer<CChar>?,
                                  UnsafePointer<UInt8>?, Int,
                                  UnsafePointer<CChar>?) -> Void)?
) {
    guard let url = url, let callback = callback else {
        callback?(context, 0, nil, nil, 0, "Invalid parameters")
        return
    }

    let urlStr = String(cString: url)
    let methodStr = method != nil ? String(cString: method!) : "GET"

    guard let requestURL = URL(string: urlStr) else {
        callback(context, 0, nil, nil, 0, "Invalid URL")
        return
    }

    var request = URLRequest(url: requestURL)
    request.httpMethod = methodStr
    request.timeoutInterval = timeoutMs > 0 ? TimeInterval(timeoutMs) / 1000.0 : 30.0

    // Parse headers
    if let headersJson = headersJson {
        let headersStr = String(cString: headersJson)
        if let data = headersStr.data(using: .utf8),
           let headers = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
    }

    // Set body
    if let body = body, bodyLen > 0 {
        request.httpBody = Data(bytes: body, count: bodyLen)
    }

    // Perform async request
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        if let error = error {
            let errStr = error.localizedDescription
            errStr.withCString { errCStr in
                callback(context, 0, nil, nil, 0, errCStr)
            }
            return
        }

        let httpResponse = response as? HTTPURLResponse
        let statusCode = Int32(httpResponse?.statusCode ?? 0)

        // Serialize response headers as JSON
        var headersDict: [String: String] = [:]
        if let allHeaders = httpResponse?.allHeaderFields {
            for (key, value) in allHeaders {
                headersDict["\(key)"] = "\(value)"
            }
        }
        let headersJsonStr = (try? JSONSerialization.data(withJSONObject: headersDict))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

        let bodyData = data ?? Data()

        headersJsonStr.withCString { headersCStr in
            bodyData.withUnsafeBytes { bodyBuf in
                let bodyPtr = bodyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                callback(context, statusCode, headersCStr, bodyPtr, bodyData.count, nil)
            }
        }
    }
    task.resume()
}
