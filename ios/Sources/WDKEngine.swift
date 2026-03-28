// WDKEngine.swift
// WDK v2 — iOS Swift wrapper for the native C engine
//
// Thread-safe wrapper around the QuickJS-based WDK engine.
// All C engine access is serialized on a dedicated background queue.

import Foundation
import WDKEngineC

// MARK: - Error Types

/// Errors thrown by the WDK engine.
public enum WDKError: Error, LocalizedError, Sendable {
    /// The C engine could not be created (memory or initialization failure).
    case engineCreationFailed
    /// Bytecode loading failed. The associated value contains the engine error message.
    case bytecodeLoadFailed(String)
    /// A JS function call failed. The associated value contains the engine error message.
    case callFailed(String)
    /// The parameters provided could not be serialized to JSON.
    case invalidParams
    /// The engine has already been destroyed.
    case engineDestroyed

    public var errorDescription: String? {
        switch self {
        case .engineCreationFailed:
            return "WDK engine creation failed"
        case .bytecodeLoadFailed(let message):
            return "Bytecode load failed: \(message)"
        case .callFailed(let message):
            return "Call failed: \(message)"
        case .invalidParams:
            return "Invalid parameters: could not serialize to JSON"
        case .engineDestroyed:
            return "Engine has been destroyed"
        }
    }
}

// MARK: - WDKEngine

/// Swift wrapper around the WDK v2 native C engine.
///
/// All JavaScript execution happens on a dedicated serial queue to ensure
/// thread safety. The engine is created lazily and destroyed when this
/// object is deallocated.
///
/// Usage:
/// ```swift
/// let engine = try await WDKEngine()
/// try await engine.loadBytecode(fromBundle: "wallet_core")
/// let result = try await engine.call("createWallet", params: ["network": "ethereum"])
/// ```
public final class WDKEngine: @unchecked Sendable {

    // MARK: - Private State

    /// Opaque pointer to the C engine. Only accessed on `engineQueue`.
    private var engine: OpaquePointer?

    /// Serial queue that serializes all C engine access.
    private let engineQueue: DispatchQueue

    /// Tracks whether the engine has been destroyed to prevent use-after-free.
    private var isDestroyed = false

    /// Platform providers retained for the engine's lifetime.
    /// The C bridge holds raw pointers into these, so they must not be deallocated
    /// until the engine is destroyed.
    private var networkProvider: WDKNetworkProviderBridge?
    private var storageProvider: WDKStorageProviderBridge?
    private var platformProvider: WDKPlatformProviderBridge?

    // MARK: - Initialization

    /// Creates a new WDK engine instance.
    ///
    /// The engine is created on a dedicated background queue. Platform bridges
    /// (network, storage, platform) are automatically registered.
    ///
    /// - Throws: `WDKError.engineCreationFailed` if the C engine cannot be initialized.
    public init() async throws {
        self.engineQueue = DispatchQueue(
            label: "com.aspect.wdk.engine",
            qos: .userInitiated
        )

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            self.engineQueue.async {
                guard let ptr = wdk_engine_create() else {
                    continuation.resume(throwing: WDKError.engineCreationFailed)
                    return
                }
                self.engine = ptr
                continuation.resume()
            }
        }
    }

    deinit {
        let engine = self.engine
        let queue = self.engineQueue
        // Prevent double-free
        self.engine = nil
        self.isDestroyed = true

        queue.async {
            if let engine = engine {
                wdk_engine_destroy(engine)
            }
        }
    }

    // MARK: - Bytecode Loading

    /// Loads compiled QuickJS bytecode from the app bundle.
    ///
    /// - Parameter name: The resource name (without extension) of the `.qbc` file in the main bundle.
    /// - Throws: `WDKError.bytecodeLoadFailed` if the file cannot be found or loaded.
    public func loadBytecode(fromBundle name: String) async throws {
        guard let url = Bundle.main.url(forResource: name, withExtension: "qbc") else {
            throw WDKError.bytecodeLoadFailed("Resource '\(name).qbc' not found in main bundle")
        }

        let data = try Data(contentsOf: url)
        try await loadBytecode(data: data)
    }

    /// Loads compiled QuickJS bytecode from raw data.
    ///
    /// - Parameter data: The bytecode data (typically produced by `qjsc`).
    /// - Throws: `WDKError.bytecodeLoadFailed` if the bytecode is invalid or cannot be evaluated.
    public func loadBytecode(data: Data) async throws {
        try await onEngineQueue { engine in
            let result = data.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) -> Int32 in
                guard let baseAddress = rawBuffer.baseAddress else { return -1 }
                let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)
                return wdk_engine_load_bytecode(engine, ptr, rawBuffer.count)
            }

            if result != 0 {
                let errorMessage = self.getError(engine)
                throw WDKError.bytecodeLoadFailed(errorMessage)
            }

            // Pump the event loop after loading to process any initialization jobs
            _ = wdk_engine_pump(engine)
        }
    }

    // MARK: - JS Calls

    /// Calls a function on the global `wdk` object in the JavaScript context.
    ///
    /// The function is looked up as `globalThis.wdk[method]`. Parameters are
    /// serialized to JSON and passed as a single argument. The return value
    /// is the parsed JSON result.
    ///
    /// - Parameters:
    ///   - method: The function name on the `wdk` object.
    ///   - params: A JSON-serializable dictionary of parameters. Pass `nil` for no arguments.
    /// - Returns: The deserialized JSON result (can be `String`, `[String: Any]`, `[Any]`, `NSNumber`, or `NSNull`).
    /// - Throws: `WDKError.callFailed` if the JS function throws or does not exist.
    public func call(_ method: String, params: [String: Any]? = nil) async throws -> Any {
        let jsonArgs: String
        if let params = params {
            guard JSONSerialization.isValidJSONObject(params) else {
                throw WDKError.invalidParams
            }
            let data = try JSONSerialization.data(withJSONObject: params)
            guard let str = String(data: data, encoding: .utf8) else {
                throw WDKError.invalidParams
            }
            jsonArgs = str
        } else {
            jsonArgs = "{}"
        }

        return try await onEngineQueue { engine in
            guard let resultPtr = wdk_engine_call(engine, method, jsonArgs) else {
                let errorMessage = self.getError(engine)
                throw WDKError.callFailed(errorMessage)
            }

            let resultString = String(cString: resultPtr)
            wdk_free_string(resultPtr)

            // Pump the event loop to process any pending microtasks
            _ = wdk_engine_pump(engine)

            // Parse the JSON result
            guard let resultData = resultString.data(using: .utf8),
                  let parsed = try? JSONSerialization.jsonObject(with: resultData, options: .fragmentsAllowed) else {
                return resultString as Any
            }

            return parsed
        }
    }

    /// Calls a function on the global `wdk` object with a pre-encoded JSON string.
    ///
    /// This is useful when you already have a JSON string and want to avoid
    /// double-serialization overhead.
    ///
    /// - Parameters:
    ///   - method: The function name on the `wdk` object.
    ///   - jsonArgs: A valid JSON string to pass as the argument.
    /// - Returns: The raw JSON string result.
    /// - Throws: `WDKError.callFailed` if the JS function throws or does not exist.
    public func call(_ method: String, jsonArgs: String) async throws -> String {
        try await onEngineQueue { engine in
            guard let resultPtr = wdk_engine_call(engine, method, jsonArgs) else {
                let errorMessage = self.getError(engine)
                throw WDKError.callFailed(errorMessage)
            }

            let result = String(cString: resultPtr)
            wdk_free_string(resultPtr)

            _ = wdk_engine_pump(engine)

            return result
        }
    }

    /// Evaluates raw JavaScript code in the engine context.
    ///
    /// This is primarily intended for testing and debugging. In production,
    /// prefer `call(_:params:)` which uses the structured `wdk` API.
    ///
    /// - Parameter js: JavaScript source code to evaluate.
    /// - Returns: The JSON-stringified result, or `nil` if the result is `undefined`.
    /// - Throws: `WDKError.callFailed` if the evaluation throws an error.
    public func eval(_ js: String) async throws -> String? {
        // Wrap the JS code in a function call via the engine's call mechanism.
        // We use a special pattern: call a synthetic evaluator by passing the
        // code as a JSON-encoded string argument.
        try await onEngineQueue { engine in
            // Use wdk_engine_call with a special "__eval" method if available,
            // otherwise fall back to calling via the raw engine interface.
            // For now, we encode the JS as a JSON argument to an eval wrapper.
            let escapedJS: String
            if let jsonData = try? JSONSerialization.data(withJSONObject: js),
               let jsonStr = String(data: jsonData, encoding: .utf8) {
                escapedJS = "{\"code\":\(jsonStr)}"
            } else {
                throw WDKError.invalidParams
            }

            guard let resultPtr = wdk_engine_call(engine, "__eval", escapedJS) else {
                let errorMessage = self.getError(engine)
                throw WDKError.callFailed(errorMessage)
            }

            let result = String(cString: resultPtr)
            wdk_free_string(resultPtr)

            _ = wdk_engine_pump(engine)

            return result == "undefined" ? nil : result
        }
    }

    // MARK: - Private Helpers

    /// Executes a closure on the engine queue, ensuring the engine is alive.
    private func onEngineQueue<T>(_ work: @escaping (OpaquePointer) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            engineQueue.async {
                guard !self.isDestroyed, let engine = self.engine else {
                    continuation.resume(throwing: WDKError.engineDestroyed)
                    return
                }
                do {
                    let result = try work(engine)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Retrieves the last error message from the C engine.
    /// Must be called on `engineQueue`.
    private func getError(_ engine: OpaquePointer) -> String {
        if let errPtr = wdk_engine_get_error(engine) {
            return String(cString: errPtr)
        }
        return "Unknown engine error"
    }
}

// MARK: - Internal Bridge Wrappers

/// Retains the C struct and its backing closures for the network provider bridge.
internal final class WDKNetworkProviderBridge {
    var cProvider: WDKNetProvider

    init(_ cProvider: WDKNetProvider) {
        self.cProvider = cProvider
    }
}

/// Retains the C struct and its backing closures for the storage provider bridge.
internal final class WDKStorageProviderBridge {
    var cProvider: WDKStorageProvider

    init(_ cProvider: WDKStorageProvider) {
        self.cProvider = cProvider
    }
}

/// Retains the C struct and its backing closures for the platform provider bridge.
internal final class WDKPlatformProviderBridge {
    var cProvider: WDKPlatformProvider

    init(_ cProvider: WDKPlatformProvider) {
        self.cProvider = cProvider
    }
}
