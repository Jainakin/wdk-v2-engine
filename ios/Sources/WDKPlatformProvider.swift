// WDKPlatformProvider.swift
// WDK v2 — Platform utilities bridge
//
// Provides OS-level services: cryptographic random bytes, structured logging,
// and platform identification.

import Foundation
import Security
#if canImport(os)
import os
#endif
#if canImport(WDKEngineC)
import WDKEngineC
#endif

/// Provides platform-level utilities for the WDK engine.
///
/// - Cryptographically secure random bytes via `SecRandomCopyBytes`.
/// - Structured logging via `os_log`.
/// - Platform identification.
public final class WDKPlatformProvider: Sendable {

    /// The engine version string. Update this when releasing new versions.
    public static let engineVersion = "2.0.0"

    /// The platform OS identifier.
    public static var os: String { "ios" }

    // MARK: - Random Bytes

    /// Generates cryptographically secure random bytes using the platform CSPRNG.
    ///
    /// - Parameter count: Number of random bytes to generate.
    /// - Returns: A `Data` object containing `count` random bytes.
    /// - Throws: An error if the system CSPRNG fails.
    public static func getRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw WDKPlatformError.randomBytesFailed(status: status)
        }
        return Data(bytes)
    }

    // MARK: - Logging

    /// Log levels matching the C bridge `WDK_LOG_*` constants.
    public enum LogLevel: Int32, Sendable {
        case debug = 0
        case info  = 1
        case warn  = 2
        case error = 3
    }

    /// The `os_log` logger used for WDK messages.
    private static let logger = Logger(subsystem: "com.aspect.wdk", category: "engine")

    /// Logs a message at the specified level using `os_log`.
    ///
    /// - Parameters:
    ///   - level: The log severity level.
    ///   - message: The log message.
    public static func log(level: LogLevel, message: String) {
        switch level {
        case .debug:
            logger.debug("\(message, privacy: .public)")
        case .info:
            logger.info("\(message, privacy: .public)")
        case .warn:
            logger.warning("\(message, privacy: .public)")
        case .error:
            logger.error("\(message, privacy: .public)")
        }
    }

    /// Logs a message using the raw C log level integer.
    ///
    /// - Parameters:
    ///   - level: Integer log level (0=debug, 1=info, 2=warn, 3=error).
    ///   - message: The log message.
    public static func log(level: Int32, message: String) {
        let logLevel = LogLevel(rawValue: level) ?? .info
        log(level: logLevel, message: message)
    }

    // MARK: - C Bridge Registration

    /// Creates a `WDKPlatformProvider` C struct that routes platform calls to native implementations.
    ///
    /// The returned struct can be passed to `wdk_register_platform_bridge()`.
    ///
    /// - Important: The `os_name` and `engine_version` pointers reference static string storage
    ///   that is valid for the process lifetime.
    internal static func makeCProvider() -> WDKPlatformProviderStruct {
        var provider = WDKPlatformProviderStruct()

        // Static strings — these live for the process lifetime as C string literals
        provider.os_name = UnsafePointer(strdup("ios"))
        provider.engine_version = UnsafePointer(strdup(engineVersion))

        // get_random_bytes
        provider.get_random_bytes = { (buf: UnsafeMutablePointer<UInt8>?, len: Int) -> Int32 in
            guard let buf = buf, len > 0 else { return -1 }
            let status = SecRandomCopyBytes(kSecRandomDefault, len, buf)
            return status == errSecSuccess ? 0 : -1
        }

        // log_message
        provider.log_message = { (level: Int32, messagePtr: UnsafePointer<CChar>?) in
            guard let messagePtr = messagePtr else { return }
            let message = String(cString: messagePtr)
            WDKPlatformProvider.log(level: level, message: message)
        }

        return provider
    }
}

/// Errors specific to platform operations.
public enum WDKPlatformError: Error, LocalizedError, Sendable {
    /// The system CSPRNG failed to generate random bytes.
    case randomBytesFailed(status: OSStatus)

    public var errorDescription: String? {
        switch self {
        case .randomBytesFailed(let status):
            return "SecRandomCopyBytes failed with status \(status)"
        }
    }
}

/// Type alias to disambiguate from the Swift class name.
/// Maps to the C struct `WDKPlatformProvider` from bridge.h.
internal typealias WDKPlatformProviderStruct = WDKEngineC.WDKPlatformProvider
