// WDKStorageProvider.swift
// WDK v2 — Storage bridge implementation
//
// Secure storage via iOS Keychain (kSecClassGenericPassword).
// Regular storage via UserDefaults.

import Foundation
import Security
#if canImport(WDKEngineC)
import WDKEngineC
#endif

/// Provides persistent storage for the WDK engine.
///
/// Two tiers of storage:
/// - **Secure**: Hardware-backed iOS Keychain, used for cryptographic keys and secrets.
/// - **Regular**: `UserDefaults`-backed, used for non-sensitive preferences and cached data.
public final class WDKStorageProvider: Sendable {

    /// Keychain service identifier used to namespace WDK entries.
    private static let keychainService = "com.aspect.wdk.secure"

    /// UserDefaults suite used to namespace WDK entries.
    private static let defaults = UserDefaults(suiteName: "com.aspect.wdk.storage")!

    // MARK: - Secure Storage (Keychain)

    /// Stores a value in the iOS Keychain.
    ///
    /// - Parameters:
    ///   - key: The storage key.
    ///   - value: The data to store.
    /// - Returns: `true` on success, `false` on failure.
    @discardableResult
    public static func secureSet(key: String, value: Data) -> Bool {
        // Delete any existing item first to avoid errSecDuplicateItem
        secureDelete(key: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Retrieves a value from the iOS Keychain.
    ///
    /// - Parameter key: The storage key.
    /// - Returns: The stored data, or `nil` if not found or on error.
    public static func secureGet(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            return nil
        }

        return result as? Data
    }

    /// Deletes a value from the iOS Keychain.
    ///
    /// - Parameter key: The storage key.
    /// - Returns: `true` if the item was deleted or did not exist, `false` on error.
    @discardableResult
    public static func secureDelete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Checks whether a key exists in the iOS Keychain.
    ///
    /// - Parameter key: The storage key.
    /// - Returns: `true` if the key exists, `false` otherwise.
    public static func secureHas(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    // MARK: - Regular Storage (UserDefaults)

    /// Stores a string value in UserDefaults.
    ///
    /// - Parameters:
    ///   - key: The storage key.
    ///   - value: The string value to store.
    /// - Returns: `true` on success.
    @discardableResult
    public static func regularSet(key: String, value: String) -> Bool {
        defaults.set(value, forKey: key)
        return true
    }

    /// Retrieves a string value from UserDefaults.
    ///
    /// - Parameter key: The storage key.
    /// - Returns: The stored string, or `nil` if not found.
    public static func regularGet(key: String) -> String? {
        return defaults.string(forKey: key)
    }

    /// Deletes a value from UserDefaults.
    ///
    /// - Parameter key: The storage key.
    /// - Returns: `true` on success.
    @discardableResult
    public static func regularDelete(key: String) -> Bool {
        defaults.removeObject(forKey: key)
        return true
    }

    // MARK: - C Bridge Registration

    /// Creates a `WDKStorageProvider` C struct that routes storage calls to Keychain / UserDefaults.
    ///
    /// The returned struct can be passed to `wdk_register_storage_bridge()`.
    internal static func makeCProvider() -> WDKStorageProviderStruct {
        var provider = WDKStorageProviderStruct()

        // secure_set
        provider.secure_set = { (keyPtr, valuePtr, valueLen) -> Int32 in
            guard let keyPtr = keyPtr else { return -1 }
            let key = String(cString: keyPtr)
            let value: Data
            if let valuePtr = valuePtr, valueLen > 0 {
                value = Data(bytes: valuePtr, count: valueLen)
            } else {
                value = Data()
            }
            return WDKStorageProvider.secureSet(key: key, value: value) ? 0 : -1
        }

        // secure_get
        provider.secure_get = { (keyPtr, outValuePtr, outLenPtr) -> Int32 in
            guard let keyPtr = keyPtr,
                  let outValuePtr = outValuePtr,
                  let outLenPtr = outLenPtr else { return -1 }

            let key = String(cString: keyPtr)
            guard let data = WDKStorageProvider.secureGet(key: key) else {
                outValuePtr.pointee = nil
                outLenPtr.pointee = 0
                return -1
            }

            // Allocate a buffer for the caller (C bridge will free it)
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
            data.copyBytes(to: buf, count: data.count)
            outValuePtr.pointee = buf
            outLenPtr.pointee = data.count
            return 0
        }

        // secure_delete
        provider.secure_delete = { (keyPtr) -> Int32 in
            guard let keyPtr = keyPtr else { return -1 }
            let key = String(cString: keyPtr)
            return WDKStorageProvider.secureDelete(key: key) ? 0 : -1
        }

        // secure_has
        provider.secure_has = { (keyPtr) -> Int32 in
            guard let keyPtr = keyPtr else { return -1 }
            let key = String(cString: keyPtr)
            return WDKStorageProvider.secureHas(key: key) ? 1 : 0
        }

        // regular_set
        provider.regular_set = { (keyPtr, valuePtr) -> Int32 in
            guard let keyPtr = keyPtr,
                  let valuePtr = valuePtr else { return -1 }
            let key = String(cString: keyPtr)
            let value = String(cString: valuePtr)
            return WDKStorageProvider.regularSet(key: key, value: value) ? 0 : -1
        }

        // regular_get
        provider.regular_get = { (keyPtr) -> UnsafeMutablePointer<CChar>? in
            guard let keyPtr = keyPtr else { return nil }
            let key = String(cString: keyPtr)
            guard let value = WDKStorageProvider.regularGet(key: key) else {
                return nil
            }
            // Allocate a C string for the caller (C bridge will free it)
            return strdup(value)
        }

        // regular_delete
        provider.regular_delete = { (keyPtr) -> Int32 in
            guard let keyPtr = keyPtr else { return -1 }
            let key = String(cString: keyPtr)
            return WDKStorageProvider.regularDelete(key: key) ? 0 : -1
        }

        return provider
    }
}

/// Type alias to disambiguate from the Swift class name.
/// Maps to the C struct `WDKStorageProvider` from bridge.h.
internal typealias WDKStorageProviderStruct = WDKEngineC.WDKStorageProvider
