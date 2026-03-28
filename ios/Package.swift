// swift-tools-version: 5.9
// Package.swift
// WDK v2 Engine — Swift Package Manager configuration

import PackageDescription

let package = Package(
    name: "WDKEngine",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "WDKEngine",
            targets: ["WDKEngine"]
        ),
    ],
    targets: [
        // MARK: - C Target
        // Wraps the entire shared-c/ tree (QuickJS, secp256k1, ed25519, hashing, encoding, BIP, bridge)
        // into a single C module that Swift can import.
        .target(
            name: "WDKEngineC",
            path: "../shared-c",
            exclude: [
                // Exclude CMake build files
                "CMakeLists.txt",
            ],
            sources: [
                // QuickJS-NG
                "vendor/quickjs-ng/quickjs.c",
                "vendor/quickjs-ng/quickjs-libc.c",
                "vendor/quickjs-ng/libregexp.c",
                "vendor/quickjs-ng/libunicode.c",
                "vendor/quickjs-ng/dtoa.c",
                // libsecp256k1
                "vendor/secp256k1/src/secp256k1.c",
                "vendor/secp256k1/src/precomputed_ecmult.c",
                "vendor/secp256k1/src/precomputed_ecmult_gen.c",
                // TweetNaCl (Ed25519)
                "vendor/ed25519/tweetnacl.c",
                "vendor/ed25519/randombytes.c",
                // Hashing
                "hashing/sha256.c",
                "hashing/sha512.c",
                "hashing/hmac.c",
                "hashing/keccak256.c",
                "hashing/ripemd160.c",
                "hashing/blake2b.c",
                // Encoding
                "encoding/hex.c",
                "encoding/base58.c",
                "encoding/base58check.c",
                "encoding/bech32.c",
                "encoding/base64.c",
                // BIP
                "bip/bip39.c",
                "bip/bip32.c",
                "bip/bip44.c",
                // Bridge + Engine
                "bridge/engine.c",
                "bridge/key_store.c",
                "bridge/bridge_crypto.c",
                "bridge/bridge_encoding.c",
            ],
            publicHeadersPath: "bridge",
            cSettings: [
                // QuickJS compile definitions
                .define("CONFIG_VERSION", to: "\"0.10.0\""),
                .define("CONFIG_BIGNUM"),
                .define("_GNU_SOURCE"),
                // secp256k1 compile definitions
                .define("SECP256K1_STATIC"),
                .define("ENABLE_MODULE_RECOVERY", to: "1"),
                .define("ENABLE_MODULE_EXTRAKEYS", to: "1"),
                .define("ENABLE_MODULE_SCHNORRSIG", to: "1"),
                .define("ENABLE_MODULE_ECDH", to: "1"),
                // Include paths for internal headers
                .headerSearchPath("."),
                .headerSearchPath("bridge"),
                .headerSearchPath("hashing"),
                .headerSearchPath("encoding"),
                .headerSearchPath("bip"),
                .headerSearchPath("vendor/quickjs-ng"),
                .headerSearchPath("vendor/secp256k1/include"),
                .headerSearchPath("vendor/secp256k1/src"),
                .headerSearchPath("vendor/secp256k1"),
                .headerSearchPath("vendor/ed25519"),
                // Suppress warnings in vendored code
                .unsafeFlags([
                    "-Wno-sign-compare",
                    "-Wno-unused-parameter",
                    "-Wno-missing-field-initializers",
                    "-Wno-implicit-fallthrough",
                    "-Wno-unused-function",
                ]),
            ]
        ),

        // MARK: - Swift Target
        .target(
            name: "WDKEngine",
            dependencies: ["WDKEngineC"],
            path: "Sources"
        ),
    ]
)
