cmake_minimum_required(VERSION 3.20)
project(wdk_engine C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic)

# ─── QuickJS-NG ──────────────────────────────────────────────
add_library(quickjs STATIC
    vendor/quickjs-ng/quickjs.c
    vendor/quickjs-ng/quickjs-libc.c
    vendor/quickjs-ng/libregexp.c
    vendor/quickjs-ng/libunicode.c
    vendor/quickjs-ng/dtoa.c
)
target_include_directories(quickjs PUBLIC vendor/quickjs-ng)
target_compile_definitions(quickjs PRIVATE
    CONFIG_VERSION="0.10.0"
    CONFIG_BIGNUM
    _GNU_SOURCE
)
# QuickJS generates some warnings we can't fix in vendored code
target_compile_options(quickjs PRIVATE -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers -Wno-implicit-fallthrough)

# ─── libsecp256k1 ────────────────────────────────────────────
# Build secp256k1 as a static library from source
add_library(secp256k1 STATIC
    vendor/secp256k1/src/secp256k1.c
    vendor/secp256k1/src/precomputed_ecmult.c
    vendor/secp256k1/src/precomputed_ecmult_gen.c
)
target_include_directories(secp256k1 PUBLIC vendor/secp256k1/include)
target_include_directories(secp256k1 PRIVATE vendor/secp256k1/src vendor/secp256k1)
target_compile_definitions(secp256k1 PRIVATE
    SECP256K1_STATIC
    ENABLE_MODULE_RECOVERY=1
    ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_ECDH=1
)
target_compile_options(secp256k1 PRIVATE -Wno-unused-function -Wno-unused-parameter)

# ─── TweetNaCl (Ed25519) ────────────────────────────────────
add_library(ed25519 STATIC vendor/ed25519/tweetnacl.c vendor/ed25519/randombytes.c vendor/ed25519/ed25519_derive.c)
target_include_directories(ed25519 PUBLIC vendor/ed25519)
target_compile_options(ed25519 PRIVATE -Wno-unused-parameter -Wno-sign-compare)

# ─── Hashing ─────────────────────────────────────────────────
add_library(wdk_hashing STATIC
    hashing/sha256.c
    hashing/sha512.c
    hashing/hmac.c
    hashing/keccak256.c
    hashing/ripemd160.c
    hashing/blake2b.c
    hashing/pbkdf2.c
    hashing/hkdf.c
    hashing/aes_gcm.c
)
target_include_directories(wdk_hashing PUBLIC hashing)

# ─── Encoding ────────────────────────────────────────────────
add_library(wdk_encoding STATIC
    encoding/hex.c
    encoding/base58.c
    encoding/base58check.c
    encoding/bech32.c
    encoding/base64.c
)
target_include_directories(wdk_encoding PUBLIC encoding)
target_link_libraries(wdk_encoding PRIVATE wdk_hashing)

# ─── BIP ─────────────────────────────────────────────────────
add_library(wdk_bip STATIC
    bip/bip39.c
    bip/bip32.c
    bip/bip44.c
)
target_include_directories(wdk_bip PUBLIC bip)
target_link_libraries(wdk_bip PRIVATE wdk_hashing)

# ─── Bridge + Engine ─────────────────────────────────────────
add_library(wdk_engine STATIC
    bridge/engine.c
    bridge/key_store.c
    bridge/bridge_crypto.c
    bridge/bridge_encoding.c
    bridge/bridge_net.c
    bridge/bridge_storage.c
    bridge/bridge_platform.c
)
target_include_directories(wdk_engine PUBLIC bridge)
target_include_directories(wdk_engine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    vendor/secp256k1/include
    vendor/ed25519
)
target_link_libraries(wdk_engine PUBLIC
    quickjs
    secp256k1
    ed25519
    wdk_hashing
    wdk_encoding
    wdk_bip
)

# ─── Test executable (host only) ─────────────────────────────
# Tests link individual modules directly (not wdk_engine which pulls in QuickJS)
if(CMAKE_SYSTEM_NAME STREQUAL CMAKE_HOST_SYSTEM_NAME)
    add_executable(wdk_test_runner
        ../tests/test_crypto.c
        bridge/key_store.c
    )
    target_include_directories(wdk_test_runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        bridge
        hashing
        encoding
        bip
        vendor/secp256k1/include
        vendor/ed25519
    )
    target_link_libraries(wdk_test_runner PRIVATE
        wdk_hashing
        wdk_encoding
        wdk_bip
        secp256k1
        ed25519
    )
    target_compile_options(wdk_test_runner PRIVATE -Wno-unused-parameter)

    # Bridge integration tests (require full engine + QuickJS)
    add_executable(test_bridges
        ../tests/test_bridges.c
    )
    target_include_directories(test_bridges PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        bridge
        hashing
        encoding
        bip
        vendor/secp256k1/include
        vendor/ed25519
    )
    target_link_libraries(test_bridges PRIVATE wdk_engine)
    target_compile_options(test_bridges PRIVATE -Wno-unused-parameter)
endif()
