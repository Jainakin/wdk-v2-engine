/*
 * WDK v2 Native Engine — BIP-32 Hierarchical Deterministic Key Derivation
 *
 * Implements BIP-32: Hierarchical Deterministic Wallets.
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

#ifndef WDK_BIP32_H
#define WDK_BIP32_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDK_BIP32_HARDENED_BIT  0x80000000u

typedef struct {
    uint8_t private_key[32];
    uint8_t chain_code[32];
    uint8_t public_key[33]; /* compressed secp256k1 public key, filled on demand */
    int has_public_key;
} wdk_bip32_key;

/**
 * Derive a master key from a BIP-39 seed.
 *
 * HMAC-SHA512(key="Bitcoin seed", data=seed).
 * First 32 bytes become the private key, last 32 become the chain code.
 *
 * @param seed      Seed bytes (typically 64 bytes from BIP-39).
 * @param seed_len  Length of seed in bytes.
 * @param out       Output key structure.
 * @return          0 on success, -1 on invalid parameters,
 *                  -2 if the derived key is invalid (zero or >= curve order).
 */
int wdk_bip32_from_seed(const uint8_t *seed, size_t seed_len, wdk_bip32_key *out);

/**
 * Derive a child key from a parent key.
 *
 * @param parent    Parent key (must have private_key set).
 * @param index     Child index (0-based, without hardened bit).
 * @param hardened  Non-zero for hardened derivation (index += 0x80000000).
 * @param child     Output child key.
 * @return          0 on success, -1 on invalid parameters,
 *                  -2 if the derived key is invalid.
 */
int wdk_bip32_derive_child(const wdk_bip32_key *parent, uint32_t index,
                            int hardened, wdk_bip32_key *child);

/**
 * Derive a key along a full BIP-32 path string.
 *
 * Parses paths like "m/44'/60'/0'/0/0" and derives step by step.
 *
 * @param master  Master key (from wdk_bip32_from_seed).
 * @param path    Derivation path string.
 * @param out     Output key at the end of the path.
 * @return        0 on success, -1 on invalid path, -2 on derivation failure.
 */
int wdk_bip32_derive_path(const wdk_bip32_key *master, const char *path,
                           wdk_bip32_key *out);

/**
 * Compute the compressed public key for a key that has a private key.
 * Requires secp256k1 to be available.
 *
 * @param key  Key structure; public_key and has_public_key will be updated.
 * @return     0 on success, -1 on error.
 */
int wdk_bip32_fill_public_key(wdk_bip32_key *key);

/**
 * Securely zero a key structure.
 *
 * @param key  Key structure to wipe.
 */
void wdk_bip32_key_wipe(wdk_bip32_key *key);

#ifdef __cplusplus
}
#endif

#endif /* WDK_BIP32_H */
