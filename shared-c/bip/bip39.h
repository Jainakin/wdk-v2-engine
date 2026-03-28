/*
 * WDK v2 Native Engine — BIP-39 Mnemonic Generation and Seed Derivation
 *
 * Implements BIP-39: Mnemonic code for generating deterministic keys.
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

#ifndef WDK_BIP39_H
#define WDK_BIP39_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate a BIP-39 mnemonic phrase.
 *
 * @param word_count  Number of words (12 or 24).
 * @param out         Output buffer for the space-separated mnemonic string.
 * @param out_size    Size of the output buffer in bytes.
 * @return            0 on success, -1 on invalid parameters, -2 on buffer too small,
 *                    -3 on entropy generation failure.
 */
int wdk_bip39_generate_mnemonic(int word_count, char *out, size_t out_size);

/**
 * Generate a BIP-39 mnemonic from caller-supplied entropy.
 *
 * @param entropy      Entropy bytes (16 bytes for 12 words, 32 bytes for 24 words).
 * @param entropy_len  Length of entropy in bytes.
 * @param out          Output buffer for the space-separated mnemonic string.
 * @param out_size     Size of the output buffer in bytes.
 * @return             0 on success, -1 on invalid parameters, -2 on buffer too small.
 */
int wdk_bip39_generate_mnemonic_from_entropy(const uint8_t *entropy, size_t entropy_len,
                                              char *out, size_t out_size);

/**
 * Derive a 512-bit seed from a mnemonic phrase using PBKDF2-HMAC-SHA512.
 *
 * @param mnemonic    Space-separated mnemonic phrase (UTF-8 NFKD normalized).
 * @param passphrase  Optional passphrase (NULL or "" for no passphrase).
 * @param out         Output buffer for 64-byte seed.
 * @return            0 on success, -1 on invalid parameters.
 */
int wdk_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t out[64]);

/**
 * Validate a BIP-39 mnemonic phrase.
 *
 * Checks that:
 *  - Word count is 12, 15, 18, 21, or 24.
 *  - All words are in the BIP-39 English wordlist.
 *  - The checksum is correct.
 *
 * @param mnemonic  Space-separated mnemonic phrase.
 * @return          1 if valid, 0 if invalid.
 */
int wdk_bip39_validate_mnemonic(const char *mnemonic);

#ifdef __cplusplus
}
#endif

#endif /* WDK_BIP39_H */
