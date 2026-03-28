/*
 * WDK v2 Native Engine — BIP-44 Path Parsing and Constants
 *
 * Implements BIP-44: Multi-Account Hierarchy for Deterministic Wallets.
 * https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 */

#ifndef WDK_BIP44_H
#define WDK_BIP44_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BIP-44 purpose constant */
#define WDK_BIP44_PURPOSE   44

/* SLIP-44 coin type constants */
#define WDK_COIN_BTC        0
#define WDK_COIN_ETH        60
#define WDK_COIN_TON        607
#define WDK_COIN_TRON       195
#define WDK_COIN_SOL        501

/* Maximum derivation depth (m/ + 5 levels is typical, allow 10 for safety) */
#define WDK_BIP44_MAX_DEPTH 10

/* Hardened flag in the high bit of a 32-bit index */
#define WDK_BIP44_HARDENED  0x80000000u

/**
 * Parse a BIP-44 derivation path string into an array of uint32_t indices.
 *
 * The path must begin with "m/" and each component is a decimal number
 * optionally followed by "'" or "h" to indicate hardened derivation.
 *
 * Example: "m/44'/60'/0'/0/0" -> {0x8000002C, 0x8000003C, 0x80000000, 0, 0}
 *
 * @param path       Derivation path string (e.g., "m/44'/60'/0'/0/0").
 * @param indices    Output array of uint32_t indices (with hardened flag in high bit).
 * @param count      Output: number of indices written.
 * @param max_count  Maximum number of indices the array can hold.
 * @return           0 on success, -1 on invalid path format, -2 if path too deep.
 */
int wdk_bip44_parse_path(const char *path, uint32_t *indices, int *count, int max_count);

/**
 * Build a standard BIP-44 path string.
 *
 * Produces: m/44'/<coin>'/<account>'/<change>/<address_index>
 *
 * @param coin_type      SLIP-44 coin type (e.g., WDK_COIN_ETH).
 * @param account        Account index.
 * @param change         0 for external, 1 for internal (change).
 * @param address_index  Address index.
 * @param out            Output buffer for the path string.
 * @param out_size       Size of the output buffer.
 * @return               0 on success, -1 on invalid parameters, -2 on buffer too small.
 */
int wdk_bip44_build_path(uint32_t coin_type, uint32_t account,
                          uint32_t change, uint32_t address_index,
                          char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* WDK_BIP44_H */
