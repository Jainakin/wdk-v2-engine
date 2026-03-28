/**
 * @file bech32.h
 * @brief Bech32 / Bech32m encoding and decoding (BIP-173, BIP-350)
 *        and SegWit address helpers for Bitcoin.
 */

#ifndef WDK_ENCODING_BECH32_H
#define WDK_ENCODING_BECH32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode data as a Bech32 or Bech32m string.
 *
 * @param out       Output buffer for the null-terminated encoded string.
 * @param out_size  Size of the output buffer.
 * @param hrp       Human-readable part (e.g. "bc", "tb").
 * @param data      Data values (5-bit groups, each 0..31).
 * @param data_len  Number of 5-bit data values.
 * @param bech32m   0 for Bech32 (BIP-173), 1 for Bech32m (BIP-350).
 * @return 0 on success, -1 on error.
 */
int wdk_bech32_encode(char *out, size_t out_size, const char *hrp,
                      const uint8_t *data, size_t data_len, int bech32m);

/**
 * Decode a Bech32 or Bech32m string.
 *
 * @param hrp        Output buffer for the human-readable part.
 * @param hrp_size   Size of the hrp buffer.
 * @param data       Output buffer for decoded 5-bit data values.
 * @param data_len   On success, set to number of 5-bit values decoded.
 * @param data_size  Size of the data buffer.
 * @param str        Null-terminated Bech32/Bech32m string.
 * @param is_bech32m On success, set to 1 if Bech32m, 0 if Bech32.
 * @return 0 on success, -1 on error (invalid encoding, bad checksum, etc.).
 */
int wdk_bech32_decode(char *hrp, size_t hrp_size, uint8_t *data,
                      size_t *data_len, size_t data_size, const char *str,
                      int *is_bech32m);

/**
 * Encode a SegWit address from witness version and witness program.
 *
 * Automatically selects Bech32 (witness v0) or Bech32m (witness v1+).
 *
 * @param out         Output buffer for the null-terminated address string.
 * @param out_size    Size of the output buffer.
 * @param hrp         Human-readable part ("bc" for mainnet, "tb" for testnet).
 * @param witver      Witness version (0..16).
 * @param witprog     Witness program bytes.
 * @param witprog_len Length of the witness program (2..40 bytes).
 * @return 0 on success, -1 on error.
 */
int wdk_segwit_addr_encode(char *out, size_t out_size, const char *hrp,
                           int witver, const uint8_t *witprog,
                           size_t witprog_len);

/**
 * Decode a SegWit address into witness version and witness program.
 *
 * @param witver      On success, set to the witness version (0..16).
 * @param witprog     Output buffer for the witness program bytes.
 * @param witprog_len On success, set to the length of the witness program.
 * @param hrp         Expected human-readable part ("bc" or "tb").
 * @param addr        Null-terminated SegWit address string.
 * @return 0 on success, -1 on error.
 */
int wdk_segwit_addr_decode(int *witver, uint8_t *witprog, size_t *witprog_len,
                           const char *hrp, const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENCODING_BECH32_H */
