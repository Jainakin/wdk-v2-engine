/**
 * @file base58check.h
 * @brief Base58Check encoding and decoding for Bitcoin addresses.
 *
 * Base58Check = Base58(data + checksum)
 * where checksum = first 4 bytes of SHA256(SHA256(data)).
 */

#ifndef WDK_ENCODING_BASE58CHECK_H
#define WDK_ENCODING_BASE58CHECK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode data with Base58Check.
 *
 * The input data already includes the version byte as its first byte.
 * This function appends a 4-byte checksum (first 4 bytes of double-SHA256)
 * and then Base58-encodes the result.
 *
 * @param data    Input data (version byte + payload).
 * @param len     Length of input data.
 * @param out     Output buffer for null-terminated Base58Check string.
 *                Must be large enough; (len+4)*138/100+2 is a safe upper bound.
 * @param out_len On success, set to the length of the encoded string
 *                (not including null terminator).
 * @return 0 on success, -1 on error.
 */
int wdk_base58check_encode(const uint8_t *data, size_t len, char *out, size_t *out_len);

/**
 * Decode a Base58Check string.
 *
 * Decodes the Base58 string, verifies the 4-byte checksum, and returns
 * the payload (including the version byte, excluding the checksum).
 *
 * @param str      Null-terminated Base58Check string.
 * @param out      Output buffer for decoded data (version byte + payload).
 * @param out_len  On success, set to the number of decoded bytes
 *                 (version + payload, without checksum).
 * @param out_size Size of the output buffer.
 * @return 0 on success, -1 on invalid checksum, bad encoding, or buffer too small.
 */
int wdk_base58check_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENCODING_BASE58CHECK_H */
