/**
 * @file base58.h
 * @brief Base58 encoding and decoding using the Bitcoin alphabet.
 */

#ifndef WDK_ENCODING_BASE58_H
#define WDK_ENCODING_BASE58_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode binary data to a Base58 string (Bitcoin alphabet).
 *
 * Leading zero bytes in input become leading '1' characters in output.
 *
 * @param data    Input binary data.
 * @param len     Length of input data in bytes.
 * @param out     Output buffer for null-terminated Base58 string.
 *                Must be large enough; len*138/100+2 is a safe upper bound.
 * @param out_len On success, set to the length of the encoded string
 *                (not including null terminator).
 * @return 0 on success, -1 on error.
 */
int wdk_base58_encode(const uint8_t *data, size_t len, char *out, size_t *out_len);

/**
 * Decode a Base58 string to binary data.
 *
 * Leading '1' characters in input become leading zero bytes in output.
 *
 * @param str      Null-terminated Base58 string.
 * @param out      Output buffer for decoded bytes.
 * @param out_len  On success, set to the number of decoded bytes.
 * @param out_size Size of the output buffer.
 * @return 0 on success, -1 on invalid Base58 character or buffer too small.
 */
int wdk_base58_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENCODING_BASE58_H */
