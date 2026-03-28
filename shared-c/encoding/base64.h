/**
 * @file base64.h
 * @brief Standard Base64 encoding and decoding (RFC 4648).
 */

#ifndef WDK_ENCODING_BASE64_H
#define WDK_ENCODING_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode binary data to a Base64 string with padding.
 *
 * @param data    Input binary data.
 * @param len     Length of input data in bytes.
 * @param out     Output buffer for null-terminated Base64 string.
 *                Must be at least ((len + 2) / 3) * 4 + 1 bytes.
 * @param out_len On success, set to the length of the encoded string
 *                (not including null terminator).
 * @return 0 on success, -1 on error.
 */
int wdk_base64_encode(const uint8_t *data, size_t len, char *out, size_t *out_len);

/**
 * Decode a Base64 string to binary data. Handles '=' padding.
 *
 * @param str      Null-terminated Base64 string.
 * @param out      Output buffer for decoded bytes.
 * @param out_len  On success, set to the number of decoded bytes.
 * @param out_size Size of the output buffer.
 * @return 0 on success, -1 on invalid input or buffer too small.
 */
int wdk_base64_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENCODING_BASE64_H */
