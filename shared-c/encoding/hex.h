/**
 * @file hex.h
 * @brief Hexadecimal encoding and decoding for WDK v2 native engine.
 */

#ifndef WDK_ENCODING_HEX_H
#define WDK_ENCODING_HEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode binary data to a hex string.
 *
 * @param data     Input binary data.
 * @param len      Length of input data in bytes.
 * @param out      Output buffer for null-terminated hex string.
 * @param out_size Size of the output buffer. Must be at least len*2+1.
 * @return 0 on success, -1 if out_size is too small or arguments are NULL.
 */
int wdk_hex_encode(const uint8_t *data, size_t len, char *out, size_t out_size);

/**
 * Decode a hex string to binary data.
 *
 * Handles both uppercase and lowercase hex characters.
 *
 * @param hex      Null-terminated hex string (must have even length).
 * @param out      Output buffer for decoded bytes.
 * @param out_len  On success, set to the number of decoded bytes.
 * @param out_size Size of the output buffer.
 * @return 0 on success, -1 on invalid hex input or buffer too small.
 */
int wdk_hex_decode(const char *hex, uint8_t *out, size_t *out_len, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* WDK_ENCODING_HEX_H */
