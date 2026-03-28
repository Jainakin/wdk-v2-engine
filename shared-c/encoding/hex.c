/**
 * @file hex.c
 * @brief Hexadecimal encoding and decoding for WDK v2 native engine.
 */

#include "hex.h"
#include <string.h>

static const char hex_chars_lower[] = "0123456789abcdef";

int wdk_hex_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
    if (!data || !out) {
        return -1;
    }
    if (out_size < len * 2 + 1) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_chars_lower[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars_lower[data[i] & 0x0F];
    }
    out[len * 2] = '\0';

    return 0;
}

/**
 * Convert a single hex character to its 4-bit value.
 * Returns -1 if the character is not a valid hex digit.
 */
static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int wdk_hex_decode(const char *hex, uint8_t *out, size_t *out_len, size_t out_size) {
    if (!hex || !out || !out_len) {
        return -1;
    }

    size_t hex_len = strlen(hex);

    /* Hex string must have even length */
    if (hex_len % 2 != 0) {
        return -1;
    }

    size_t decoded_len = hex_len / 2;
    if (decoded_len > out_size) {
        return -1;
    }

    for (size_t i = 0; i < decoded_len; i++) {
        int hi = hex_char_to_val(hex[i * 2]);
        int lo = hex_char_to_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = decoded_len;
    return 0;
}
