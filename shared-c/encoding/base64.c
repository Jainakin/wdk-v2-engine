/**
 * @file base64.c
 * @brief Standard Base64 encoding and decoding (RFC 4648).
 */

#include "base64.h"
#include <string.h>

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Reverse mapping: ASCII -> 6-bit value.
 * 255 = invalid, 254 = padding ('='), other values are the 6-bit decoded value.
 */
static const uint8_t b64_decode_table[256] = {
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255, 62,255,255,255, 63, /* +, / */
     52, 53, 54, 55, 56, 57, 58, 59,  60, 61,255,255,255,254,255,255, /* 0-9, = */
    255,  0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14, /* A-O */
     15, 16, 17, 18, 19, 20, 21, 22,  23, 24, 25,255,255,255,255,255, /* P-Z */
    255, 26, 27, 28, 29, 30, 31, 32,  33, 34, 35, 36, 37, 38, 39, 40, /* a-o */
     41, 42, 43, 44, 45, 46, 47, 48,  49, 50, 51,255,255,255,255,255, /* p-z */
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
};

int wdk_base64_encode(const uint8_t *data, size_t len, char *out, size_t *out_len) {
    if (!data || !out || !out_len) {
        return -1;
    }

    size_t encoded_len = ((len + 2) / 3) * 4;
    size_t pos = 0;

    size_t i = 0;
    while (i + 2 < len) {
        uint32_t triple = ((uint32_t)data[i] << 16) |
                          ((uint32_t)data[i + 1] << 8) |
                          ((uint32_t)data[i + 2]);
        out[pos++] = b64_alphabet[(triple >> 18) & 0x3F];
        out[pos++] = b64_alphabet[(triple >> 12) & 0x3F];
        out[pos++] = b64_alphabet[(triple >> 6) & 0x3F];
        out[pos++] = b64_alphabet[triple & 0x3F];
        i += 3;
    }

    /* Handle remaining 1 or 2 bytes */
    if (i < len) {
        uint32_t val = (uint32_t)data[i] << 16;
        if (i + 1 < len) {
            val |= (uint32_t)data[i + 1] << 8;
        }
        out[pos++] = b64_alphabet[(val >> 18) & 0x3F];
        out[pos++] = b64_alphabet[(val >> 12) & 0x3F];

        if (i + 1 < len) {
            out[pos++] = b64_alphabet[(val >> 6) & 0x3F];
        } else {
            out[pos++] = '=';
        }
        out[pos++] = '=';
    }

    out[pos] = '\0';
    *out_len = encoded_len;
    return 0;
}

int wdk_base64_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size) {
    if (!str || !out || !out_len) {
        return -1;
    }

    size_t str_len = strlen(str);

    /* Base64 string length must be a multiple of 4 */
    if (str_len % 4 != 0) {
        return -1;
    }

    if (str_len == 0) {
        *out_len = 0;
        return 0;
    }

    /* Calculate decoded length accounting for padding */
    size_t decoded_len = (str_len / 4) * 3;
    if (str[str_len - 1] == '=') decoded_len--;
    if (str_len >= 2 && str[str_len - 2] == '=') decoded_len--;

    if (decoded_len > out_size) {
        return -1;
    }

    size_t out_idx = 0;

    for (size_t i = 0; i < str_len; i += 4) {
        uint8_t a = b64_decode_table[(unsigned char)str[i]];
        uint8_t b = b64_decode_table[(unsigned char)str[i + 1]];
        uint8_t c = b64_decode_table[(unsigned char)str[i + 2]];
        uint8_t d = b64_decode_table[(unsigned char)str[i + 3]];

        /* First two characters must not be padding or invalid */
        if (a == 255 || a == 254 || b == 255 || b == 254) {
            return -1;
        }

        /* Third character: can be valid or padding */
        if (c == 255) return -1;
        /* Fourth character: can be valid or padding */
        if (d == 255) return -1;

        /* Validate padding: if c is padding, d must also be padding */
        if (c == 254 && d != 254) return -1;
        /* Padding only allowed at end */
        if ((c == 254 || d == 254) && i + 4 != str_len) return -1;

        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12);

        if (c != 254) {
            triple |= ((uint32_t)c << 6);
        }
        if (d != 254) {
            triple |= (uint32_t)d;
        }

        if (out_idx < decoded_len) out[out_idx++] = (uint8_t)((triple >> 16) & 0xFF);
        if (out_idx < decoded_len) out[out_idx++] = (uint8_t)((triple >> 8) & 0xFF);
        if (out_idx < decoded_len) out[out_idx++] = (uint8_t)(triple & 0xFF);
    }

    *out_len = decoded_len;
    return 0;
}
