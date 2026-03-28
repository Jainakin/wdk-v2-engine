/**
 * @file base58.c
 * @brief Base58 encoding and decoding using the Bitcoin alphabet.
 *
 * Algorithm: treat input bytes as a big-endian big integer, repeatedly divide
 * by 58, and map remainders to the Bitcoin Base58 alphabet. Leading zero bytes
 * in the input produce leading '1' characters in the output.
 */

#include "base58.h"
#include <string.h>

static const char b58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Reverse mapping: ASCII value -> base58 digit value, -1 = invalid */
static const int8_t b58_digits_map[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1, /* '1'..'9' = 0..8 */
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,  /* 'A'..'N' (skip I) */
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,  /* 'P'..'Z' (skip O) */
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,  /* 'a'..'n' (skip l) */
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,  /* 'o'..'z' */
};

int wdk_base58_encode(const uint8_t *data, size_t len, char *out, size_t *out_len) {
    if (!data || !out || !out_len) {
        return -1;
    }

    /* Count leading zeros */
    size_t leading_zeros = 0;
    while (leading_zeros < len && data[leading_zeros] == 0) {
        leading_zeros++;
    }

    /*
     * Allocate a temporary buffer for the base58 digits (in reverse order).
     * Upper bound on encoded size: len * 138 / 100 + 1
     * (log(256) / log(58) ~ 1.3863)
     */
    size_t buf_size = len * 138 / 100 + 2;
    uint8_t b58_buf[2048]; /* Stack buffer; 2048 handles up to ~1400 input bytes */
    uint8_t *buf = b58_buf;

    if (buf_size > sizeof(b58_buf)) {
        /* For extremely large inputs this would need dynamic allocation.
         * In practice, Bitcoin/crypto payloads are small. */
        return -1;
    }
    memset(buf, 0, buf_size);

    /* Convert big-endian bytes to base58 digits */
    size_t digits_len = 1;
    for (size_t i = leading_zeros; i < len; i++) {
        uint32_t carry = data[i];
        for (size_t j = 0; j < digits_len; j++) {
            carry += (uint32_t)buf[j] << 8;
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            buf[digits_len++] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    /* Build output: leading '1's + reversed base58 digits */
    size_t out_idx = 0;
    for (size_t i = 0; i < leading_zeros; i++) {
        out[out_idx++] = '1';
    }
    for (size_t i = 0; i < digits_len; i++) {
        out[out_idx++] = b58_alphabet[buf[digits_len - 1 - i]];
    }

    /* Handle empty input edge case */
    if (len == 0) {
        out_idx = 0;
    }

    out[out_idx] = '\0';
    *out_len = out_idx;
    return 0;
}

int wdk_base58_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size) {
    if (!str || !out || !out_len) {
        return -1;
    }

    size_t str_len = strlen(str);
    if (str_len == 0) {
        *out_len = 0;
        return 0;
    }

    /* Count leading '1' characters (leading zero bytes) */
    size_t leading_ones = 0;
    while (leading_ones < str_len && str[leading_ones] == '1') {
        leading_ones++;
    }

    /*
     * Temporary buffer for the decoded big integer.
     * Upper bound: str_len * 733 / 1000 + 1
     * (log(58) / log(256) ~ 0.7322)
     */
    size_t buf_size = str_len * 733 / 1000 + 2;
    uint8_t dec_buf[2048];
    uint8_t *buf = dec_buf;

    if (buf_size > sizeof(dec_buf)) {
        return -1;
    }
    memset(buf, 0, buf_size);

    /* Convert base58 string to big-endian bytes */
    size_t bytes_len = 1;
    for (size_t i = leading_ones; i < str_len; i++) {
        unsigned char ch = (unsigned char)str[i];
        if (ch >= 128) {
            return -1;
        }
        int digit = b58_digits_map[ch];
        if (digit < 0) {
            return -1;
        }

        uint32_t carry = (uint32_t)digit;
        for (size_t j = 0; j < bytes_len; j++) {
            carry += (uint32_t)buf[j] * 58;
            buf[j] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            buf[bytes_len++] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
    }

    /* Skip trailing zeros in buf (they are leading zeros in big-endian) */
    size_t actual_len = bytes_len;
    while (actual_len > 0 && buf[actual_len - 1] == 0) {
        actual_len--;
    }

    size_t total_len = leading_ones + actual_len;
    if (total_len > out_size) {
        return -1;
    }

    /* Write leading zero bytes */
    memset(out, 0, leading_ones);

    /* Write decoded bytes in big-endian order */
    for (size_t i = 0; i < actual_len; i++) {
        out[leading_ones + i] = buf[actual_len - 1 - i];
    }

    *out_len = total_len;
    return 0;
}
