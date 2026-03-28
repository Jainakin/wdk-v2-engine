/**
 * @file base58check.c
 * @brief Base58Check encoding and decoding for Bitcoin addresses.
 */

#include "base58check.h"
#include "base58.h"
#include "../hashing/sha256.h"

#include <string.h>

/**
 * Compute double-SHA256 checksum (first 4 bytes).
 */
static void compute_checksum(const uint8_t *data, size_t len, uint8_t checksum[4]) {
    uint8_t hash1[32];
    uint8_t hash2[32];

    wdk_sha256(data, len, hash1);
    wdk_sha256(hash1, 32, hash2);

    memcpy(checksum, hash2, 4);

    /* Clear intermediate hashes */
    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
}

int wdk_base58check_encode(const uint8_t *data, size_t len, char *out, size_t *out_len) {
    if (!data || !out || !out_len) {
        return -1;
    }

    /* Build versioned data + checksum in a temporary buffer */
    size_t total_len = len + 4;
    uint8_t tmp[1024];

    if (total_len > sizeof(tmp)) {
        return -1;
    }

    memcpy(tmp, data, len);
    compute_checksum(data, len, tmp + len);

    int ret = wdk_base58_encode(tmp, total_len, out, out_len);

    memset(tmp, 0, total_len);
    return ret;
}

int wdk_base58check_decode(const char *str, uint8_t *out, size_t *out_len, size_t out_size) {
    if (!str || !out || !out_len) {
        return -1;
    }

    /* Decode the base58 string */
    uint8_t decoded[1024];
    size_t decoded_len = 0;

    if (wdk_base58_decode(str, decoded, &decoded_len, sizeof(decoded)) != 0) {
        return -1;
    }

    /* Must have at least 4 bytes for the checksum + 1 byte for version */
    if (decoded_len < 5) {
        memset(decoded, 0, decoded_len);
        return -1;
    }

    /* Verify checksum */
    size_t payload_len = decoded_len - 4;
    uint8_t expected_checksum[4];
    compute_checksum(decoded, payload_len, expected_checksum);

    /* Constant-time comparison of checksum bytes */
    uint8_t diff = 0;
    for (int i = 0; i < 4; i++) {
        diff |= decoded[payload_len + i] ^ expected_checksum[i];
    }

    if (diff != 0) {
        memset(decoded, 0, decoded_len);
        return -1;
    }

    /* Copy payload (version + data, without checksum) */
    if (payload_len > out_size) {
        memset(decoded, 0, decoded_len);
        return -1;
    }

    memcpy(out, decoded, payload_len);
    *out_len = payload_len;

    memset(decoded, 0, decoded_len);
    return 0;
}
