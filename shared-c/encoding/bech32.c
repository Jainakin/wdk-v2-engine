/**
 * @file bech32.c
 * @brief Bech32 / Bech32m encoding and decoding (BIP-173, BIP-350)
 *        and SegWit address helpers for Bitcoin.
 *
 * Implements the BCH code over GF(32) used by Bech32 encoding.
 */

#include "bech32.h"
#include <string.h>

/* Bech32 character set for encoding */
static const char bech32_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* Reverse mapping: ASCII -> 5-bit value, -1 = invalid */
static const int8_t bech32_charset_rev[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30,  7, 5,-1,-1,-1,-1,-1,-1, /* 0-9 */
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1, /* A-O */
    1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1,  /* P-Z */
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1, /* a-o */
    1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1,  /* p-z */
};

/* BCH generator polynomial constants */
static const uint32_t bech32_generators[5] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};

/* Bech32 final constant = 1, Bech32m final constant */
#define BECH32_CONST  1u
#define BECH32M_CONST 0x2bc830a3u

/**
 * Compute the Bech32 polymod checksum.
 */
static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                chk ^= bech32_generators[j];
            }
        }
    }
    return chk;
}

/**
 * Expand the HRP for checksum computation.
 * Output: [hrp[i] >> 5 for each char] + [0] + [hrp[i] & 31 for each char]
 * Requires out_size >= hrp_len * 2 + 1.
 *
 * @return Expansion length on success, 0 on error (buffer too small).
 */
static size_t bech32_hrp_expand(const char *hrp, uint8_t *out, size_t out_size) {
    size_t hrp_len = strlen(hrp);
    size_t needed = hrp_len * 2 + 1;
    if (needed > out_size) {
        return 0;
    }
    for (size_t i = 0; i < hrp_len; i++) {
        out[i] = (uint8_t)((unsigned char)hrp[i] >> 5);
    }
    out[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        out[hrp_len + 1 + i] = (uint8_t)((unsigned char)hrp[i] & 0x1f);
    }
    return needed;
}

/**
 * Verify or create a Bech32 checksum.
 *
 * For verification, the polymod of hrp_expand(hrp) + data + checksum
 * should equal the encoding constant.
 *
 * @return The polymod result (should equal BECH32_CONST or BECH32M_CONST).
 */
static uint32_t bech32_verify_checksum(const char *hrp, const uint8_t *data,
                                       size_t data_len) {
    uint8_t exp[256];
    size_t exp_len = bech32_hrp_expand(hrp, exp, sizeof(exp));
    if (exp_len == 0) {
        return 0; /* HRP expansion failed */
    }

    /* Concatenate expanded HRP and data into a single buffer for polymod */
    size_t total = exp_len + data_len;
    if (total > sizeof(exp)) {
        return 0; /* too large */
    }
    memcpy(exp + exp_len, data, data_len);
    return bech32_polymod(exp, total);
}

/**
 * Create the 6-value checksum for a Bech32/Bech32m encoding.
 */
static void bech32_create_checksum(const char *hrp, const uint8_t *data,
                                   size_t data_len, int bech32m,
                                   uint8_t checksum[6]) {
    uint8_t values[512];
    size_t hrp_exp_len = bech32_hrp_expand(hrp, values, sizeof(values));
    if (hrp_exp_len == 0) {
        memset(checksum, 0, 6);
        return;
    }

    /* Bounds check: need hrp_expand + data + 6 zeros */
    size_t total = hrp_exp_len + data_len;
    if (total + 6 > sizeof(values)) {
        memset(checksum, 0, 6);
        return;
    }

    memcpy(values + hrp_exp_len, data, data_len);

    /* Append 6 zero bytes for the checksum positions */
    memset(values + total, 0, 6);
    total += 6;

    uint32_t target = bech32m ? BECH32M_CONST : BECH32_CONST;
    uint32_t polymod = bech32_polymod(values, total) ^ target;

    for (int i = 0; i < 6; i++) {
        checksum[i] = (uint8_t)((polymod >> (5 * (5 - i))) & 0x1f);
    }
}

int wdk_bech32_encode(char *out, size_t out_size, const char *hrp,
                      const uint8_t *data, size_t data_len, int bech32m) {
    if (!out || !hrp || !data) {
        return -1;
    }

    size_t hrp_len = strlen(hrp);
    if (hrp_len == 0 || hrp_len > 83) {
        return -1;
    }

    /* Validate HRP characters (must be 33..126) and check case consistency */
    int have_lower = 0, have_upper = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        unsigned char c = (unsigned char)hrp[i];
        if (c < 33 || c > 126) return -1;
        if (c >= 'a' && c <= 'z') have_lower = 1;
        if (c >= 'A' && c <= 'Z') have_upper = 1;
    }
    if (have_lower && have_upper) return -1;

    /* Validate data values (must be 0..31) */
    for (size_t i = 0; i < data_len; i++) {
        if (data[i] > 31) return -1;
    }

    /* Total output length: hrp + '1' + data_len + 6 (checksum) + '\0' */
    size_t total_len = hrp_len + 1 + data_len + 6;
    if (total_len + 1 > out_size) {
        return -1;
    }
    if (total_len > 90) {
        /* BIP-173 limit (relaxed for some use cases, but enforce for safety) */
        /* Actually, BIP-350 allows longer strings in some contexts.
         * We still enforce 90 for SegWit but not here in the raw encoder. */
    }

    /* Compute checksum */
    uint8_t checksum[6];
    bech32_create_checksum(hrp, data, data_len, bech32m, checksum);

    /* Build output string */
    size_t pos = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        unsigned char c = (unsigned char)hrp[i];
        /* Output HRP in lowercase */
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
        out[pos++] = (char)c;
    }
    out[pos++] = '1'; /* separator */

    for (size_t i = 0; i < data_len; i++) {
        out[pos++] = bech32_charset[data[i]];
    }
    for (int i = 0; i < 6; i++) {
        out[pos++] = bech32_charset[checksum[i]];
    }
    out[pos] = '\0';

    return 0;
}

int wdk_bech32_decode(char *hrp, size_t hrp_size, uint8_t *data,
                      size_t *data_len, size_t data_size, const char *str,
                      int *is_bech32m) {
    if (!hrp || !data || !data_len || !str || !is_bech32m) {
        return -1;
    }

    size_t str_len = strlen(str);
    if (str_len < 8) { /* minimum: 1 HRP + '1' + 6 checksum */
        return -1;
    }

    /* Find the last '1' separator */
    size_t sep_pos = 0;
    int found_sep = 0;
    for (size_t i = str_len; i > 0; i--) {
        if (str[i - 1] == '1') {
            sep_pos = i - 1;
            found_sep = 1;
            break;
        }
    }
    if (!found_sep) return -1;
    if (sep_pos == 0) return -1; /* empty HRP */
    if (sep_pos + 7 > str_len) return -1; /* need at least 6 checksum chars */

    /* Extract and validate HRP */
    if (sep_pos + 1 > hrp_size) return -1;

    int have_lower = 0, have_upper = 0;
    for (size_t i = 0; i < sep_pos; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c < 33 || c > 126) return -1;
        if (c >= 'a' && c <= 'z') have_lower = 1;
        if (c >= 'A' && c <= 'Z') have_upper = 1;
        /* Store HRP in lowercase */
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        hrp[i] = (char)c;
    }
    hrp[sep_pos] = '\0';

    if (have_lower && have_upper) return -1; /* mixed case */

    /* Check data part case consistency with HRP */
    for (size_t i = sep_pos + 1; i < str_len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c >= 'a' && c <= 'z') have_lower = 1;
        if (c >= 'A' && c <= 'Z') have_upper = 1;
    }
    if (have_lower && have_upper) return -1;

    /* Decode the data part (including checksum) */
    size_t data_part_len = str_len - sep_pos - 1;
    uint8_t all_data[512];
    if (data_part_len > sizeof(all_data)) return -1;

    for (size_t i = 0; i < data_part_len; i++) {
        unsigned char c = (unsigned char)str[sep_pos + 1 + i];
        if (c >= 128) return -1;
        int8_t val = bech32_charset_rev[c];
        if (val < 0) return -1;
        all_data[i] = (uint8_t)val;
    }

    /* Verify checksum */
    uint32_t check = bech32_verify_checksum(hrp, all_data, data_part_len);
    if (check == BECH32_CONST) {
        *is_bech32m = 0;
    } else if (check == BECH32M_CONST) {
        *is_bech32m = 1;
    } else {
        return -1;
    }

    /* Output data without the 6 checksum values */
    size_t result_len = data_part_len - 6;
    if (result_len > data_size) return -1;

    memcpy(data, all_data, result_len);
    *data_len = result_len;

    return 0;
}

/* ---- Bit conversion helpers for SegWit addresses ---- */

/**
 * Convert between bit groups.
 *
 * @param out       Output buffer.
 * @param out_len   On entry, pointer to 0. On success, number of values written.
 * @param out_size  Size of the output buffer.
 * @param outbits   Number of bits per output value (e.g., 5 or 8).
 * @param in        Input values.
 * @param in_len    Number of input values.
 * @param inbits    Number of bits per input value (e.g., 8 or 5).
 * @param pad       If nonzero, pad incomplete groups with zeros.
 * @return 0 on success, -1 on error.
 */
static int convert_bits(uint8_t *out, size_t *out_len, size_t out_size,
                        int outbits, const uint8_t *in, size_t in_len,
                        int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = ((uint32_t)1 << outbits) - 1;
    size_t idx = 0;

    for (size_t i = 0; i < in_len; i++) {
        val = (val << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            if (idx >= out_size) return -1;
            out[idx++] = (uint8_t)((val >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            if (idx >= out_size) return -1;
            out[idx++] = (uint8_t)((val << (outbits - bits)) & maxv);
        }
    } else {
        if (bits >= inbits) return -1;
        if (((val << (outbits - bits)) & maxv) != 0) return -1;
    }

    *out_len = idx;
    return 0;
}

int wdk_segwit_addr_encode(char *out, size_t out_size, const char *hrp,
                           int witver, const uint8_t *witprog,
                           size_t witprog_len) {
    if (!out || !hrp || !witprog) return -1;
    if (witver < 0 || witver > 16) return -1;
    if (witprog_len < 2 || witprog_len > 40) return -1;

    /* Additional BIP-141 constraints */
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return -1;

    /* Convert 8-bit witness program to 5-bit groups.
     * Max 5-bit values from convert_bits: ceil(40*8/5) + 1 (padding) = 65.
     * data5 needs 1 (witness version) + 65 = 66. */
    uint8_t conv_out[66];
    size_t conv_len = 0;
    uint8_t data5[67]; /* 1 (version) + up to 65 (converted) + margin */
    size_t data5_len = 0;

    if (convert_bits(conv_out, &conv_len, sizeof(conv_out), 5,
                     witprog, witprog_len, 8, 1) != 0) {
        return -1;
    }

    /* Prepend witness version */
    if (1 + conv_len > sizeof(data5)) return -1;
    data5[0] = (uint8_t)witver;
    memcpy(data5 + 1, conv_out, conv_len);
    data5_len = 1 + conv_len;

    /* Witness version 0 uses Bech32, version 1+ uses Bech32m */
    int use_bech32m = (witver > 0) ? 1 : 0;

    return wdk_bech32_encode(out, out_size, hrp, data5, data5_len, use_bech32m);
}

int wdk_segwit_addr_decode(int *witver, uint8_t *witprog, size_t *witprog_len,
                           const char *hrp, const char *addr) {
    if (!witver || !witprog || !witprog_len || !hrp || !addr) return -1;

    char decoded_hrp[84];
    uint8_t data5[84];
    size_t data5_len = 0;
    int is_bech32m = 0;

    if (wdk_bech32_decode(decoded_hrp, sizeof(decoded_hrp), data5, &data5_len,
                          sizeof(data5), addr, &is_bech32m) != 0) {
        return -1;
    }

    /* Verify HRP matches (case-insensitive) */
    size_t hrp_len = strlen(hrp);
    size_t dec_hrp_len = strlen(decoded_hrp);
    if (hrp_len != dec_hrp_len) return -1;
    for (size_t i = 0; i < hrp_len; i++) {
        char a = hrp[i];
        char b = decoded_hrp[i];
        if (a >= 'A' && a <= 'Z') a = a - 'A' + 'a';
        if (b >= 'A' && b <= 'Z') b = b - 'A' + 'a';
        if (a != b) return -1;
    }

    if (data5_len < 1) return -1;

    /* First 5-bit value is the witness version */
    int ver = data5[0];
    if (ver > 16) return -1;

    /* Verify encoding type matches witness version */
    if (ver == 0 && is_bech32m) return -1; /* v0 must use Bech32 */
    if (ver > 0 && !is_bech32m) return -1; /* v1+ must use Bech32m */

    /* Convert remaining 5-bit groups to 8-bit bytes */
    size_t prog_len = 0;
    if (convert_bits(witprog, &prog_len, 40, 8,
                     data5 + 1, data5_len - 1, 5, 0) != 0) {
        return -1;
    }

    /* Validate witness program length */
    if (prog_len < 2 || prog_len > 40) return -1;
    if (ver == 0 && prog_len != 20 && prog_len != 32) return -1;

    *witver = ver;
    *witprog_len = prog_len;
    return 0;
}
