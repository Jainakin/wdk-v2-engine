/*
 * WDK v2 Native Engine — BIP-39 Implementation
 *
 * Mnemonic generation and PBKDF2-HMAC-SHA512 seed derivation.
 */

#include "bip39.h"
#include "bip39_wordlist_en.h"
#include "../hashing/sha256.h"
#include "../hashing/hmac.h"

#include <string.h>
#include <stdlib.h>

/* --------------------------------------------------------------------------
 * Platform entropy
 * -------------------------------------------------------------------------- */

#if defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#include <fcntl.h>
#include <unistd.h>

static int platform_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }
    close(fd);
    return 0;
}

#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>

static int platform_random(uint8_t *buf, size_t len)
{
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return NT_SUCCESS(status) ? 0 : -1;
}

#else
#error "Unsupported platform for random number generation"
#endif

/* --------------------------------------------------------------------------
 * PBKDF2-HMAC-SHA512 (RFC 8018)
 * -------------------------------------------------------------------------- */

static int pbkdf2_hmac_sha512(const uint8_t *password, size_t pw_len,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t iterations, uint8_t *out, size_t out_len)
{
    /*
     * BIP-39 always uses dkLen=64, which fits in one HMAC block (hLen=64).
     * We implement the general case for correctness.
     */
    const size_t h_len = 64; /* SHA-512 output length */
    uint8_t U[64];
    uint8_t T[64];
    uint8_t salt_block[256]; /* salt + 4-byte block counter */
    uint32_t block_num = 1;
    size_t remaining = out_len;
    size_t offset = 0;

    if (!password || !salt || !out || iterations == 0)
        return -1;

    /* Salt must fit in our buffer minus the 4-byte counter */
    if (salt_len > sizeof(salt_block) - 4)
        return -1;

    while (remaining > 0) {
        size_t copy_len = remaining < h_len ? remaining : h_len;

        /* Construct salt || INT_32_BE(block_num) */
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (uint8_t)(block_num >> 24);
        salt_block[salt_len + 1] = (uint8_t)(block_num >> 16);
        salt_block[salt_len + 2] = (uint8_t)(block_num >> 8);
        salt_block[salt_len + 3] = (uint8_t)(block_num);

        /* U_1 = PRF(password, salt || INT_32_BE(i)) */
        wdk_hmac_sha512(password, pw_len, salt_block, salt_len + 4, U);
        memcpy(T, U, h_len);

        /* U_2 .. U_c */
        for (uint32_t j = 1; j < iterations; j++) {
            wdk_hmac_sha512(password, pw_len, U, h_len, U);
            for (size_t k = 0; k < h_len; k++) {
                T[k] ^= U[k];
            }
        }

        memcpy(out + offset, T, copy_len);
        offset += copy_len;
        remaining -= copy_len;
        block_num++;
    }

    /* Wipe intermediates */
    memset(U, 0, sizeof(U));
    memset(T, 0, sizeof(T));
    memset(salt_block, 0, sizeof(salt_block));

    return 0;
}

/* --------------------------------------------------------------------------
 * Utility: secure memset that won't be optimized away
 * -------------------------------------------------------------------------- */

static void secure_wipe(void *p, size_t len)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (len--) {
        *vp++ = 0;
    }
}

/* --------------------------------------------------------------------------
 * Bit manipulation helpers for entropy -> mnemonic conversion
 * -------------------------------------------------------------------------- */

/*
 * Extract an 11-bit value from a byte array at a given bit offset.
 * data_len is the total size of the data buffer for bounds safety.
 *
 * Needs up to 3 consecutive bytes starting at bit_offset/8.
 * Caller must ensure data_len >= (bit_offset/8) + 3.
 */
static uint32_t extract_11bits(const uint8_t *data, size_t data_len,
                                 size_t bit_offset)
{
    size_t byte_idx = bit_offset / 8;
    size_t bit_idx = bit_offset % 8;

    /* Bounds check: we read 3 bytes starting at byte_idx */
    if (byte_idx + 2 >= data_len) {
        /* Safe fallback: read available bytes, zero-pad the rest */
        uint32_t word = 0;
        if (byte_idx < data_len)
            word |= (uint32_t)data[byte_idx] << 16;
        if (byte_idx + 1 < data_len)
            word |= (uint32_t)data[byte_idx + 1] << 8;
        if (byte_idx + 2 < data_len)
            word |= (uint32_t)data[byte_idx + 2];
        uint32_t shift = 24 - 11 - bit_idx;
        return (word >> shift) & 0x7FF;
    }

    /* Fast path: all 3 bytes available */
    uint32_t word = (uint32_t)data[byte_idx] << 16;
    word |= (uint32_t)data[byte_idx + 1] << 8;
    word |= (uint32_t)data[byte_idx + 2];

    uint32_t shift = 24 - 11 - bit_idx;
    return (word >> shift) & 0x7FF;
}

/* --------------------------------------------------------------------------
 * Word lookup helper
 * -------------------------------------------------------------------------- */

static int word_to_index(const char *word, size_t word_len)
{
    for (int i = 0; i < BIP39_WORDLIST_COUNT; i++) {
        if (bip39_wordlist[i] == NULL)
            continue;
        if (strlen(bip39_wordlist[i]) == word_len &&
            memcmp(bip39_wordlist[i], word, word_len) == 0) {
            return i;
        }
    }
    return -1;
}

/* --------------------------------------------------------------------------
 * Generate mnemonic from entropy
 * -------------------------------------------------------------------------- */

int wdk_bip39_generate_mnemonic_from_entropy(const uint8_t *entropy, size_t entropy_len,
                                              char *out, size_t out_size)
{
    int word_count;

    if (!entropy || !out || out_size == 0)
        return -1;

    /* Determine word count from entropy length */
    switch (entropy_len) {
        case 16: word_count = 12; break;
        case 20: word_count = 15; break;
        case 24: word_count = 18; break;
        case 28: word_count = 21; break;
        case 32: word_count = 24; break;
        default: return -1;
    }

    /* Step 1: SHA-256 hash of entropy for checksum */
    uint8_t hash[32];
    wdk_sha256(entropy, entropy_len, hash);

    /*
     * Step 2: Build the full bit array: entropy || checksum bits.
     * Checksum bits = entropy_bits / 32 = entropy_len * 8 / 32 = entropy_len / 4.
     * Total bits = entropy_bits + checksum_bits = word_count * 11.
     *
     * We need at most 32 + 1 = 33 bytes to hold entropy + checksum bits.
     */
    size_t entropy_bits = entropy_len * 8;
    size_t cs_bits = entropy_bits / 32;
    size_t total_bits = entropy_bits + cs_bits;
    (void)total_bits; /* used implicitly: word_count * 11 == total_bits */

    uint8_t data[33 + 1]; /* +1 for extract_11bits safety margin */
    memset(data, 0, sizeof(data));
    memcpy(data, entropy, entropy_len);

    /*
     * Append checksum bits from hash[0].
     * cs_bits ranges from 4 to 8.
     * We need to place the top cs_bits of hash[0] at bit position entropy_bits.
     */
    {
        size_t byte_pos = entropy_bits / 8;
        size_t bit_pos = entropy_bits % 8;

        /* The checksum byte - take the top cs_bits of hash[0] */
        uint8_t cs_byte = hash[0];

        if (bit_pos == 0) {
            /* Entropy ends on a byte boundary */
            data[byte_pos] = cs_byte;
        } else {
            /* Entropy does not end on a byte boundary - merge bits */
            data[byte_pos] |= (cs_byte >> bit_pos);
            if (byte_pos + 1 < sizeof(data)) {
                data[byte_pos + 1] = (uint8_t)(cs_byte << (8 - bit_pos));
            }
        }
    }

    /* Step 3: Extract 11-bit groups and map to words */
    size_t written = 0;
    for (int i = 0; i < word_count; i++) {
        uint32_t idx = extract_11bits(data, sizeof(data), (size_t)i * 11);

        if (idx >= BIP39_WORDLIST_COUNT || bip39_wordlist[idx] == NULL) {
            secure_wipe(data, sizeof(data));
            return -1; /* Wordlist not fully populated */
        }

        const char *word = bip39_wordlist[idx];
        size_t wlen = strlen(word);

        /* Check buffer space: word + separator or null terminator */
        size_t needed = wlen + (i < word_count - 1 ? 1 : 1); /* space or NUL */
        if (written + needed > out_size) {
            secure_wipe(data, sizeof(data));
            return -2; /* Buffer too small */
        }

        if (i > 0) {
            out[written++] = ' ';
        }
        memcpy(out + written, word, wlen);
        written += wlen;
    }
    out[written] = '\0';

    secure_wipe(data, sizeof(data));
    secure_wipe(hash, sizeof(hash));

    return 0;
}

/* --------------------------------------------------------------------------
 * Generate mnemonic with platform entropy
 * -------------------------------------------------------------------------- */

int wdk_bip39_generate_mnemonic(int word_count, char *out, size_t out_size)
{
    size_t entropy_len;

    if (!out || out_size == 0)
        return -1;

    switch (word_count) {
        case 12: entropy_len = 16; break;
        case 15: entropy_len = 20; break;
        case 18: entropy_len = 24; break;
        case 21: entropy_len = 28; break;
        case 24: entropy_len = 32; break;
        default: return -1;
    }

    uint8_t entropy[32];
    if (platform_random(entropy, entropy_len) != 0) {
        secure_wipe(entropy, sizeof(entropy));
        return -3;
    }

    int rc = wdk_bip39_generate_mnemonic_from_entropy(entropy, entropy_len, out, out_size);

    secure_wipe(entropy, sizeof(entropy));
    return rc;
}

/* --------------------------------------------------------------------------
 * Mnemonic to seed (PBKDF2-HMAC-SHA512)
 * -------------------------------------------------------------------------- */

int wdk_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t out[64])
{
    if (!mnemonic || !out)
        return -1;

    if (!passphrase)
        passphrase = "";

    /* Build salt: "mnemonic" + passphrase */
    const char *prefix = "mnemonic";
    size_t prefix_len = 8;
    size_t pass_len = strlen(passphrase);
    size_t salt_len = prefix_len + pass_len;

    /* Allocate salt buffer */
    uint8_t salt_stack[256];
    uint8_t *salt;

    if (salt_len <= sizeof(salt_stack)) {
        salt = salt_stack;
    } else {
        salt = (uint8_t *)malloc(salt_len);
        if (!salt)
            return -1;
    }

    memcpy(salt, prefix, prefix_len);
    memcpy(salt + prefix_len, passphrase, pass_len);

    /* PBKDF2-HMAC-SHA512: password=mnemonic, salt="mnemonic"+passphrase, c=2048, dkLen=64 */
    int rc = pbkdf2_hmac_sha512(
        (const uint8_t *)mnemonic, strlen(mnemonic),
        salt, salt_len,
        2048,
        out, 64
    );

    /* Wipe and free salt */
    secure_wipe(salt, salt_len);
    if (salt != salt_stack)
        free(salt);

    return rc;
}

/* --------------------------------------------------------------------------
 * Validate mnemonic
 * -------------------------------------------------------------------------- */

int wdk_bip39_validate_mnemonic(const char *mnemonic)
{
    if (!mnemonic || *mnemonic == '\0')
        return 0;

    /* Parse words and collect indices */
    uint16_t indices[24];
    int word_count = 0;
    const char *p = mnemonic;

    /* Skip leading whitespace */
    while (*p == ' ') p++;

    while (*p != '\0' && word_count < 24) {
        const char *word_start = p;
        while (*p != '\0' && *p != ' ')
            p++;

        size_t word_len = (size_t)(p - word_start);
        if (word_len == 0)
            break;

        int idx = word_to_index(word_start, word_len);
        if (idx < 0)
            return 0; /* Word not in dictionary */

        indices[word_count++] = (uint16_t)idx;

        /* Skip whitespace between words */
        while (*p == ' ') p++;
    }

    /* If there are more words remaining, invalid */
    if (*p != '\0')
        return 0;

    /* Valid word counts: 12, 15, 18, 21, 24 */
    if (word_count < 12 || word_count > 24 || (word_count % 3) != 0)
        return 0;

    /*
     * Reconstruct the entropy + checksum bits from the word indices,
     * then verify the checksum.
     *
     * Total bits = word_count * 11
     * Checksum bits (CS) = total_bits / 33  (which is entropy_bits / 32)
     * Entropy bits (ENT) = total_bits - CS
     */
    size_t total_bits = (size_t)word_count * 11;
    size_t cs_bits = total_bits / 33;
    size_t ent_bits = total_bits - cs_bits;
    size_t ent_bytes = ent_bits / 8;

    /* Reconstruct the full bit stream */
    uint8_t data[33 + 1]; /* max 264 bits = 33 bytes, +1 safety */
    memset(data, 0, sizeof(data));

    for (int i = 0; i < word_count; i++) {
        uint32_t val = indices[i];
        size_t bit_offset = (size_t)i * 11;

        /* Set 11 bits at bit_offset */
        for (int b = 0; b < 11; b++) {
            if (val & (1 << (10 - b))) {
                size_t pos = bit_offset + (size_t)b;
                data[pos / 8] |= (uint8_t)(0x80 >> (pos % 8));
            }
        }
    }

    /* Extract entropy bytes */
    uint8_t entropy[32];
    memcpy(entropy, data, ent_bytes);

    /* Compute SHA-256 of entropy */
    uint8_t hash[32];
    wdk_sha256(entropy, ent_bytes, hash);

    /* Extract the checksum bits from the reconstructed data */
    uint8_t cs_reconstructed = 0;
    for (size_t b = 0; b < cs_bits; b++) {
        size_t pos = ent_bits + b;
        if (data[pos / 8] & (0x80 >> (pos % 8))) {
            cs_reconstructed |= (uint8_t)(1 << (cs_bits - 1 - b));
        }
    }

    /* Extract expected checksum from hash */
    uint8_t cs_expected = (uint8_t)(hash[0] >> (8 - cs_bits));

    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(hash, sizeof(hash));
    secure_wipe(data, sizeof(data));

    return (cs_reconstructed == cs_expected) ? 1 : 0;
}
