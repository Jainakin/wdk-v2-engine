/*
 * WDK v2 Native Engine — BIP-32 Implementation
 *
 * Hierarchical Deterministic key derivation per BIP-32.
 */

#include "bip32.h"
#include "bip44.h"
#include "../hashing/hmac.h"
#include "../hashing/sha512.h"

#include <string.h>
#include <stdlib.h>

/* --------------------------------------------------------------------------
 * External: secp256k1 public key derivation
 *
 * Implemented in bridge_crypto.c where libsecp256k1 is available.
 * Computes the compressed (33-byte) public key from a 32-byte private key.
 * Returns 0 on success, -1 on error.
 * -------------------------------------------------------------------------- */
extern int wdk_secp256k1_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[33]);

/* --------------------------------------------------------------------------
 * secp256k1 curve order (n) for key validation
 *
 * n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * -------------------------------------------------------------------------- */
static const uint8_t secp256k1_order[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

/* --------------------------------------------------------------------------
 * Utility functions
 * -------------------------------------------------------------------------- */

static void secure_wipe(void *p, size_t len)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (len--) {
        *vp++ = 0;
    }
}

/*
 * Check if a 32-byte big-endian integer is zero.
 */
static int is_zero_32(const uint8_t *data)
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) {
        acc |= data[i];
    }
    return acc == 0;
}

/*
 * Compare two 32-byte big-endian integers.
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b.
 */
static int compare_be32(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/*
 * Check if a private key is valid for secp256k1.
 * Must be non-zero and less than the curve order.
 */
static int is_valid_private_key(const uint8_t key[32])
{
    if (is_zero_32(key))
        return 0;
    if (compare_be32(key, secp256k1_order) >= 0)
        return 0;
    return 1;
}

/*
 * Add two 256-bit big-endian integers modulo the secp256k1 order.
 * result = (a + b) mod n
 * a and b must be < n.
 */
static void add_mod_order(const uint8_t a[32], const uint8_t b[32], uint8_t result[32])
{
    uint16_t carry = 0;
    uint8_t sum[32];

    /* Add a + b in big-endian */
    for (int i = 31; i >= 0; i--) {
        carry += (uint16_t)a[i] + (uint16_t)b[i];
        sum[i] = (uint8_t)(carry & 0xFF);
        carry >>= 8;
    }

    /* If carry or sum >= order, subtract the order */
    int need_subtract = (carry != 0) || (compare_be32(sum, secp256k1_order) >= 0);

    if (need_subtract) {
        uint16_t borrow = 0;
        for (int i = 31; i >= 0; i--) {
            uint16_t diff = (uint16_t)sum[i] - (uint16_t)secp256k1_order[i] - borrow;
            result[i] = (uint8_t)(diff & 0xFF);
            borrow = (diff >> 15) & 1; /* borrow if underflow */
        }
    } else {
        memcpy(result, sum, 32);
    }

    secure_wipe(sum, sizeof(sum));
}

/* --------------------------------------------------------------------------
 * BIP-32: Master key from seed
 * -------------------------------------------------------------------------- */

int wdk_bip32_from_seed(const uint8_t *seed, size_t seed_len, wdk_bip32_key *out)
{
    if (!seed || seed_len == 0 || !out)
        return -1;

    /* BIP-32 specifies seed should be 128-512 bits (16-64 bytes) */
    if (seed_len < 16 || seed_len > 64)
        return -1;

    uint8_t hmac_out[64];
    const uint8_t *key = (const uint8_t *)"Bitcoin seed";
    size_t key_len = 12;

    wdk_hmac_sha512(key, key_len, seed, seed_len, hmac_out);

    /* First 32 bytes = private key, last 32 bytes = chain code */
    memcpy(out->private_key, hmac_out, 32);
    memcpy(out->chain_code, hmac_out + 32, 32);
    out->has_public_key = 0;
    memset(out->public_key, 0, 33);

    /* Validate: private key must be non-zero and < curve order */
    if (!is_valid_private_key(out->private_key)) {
        secure_wipe(hmac_out, sizeof(hmac_out));
        wdk_bip32_key_wipe(out);
        return -2;
    }

    secure_wipe(hmac_out, sizeof(hmac_out));
    return 0;
}

/* --------------------------------------------------------------------------
 * BIP-32: Child key derivation (CKDpriv)
 * -------------------------------------------------------------------------- */

int wdk_bip32_derive_child(const wdk_bip32_key *parent, uint32_t index,
                            int hardened, wdk_bip32_key *child)
{
    if (!parent || !child)
        return -1;

    uint32_t child_index = index;
    if (hardened) {
        child_index |= WDK_BIP32_HARDENED_BIT;
    }

    /*
     * Data for HMAC:
     * - Hardened: 0x00 || parent_private_key (33 bytes) || child_index (4 bytes) = 37 bytes
     * - Normal:   parent_public_key (33 bytes) || child_index (4 bytes) = 37 bytes
     */
    uint8_t data[37];

    if (hardened || (child_index & WDK_BIP32_HARDENED_BIT)) {
        /* Hardened child: use 0x00 || private key */
        data[0] = 0x00;
        memcpy(data + 1, parent->private_key, 32);
    } else {
        /* Normal child: use compressed public key */
        if (!parent->has_public_key) {
            /*
             * We need the public key for normal derivation.
             * Try to compute it. If secp256k1 is not available, fail.
             */
            wdk_bip32_key *mutable_parent = (wdk_bip32_key *)parent; /* const cast for caching */
            int rc = wdk_secp256k1_pubkey_from_privkey(parent->private_key, mutable_parent->public_key);
            if (rc != 0) {
                secure_wipe(data, sizeof(data));
                return -1;
            }
            mutable_parent->has_public_key = 1;
        }
        memcpy(data, parent->public_key, 33);
    }

    /* Append child index as big-endian 4 bytes */
    data[33] = (uint8_t)(child_index >> 24);
    data[34] = (uint8_t)(child_index >> 16);
    data[35] = (uint8_t)(child_index >> 8);
    data[36] = (uint8_t)(child_index);

    /* HMAC-SHA512(key=chain_code, data=data) */
    uint8_t hmac_out[64];
    wdk_hmac_sha512(parent->chain_code, 32, data, 37, hmac_out);

    /* IL (first 32 bytes) must be valid as a private key tweak */
    uint8_t *il = hmac_out;
    uint8_t *ir = hmac_out + 32;

    /* Check IL < order */
    if (compare_be32(il, secp256k1_order) >= 0) {
        secure_wipe(data, sizeof(data));
        secure_wipe(hmac_out, sizeof(hmac_out));
        return -2; /* Invalid child key, try next index */
    }

    /* child_key = (IL + parent_key) mod n */
    add_mod_order(il, parent->private_key, child->private_key);

    /* Check result is not zero */
    if (is_zero_32(child->private_key)) {
        secure_wipe(data, sizeof(data));
        secure_wipe(hmac_out, sizeof(hmac_out));
        wdk_bip32_key_wipe(child);
        return -2; /* Invalid child key, try next index */
    }

    /* Chain code = IR */
    memcpy(child->chain_code, ir, 32);
    child->has_public_key = 0;
    memset(child->public_key, 0, 33);

    secure_wipe(data, sizeof(data));
    secure_wipe(hmac_out, sizeof(hmac_out));

    return 0;
}

/* --------------------------------------------------------------------------
 * BIP-32: Derive along a path
 * -------------------------------------------------------------------------- */

int wdk_bip32_derive_path(const wdk_bip32_key *master, const char *path,
                           wdk_bip32_key *out)
{
    if (!master || !path || !out)
        return -1;

    /* Parse the path using BIP-44 parser */
    uint32_t indices[WDK_BIP44_MAX_DEPTH];
    int count = 0;

    int rc = wdk_bip44_parse_path(path, indices, &count, WDK_BIP44_MAX_DEPTH);
    if (rc != 0)
        return -1;

    /* Start with the master key */
    wdk_bip32_key current;
    memcpy(&current, master, sizeof(wdk_bip32_key));

    /* Derive step by step */
    for (int i = 0; i < count; i++) {
        uint32_t idx = indices[i];
        int hardened = (idx & WDK_BIP32_HARDENED_BIT) != 0;
        uint32_t child_idx = idx & ~WDK_BIP32_HARDENED_BIT;

        wdk_bip32_key next;
        /*
         * For hardened derivation, pass the index without the hardened bit
         * and set hardened=1. The derive_child function will add it back.
         * But if the index already has the hardened bit set from the parser,
         * we pass it directly with hardened=0 since the bit is already in place.
         */
        rc = wdk_bip32_derive_child(&current, child_idx, hardened, &next);
        if (rc != 0) {
            secure_wipe(&current, sizeof(current));
            return -2;
        }

        secure_wipe(&current, sizeof(current));
        memcpy(&current, &next, sizeof(wdk_bip32_key));
    }

    memcpy(out, &current, sizeof(wdk_bip32_key));
    secure_wipe(&current, sizeof(current));

    return 0;
}

/* --------------------------------------------------------------------------
 * BIP-32: Fill public key
 * -------------------------------------------------------------------------- */

int wdk_bip32_fill_public_key(wdk_bip32_key *key)
{
    if (!key)
        return -1;

    if (key->has_public_key)
        return 0;

    int rc = wdk_secp256k1_pubkey_from_privkey(key->private_key, key->public_key);
    if (rc == 0) {
        key->has_public_key = 1;
    }
    return rc;
}

/* --------------------------------------------------------------------------
 * Securely wipe a key structure
 * -------------------------------------------------------------------------- */

void wdk_bip32_key_wipe(wdk_bip32_key *key)
{
    if (key) {
        secure_wipe(key, sizeof(wdk_bip32_key));
    }
}
