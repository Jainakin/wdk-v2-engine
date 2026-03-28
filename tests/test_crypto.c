/*
 * test_crypto.c — Comprehensive tests for WDK v2 native engine
 *
 * Tests against known test vectors from BIP-39, BIP-32, and crypto specs.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static void crash_handler(int sig) {
    const char msg[] = "CAUGHT SIGNAL: ";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    char c = '0' + sig / 10; write(STDERR_FILENO, &c, 1);
    c = '0' + sig % 10; write(STDERR_FILENO, &c, 1);
    write(STDERR_FILENO, "\n", 1);
    _exit(128 + sig);
}

__attribute__((constructor))
static void install_crash_handler(void) {
    signal(SIGABRT, crash_handler);
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
}

#include "sha256.h"
#include "sha512.h"
#include "hmac.h"
#include "keccak256.h"
#include "ripemd160.h"
#include "blake2b.h"
#include "key_store.h"
#include "hex.h"
#include "base58.h"
#include "base58check.h"
#include "bech32.h"
#include "base64.h"
#include "bip39.h"
#include "bip32.h"
#include "bip44.h"

#include <secp256k1.h>
#include "ed25519_derive.h"
#include "tweetnacl.h"

/* Provide the secp256k1 pubkey function that BIP-32 extern-declares */
int wdk_secp256k1_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[33]) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, privkey)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return 0;
}

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%02d] %-50s ", tests_run, name); \
} while(0)

#define PASS() do { tests_passed++; printf("\033[32mPASS\033[0m\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("\033[31mFAIL: %s\033[0m\n", msg); } while(0)

/* Helper: hex string to bytes */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t len;
    if (wdk_hex_decode(hex, out, &len, max_len) != 0) return -1;
    return (int)len;
}

/* ══════════════════════════════════════════════════════════════
 *  HASHING TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_sha256(void) {
    uint8_t out[32];

    TEST("SHA-256: empty string");
    wdk_sha256((const uint8_t *)"", 0, out);
    uint8_t exp1[32];
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", exp1, 32);
    if (memcmp(out, exp1, 32) == 0) { PASS(); } else { FAIL("mismatch"); }

    TEST("SHA-256: 'abc'");
    wdk_sha256((const uint8_t *)"abc", 3, out);
    uint8_t exp2[32];
    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp2, 32);
    if (memcmp(out, exp2, 32) == 0) { PASS(); } else { FAIL("mismatch"); }
}

static void test_sha512(void) {
    uint8_t out[64];

    TEST("SHA-512: 'abc'");
    wdk_sha512((const uint8_t *)"abc", 3, out);
    uint8_t exp[64];
    hex_to_bytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", exp, 64);
    if (memcmp(out, exp, 64) == 0) { PASS(); } else { FAIL("mismatch"); }
}

static void test_keccak256(void) {
    uint8_t out[32];

    TEST("Keccak-256: empty string");
    wdk_keccak256((const uint8_t *)"", 0, out);
    uint8_t exp[32];
    hex_to_bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", exp, 32);
    if (memcmp(out, exp, 32) == 0) { PASS(); } else { FAIL("mismatch"); }
}

static void test_ripemd160(void) {
    uint8_t out[20];

    TEST("RIPEMD-160: 'abc'");
    wdk_ripemd160((const uint8_t *)"abc", 3, out);
    uint8_t exp[20];
    hex_to_bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", exp, 20);
    if (memcmp(out, exp, 20) == 0) { PASS(); } else { FAIL("mismatch"); }
}

static void test_hmac(void) {
    uint8_t out256[32], out512[64];

    /* RFC 4231 Test Case 2 */
    TEST("HMAC-SHA256: RFC 4231 TC2");
    const char *key_str = "Jefe";
    const char *data_str = "what do ya want for nothing?";
    wdk_hmac_sha256((const uint8_t *)key_str, 4,
                     (const uint8_t *)data_str, 28, out256);
    uint8_t exp256[32];
    hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", exp256, 32);
    if (memcmp(out256, exp256, 32) == 0) { PASS(); } else { FAIL("mismatch"); }

    TEST("HMAC-SHA512: RFC 4231 TC2");
    wdk_hmac_sha512((const uint8_t *)key_str, 4,
                     (const uint8_t *)data_str, 28, out512);
    uint8_t exp512[64];
    hex_to_bytes("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                 "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", exp512, 64);
    if (memcmp(out512, exp512, 64) == 0) { PASS(); } else { FAIL("mismatch"); }
}

/* ══════════════════════════════════════════════════════════════
 *  KEY STORE TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_key_store(void) {
    wdk_key_store_init();

    TEST("Key store: add + get round-trip");
    uint8_t k[32]; memset(k, 0xAB, 32);
    int32_t h = wdk_key_store_add(k, 32, WDK_CURVE_SECP256K1);
    size_t len; int curve;
    const uint8_t *got = wdk_key_store_get(h, &len, &curve);
    if (got && len == 32 && curve == WDK_CURVE_SECP256K1 && memcmp(got, k, 32) == 0) {
        PASS();
    } else { FAIL("data mismatch"); }

    TEST("Key store: release invalidates handle");
    wdk_key_store_release(h);
    if (!wdk_key_store_is_valid(h)) { PASS(); } else { FAIL("still valid"); }

    TEST("Key store: stress 256 + overflow rejection");
    wdk_key_store_init();
    int ok = 1;
    for (int i = 0; i < 256; i++) {
        uint8_t kk[32]; memset(kk, (uint8_t)i, 32);
        if (wdk_key_store_add(kk, 32, 0) < 0) { ok = 0; break; }
    }
    uint8_t overflow[32] = {0};
    if (wdk_key_store_add(overflow, 32, 0) >= 0) ok = 0;
    if (ok) { PASS(); } else { FAIL("stress failed"); }
    wdk_key_store_destroy();
}

/* ══════════════════════════════════════════════════════════════
 *  SECP256K1 TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_secp256k1(void) {
    TEST("secp256k1: pubkey from privkey");
    /* Known test vector: private key = 1 */
    uint8_t privkey[32] = {0};
    privkey[31] = 1; /* private key = 1 */

    /* Public key for privkey=1 (compressed):
     * 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 */
    uint8_t expected_pubkey[33];
    hex_to_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                 expected_pubkey, 33);

    /* Use our function */
    extern int wdk_secp256k1_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[33]);
    uint8_t pubkey[33];
    int ret = wdk_secp256k1_pubkey_from_privkey(privkey, pubkey);
    if (ret != 0) { FAIL("pubkey derivation failed"); return; }
    if (memcmp(pubkey, expected_pubkey, 33) == 0) { PASS(); } else { FAIL("pubkey mismatch"); }

    TEST("secp256k1: sign + verify round-trip");
    /* Use a real private key */
    uint8_t test_privkey[32];
    hex_to_bytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                 test_privkey, 32);

    /* Hash to sign */
    uint8_t msg_hash[32];
    wdk_sha256((const uint8_t *)"test message", 12, msg_hash);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Sign */
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, test_privkey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        FAIL("sign failed"); return;
    }

    /* Get public key for verification */
    secp256k1_pubkey pk;
    secp256k1_ec_pubkey_create(ctx, &pk, test_privkey);

    /* Verify */
    int valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pk);
    secp256k1_context_destroy(ctx);

    if (valid) { PASS(); } else { FAIL("verify failed"); }
}

/* ══════════════════════════════════════════════════════════════
 *  ENCODING TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_hex(void) {
    TEST("Hex: encode/decode round-trip");
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    char hex[16];
    wdk_hex_encode(data, 6, hex, sizeof(hex));
    if (strcmp(hex, "deadbeef0001") != 0) { FAIL("encode"); return; }
    uint8_t dec[6]; size_t dec_len;
    wdk_hex_decode(hex, dec, &dec_len, sizeof(dec));
    if (dec_len == 6 && memcmp(dec, data, 6) == 0) { PASS(); } else { FAIL("decode"); }
}

static void test_base58(void) {
    TEST("Base58: encode known vector");
    /* "Hello World" in Base58 = "JxF12TrwUP45BMd" */
    uint8_t data[] = "Hello World";
    char out[64]; size_t out_len;
    wdk_base58_encode(data, 11, out, &out_len);
    if (strcmp(out, "JxF12TrwUP45BMd") == 0) { PASS(); } else {
        char msg[128]; snprintf(msg, sizeof(msg), "got '%s'", out);
        FAIL(msg);
    }
}

static void test_base58check(void) {
    TEST("Base58Check: encode/decode round-trip");
    /* Version byte 0x00 + 20-byte payload = P2PKH address */
    uint8_t hash[32];
    wdk_sha256((const uint8_t *)"test", 4, hash); /* SHA-256 writes 32 bytes */
    uint8_t data[21];
    data[0] = 0x00;
    memcpy(data + 1, hash, 20); /* Only copy first 20 bytes of hash */

    char encoded[64]; size_t enc_len;
    int ret = wdk_base58check_encode(data, 21, encoded, &enc_len);
    if (ret != 0) { FAIL("encode failed"); return; }

    uint8_t decoded[64]; size_t dec_len;
    ret = wdk_base58check_decode(encoded, decoded, &dec_len, sizeof(decoded));
    if (ret != 0) { FAIL("decode failed"); return; }
    if (dec_len == 21 && memcmp(decoded, data, 21) == 0) { PASS(); } else { FAIL("round-trip mismatch"); }
}

static void test_bech32(void) {
    TEST("Bech32: SegWit v0 address encode/decode");
    /* Known BIP-173 test vector:
     * witness version 0, 20-byte program (P2WPKH) */
    uint8_t witprog[20];
    hex_to_bytes("751e76e8199196d454941c45d1b3a323f1433bd6", witprog, 20);

    char addr[128];
    int ret = wdk_segwit_addr_encode(addr, sizeof(addr), "bc", 0, witprog, 20);
    if (ret != 0) { FAIL("encode failed"); return; }

    /* Expected: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 */
    if (strcmp(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0) { PASS(); } else {
        char msg[256]; snprintf(msg, sizeof(msg), "got '%s'", addr);
        FAIL(msg);
    }
}

static void test_base64(void) {
    TEST("Base64: encode/decode round-trip");
    const uint8_t data[] = "Hello, World!";
    char encoded[64]; size_t enc_len;
    wdk_base64_encode(data, 13, encoded, &enc_len);
    /* "Hello, World!" → "SGVsbG8sIFdvcmxkIQ==" */
    if (strcmp(encoded, "SGVsbG8sIFdvcmxkIQ==") != 0) {
        char msg[128]; snprintf(msg, sizeof(msg), "got '%s'", encoded);
        FAIL(msg); return;
    }
    uint8_t decoded[64]; size_t dec_len;
    wdk_base64_decode(encoded, decoded, &dec_len, sizeof(decoded));
    if (dec_len == 13 && memcmp(decoded, data, 13) == 0) { PASS(); } else { FAIL("decode mismatch"); }
}

/* ══════════════════════════════════════════════════════════════
 *  BIP-39 TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_bip39(void) {
    TEST("BIP-39: generate 12-word mnemonic");
    char mnemonic[512];
    int ret = wdk_bip39_generate_mnemonic(12, mnemonic, sizeof(mnemonic));
    if (ret != 0) { FAIL("generation failed"); return; }
    int words = 1;
    for (char *p = mnemonic; *p; p++) if (*p == ' ') words++;
    if (words == 12) { PASS(); } else { FAIL("wrong word count"); }

    TEST("BIP-39: generate 24-word mnemonic");
    ret = wdk_bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic));
    if (ret != 0) { FAIL("generation failed"); return; }
    words = 1;
    for (char *p = mnemonic; *p; p++) if (*p == ' ') words++;
    if (words == 24) { PASS(); } else { FAIL("wrong word count"); }

    TEST("BIP-39: mnemonic → seed (known vector)");
    /* BIP-39 test vector:
     * mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
     * passphrase: ""
     * seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
     *        9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4 */
    const char *test_mnemonic = "abandon abandon abandon abandon abandon abandon "
                                 "abandon abandon abandon abandon abandon about";
    uint8_t seed[64];
    ret = wdk_bip39_mnemonic_to_seed(test_mnemonic, "", seed);
    if (ret != 0) { FAIL("seed derivation failed"); return; }

    uint8_t expected_seed[64];
    hex_to_bytes("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
                 "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                 expected_seed, 64);
    if (memcmp(seed, expected_seed, 64) == 0) { PASS(); } else { FAIL("seed mismatch"); }
}

/* ══════════════════════════════════════════════════════════════
 *  BIP-32 TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_bip32(void) {
    /* BIP-32 Test Vector 1:
     * Seed: 000102030405060708090a0b0c0d0e0f
     * Master key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
     * Master chain: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508 */

    TEST("BIP-32: master key from seed (TV1)");
    uint8_t seed[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, 16);

    wdk_bip32_key master;
    int ret = wdk_bip32_from_seed(seed, 16, &master);
    if (ret != 0) { FAIL("from_seed failed"); return; }

    uint8_t expected_key[32], expected_chain[32];
    hex_to_bytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                 expected_key, 32);
    hex_to_bytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                 expected_chain, 32);

    if (memcmp(master.private_key, expected_key, 32) == 0 &&
        memcmp(master.chain_code, expected_chain, 32) == 0) {
        PASS();
    } else {
        FAIL("key or chain code mismatch");
    }

    /* Derive m/0' (hardened child 0) */
    TEST("BIP-32: derive m/0' (TV1)");
    wdk_bip32_key child;
    ret = wdk_bip32_derive_child(&master, 0, 1, &child);
    if (ret != 0) { FAIL("derive_child failed"); return; }

    uint8_t exp_child_key[32], exp_child_chain[32];
    hex_to_bytes("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                 exp_child_key, 32);
    hex_to_bytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                 exp_child_chain, 32);

    if (memcmp(child.private_key, exp_child_key, 32) == 0 &&
        memcmp(child.chain_code, exp_child_chain, 32) == 0) {
        PASS();
    } else {
        FAIL("child key or chain code mismatch");
    }

    /* Test path derivation: m/0'/1 */
    TEST("BIP-32: derive path m/0'/1 (TV1)");
    wdk_bip32_key derived;
    ret = wdk_bip32_derive_path(&master, "m/0'/1", &derived);
    if (ret != 0) { FAIL("derive_path failed"); return; }

    uint8_t exp_path_key[32];
    hex_to_bytes("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                 exp_path_key, 32);
    if (memcmp(derived.private_key, exp_path_key, 32) == 0) {
        PASS();
    } else {
        FAIL("path derivation key mismatch");
    }

    wdk_bip32_key_wipe(&master);
    wdk_bip32_key_wipe(&child);
    wdk_bip32_key_wipe(&derived);
}

/* ══════════════════════════════════════════════════════════════
 *  BIP-44 PATH PARSING TEST
 * ══════════════════════════════════════════════════════════════ */

static void test_bip44(void) {
    TEST("BIP-44: parse m/44'/60'/0'/0/0");
    uint32_t indices[10];
    int count = 0;
    int ret = wdk_bip44_parse_path("m/44'/60'/0'/0/0", indices, &count, 10);
    if (ret != 0) { FAIL("parse failed"); return; }
    if (count != 5) { FAIL("wrong count"); return; }
    /* 44' = 44 | 0x80000000 = 0x8000002C */
    if (indices[0] != 0x8000002C) { FAIL("index 0 wrong"); return; }
    /* 60' = 60 | 0x80000000 = 0x8000003C */
    if (indices[1] != 0x8000003C) { FAIL("index 1 wrong"); return; }
    /* 0' = 0x80000000 */
    if (indices[2] != 0x80000000) { FAIL("index 2 wrong"); return; }
    /* 0 */
    if (indices[3] != 0) { FAIL("index 3 wrong"); return; }
    /* 0 */
    if (indices[4] != 0) { FAIL("index 4 wrong"); return; }
    PASS();
}

/* ══════════════════════════════════════════════════════════════
 *  ED25519 TESTS
 * ══════════════════════════════════════════════════════════════ */

static void test_ed25519(void) {
    /* RFC 8032 Test Vector 1:
     * seed    = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
     * pubkey  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
     * message = "" (empty)
     * sig     = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
     *           5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
     */
    TEST("Ed25519: pubkey from seed (RFC 8032 TV1)");
    uint8_t seed1[32], expected_pk1[32];
    hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                 seed1, 32);
    hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                 expected_pk1, 32);

    uint8_t pk1[32];
    wdk_ed25519_pubkey_from_seed(seed1, pk1);
    if (memcmp(pk1, expected_pk1, 32) == 0) { PASS(); } else { FAIL("pubkey mismatch"); }

    /* RFC 8032 Test Vector 2:
     * seed    = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
     * pubkey  = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
     */
    TEST("Ed25519: pubkey from seed (RFC 8032 TV2)");
    uint8_t seed2[32], expected_pk2[32];
    hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                 seed2, 32);
    hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                 expected_pk2, 32);

    uint8_t pk2[32];
    wdk_ed25519_pubkey_from_seed(seed2, pk2);
    if (memcmp(pk2, expected_pk2, 32) == 0) { PASS(); } else { FAIL("pubkey mismatch"); }

    /* Test signing with RFC 8032 TV1 (empty message) */
    TEST("Ed25519: sign empty message (RFC 8032 TV1)");
    uint8_t expected_sig[64];
    hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                 expected_sig, 64);

    /* Build full 64-byte sk = seed || pubkey */
    uint8_t sk[64];
    memcpy(sk, seed1, 32);
    memcpy(sk + 32, pk1, 32);

    uint8_t sm[128]; /* signature (64) + message (0) */
    unsigned long long smlen;
    int ret = crypto_sign_ed25519_tweet(sm, &smlen, (const unsigned char *)"", 0, sk);
    if (ret != 0) { FAIL("sign failed"); return; }
    if (smlen != 64) { FAIL("unexpected smlen"); return; }
    if (memcmp(sm, expected_sig, 64) == 0) { PASS(); } else { FAIL("signature mismatch"); }

    /* Test sign + verify round-trip with RFC 8032 TV2 */
    TEST("Ed25519: sign + verify round-trip (RFC 8032 TV2)");
    uint8_t sk2[64];
    memcpy(sk2, seed2, 32);
    memcpy(sk2 + 32, pk2, 32);

    const unsigned char tv2_msg[] = {0x72};
    uint8_t sm2[128];
    unsigned long long smlen2;
    ret = crypto_sign_ed25519_tweet(sm2, &smlen2, tv2_msg, 1, sk2);
    if (ret != 0) { FAIL("sign failed"); return; }

    /* Verify */
    uint8_t m_out[128];
    unsigned long long mlen_out;
    ret = crypto_sign_ed25519_tweet_open(m_out, &mlen_out, sm2, smlen2, pk2);
    if (ret == 0 && mlen_out == 1 && m_out[0] == 0x72) { PASS(); } else { FAIL("verify failed"); }
}

/* ══════════════════════════════════════════════════════════════
 *  FULL CRYPTO ROUND-TRIP TEST
 * ══════════════════════════════════════════════════════════════ */

static void test_full_roundtrip(void) {
    TEST("Full: mnemonic → seed → derive → pubkey → sign → verify");

    /* 1. Generate mnemonic */
    char mnemonic[512];
    int ret = wdk_bip39_generate_mnemonic(12, mnemonic, sizeof(mnemonic));
    if (ret != 0) { FAIL("mnemonic gen"); return; }

    /* 2. Derive seed */
    uint8_t seed[64];
    ret = wdk_bip39_mnemonic_to_seed(mnemonic, "", seed);
    if (ret != 0) { FAIL("seed"); return; }

    /* 3. Master key from seed */
    wdk_bip32_key master;
    ret = wdk_bip32_from_seed(seed, 64, &master);
    if (ret != 0) { FAIL("master key"); return; }

    /* 4. Derive BTC key: m/84'/0'/0'/0/0 */
    wdk_bip32_key btc_key;
    ret = wdk_bip32_derive_path(&master, "m/84'/0'/0'/0/0", &btc_key);
    if (ret != 0) { FAIL("derive path"); return; }

    /* 5. Get public key */
    extern int wdk_secp256k1_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[33]);
    uint8_t pubkey[33];
    ret = wdk_secp256k1_pubkey_from_privkey(btc_key.private_key, pubkey);
    if (ret != 0) { FAIL("pubkey"); return; }
    if (pubkey[0] != 0x02 && pubkey[0] != 0x03) { FAIL("invalid pubkey prefix"); return; }

    /* 6. Sign a message hash */
    uint8_t msg_hash[32];
    wdk_sha256((const uint8_t *)"WDK v2 test", 11, msg_hash);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, btc_key.private_key, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        FAIL("sign"); return;
    }

    /* 7. Verify the signature */
    secp256k1_pubkey pk;
    secp256k1_ec_pubkey_create(ctx, &pk, btc_key.private_key);
    int valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pk);
    secp256k1_context_destroy(ctx);

    if (!valid) { FAIL("verify"); return; }

    /* Cleanup */
    wdk_bip32_key_wipe(&master);
    wdk_bip32_key_wipe(&btc_key);

    PASS();
}

/* ══════════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════════ */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* disable buffering */
    printf("\n=== WDK v2 Engine — Comprehensive Test Suite ===\n\n");

    printf("--- Hashing ---\n");
    test_sha256();
    test_sha512();
    test_keccak256();
    test_ripemd160();
    test_hmac();

    printf("\n--- Key Store ---\n");
    test_key_store();

    printf("\n--- secp256k1 ---\n");
    test_secp256k1();

    printf("\n--- Ed25519 ---\n");
    test_ed25519();

    printf("\n--- Encoding ---\n");
    test_hex();
    test_base58();
    test_base58check();
    test_bech32();
    test_base64();

    printf("\n--- BIP-39 ---\n");
    test_bip39();

    printf("\n--- BIP-32 ---\n");
    test_bip32();

    printf("\n--- BIP-44 ---\n");
    test_bip44();

    printf("\n--- Integration ---\n");
    test_full_roundtrip();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(", %d FAILED", tests_failed);
    }
    printf(" ===\n\n");

    return (tests_failed == 0) ? 0 : 1;
}
