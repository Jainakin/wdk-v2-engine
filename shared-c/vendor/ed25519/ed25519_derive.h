#ifndef ED25519_DERIVE_H
#define ED25519_DERIVE_H

#include <stdint.h>

/*
 * Derive an Ed25519 public key from a 32-byte seed.
 * Replicates the logic of TweetNaCl's crypto_sign_ed25519_tweet_keypair
 * but uses a caller-supplied seed instead of randombytes.
 *
 * Returns 0 on success.
 */
int wdk_ed25519_pubkey_from_seed(const uint8_t seed[32], uint8_t pubkey[32]);

#endif /* ED25519_DERIVE_H */
