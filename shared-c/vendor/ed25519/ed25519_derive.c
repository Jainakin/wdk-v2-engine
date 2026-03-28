/*
 * ed25519_derive.c — Ed25519 public key derivation from seed
 *
 * Extracts the minimal TweetNaCl internals needed to compute:
 *   pubkey = scalarbase(clamp(SHA-512(seed)[0..31]))
 *
 * This avoids modifying the vendored tweetnacl.c while providing
 * the ability to derive a public key from a known seed (which
 * crypto_sign_ed25519_tweet_keypair cannot do since it calls randombytes).
 */

#include "ed25519_derive.h"
#include "tweetnacl.h"
#include <string.h>

/* ── TweetNaCl internal types ────────────────────────────────── */

typedef unsigned char u8;
typedef long long i64;
typedef i64 gf[16];

#define FOR(i,n) for (i = 0; i < n; ++i)

/* ── Constants (from tweetnacl.c) ────────────────────────────── */

static const gf
  _gf0,
  _gf1 = {1},
  _D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
          0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  _X  = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
          0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  _Y  = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

/* ── Field arithmetic (from tweetnacl.c) ─────────────────────── */

static void set25519(gf r, const gf a) {
    int i;
    FOR(i,16) r[i] = a[i];
}

static void car25519(gf o) {
    int i;
    i64 c;
    FOR(i,16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i+1)*(i<15)] += c - 1 + 37*(c-1)*(i==15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    i64 t, i, c = ~(b-1);
    FOR(i,16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8 *o, const gf n) {
    int i, j, b;
    gf m, t;
    FOR(i,16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j,2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1-b);
    }
    FOR(i,16) {
        o[2*i] = t[i] & 0xff;
        o[2*i+1] = t[i] >> 8;
    }
}

static u8 par25519(const gf a) {
    u8 d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void A(gf o, const gf a, const gf b) {
    int i;
    FOR(i,16) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    int i;
    FOR(i,16) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    i64 i, j, t[31];
    FOR(i,31) t[i] = 0;
    FOR(i,16) FOR(j,16) t[i+j] += a[i] * b[j];
    FOR(i,15) t[i] += 38 * t[i+16];
    FOR(i,16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    FOR(a,16) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    FOR(a,16) o[a] = c[a];
}

/* ── Ed25519 point operations (from tweetnacl.c) ────────────── */

static void _add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, _D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], u8 b) {
    int i;
    FOR(i,4) sel25519(p[i], q[i], b);
}

static void _pack(u8 *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const u8 *s) {
    int i;
    set25519(p[0], _gf0);
    set25519(p[1], _gf1);
    set25519(p[2], _gf1);
    set25519(p[3], _gf0);
    for (i = 255; i >= 0; --i) {
        u8 b = (s[i/8] >> (i&7)) & 1;
        cswap(p, q, b);
        _add(q, p);
        _add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const u8 *s) {
    gf q[4];
    set25519(q[0], _X);
    set25519(q[1], _Y);
    set25519(q[2], _gf1);
    M(q[3], _X, _Y);
    scalarmult(p, q, s);
}

/* ── Public API ──────────────────────────────────────────────── */

int wdk_ed25519_pubkey_from_seed(const uint8_t seed[32], uint8_t pubkey[32]) {
    u8 d[64];
    gf p[4];

    /* SHA-512 the seed */
    crypto_hash_sha512_tweet(d, seed, 32);

    /* Clamp */
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    /* Scalar multiply base point */
    scalarbase(p, d);

    /* Pack the point into 32 bytes */
    _pack(pubkey, p);

    return 0;
}
