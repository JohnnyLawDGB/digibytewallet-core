//
//  BRKey.c
//
//  Created by Aaron Voisine on 8/19/15.
//  Copyright (c) 2015 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

/*
 * ToDo: Replace DIGIBYTE_PUBKEY_LEGACY
*/

#include "BRKey.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRBech32.h"
#include "BRNetwork.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#define BITCOIN_PRIVKEY        128
#define BITCOIN_PRIVKEY_LEGACY 158
#define BITCOIN_PRIVKEY_TEST   239

#if __BIG_ENDIAN__ || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||\
    __ARMEB__ || __THUMBEB__ || __AARCH64EB__ || __MIPSEB__
#define WORDS_BIGENDIAN        1
#endif
#define DETERMINISTIC          1
// secp256k1 v0.4.1 amalgamation: enable the modules this build needs.
// recovery = Digi-ID recoverable ECDSA; ecdh; extrakeys + schnorrsig = BIP340
// (Taproot prerequisite). USE_BASIC_CONFIG is gone — modern secp256k1
// auto-detects field/scalar/widemul and ships no src/basic-config.h.
#define ENABLE_MODULE_ECDH       1
#define ENABLE_MODULE_RECOVERY   1
#define ENABLE_MODULE_EXTRAKEYS  1
#define ENABLE_MODULE_SCHNORRSIG 1

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wconditional-uninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "secp256k1/src/secp256k1.c"
// Modern secp256k1 ships the ecmult tables as separate translation units instead
// of generating them at runtime. Amalgamation-#include them here so every secp
// symbol stays confined to this one compilation unit and the table config
// (ECMULT_WINDOW_SIZE / ECMULT_GEN_PREC_BITS) is guaranteed to match secp256k1.c.
#include "secp256k1/src/precomputed_ecmult.c"
#include "secp256k1/src/precomputed_ecmult_gen.c"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

static secp256k1_context *_ctx = NULL;
static pthread_once_t _ctx_once = PTHREAD_ONCE_INIT;

static void _ctx_init()
{
    _ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int BRSecp256k1ModAdd(UInt256 *a, const UInt256 *b)
{
    pthread_once(&_ctx_once, _ctx_init);
    return secp256k1_ec_seckey_tweak_add(_ctx, (unsigned char *)a, (const unsigned char *)b);
}

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int BRSecp256k1ModMul(UInt256 *a, const UInt256 *b)
{
    pthread_once(&_ctx_once, _ctx_init);
    return secp256k1_ec_seckey_tweak_mul(_ctx, (unsigned char *)a, (const unsigned char *)b);
}

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
int BRSecp256k1PointGen(BRECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_create(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p
// returns true on success
int BRSecp256k1PointAdd(BRECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_parse(_ctx, &pubkey, (const unsigned char *)p, sizeof(*p)) &&
            secp256k1_ec_pubkey_tweak_add(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p
// returns true on success
int BRSecp256k1PointMul(BRECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_parse(_ctx, &pubkey, (const unsigned char *)p, sizeof(*p)) &&
            secp256k1_ec_pubkey_tweak_mul(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int BRPrivKeyIsValid(const char *privKey)
{
    uint8_t data[34];
    size_t dataLen, strLen;
    int r = 0;
    
    assert(privKey != NULL);

    dataLen = BRBase58CheckDecode(data, sizeof(data), privKey);
    strLen = strlen(privKey);
    
    if (dataLen == 33 || dataLen == 34) { // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
        if (BRNetworkIsTestnet()) {
            r = (data[0] == BITCOIN_PRIVKEY_TEST);
        }
        else {
            if(data[0] == BITCOIN_PRIVKEY) {
                r = 1;
            }
            if(data[0] == BITCOIN_PRIVKEY_LEGACY) {
                r = 1;
            }
        }
    }
    else if ((strLen == 30 || strLen == 22) && privKey[0] == 'S') { // mini private key format
        char s[strLen + 2];
        
        strncpy(s, privKey, sizeof(s));
        s[sizeof(s) - 2] = '?';
        BRSHA256(data, s, sizeof(s) - 1);
        mem_clean(s, sizeof(s));
        r = (data[0] == 0);
    }
    else r = (strspn(privKey, "0123456789ABCDEFabcdef") == 64); // hex encoded key
    
    mem_clean(data, sizeof(data));
    return r;
}

// assigns secret to key and returns true on success
int BRKeySetSecret(BRKey *key, const UInt256 *secret, int compressed)
{
    assert(key != NULL);
    assert(secret != NULL);
    
    pthread_once(&_ctx_once, _ctx_init);
    BRKeyClean(key);
    key->secret = UInt256Get(secret);
    key->compressed = compressed;
    return secp256k1_ec_seckey_verify(_ctx, key->secret.u8);
}

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int BRKeySetPrivKey(BRKey *key, const char *privKey)
{
    size_t len = strlen(privKey);
    uint8_t data[34], version = BRNetworkIsTestnet() ? BITCOIN_PRIVKEY_TEST : BITCOIN_PRIVKEY;
    int r = 0;

    assert(key != NULL);
    assert(privKey != NULL);
    
    // mini private key format
    if ((len == 30 || len == 22) && privKey[0] == 'S') {
        if (! BRPrivKeyIsValid(privKey)) return 0;
        BRSHA256(data, privKey, strlen(privKey));
        r = BRKeySetSecret(key, (UInt256 *)data, 0);
    }
    else {
        len = BRBase58CheckDecode(data, sizeof(data), privKey);
        if (len == 0 || len == 28) len = BRBase58Decode(data, sizeof(data), privKey);

        if (len < sizeof(UInt256) || len > sizeof(UInt256) + 2) { // treat as hex string
            for (len = 0; privKey[len*2] && privKey[len*2 + 1] && len < sizeof(data); len++) {
                if (sscanf(&privKey[len*2], "%2hhx", &data[len]) != 1) break;
            }
        }

        if ((len == sizeof(UInt256) + 1 || len == sizeof(UInt256) + 2) && data[0] == version) {
            r = BRKeySetSecret(key, (UInt256 *)&data[1], (len == sizeof(UInt256) + 2));
        }
        else if (len == sizeof(UInt256)) {
            r = BRKeySetSecret(key, (UInt256 *)data, 0);
        }
    }

    mem_clean(data, sizeof(data));
    return r;
}

// assigns DER encoded pubKey to key and returns true on success
int BRKeySetPubKey(BRKey *key, const uint8_t *pubKey, size_t pkLen)
{
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(pubKey != NULL);
    assert(pkLen == 33 || pkLen == 65);
    
    pthread_once(&_ctx_once, _ctx_init);
    BRKeyClean(key);
    memcpy(key->pubKey, pubKey, pkLen);
    key->compressed = (pkLen <= 33);
    return secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, pkLen);
}

// writes the WIF private key to privKey and returns the number of bytes writen, or pkLen needed if privKey is NULL
// returns 0 on failure
size_t BRKeyPrivKey(const BRKey *key, char *privKey, size_t pkLen)
{
    uint8_t data[34];

    assert(key != NULL);
    
    if (secp256k1_ec_seckey_verify(_ctx, key->secret.u8)) {
        data[0] = BRNetworkIsTestnet() ? BITCOIN_PRIVKEY_TEST : BITCOIN_PRIVKEY;

        UInt256Set(&data[1], key->secret);
        if (key->compressed) data[33] = 0x01;
        pkLen = BRBase58CheckEncode(privKey, pkLen, data, (key->compressed) ? 34 : 33);
        mem_clean(data, sizeof(data));
    }
    else pkLen = 0;
    
    return pkLen;
}

// writes the DER encoded public key to pubKey and returns number of bytes written, or pkLen needed if pubKey is NULL
size_t BRKeyPubKey(BRKey *key, void *pubKey, size_t pkLen)
{
    static uint8_t empty[65]; // static vars initialize to zero
    size_t size = (key->compressed) ? 33 : 65;
    secp256k1_pubkey pk;

    assert(key != NULL);
    
    if (memcmp(key->pubKey, empty, size) == 0) {
        if (secp256k1_ec_pubkey_create(_ctx, &pk, key->secret.u8)) {
            secp256k1_ec_pubkey_serialize(_ctx, key->pubKey, &size, &pk,
                                          (key->compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
        }
        else size = 0;
    }

    if (pubKey && size <= pkLen) memcpy(pubKey, key->pubKey, size);
    return (! pubKey || size <= pkLen) ? size : 0;
}

// returns the ripemd160 hash of the sha256 hash of the public key
UInt160 BRKeyHash160(BRKey *key)
{
    UInt160 hash = UINT160_ZERO;
    size_t len;
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    len = BRKeyPubKey(key, NULL, 0);
    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, len)) BRHash160(&hash, key->pubKey, len);
    return hash;
}

// writes the pay-to-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t BRKeyAddress(BRKey *key, char *addr, size_t addrLen)
{
    UInt160 hash;
    uint8_t data[21];

    assert(key != NULL);
    
    hash = BRKeyHash160(key);
    data[0] = BRNetworkIsTestnet() ? BITCOIN_PUBKEY_ADDRESS_TEST : DIGIBYTE_PUBKEY_LEGACY;
    UInt160Set(&data[1], hash);

    if (! UInt160IsZero(hash)) {
        addrLen = BRBase58CheckEncode(addr, addrLen, data, sizeof(data));
    }
    else addrLen = 0;
    
    return addrLen;
}

// writes the pay-to-witness-pubkeyhash address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t BRKeySegwitAddress(BRKey* key, char* addr, size_t addrLen, uint8_t segwitVersion) {
    assert(key->compressed != 0);
    
    uint8_t data[91] = { '\0' };
    char result[91] = { '\0' };
    size_t count;
    
    data[0] = segwitVersion;
    data[1] = sizeof(UInt160); // ripemd160
    
    UInt160 hash = BRKeyHash160(key);
    memcpy(&data[2], &hash, sizeof(UInt160));
    
    count = BRBech32Encode(&result[0], BRDigiByteBech32Hrp(), &data[0]);
    assert(count < addrLen);

    if (addr && count < addrLen)
        // copy the result
        memcpy(addr, &result[0], count);
    else
        return 0;
    
    return count;
}

// signs md with key and writes signature to sig
// returns the number of bytes written, or sigLen needed if sig is NULL
// returns 0 on failure
size_t BRKeySign(const BRKey *key, void *sig, size_t sigLen, UInt256 md)
{
    secp256k1_ecdsa_signature s;
    
    assert(key != NULL);
    
    if (secp256k1_ecdsa_sign(_ctx, &s, md.u8, key->secret.u8, secp256k1_nonce_function_rfc6979, NULL)) {
        if (! secp256k1_ecdsa_signature_serialize_der(_ctx, sig, &sigLen, &s)) sigLen = 0;
    }
    else sigLen = 0;
    
    return sigLen;
}

// returns true if the signature for md is verified to have been made by key
int BRKeyVerify(BRKey *key, UInt256 md, const void *sig, size_t sigLen)
{
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature s;
    size_t len;
    int r = 0;
    
    assert(key != NULL);
    assert(sig != NULL || sigLen == 0);
    assert(sigLen > 0);
    
    len = BRKeyPubKey(key, NULL, 0);
    
    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, len) &&
        secp256k1_ecdsa_signature_parse_der(_ctx, &s, sig, sigLen)) {
        if (secp256k1_ecdsa_verify(_ctx, &s, md.u8, &pk) == 1) r = 1; // success is 1, all other values are fail
    }
    
    return r;
}

// wipes key material from key
void BRKeyClean(BRKey *key)
{
    assert(key != NULL);
    var_clean(key);
}

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
size_t BRKeyCompactSign(const BRKey *key, void *compactSig, size_t sigLen, UInt256 md)
{
    size_t r = 0;
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature s;

    assert(key != NULL);
    assert(sigLen >= 65 || compactSig == NULL);

    if (! UInt256IsZero(key->secret)) { // can't sign with a public key
        if (compactSig && sigLen >= 65 &&
            secp256k1_ecdsa_sign_recoverable(_ctx, &s, md.u8, key->secret.u8, secp256k1_nonce_function_rfc6979, NULL) &&
            secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, (uint8_t *)compactSig + 1, &recid, &s)) {
            ((uint8_t *)compactSig)[0] = 27 + recid + (key->compressed ? 4 : 0);
            r = 65;
        }
        else if (! compactSig) r = 65;
    }
    
    return r;
}

// assigns pubKey recovered from compactSig to key and returns true on success
int BRKeyRecoverPubKey(BRKey *key, UInt256 md, const void *compactSig, size_t sigLen)
{
    int r = 0, compressed = 0, recid = 0;
    uint8_t pubKey[65];
    size_t len = sizeof(pubKey);
    secp256k1_ecdsa_recoverable_signature s;
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(compactSig != NULL);
    assert(sigLen == 65);
    
    if (sigLen == 65) {
        if (((uint8_t *)compactSig)[0] - 27 >= 4) compressed = 1;
        recid = (((uint8_t *)compactSig)[0] - 27) % 4;
        
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, &s, (const uint8_t *)compactSig + 1, recid) &&
            secp256k1_ecdsa_recover(_ctx, &pk, &s, md.u8) &&
            secp256k1_ec_pubkey_serialize(_ctx, pubKey, &len, &pk,
                                          (compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))) {
            r = BRKeySetPubKey(key, pubKey, len);
        }
    }

    return r;
}

// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). `tag` is a
// NUL-terminated ASCII string; writes the 32-byte result to *out.
//
// The doubled tag-hash prefix is concatenated with msg into a heap buffer
// (rather than a stack buffer/VLA sized by the caller-controlled msgLen) —
// this codebase already fixed one stack-overflow bug from a length-driven
// stack VLA (BRPeerSendMessage, oversized-inv DoS), so a runtime-sized
// buffer here is allocated on the heap on purpose.
void BRKeyTaggedHash(const char *tag, const uint8_t *msg, size_t msgLen, UInt256 *out)
{
    UInt256 tagHash;
    size_t bufLen = sizeof(tagHash) * 2 + msgLen;

    assert(tag != NULL);
    assert(msg != NULL || msgLen == 0);
    assert(out != NULL);

    BRSHA256(tagHash.u8, tag, strlen(tag));

    uint8_t *buf = malloc(bufLen);
    assert(buf != NULL);
    memcpy(buf, tagHash.u8, sizeof(tagHash));
    memcpy(buf + sizeof(tagHash), tagHash.u8, sizeof(tagHash));
    if (msgLen > 0) memcpy(buf + sizeof(tagHash)*2, msg, msgLen);

    BRSHA256(out->u8, buf, bufLen);

    mem_clean(buf, bufLen);
    free(buf);
}

// BIP-340 Schnorr-signs the 32-byte message/digest md with key's UNTWEAKED
// secret key, writing a 64-byte signature to sig64. Returns 64 on success,
// 0 on failure.
//
// aux_rand is passed as NULL (secp256k1_schnorrsig_sign32 treats NULL the
// same as an all-zero 32-byte buffer per its own doc comment), making this
// primitive a deterministic function of (key, md) — useful for reproducible
// signing and testing. This is the raw BIP-340 primitive: no BIP-341
// taptweak is applied here; a caller that needs a taproot output-key
// signature must tweak key->secret before calling this.
size_t BRKeySchnorrSign(BRKey *key, uint8_t *sig64, UInt256 md)
{
    secp256k1_keypair kp;
    size_t r = 0;

    assert(key != NULL);
    assert(sig64 != NULL);

    pthread_once(&_ctx_once, _ctx_init);

    if (secp256k1_keypair_create(_ctx, &kp, key->secret.u8) &&
        secp256k1_schnorrsig_sign32(_ctx, sig64, md.u8, &kp, NULL)) {
        r = 64;
    }
    var_clean(&kp);

    return r;
}

// BIP-341 key-path (BIP-86) tap-tweaked Schnorr sign. `key` holds the UNTWEAKED
// child secret d; this applies the BIP-86 taptweak INTERNALLY and signs md for
// the output key Q, writing a 64-byte signature to sig64. Returns 64 on
// success, 0 on failure.
//
// Steps: P = x-only(pubkey(d)); t = TaggedHash("TapTweak", P) -- BIP-86 uses an
// EMPTY script tree, so NO merkle root is appended (identical tweak to
// BRKeyTaprootOutputKey). The keypair is tweaked with
// secp256k1_keypair_xonly_tweak_add, which negates d as needed so the result
// signs for the even-Y output key Q = P + t*G (the x-only key a P2TR UTXO locks
// to); the parity handling required by BIP-341 is done inside secp256k1 rather
// than by hand here. The produced signature verifies under X(Q).
//
// aux_rand is passed as NULL (secp256k1_schnorrsig_sign32 treats NULL the same
// as a 32-byte all-zero buffer), making this a deterministic function of
// (key, md) -- which is exactly how the BIP-341 wallet-test-vectors key-path
// witness signatures were produced (aux = 32 zero bytes), so this reproduces
// them byte-for-byte. Production nonce randomization is left to a later phase,
// as with BRKeySchnorrSign.
size_t BRKeyTaprootSchnorrSign(BRKey *key, uint8_t *sig64, UInt256 md)
{
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xo;
    uint8_t p32[32];
    UInt256 t = UINT256_ZERO;
    size_t r = 0;

    assert(key != NULL);
    assert(sig64 != NULL);

    pthread_once(&_ctx_once, _ctx_init);

    if (secp256k1_keypair_create(_ctx, &kp, key->secret.u8) &&
        secp256k1_keypair_xonly_pub(_ctx, &xo, NULL, &kp) &&
        secp256k1_xonly_pubkey_serialize(_ctx, p32, &xo)) {

        BRKeyTaggedHash("TapTweak", p32, sizeof(p32), &t); // BIP-86: no merkle root

        if (secp256k1_keypair_xonly_tweak_add(_ctx, &kp, t.u8) && // parity handled internally
            secp256k1_schnorrsig_sign32(_ctx, sig64, md.u8, &kp, NULL)) {
            r = 64;
        }
    }

    var_clean(&kp);
    var_clean(&t);

    return r;
}

// BIP-86 key-path-only Taproot output key. P = x-only(pubkey(key));
// t = TaggedHash("TapTweak", P) -- BIP-86 always uses an EMPTY script tree,
// so NO merkle root is appended to the tagged hash (that omission is the
// entire point of key-path-only spending: the general BIP-341 tweak is
// TaggedHash("TapTweak", P || merkle_root), and an empty script tree means
// merkle_root is the empty byte string, i.e. nothing appended at all).
// Q = P + t*G; writes the 32-byte x-only serialization X(Q) to out32.
// Returns 1 on success, 0 on failure.
int BRKeyTaprootOutputKey(BRKey *key, uint8_t out32[32])
{
    secp256k1_pubkey pk, pkQ;
    secp256k1_xonly_pubkey xo;
    uint8_t pubKey[65], p32[32];
    size_t len;
    UInt256 t;
    int r = 0;

    assert(key != NULL);
    assert(out32 != NULL);

    pthread_once(&_ctx_once, _ctx_init);

    len = BRKeyPubKey(key, pubKey, sizeof(pubKey));

    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, pubKey, len) &&
        secp256k1_xonly_pubkey_from_pubkey(_ctx, &xo, NULL, &pk) &&
        secp256k1_xonly_pubkey_serialize(_ctx, p32, &xo)) {

        BRKeyTaggedHash("TapTweak", p32, sizeof(p32), &t);

        if (secp256k1_xonly_pubkey_tweak_add(_ctx, &pkQ, &xo, t.u8) &&
            secp256k1_xonly_pubkey_from_pubkey(_ctx, &xo, NULL, &pkQ) &&
            secp256k1_xonly_pubkey_serialize(_ctx, out32, &xo)) {
            r = 1;
        }
    }

    var_clean(&t);
    return r;
}

// writes the BIP-86 key-path-only P2TR (Taproot) address for key to addr:
// {OP_1, 0x20, X(Q)} bech32m-encoded (BIP-350) with the DigiByte witness hrp.
// returns the number of bytes written, or 0 on failure
size_t BRKeyTaprootAddress(BRKey *key, char *addr, size_t addrLen)
{
    uint8_t data[91] = { '\0' };
    char result[91] = { '\0' };
    size_t count;

    assert(key != NULL);

    data[0] = OP_1;
    data[1] = 32; // x-only output key length

    if (! BRKeyTaprootOutputKey(key, &data[2])) return 0;

    count = BRBech32Encode(&result[0], BRDigiByteBech32Hrp(), &data[0]);
    assert(count < addrLen);

    if (addr && count < addrLen)
        // copy the result
        memcpy(addr, &result[0], count);
    else
        return 0;

    return count;
}
