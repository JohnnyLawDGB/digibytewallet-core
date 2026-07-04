//
//  BRKey.h
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

#ifndef BRKey_h
#define BRKey_h

#include "BRInt.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t p[33];
} BRECPoint;

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int BRSecp256k1ModAdd(UInt256 *a, const UInt256 *b);

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int BRSecp256k1ModMul(UInt256 *a, const UInt256 *b);

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
int BRSecp256k1PointGen(BRECPoint *p, const UInt256 *i);

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p
// returns true on success
int BRSecp256k1PointAdd(BRECPoint *p, const UInt256 *i);

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p
// returns true on success
int BRSecp256k1PointMul(BRECPoint *p, const UInt256 *i);

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int BRPrivKeyIsValid(const char *privKey);

typedef struct {
    UInt256 secret;
    uint8_t pubKey[65];
    int compressed;
} BRKey;

// assigns secret to key and returns true on success
int BRKeySetSecret(BRKey *key, const UInt256 *secret, int compressed);

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int BRKeySetPrivKey(BRKey *key, const char *privKey);

// assigns DER encoded pubKey to key and returns true on success
int BRKeySetPubKey(BRKey *key, const uint8_t *pubKey, size_t pkLen);

// writes the WIF private key to privKey and returns the number of bytes writen, or pkLen needed if privKey is NULL
// returns 0 on failure
size_t BRKeyPrivKey(const BRKey *key, char *privKey, size_t pkLen);

// writes the DER encoded public key to pubKey and returns number of bytes written, or pkLen needed if pubKey is NULL
size_t BRKeyPubKey(BRKey *key, void *pubKey, size_t pkLen);

// returns the ripemd160 hash of the sha256 hash of the public key, or UINT160_ZERO on error
UInt160 BRKeyHash160(BRKey *key);

// writes the pay-to-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t BRKeyAddress(BRKey *key, char *addr, size_t addrLen);
    
// writes the pay-to-witness-pubkeyhash address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t BRKeySegwitAddress(BRKey* key, char* addr, size_t addrLen, uint8_t segwitVersion);

// signs md with key and writes signature to sig
// returns the number of bytes written, or sigLen needed if sig is NULL
// returns 0 on failure
size_t BRKeySign(const BRKey *key, void *sig, size_t sigLen, UInt256 md);

// returns true if the signature for md is verified to have been made by key
int BRKeyVerify(BRKey *key, UInt256 md, const void *sig, size_t sigLen);

// wipes key material from key
void BRKeyClean(BRKey *key);

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
size_t BRKeyCompactSign(const BRKey *key, void *compactSig, size_t sigLen, UInt256 md);

// assigns pubKey recovered from compactSig to key and returns true on success
int BRKeyRecoverPubKey(BRKey *key, UInt256 md, const void *compactSig, size_t sigLen);

// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). `tag` is a
// NUL-terminated ASCII string (e.g. "BIP0340/challenge", "TapTweak"); `msg`/
// `msgLen` is the payload to hash after the doubled tag-hash prefix. Writes
// the 32-byte result to *out.
void BRKeyTaggedHash(const char *tag, const uint8_t *msg, size_t msgLen, UInt256 *out);

// BIP-340 Schnorr-signs the 32-byte message/digest md with key's UNTWEAKED
// secret key, writing a 64-byte signature to sig64. Returns 64 on success,
// 0 on failure. This is the raw BIP-340 primitive: it does not apply any
// BIP-341 taptweak to the key -- callers that need a taproot output-key
// signature must tweak key->secret before calling this.
size_t BRKeySchnorrSign(BRKey *key, uint8_t *sig64, UInt256 md);

// BIP-341 key-path (BIP-86) tap-tweaked Schnorr sign. `key` holds the
// UNTWEAKED child secret d; this applies the BIP-86 taptweak
// (t = TaggedHash("TapTweak", x-only(pubkey(d))), NO merkle root -- empty
// script tree) INTERNALLY via secp256k1_keypair_xonly_tweak_add (which handles
// the BIP-341 key-negation/parity) and signs md for the output key
// Q = P + t*G, writing a 64-byte signature to sig64. Returns 64 on success,
// 0 on failure. The signature verifies under the x-only output key X(Q) -- the
// key a BIP-86 P2TR UTXO locks to. aux_rand is NULL (deterministic), matching
// how the BIP-341 wallet test vectors' key-path witness signatures were made.
size_t BRKeyTaprootSchnorrSign(BRKey *key, uint8_t *sig64, UInt256 md);

// BIP-86 key-path-only Taproot output key: P = x-only(pubkey(key));
// t = TaggedHash("TapTweak", P) (NO merkle root appended -- BIP-86 always
// uses an empty script tree, which is the entire point of key-path-only
// spending); Q = P + t*G. Writes the 32-byte x-only serialization X(Q) to
// out32. Returns 1 on success, 0 on failure.
int BRKeyTaprootOutputKey(BRKey *key, uint8_t out32[32]);

// writes the BIP-86 key-path-only P2TR (Taproot) address for key to addr:
// {OP_1, 0x20, X(Q)} bech32m-encoded (BIP-350) with the DigiByte witness hrp.
// returns the number of bytes written, or 0 on failure
size_t BRKeyTaprootAddress(BRKey *key, char *addr, size_t addrLen);

#ifdef __cplusplus
}
#endif

#endif // BRKey_h
