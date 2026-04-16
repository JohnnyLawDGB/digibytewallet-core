//
//  BRBIP32Sequence.h
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

#ifndef BRBIP32Sequence_h
#define BRBIP32Sequence_h

#include "BRKey.h"
#include "BRInt.h"
#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

#define BIP32_HARD                  0x80000000

#define BIP84_PURPOSE               84
#define DGB_COIN_TYPE               20
#define BIP84_ACCOUNT               0

#define SEQUENCE_GAP_LIMIT_EXTERNAL_BIP84  20
#define SEQUENCE_GAP_LIMIT_INTERNAL_BIP84  10
// Legacy scan must cover all addresses the old wallet could have generated.
// Old gap limit was 10, but each received tx extends the pool. A user with
// 90 received txs would have addresses up to index ~100. Use 150/50 to be safe.
#define SEQUENCE_GAP_LIMIT_EXTERNAL_LEGACY 150
#define SEQUENCE_GAP_LIMIT_INTERNAL_LEGACY 50

#define SEQUENCE_GAP_LIMIT_EXTERNAL 10
#define SEQUENCE_GAP_LIMIT_INTERNAL 5
#define SEQUENCE_EXTERNAL_CHAIN     0
#define SEQUENCE_INTERNAL_CHAIN     1

typedef struct {
    uint32_t fingerPrint;
    UInt256 chainCode;
    uint8_t pubKey[33];
} BRMasterPubKey;

#define BR_MASTER_PUBKEY_NONE ((BRMasterPubKey) { 0, UINT256_ZERO, \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } })

// returns the master public key for the default BIP32 wallet layout - derivation path N(m/0H)
BRMasterPubKey BRBIP32MasterPubKey(const void *seed, size_t seedLen);

// returns the master public key for BIP84 — derivation path N(m/84'/20'/0')
// uses standard "Bitcoin seed" HMAC key per BIP32 spec
BRMasterPubKey BRBIP32MasterPubKeyBIP84(const void *seed, size_t seedLen);

// returns the master public key for legacy breadwallet layout — derivation path N(m/0H)
// uses "DigiByte seed" HMAC key (non-standard, for backward compatibility)
BRMasterPubKey BRBIP32MasterPubKeyLegacy(const void *seed, size_t seedLen);

// sets the private key for BIP84 path m/84'/20'/0'/chain/index
// uses "Bitcoin seed" HMAC key
void BRBIP32PrivKeyBIP84(BRKey *key, const void *seed, size_t seedLen, uint32_t chain, uint32_t index);

// batch version — sets private key for each element in keys
void BRBIP32PrivKeyListBIP84(BRKey keys[], size_t keysCount, const void *seed, size_t seedLen,
                             uint32_t chain, const uint32_t indexes[]);

// writes the public key for path N(m/0H/chain/index) to pubKey
// returns number of bytes written, or pubKeyLen needed if pubKey is NULL
size_t BRBIP32PubKey(uint8_t *pubKey, size_t pubKeyLen, BRMasterPubKey mpk, uint32_t chain, uint32_t index);

// sets the private key for path m/0H/chain/index to key
void BRBIP32PrivKey(BRKey *key, const void *seed, size_t seedLen, uint32_t chain, uint32_t index);

// sets the private key for path m/0H/chain/index to each element in keys
void BRBIP32PrivKeyList(BRKey keys[], size_t keysCount, const void *seed, size_t seedLen, uint32_t chain,
                        const uint32_t indexes[]);
    
// sets the private key for the specified path to key
// depth is the number of arguments used to specify the path
// ── Universal Restore primitives ──────────────────────────────────────────────
//
// Derive keys at arbitrary paths with a caller-supplied HMAC seed-key string
// ("Bitcoin seed" vs "DigiByte seed"). Used by the Kotlin RecoveryScanService
// to probe for funds on non-native derivation paths (BIP44 DGB, BIP44 BTC
// wrong-coin, BIP49, legacy-with-wrong-hmac, etc.) during seed restore.
//
// `hmacKey` is typically one of "Bitcoin seed" or "DigiByte seed".
// `path` is an array of child indices; apply BIP32_HARD to any segment that
// must be hardened (e.g. 44 | BIP32_HARD for BIP44's purpose level).

// returns the master public key derived at the given path prefix. Callers
// pass only the hardened prefix (e.g. m/44'/20'/0') then use BRBIP32PubKey
// with chain/index for each child address — faster than re-walking the
// prefix for every address.
BRMasterPubKey BRBIP32MasterPubKeyPath(const void *seed, size_t seedLen,
                                       const char *hmacKey,
                                       const uint32_t *path, size_t depth);

// sets the private key at an arbitrary full path. Used by the legacy-path
// sweeper to sign inputs from UTXOs the main wallet doesn't hold directly.
void BRBIP32PrivKeyArrayPath(BRKey *key, const void *seed, size_t seedLen,
                             const char *hmacKey,
                             const uint32_t *path, size_t depth);

void BRBIP32PrivKeyPath(BRKey *key, const void *seed, size_t seedLen, int depth, ...);

// sets the private key for the path specified by vlist to key
// depth is the number of arguments in vlist
void BRBIP32vPrivKeyPath(BRKey *key, const void *seed, size_t seedLen, int depth, va_list vlist);

// writes the base58check encoded serialized master private key (xprv) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t BRBIP32SerializeMasterPrivKey(char *str, size_t strLen, const void *seed, size_t seedLen);

// writes a master private key to seed given a base58check encoded serialized master private key (xprv)
// returns number of bytes written, or seedLen needed if seed is NULL
size_t BRBIP32ParseMasterPrivKey(void *seed, size_t seedLen, const char *str);

// writes the base58check encoded serialized master public key (xpub) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t BRBIP32SerializeMasterPubKey(char *str, size_t strLen, BRMasterPubKey mpk);

// returns a master public key give a base58check encoded serialized master public key (xpub)
BRMasterPubKey BRBIP32ParseMasterPubKey(const char *str);

// key used for authenticated API calls, i.e. bitauth: https://github.com/bitpay/bitauth - path m/1H/0
void BRBIP32APIAuthKey(BRKey *key, const void *seed, size_t seedLen);

// key used for BitID: https://github.com/bitid/bitid/blob/master/BIP_draft.md
void BRBIP32BitIDKey(BRKey *key, const void *seed, size_t seedLen, uint32_t index, const char *uri);

#ifdef __cplusplus
}
#endif

#endif // BRBIP32Sequence_h
