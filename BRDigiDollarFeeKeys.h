//
//  BRDigiDollarFeeKeys.h
//
//  The keys that sign a DigiDollar recovery transfer's fee inputs, each from the derivation its own coin
//  was found under. Until 2026-11 this lived in Android's JNI bridge
//  (native/src/main/jni/bridge/digidollar_fee_keys.h: dd_fee_input_keys). Moved unchanged. The transfer
//  itself -- its inputs, outputs and signature -- is still assembled by each platform's caller (Android:
//  the bridge's buildAndSignForeignDigiDollarTransfer); see BRDigiDollarTransferLayout.h for its shape.
//
//  The dollars of a recovered seed sit at m/86'/20'/0'; the DGB that pays their fee sits wherever the
//  scan found it -- BIP84, BIP44, the bread path -- and the fee one transfer needs may only be covered
//  by coins from two of them. So each fee input carries its own derivation: the HMAC key, the prefix,
//  and the (chain, index) of its address under that prefix. A coin signed with another derivation's key
//  is not signed at all, and the transfer is refused.
//
//  BRDigiDollarFeeInputKeys writes keys[i] for each fee input, derived from paths[i]
//  (BRBIP32PrivKeyArrayPath over prefix, chain, index). Returns 1 when every key was derived; 0 when
//  keys, paths or seed is NULL, or a path cannot be used (no HMAC key, or a prefix longer than
//  BR_DIGIDOLLAR_FEE_PATH_MAX) -- then no key is to be used: keys before the refused path have been
//  written, and the caller wipes all of them, as it does after signing. A count of 0 answers 1. seedLen
//  is passed to BRBIP32PrivKeyArrayPath as given; the caller bounds it (a BIP39 seed is 64 bytes).
//
//  Header-only, static inline; no I/O, no clock, no locking, no allocation.
//
//  Test seam (host KAT digidollar_fee_keys_core_kat in the Android repo): DIGIDOLLAR_FEE_KEYS_UNFIXED,
//  tested by VALUE (#if). =1 is the comparison arm, the behaviour before: one HMAC key and one prefix for
//  every fee input (the first one's), with only the chain and index per input. Unset or =0 is what ships.
//

#ifndef BRDigiDollarFeeKeys_h
#define BRDigiDollarFeeKeys_h

#include "BRKey.h"             // BRKey
#include "BRBIP32Sequence.h"   // BRBIP32PrivKeyArrayPath
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIGIDOLLAR_FEE_KEYS_UNFIXED
#define DIGIDOLLAR_FEE_KEYS_UNFIXED 0
#endif

#define BR_DIGIDOLLAR_FEE_PATH_MAX 8    // the longest derivation prefix a fee input may carry (the built-in profiles use one to three levels)
#define BR_DIGIDOLLAR_FEE_HMAC_MAX 64   // the longest HMAC key a fee input may name, its terminator included ("DigiByte seed" is 14)

typedef struct {
    const char *hmacKey;                           // the derivation's HMAC key: "Bitcoin seed", "DigiByte seed"
    uint32_t prefix[BR_DIGIDOLLAR_FEE_PATH_MAX];   // its prefix path, hardened levels included (e.g. 84', 20', 0')
    size_t prefixLen;
    uint32_t chain, index;                         // where the coin's address sits under that prefix
} BRDigiDollarFeeInputPath;

// keys[i] for each fee input, derived from paths[i]: 1 when every key was derived, 0 when a path cannot
// be used (no HMAC key, or a prefix longer than BR_DIGIDOLLAR_FEE_PATH_MAX) -- then no key is to be used.
static inline int BRDigiDollarFeeInputKeys(BRKey *keys, const BRDigiDollarFeeInputPath *paths, size_t count,
                                           const void *seed, size_t seedLen)
{
    uint32_t full[BR_DIGIDOLLAR_FEE_PATH_MAX + 2];

    if (! keys || ! paths || ! seed) return 0;
    for (size_t i = 0; i < count; i++) {
#if DIGIDOLLAR_FEE_KEYS_UNFIXED
        const BRDigiDollarFeeInputPath *d = &paths[0];   // one derivation for every fee input
#else
        const BRDigiDollarFeeInputPath *d = &paths[i];
#endif
        if (! d->hmacKey || d->prefixLen > BR_DIGIDOLLAR_FEE_PATH_MAX) return 0;
        memcpy(full, d->prefix, d->prefixLen * sizeof(uint32_t));
        full[d->prefixLen] = paths[i].chain;
        full[d->prefixLen + 1] = paths[i].index;
        BRBIP32PrivKeyArrayPath(&keys[i], seed, seedLen, d->hmacKey, full, d->prefixLen + 2);
    }
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiDollarFeeKeys_h
