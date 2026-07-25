//
//  BRWalletFilterElements.h
//
//  Wallet-side element list for BIP 158 compact-filter matching.
//  Snapshots every address the wallet derives (used and unused
//  within the gap-limit window) and emits the canonical scriptPubKey
//  bytes — exactly the elements BIP 158 §Contents tells full nodes
//  to insert into the basic filter.
//
//  Matching is purely local: pass the element list to
//  BRGCSFilterMatchAny on a decoded filter to test whether any
//  wallet-relevant tx might live in the corresponding block.
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#ifndef BRWalletFilterElements_h
#define BRWalletFilterElements_h

#include <stddef.h>
#include <stdint.h>
#include "BRWallet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t count;
    const uint8_t **elements;  // pointers into the packed `backing` buffer
    size_t *elementLens;       // parallel array of lengths
    uint8_t *backing;          // packed element bytes; do not free directly
} BRWalletFilterElements;

/**
 * Snapshot the wallet's current address set into a BIP 158 element list.
 *
 * Caller is responsible for any gap-limit pre-derivation it needs
 * (see _BRPeerManagerPregenAddrWindow, which maintains this gap+100
 * look-ahead window on the compact-filter path).
 *
 * Returns NULL on allocation failure or if the wallet has no addresses.
 * Free with BRWalletFilterElementsFree.
 */
BRWalletFilterElements *BRWalletGetFilterElements(BRWallet *wallet);

/** Releases all memory associated with the element list. Accepts NULL. */
void BRWalletFilterElementsFree(BRWalletFilterElements *fe);

/**
 * Counters from the most recent BRWalletGetFilterElements build.
 *
 * There is deliberately no DigiDollar bucket: a DD address (Base58Check over a 34-byte
 * payload) has no encodable scriptPubKey and needs none — a DD token output is a plain
 * P2TR script, so its 34-byte element is already emitted by the taproot chain.
 */
typedef struct {
    size_t addrs;          // addresses enumerated from the wallet
    size_t elements;       // filter elements actually produced
    size_t derived;        // elements sourced from the derived chains
    size_t watched;        // elements sourced from explicitly-watched pins
    size_t dropped;        // addresses with no encodable scriptPubKey (silently skipped pre-fix)
    size_t allocFailures;  // sticky: builds abandoned on an allocation failure
    char   firstDroppedPrefix[7]; // first 6 chars of the first dropped address, never the full string
} BRWalletFilterElementsStats;

/**
 * Copy the last build's counters. Pass the wallet to assert ownership (a KAT with two
 * wallets must not read the other's counters), or NULL to accept whichever wallet built
 * last. Returns 1 if `out` was populated, 0 if no build has happened for that wallet.
 *
 * Takes only a private leaf mutex — never PEER_GUARD, never wallet->lock — so it is safe
 * to call from a JNI getter on any thread.
 */
int BRWalletFilterElementsGetStats(const BRWallet *wallet, BRWalletFilterElementsStats *out);

#ifdef __cplusplus
}
#endif

#endif // BRWalletFilterElements_h
