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

#ifdef __cplusplus
}
#endif

#endif // BRWalletFilterElements_h
