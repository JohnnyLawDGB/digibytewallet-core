//
//  BRWalletSend.h
//
//  The two rules a platform must follow around BRPeerManagerPublishTx, shared so iOS and
//  Android follow them identically. Until 2026-10 both lived in the Android JNI bridge
//  (jni_transaction.c: _registerWalletCopy and the publish-result ring), which the iOS
//  XCFramework does not contain.
//
//  1. ONE OWNER PER OBJECT (BRWalletRegisterOwnSend). The wallet keeps its own record of a
//     send and the peer manager is handed the ORIGINAL to broadcast; the manager takes
//     ownership and may release it at any time, so the wallet's record must be an
//     independent COPY. The copy is made only when the wallet holds no record of the hash
//     yet: a re-publish (a stranded-send sweep, a manual retry) keeps the record it has. If
//     the wallet did not take the copy after all (a peer thread registered the hash in
//     between, or it is a confirmed transaction the wallet keeps no record of), the copy is
//     released here. The timestamp is set first because the wallet orders by it. Own sends are
//     registered TRUSTED: this wallet signed them, so no input-signature check applies
//     (BRWalletRegisterTransactionTrusted, bounty fix c7350fc).
//
//     Register BEFORE publishing, so the send is in BRWalletTransactions() the moment the
//     publish returns, and pass a NON-NULL callback to BRPeerManagerPublishTx: a NULL-callback
//     publish is never cancelled or freed, so a send the network refused stays "pending" with
//     its inputs marked spent.
//
//  2. THE PUBLISH VERDICT IS RECORDED (BRPublishRing). The publish callback fires on a peer
//     thread long after the caller returned, so the platform asks later. A fixed ring, not a
//     growing map: written on every publish for the life of the process. A re-publish
//     overwrites its own entry, so no staler verdict is found first; EALREADY is never
//     recorded (it means an earlier publish of the same transaction is still pending, and that
//     publish's callback carries the verdict). "No entry" reads as PENDING, never as accepted.
//     The ring takes no lock: the platform wraps every call in its own.
//
//  Map a recorded error to what the UI says with BRPublishOutcome.h.
//  Host KAT: digibytewallet-android native/src/test/host/wallet_send_kat/.
//  Header-only, static inline; no I/O.
//

#ifndef BRWalletSend_h
#define BRWalletSend_h

#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRInt.h"
#include <errno.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- 1. register an own send ---------------------------------------------------------------

// Registers the wallet's own record of tx, a send this wallet signed, before tx itself is
// handed to BRPeerManagerPublishTx. tx stays the caller's (and then the manager's); the wallet
// gets an independent copy, or keeps the record it already has.
static inline void BRWalletRegisterOwnSend(BRWallet *wallet, BRTransaction *tx)
{
    BRTransaction *walletCopy;

    if (! wallet || ! tx) return;
    if (! tx->timestamp) tx->timestamp = (uint32_t)time(NULL);
    if (BRWalletTransactionForHash(wallet, tx->txHash)) return;   // already held: nothing to copy

#ifdef WALLET_SEND_SAME_OBJECT_UNFIXED
    // RED-gate shape only: the wallet registers the very object the manager is about to own.
    // Never defined in a production build.
    walletCopy = tx;
#else
    walletCopy = BRTransactionCopy(tx);
#endif
    if (! walletCopy) return;                                       // the peer relay-back re-registers
    BRWalletRegisterTransactionTrusted(wallet, walletCopy);
    if (walletCopy != tx && BRWalletTransactionForHash(wallet, tx->txHash) != walletCopy) BRTransactionFree(walletCopy);
}

// ---- 2. the publish verdict ring -----------------------------------------------------------

#define BR_PUBLISH_RING_SIZE 32
#define BR_PUBLISH_PENDING   (-1)   // no verdict yet (or aged out): never read as accepted

typedef struct {
    struct {
        UInt256 txHash;
        int error;
        int used;
    } entries[BR_PUBLISH_RING_SIZE];
    size_t next;
} BRPublishRing;

// Records the verdict a publish callback delivered for txHash. Caller holds its lock.
static inline void BRPublishRingRecord(BRPublishRing *ring, UInt256 txHash, int error)
{
    size_t i;

    if (! ring) return;
#ifndef PUBLISH_RING_RECORDS_EALREADY_UNFIXED
    if (error == EALREADY) return;   // the earlier publish's callback carries the verdict
#endif
    for (i = 0; i < BR_PUBLISH_RING_SIZE; i++) {
        if (ring->entries[i].used && UInt256Eq(ring->entries[i].txHash, txHash)) {
            ring->entries[i].error = error;   // a re-publish replaces its own, older verdict
            return;
        }
    }
    i = ring->next;
    ring->next = (ring->next + 1) % BR_PUBLISH_RING_SIZE;
    ring->entries[i].txHash = txHash;
    ring->entries[i].error = error;
    ring->entries[i].used = 1;
}

// The recorded verdict for txHash (an errno, 0 = accepted), or BR_PUBLISH_PENDING.
static inline int BRPublishRingLookup(const BRPublishRing *ring, UInt256 txHash)
{
    size_t i;

    if (! ring) return BR_PUBLISH_PENDING;
    for (i = 0; i < BR_PUBLISH_RING_SIZE; i++) {
        if (ring->entries[i].used && UInt256Eq(ring->entries[i].txHash, txHash)) return ring->entries[i].error;
    }
    return BR_PUBLISH_PENDING;
}

#ifdef __cplusplus
}
#endif

#endif // BRWalletSend_h
