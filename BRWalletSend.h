//
//  BRWalletSend.h
//
//  The rules a platform must follow around BRPeerManagerPublishTx, shared so iOS and Android
//  follow them identically. Until 2026-10 they lived in the Android JNI bridge
//  (jni_transaction.c: _registerWalletCopy and the publish-result ring), which the iOS
//  XCFramework does not contain. This header carries rules 1 and 2; steps 0 and 1b below are
//  the rest of every Android publish path (since 4.1.2) and are not in this header.
//
//  The order, as every Android publish path runs it (publishTransaction, publishTransactionStem,
//  sendApprovedDigiDollar):
//
//     0. tx = BRTransactionParseSigned(bytes)       -- only where the send arrives as bytes
//     1. BRWalletRegisterOwnSend(wallet, tx)        -- rule 1 below (Android: _registerWalletCopy)
//    1b. coin_reservation_release(tx->txHash)       -- immediately after 1, never before
//     2. BRPeerManagerPublishTx(manager, tx, ctx, cb) with cb recording into a BRPublishRing
//
//  0. PARSE PUBLISH BYTES AS SIGNED. A send handed to the publish as serialized bytes (Android's
//     publishTransaction and publishTransactionStem; the DigiDollar path builds and signs its tx
//     in-process and has no bytes to parse) is read with BRTransactionParseSigned, never
//     BRTransactionParse: the latter may read a signed input whose scriptSig also looks like a
//     scriptPubKey as the internal unsigned form, misparse the rest, and get the txid wrong
//     (4.1.2 row 9). The wallet would then register, and key the ring by, a hash no peer echoes.
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
//     its inputs marked spent. (Step 1b, the coin-reservation release, goes between this
//     registration and the publish.)
//
//  1b. RELEASE THE COIN RESERVATION RIGHT AFTER REGISTERING. Since 4.1.2 Android's signer claims
//     a signed transaction's inputs for its txid (bridge coin_reservation.h; seed_sign_transaction)
//     and refuses to sign another transaction spending a claimed coin. The claim covers the window
//     between the signature and step 1, when the wallet does not yet hold those coins as spent.
//     Release it only AFTER step 1: releasing before the wallet's record exists reopens exactly
//     that window (a second send checked in between is signed on the same coins -- the
//     double-sign 4.1.2 closed). Never releasing is not safe either: the coins stay held for the
//     reservation's TTL (COIN_RESERVATION_TTL_S, 60 s), refusing every legitimate send that needs
//     them. Android releases unconditionally, whether or not rule 1 took a copy (a record
//     already held marks the coins spent just the same). Android gates the order with
//     native/src/test/host/coin_reservation_kat/run.sh (each _registerWalletCopy line must be
//     followed directly by the release).
//     Coin reservation lives only in Android's bridge today. A platform with more than one path
//     that signs (a send, a DigiDollar or asset send, a sweep) needs the same claim/release; it is
//     a push-down candidate for this core.
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
