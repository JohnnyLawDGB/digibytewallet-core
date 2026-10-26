//
//  BRStrandedSend.h
//
//  The stranded-send sweep's decision: for one send the wallet recorded and has not yet seen
//  settle, whether to re-publish it now, hold it, or settle it (leave the sweep's working set).
//
//  A send can strand: the process dies during a Dandelion++ embargo, or every peer that took
//  it dropped it. The sweep re-publishes such sends, and the decision of which ones must be
//  the same on every platform: a re-published CONFIRMED send is not harmless (every peer sees
//  this wallet announce an old send of its own, on a timer, for as long as it runs), and an
//  unconfirmed one re-published without bound floods the network. Android had a confirmed
//  send re-published every 90 s (measured on the Note 8, 2026-09-26) until this rule.
//
//  The rule, from the wallet's own listing of its transactions:
//    - listed at a confirmed height                 -> SETTLE_CONFIRMED
//    - listed unconfirmed, or at a height that cannot be read
//                                                   -> REPUBLISH, BR_STRANDED_MAX_ATTEMPTS times
//                                                      in a row, then HOLD until
//                                                      BR_STRANDED_HOLD_MS has passed since the
//                                                      last attempt, then once more, and so on
//    - not listed, and the listing is FULL          -> SETTLE_AGED_OUT (older than every listed
//                                                      row, so confirmed)
//    - not listed otherwise                         -> REPUBLISH up to BR_STRANDED_MAX_ATTEMPTS
//                                                      times (a send recorded a moment before
//                                                      the wallet registered it), then
//                                                      SETTLE_GAVE_UP
//
//  "Full" exists because Android's listing is CAPPED (the BR_STRANDED_WINDOW most recent
//  rows). The wallet orders transactions by height and an unconfirmed one carries the greatest
//  height of all, so a capped listing names every unconfirmed transaction, and one that has
//  aged out of it has confirmed. A listing of nothing but unconfirmed rows says nothing about
//  what fell out (an unconfirmed parent is older than all of them), so it is full only when at
//  least one listed row is confirmed (BRStrandedListingIsFull). A platform that lists the
//  WHOLE wallet (iOS, from a locked snapshot) never has a full listing: a send that would
//  age out of Android's window is listed there at its confirmed height, and settles as
//  SETTLE_CONFIRMED. Both settle; neither re-publishes.
//
//  A listing the wallet could not produce, or an empty one, decides nothing: the caller must
//  not call this at all on its account (Android: a blank details text skips the sweep).
//
//  Until 2026-10 this rule lived in Kotlin (StrandedSendSelector.kt), out of reach of the iOS
//  build. Its unit tests are carried over case for case in the host KAT.
//
//  The refusal hold (below BRStrandedSendIsConflicted) decides when the sweep removes a send the
//  network refused, which unlocks its coins (Android 4.1.0, PublishOutcome.actionFor and
//  RefusalHold.kt; the conflicted verdict holds the same way since 4.1.2).
//
//  Host KATs: digibytewallet-android native/src/test/host/stranded_send_kat/ and
//  native/src/test/host/refusal_hold_kat/.
//  Header-only, static inline, no state of its own (the refusal hold's is the caller's).
//

#ifndef BRStrandedSend_h
#define BRStrandedSend_h

#include "BRTransaction.h"   // TX_UNCONFIRMED
#include "BRPublishOutcome.h" // BRPublishOutcomeOf: the terminal verdict
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Rows Android's transaction listing is capped at (its most recent).
#define BR_STRANDED_WINDOW        100u
// Re-publishes of one send before the sweep holds it (or, for a send the wallet does not hold,
// gives it up).
#define BR_STRANDED_MAX_ATTEMPTS  3u
// How long a held send waits, after its last attempt, before the sweep tries it once more:
// one hour. A plain literal, so Swift's C importer sees it (it skips expression macros).
#define BR_STRANDED_HOLD_MS       3600000LL

typedef enum {
    BRStrandedRepublish = 0,     // re-publish now; the caller counts the attempt
    BRStrandedHold,              // unconfirmed, attempt cap reached within the hold: leave it
    BRStrandedSettleConfirmed,   // listed at a confirmed height
    BRStrandedSettleAgedOut,     // not listed although the listing is full: confirmed
    BRStrandedSettleGaveUp       // not held by the wallet after every attempt
} BRStrandedAction;

// A height the wallet has confirmed: above 0 and below TX_UNCONFIRMED. A platform that cannot
// read a row's height passes 0, which (like the unconfirmed sentinel) is not confirmed.
static inline int BRStrandedHeightIsConfirmed(uint32_t height)
{
    return height > 0 && height < (uint32_t)TX_UNCONFIRMED;
}

// Whether a CAPPED listing has aged rows out: at capacity, and anchored by a confirmed row.
// A listing of the whole wallet is never full; pass 0 for it.
static inline int BRStrandedListingIsFull(size_t rows, size_t confirmedRows)
{
    return rows >= BR_STRANDED_WINDOW && confirmedRows > 0;
}

// True when the send leaves the sweep's working set.
static inline int BRStrandedActionSettles(BRStrandedAction action)
{
    return action != BRStrandedRepublish && action != BRStrandedHold;
}

// The decision for one recorded send.
//   listed          the wallet's listing names the send
//   height          its height as listed (0 when it cannot be read); ignored when not listed
//   listingFull     BRStrandedListingIsFull of the listing (always 0 for a whole-wallet one)
//   attempts        the sweep's attempt count for this send
//   lastAttemptMs   wall-clock time of the last attempt
//   nowMs           wall-clock time now
// Time differences wrap as two's complement (as Kotlin's Long does): a clock that went back
// reads as "still inside the hold".
static inline BRStrandedAction BRStrandedSendDecide(int listed, uint32_t height, int listingFull,
                                                    uint32_t attempts, int64_t lastAttemptMs,
                                                    int64_t nowMs)
{
#ifdef STRANDED_SEND_UNFIXED
    // RED ARM SEAM (stranded_send_kat): the sweep before the rule. Anything not listed at a
    // confirmed height is re-published, every sweep, without bound.
    (void)listingFull; (void)attempts; (void)lastAttemptMs; (void)nowMs;
    if (listed && BRStrandedHeightIsConfirmed(height)) return BRStrandedSettleConfirmed;
    return BRStrandedRepublish;
#else
    if (listed) {
        int64_t since = (int64_t)((uint64_t)nowMs - (uint64_t)lastAttemptMs);

        if (BRStrandedHeightIsConfirmed(height)) return BRStrandedSettleConfirmed;
        if (attempts >= BR_STRANDED_MAX_ATTEMPTS && since < BR_STRANDED_HOLD_MS) return BRStrandedHold;
        return BRStrandedRepublish;
    }
    if (listingFull) return BRStrandedSettleAgedOut;
    return (attempts >= BR_STRANDED_MAX_ATTEMPTS) ? BRStrandedSettleGaveUp : BRStrandedRepublish;
#endif
}

// A send the wallet holds but can never confirm: another transaction spent one of its inputs
// (BRWalletTransactionIsValid is 0; it is 1 for a hash the wallet does not hold). When the
// decision above is BRStrandedRepublish and the send is conflicted, it is REMOVED instead of
// re-published, through the manager when there is one (BRPeerManagerRemoveTransaction, so the
// publish list and the wallet agree), and its record is dropped: re-flooding it forever is the
// only alternative, since it cannot confirm. Only this authoritative signal removes a send, never
// a missing relay, so a valid but slow send is never dropped. (Android's SyncService sweep; on
// Android the asset rows such a send leaves behind are cleaned too.)
//
// Since Android 4.1.2 the conflicted verdict must also HOLD before the send is removed: the core
// marks invalid an unconfirmed send that lost an ordering race to another unconfirmed wallet
// transaction, and that send can still be the one that confirms. So the caller passes the
// verdict through a BRStrandedRefusalHold of its own (refused = conflicted; one slot per send,
// never the slot of the same send's peer refusal, below) and removes the send only once
// BRStrandedRefusalHoldObserve answers 1 (Android: InvalidSendRemoval.kt).
static inline int BRStrandedSendIsConflicted(int listed, int valid)
{
    return listed && ! valid;
}

// ---- A send the network refused: removed, and its coins unlocked, only on all of this ----
//
// From Android 4.1.0 (PublishOutcome.actionFor, RefusalHold.kt; the sweep in SyncService). The
// sweep removes a recorded send, which gives its coins back to the wallet, and forgets its
// record, only when all three hold:
//
//   1. its last publish ended in a TERMINAL verdict (BRPublishOutcomeOf(error).isTerminal: EINVAL);
//   2. it is a PLAIN DGB send (BRStrandedSendIsPlainDgb): an asset or DigiDollar send keeps its
//      own handling, since the asset layer reads an abandoned attempt from the wallet;
//   3. the core calls it refused BY THE NETWORK (BRPeerManagerTxRefusedByNetwork: peers in at
//      least two network groups rejected it and no peer relayed, announced or asked for it),
//      and that answer has HELD (BRStrandedRefusalHoldObserve): refused at two observations at
//      least BR_STRANDED_REFUSAL_HOLD_MS apart, on one peer manager, and at every observation
//      in between.
//
// No single peer's message removes a send. A terminal verdict can be one peer's rejection, and a
// peer can reject a valid transaction honest peers already relayed: removing it would give its
// coins back, the user would pay again with other coins, and both payments could confirm. The
// network's answer can also come moments after a peer manager starts, before every connected
// peer has answered, and a rebuilt manager starts with no relay evidence; hence the hold, on one
// manager. Anything else keeps the send: its coins stay locked and the sweep carries on.

// The refusal hold: ten minutes, about seven sweeps at Android's 90-second cadence. A plain
// literal, so Swift's C importer sees it.
#define BR_STRANDED_REFUSAL_HOLD_MS  600000LL

typedef enum {
    BRStrandedRefusalKeep = 0,            // carry on as before: validity check, bounded republish
    BRStrandedRefusalRemoveAndUnlock = 1  // remove the send from the wallet (unlocks its coins), forget its record
} BRStrandedRefusalAction;

// Whether a recorded send moves only DGB, from the wallet's own copy of it. Every input fails
// closed: anything that is not exactly "held, no asset, no DigiDollar" is not plain.
//   held            the wallet holds the send (its copy could be read)
//   containsAsset   BRTXContainsAsset of that copy: 0 for none; nonzero for an asset transfer,
//                   or when it could not be read
//   digiDollarType  BRDigiDollarTxType of that copy: 0 for none, 1-3 for a DigiDollar
//                   transaction, negative when it could not be read
// (Android: SyncService.isPlainDgbSend, which reads both through NativeBridge.)
static inline int BRStrandedSendIsPlainDgb(int held, int containsAsset, int digiDollarType)
{
    return held && containsAsset == 0 && digiDollarType == 0;
}

// The sweep's action on a recorded send.
//   publishError    the errno of its last publish (BRPublishOutcomeOf); a send with no verdict
//                   yet passes -1 (Android's PENDING), which is not terminal
//   plainDgb        BRStrandedSendIsPlainDgb
//   refusedByPeers  BRStrandedRefusalHoldObserve's answer for the send's network refusal
static inline BRStrandedRefusalAction BRStrandedRefusalActionFor(int publishError, int plainDgb,
                                                                 int refusedByPeers)
{
    int terminal = BRPublishOutcomeOf(publishError).isTerminal;

#if defined(STRANDED_REFUSAL_RED_NO_PLAIN_GATE)
    // RED ARM SEAM (refusal_hold_kat): no plain-DGB gate; an asset or DigiDollar send is removed too.
    (void)plainDgb;
    return (terminal && refusedByPeers) ? BRStrandedRefusalRemoveAndUnlock : BRStrandedRefusalKeep;
#elif defined(STRANDED_REFUSAL_RED_ONE_PEER)
    // RED ARM SEAM (refusal_hold_kat): one peer's terminal rejection removes the send.
    (void)refusedByPeers;
    return (terminal && plainDgb) ? BRStrandedRefusalRemoveAndUnlock : BRStrandedRefusalKeep;
#else
    return (terminal && plainDgb && refusedByPeers) ? BRStrandedRefusalRemoveAndUnlock
                                                    : BRStrandedRefusalKeep;
#endif
}

// One send's first sighting of a refusal, kept by the caller, one per send (and one more per
// send for the conflicted verdict, above). All zeroes (= {0}) is "no sighting": a new session
// starts with none, and nothing here is ever persisted.
typedef struct {
    int sighted;          // 0: no sighting; the other fields mean nothing
    int64_t firstSeenMs;  // the clock when the refusal was first seen
    int64_t manager;      // the peer manager it was seen on
} BRStrandedRefusalHold;

// Drops the send's first sighting: the send has left the sweep.
static inline void BRStrandedRefusalHoldForget(BRStrandedRefusalHold *hold)
{
    if (hold) { hold->sighted = 0; hold->firstSeenMs = 0; hold->manager = 0; }
}

// Records one observation of the core's answer for a send, and returns 1 only once the refusal
// has held for holdMs (BR_STRANDED_REFUSAL_HOLD_MS) on one peer manager.
//   refused         the core's answer, read BETWEEN the two readings of the manager
//   beforeKnown, managerBefore / afterKnown, managerAfter
//                   the peer manager (Android: the bridge's generation, which every build bumps)
//                   read before and after the answer; known = 0 when it could not be read
//   nowMs           a clock that never steps back and does not run while the device sleeps
//                   (Android: SystemClock.uptimeMillis)
// An answer that is not a refusal, during which the manager changed, or whose manager is unknown
// is no sighting, and drops the first sighting: the refusal must hold again from the start. A
// first sighting made on another manager starts again on this one, so a hold started on one
// manager never completes on another. A clock reading earlier than the first sighting never
// counts as time held (differences wrap as Kotlin's Long does). holdMs <= 0 never acts (Kotlin
// refuses to build such a hold). A NULL hold answers 0.
static inline int BRStrandedRefusalHoldObserve(BRStrandedRefusalHold *hold, int refused,
                                               int beforeKnown, int64_t managerBefore,
                                               int afterKnown, int64_t managerAfter,
                                               int64_t nowMs, int64_t holdMs)
{
    if (! hold) return 0;
    if (holdMs <= 0) { BRStrandedRefusalHoldForget(hold); return 0; }

#ifdef STRANDED_REFUSAL_RED_NO_HOLD
    // RED ARM SEAM (refusal_hold_kat): the first sighting is acted on at once.
    (void)beforeKnown; (void)managerBefore; (void)afterKnown; (void)managerAfter; (void)nowMs;
    return refused ? 1 : 0;
#else
#ifdef STRANDED_REFUSAL_RED_ANY_MANAGER
    // RED ARM SEAM (refusal_hold_kat): the manager is not read; a hold spans a rebuild.
    beforeKnown = afterKnown = 1; managerBefore = managerAfter = 0;
#endif
    if (! refused || ! beforeKnown || ! afterKnown || managerBefore != managerAfter) {
        BRStrandedRefusalHoldForget(hold);
        return 0;
    }
    if (! hold->sighted || hold->manager != managerBefore) {
        hold->sighted = 1;
        hold->firstSeenMs = nowMs;
        hold->manager = managerBefore;
        return 0;
    }
    return (int64_t)((uint64_t)nowMs - (uint64_t)hold->firstSeenMs) >= holdMs;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRStrandedSend_h
