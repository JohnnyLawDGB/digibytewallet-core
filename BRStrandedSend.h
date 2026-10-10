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
//  Host KAT: digibytewallet-android native/src/test/host/stranded_send_kat/.
//  Header-only, static inline, no state.
//

#ifndef BRStrandedSend_h
#define BRStrandedSend_h

#include "BRTransaction.h"   // TX_UNCONFIRMED
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

#ifdef __cplusplus
}
#endif

#endif // BRStrandedSend_h
