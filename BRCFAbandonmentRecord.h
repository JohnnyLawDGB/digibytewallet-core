//
//  BRCFAbandonmentRecord.h
//
//  The abandoned compact-filter band's record, and the poll that keeps it: when a band is
//  recorded, extended, witnessed and recovered. BRCFAbandonment.h holds the pure predicates;
//  this holds the decisions the platform used to make around them (Android's
//  CfAbandonmentStore.noteAbandonment / noteScanCoverage / markRecovered and the
//  WalletViewModel poll that drives them). Each platform only PERSISTS the record, field for
//  field, and keeps the low hint in memory; what the record says, and when it changes, is decided
//  here, so two wallets on the same seed agree on whether history is still unverified (which
//  withholds "Synced": BRSyncFrontier.h's abandonedBandUnrecovered is
//  BRCFAbandonmentIsUnrecovered).
//
//  The poll (BRCFAbandonmentPoll), in Android's order:
//    1. while the valve is mid-decision (a pending abandonment) and the scan frontier is known,
//       the frontier is the band's bottom-to-be: remember it as the low hint;
//    2. a standing watermark (abandonedBelow > 0) is folded into the band (BRCFAbandonedBandNext);
//       a change is a NEW gap: not recovered, and nothing witnessed about it yet;
//    3. otherwise the ordinary scan may have re-covered the band, TWO-PHASE: the floor no longer
//       covers the band, the frontier is known, and the frontier was seen at or below the band's
//       top (phase 1, the witness, persisted) BEFORE it is seen past the top (phase 2). A floor
//       re-initialised above the band never produces a phase-1 observation, so a routine
//       reconnect cannot clear a band it never scanned;
//    4. failing that, the ledger itself may prove the band evaluated
//       (BRCFAbandonedBandCoverageIsProven: contiguous coverage from a start at or below it).
//  BRCFAbandonmentMarkRecovered is also the other recoveries' signal (an own-node reconcile that
//  covered the owned set); a full rescan clears the record (BRCFAbandonmentClear).
//
//  Host KAT: digibytewallet-android native/src/test/host/cf_abandonment_record_kat/ (Android's
//  CfAbandonmentStoreTest store cases, case for case, plus the poll's order).
//  Header-only, static inline.
//

#ifndef BRCFAbandonmentRecord_h
#define BRCFAbandonmentRecord_h

#include "BRCFAbandonment.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// What the platform persists (all zero = nothing was ever abandoned).
typedef struct {
    BRCFAbandonedBand band;     // meaningful only when hasBand
    int hasBand;
    int recovered;              // a recovery covered the band
    int sawFrontierInBand;      // phase-1 witness for the band as it now stands
} BRCFAbandonmentRecord;

// BRCFAbandonmentPoll's result bits.
#define BR_CF_ABANDON_CHANGED    1   // the record changed: persist it
#define BR_CF_ABANDON_RECORDED   2   // a new or extended band (surface it)
#define BR_CF_ABANDON_RECOVERED  4   // this poll recovered the band

// The band that still needs recovering: what the banner and the Synced gate key on.
static inline int BRCFAbandonmentIsUnrecovered(const BRCFAbandonmentRecord *r)
{
    return r->hasBand && ! r->recovered;
}

// Fold a polled watermark into the record. Returns 1 iff the band changed.
static inline int BRCFAbandonmentNote(BRCFAbandonmentRecord *r, uint32_t abandonedBelow, uint32_t lowHint)
{
    BRCFAbandonedBand next;

    if (! BRCFAbandonedBandNext(r->hasBand ? &r->band : NULL, abandonedBelow, lowHint, &next)) return 0;
    r->band = next;
    r->hasBand = 1;
    r->recovered = 0;            // a new gap is not recovered
    r->sawFrontierInBand = 0;    // ...and nothing has been observed about it yet
    return 1;
}

// A recovery covered the band. Returns 1 iff this set the signal (no band, or already
// recovered: nothing changes).
static inline int BRCFAbandonmentMarkRecovered(BRCFAbandonmentRecord *r)
{
    if (! r->hasBand || r->recovered) return 0;
    r->recovered = 1;
    return 1;
}

// The ordinary scan re-covered the band (two-phase). Returns 1 iff this call recovered it; the
// witness may be set without recovering (compare the record to know whether to persist).
static inline int BRCFAbandonmentNoteScanCoverage(BRCFAbandonmentRecord *r, uint32_t abandonedBelow,
                                                  uint32_t scanFrontier)
{
    if (! BRCFAbandonmentIsUnrecovered(r)) return 0;
    if (! BRCFAbandonedBandIsRetired(r->band.low, abandonedBelow)) return 0;   // partial retirement is not recovery
    if (scanFrontier == 0) return 0;                                           // a failed read, not an observation
    if (scanFrontier <= r->band.high) {
        r->sawFrontierInBand = 1;                                              // phase 1
        return 0;
    }
#ifndef CF_ABANDONMENT_RECORD_RED
    if (! r->sawFrontierInBand) return 0;                                      // phase 2 needs phase 1
#endif
    // RED ARM SEAM (cf_abandonment_record_kat): without the line above, a floor re-initialised at
    // the band's top clears a band the scan never covered.
    return BRCFAbandonmentMarkRecovered(r);
}

// The full rescan (or a wallet wipe): the band no longer exists.
static inline void BRCFAbandonmentClear(BRCFAbandonmentRecord *r)
{
    BRCFAbandonmentRecord zero = { { 0, 0, 0 }, 0, 0, 0 };
    *r = zero;
}

// One poll. *lowHint is the caller's in-memory hint (start it at 0; never persisted). The reads are
// the peer manager's: BRPeerManagerHasPendingAbandonment, BRPeerManagerLowestNeededHeight,
// BRPeerManagerAbandonedBelow, BRPeerManagerScanLedgerStart and BRPeerManagerCFLedgerCounts'
// scannedThrough and gaveUp; a failed read is 0. Returns BR_CF_ABANDON_* bits.
static inline int BRCFAbandonmentPoll(BRCFAbandonmentRecord *r, uint32_t *lowHint, uint32_t abandonmentPending,
                                      uint32_t scanFrontier, uint32_t abandonedBelow, uint32_t ledgerStart,
                                      uint32_t scannedThrough, size_t gaveUpCount)
{
    int sawBefore;

    if (abandonmentPending > 0 && scanFrontier > 0) *lowHint = scanFrontier;
    if (abandonedBelow > 0) {
        return BRCFAbandonmentNote(r, abandonedBelow, *lowHint) ? (BR_CF_ABANDON_CHANGED | BR_CF_ABANDON_RECORDED) : 0;
    }
    sawBefore = r->sawFrontierInBand;
    if (BRCFAbandonmentNoteScanCoverage(r, abandonedBelow, scanFrontier)) {
        return BR_CF_ABANDON_CHANGED | BR_CF_ABANDON_RECOVERED;
    }
    if (BRCFAbandonmentIsUnrecovered(r) &&
        BRCFAbandonedBandCoverageIsProven(r->band.low, r->band.high, r->band.lowKnown, ledgerStart, scannedThrough,
                                          abandonedBelow, gaveUpCount) &&
        BRCFAbandonmentMarkRecovered(r)) {
        return BR_CF_ABANDON_CHANGED | BR_CF_ABANDON_RECOVERED;
    }
    return r->sawFrontierInBand != sawBefore ? BR_CF_ABANDON_CHANGED : 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRCFAbandonmentRecord_h
