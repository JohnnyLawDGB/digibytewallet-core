//
//  BRCFAbandonment.h
//
//  The pure predicates behind the abandoned compact-filter band: what the
//  B2 abandonment valve gave up on, whether it is still condemned, and when
//  it may be declared recovered.
//
//  The B2 valve may abandon a height that was in fact servable -- it can only
//  prove refusal by the peers it is CURRENTLY connected to, never fleet-wide.
//  That residual is acceptable ONLY because every abandoned band stays visible
//  and recoverable, which is what these three decisions guarantee. Each of
//  them has a direction that costs money if it is wrong:
//
//    BRCFAbandonedBandNext      folds a freshly-polled abandonedBelow into the
//                               recorded band. Inventing a bottom the app never
//                               observed claims the wallet's whole history was
//                               abandoned; churning the record on a re-read of
//                               the same watermark resets "recovered" on every
//                               poll and makes the banner un-clearable.
//    BRCFAbandonedBandIsRetired is every height in the band requestable again?
//                               The floor can be LOWERED by the backfill, so a
//                               non-zero floor left by an older, deeper band says
//                               nothing about this one. Partial retirement is
//                               NOT recovery.
//    BRCFAbandonedBandCoverageIsProven
//                               was every height in the band evaluated? The
//                               ledger's scannedThrough is contiguous FROM ITS
//                               START, so a ledger re-initialised above the band
//                               proves nothing about it. Concluding otherwise is
//                               the false "all clear" -- the silent balance
//                               under-report this whole mechanism exists to
//                               prevent. That is the RED gate.
//
//  Ported from core/sync/CfAbandonmentStore.kt (nextAbandonedBand,
//  bandIsRetired, coverageIsProven). The persistence -- the band record, the
//  recovered flag and the two-phase "saw the frontier inside the band"
//  witness -- stays on the platform: the witness compares against a frontier
//  that no longer exists once the peer manager is recreated, so it cannot live
//  below the recreate. Only the DECISIONS are here, over caller-supplied
//  scalars, and they are what must not differ between platforms: two wallets
//  on the same seed must agree on whether a range is still condemned.
//
//  The scalars are the real BRCFScanLedger fields: start, scannedThrough,
//  abandonedBelow, gaveUpCount. The convenience overload reads them off the
//  struct so a caller with a ledger in hand cannot pass them in the wrong
//  order. A failed native read arrives as 0 and is never evidence.
//
//  Header-only static-inline, no BRPeerManager, no locking, no I/O; testable
//  standalone on the host (native/src/test/host/cf_abandonment_kat/), where
//  it is cross-checked against a ledger driven by the real BRCFScanLedger.c.
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

#ifndef BRCFAbandonment_h
#define BRCFAbandonment_h

#include <stdint.h>
#include <stddef.h>

#include "BRCFScanLedger.h"   // the struct whose fields these predicates read

#ifdef __cplusplus
extern "C" {
#endif

// A contiguous range of block heights the abandonment valve gave up on.
//
// `high` is exact: abandonedBelow - 1, read straight off the native monotonic
// watermark. `low` is the best-known bottom and is trustworthy only when
// `lowKnown`; when the app was not running while the valve decided there is no
// observation of the bottom, `low` is stored as 0 and MEANS UNKNOWN, not zero.
typedef struct {
    uint32_t low;
    uint32_t high;
    int      lowKnown;
} BRCFAbandonedBand;

// Fold a freshly-polled `abandonedBelow` into the recorded band.
//
//   existing == NULL         nothing was ever abandoned
//   abandonedBelow == 0      nothing abandoned now -> unchanged
//   high <= existing->high   a re-read of the same (or an older) watermark ->
//                            unchanged. The caller keys "recovered resets" off
//                            a change, so this MUST NOT churn.
//   existing != NULL         a later abandonment EXTENDS the band upward and
//                            keeps the original bottom: one banner covers
//                            everything still un-recovered.
//   first abandonment        the bottom is `lowHint` (the CF scan frontier
//                            observed while the valve was mid-decision) if it
//                            is inside [1, high]; otherwise UNKNOWN. A hint
//                            above the watermark is a stale poll, not a bottom.
//
// Returns 1 and writes *out when the record changes; 0 and leaves *out
// untouched when it does not.
static inline int BRCFAbandonedBandNext(const BRCFAbandonedBand *existing,
                                        uint32_t abandonedBelow, uint32_t lowHint,
                                        BRCFAbandonedBand *out)
{
    uint32_t high;

    if (abandonedBelow == 0) return 0;
    high = abandonedBelow - 1;
    if (existing) {
        if (high <= existing->high) return 0;
        out->low = existing->low;
        out->high = high;
        out->lowKnown = existing->lowKnown;
        return 1;
    }
    out->high = high;
    if (lowHint >= 1 && lowHint <= high) {
        out->low = lowHint;
        out->lowKnown = 1;
    } else {
        out->low = 0;
        out->lowKnown = 0;
    }
    return 1;
}

// Is every height in a band whose bottom is `bandLow` requestable again?
//
// Until the backfill existed abandonedBelow had no lowering path, so "still
// clamping" and "non-zero" were the same statement and this tested for 0.
// They are no longer the same: the backfill lowers the floor, and a floor
// left non-zero by an OLDER, DEEPER band says nothing about this one. Testing
// for 0 leaves the user staring at a warning about a range that has already
// been recovered. Partial retirement (floor inside the band) is not recovery.
static inline int BRCFAbandonedBandIsRetired(uint32_t bandLow, uint32_t abandonedBelow)
{
    return abandonedBelow <= bandLow ? 1 : 0;
}

// Was the band demonstrably evaluated, independent of the platform's
// two-phase witness?
//
// `scannedThrough` is a CONTIGUOUS high-water mark over evaluated heights and
// never advances past an outstanding or given-up hole. If it has passed the
// band top, every height in the band was evaluated -- PROVIDED contiguity
// started at or below the band. It is measured from `ledgerStart`, so a
// ledger re-initialised above the band never looked at it, and
// scannedThrough >= bandHigh proves nothing. That is checked explicitly.
//
// A band recorded without a low hint stores low = 0 meaning UNKNOWN. Read
// literally it can never be cleared (ledgerStart is always > 0), which is how
// a wallet ends up displaying a permanent warning (Note 8, v4.0.44). An
// abandoned range cannot extend below the ledger's own start -- heights below
// it were never in scope to abandon -- so for an unknown low the effective low
// IS the start. A band that KNOWS its low is still held to it.
//
// Every zero in `ledgerStart` / `scannedThrough` is a failed read, never
// evidence. A live floor (`abandonedBelow != 0`) means heights really are
// condemned; anything given up is a real hole.
static inline int BRCFAbandonedBandCoverageIsProven(uint32_t bandLow, uint32_t bandHigh,
                                                    int lowKnown,
                                                    uint32_t ledgerStart, uint32_t scannedThrough,
                                                    uint32_t abandonedBelow, size_t gaveUpCount)
{
    uint32_t effectiveLow;

    if (ledgerStart == 0 || scannedThrough == 0) return 0;   // failed reads
    if (abandonedBelow != 0) return 0;                        // still clamping
    if (gaveUpCount != 0) return 0;                           // a real hole exists
    effectiveLow = lowKnown ? bandLow : ledgerStart;
#ifndef CF_ABANDONMENT_START_UNQUALIFIED_UNFIXED
    if (ledgerStart > effectiveLow) return 0;                 // band predates this ledger
#else
    // RED-gate shape only: the contiguity claim without its start qualifier --
    // the false "all clear" over a band the ledger never looked at. Never
    // defined in a production build.
    (void)effectiveLow;
#endif
    return scannedThrough >= bandHigh ? 1 : 0;
}

// The same decision read straight off a live ledger, so a caller cannot pass
// the four scalars in the wrong order.
static inline int BRCFAbandonedBandCoverageIsProvenByLedger(const BRCFScanLedger *l,
                                                            const BRCFAbandonedBand *band)
{
    if (! l || ! band) return 0;
    return BRCFAbandonedBandCoverageIsProven(band->low, band->high, band->lowKnown,
                                             l->start, l->scannedThrough,
                                             l->abandonedBelow, l->gaveUpCount);
}

#ifdef __cplusplus
}
#endif

#endif // BRCFAbandonment_h
