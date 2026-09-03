//
//  BRCFRecoveryPolicy.h
//
//  What a compact-filter recovery is allowed to destroy.
//
//  The BIP158 watchdog branches used to delete the filter-header chain and the
//  CF scan ledger together, on every recovery. Those record different things:
//
//   - the filter-header CHAIN is BIP158 header data. It really can diverge from
//     the block chain or corrupt, and re-fetching it IS the recovery;
//   - the scan LEDGER records which block ranges this wallet has already scanned
//     against its own watch set. A wedged or diverged filter chain says nothing
//     about whether those ranges were scanned.
//
//  The ledger is what lets a restart resume near tip rather than at the birth
//  floor. Deleting it during a routine stall is what turned a recovery into
//  ~6 hours of re-scanning 1.4M blocks on a Note 8 -- the wallet re-derived work
//  it had already done and had a correct record of.
//
//  So: recovery may drop the chain freely, and may drop the ledger only for a
//  reason that actually implicates the ledger.
//
//  Ported from core/sync/CfRecoveryPolicy.kt so both platforms share one
//  decision. A scan floor is wallet state: two implementations of this table
//  means one platform can resume near tip while the other re-scans from the
//  birth checkpoint, off the same seed. Header-only static-inline predicate over
//  caller-supplied scalars -- no BRPeerManager, no locking, no I/O -- so it is
//  testable standalone on the host (see
//  native/src/test/host/cf_recovery_policy_kat/). Same shape as
//  BRPeerCFStatus.h and bridge_status_stale.h.
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

#ifndef BRCFRecoveryPolicy_h
#define BRCFRecoveryPolicy_h

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    // cfTip stuck at the network max while the block tip climbs. A stall, not
    // proof of anything about the scan record.
    BRCFRecoveryReasonFilterChainWedged = 0,

    // The chain was re-anchored at a floor; the persisted copy must go so a kill
    // before the first re-anchored append cannot restore the stuck tip.
    BRCFRecoveryReasonReanchored = 1,

    // Still wedged AFTER a re-anchor -- the persisted chain is not merely stale,
    // and the scan record derived alongside it is no longer trustworthy either.
    BRCFRecoveryReasonFilterChainCorrupt = 2,

    // The ledger blob itself failed to decode.
    BRCFRecoveryReasonScanLedgerCorrupt = 3,

    // Explicit reset: wipe, restore, or the startup crash-loop breaker.
    BRCFRecoveryReasonWalletReset = 4,
} BRCFRecoveryReason;

typedef struct {
    int dropFilterChain;
    int dropScanLedger;
} BRCFRecoveryDecision;

// The decision table. Values are 0/1 rather than bool so this header stays
// usable from plain C89 call sites and from a Swift bridging import without
// pulling in <stdbool.h>.
//
// NOTE ON THE DEFAULT CASE -- this is the one place the C port must say more
// than the Kotlin original did. Kotlin's `when` over an enum is exhaustive and
// the compiler proves no other value exists. A C enum is an int: a value from a
// future version, a corrupted read, or a bad cast can arrive here. So an
// unknown reason needs a defined answer, and the safe answer is NOT "drop
// everything" -- that is the pre-fix behavior this whole policy exists to
// remove, and it would cost the ~6-hour rescan on any unrecognised input. It
// drops the chain (cheap to re-fetch, and re-fetching is what recovery means)
// and KEEPS the ledger (expensive, and nothing about an unknown reason
// implicates it).
static inline BRCFRecoveryDecision BRCFRecoveryDecide(BRCFRecoveryReason reason)
{
    BRCFRecoveryDecision d;

    switch (reason) {
        case BRCFRecoveryReasonFilterChainWedged:
            d.dropFilterChain = 1; d.dropScanLedger = 0; break;

        case BRCFRecoveryReasonReanchored:
            d.dropFilterChain = 1; d.dropScanLedger = 0; break;

        case BRCFRecoveryReasonFilterChainCorrupt:
            d.dropFilterChain = 1; d.dropScanLedger = 1; break;

        case BRCFRecoveryReasonScanLedgerCorrupt:
            d.dropFilterChain = 0; d.dropScanLedger = 1; break;

        case BRCFRecoveryReasonWalletReset:
            d.dropFilterChain = 1; d.dropScanLedger = 1; break;

        default:
            d.dropFilterChain = 1; d.dropScanLedger = 0; break;
    }

#ifdef CF_RECOVERY_DROPS_BOTH_UNFIXED
    // RED-gate shape only: the pre-fix watchdog, which deleted the filter-header
    // chain and the scan ledger together on every recovery. Never defined in a
    // production build; the host KAT defines it to prove the table is
    // load-bearing rather than incidentally passing.
    d.dropFilterChain = 1; d.dropScanLedger = 1;
#endif

    return d;
}

// True when this reason is allowed to destroy the scan ledger. The ledger is
// the expensive artifact -- callers that only need the guard question should ask
// it directly rather than re-deriving it from the struct at each site.
static inline int BRCFRecoveryMayDropScanLedger(BRCFRecoveryReason reason)
{
    return BRCFRecoveryDecide(reason).dropScanLedger;
}

#ifdef __cplusplus
}
#endif

#endif // BRCFRecoveryPolicy_h
