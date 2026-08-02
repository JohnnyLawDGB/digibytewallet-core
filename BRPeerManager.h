//
//  BRPeerManager.h
//
//  Created by Aaron Voisine on 9/2/15.
//  Copyright (c) 2015 breadwallet LLC.
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

#ifndef BRPeerManager_h
#define BRPeerManager_h

#include "BRPeer.h"
#include "BRMerkleBlock.h"
#include "BRTransaction.h"
#include "BRWallet.h"
#include "BRChainParams.h"
#include "BRCompactFilterChain.h"
// Both are already unconditional includes of BRPeerManager.c; hoisted to the
// header so the CROSS-MODULE CONSTANT-RELATION SWEEP below can assert the
// relations that span them (CF ledger bounds vs the paced-convoy window vs the
// BIP157 wire limits in BRPeer.h vs the GCS size cap). BRCFScanLedger.h also
// provides the CF_STATIC_ASSERT spelling used there. Both are pure headers
// (stdint/stddef/BRInt.h only), so this adds no dependency weight.
#include "BRCFScanLedger.h"
#include "BRGCSFilter.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// Max simultaneous peer connections. Raised 5 -> 8 (Bitcoin Core's default
// outbound) to improve discovery of scarce compact-filter (BIP157/158) peers on
// mainnet: with only ~a handful of filter-serving nodes, 5 slots were too few to
// reliably hold a synced filter peer. Revisit toward 12-16 as the filter-node
// population grows (oracle-bootstrap). Bloom-mode sync is unaffected.
#define PEER_MAX_CONNECTIONS 8

// ANR fix #2 (native peer-manager keepalive lock-starvation,
// .superpowers/sdd/anr-fix2-native-design.md). Robustness eviction for peers that are
// dead but not currently being pinged (e.g. NAT silently dropped the return path, no
// outbound stall yet to trip the send-path eviction). BRPeerManagerKeepAlive schedules
// a real disconnect for any connected peer whose last inbound read
// (BRPeerLastRecvTime) is older than this, replacing the DBL_MAX idle sentinel
// _BRPeerDidConnect sets. Safely longer than the ~10s keepalive tick interval so a
// responsive peer -- which gets pinged, and thus reads a pong, every tick -- never
// trips it.
#define PEER_INBOUND_IDLE_LIMIT 90.0

/* defines, how many blocks to be held in sqlite DB */
#define SAVE_BLOCK_COUNT 300
#define SAVE_BLOCK_INTERVAL 4000
    
/* OPTIONS FOR CLEARING MEMORY */
/*
Remarks:
    The authors of the original breadwallet core ensure that the application
    contains at least 2016 blocks, until a difficulty transition block gets relayed.
    Since Digibyte makes use of DigiShield (or more specifically MultiShield), on each and
    every block there occurs a difficulty transition.
    We need to keep some blocks in memory in case of forks, to walk the chain backwards.
    To clear memory we have introduced a trigger value: CLEAR_MEM_BLOCKS_COUNT_TRIGGER.
    If the BRPeerManager instance contains more than CLEAR_MEM_BLOCKS_COUNT_TRIGGER blocks in 'blocks',
    we trigger the memory cleanup. The first CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN blocks will be freed up.
    Note that we have to remove the tail, that is, we have to walk back the chain, until we reach the tail,
    then free up the remaining blocks.
 
    CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN is at least the SAVE_BLOCK_COUNT
        plus a reserve of CLEAR_MEM_BLOCKS_RESERVE_COUNT blocks.
*/
#define CLEAR_MEM_BLOCKS_COUNT_TRIGGER 5000
#define CLEAR_MEM_BLOCKS_RESERVE_COUNT 500
#define CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN (CLEAR_MEM_BLOCKS_COUNT_TRIGGER - SAVE_BLOCK_COUNT - CLEAR_MEM_BLOCKS_RESERVE_COUNT)

/* BIP 158: block headers at/above (cfTip - this margin) are never pruned, so
   the cfheaders driver can always walk prevBlock links back to its next batch's
   stop height. Without this, pruning frees the deficit region and cfheaders
   stalls forever with "no block hash for height H". In steady state cfTip
   tracks blockTip so the retained span collapses to the normal tail; it only
   expands transiently while a large cfTip deficit is being recovered. */
#define CLEAR_MEM_CF_RETENTION_MARGIN 144

/* HARD BOUND on how far below the tip block headers are retained.

   The convoy's retention floor is min(cfNext, LowestNeededHeight) - margin, i.e. it is
   anchored to the SCAN. That is correct, and it is exactly what stops the scan-floor headers
   being pruned out from under the buffer-drain and the residual re-request. But its bound
   is CONDITIONAL: the convoy's own note says the span is "flat at any restore depth" BECAUSE
   the header/cfheader frontiers are paced to within CF_CONVOY_WINDOW of the scan frontier.
   If the scan frontier stops moving, that premise fails and the floor stops rising with it,
   so every header from the frozen frontier to the tip must be retained — without limit.

   MEASURED, this is not theoretical: with the scan frozen at 23,683,999 and the block tip at
   23,806,540, manager->blocks reached 145,894 entries (~33 MB) and _BRPeerManagerClearMemory
   logged "Blocks reduced from 145894 to 145894" — running every block-add and freeing
   nothing. That is the OOM the convoy exists to prevent, reached THROUGH the convoy's own
   honest anchor, and it feeds back: the bigger the retained set, the less headroom the loop
   that would unfreeze the scan has.

   This clamp makes the bound UNCONDITIONAL. It is a backstop, not a tuning knob: in healthy
   convoy operation the span is ~CF_CONVOY_WINDOW (10k) and this never binds. It is sized well
   above the worst overshoot actually observed (~122k, the F1 header-overshoot regime) so it
   does not bind on a merely-degraded sync, and it is finite so a wedged one cannot grow
   without limit. 150,000 headers x ~224 B all-in ~= 34 MB.

   When it DOES bind the floor rises above what the scan still wants, those heights become
   unrequestable, and the existing surfacing path (snap-up / C-1 -> abandonedBelow -> banner)
   reports them. That is a visible, recoverable gap instead of an unbounded allocation — the
   same priority the rest of this file takes: never silent, never fatal.

   Do NOT shrink this toward CF_CONVOY_WINDOW to "tighten" it. A fresh install legitimately
   starts its scan at the newest hardcoded checkpoint, hundreds of thousands of blocks below
   the tip, and a clamp near the window would skip that history on every first run. */
#define CF_RETENTION_SPAN_MAX 150000u

/* How far the retention floor must RISE before _BRPeerManagerClearMemory pays for another
   full descent of the resident block set.

   WHY THIS EXISTS (measured on a Note 8, 2026-08-02, deep restore from height 22,650,000).
   Once CF_RETENTION_SPAN_MAX binds, the floor becomes `tip - 150000`, so it rises by ONE on
   every block-add. That defeats the O(1) no-op short-circuit twice over: the memo is keyed on
   `cfFloor <= clearMemNoopFloor`, which a strictly-rising floor never satisfies, and freeing
   even one block resets the memo to 0. The result is a FULL descent of the ~150,000-block
   resident set per block-add, to free the single block that just dropped below the floor.

   That is not merely wasteful, it is self-sustaining. Measured: ~149,198 BRSetGet per header
   against a ~28.8 MB working set (vs 2 MB of L2 on a Kryo 280) = 74.6 ms/header predicted,
   77 ms/header observed, one core pegged at 100%. The descent holds manager->lock, so
   BRPeerManagerKeepAlive cannot tick; the residual re-request driver never runs; outstanding
   heights are never retried; the scan frontier never advances; the clamp keeps binding. The
   device logged "keepalive stale: no tick in 80s" four times and abandoned 18,549 heights.
   Header throughput collapsed from 108,696/s to 13/s -- a factor of 8,361.

   Amortising is sound because the ONLY cost of deferring is that at most this many blocks
   stay resident past the floor (~2048 x 224 B ~= 459 KB, against a 34 MB budget), and a LOWER
   resident floor is strictly safer for coverage: it makes MORE heights requestable, never
   fewer. Correctness never depended on pruning promptly -- only on pruning eventually.

   Not 1000: three unrelated constants in this project already sit at 1000 and a collision
   there once let a dead band eat real work. */
#define CLEAR_MEM_PRUNE_STRIDE 2048u

/* How far the forward cfilter CURSOR may run ahead of the SCAN FRONTIER.

   The convoy paces the header and cfheader frontiers against the scan frontier, but nothing
   paced the cfilter cursor against it: B1.1 always fetches from autoFetchCFiltersThrough+1
   upward and never consults scannedThrough. The residual driver does work the frontier
   lowest-first, but its heights sit on a 30-120 s backoff while the cursor advances a full
   MAX_CFILTERS_RESULTS batch every ~10 s KeepAlive tick, so the cursor always outruns it.

   MEASURED consequence on a fresh wallet: requests were landing 2,000-11,000 blocks ABOVE the
   pin, and of 6,487 cfilters received, 5,791 (89.3%) were outside the pinning hole's window.
   Every one of them evaluated successfully — and bought nothing, because scannedThrough only
   advances across the CONTIGUOUS prefix at the bottom. 6,487 successful evaluations moved the
   frontier 622 blocks. Meanwhile the starved prefix heights timed out and parked, driving
   outstanding to ~3,900 and gaveUp to ~3,500 and handing the B2 valve a band it should never
   have had to abandon.

   Two batches of headroom: enough to keep the pipeline full (a batch in flight while the next
   is being evaluated), small enough that the frontier is what the fetch budget is spent on.
   This does NOT stop forward progress when the prefix is genuinely dead — the B2 valve raises
   abandonedBelow, which raises the frontier, which reopens this gate. */

/* NOTE: there is deliberately NO depth ceiling here. CF_RETENTION_MAX_SPAN used
   to bound the retained block-header span to a fixed depth below the chain tip
   and abandon retry-exhausted (gaveUp) heights below the clamp; the app layer
   read the same constant to REFUSE deep restores up front. Both halves are
   DELETED (paced-convoy design, KEPT/REMOVED/REPURPOSED): no restore is refused
   at any depth, because the convoy bounds resident headers to CF_CONVOY_WINDOW
   at ANY depth. The abandonment VALVE the ceiling doubled as is RETAINED but
   re-triggered on proven connected-CF-subset refusal (Part B2,
   BRPeerManagerKeepAlive), not on depth. The retention FLOOR
   (min(cfNext, LowestNeededHeight) - CLEAR_MEM_CF_RETENTION_MARGIN) is untouched. */

/* PACED-CONVOY B2 -- how many FRESH retry cycles a retry-exhausted (gaveUp) hole
   is granted against a LIVE CF-peer set before the abandonment valve may abandon
   it (spec Part C / Part B2). Each cycle is a full re-request backoff schedule
   (30/60/120/120/120 = 7.5 min) during which the residual driver rotates the hole
   across every connected CF peer, so 2 cycles is ~15 min of productive rotated
   retry (~22 min counting the original cycle).

   >= 2 DELIBERATELY, not 1: a single unlucky peer-rotation cycle -- the peer set
   churning, the fleet momentarily saturated -- must not be able to false-positive
   into abandoning a height the fleet can actually serve.

   This is an ACCEPTANCE-INFORMED TUNABLE, not a blind constant. It is calibrated
   on how fast the CONNECTED CF-peer subset rotates through the fleet, and the
   accepted residual (fleet saturation: the oracle that HAS the filter is at
   maxconnections, so we never connect to it) is exactly where rotation is
   SLOWEST. Every abandonment warn-logs its height range: if a height abandons and
   a later node-reconcile CREDITS it, that is the signal to RAISE this number --
   not that the valve is broken. */
#define CF_CONVOY_REARM_MAX 2

/* PACED-CONVOY FETCH WINDOW (spec 2026-07-28-paced-convoy-fetch-design.md,
   Parts A + C). The maximum number of blocks the block-header frontier
   (manager->lastBlock->height) and the cfheader frontier
   (BRCompactFilterChainNextHeight - 1) may lead the CF SCAN frontier
   (BRCFScanLedgerLowestNeededHeight) by. Beyond it the two TIP-RACING
   continuations -- BRPeer.c's CF-only 2000-header continuation and
   _BRPeerManagerRequestNextCFHeaders' clean-append advance -- are suppressed, so
   the header/cfheader/scan frontiers climb birth->tip as one convoy instead of
   the headers fast-forwarding to the tip and filling manager->blocks with
   [birth..tip] before the scan has processed anything (the deep-restore OOM).
   RECOVERY and SYNC-START sends are NEVER gated -- suppressing one deadlocks the
   convoy from the other side.

   The value is a floor-derived bound, not a magic number. It must EXCEED all of:
   (1) the scan lookahead CF_OUTSTANDING_MAX(4096) + MAX_CFILTERS_RESULTS(1000)
       = 5096 -- a smaller window starves the scan: the forward cfilter fetch can
       only ask for heights the cfheader frontier already covers, so a window
       below the in-flight ceiling would throttle the very path that ADVANCES the
       scan frontier the window is measured from (deadlock from the other side);
   (2) the cfheader quantum MAX_CFHEADERS_RESULTS(2000) -- below one batch the
       gate would suppress every cfheaders advance and never re-open;
   (3) a re-kick-latency margin at DGB's ~15 s blocks -- the window must hold
       enough headers to keep the scan fed across one CF_CONVOY_HDR_REKICK_BASE_SECS
       (30 s) re-kick interval, i.e. >= 30 s x the scan's 100 heights/s ceiling.
   W = 10000 clears (1) by 4904, (2) by 8000, (3) by ~2 orders of magnitude.

   THE THREE CONSEQUENCES OF THE CHOSEN VALUE (state them when changing it):
   a. MAX RESIDENT BLOCK HEADERS ~= W + CLEAR_MEM_CF_RETENTION_MARGIN = 10144
      (the retention floor sits 144 below the scan frontier, the header frontier
      at most W above it), x ~220 B/header ~= 2.2 MB -- FLAT AT ANY RESTORE
      DEPTH. That is the whole feature: the deep-restore OOM stops existing.
      (Add the ~2-batch stale-flag overshoot at BRPeer.c:648, ~4000 headers /
      ~0.88 MB, for the true instantaneous peak: ~14.1k headers / ~3.1 MB.)
   b. MAX prevBlock WALK DEPTH = W_hdr ~= 10000. Every getcfilters/getcfheaders
      stop hash resolves by walking down from lastBlock (_BRPeerManagerBlockHashAtHeight,
      batched at _BRPeerManagerResolveHashesAtHeightsLocked), so the walk is short
      BY CONSTRUCTION rather than by optimization -- depth-independent, sub-ANR,
      and it is why no height->hash index is needed (or possible: the reorg path
      never BRSetRemoves, so an index has no eviction hook).
   c. SCAN-LOOKAHEAD HEADROOM = W - (CF_OUTSTANDING_MAX + MAX_CFILTERS_RESULTS)
      = 10000 - 5096 = 4904 blocks of cfheader frontier the scan can consume
      before the convoy has to re-kick, i.e. ~5 full forward-fetch batches of
      slack against a stalled header supply. */
#define CF_CONVOY_WINDOW 10000

/* PACED-CONVOY driver B1.3 -- the getheaders re-kick's RATE LIMIT (spec Part B1
   step 3). KeepAlive re-issues the header continuation BRPeer.c holds while the
   window is full; the trigger (a header frontier frozen across a whole ~10 s
   tick) is necessary but NOT sufficient, because "frozen" cannot distinguish
   "the continuation was suppressed and nothing is in flight" (re-kick wanted)
   from "a reply IS in flight and just hasn't been parsed yet" (re-kick harmful).
   BRPeer.c issues its continuation BEFORE the relay loop, so lastBlock does not
   move until the whole ~440 KB batch is parsed -- on a slow link that is minutes
   of "frozen". So the re-kick is additionally rate-limited by an interval that
   BACKS OFF while unproductive and RESETS the moment the header tip actually
   advances. Same 'delay = min(BASE << n, CAP), reset on progress' idiom the CF
   scan-ledger's residual re-request driver already uses (CF_REREQ_BASE_SECS /
   CF_REREQ_BACKOFF_CAP_SECS) -- deliberately not a new mechanism.

   Sequence: 30, 60, 120, 240, 480, 600, 600, ... An EPISODE ends -- and the
   interval resets to 30 -- on either of the two things that mean the accumulated
   penalty no longer describes reality: real header-tip progress (the chain is
   alive), or a GATED->open transition (a gated period issues no re-kicks, so it
   can neither earn a penalty nor carry one across; the reopen is served on the
   very next tick, which is what B1.3 exists for). Note those two are INDEPENDENT:
   the window can close and reopen from scanFrontier movement alone, with the
   header tip never advancing.

   TOO SHORT costs bandwidth, and it COMPOUNDS: each injected getheaders is
   answered with a full 2000-header batch, and because count >= 2000 every reply
   spawns its OWN independent, lockstep continuation chain that persists until
   the gate shuts it -- N re-kicks during one slow batch means N x ~2.2 MB of
   duplicate headers per window-open period, recurring on every re-open of a
   multi-hour deep restore, amplifying exactly on the slow mobile links the
   convoy exists to make cheap. It also has a STEADY-STATE leak: estimatedHeight
   is only ever RAISED, so a peer that advertised a height we never reach leaves
   lastBlock->height < estimatedHeight forever on a fully-synced wallet (where
   W_hdr ~ 0, i.e. the window is permanently open) -- at the bare 10 s tick that
   is a ~1.2 KB full-locator getheaders every 10 s forever (~10 MB/day upstream),
   each answered with 0 headers. The 600 s ceiling bounds that to ~170 KB/day.

   TOO LONG costs window-reopen recovery latency: after the scan climbs enough to
   re-open the window, the header frontier stays frozen until the next re-kick is
   due. BASE is what that path actually pays, because the previous batch landing
   is itself tip progress and RESETS the backoff -- so an ordinary descent always
   re-kicks at 30 s, never at the ceiling. At 30 s the header supply is ~4000
   headers per interval (the M-2 two-batch overshoot: BRPeer.c reads the gate
   flag one batch stale), i.e. ~133 heights/s, which stays ahead of the scan's
   ceiling of MAX_CFILTERS_RESULTS(1000) per ~10 s tick == 100 heights/s. So the
   convoy is never header-starved by this throttle. */
#define CF_CONVOY_HDR_REKICK_BASE_SECS 30
#define CF_CONVOY_HDR_REKICK_MAX_SECS  600

/* BIP 158 continuity-failure recovery. If this many DISTINCT peers fail the
   cfheaders continuity check against our current tip since the last successful
   append, our chain is the outlier (it diverged via unverified TOFU) — re-anchor
   instead of marking the (honest) peers misbehavin'. Bounded per session so a
   persistently-divergent peer can't loop forever. */
#define CF_CONTINUITY_REANCHOR_K   2
#define CF_CONTINUITY_REANCHOR_MAX 3

/* Floor of connected filter peers below which the cfheaders stall-recovery must
   NOT disconnect a peer. A batch no peer can serve (e.g. a contested range during
   a rescan) would otherwise shred the whole filter-peer pool to 0 one peer per
   rotation; keep at least this many so the keepalive can grow the pool instead of
   racing the shredder. */
#define CF_MIN_FILTER_PEERS 2

/* ---- CROSS-MODULE CONSTANT-RELATION SWEEP ---------------------------------
 *
 * The companion to the intra-module sweep in BRCFScanLedger.h; read the "WHY
 * THIS BLOCK EXISTS" note there first. These are the relations that span
 * headers — the CF scan ledger's bounds against the BIP157 wire limits
 * (BRPeer.h), the paced-convoy window against both, and the filter buffer
 * against the GCS size cap (BRGCSFilter.h) — so none of them could be asserted
 * inside the pure ledger header. Same rule: every assertion states WHAT BREAKS.
 *
 * The paced-convoy window's three derivation floors were written out in prose at
 * the CF_CONVOY_WINDOW define above ("It must EXCEED all of: (1)... (2)... (3)...")
 * and enforced by nothing. Prose is exactly what F4 had.
 *
 * One relation here is same-header rather than cross-module (the ClearMemory
 * trio). It lives in this block anyway: the value of a sweep is that it is in ONE
 * place a reader can audit, and the memory-ceiling constants belong beside the
 * convoy window they now share a job with.
 */

/* --- the ClearMemory trio: trigger vs retained tail ---
 * CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN is DERIVED (TRIGGER - SAVE_BLOCK_COUNT - RESERVE),
 * and _BRPeerManagerClearMemory walks (TRIGGER - TAIL_LEN) blocks DOWN from lastBlock
 * before freeing anything below that point.
 * BREAKS: if SAVE_BLOCK_COUNT + RESERVE reaches TRIGGER, TAIL_LEN is <= 0 and the
 * walk bound (TRIGGER - TAIL_LEN) becomes >= TRIGGER — i.e. at least as many blocks
 * as the trigger count itself. The walk runs off the bottom of the resident chain,
 * blockPtr comes back NULL, the `if (blockPtr)` guard skips the free, and ClearMemory
 * is a PERMANENT NO-OP: manager->blocks grows without bound. That matters more now
 * than it used to, because the paced convoy's flat-footprint guarantee is a bound on
 * the FETCH side only — this function is the one thing that actually frees, and it is
 * also what enforces the CF retention floor. The header's own remark ("TAIL_LEN is at
 * least the SAVE_BLOCK_COUNT plus a reserve of CLEAR_MEM_BLOCKS_RESERVE_COUNT
 * blocks") states the relation in prose and enforces nothing — F4's exact shape. */
CF_STATIC_ASSERT(SAVE_BLOCK_COUNT + CLEAR_MEM_BLOCKS_RESERVE_COUNT < CLEAR_MEM_BLOCKS_COUNT_TRIGGER,
               "CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN must stay positive, else _BRPeerManagerClearMemory's "
               "walk-down bound exceeds the resident chain, the free is skipped, and block-header "
               "pruning silently stops happening at all");

/* --- the residual re-request run vs what one getcfilters can carry ---
 * BREAKS: BRCFScanLedgerPeekRerequestRange coalesces a run of up to
 * CF_REREQ_MAX_RANGE heights and the residual driver sends it as ONE getcfilters
 * whose stop is a HASH resolved at the run's top height. If the run can exceed
 * one wire window, the range that goes out spans more heights than the message
 * may request, and _BRPeerManagerRequestCFiltersWithStopHashLocked's own
 * `assert(stopHeight <= startHeight + (MAX_CFILTERS_RESULTS - 1))` fires — or, in
 * an NDEBUG production build where that assert is compiled out, the stop HASH
 * belongs to a different height than the peer's stop, i.e. the silent
 * wrong-range fetch the single-descent resolver design explicitly exists to make
 * impossible. Either way BRCFScanLedgerCommitRerequest bumps `attempts` for the
 * whole coalesced range while only part of it was actually asked for, so the tail
 * burns its retry budget un-offered and is abandoned. (`==` is the tuned choice;
 * `<=` is the correctness bound — a smaller RANGE only coalesces less.) */
CF_STATIC_ASSERT(CF_REREQ_MAX_RANGE <= MAX_CFILTERS_RESULTS,
               "a coalesced re-request run must fit ONE getcfilters, else the pre-resolved stop "
               "hash names a different height than the wire stop (silent wrong-range fetch) and "
               "the run's tail burns attempts un-offered");

/* --- forward-fetch back-pressure headroom ---
 * BREAKS: the forward auto-fetch gate tests `outstandingCount < CF_OUTSTANDING_LOWWATER`
 * and then requests up to MAX_CFILTERS_RESULTS heights in one batch, so the post-batch
 * peak is (LOWWATER - 1) + MAX_CFILTERS_RESULTS. If that exceeds CF_OUTSTANDING_MAX,
 * _cfLedgerInsertOutstanding takes its overflow branch mid-batch and DROPS THE OLDEST
 * outstanding heights — heights that were requested and never evaluated leave the
 * ledger, so _cfLedgerAdvance stops seeing them as holes and scannedThrough advances
 * over them. That is the STANDING INVARIANT broken by arithmetic: no code path decided
 * to give up on those heights, the two caps just did not add up. This is the relation
 * the LOWWATER comment asserts in prose ("Left with headroom under the hard cap so
 * eviction should never actually trigger in practice"). */
CF_STATIC_ASSERT(CF_OUTSTANDING_LOWWATER + MAX_CFILTERS_RESULTS <= CF_OUTSTANDING_MAX + 1u,
               "back-pressure low-water plus one forward batch must fit under CF_OUTSTANDING_MAX, "
               "else a single batch overflows outstanding[] and evicts unevaluated heights out "
               "from under scannedThrough");

/* --- paced-convoy window, derivation floor (1): the scan lookahead ---
 * BREAKS (verbatim from the CF_CONVOY_WINDOW comment): a smaller window starves the
 * scan — the forward cfilter fetch can only ask for heights the cfheader frontier
 * already covers, so a window below the in-flight ceiling throttles the very path that
 * ADVANCES the scan frontier the window is measured from. The convoy deadlocks from the
 * other side: gate shut because the scan is behind, scan behind because the gate is shut. */
CF_STATIC_ASSERT(CF_CONVOY_WINDOW > CF_OUTSTANDING_MAX + MAX_CFILTERS_RESULTS,
               "CF_CONVOY_WINDOW must exceed the CF scan's in-flight ceiling "
               "(CF_OUTSTANDING_MAX + MAX_CFILTERS_RESULTS), else the gate throttles the only "
               "path that advances the scan frontier it is measured from — convoy deadlock");

/* --- paced-convoy window, derivation floor (2): the cfheader quantum ---
 * BREAKS: cfheaders arrive in batches of up to MAX_CFHEADERS_RESULTS. With a window
 * narrower than one batch, a single clean append pushes the cfheader frontier past the
 * window in one step, the gate shuts, and it can only re-open when the SCAN frontier
 * climbs — which needs cfheaders. Every cfheaders advance is suppressed and the gate
 * never re-opens. */
CF_STATIC_ASSERT(CF_CONVOY_WINDOW > MAX_CFHEADERS_RESULTS,
               "CF_CONVOY_WINDOW must exceed one cfheaders batch (MAX_CFHEADERS_RESULTS), else "
               "one clean append shuts the gate permanently");

/* --- paced-convoy window, derivation floor (3): re-kick latency margin ---
 * BREAKS: while the window is full BRPeer.c HOLDS its header continuation, and the only
 * thing that re-issues it is KeepAlive's B1.3 re-kick, no oftener than
 * CF_CONVOY_HDR_REKICK_BASE_SECS. The window must therefore hold enough headers to keep
 * the scan fed across one whole re-kick interval; below that the scan drains the resident
 * headers, idles waiting for the re-kick, and the convoy descends at the re-kick's rate
 * instead of the fetch's — turning a bounded-memory feature into a bounded-THROUGHPUT one
 * (a multi-hour deep restore becomes multi-day).
 *
 * The scan's ceiling is MAX_CFILTERS_RESULTS heights per KeepAlive tick, and the tick
 * period is a Kotlin-side literal (SyncService.kt, `delay(10_000L)`) that C cannot see —
 * hence the 10 below. CAVEAT, stated rather than hidden: this assertion pins the C half
 * only. Shortening the Kotlin tick raises the scan's heights/s ceiling and TIGHTENS this
 * floor without this assertion noticing. It is a one-directional guard, not a complete one. */
CF_STATIC_ASSERT(CF_CONVOY_WINDOW >= CF_CONVOY_HDR_REKICK_BASE_SECS * (MAX_CFILTERS_RESULTS / 10u),
               "CF_CONVOY_WINDOW must hold at least one re-kick interval's worth of scan supply "
               "(REKICK_BASE_SECS x MAX_CFILTERS_RESULTS per 10s tick), else the convoy descends "
               "at the re-kick's rate instead of the fetch's");

/* --- re-kick backoff: ceiling vs base ---
 * BREAKS: the escalation is `backoff = (backoff >= MAX/2) ? MAX : backoff * 2`, starting at
 * BASE. With MAX < BASE the very first send clamps the interval DOWN to MAX, so the ceiling
 * becomes a floor-breaker: re-kicks fire more often than BASE forever. That is the expensive
 * direction — each injected getheaders is answered with a full 2000-header batch that spawns
 * its own lockstep continuation chain, so the CF_CONVOY_HDR_REKICK_BASE_SECS comment's
 * "N re-kicks during one slow batch means N x ~2.2 MB of duplicate headers" compounds on
 * exactly the slow mobile links the convoy exists to make cheap. */
CF_STATIC_ASSERT(CF_CONVOY_HDR_REKICK_MAX_SECS >= CF_CONVOY_HDR_REKICK_BASE_SECS,
               "the re-kick backoff CEILING must not sit below its BASE, else the first "
               "escalation clamps the interval DOWN and re-kicks fire faster than BASE forever");

/* --- retention margin vs the convoy window ---
 * These are the two terms of the resident-header span: the header frontier rides at most
 * CF_CONVOY_WINDOW above the CF scan frontier, and _BRPeerManagerClearMemory's floor sits
 * CLEAR_MEM_CF_RETENTION_MARGIN below it, so resident headers ~= W + MARGIN.
 * BREAKS: both headline guarantees of the paced convoy are stated in terms of W —
 * consequence (a) "MAX RESIDENT BLOCK HEADERS ~= W + MARGIN ... ~2.2 MB, FLAT AT ANY RESTORE
 * DEPTH" (the deep-restore OOM fix itself) and consequence (b) "MAX prevBlock WALK DEPTH
 * ~= W" (the sub-ANR, index-free hash resolution). If MARGIN is not the small correction
 * term, both are actually governed by a constant sized for a completely different job
 * (keeping ~one DigiShield window of headers alive so cfheaders can walk prevBlock links
 * back to its next batch's stop), and W could be tuned to no effect while the real
 * footprint and the real walk depth stayed put.
 * This one is a GUARANTEE/footprint relation, not a correctness one — said plainly so
 * nobody reads it as stronger than it is. */
CF_STATIC_ASSERT(CLEAR_MEM_CF_RETENTION_MARGIN < CF_CONVOY_WINDOW,
               "CLEAR_MEM_CF_RETENTION_MARGIN must stay the small correction term under "
               "CF_CONVOY_WINDOW, else the resident-header footprint and the prevBlock walk "
               "depth are set by the retention margin and both paced-convoy guarantees are "
               "governed by a constant sized for neither");

/* --- B2 re-arm budget vs the field that carries it ---
 * BREAKS: BRCFOutstanding.rearmCycles / BRCFScanLedger.gaveUpRearmCycles[] are uint8_t and
 * SATURATE at 0xFF (BRCFScanLedger.c, `if (e->rearmCycles < 0xFFu) e->rearmCycles++`). The
 * valve abandons only when `rearmCycles >= CF_CONVOY_REARM_MAX`, so a budget the field
 * cannot represent is never reached: the valve re-arms the pinning hole forever and NEVER
 * abandons, which is the permanent convoy wedge the valve exists to prevent. Same shape as
 * the CF_REREQ_MAX_ATTEMPTS/uint8_t relation in BRCFScanLedger.h — a constant outgrowing the
 * field width, which is how F4's ceiling defect would come back. */
CF_STATIC_ASSERT(CF_CONVOY_REARM_MAX <= 255,
               "CF_CONVOY_REARM_MAX must fit the uint8_t rearmCycles counters (which saturate at "
               "0xFF), else the B2 valve's abandon threshold is unreachable and it re-arms the "
               "pinning hole forever");

/* --- filter buffer budget vs a WIRE-LEGAL filter ---
 * BREAKS at <= BR_GCS_MAX_ENCODED_SIZE: BRPeer.c's cfilter parser accepts any encoded filter
 * up to BR_GCS_MAX_ENCODED_SIZE, but BRCFScanLedgerBufferFilter refuses outright
 * (`if (len > CF_FILTER_BUFFER_MAX_BYTES) return 0`) anything bigger than the whole budget.
 * A wire-legal filter we already received and validated could then not be buffered at all,
 * so the header-race fast path silently stops covering the largest filters and those heights
 * can only heal through the slower re-request schedule.
 * BREAKS at <= 2x: the insert-path eviction loop is `while (bufferedBytes + len >= MAX_BYTES
 * && filterBufCount > 0)`, so with room for only one maximal filter every insert evicts the
 * previous one — two concurrently header-raced large filters thrash instead of both waiting
 * for their headers. 2x is the honest minimum for the buffer to be a buffer. */
CF_STATIC_ASSERT(CF_FILTER_BUFFER_MAX_BYTES > 2u * BR_GCS_MAX_ENCODED_SIZE,
               "the filter buffer must hold at least two wire-legal (BR_GCS_MAX_ENCODED_SIZE) "
               "filters, else BufferFilter refuses the largest legal filters outright / evicts "
               "the previous one on every insert");

/* Readability constants */
#define ADD_TO_SAVED_BLOCKS 0
#define REPLACE_SAVED_BLOCKS 1

// BIP 158 sync mode. Controls which peer protocols the manager uses to find
// wallet-relevant transactions. Set via BRPeerManagerSetSyncMode before
// BRPeerManagerConnect; changes after connect take effect on the next sync.
typedef enum {
    BR_SYNC_MODE_BLOOM_ONLY = 0,            // legacy BIP 37 SPV (default)
    BR_SYNC_MODE_COMPACT_FILTERS_ONLY = 1,  // BIP 157/158 only
    BR_SYNC_MODE_BOTH = 2,                  // both paths in parallel
} BRSyncMode;

typedef struct BRPeerManagerStruct BRPeerManager;

// returns a newly allocated BRPeerManager struct that must be freed by calling BRPeerManagerFree()
BRPeerManager* BRPeerManagerNew(const BRChainParams* params, BRWallet* wallet, uint32_t earliestKeyTime,
                                BRMerkleBlock* blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);

// Extension of the above. Accepts a custom initial block
BRPeerManager* BRPeerManagerNewEx(const BRChainParams* params, BRWallet* wallet, uint32_t earliestKeyTime,
                                  BRMerkleBlock* blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startSyncFrom);
    
// not thread-safe, set callbacks once before calling BRPeerManagerConnect()
// info is a void pointer that will be passed along with each callback call
// void syncStarted(void *) - called when blockchain syncing starts
// void syncStopped(void *, int) - called when blockchain syncing stops, error is an errno.h code
// void txStatusUpdate(void *) - called when transaction status may have changed such as when a new block arrives
// void saveBlocks(void *, int, const uint8_t *bytes, size_t len) - called when blocks should be saved to the
//   persistent store. The core serializes the blocks UNDER its lock and hands the immutable `bytes` buffer (NOT
//   live block pointers), so the callback can do a slow JNI upcall without racing a concurrent reorg free.
// - if replace is true, remove any previously saved blocks first
// void savePeers(void *, int, const BRPeer[], size_t) - called when peers should be saved to the persistent store
// - if replace is true, remove any previously saved peers first
// int networkIsReachable(void *) - must return true when networking is available, false otherwise
// void threadCleanup(void *) - called before a thread terminates to faciliate any needed cleanup
void BRPeerManagerSetCallbacks(BRPeerManager *manager, void *info,
                               void (*syncStarted)(void *info),
                               void (*syncStopped)(void *info, int error),
                               void (*txStatusUpdate)(void *info),
                               void (*saveBlocks)(void *info, int replace, const uint8_t *bytes, size_t len, uint64_t* memIntegrityCheck),
                               void (*savePeers)(void *info, int replace, const BRPeer peers[], size_t peersCount),
                               int (*networkIsReachable)(void *info),
                               void (*threadCleanup)(void *info));

// specifies a single fixed peer to use when connecting to the bitcoin network
// set address to UINT128_ZERO to revert to default behavior
void BRPeerManagerSetFixedPeer(BRPeerManager *manager, UInt128 address, uint16_t port);

// dynamically set the target peer connection count (full while catching up, fewer once synced);
// reducing gently disconnects the excess (never the download peer or the pinned own-node)
void BRPeerManagerSetMaxConnectCount(BRPeerManager *manager, size_t count);

// add a peer to the live candidate pool the manager picks from on the next
// BRPeerManagerConnect cycle. Idempotent — if the address+port pair is already
// present, this is a no-op. Returns 1 if the peer was newly added, 0 if it was
// already known. Use this to feed runtime-discovered peers (e.g. from a seeder
// API) into a manager that's already been built — passing them through the
// init-time savedPeers blob only works once and is lost on next connect cycle.
int BRPeerManagerAddPeer(BRPeerManager *manager, UInt128 address, uint16_t port,
                          uint64_t services);

// sets a custom start block
void BRPeerManagerSetStartBlock(BRPeerManager* manager, BRMerkleBlock* start);
    
// current connect status
BRPeerStatus BRPeerManagerConnectStatus(BRPeerManager *manager);

// Own-node first-class pairing. Pin a user-paired node (addr:port) as a reserved,
// never-churn-evicted compact-filter peer that BRPeerManagerConnect always dials
// first. exclusive != 0 makes the dialer contact ONLY the pinned node. These take
// manager->lock internally; call them from the JNI layer (which holds PEER_GUARD).
void BRPeerManagerSetPinnedPeer(BRPeerManager *manager, UInt128 addr, uint16_t port, int exclusive);

// Clear any pinned own-node, reverting to normal dial/eviction behavior.
void BRPeerManagerClearPinnedPeer(BRPeerManager *manager);

// Compact-filter status of the peer at addr:port, for the own-node connectivity UI:
// one of BR_CF_PEER_{UNKNOWN,CONNECTING,CONNECTED_NOT_SERVING,SERVING} (see
// BRPeerCFStatus.h). SERVING means it has answered a cfheaders/cfilter this session.
int BRPeerManagerCompactFilterPeerStatus(BRPeerManager *manager, UInt128 addr, uint16_t port);

// connect to bitcoin peer-to-peer network (also call this whenever networkIsReachable() status changes)
void BRPeerManagerConnect(BRPeerManager *manager);

// disconnect from bitcoin peer-to-peer network (may cause syncStopped() or savePeers() callbacks to fire; NOT
// saveBlocks() — in this codebase saveBlocks fires only from _peerRelayedBlock, never from a disconnect)
void BRPeerManagerDisconnect(BRPeerManager *manager);

// send a keepalive ping to every connected peer so idle CF filter-peer connections don't get
// dropped by the remote node / NAT inactivity timeout (call periodically, e.g. every ~10-20s)
void BRPeerManagerKeepAlive(BRPeerManager *manager);

// rescans blocks and transactions after earliestKeyTime (a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter)
void BRPeerManagerRescan(BRPeerManager *manager);

// the (unverified) best block height reported by connected peers
uint32_t BRPeerManagerEstimatedBlockHeight(BRPeerManager *manager);

// current proof-of-work verified best block height
uint32_t BRPeerManagerLastBlockHeight(BRPeerManager *manager);

// current proof-of-work verified best block timestamp (time interval since unix epoch)
uint32_t BRPeerManagerLastBlockTimestamp(BRPeerManager *manager);

// current network sync progress from 0 to 1
// startHeight is the block height of the most recent fully completed sync
double BRPeerManagerSyncProgress(BRPeerManager *manager, uint32_t startHeight);

// returns the number of currently connected peers
size_t BRPeerManagerPeerCount(BRPeerManager *manager);

// description of the peer most recently used to sync blockchain data
const char *BRPeerManagerDownloadPeerName(BRPeerManager *manager);

// publishes tx to bitcoin network (do not call BRTransactionFree() on tx afterward)
void BRPeerManagerPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                            void (*callback)(void *info, int error));

// number of connected peers that have relayed the given unconfirmed transaction
size_t BRPeerManagerRelayCount(BRPeerManager *manager, UInt256 txHash);

// Enable/disable Dandelion stem submission (default on). Thread-safe.
void BRPeerManagerSetDandelionEnabled(BRPeerManager *manager, int enabled);

// Register a peer address as Dandelion-capable (sourced from the seeder + the
// priority peer; there is no service bit to read). Idempotent, thread-safe.
void BRPeerManagerAddDandelionPeer(BRPeerManager *manager, UInt128 address);

// 1 if Dandelion is enabled AND a connected peer is Dandelion-capable.
int BRPeerManagerHasDandelionPeer(BRPeerManager *manager);

// Stem-submit a signed tx to ONE Dandelion-capable peer (sets is_dandelion=1 and
// invs only that peer; the peer's getdata then pulls the dandeliontx). Returns 1
// if stemmed, 0 if no capable peer was available (caller should then fall back to
// BRPeerManagerPublishTx for a normal flood). Do not BRTransactionFree(tx) after.
int BRPeerManagerStemPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                               void (*callback)(void *info, int error));

// Re-broadcast (flood) a previously stem-submitted tx to all connected peers,
// clearing the dandelion flag. Idempotent; no-op if the tx isn't in the publish list.
void BRPeerManagerFluffTx(BRPeerManager *manager, UInt256 txHash);

// ----------- BIP 158 compact-filter sync (opt-in) -----------
//
// The functions below are inert until BRPeerManagerSetSyncMode is called with
// a mode other than BR_SYNC_MODE_BLOOM_ONLY. With BLOOM_ONLY (the default)
// the manager behaves exactly as before.
//
// Lifecycle for a filter-sync-enabled wallet:
//   1) BRPeerManagerSetSyncMode(manager, BR_SYNC_MODE_COMPACT_FILTERS_ONLY)
//   2) Either pass a previously persisted chain via SetCompactFilterChain
//      (deserialize from SharedPreferences) or skip — the manager will lazily
//      create one anchored at startHeight=0 / UINT256_ZERO on the first
//      cfheaders batch.
//   3) Register saveFilterHeaders so the manager can persist progress every
//      time it successfully extends the chain.
//   4) BRPeerManagerConnect — peers advertising NODE_COMPACT_FILTERS will be
//      driven to send cfheaders/cfheaders/cfcheckpt; the chain accumulator
//      validates continuity and the manager misbehavin's any peer whose
//      batch breaks the chain.

// Set the sync mode. Must be called before BRPeerManagerConnect, or before
// the next BRPeerManagerRescan. No-op if the same mode is already set.
void BRPeerManagerSetSyncMode(BRPeerManager *manager, BRSyncMode mode);

BRSyncMode BRPeerManagerGetSyncMode(BRPeerManager *manager);

// Current compact-filter chain tip height (0 if no chain yet). Used by
// the watchdog to detect "filter peers connected but not making progress."
uint32_t BRPeerManagerCFChainTipHeight(BRPeerManager *manager);

// Re-anchor the compact-filter chain at the block floor when cfTip is stuck
// below the downloaded chain (legacy deficit). Returns 1 if re-anchored.
int BRPeerManagerReanchorCompactFilterChainAtFloor(BRPeerManager *manager);

// Proactively re-issue a full-locator getheaders to all connected peers to un-stick
// a frozen block-header tip (all other getheaders senders are reactive). Called by
// the Kotlin tip-stall watchdog. Returns the peer count the request was sent to.
int BRPeerManagerRerequestHeadersFromTip(BRPeerManager *manager);

// Provide a previously persisted filter-header chain. The manager takes
// ownership of the chain pointer; do not free it. Passing NULL clears any
// existing chain. Must be called before BRPeerManagerConnect.
void BRPeerManagerSetCompactFilterChain(BRPeerManager *manager,
                                         BRCompactFilterChain *chain);

// Borrowed pointer into the manager's chain (do NOT free). NULL when sync
// mode is BLOOM_ONLY or no batches have been received yet.
const BRCompactFilterChain *BRPeerManagerGetCompactFilterChain(BRPeerManager *manager);

// Persistence hook. Called from inside the manager lock after every
// successful BRCompactFilterChainAppend, with the chain pointer that was
// updated. The callback may serialize it via BRCompactFilterChainSerialize.
// Pass NULL to clear.
void BRPeerManagerSetSaveFilterHeaders(BRPeerManager *manager, void *info,
                                       void (*saveFilterHeaders)(void *info,
                                                                  const BRCompactFilterChain *chain));

// ---- CF scan-completeness ledger (Phase 1: observe-only) -------------------
// Per-height BIP157/158 scan-completeness bookkeeping. The manager owns one
// ledger, populated under manager->lock by the CF request/eval/drop paths. In
// Phase 1 these accessors are read-only reporting for the UI/JNI; nothing here
// alters sync behavior. Each takes manager->lock for the duration of the call.

// Snapshot the ledger's scalar counts. Any out-pointer may be NULL to skip it.
void BRPeerManagerCFLedgerCounts(BRPeerManager *manager, uint32_t *scannedThrough, uint32_t *outstanding,
                                 uint32_t *gaveUp, uint32_t *pending);

// Coalesce the outstanding + gaveUp heights into ascending [start..end] ranges.
// Writes up to `cap` ranges into outStarts/outEnds; returns the number written.
size_t BRPeerManagerCFLedgerHoleRanges(BRPeerManager *manager, uint32_t *outStarts, uint32_t *outEnds, size_t cap);

// Serialize the ledger into buf. Returns the byte count the blob needs; writes it
// iff buflen is large enough (call with buf NULL / buflen 0 to size first).
size_t BRPeerManagerCFLedgerSerialize(BRPeerManager *manager, uint8_t *buf, size_t buflen);

// Restore a ledger blob produced by BRPeerManagerCFLedgerSerialize. Returns 1 on
// success, 0 on a garbled/short blob (ledger left empty for the caller to rebuild).
int BRPeerManagerCFLedgerRestore(BRPeerManager *manager, const uint8_t *buf, size_t buflen);

// Persistence hook. Called from inside the manager lock after each successful
// cfheaders extend, with the serialized ledger blob. Pass NULL to clear.
void BRPeerManagerSetSaveCFLedger(BRPeerManager *manager, void *info,
                                  void (*callback)(void *info, const uint8_t *bytes, size_t len));

// ---- CF scan-frontier + abandonment accessors (paced-convoy fetch, Task 1) -
// Read-only wrappers around the ledger's CF-retention scan-floor API (see
// BRCFScanLedger.h "CF-retention scan-floor (Task 1)"). Each takes
// manager->lock for the duration of the call, same as the Phase 1 accessors
// above. The paced-convoy fetch gate/driver's fetch frontier is
// LowestNeededHeight, NOT scannedThrough — LowestNeededHeight folds in the
// hard abandonedBelow floor, scannedThrough alone does not.

// Lowest height the CF scan still needs a header retained for:
// max(scannedThrough+1, abandonedBelow). O(1).
uint32_t BRPeerManagerLowestNeededHeight(BRPeerManager *manager);

// The retention hard-floor watermark: heights below this have been
// permanently abandoned (too deep to retain) and are never re-requested.
// MONOTONIC (only ever advances).
uint32_t BRPeerManagerAbandonedBelow(BRPeerManager *manager);

// Cumulative count of heights abandoned so far: heights in
// [start .. abandonedBelow-1], i.e. max(abandonedBelow - start, 0).
size_t BRPeerManagerAbandonedCount(BRPeerManager *manager);

// ---- B2 valve / watchdog ORDERING (paced-convoy fetch, Task 6, spec Part C) -
//
// "Is the B2 abandonment valve currently mid-decision on the hole that PINS the
// scan frontier?" — the signal the Kotlin tip-stall watchdog uses to stand down
// while the valve does its work, so the two scan-stall watchers do not race
// (the valve owns a KNOWN gaveUp stall and its re-arm IS productive work, where
// the watchdog's escalation — an ungated getheaders, then a manager recreate —
// is pure churn on top of it).
//
// PENDING covers BOTH halves of the valve's window, not just the decision instant:
//   (a) the frontier-pinning hole is PARKED in gaveUp — the valve decides at the
//       next KeepAlive tick; and
//   (b) the frontier-pinning hole is OUTSTANDING with rearmCycles > 0 — a
//       valve-granted RE-ARM CYCLE IS IN FLIGHT (~7.5 min of rotated retry, the
//       larger half of the window). An ordinary outstanding hole (rearmCycles == 0)
//       belongs to the residual driver, not the valve, and reads 0.
//
// RETURN VALUE — a COUNT, not a boolean, and that is load-bearing:
//   0  == the valve owns nothing at the scan frontier; nothing pending.
//   N>0 == the valve is on cycle N of that hole: N == 1 is the ORIGINAL cycle
//          (exhausted, no re-arm granted yet); N == 2 is the first re-arm cycle
//          (in flight, or exhausted and being decided); in general
//          N == rearmCycles + 1, and the valve may abandon once
//          N == CF_CONVOY_REARM_MAX + 1. Saturating (rearmCycles is a uint8_t
//          widened to uint32_t), so it never wraps back to 0 and can never be
//          mistaken for "not pending".
//
// WHY A COUNT (do NOT reduce this to a bare boolean — the Task-5 review found the
// failure it prevents). The valve's per-cycle offersReachedLivePeer latch is
// cleared by ANY disconnect of the peer stamped on the hole, and a deciding cycle
// is 5 offers over ~7.5 min. On a churny fleet — canon oracles at maxconnections,
// errno-101 blips, ~8 peers rotating — EVERY cycle can be tainted, so the valve
// re-arms INDEFINITELY and this function returns non-zero forever. A consumer
// that suppresses its watchdog on a bare "pending" would then stand down FOREVER,
// in exactly the case the backstop exists for. So BOUND THE SUPPRESSION on this
// value: suppress only while the returned N is within the cycles the valve is
// actually entitled to (N <= CF_CONVOY_REARM_MAX + 1, i.e. through the deciding
// cycle); once N exceeds that, the hole is re-arming without converging and MUST
// be re-exposed to the watchdog. The resulting failure mode is a bounded-memory
// VISIBLE stall (the convoy gate holds manager->blocks flat at ~W+144), never an
// OOM and never a silent wrong balance.
//
// The pinning-hole predicate is the valve's own (the LOWEST hole of either kind —
// _cfLedgerAdvance caps scannedThrough at min(outstanding[0], gaveUp[0]) - 1), so a
// consumer can never defer to a valve decision that is not actually happening: a
// gaveUp height sitting ABOVE a still-outstanding hole does not pin the frontier,
// is not the valve's business, and reads 0 here.
//
// LOCKING: takes manager->lock, like every other public accessor here. Call it
// from the JNI layer OUTSIDE any lock — NEVER from in-lock code (KeepAlive,
// _peerRelayed*, _BRPeerManagerRequestNextCFHeaders); manager->lock is
// NON-recursive and in-lock callers must read BRCFScanLedgerLowestGaveUp directly.
uint32_t BRPeerManagerHasPendingAbandonment(BRPeerManager *manager);

// Request cfilters for the inclusive range [startHeight, stopHeight] from
// any filter-capable peer that is currently connected. Caps the range at
// MAX_CFILTERS_RESULTS; if the requested range is larger, only the first
// MAX_CFILTERS_RESULTS blocks are requested and the caller must call again
// with the remainder.
//
// Returns the number of blocks actually requested (0 if no eligible peer
// is connected, or both endpoints fall outside the in-memory block window).
size_t BRPeerManagerRequestCompactFilters(BRPeerManager *manager,
                                          uint32_t startHeight, uint32_t stopHeight);

// Enable automatic cfilter requesting. Once enabled, every successful
// cfheaders batch triggers a cfilter request for the new range capped at
// MAX_CFILTERS_RESULTS, starting from max(startHeight, lastRequested+1).
// "startHeight" should be the wallet's birth height (height of earliest
// block that could contain a wallet-relevant tx). Pass 0 to scan from
// genesis.
//
// SPV wallets only persist a window of block headers near the current
// tip, so passing a startHeight below that window would defer the first
// cfheaders batch forever (the driver can't produce a stopHash for an
// unknown block). The implementation snaps startHeight up to a height it
// can resolve, biased toward lastBlock. Use BRPeerManagerGetAutoFetchCFiltersStart
// to read back the value the manager actually committed to.
//
// Disable resets the auto-fetch cursor so the next Enable starts fresh.
void BRPeerManagerEnableAutoCompactFilterFetch(BRPeerManager *manager, uint32_t startHeight);
void BRPeerManagerDisableAutoCompactFilterFetch(BRPeerManager *manager);
uint32_t BRPeerManagerGetAutoFetchCFiltersStart(BRPeerManager *manager);

// Read back the current forward-fetch cursor (autoFetchCFiltersThrough). Mostly
// useful for before/after logging around BRPeerManagerSnapAutoFetchThroughToScanFrontier
// below.
uint32_t BRPeerManagerGetAutoFetchCFiltersThrough(BRPeerManager *manager);

// ---- Resume cursor reconciliation (paced-convoy fetch, Task 4, spec Part
// B1-resume) --------------------------------------------------------------
//
// On resume, the caller arms auto-fetch via BRPeerManagerEnableAutoCompactFilterFetch
// (autoFetchCFiltersThrough = birthHeight-1) BEFORE the persisted CF scan ledger
// is restored (BRPeerManagerCFLedgerRestore), which can set scannedThrough far
// above birthHeight. Left unreconciled, the very next forward-fetch tick
// re-requests from birthHeight (reqStart = autoFetchCFiltersThrough+1) --
// already-scanned history -- and BRCFScanLedgerRecordRequested re-inserts those
// heights as outstanding, dragging scannedThrough back down: the persisted scan
// progress is thrown away and the whole birth->tip descent restarts.
//
// Call this ONCE, immediately after restoring the ledger, to snap the cursor up
// to BRCFScanLedgerLowestNeededHeight - 1 (NOT LowestNeededHeight itself --
// reqStart is autoFetchCFiltersThrough+1, so snapping to LowestNeededHeight would
// make the next fetch start one height too high and silently skip it forever,
// the exact bug class this ledger subsystem exists to prevent). Folds in the
// ledger's abandonedBelow hard floor via LowestNeededHeight, so an abandoned
// prefix is never re-requested either. A no-op on a not-yet-armed ledger
// (LowestNeededHeight == 0).
//
// ⚠️ IT IS NO LONGER RAISE-ONLY (paced-convoy fix wave, C-1) — do not "restore"
// that. On a RESUME, BRPeerManagerEnableAutoCompactFilterFetch's resolvability
// clamp lands on the SAVED-BLOCKS TIP, because a resumed manager's in-memory chain
// is only the checkpoints plus the persisted
// [savedTip-(SAVE_BLOCK_COUNT-1) .. savedTip] run, so a deep birth height cannot
// resolve. (Fix wave R2 lowered that floor from the saved tip itself, where the old
// FORWARD chaining left it, to savedTip-299 — still ~a full convoy window above a
// resumed deep descent's frontier, so nothing here changes.) Both `autoFetchCFiltersStart` and the cursor therefore start
// ~CF_CONVOY_WINDOW ABOVE the restored scan frontier, and every forward-fetch site
// clamps reqStart UP to autoFetchCFiltersStart — so a raise-only snap could never
// pull them back down and the next forward request began at the clamped tip, which
// made _cfLedgerAdvance sail scannedThrough over ~CF_CONVOY_WINDOW never-requested
// heights with abandonedBelow still 0 (no WARN, no banner, wallet reports Synced).
// This function therefore now:
//   1. SURFACES any still-needed history below the in-memory block floor
//      (BRCFScanLedgerAbandonUnscannableBelow + WARN) — that band is unservable for
//      the whole session, so it becomes skipped-and-surfaced-and-recoverable
//      instead of silently skipped;
//   2. lowers autoFetchCFiltersStart to the frontier and clamps the cursor down to
//      cfLedger.requestedThrough (a cursor above what was actually requested is
//      what lets a non-contiguous RecordRequested sail), then raises it to
//      LowestNeededHeight - 1 as before.
//
// LOCKING: unlike the file-static _cfConvoy*/B1-driver helpers (which run INSIDE
// an already-locked BRPeerManagerKeepAlive pass and must NOT take the lock),
// this is a public entry point meant to be called from the JNI layer OUTSIDE any
// lock, so it takes manager->lock itself. Do NOT call it from any already-locked
// path -- manager->lock is NON-recursive.
void BRPeerManagerSnapAutoFetchThroughToScanFrontier(BRPeerManager *manager);

// ---- Runtime-readable convoy constants (spec Part C: "ideally runtime-readable")
//
// CF_CONVOY_WINDOW and CF_CONVOY_REARM_MAX are consumed on BOTH sides of the JNI
// boundary: the native gate/valve use them directly, and the Kotlin tip-stall +
// BIP158 watchdogs need them to decide "the header tip is frozen BY DESIGN"
// (isConvoyWindowFull) and "the valve still owns this stall" (isConvoySuppressed,
// bounded at CF_CONVOY_REARM_MAX + 1). Hand-mirroring them in Kotlin is a DRIFT
// TRAP with teeth, and the spec's own tuning signal tells the operator to raise
// CF_CONVOY_REARM_MAX here when an abandoned height later reconciles:
//   * REARM_MAX raised natively only -> Kotlin releases its suppression at 4 while
//     the valve is legitimately still working cycles 4..N, so the tip-stall
//     watchdog escalates INTO a productive valve and tier 2 recreates the manager;
//   * WINDOW lowered natively only -> Kotlin reads "window not full", drops the
//     tip-frozen conjunct, and arms tier 1/tier 2 during a HEALTHY paced descent.
// These accessors exist so Kotlin DERIVES both values at runtime and there is no
// second copy to drift. Pure constant readers: no manager, no lock, safe anywhere.
uint32_t BRPeerManagerConvoyWindow(void);
uint32_t BRPeerManagerConvoyRearmMax(void);

// ----------- end BIP 158 opt-in -----------

// frees memory allocated for manager (call BRPeerManagerDisconnect() first if connected)
void BRPeerManagerFree(BRPeerManager *manager);
	
/*
 * The following two methods sync the blockchain beginning from startBlock.
 *
 * Usage: Create a custom merkle block and pass it to BPPeerManagerMainNetNewEx()
 *     BRMerkleBlock* test = BRMerkleBlockNew();
 *     test->blockHash = UInt256Reverse(uint256("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496"));
 *     test->height = 0;
 *     test->timestamp = 1389388394;
 *     test->target = 0x1e0ffff0;
 */

BRPeerManager* BPPeerManagerMainNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock);

BRPeerManager* BPPeerManagerTestNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock);
    
// function to create Peermanager under for the mainnet directly
BRPeerManager *BPPeerManagerMainNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);

// function to create Peermanager under for the testnet directly
BRPeerManager *BPPeerManagerTestNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);


#ifdef __cplusplus
}
#endif

#endif // BRPeerManager_h
