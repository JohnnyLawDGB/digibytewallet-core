//
//  BRCFScanLedger.h
//
//  Per-height compact-filter (BIP157/158) scan-completeness ledger.
//
//  In COMPACT_FILTERS_ONLY the wallet requests cfilters in forward batches
//  and advances a single monotonic cursor (BRPeerManager's
//  autoFetchCFiltersThrough) the moment a getcfilters is *sent* — not when
//  each cfilter is *evaluated*. Any height whose cfilter is dropped before
//  evaluation (header race, verify-fail, GCS parse-fail, or a peer that
//  disconnected mid-batch) becomes a permanent hole, and a hole over a block
//  that pays the wallet is a missed receive. This ledger keeps a per-height
//  record so a "scanned" high-water (scannedThrough) advances ONLY over
//  heights that were actually evaluated, and so dropped heights can be
//  re-requested (Phase 2).
//
//  This module is PURE: it holds no locks and no sockets and depends only on
//  BRInt.h (UInt128/UInt256). BRPeerManager owns one instance and calls into
//  it only while holding manager->lock. Being pure, it is host-KAT-testable
//  standalone (see native/src/test/host/cf_scan_ledger_kat/), the same shape
//  as BRPeerCFStatus.h / BRComputeCFPeerStatus.
//
//  Design: docs/superpowers/specs/2026-07-25-cf-scan-ledger-design.md
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

#ifndef BRCFScanLedger_h
#define BRCFScanLedger_h

#include <stdint.h>
#include <stddef.h>
#include "BRInt.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- Phase gate (§6) -------------------------------------------------------
// A single, clearly-named compile-time constant gates all *behavior change* at
// the caller (BRPeerManager). Phase 1 = 0 (observe only): populate the ledger,
// log holes, expose counts — but never re-request. The Phase 2 PR flips this to
// 1 to arm the re-request driver / back-pressure / header-race retry.
//
// NOTE: this gate is a CALLER guard. BRCFScanLedgerNextRerequest (the Phase-2
// driver logic) is ALWAYS compiled so it stays unit-testable; production simply
// does not invoke it while the gate is 0.
#ifndef CF_LEDGER_DRIVE_REREQUEST
#define CF_LEDGER_DRIVE_REREQUEST 1   // Phase 2: driver ARMED (buffer-drain + residual re-request + back-pressure). -D wins for KATs.
#endif

// Sentinel: "no height was evicted" — returned by the overflow-drop-reporting
// insert/record paths so a real (32-bit) evicted height is never ambiguous
// with "nothing dropped".
#define CF_LEDGER_NO_DROP 0xFFFFFFFFu

// ---- Bounds & pinned constants (§3) ----------------------------------------
#define CF_OUTSTANDING_MAX      4096  // hard cap; overflow drops OLDEST (caller LOGWs its height range)
#define CF_PENDING_CONFIRM_MAX   256  // blocks awaiting header-connect confirmation
#define CF_PENDING_TX_MAX         32  // wallet txs recorded per pending block (small, capped)
#define CF_GAVEUP_MAX            512  // heights that exhausted retries — REPORTED, never dropped

// Phase-2 re-request backoff — PINNED 2026-07-25 (§3, §13):
#define CF_REREQ_HEADERRACE_SECS  10  // header-race first retry — the header connects quickly
#define CF_REREQ_BASE_SECS        30  // all other holes: base delay
#define CF_REREQ_BACKOFF_CAP_SECS 120 // delay = min(BASE << attempts, CAP) → 30/60/120/120/120
#define CF_REREQ_MAX_ATTEMPTS      5  // per-height cap; on reaching it → gaveUp list (NEVER silent)
#define CF_REREQ_MAX_RANGE      1000  // == MAX_CFILTERS_RESULTS (BRPeer.h:116) — Peek's coalesced-run cap

// Phase-2 driver back-pressure (Task 5, BRPeerManagerKeepAlive) — PINNED 2026-07-26:
// forward auto-fetch pauses once outstandingCount reaches this low-water mark, so a
// stalled/slow filter peer can't grow the outstanding set past CF_OUTSTANDING_MAX
// (which would start silently evicting the oldest holes). Left with headroom under
// the hard cap so eviction should never actually trigger in practice.
#define CF_OUTSTANDING_LOWWATER 3072
// Cap on residual re-request ranges (peek/commit) offered per BRPeerManagerKeepAlive
// tick — bounds the driver's per-tick work under a large outstanding/gaveUp set.
#define CF_REREQ_BATCH_PER_TICK   64

// Filter-byte buffer (Phase 2 Task 2, §7) — a header-race-dropped cfilter's raw
// (unverified) bytes are held here, keyed by blockHash, until its header AND
// cfheader both connect. Byte-budgeted, not count-budgeted: eviction is driven
// by CF_FILTER_BUFFER_MAX_BYTES; CF_FILTER_BUF_SLOTS is only a fixed-capacity
// backstop against a pathological run of many tiny filters exhausting the
// pointer array (real GCS filters average well under budget/slots bytes).
#define CF_FILTER_BUFFER_MAX_BYTES 262144  // 256 KiB total buffered raw filter bytes
#define CF_FILTER_DRAIN_PER_TICK   128      // max READY entries dispatched per DrainConnected call
#define CF_FILTER_BUF_SLOTS        2048     // fixed-capacity backstop, independent of the byte budget

// Age-out backstop (Task 3, stale-buffer livelock fix, §7): a pruned/orphaned
// hash can be re-served by a peer indefinitely, keeping its bytes buffered
// forever (BufferFilter's de-dup path resets `at` on every re-buffer, so an
// `at`-keyed age-out would never fire). This is byte reclamation, NOT a
// livelock guarantee (Task 4 handles correctness) — 900s (15 min) is chosen
// to sit well above the re-request retry schedule (30+60+120+120+120 = 7.5
// min), so a legitimately-slow header still drains before age-out, and well
// below the retention margin.
#define CF_FILTER_BUF_MAX_AGE_SECS 900

// ---- Records ---------------------------------------------------------------

// One requested-but-not-yet-evaluated height. `outstanding` is kept sorted
// ascending by height so the scannedThrough walk is O(gap) and the lowest hole
// is always outstanding[0].
typedef struct {
    uint32_t height;
    UInt128  peer;         // peer the getcfilters was sent to (for rotate-away)
    uint16_t port;
    uint32_t requestedAt;  // unix secs; re-request backoff clock (NOT persisted)
    uint8_t  attempts;     // re-requests already made; capped at CF_REREQ_MAX_ATTEMPTS (NOT persisted)
    uint8_t  headerRace;   // dropped because the block header wasn't known yet → short retry
} BRCFOutstanding;

// Wallet txs from a CF-driven full block whose header hasn't connected yet.
// Transient (in-memory only) — NOT persisted (a re-anchor/rescan rebuilds it).
typedef struct {
    UInt256  blockHash;
    UInt256  txHashes[CF_PENDING_TX_MAX];   // wallet txs awaiting this block's header
    uint16_t txCount;
    uint32_t recordedAt;
} BRCFPendingConfirm;

// One buffered raw (unverified) cfilter awaiting both its block header and its
// cfheader to connect. `bytes` is a malloc'd copy of the wire payload; freed on
// eviction, drain-removal, ClearFilterBuffer, or Free. In-memory only — NOT
// persisted (§ClearFilterBuffer note d: process death -> normal floor re-anchor).
typedef struct {
    UInt256  blockHash;
    uint8_t *bytes;
    size_t   len;
    uint32_t at;      // unix secs when (re-)buffered; reset on every re-buffer (observability only)
    uint32_t firstAt;  // unix secs when FIRST buffered; immutable-per-entry so age-out
                       // (BRCFScanLedgerEvictAgedFilters) can't be rejuvenated by a re-serving peer
} BRCFFilterBufEntry;

typedef struct {
    uint32_t start;              // birth height, inclusive (mirrors autoFetchCFiltersStart)
    uint32_t scannedThrough;     // contiguous high-water: EVERY height in [start..this] was EVALUATED
                                 //   (matched or cleanly missed). Never passes an outstanding/gaveUp hole.
    uint32_t requestedThrough;   // max stop ever recorded — scannedThrough's ceiling, tracked here so it is
                                 //   independent of BRPeerManager's autoFetchCFiltersThrough.
    uint32_t abandonedBelow;     // retention HARD FLOOR (CF-retention scan-floor, Task 1): heights below this
                                 //   have been abandoned (too deep to retain — their headers pruned by the
                                 //   memory ceiling) and are NEVER re-requested. MONOTONIC (only advances).
                                 //   Advanced ONLY by BRCFScanLedgerAbandonGaveUpBelow, never past a still-
                                 //   outstanding (retrying) hole. Persisted (blob v2; a v1 blob loads it as 0).
    BRCFOutstanding    outstanding[CF_OUTSTANDING_MAX];   // sorted ascending by height
    size_t             outstandingCount;
    BRCFPendingConfirm pending[CF_PENDING_CONFIRM_MAX];
    size_t             pendingCount;
    uint32_t           gaveUp[CF_GAVEUP_MAX];  // sorted ascending; heights past the attempt cap — reported,
    size_t             gaveUpCount;            //   persisted, NEVER silently dropped (else we rebuild the bug)
    uint32_t           lastDriveAt;            // re-request driver throttle (Phase 2)

    // Filter-byte buffer (Task 2, §7): FIFO, oldest at index 0. In-memory only —
    // NOT persisted (Serialize/Parse never touch this section).
    BRCFFilterBufEntry *filterBuf[CF_FILTER_BUF_SLOTS];
    size_t              filterBufCount;
    size_t              bufferedBytes;
    // Internal marker (NOT part of the persisted/public contract, NOT a
    // memory-safety guarantee): set only by Init/Parse. It is a defensive
    // heuristic so the free-before-memset step in Init/Parse behaves
    // predictably under the host-KAT's unzeroed-stack test pattern (see the
    // comment on _cfLedgerFreeFilterBuffer in BRCFScanLedger.c for why it
    // isn't, and can't be, a real guarantee). The actual precondition every
    // caller must uphold is: `l` is zeroed (e.g. calloc'd, as the real
    // production BRPeerManager ledger always is) or already Init/Parse'd
    // before the first BufferFilter/Init/Parse call on it.
    uint32_t            filterBufMagic;
} BRCFScanLedger;

// ---- Pure operations (host-testable) ---------------------------------------

// Zero the ledger and set the scan floor. scannedThrough/requestedThrough start
// at start-1 (nothing evaluated/requested yet). `start` is a real birth height (>0).
void     BRCFScanLedgerInit(BRCFScanLedger *l, uint32_t start);

// Add every height in [startH..stopH] to `outstanding` (sorted, de-duplicated)
// and raise requestedThrough. A height already outstanding just refreshes its
// target (peer/port/requestedAt) — used by a re-request. On CF_OUTSTANDING_MAX
// overflow the OLDEST (lowest-height, front) entry is dropped in-module; the
// loud height-range log is the caller's job.
void     BRCFScanLedgerRecordRequested(BRCFScanLedger *l, uint32_t startH, uint32_t stopH,
                                        UInt128 peer, uint16_t port, uint32_t now);

// Same as BRCFScanLedgerRecordRequested but never silent about CF_OUTSTANDING_MAX
// overflow: returns the count of oldest heights evicted to make room and, if
// outLow/outHigh are non-NULL, writes the evicted heights' [low..high] range
// (CF_LEDGER_NO_DROP in each if none were evicted). requestedThrough still
// advances to stopH regardless — it is scannedThrough's ceiling and must never
// fail to track the caller's actual request range.
int      BRCFScanLedgerRecordRequestedDropped(BRCFScanLedger *l, uint32_t startH, uint32_t stopH,
                                              UInt128 peer, uint16_t port, uint32_t now,
                                              uint32_t *outLow, uint32_t *outHigh);

// A cfilter for `height` was evaluated (matched or cleanly missed). Remove it
// from outstanding (and, defensively, gaveUp) and advance scannedThrough over
// any newly-contiguous evaluated run.
void     BRCFScanLedgerMarkEvaluated(BRCFScanLedger *l, uint32_t height);

// The cfilter for `height` was dropped because its block header wasn't known
// yet. Keep it outstanding and flag it for the fast (10s) header-race retry.
void     BRCFScanLedgerMarkHeaderRace(BRCFScanLedger *l, uint32_t height);

// A peer disconnected with a batch in flight: clear the recorded peer on every
// outstanding height that targeted (peer,port), keeping the heights (and their
// attempt counts) so the driver re-requests them from someone else.
void     BRCFScanLedgerReArmPeer(BRCFScanLedger *l, UInt128 peer, uint16_t port);

// Phase-2 driver: offer the lowest-height outstanding hole whose backoff has
// elapsed, applying the pinned schedule (header-race 10s first, else
// 30/60/120/120/120). Increments that height's attempt count and re-stamps its
// clock. A height that reaches CF_REREQ_MAX_ATTEMPTS is moved to the `gaveUp`
// list (reported, never silently dropped) and no longer offered. Returns 1 and
// writes *outHeight when a height is offered, else 0. Always compiled so it is
// unit-testable; production gates its invocation on CF_LEDGER_DRIVE_REREQUEST.
int      BRCFScanLedgerNextRerequest(BRCFScanLedger *l, uint32_t now, uint32_t *outHeight);

// ---- Phase-2 residual re-request driver (Task 3, peek/commit + retire) ----
// Serves only the RESIDUAL drop set (verify/parse/disconnect — the dominant
// header-race floor cluster is handled by the Task 2 filter buffer instead).
// The three-call shape lets the caller (BRPeerManager) build a real
// getcfilters wire message from the offered range before committing to it:
// a failed/partial send never burns an attempt on heights it didn't reach.

// Move every outstanding entry that has reached CF_REREQ_MAX_ATTEMPTS to the
// gaveUp list (reported, never silently dropped). PUBLIC — the caller runs
// this once per driver "tick", NOT automatically inside Peek.
void     BRCFScanLedgerRetireCapped(BRCFScanLedger *l);

// Offer (without mutating) the lowest-height outstanding, sub-cap-attempt,
// due (backoff-elapsed per the pinned schedule) hole at height >= minHeight.
// Coalesces forward into the longest contiguous run sharing the same
// (peer,port), all due, all sub-cap, capped at CF_REREQ_MAX_RANGE heights.
// Writes [*outStart..*outStop] and returns 1 when a run is offered, 0 if
// nothing is due. Does NOT retire capped entries (see RetireCapped) and does
// NOT bump attempts/timestamps (see CommitRerequest) — purely a peek.
int      BRCFScanLedgerPeekRerequestRange(BRCFScanLedger *l, uint32_t now, uint32_t minHeight,
                                          uint32_t *outStart, uint32_t *outStop);

// Record that a getcfilters covering [startH..stopH] was actually sent to
// (peer,port) at `now`: for every height in range that is STILL outstanding,
// bump its attempt count and re-stamp its peer/port/requestedAt. Heights in
// range that were already evaluated (no longer outstanding) are silently
// skipped. A caller that only sent part of an offered range (e.g. a partial
// batch) should pass just the sub-range that actually went on the wire — the
// rest keeps its old attempt count and is offered again next tick.
void     BRCFScanLedgerCommitRerequest(BRCFScanLedger *l, uint32_t startH, uint32_t stopH,
                                       UInt128 peer, uint16_t port, uint32_t now);

uint32_t BRCFScanLedgerScannedThrough(const BRCFScanLedger *l);
size_t   BRCFScanLedgerOutstandingCount(const BRCFScanLedger *l);
size_t   BRCFScanLedgerGaveUpCount(const BRCFScanLedger *l);

// ---- CF-retention scan-floor (Task 1) --------------------------------------

// Lowest height the CF scan still needs a header retained for. O(1).
//   == max(scannedThrough+1, abandonedBelow)
// gaveUp-INCLUSIVE by construction: _cfLedgerAdvance already caps scannedThrough
// at min(outstanding[0], gaveUp[0]) - 1, so scannedThrough+1 folds in gaveUp
// (retry-exhausted holes whose buffered bytes still need the header to
// drain+credit) AND buffered heights (buffered ⊆ outstanding∪gaveUp). Do NOT
// "simplify" this to exclude gaveUp: a buffered+gaveUp height would lose its
// header and its receive is silently lost. BRPeerManager's _BRPeerManagerClearMemory
// bounds the retained span at min(cfNext, this) - CLEAR_MEM_CF_RETENTION_MARGIN.
uint32_t BRCFScanLedgerLowestNeededHeight(const BRCFScanLedger *l);

// The retention hard-floor watermark: heights below this are abandoned (too deep
// to retain) and never re-requested. MONOTONIC. Surfaced to the UI/status so the
// abandoned count is a reported, countable event — distinct from "scanned".
uint32_t BRCFScanLedgerAbandonedBelow(const BRCFScanLedger *l);

// Retention memory ceiling reached: abandon retry-exhausted (gaveUp) heights that
// are too deep to keep retaining. The PURE ledger has no logger — it RETURNS the
// data the caller (BRPeerManager) warn-logs; do not add a logger dependency here.
//   - Drops gaveUp[] entries < target (= min(clamp, lowest-still-outstanding),
//     the new watermark) — NOT < clamp. A gaveUp in [target, clamp), i.e. above a
//     still-outstanding hole, is KEPT: dropping it would lose it silently after a
//     restart (gone from gaveUp, not below the persisted abandonedBelow watermark).
//   - Advances abandonedBelow to min(clamp, lowest-still-OUTSTANDING-height): NEVER
//     past a still-retrying outstanding hole (that hole is recoverable — not
//     abandoned; only retry-exhausted gaveUp heights are). abandonedBelow only
//     ever advances (monotonic — a lower clamp never regresses it).
//   - If outCount/outLo/outHi are non-NULL, writes the number of gaveUp heights
//     abandoned by THIS call and their [lo..hi] range (CF_LEDGER_NO_DROP in each
//     when none were abandoned) so the caller can warn-log it.
// Returns the new lowest-still-needed height (== BRCFScanLedgerLowestNeededHeight
// after the mutation) — the caller's new retention floor target.
uint32_t BRCFScanLedgerAbandonGaveUpBelow(BRCFScanLedger *l, uint32_t clamp,
                                          uint32_t *outCount, uint32_t *outLo, uint32_t *outHi);

// Coalesce the outstanding + gaveUp heights into ascending [start..end] ranges
// for the JNI/UI hole report. Writes up to `cap` ranges into outStarts/outEnds
// and returns the number written.
size_t   BRCFScanLedgerHoleRanges(const BRCFScanLedger *l, uint32_t *outStarts, uint32_t *outEnds, size_t cap);

// ---- Filter-byte buffer (§7, header-race hold) -----------------------------

// PRECONDITION: `l` must already have been through BRCFScanLedgerInit or
// BRCFScanLedgerParse (or otherwise be a zeroed struct) before the FIRST call
// to BufferFilter. BufferFilter does not — and cannot — establish that on its
// own: it reads filterBufCount/filterBuf[] as part of the de-dup scan on
// every call, so calling it on a never-Init'd struct is unconditionally
// unsafe regardless of anything BufferFilter itself does first.
//
// Store a raw (unverified) cfilter keyed by blockHash. De-dups by hash (a
// re-buffer of the same block replaces its bytes in place). Byte-budgeted:
// while bufferedBytes + len > CF_FILTER_BUFFER_MAX_BYTES, evicts the OLDEST
// entry (FIFO; freed) to make room. Returns 1 if stored, 0 if the single
// filter itself exceeds the budget (caller leaves the height outstanding for
// the ordinary re-request fallback — nothing is buffered in that case).
int      BRCFScanLedgerBufferFilter(BRCFScanLedger *l, UInt256 blockHash,
                                     const uint8_t *bytes, size_t len, uint32_t now);

// For up to maxDrain buffered entries whose isReady(blockHash)->height returns
// 1, copy the bytes (bounded by scratchCap) into scratch and call
// evalFn(ctx, height, blockHash, scratch, len). The entry is removed (and its
// bytes freed) ONLY when evalFn returns 1 (credited, or a clean verified
// miss); a 0 return (a wallet HIT that could not dispatch this tick — e.g. no
// CF-capable peer connected) KEEPS the entry buffered so the next tick
// retries. isReady requires the caller to gate on BOTH the block header and
// the cfheader for that height — buffered bytes are raw/unverified. Returns
// the number of entries REMOVED. Pure: reaches BRPeerManager only through the
// two function pointers.
size_t   BRCFScanLedgerDrainConnected(BRCFScanLedger *l,
                                      int (*isReady)(void *ctx, UInt256 blockHash, uint32_t *outHeight),
                                      void *ctx,
                                      uint8_t *scratch, size_t scratchCap,
                                      int (*evalFn)(void *ctx, uint32_t height, UInt256 blockHash,
                                                    const uint8_t *bytes, size_t len),
                                      size_t maxDrain);

// Free and discard ALL buffered filter bytes (re-anchor/wipe). In-memory only —
// the ledger's persisted fields are unaffected; a re-anchored/rescanned floor
// naturally re-requests anything that was buffered here.
void     BRCFScanLedgerClearFilterBuffer(BRCFScanLedger *l);

// Age-out byte-reclamation backstop (Task 3, §7): free every buffered entry
// whose `nowSec - firstAt > CF_FILTER_BUF_MAX_AGE_SECS` (keyed off the
// IMMUTABLE first-buffered timestamp, NOT the re-buffer-reset `at`), and
// compact the FIFO array. Touches ONLY filterBuf[]/filterBufCount/
// bufferedBytes — never outstanding/scannedThrough/requestedThrough/gaveUp,
// and never calls MarkEvaluated. This is a pure byte-budget reclaim, NOT a
// livelock cure: an evicted hash's height is simply left to the ordinary
// re-request path (Task 4 handles the correctness/skip-set side).
void     BRCFScanLedgerEvictAgedFilters(BRCFScanLedger *l, uint32_t nowSec);

// Free all buffered filter bytes (teardown). Safe to call on an empty (or
// never-buffered) ledger. Call from BRPeerManagerFree alongside the other frees.
void     BRCFScanLedgerFree(BRCFScanLedger *l);

size_t   BRCFScanLedgerBufferedCount(const BRCFScanLedger *l);
size_t   BRCFScanLedgerBufferedBytes(const BRCFScanLedger *l);

// Copy up to `cap` buffered blockHashes (FIFO order, oldest at index 0) into
// out[] and return the count written (min(filterBufCount, cap); 0 if out is
// NULL). O(filterBufCount), holds no locks, no BRPeerManager dependency — the
// pure reverse-map input BRPeerManager's residual re-request suppressor uses to
// skip re-requesting heights whose canonical block is currently buffered
// (in-flight), by resolving each hash through manager->blocks (an O(1) set
// lookup per hash) rather than ever computing canonical(H) by a forward walk.
size_t   BRCFScanLedgerBufferedHashes(const BRCFScanLedger *l, UInt256 *out, size_t cap);

// ---- Pending-confirm (confirmation-side twin) ------------------------------

// Record wallet txs from a CF-driven full block whose header hasn't connected
// yet. On CF_PENDING_CONFIRM_MAX overflow the OLDEST entry is dropped (caller
// logs). A re-record of the same blockHash replaces its tx set.
void     BRCFScanLedgerRecordPending(BRCFScanLedger *l, UInt256 blockHash,
                                     const UInt256 *txHashes, size_t n, uint32_t now);

// Drain (remove + return) the wallet txs recorded for blockHash, e.g. once its
// header connects. Copies up to `cap` hashes into outTx; returns the count.
size_t   BRCFScanLedgerTakePending(BRCFScanLedger *l, UInt256 blockHash, UInt256 *outTx, size_t cap);

// ---- Persistence (§5) ------------------------------------------------------
// Persists ONLY: start, scannedThrough, requestedThrough, the outstanding
// heights + their headerRace flag, and the gaveUp list. attempts/timestamps/
// peers are NOT persisted (a fresh process gets fresh peers) and pending is NOT
// persisted (rebuilt by a re-anchor/rescan). On Parse those reset.

// Serialize into buf. Returns the number of bytes the blob needs; writes it iff
// buflen is large enough (call with buflen 0 / NULL buf to size first).
size_t   BRCFScanLedgerSerialize(const BRCFScanLedger *l, uint8_t *buf, size_t buflen);

// Parse a blob produced by BRCFScanLedgerSerialize. Returns 1 on success
// (l fully populated; attempts/timestamps/peers reset, pending empty), 0 on a
// garbled/oversized/short blob (l left as an empty ledger — the caller rebuilds).
int      BRCFScanLedgerParse(BRCFScanLedger *l, const uint8_t *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif // BRCFScanLedger_h
