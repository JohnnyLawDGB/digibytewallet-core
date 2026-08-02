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
// SHIPPING AT 0 (Phase 1, observe-only) — deliberately, not by oversight. Phase 2
// was armed here before it had ever shipped, and the back-pressure half of it is
// unsafe against this core's retention predicate:
//
//   _BRPeerManagerClearMemory anchors its retention floor to the CFHEADER frontier
//   (cfNext - CLEAR_MEM_CF_RETENTION_MARGIN, BRPeerManager.c). cfheaders advance
//   2000 per message and are requested unconditionally, while cfilters are
//   requested <=1000 per batch and arrive one message at a time, so a single
//   cfheaders append can put an entire in-flight filter batch below the floor —
//   the margin is 144, less than one batch. Those block headers are then freed
//   while their cfilters are still outstanding.
//
//   Such a height can never leave `outstanding`: both MarkEvaluated sites require
//   a resident header, and the residual re-request cannot even SEND, because its
//   stop hash is resolved by walking prevBlock links through manager->blocks and
//   that walk dies in the pruned gap. sent == 0 means CommitRerequest never runs,
//   so attempts never increment and RetireCapped never retires it.
//
//   Phase 2's back-pressure gate pauses forward auto-fetch while outstanding >=
//   CF_OUTSTANDING_LOWWATER (3072) on the premise that the residual driver drains
//   the backlog. For pruned heights that premise is false, and the count only ever
//   grows — so on a restore of any real depth forward cfilter fetch eventually
//   pauses FOREVER: no new filters, so no new transactions detected, while headers
//   and cfheaders keep advancing and the UI still reports Synced.
//
// At 0 the ledger still records requested heights and marks them evaluated on
// arrival (see the #else in _peerRelayedCFHeaders' auto-fetch block), so holes stay
// visible on the Network Info screen — the observability win is kept and only the
// behaviour change is dropped. A pruned-before-scanned filter is dropped with a log
// line, which is exactly what the last shipped release (v4.0.23) already did.
//
// Re-arm this to 1 together with the paced-convoy + scan-frontier-anchored
// retention pair, which removes the pruning race the back-pressure premise needs.
// Arming it WITHOUT that pair is the regression described above. The scan-frontier
// retention fix must not be cherry-picked alone either: it retains every header from
// the scan frontier to the tip, and only the convoy bounds that span.
//
// KATs pass -DCF_LEDGER_DRIVE_REREQUEST=1 explicitly, so Phase-2 logic stays fully
// covered by the host suite while production runs at 0.
#ifndef CF_LEDGER_DRIVE_REREQUEST
#define CF_LEDGER_DRIVE_REREQUEST 0   // Phase 1: observe only. -D wins for KATs.
#endif

// Sentinel: "no height was evicted" — returned by the overflow-drop-reporting
// insert/record paths so a real (32-bit) evicted height is never ambiguous
// with "nothing dropped".
#define CF_LEDGER_NO_DROP 0xFFFFFFFFu

// ---- CF_STATIC_ASSERT ------------------------------------------------------
// One portable spelling for every compile-time constant-relation assertion in
// the CF stack (this header and BRPeerManager.h). Factored out because the
// relations are swept, not one-off: each one wrapped in its own
// `#if defined(__STDC_VERSION__) && ...` was unreadable, and an unreadable
// assertion is one a future footprint trim deletes instead of satisfying.
//
// Toolchain reality this has to survive:
//   - Both the host KATs (clang, no -std -> gnu17) and the Android NDK build
//     (clang, no -std in native/CMakeLists.txt -> gnu17) report
//     __STDC_VERSION__ == 201710L, so the C11 form IS compiled and evaluated
//     in every shipped build. These are not documentation-only.
//   - The other two branches are BELT-AND-BRACES, and MEASURED to be
//     unreachable today rather than assumed to matter: both headers carry
//     `extern "C"` blocks, which invites a C++ TU, and both nominally support
//     older C — but including either one from C++ or under -std=c89 already
//     fails in BRInt.h (a C++-illegal anonymous-union compound literal at
//     BRInt.h:250; `inline` unknown under c89 at BRInt.h:63) long before
//     reaching these macros. So the C11 branch is the ONLY one this codebase
//     actually compiles; the other two exist so that whoever fixes BRInt.h
//     does not also have to fix this.
//     The fallback is a repeatable extern DECLARATION, not an empty expansion:
//     every use site is written `CF_STATIC_ASSERT(...);`, and an empty expansion
//     would leave a stray file-scope `;` (a C89 constraint violation), i.e. the
//     graceful-degradation path would itself break the build it exists to save.
//     Re-declaring the same extern with the same type is legal and harmless.
#ifndef CF_STATIC_ASSERT
#if defined(__cplusplus)
#define CF_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define CF_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#define CF_STATIC_ASSERT(cond, msg) extern char cf_static_assert_unenforced_pre_c11
#endif
#endif

// ---- Bounds & pinned constants (§3) ----------------------------------------
#define CF_OUTSTANDING_MAX      4096  // hard cap; overflow drops OLDEST (caller LOGWs its height range)
#define CF_PENDING_CONFIRM_MAX   256  // blocks awaiting header-connect confirmation
#define CF_PENDING_TX_MAX         32  // wallet txs recorded per pending block (small, capped)

// heights that exhausted retries — REPORTED, never dropped.
//
// SIZED TO CF_OUTSTANDING_MAX, NOT SMALLER — this is a CORRECTNESS bound, not a
// footprint knob (F4 Part A). It was 512 while CF_REREQ_MAX_RANGE is 1000, i.e.
// the ceiling on the parked set was HALF the largest run
// BRCFScanLedgerPeekRerequestRange can coalesce and offer as one getcfilters. A
// maximal dead run therefore could never be fully retired: RetireCapped walks
// `outstanding` from the front, _cfLedgerMoveToGaveUp returns 0 once gaveUp is
// full, and RetireCapped then KEEPS that entry in `outstanding` — where it is
// capped, so no driver ever offers it again (NextRerequest's
// `attempts >= CF_REREQ_MAX_ATTEMPTS` continue; PeekRerequestRange's
// `attempts < CF_REREQ_MAX_ATTEMPTS` candidate test). 512 heights park, 488 sit
// in `outstanding` forever, and because _cfLedgerAdvance caps scannedThrough at
// min(outstanding[0], gaveUp[0]) - 1 they pin the scan frontier — and therefore
// the whole paced convoy — permanently.
//
// The B2 valve cannot rescue that state either: once it re-arms the lowest
// parked hole, that hole becomes outstanding[0] BELOW gaveUp[0], and when its
// fresh cycle re-exhausts, gaveUp is full again so it cannot be re-parked. See
// the arm-predicate discussion in BRPeerManager.c's B2 block for the other half
// of that fix.
//
// So the bound that makes the class structurally impossible is: gaveUp must be
// able to absorb EVERYTHING outstanding can hold. Any smaller value (even one
// >= CF_REREQ_MAX_RANGE, e.g. 1024) merely moves the defect further out — 4096
// dead heights across five runs reproduce it exactly.
//
// FOOTPRINT (stated, not buried): the parked entry is 6 bytes — gaveUp[]
// (uint32_t) + gaveUpRearmCycles[] (uint8_t) + gaveUpOffersLive[] (uint8_t).
// 512 -> 4096 is +3584 entries = +21,504 bytes ≈ +21 KiB on the single
// BRPeerManager-embedded ledger, against the ~128 KiB outstanding[] (4096 x
// sizeof(BRCFOutstanding)) already sitting next to it. Persisted blob (§5) grows
// by the same 6 bytes per ACTUAL parked height, worst case +21 KiB.
#ifdef CF_GAVEUP_CEILING_UNFIXED
// PRE-FIX shape — host-KAT red-before-green ONLY, never a production build.
#define CF_GAVEUP_MAX            512
#else
#define CF_GAVEUP_MAX            CF_OUTSTANDING_MAX
#endif

// Phase-2 re-request backoff — PINNED 2026-07-25 (§3, §13):
#define CF_REREQ_HEADERRACE_SECS  10  // header-race first retry — the header connects quickly
#define CF_REREQ_BASE_SECS        30  // all other holes: base delay
#define CF_REREQ_BACKOFF_CAP_SECS 120 // delay = min(BASE << attempts, CAP) → 30/60/120/120/120
#define CF_REREQ_MAX_ATTEMPTS      5  // per-height cap; on reaching it → gaveUp list (NEVER silent)
#define CF_REREQ_MAX_RANGE      1000  // == MAX_CFILTERS_RESULTS (BRPeer.h:116) — Peek's coalesced-run cap

// The F4 Part A bound, asserted at COMPILE TIME so a future footprint trim of
// CF_GAVEUP_MAX cannot silently re-open the "a maximal run can never be fully
// retired" wedge. Deliberately NOT asserted in the CF_GAVEUP_CEILING_UNFIXED
// build — that build exists precisely to compile the violating shape for the
// red-before-green gate.
#ifndef CF_GAVEUP_CEILING_UNFIXED
CF_STATIC_ASSERT(CF_GAVEUP_MAX >= CF_OUTSTANDING_MAX,
               "CF_GAVEUP_MAX must absorb everything outstanding[] can hold, else "
               "BRCFScanLedgerRetireCapped leaves capped heights in outstanding[] where no "
               "driver offers them and they pin scannedThrough forever (F4 Part A)");
CF_STATIC_ASSERT(CF_GAVEUP_MAX >= CF_REREQ_MAX_RANGE,
               "CF_GAVEUP_MAX must at minimum absorb one maximal coalesced re-request run");
#endif

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

// ---- CONSTANT-RELATION SWEEP (intra-module) --------------------------------
//
// WHY THIS BLOCK EXISTS. F4 was not "a constant was too small". It was a PAIR of
// constants (CF_GAVEUP_MAX, CF_REREQ_MAX_RANGE) bounding the same quantity from
// opposite sides with NOTHING tying them together, so a footprint-motivated
// choice of one silently broke a correctness property of the other, and the
// breakage was only observable as a wedged wallet in the field months later.
// Every relation the code below actually depends on is therefore asserted at
// COMPILE TIME here. The rule for this block:
//
//   an assertion whose comment does not say WHAT BREAKS is noise — delete it
//   rather than leave a reader guessing whether it is load-bearing.
//
// Relations that span module boundaries (the CF ledger vs the wire limits in
// BRPeer.h, the paced-convoy window in BRPeerManager.h, the GCS size cap in
// BRGCSFilter.h) are asserted in BRPeerManager.h instead — this header is PURE
// (BRInt.h only, see the file comment) and stays that way. See the
// "CROSS-MODULE CONSTANT-RELATION SWEEP" block there.
//
// The two CF_GAVEUP_MAX relations are asserted above, at the define they
// constrain, because that define carries the F4 narrative.

// --- back-pressure low-water vs the hard cap ---
// BREAKS: with LOWWATER >= CF_OUTSTANDING_MAX the forward-fetch back-pressure gate
// (BRPeerManager.c, `OutstandingCount(&cfLedger) < CF_OUTSTANDING_LOWWATER`) never
// closes before the hard cap, so _cfLedgerInsertOutstanding starts taking its
// overflow branch and DROPS THE OLDEST outstanding height to make room. That
// height leaves the ledger entirely, so _cfLedgerAdvance no longer sees a hole
// there and scannedThrough sails over a height that never received
// MarkEvaluated — the STANDING INVARIANT, violated by arithmetic rather than by a
// code path. (The caller LOGWs the dropped range, so it is not literally silent;
// the cursor still advances, which is the prohibited part.)
CF_STATIC_ASSERT(CF_OUTSTANDING_LOWWATER < CF_OUTSTANDING_MAX,
               "CF_OUTSTANDING_LOWWATER must leave headroom under CF_OUTSTANDING_MAX, else "
               "forward-fetch back-pressure never engages and outstanding[] silently evicts "
               "unevaluated heights out from under scannedThrough");

// BREAKS: at 0 the same gate is never satisfied, so the forward cfilter fetch never
// runs at all — the scan frontier never advances, the paced convoy never opens, and
// a fresh sync wedges at the birth height forever.
CF_STATIC_ASSERT(CF_OUTSTANDING_LOWWATER > 0,
               "CF_OUTSTANDING_LOWWATER == 0 disables forward cfilter auto-fetch entirely "
               "(the gate is `outstandingCount < LOWWATER`) — permanent sync wedge");

// --- the re-request backoff schedule vs its attempt cap ---
// _cfLedgerRerequestDelay is `d = BASE; for (k < attempts) { d <<= 1; if (d >= CAP)
// { d = CAP; break; } }`, i.e. min(BASE << attempts, CAP) -> 30/60/120/120/120.
//
// BREAKS (CAP < BASE): the very first delay is already clamped to CAP, so the
// schedule is a FLAT CAP and the documented 7.5-minute cycle is fiction. Everything
// calibrated on that cycle length silently shifts with it: CF_CONVOY_REARM_MAX's
// "~15 min of productive rotated retry" (BRPeerManager.h), the age-out margin
// asserted just below, and the B2 valve's whole "offered and refused across N full
// cycles" claim.
CF_STATIC_ASSERT(CF_REREQ_BACKOFF_CAP_SECS >= CF_REREQ_BASE_SECS,
               "CF_REREQ_BACKOFF_CAP_SECS below CF_REREQ_BASE_SECS clamps the FIRST retry, "
               "collapsing min(BASE<<n, CAP) to a flat CAP and invalidating every timing "
               "derived from the 30/60/120/120/120 schedule");

// BREAKS: the header-race short-circuit exists precisely to retry SOONER than the
// ordinary schedule (the block header connects within seconds, so the buffered
// filter can be drained almost immediately). If it is longer, the common
// self-healing case waits longer than a hard drop and the special case is worse
// than not having it.
CF_STATIC_ASSERT(CF_REREQ_HEADERRACE_SECS <= CF_REREQ_BASE_SECS,
               "the header-race retry must be SHORTER than the base delay — that is the only "
               "reason CF_REREQ_HEADERRACE_SECS exists");

// BREAKS: the loop shifts `d <<= 1` BEFORE testing `d >= CAP`, so a cap above half
// the uint32 range lets the shift WRAP. The delay collapses to a tiny value, the
// driver turns into a retry storm that burns all CF_REREQ_MAX_ATTEMPTS in seconds,
// and the height is retired to gaveUp and handed to the abandonment valve having
// never had a real retry window.
CF_STATIC_ASSERT(CF_REREQ_BACKOFF_CAP_SECS <= 0xFFFFFFFFu / 2u,
               "CF_REREQ_BACKOFF_CAP_SECS above UINT32_MAX/2 lets _cfLedgerRerequestDelay's "
               "`d <<= 1` wrap before the cap test, collapsing the backoff to a retry storm");

// BREAKS: at 0 a freshly inserted hole (attempts == 0) already satisfies
// `attempts >= CF_REREQ_MAX_ATTEMPTS`, so it is PARKED AT BIRTH —
// BRCFScanLedgerNextRerequest `continue`s it, BRCFScanLedgerPeekRerequestRange
// never selects it as a candidate, and BRCFScanLedgerRetireCapped moves it straight
// to gaveUp. No height is ever re-requested even once; every hole goes to the
// abandonment valve.
CF_STATIC_ASSERT(CF_REREQ_MAX_ATTEMPTS >= 1,
               "CF_REREQ_MAX_ATTEMPTS == 0 parks every hole at birth — nothing is ever "
               "re-requested and every hole is handed to the abandonment valve");

// BREAKS: BRCFOutstanding.attempts is a uint8_t, incremented (BRCFScanLedger.c
// `e->attempts++`) with no saturation guard because the `attempts >= MAX` tests are
// supposed to stop it first. Above 255 those tests can never be true: attempts
// wraps 255 -> 0, RetireCapped becomes a permanent no-op, nothing ever reaches
// gaveUp, the B2 valve (which acts on the parked/gaveUp pin) never fires — and the
// scan frontier pins on a hole that is retried forever. The exact F4 failure shape
// (a hole that can never retire) reintroduced through a field width instead of an
// array bound.
CF_STATIC_ASSERT(CF_REREQ_MAX_ATTEMPTS <= 255,
               "CF_REREQ_MAX_ATTEMPTS must fit BRCFOutstanding.attempts (uint8_t) — a cap the "
               "field cannot represent makes RetireCapped a no-op and pins the scan frontier "
               "on an eternally-retried hole");

// --- filter-buffer age-out vs the retry schedule it must outlive ---
// BREAKS: BRCFScanLedgerEvictAgedFilters frees a buffered header-race filter's bytes
// once firstAt is older than this. If the age-out can fire while that height's retry
// schedule is still running, the bytes we already hold are discarded mid-schedule and
// the height must be re-fetched from the wire instead of drained locally — and if its
// header still has not connected it re-buffers and re-ages, so a BACKSTOP becomes a
// work-discarding loop on exactly the slow-header case the buffer exists to cover.
// CF_REREQ_MAX_ATTEMPTS * CF_REREQ_BACKOFF_CAP_SECS is a deliberately CONSERVATIVE
// (constant-expression) upper bound on the schedule: the true wall time is smaller
// because the early attempts pay BASE << n < CAP (30+60+120+120+120 = 450 today, vs
// the 600 asserted here).
CF_STATIC_ASSERT(CF_REREQ_MAX_ATTEMPTS * CF_REREQ_BACKOFF_CAP_SECS < CF_FILTER_BUF_MAX_AGE_SECS,
               "CF_FILTER_BUF_MAX_AGE_SECS must outlast a full re-request schedule, else the "
               "byte-reclamation backstop discards buffered filters while their own retry "
               "cycle is still running");

// --- filter buffer: byte budget vs slot backstop ---
// The design (see the two defines above) is: eviction is BYTE-driven; the slot array
// is a fixed-capacity backstop against a pathological run of many tiny filters.
// BREAKS: with fewer budget bytes than slots, the byte budget binds before the slot
// array can ever fill even for 1-byte filters, so CF_FILTER_BUF_SLOTS is unreachable
// dead code AND the array's memory (SLOTS x sizeof(ptr)) is provisioned for a state
// that cannot occur — the stated division of labour is inverted, and a future reader
// tuning "the" cap tunes the wrong one. (This is the weak half of the pair; the
// load-bearing half — the budget vs a WIRE-LEGAL filter size — needs
// BR_GCS_MAX_ENCODED_SIZE and is asserted in BRPeerManager.h.)
CF_STATIC_ASSERT(CF_FILTER_BUFFER_MAX_BYTES >= CF_FILTER_BUF_SLOTS,
               "the filter buffer's byte budget must exceed its slot count (>= 1 byte per "
               "slot), else the slot backstop is unreachable and the byte cap is the only "
               "real bound — inverting the documented byte-budgeted design");

// BREAKS: BRCFScanLedgerBufferFilter's de-dup path evicts
// `while (bufferedBytes >= MAX_BYTES && filterBufCount > 1)` — it deliberately keeps
// the entry it just updated. With a single slot that guard can never evict, so
// bufferedBytes can settle at or above the byte cap and stay there.
CF_STATIC_ASSERT(CF_FILTER_BUF_SLOTS >= 2,
               "CF_FILTER_BUF_SLOTS must be >= 2: BufferFilter's de-dup eviction loop stops at "
               "filterBufCount > 1, so a 1-slot buffer can never come back under the byte cap");

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

    // ---- B2 abandonment-valve state (paced-convoy design Part B2) ----------
    uint8_t  rearmCycles;  // PERSISTED (blob v3; a v1/v2 blob loads it as 0). How many FRESH
                           //   retry cycles the valve has already granted this hole against a
                           //   live CF-peer set. 0 == the original cycle. Saturating (never
                           //   wraps). Carried across the outstanding→gaveUp→outstanding round
                           //   trip by gaveUpRearmCycles[].
    uint8_t  offersReachedLivePeer;  // NOT persisted for an outstanding entry (it follows
                           //   `attempts`, the cycle it describes — see the persistence section);
                           //   its parked twin gaveUpOffersLive[] IS.
                           //   PER-CYCLE LATCH. 1 while EVERY retry offer made during
                           //   THIS cycle actually reached a CONNECTED CF-capable peer; cleared
                           //   the moment one did not (no CF peer to offer to, a send that never
                           //   went on the wire, or the target peer disconnecting with the offer
                           //   in flight). Set to 1 when a cycle STARTS (insert / ReArmGaveUp)
                           //   and never re-raised within a cycle — a tainted cycle can never be
                           //   un-tainted. This is what makes an abandonment "offered AND refused
                           //   by live peers" rather than merely "un-offered".
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

    // B2 valve state PARKED with a retired hole, INDEX-PARALLEL to gaveUp[] (entry i
    // describes gaveUp[i]). A retiring hole's BRCFOutstanding record is destroyed by
    // _cfLedgerMoveToGaveUp, so without this the re-arm cycle counter would reset to 0
    // on every retirement and `rearmCycles >= CF_CONVOY_REARM_MAX` could NEVER be
    // reached — a valve that re-arms forever and never abandons, i.e. the permanent
    // convoy wedge this valve exists to prevent. Persisted (blob v3; v1/v2 → 0).
    //
    // INVARIANT: these two arrays are mutated ONLY through _cfLedgerAddGaveUp /
    // _cfLedgerRemoveGaveUp / _cfLedgerGaveUpDropPrefix, which shift all three arrays
    // together. Never memmove gaveUp[] by hand.
    uint8_t            gaveUpRearmCycles[CF_GAVEUP_MAX];
    uint8_t            gaveUpOffersLive[CF_GAVEUP_MAX];

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

// ---- B2 abandonment valve (paced-convoy design Part B2) --------------------
// Once BRCFScanLedgerRetireCapped parks a hole in `gaveUp`, NO driver ever
// re-requests it (both NextRerequest and PeekRerequestRange iterate `outstanding`
// only), and because scannedThrough is capped at min(outstanding[0], gaveUp[0])-1
// that one hole pins the scan frontier — and therefore the whole paced convoy —
// FOREVER. `gaveUp` is only a HEURISTIC for "unservable": during a convoy climb
// retries can exhaust for transient, convoy-induced reasons (the peer set rotated,
// the fleet was momentarily saturated, the range was briefly unavailable). So the
// valve NEVER abandons on gaveUp alone; it re-arms the hole against the CURRENT
// (possibly healed) peer set first, and abandons only on re-exhaustion that was
// provably OFFERED AND REFUSED by connected CF peers. These two calls are the
// ledger-side primitives; the decision itself lives in BRPeerManagerKeepAlive.

// Move `height` from gaveUp back into `outstanding` for a FRESH full retry cycle:
// attempts = 0 (immediately due), rearmCycles = the parked count + 1 (saturating),
// offersReachedLivePeer = 1 (a new, so-far-untainted cycle) — and REMOVE it from
// gaveUp, so the height has exactly ONE home. (Leaving it in both would make
// gaveUp[0]/gaveUpCount — which the valve's own decision and _cfLedgerAdvance both
// read — describe a hole that is simultaneously being retried.) Returns 1 if
// re-armed; 0 if `height` is not a gaveUp hole, is below the abandonedBelow hard
// floor, or `outstanding` is full (re-arming through a full outstanding array would
// evict the lowest-height hole, silently losing it — better to leave it parked).
int      BRCFScanLedgerReArmGaveUp(BRCFScanLedger *l, uint32_t height);

// Read the LOWEST parked (gaveUp) hole plus its parked valve state. Returns 1 and
// writes the outputs when gaveUp is non-empty, else 0 (outputs untouched). gaveUp
// is sorted ascending, so gaveUp[0] is the hole that pins the scan frontier.
int      BRCFScanLedgerLowestGaveUp(const BRCFScanLedger *l, uint32_t *outHeight,
                                    uint8_t *outRearmCycles, uint8_t *outOffersReachedLivePeer);

// ---- B2 valve: the PINNING hole, whatever list it lives in (F4 Part B) ------
//
// WHY LowestGaveUp IS NOT ENOUGH. The valve's job is to unstick the ONE hole that
// pins the scan frontier — exactly the height _cfLedgerAdvance caps scannedThrough
// one below, i.e. min(outstanding[0], gaveUp[0]). Its original arm predicate read
// that as "gaveUp[0] < outstanding[0]", which treats ANY outstanding entry as
// recoverable-and-being-retried. That is false for a CAPPED one: an outstanding
// entry at CF_REREQ_MAX_ATTEMPTS is skipped by BRCFScanLedgerNextRerequest (the
// `attempts >= CF_REREQ_MAX_ATTEMPTS` continue) and never selected by
// BRCFScanLedgerPeekRerequestRange (whose candidate test requires
// `attempts < CF_REREQ_MAX_ATTEMPTS`), so NO driver will ever offer it again. It is
// a PARKED hole that merely failed to reach gaveUp — operationally identical to a
// gaveUp hole, but invisible to the valve, and it pins the frontier forever.
//
// That state is reached whenever _cfLedgerMoveToGaveUp cannot park a capped entry,
// i.e. gaveUp is full. F4 Part A removes the easy route to it (CF_GAVEUP_MAX now
// absorbs everything outstanding[] can hold), but not the last one: the valve
// re-arms gaveUp[0] into outstanding, another height retires into the freed slot,
// and when the re-armed hole re-exhausts gaveUp is full again — outstanding[0]
// below gaveUp[0], capped, unofferable, and the old predicate reads FALSE forever.
// Both halves are needed.

// Describe the hole that PINS the scan frontier: the LOWEST height in
// outstanding[] ∪ gaveUp[] (both arrays sorted ascending, so this is O(1)).
// Returns 0 and leaves every output untouched when there is no hole at all.
//   *outOfferable            1 iff a driver can still OFFER it (an outstanding
//                            entry under CF_REREQ_MAX_ATTEMPTS); 0 for a gaveUp
//                            hole AND for a capped outstanding entry.
//   *outRearmCycles          the pinning hole's B2 re-arm count, read from
//   *outOffersReachedLivePeer whichever list holds it.
// A height cannot be in both lists (ReArmGaveUp removes before inserting;
// MarkEvaluated removes from both), but if bookkeeping ever drifted so that
// outstanding[0] == gaveUp[0], the OUTSTANDING record wins — the reluctant
// direction (it can be offerable, which withholds abandonment).
int      BRCFScanLedgerPinningHole(const BRCFScanLedger *l, uint32_t *outHeight, int *outOfferable,
                                   uint8_t *outRearmCycles, uint8_t *outOffersReachedLivePeer);

// Length of the contiguous ABANDONABLE run starting at startH inclusive:
// consecutive heights startH, startH+1, … each of which is
//   (a) PARKED — either a gaveUp entry or a CAPPED (attempts >=
//       CF_REREQ_MAX_ATTEMPTS) outstanding entry, i.e. one no driver will offer; AND
//   (b) at the valve's abandon threshold — rearmCycles >= minCycles AND
//       offersReachedLivePeer == 1 (the offered-and-refused proof).
// Stops at the first height that is absent, still offerable, or short of the
// threshold; at `maxRun` heights; or at UINT32_MAX. Writes the run's high end to
// *outHi when non-NULL. Returns the run length — 0 iff startH itself does not
// qualify (then *outHi is untouched).
//
// The per-member (b) test is what keeps a run-wide decision from widening the
// DECISION: a height one cycle short of the threshold, or whose deciding cycle was
// tainted, ENDS the run and becomes the next tick's pin instead of being carried
// along by its neighbours' evidence.
//
// This is what lets the valve act on a whole coalesced RUN instead of one height
// per cycle. One height per (1 + CF_CONVOY_REARM_MAX) x 7.5-min cycle would make a
// CF_REREQ_MAX_RANGE-wide dead band take ~15 DAYS to clear — an escape that exists
// only on paper. A run-wide decision clears the same band in one 22.5-min sequence,
// and it matches what the driver already does: PeekRerequestRange coalesces exactly
// such a run into ONE getcfilters, so the whole run shares one retry cycle and one
// offered-and-refused verdict.
size_t   BRCFScanLedgerAbandonableRunFrom(const BRCFScanLedger *l, uint32_t startH, size_t maxRun,
                                          uint8_t minCycles, uint32_t *outHi);

// Grant a FRESH full retry cycle to every height in the contiguous parked run at
// startH (bounded by maxRun): attempts = 0 and requestedAt = 0 (immediately due),
// peer/port cleared (so PeekRerequestRange coalesces the whole run into ONE
// getcfilters), headerRace = 0, rearmCycles = old + 1 (saturating),
// offersReachedLivePeer = 1 (a new, so-far-untainted cycle). A gaveUp height moves
// back into outstanding (BRCFScanLedgerReArmGaveUp); a capped outstanding height
// gets the identical state change without a list move. Stops at the first height
// that is not parked, is below abandonedBelow, or cannot be re-armed (outstanding
// full). Returns the number of heights re-armed — 0 means the valve did nothing,
// and nothing was lost: every height stays exactly where it was.
size_t   BRCFScanLedgerReArmParkedRun(BRCFScanLedger *l, uint32_t startH, size_t maxRun);

// Clear the per-cycle offersReachedLivePeer latch on every OUTSTANDING height in
// [startH..stopH]: a retry offer for those heights did NOT reach a connected
// CF-capable peer this round (no peer was available to offer to, or the send never
// went on the wire), so this cycle can no longer serve as proof of refusal. The
// latch is only ever raised at the START of a cycle — never here.
void     BRCFScanLedgerMarkOffersMissedLivePeer(BRCFScanLedger *l, uint32_t startH, uint32_t stopH);

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
//   - Advances abandonedBelow ONLY to cover gaveUp ACTUALLY dropped — to the
//     highest dropped height + 1 (Part 3b determinism guard). If NOTHING is
//     dropped (empty gaveUp below the clamp) abandonedBelow is UNCHANGED: it is
//     NEVER raised preemptively. A preemptive raise past unscanned history would
//     let a deep restore whose scan hasn't started (empty outstanding) COMPLETE
//     with a WRONG BALANCE. Every dropped height < target = min(clamp,
//     lowest-still-OUTSTANDING), so highest-dropped+1 never passes a still-
//     retrying outstanding hole (recoverable — never abandoned). Monotonic (only
//     ever advances). Consequence: abandonedBelow advances IFF gaveUp was dropped
//     ⟺ *outCount>0, so the caller's WARN on *outCount>0 is exactly a WARN on any
//     advance.
//   - If outCount/outLo/outHi are non-NULL, writes the number of gaveUp heights
//     abandoned by THIS call and their [lo..hi] range (CF_LEDGER_NO_DROP in each
//     when none were abandoned) so the caller can warn-log it.
// Returns the new lowest-still-needed height (== BRCFScanLedgerLowestNeededHeight
// after the mutation) — the caller's new retention floor target.
uint32_t BRCFScanLedgerAbandonGaveUpBelow(BRCFScanLedger *l, uint32_t clamp,
                                          uint32_t *outCount, uint32_t *outLo, uint32_t *outHi);

// STRUCTURALLY UNSCANNABLE band (paced-convoy C-1): surface `[lo .. floor-1]`
// instead of letting the scan floor move past it silently.
//
// WHY THIS EXISTS, AND WHY IT IS NOT AbandonGaveUpBelow. A cfilter can only be
// EVALUATED for a block the peer manager still holds (_peerRelayedCFilter resolves
// the response's blockHash in manager->blocks; an unknown block is dropped), and a
// getcfilters can only be SENT for a range whose stop height resolves to a hash by
// walking prevBlock down from lastBlock. So every height below the manager's block
// FLOOR is unservable AND unevaluatable for the whole session — no retry, no peer
// and no re-request driver can ever change that. Such a height therefore never
// reaches gaveUp (attempts only advance on a real send), so the B2 valve is
// structurally BLIND to it: it pins the scan frontier forever, invisibly. That is
// exactly the resume shape C-1 describes — BRPeerManagerNewEx makes only the
// persisted [tip-(SAVE_BLOCK_COUNT-1) .. tip] run resident, so a resumed manager's
// floor is 299 below the SAVED TIP while a restored scan frontier sits a full
// ~CF_CONVOY_WINDOW below it. (Before fix-wave R2 the chaining ran FORWARD from
// the highest saved block and only ONE header was resident, putting the floor at
// the saved tip itself — which also surfaced a spurious 1–2 height band on an
// ordinary kill of a healthy wallet, since the CF ledger's 20-s coalesced write
// trails the per-callback saved-blocks write.)
//
// CONTRACT (mirrors AbandonGaveUpBelow's determinism guard — the caller MUST warn):
//   - `lo` is first clamped UP to the existing abandonedBelow, so history already
//     surfaced by an earlier call is never counted or warned about twice. That is
//     what makes *outCount > 0 hold EXACTLY when abandonedBelow advances.
//   - No-op unless 0 < lo < floor: *outCount = 0 and abandonedBelow is UNCHANGED.
//     There is no preemptive raise here either.
//   - Otherwise raises abandonedBelow to `floor` (monotonic), drops every
//     outstanding[] and gaveUp[] entry below `floor` (they can never be served),
//     and re-advances scannedThrough.
//   - *outCount = floor - lo = the number of heights surfaced; the band is
//     [lo .. floor-1]. *outCount > 0 ⟺ abandonedBelow advanced ⟺ caller WARNs.
// `lo` is supplied by the caller rather than read from the ledger because the two
// call shapes differ: a LIVE check passes BRCFScanLedgerLowestNeededHeight, while a
// re-Init-at-a-new-floor passes the frontier observed BEFORE the Init wiped it.
// Returns the new BRCFScanLedgerLowestNeededHeight.
uint32_t BRCFScanLedgerAbandonUnscannableBelow(BRCFScanLedger *l, uint32_t lo, uint32_t floor,
                                               uint32_t *outCount);

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
// Persists ONLY: start, scannedThrough, requestedThrough, abandonedBelow (v2+),
// the outstanding heights + their headerRace flag + their rearmCycles (v3+), and
// the gaveUp list + BOTH of its parked B2 valve bytes (v3+). attempts/timestamps/
// peers are NOT persisted (a fresh process gets fresh peers) and pending is NOT
// persisted (rebuilt by a re-anchor/rescan). On Parse those reset.
//
// An OUTSTANDING entry's offersReachedLivePeer follows `attempts` into the
// NOT-persisted set, because it describes precisely the cycle `attempts` counts:
// Parse starts a fresh cycle, so the latch starts clean (1). rearmCycles is the
// opposite case and MUST persist — if it reset on every process restart, a wallet
// backgrounded once per cycle could never reach CF_CONVOY_REARM_MAX and the valve
// would never fire. A PARKED (gaveUp) hole's cycle is finished, so both of its
// bytes are a frozen verdict and both persist.

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
