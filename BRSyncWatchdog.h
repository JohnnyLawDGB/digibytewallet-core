//
//  BRSyncWatchdog.h
//
//  The sync watchdogs' decisions: when a stuck compact-filter sync is re-anchored, healed or
//  rebuilt, and when a frozen tip is nudged (re-request headers, pin a canon filter peer) or
//  escalated (recreate the peer manager). Several of these DELETE persisted filter state and
//  re-init the scan, so a platform that decides differently either wipes a healthy descent or
//  leaves a wedged wallet wedged. Until 2026-10 the rules lived in Kotlin
//  (Bip158WatchdogPolicy.kt, and the tier ordering inline in SyncService.startTipStallWatchdog);
//  Bip158WatchdogPolicyTest.kt is carried over case for case in the host KAT.
//
//  The liveness signal is the CF SCAN frontier (BRPeerManagerLowestNeededHeight), not the block
//  tip: the paced convoy freezes the block-header frontier at scanFrontier + CF_CONVOY_WINDOW by
//  design, so a frozen block tip is pacing, not a stall. Destructive tiers (re-anchor, frozen-CF
//  recovery, corrupt-chain heal, tier-2 manager recreate) stand down while the native retry
//  valve owns a pinned hole (BRPeerManagerHasPendingAbandonment) AND the frontier moved within
//  the suppression ceiling; past the ceiling they re-arm (the unbounded form disabled every tier
//  in exactly the wedges they exist to cure). Non-destructive tiers (header re-request, the
//  canon-peer pin) are never suppressed.
//
//  Times are milliseconds; differences wrap as Kotlin's Long does. Every threshold parameter
//  is explicit; the Kotlin defaults are the BR_WD_* constants. The live convoy values are
//  CF_CONVOY_WINDOW and CF_CONVOY_REARM_MAX (BRPeerManager.h); pass
//  BRWatchdogSuppressionMaxMs(CF_CONVOY_REARM_MAX) as the ceiling.
//
//  Host KAT: digibytewallet-android native/src/test/host/sync_watchdog_kat/.
//  Header-only, static inline, no state of its own (BRTipStallState is the caller's).
//

#ifndef BRSyncWatchdog_h
#define BRSyncWatchdog_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Plain literals, so Swift's C importer sees them.
#define BR_WD_REANCHOR_GRACE_MS            60000LL     // a re-anchored chain's time to land its first cfheaders
#define BR_WD_HEALTHY_CF_GAP_BLOCKS        100LL       // block tip minus filter tip still "keeping pace"
#define BR_WD_CF_FROZEN_RECOVERY_MS        120000LL    // filter tip frozen while headers climb: wedged
#define BR_WD_CF_CORRUPT_HEAL_MS           90000LL     // frozen after the re-anchor's grace: corrupt chain
#define BR_WD_CF_CORRUPT_HEAL_COOLDOWN_MS  240000LL    // spacing between heals (wider than the threshold)
#define BR_WD_MAX_CF_CORRUPT_HEALS         3           // heals per session
#define BR_WD_TIP_STALL_TIMEOUT_MS         1200000LL   // 20 min: tier 1; twice that arms tier 2
#define BR_WD_TIP_STALL_FAST_MS            180000LL    // 3 min: the fast tier, and its throttle
#define BR_WD_TIP_STALL_TIER2_THROTTLE_MS  3600000LL   // at most one manager recreate an hour
#define BR_WD_TIP_STALL_POLL_MS            60000LL     // the tip-stall watchdog's poll
#define BR_WD_CF_VALVE_RETRY_CYCLE_MS      450000LL    // one native retry cycle for a hole (30+60+120+120+120 s)
#define BR_WD_CF_CONVOY_WINDOW_FALLBACK    10000LL     // CF_CONVOY_WINDOW, for callers without the header
#define BR_WD_CF_CONVOY_REARM_MAX_FALLBACK 2           // CF_CONVOY_REARM_MAX, likewise
#define BR_WD_SUPPRESSION_MAX_MS_FALLBACK  1800000LL   // BRWatchdogSuppressionMaxMs(2): 30 min

static inline int64_t _brWdSub(int64_t a, int64_t b) { return (int64_t)((uint64_t)a - (uint64_t)b); }
static inline int64_t _brWdTwice(int64_t a) { return (int64_t)((uint64_t)a * 2u); }

// ---- convoy window and suppression -------------------------------------------------------

// LowestNeededHeight reads 0 with no peer manager and 1 on a fresh ledger: neither is a frontier.
static inline int BRWatchdogIsScanFrontierArmed(int64_t scanFrontier) { return scanFrontier > 1; }

// The destructive tiers' ceiling: the valve's whole budget for a hole plus one spare cycle,
// (rearmMax + 2) retry cycles, derived from the live CF_CONVOY_REARM_MAX.
static inline int64_t BRWatchdogSuppressionMaxMs(int rearmMax)
{
    return (int64_t)((uint64_t)BR_WD_CF_VALVE_RETRY_CYCLE_MS * (uint64_t)((int64_t)rearmMax + 2));
}

// The header window is full (W_hdr >= window). Compared before subtracting: the scan frontier can
// sit above the block tip (an abandonment watermark), which must read as open, not full.
static inline int BRWatchdogIsConvoyWindowFull(int64_t blockHeaderFrontier, int64_t scanFrontier, int64_t window)
{
    return BRWatchdogIsScanFrontierArmed(scanFrontier) && blockHeaderFrontier >= scanFrontier &&
           blockHeaderFrontier - scanFrontier >= window;
}

// Destructive recovery stands down only while native owns a pinned hole AND the frontier moved
// within the ceiling. Bounded: past the ceiling the valve has provably failed to release it.
static inline int BRWatchdogIsConvoySuppressed(int abandonmentPendingCycles, int64_t frontierPinnedMs, int64_t suppressionMaxMs)
{
#ifdef SYNC_WATCHDOG_RED
    (void)frontierPinnedMs; (void)suppressionMaxMs;
    return abandonmentPendingCycles > 0;     // RED ARM SEAM (sync_watchdog_kat): the unbounded C2 form
#else
    return abandonmentPendingCycles > 0 && frontierPinnedMs < suppressionMaxMs;
#endif
}

// ---- the BIP158 watchdog -----------------------------------------------------------------

typedef enum {
    BRWatchdogReanchor = 0,      // attempt the one-time re-anchor at the block floor
    BRWatchdogAwaitReanchor,     // a re-anchor fired and the freed chain is still rebuilding
    BRWatchdogStayOnFilters      // nothing left to try this session (never a bloom fallback)
} BRWatchdogPostTimeoutAction;

// After the full fallback timeout with headers caught up and cfheaders not advancing.
static inline BRWatchdogPostTimeoutAction BRWatchdogDecidePostTimeout(int hasReachedSynced, int reanchoredThisSession,
    int64_t msSinceReanchor, int64_t scanStalledMs, int abandonmentPendingCycles,
    int64_t scanFrozenThresholdMs /* BR_WD_CF_FROZEN_RECOVERY_MS */, int64_t suppressionMaxMs)
{
    if (hasReachedSynced && ! reanchoredThisSession && scanStalledMs >= scanFrozenThresholdMs &&
        ! BRWatchdogIsConvoySuppressed(abandonmentPendingCycles, scanStalledMs, suppressionMaxMs)) return BRWatchdogReanchor;
    if (reanchoredThisSession && msSinceReanchor < BR_WD_REANCHOR_GRACE_MS) return BRWatchdogAwaitReanchor;
    return BRWatchdogStayOnFilters;
}

// Filters keep pace: within the gap of the block tip, and advancing or the blocks at the network tip.
static inline int BRWatchdogIsFilterSyncHealthy(int64_t gap, int cfAdvancedSinceStart, int blocksCaughtUp)
{
    return gap <= BR_WD_HEALTHY_CF_GAP_BLOCKS && (cfAdvancedSinceStart || blocksCaughtUp);
}

// The one-time frozen-CF recovery: the filter tip made progress (session max > 0), then froze
// while headers climb, and the SCAN is frozen too (a draining scan proves the CF path alive).
static inline int BRWatchdogShouldRecoverFrozenCf(int blockClimbing, int64_t cfFrozenMs, int64_t cfNetMax,
    int alreadyRecovered, int64_t scanStalledMs, int abandonmentPendingCycles,
    int64_t thresholdMs /* BR_WD_CF_FROZEN_RECOVERY_MS */, int64_t suppressionMaxMs)
{
    return ! alreadyRecovered && blockClimbing && cfNetMax > 0 && cfFrozenMs >= thresholdMs &&
           scanStalledMs >= thresholdMs &&
           ! BRWatchdogIsConvoySuppressed(abandonmentPendingCycles, scanStalledMs, suppressionMaxMs);
}

// The clean-slate heal of a corrupt persisted filter chain: headers at the tip, filter peers
// connected, the re-anchor already tried and given its grace, still frozen. Bounded per session.
static inline int BRWatchdogShouldHealCorruptChain(int blocksCaughtUp, int peerCount, int64_t cfFrozenMs,
    int reanchored, int64_t msSinceReanchor, int healsSoFar, int64_t scanStalledMs, int abandonmentPendingCycles,
    int64_t thresholdMs /* BR_WD_CF_CORRUPT_HEAL_MS */, int maxHeals /* BR_WD_MAX_CF_CORRUPT_HEALS */,
    int64_t suppressionMaxMs)
{
    return blocksCaughtUp && peerCount > 0 && reanchored && msSinceReanchor >= BR_WD_REANCHOR_GRACE_MS &&
           healsSoFar < maxHeals && cfFrozenMs >= thresholdMs && scanStalledMs >= thresholdMs &&
           ! BRWatchdogIsConvoySuppressed(abandonmentPendingCycles, scanStalledMs, suppressionMaxMs);
}

// ---- the tip-stall watchdog --------------------------------------------------------------

// Armed: the scan frozen past the threshold, and, while the window is FULL (header frontier
// pinned by the gate), the raw block tip frozen too.
static inline int BRWatchdogIsTipStallArmed(int64_t scanStalledMs, int64_t blockTipStalledMs, int convoyWindowFull, int64_t thresholdMs)
{
    return scanStalledMs >= thresholdMs && (! convoyWindowFull || blockTipStalledMs >= thresholdMs);
}

// Tier 1: re-request headers. Never suppressed (it deletes nothing).
static inline int BRWatchdogShouldRerequestHeaders(int peerCount, int64_t scanStalledMs, int64_t blockTipStalledMs,
    int convoyWindowFull, int64_t thresholdMs /* BR_WD_TIP_STALL_TIMEOUT_MS */)
{
    return peerCount > 0 && BRWatchdogIsTipStallArmed(scanStalledMs, blockTipStalledMs, convoyWindowFull, thresholdMs);
}

// Tier 2: recreate the manager, after tier 1 fired and the stall lasted twice the threshold.
// Destructive in-session (the fresh manager re-inits the scan), so it carries the liveness gate.
static inline int BRWatchdogShouldForceReconnect(int peerCount, int64_t scanStalledMs, int64_t blockTipStalledMs,
    int convoyWindowFull, int tier1Fired, int abandonmentPendingCycles,
    int64_t thresholdMs /* BR_WD_TIP_STALL_TIMEOUT_MS */, int64_t suppressionMaxMs)
{
    return peerCount > 0 && tier1Fired &&
           ! BRWatchdogIsConvoySuppressed(abandonmentPendingCycles, scanStalledMs, suppressionMaxMs) &&
           BRWatchdogIsTipStallArmed(scanStalledMs, blockTipStalledMs, convoyWindowFull, _brWdTwice(thresholdMs));
}

// The fast tier: re-request headers and pin a canon filter peer. Never suppressed.
static inline int BRWatchdogShouldFastRecover(int peerCount, int64_t scanStalledMs, int64_t blockTipStalledMs,
    int convoyWindowFull, int64_t thresholdMs /* BR_WD_TIP_STALL_FAST_MS */)
{
    return peerCount > 0 && BRWatchdogIsTipStallArmed(scanStalledMs, blockTipStalledMs, convoyWindowFull, thresholdMs);
}

// ---- scan-frontier tracking: the watchdogs' liveness clock ---------------------------------

typedef struct {
    int64_t frontier;       // the frontier to carry forward
    int64_t lastChangeMs;   // wall clock of its last CHANGE
    int changed;            // this poll observed one
} BRWatchdogFrontierProgress;

// Motion restarts the clock, and a regression to a real frontier is motion (a recovery or a deep
// reorg re-inits the ledger far below); an unarmed reading (0 or 1) is ignored.
static inline BRWatchdogFrontierProgress BRWatchdogStepScanFrontier(int64_t prevFrontier, int64_t prevChangeMs,
                                                                   int64_t frontierNow, int64_t nowMs)
{
    BRWatchdogFrontierProgress p = { prevFrontier, prevChangeMs, 0 };
    if (frontierNow == prevFrontier) return p;
    if (frontierNow > prevFrontier) { p.frontier = frontierNow; p.lastChangeMs = nowMs; p.changed = 1; return p; }
#ifndef SYNC_WATCHDOG_RED
    // (RED ARM SEAM: a forward-only tracker, which froze the clock for a whole re-climb.)
    if (BRWatchdogIsScanFrontierArmed(frontierNow)) { p.frontier = frontierNow; p.lastChangeMs = nowMs; p.changed = 1; }
#endif
    return p;
}

typedef struct {
    int64_t lastScan;          // last observed scan frontier
    int64_t lastScanChangeMs;  // wall clock of its last change (advance or re-init)
    int64_t lastTip;           // last observed raw block tip
    int64_t lastTipAdvanceMs;  // wall clock of its last advance
    int scanArmed;             // the scan frontier is a usable signal this poll
    int tier1Fired;            // tier 1 already fired for the current stall
    int progressed;            // this poll saw progress on the AUTHORITATIVE signal
} BRTipStallState;

static inline BRTipStallState BRTipStallInit(int64_t tip, int64_t scan, int64_t nowMs)
{
    BRTipStallState s = { scan, nowMs, tip, nowMs, BRWatchdogIsScanFrontierArmed(scan), 0, 0 };
    return s;
}

// One poll. The authoritative signal is the scan frontier while armed, else the block tip; the
// tier-1 latch clears only on progress of THAT signal (a block-tip re-kick while the scan is
// armed must not clear it, or tier 2 could never escalate a real scan wedge).
static inline BRTipStallState BRTipStallStep(BRTipStallState s, int64_t tipNow, int64_t scanNow, int64_t nowMs)
{
    int scanArmedNow = BRWatchdogIsScanFrontierArmed(scanNow), tipAdvanced = tipNow > s.lastTip;
    BRWatchdogFrontierProgress p = BRWatchdogStepScanFrontier(s.lastScan, s.lastScanChangeMs, scanNow, nowMs);
    int progressedNow = scanArmedNow ? p.changed : tipAdvanced;
    BRTipStallState n;

    n.lastScan = p.frontier;
    n.lastScanChangeMs = p.lastChangeMs;
    n.lastTip = tipAdvanced ? tipNow : s.lastTip;
    n.lastTipAdvanceMs = tipAdvanced ? nowMs : s.lastTipAdvanceMs;
    n.scanArmed = scanArmedNow;
    n.tier1Fired = progressedNow ? 0 : s.tier1Fired;
    n.progressed = progressedNow;
    return n;
}

// How long the authoritative signal has been stopped (the block tip until the scan is armed).
static inline int64_t BRTipStallScanStalledMs(BRTipStallState s, int64_t nowMs)
{
    return s.scanArmed ? _brWdSub(nowMs, s.lastScanChangeMs) : _brWdSub(nowMs, s.lastTipAdvanceMs);
}

// How long the raw block tip has been frozen.
static inline int64_t BRTipStallBlockTipStalledMs(BRTipStallState s, int64_t nowMs)
{
    return _brWdSub(nowMs, s.lastTipAdvanceMs);
}

typedef enum {
    BRTipStallNone = 0,
    BRTipStallRecreateManager,   // tier 2: recreate the peer manager, resuming near the tip
    BRTipStallRerequestHeaders,  // tier 1: a full-locator getheaders (BRPeerManagerRerequestHeadersFromTip)
    BRTipStallFastRecover        // re-request headers AND pin the next validated canon filter peer
} BRTipStallAction;

// The tip-stall watchdog's one decision per poll, in SyncService.startTipStallWatchdog's order:
// tier 2 (throttled to one an hour), else tier 1 (once per stall), else the fast tier (throttled
// to one per BR_WD_TIP_STALL_FAST_MS). Updates *state's tier-1 latch and the throttle stamps; the
// caller performs the action. Call after BRTipStallStep for this poll.
static inline BRTipStallAction BRTipStallDecide(BRTipStallState *state, int peerCount, int abandonmentPendingCycles,
    int convoyWindowFull, int64_t suppressionMaxMs, int64_t nowMs, int64_t *lastTier2Ms, int64_t *lastFastMs)
{
    int64_t scanStalled = BRTipStallScanStalledMs(*state, nowMs), tipStalled = BRTipStallBlockTipStalledMs(*state, nowMs);

    if (BRWatchdogShouldForceReconnect(peerCount, scanStalled, tipStalled, convoyWindowFull, state->tier1Fired,
                                       abandonmentPendingCycles, BR_WD_TIP_STALL_TIMEOUT_MS, suppressionMaxMs) &&
        _brWdSub(nowMs, *lastTier2Ms) >= BR_WD_TIP_STALL_TIER2_THROTTLE_MS) {
        *lastTier2Ms = nowMs;
        state->tier1Fired = 0;            // re-arm tier 1 against the fresh manager
        return BRTipStallRecreateManager;
    }
    if (BRWatchdogShouldRerequestHeaders(peerCount, scanStalled, tipStalled, convoyWindowFull, BR_WD_TIP_STALL_TIMEOUT_MS) &&
        ! state->tier1Fired) {
        state->tier1Fired = 1;
        return BRTipStallRerequestHeaders;
    }
    if (BRWatchdogShouldFastRecover(peerCount, scanStalled, tipStalled, convoyWindowFull, BR_WD_TIP_STALL_FAST_MS) &&
        _brWdSub(nowMs, *lastFastMs) >= BR_WD_TIP_STALL_FAST_MS) {
        *lastFastMs = nowMs;
        return BRTipStallFastRecover;
    }
    return BRTipStallNone;
}

#ifdef __cplusplus
}
#endif

#endif // BRSyncWatchdog_h
