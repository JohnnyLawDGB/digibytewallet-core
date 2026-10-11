//
//  BRSyncFrontier.h
//
//  What the wallet tells its user about sync: Connecting, Syncing (and how far), Synced or
//  Failed, and the block it is honestly at. DigiByte sync is compact-filters only, so the
//  functional frontier is the filter SCAN, not the header height: headers race to the tip through
//  every peer, while deposits and confirmations are seen only as far as the filter scan has
//  reached. Saying "Synced" while the scan lags is how a deposit is missed while the screen says
//  "Up to date". Every surface that shows sync status derives it here, so two screens (or two
//  platforms) cannot disagree about "Synced". Until 2026-10 this lived in Kotlin
//  (core.model.deriveSyncFrontier, with the session latch and the running header maximum in
//  WalletViewModel).
//
//  The rule (BRSyncFrontierDerive):
//    - target: the larger of the running maximum of the header height and the peers' agreed
//      estimate. Once this process has reached Synced and the host's state is Complete, a target
//      more than BR_SYNC_TARGET_MAX_LEAD above the header height is unproven, and the header
//      height is the target instead (a residual outlier estimate must not hold the Send gate);
//    - scan: the filter scan frontier, else the filter-header tip, else the header height (the
//      first that is known);
//    - behind: the header more than BR_SYNC_BEHIND_THRESHOLD below the target, or the scan more
//      than BR_CF_BEHIND_THRESHOLD below it, or an abandoned filter band no recovery has covered;
//    - stage: Failed when the host's state is; else Connecting with no peers; else Syncing when
//      behind; else Synced when the host's state is Complete; else Syncing;
//    - the band "holds" when it alone withholds Synced (everything else says done);
//    - current block: the scan when the scan is what lags, else the header height;
//    - progress: 1 when the band holds; current/target while behind; 1 when Complete;
//      header/target when both are known; the host's own progress while Syncing; else 0. Computed
//      in float, as Kotlin computes it, and clamped to 0..1.
//  BRSyncFrontierStep keeps the per-process part: the running header maximum (raised BEFORE each
//  derivation), and whether this process has reached Synced (latched AFTER each derivation, so a
//  derivation sees the previous one's latch, as WalletViewModel did). Zero the session at process
//  start; it is never persisted (a cold start must not inherit "reached Synced").
//
//  Host KAT: digibytewallet-android native/src/test/host/sync_frontier_kat/ (Android's
//  SyncFrontierTest case for case, plus the scan-frontier, host-state and session cases).
//  Header-only, static inline.
//

#ifndef BRSyncFrontier_h
#define BRSyncFrontier_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_SYNC_BEHIND_THRESHOLD  100LL     // blocks; well above normal tip lag, far below a re-sync
#define BR_CF_BEHIND_THRESHOLD    100LL     // blocks the filter scan may trail the target
#define BR_SYNC_TARGET_MAX_LEAD   40320LL   // one week of 15 s blocks

// The host's own sync state (Android's SyncState).
typedef enum {
    BRSyncStateIdle = 0,
    BRSyncStateSyncing,         // the host's own progress (syncingProgress) applies
    BRSyncStateRescanning,
    BRSyncStateComplete,        // the host has reached sync (sticky across launches)
    BRSyncStateFailed,
    BRSyncStateChainSplit
} BRSyncState;

// What the user is told (Android's SyncStage).
typedef enum {
    BRSyncStageConnecting = 0,
    BRSyncStageSyncing,
    BRSyncStageSynced,
    BRSyncStageFailed
} BRSyncStage;

typedef struct {
    BRSyncStage stage;
    int64_t currentBlock;       // the honest "block X": the bottleneck frontier
    int64_t targetBlock;        // the effective tip
    float progressFraction;     // 0..1, currentBlock toward targetBlock
    int abandonedBandHolding;   // the un-recovered band alone withholds Synced
} BRSyncFrontier;

typedef struct {
    int64_t headerHeightMax;    // running maximum of the header height this process has seen
    int reachedSynced;          // this process has derived Synced (or the band hold)
} BRSyncFrontierSession;

// a - b, wrapping as Kotlin's Long subtraction does (never signed-overflow UB).
static inline int64_t _BRSyncLead(int64_t a, int64_t b) { return (int64_t)((uint64_t)a - (uint64_t)b); }

// Kotlin's coerceIn(0f, 1f): a NaN passes through, as it does there.
static inline float _BRSyncClamp01(float p) { return p < 0.0f ? 0.0f : p > 1.0f ? 1.0f : p; }

static inline BRSyncFrontier BRSyncFrontierDerive(BRSyncState state, float syncingProgress, int peerCount,
                                                  int64_t currentHeight, int64_t targetHeight, int64_t externalTip,
                                                  int64_t cfTip, int64_t scanFrontier,
                                                  int abandonedBandUnrecovered, int reachedSyncedThisSession)
{
    BRSyncFrontier f;
    int complete = (state == BRSyncStateComplete);
    int64_t seenTarget = externalTip > targetHeight ? externalTip : targetHeight;
    int targetUnproven = reachedSyncedThisSession && complete && currentHeight > 0 &&
                         _BRSyncLead(seenTarget, currentHeight) > BR_SYNC_TARGET_MAX_LEAD;
    int64_t target = targetUnproven ? currentHeight : seenTarget;
    int materiallyBehind = currentHeight > 0 && target > 0 &&
                           _BRSyncLead(target, currentHeight) > BR_SYNC_BEHIND_THRESHOLD;
    int64_t scan = scanFrontier > 0 ? scanFrontier : cfTip > 0 ? cfTip : currentHeight;
#ifdef SYNC_FRONTIER_RED
    // RED ARM SEAM (sync_frontier_kat): header-only, the filter scan ignored (the drift that let
    // one screen say "Synced" while the scan was still catching up).
    int cfBehind = 0;
#else
    int cfBehind = scan > 0 && target > 0 && _BRSyncLead(target, scan) > BR_CF_BEHIND_THRESHOLD;
#endif
    int behind = materiallyBehind || cfBehind || abandonedBandUnrecovered;
    int64_t frontier = (cfBehind && scan > 0) ? scan : currentHeight;
    float progress;

    if (state == BRSyncStateFailed) f.stage = BRSyncStageFailed;
    else if (peerCount <= 0) f.stage = BRSyncStageConnecting;
    else if (behind) f.stage = BRSyncStageSyncing;
    else if (complete) f.stage = BRSyncStageSynced;
    else f.stage = BRSyncStageSyncing;

    f.abandonedBandHolding = abandonedBandUnrecovered && !materiallyBehind && !cfBehind && peerCount > 0 && complete;

    if (f.abandonedBandHolding) progress = 1.0f;
    else if (behind && target > 0) progress = _BRSyncClamp01((float)frontier / (float)target);
    else if (complete) progress = 1.0f;
    else if (currentHeight > 0 && target > 0) progress = _BRSyncClamp01((float)currentHeight / (float)target);
    else if (state == BRSyncStateSyncing) progress = syncingProgress;
    else progress = 0.0f;

    f.currentBlock = frontier;
    f.targetBlock = target;
    f.progressFraction = _BRSyncClamp01(progress);
    return f;
}

// One poll: estimatedHeight is the peers' agreed estimate (0 when unknown: the header height
// stands in, as Android's poll does), cfTip the filter-header tip, scanFrontier the filter scan
// frontier (0 when unknown for either).
static inline BRSyncFrontier BRSyncFrontierStep(BRSyncFrontierSession *session, BRSyncState state,
                                                float syncingProgress, int peerCount, int64_t currentHeight,
                                                int64_t estimatedHeight, int64_t cfTip, int64_t scanFrontier,
                                                int abandonedBandUnrecovered)
{
    BRSyncFrontier f;

    if (currentHeight > session->headerHeightMax) session->headerHeightMax = currentHeight;
    f = BRSyncFrontierDerive(state, syncingProgress, peerCount, currentHeight,
                             estimatedHeight > 0 ? estimatedHeight : currentHeight, session->headerHeightMax,
                             cfTip, scanFrontier, abandonedBandUnrecovered, session->reachedSynced);
    if (f.stage == BRSyncStageSynced || f.abandonedBandHolding) session->reachedSynced = 1;
    return f;
}

// Network Info's "Blocks Remaining": none once Synced (a block or two of normal tip lag must not
// sit beside a green "Synced"), else how far the target leads the current block.
static inline int64_t BRSyncFrontierBlocksRemaining(BRSyncFrontier f)
{
    if (f.stage == BRSyncStageSynced) return 0;
    return (f.targetBlock > f.currentBlock && f.targetBlock > 0) ? _BRSyncLead(f.targetBlock, f.currentBlock) : 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRSyncFrontier_h
