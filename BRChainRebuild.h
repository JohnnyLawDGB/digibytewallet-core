//
//  BRChainRebuild.h
//
//  What a "rebuild from chain" does, in order: the user's last resort when the transaction history
//  is wrong (phantom chained sends, missing block heights, phantom coins). It clears everything the
//  wallet re-derives from the chain, keeps the seed and what cannot be re-derived, floors the scan
//  at the wallet's birth or lower, and reloads, so every transaction is re-detected and
//  block-stamped by the compact-filter scan. Until 2026-11 the order lived only in Android's Kotlin
//  (WalletManager.kt: rebuildFromChainRescan, rebuildFromChainRescanFrom, restoreFromDisk;
//  HistoryRebuildOnUpgrade.kt: clearTransactionCacheForRebuild, armRerun, runAtProcessStart;
//  SyncService.kt: the floor step at sync start; the restart in ReconcileScreen.kt).
//
//  ## A SPECIFICATION, not an executor
//
//  The steps are I/O on each platform's own stores, and Android's reload is a process restart,
//  which a C function cannot perform and should not orchestrate. So, like BRRecreateSequence.h,
//  this header holds the KNOWLEDGE as data: the steps, their order, what each clears or keeps, and
//  which failures stop the rebuild. Each platform keeps its executor (Android: WalletManager plus a
//  process restart; iOS: an in-session executor that tears the wallet down and loads it again) and
//  its parity test asserts the executor's observed order against BRChainRebuildStepAt and
//  BRChainRebuildReloadStepAt.
//
//  ## The sequence (BRChainRebuildSteps)
//
//    STOP_SYNC             stop the sync session FIRST, so the peer manager cannot persist the
//                          saved blocks or the transaction cache again after they are cleared (a
//                          final persist, if any, runs before the clears and is overwritten).
//    ARM_RERUN             BEFORE the clears: mark the one-time history rebuild to run again at the
//                          next load (not done, in progress), keeping the floor record. A writer
//                          that puts a cache back between the clears and the reload is then
//                          cleared again before anything loads it (RELOAD, RERUN_ON_LOAD).
//    FLOOR_FROM_CACHE      BEFORE the cache is cleared: carry the cache's oldest confirmed height
//                          and oldest record time into the floor record
//                          (BRSavedTransactionsFloorMinima, then BRScanFloorFromDiscardedCache).
//                          Without it a confirmed transaction below the birth anchor (a wallet
//                          restored with the default creation time, or a transaction imported from
//                          a server) is dropped with the cache and never scanned again.
//    CLEAR_TX_CACHE        the stored transaction graph (Android `saved_transactions`).
//    CLEAR_FILTER_CHAIN    the compact-filter header chain (key and file store); it re-anchors at
//                          the floor.
//    CLEAR_SAVED_BLOCKS    the saved block-header window (key, its tip, and file store). Cleared with
//                          the filter chain: a header chain shallower than the rescan range cannot
//                          resolve the filters' stop hashes.
//    CLEAR_SYNC_STATE      "has synced" and the balance snapshots the wallet screen starts from (DGB
//                          and DigiDollar). Without "has synced" the next scan starts from the
//                          stored floor (BRCFRestoreArmHeight), not from near the saved tip.
//    CLEAR_SCAN_LEDGER     the compact-filter scan ledger. Load-bearing: the ledger's abandoned-below
//                          height is a monotonic hard floor on every filter request, so a surviving
//                          ledger would stop the rescan from ever re-covering an abandoned band.
//    CLEAR_ABANDONMENT     the surfaced abandoned band: with the ledger gone there is nothing left to
//                          recover.
//    CLEAR_OUTGOING_STORE  the recorded sends' metadata. The rebuild does NOT defer for the wallet's
//                          own unsettled sends (the one-time rebuild after an update does): it drops
//                          them with the cache and drops their records here, so an unconfirmed send
//                          the scan cannot re-learn is forgotten.
//    SET_FLOOR_AT_BIRTH    the STORED floor is overwritten with the wallet's current birth anchor,
//                          or REMOVED when that is 0 or unknown (BRScanFloorBirthToPersist: 0 is
//                          never written). This replaces the stored floor whatever it was, lower or
//                          higher; it is not a lowering. The floor record (BRScanFloor) is not
//                          touched here, and carries anything lower into the stored floor at sync
//                          start (SYNC_START_FLOOR_STEP).
//    RELOAD                load the wallet again from the cleared stores and start sync: the
//                          sub-steps below, in order. Android ends the process and starts a new one.
//
//  CLEAR_TX_CACHE .. CLEAR_ABANDONMENT are one platform operation on Android
//  (clearTransactionCacheForRebuild, shared with the one-time rebuild after an update so the two
//  cannot drift): the keys go in one synchronous commit, then the filter chain, saved blocks and
//  ledger files, then the band. It reports whether the commit landed and the three files are gone;
//  the band's clear is not checked (its result is ignored). Every write is synchronous: the reload
//  may end the process.
//
//  "Rebuild from a height" (BRChainRebuildFromSteps) is the same sequence after LOWER_FLOOR_TO,
//  which carries the floor record down to a height a reconcile reported but the wallet could not
//  check (BRScanFloorLowerTo), so the rescan reaches it.
//
//  ## RELOAD (BRChainRebuildReloadSteps)
//
//  What an in-session executor must reproduce of Android's next process start, in order:
//    RERUN_ON_LOAD             the armed one-time rebuild runs before anything reads the stores:
//                              any cache written back since the clears is carried into the floor
//                              record (BRScanFloorFromDiscardedCache over its minima), the clears
//                              run again, and only then is the rebuild stamped done.
//    LOAD_SKIPS_CACHE          while the rebuild is still in progress (its rerun did not finish),
//                              the wallet load does not read the transaction cache.
//    RESTORE_AT_FLOOR_TIME     the wallet is rebuilt from the stored seed with the creation time
//                              BRScanFloorRestoreCreationTime(stored, record time), so the header
//                              anchor sits at or below the record.
//    SYNC_START_FLOOR_STEP     at sync start, BRScanFloorHintStep carries the record into the stored
//                              floor (record applied only once that write landed), then the scan
//                              arms at BRCFRestoreArmHeight.
//
//  ## What it keeps (BRChainRebuildKept)
//
//    the seed and the keys derived from it; the saved peers; the watched addresses; the floor
//    record (BRScanFloor: ARM_RERUN keeps it, and a lower floor recorded for this wallet still
//    applies); every setting other than the stored floor.
//
//  ## Failures (BRChainRebuildContinuesAfterFailure)
//
//  A step the clears depend on stops the rebuild when it fails: STOP_SYNC (a live session can write
//  the stores back over the clears), ARM_RERUN (nothing would clear a cache written back after the
//  clears, and a clear that did not land would not be repeated), FLOOR_FROM_CACHE (the cache's
//  floor would be lost with it) and LOWER_FLOOR_TO (the rescan would not reach the height the
//  rebuild is for). An in-session executor aborts there, before any clear, or defers the rebuild
//  to the next launch. Every later step runs even when one before it failed: a cleared cache with
//  the old floor, or a cleared filter chain beside the old ledger, is worse than finishing. A clear
//  that did not land is repeated by RERUN_ON_LOAD, which holds only because ARM_RERUN landed.
//
//  A FLOOR_FROM_CACHE that fails after ARM_RERUN landed leaves the rerun armed, so stopping there
//  is a deferral to the next launch, not a clean abort. That is safe: RERUN_ON_LOAD carries the
//  cache's floor before it clears. A true abort must also disarm the rerun (done back on, in
//  progress off). Writing ARM_RERUN and FLOOR_FROM_CACHE in one commit, as Android's one-time
//  rebuild does (its run() commits in-progress and the floor together), removes the case.
//
//  (Android follows this order and these stop rules since digibytewallet-android #248: a failed
//  LOWER_FLOOR_TO, STOP_SYNC, ARM_RERUN or FLOOR_FROM_CACHE returns before any clear. A failed
//  ARM_RERUN or FLOOR_FROM_CACHE then puts done and in-progress back as they were; if that write
//  fails too, the rerun stays armed, which defers the rebuild to the next launch.)
//
//  Host KAT: digibytewallet-android native/src/test/host/scan_floor_kat/ (the order checked against
//  the order of the calls in Android's source). Vectors: vectors/scan-floor/. Header-only, static
//  inline, no I/O.
//

#ifndef BRChainRebuild_h
#define BRChainRebuild_h

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BR_CHAIN_REBUILD_LOWER_FLOOR_TO = 0,     // (from a height only) lower the floor record to it
    BR_CHAIN_REBUILD_STOP_SYNC,              // stop sync first: nothing persists over the clears
    BR_CHAIN_REBUILD_ARM_RERUN,              // before the clears: the next load clears again
    BR_CHAIN_REBUILD_FLOOR_FROM_CACHE,       // before the cache goes: its minima into the record
    BR_CHAIN_REBUILD_CLEAR_TX_CACHE,         // the transaction graph
    BR_CHAIN_REBUILD_CLEAR_FILTER_CHAIN,     // the filter-header chain
    BR_CHAIN_REBUILD_CLEAR_SAVED_BLOCKS,     // the saved header window and its tip
    BR_CHAIN_REBUILD_CLEAR_SYNC_STATE,       // "has synced" and the balance snapshots
    BR_CHAIN_REBUILD_CLEAR_SCAN_LEDGER,      // the filter scan ledger (its abandoned-below floor)
    BR_CHAIN_REBUILD_CLEAR_ABANDONMENT,      // the surfaced abandoned band
    BR_CHAIN_REBUILD_CLEAR_OUTGOING_STORE,   // recorded sends' metadata (no deferral for them)
    BR_CHAIN_REBUILD_SET_FLOOR_AT_BIRTH,     // stored floor overwritten with the birth, or removed for 0
    BR_CHAIN_REBUILD_RELOAD,                 // reload the wallet and start sync: the reload steps
} BRChainRebuildStep;

#define BR_CHAIN_REBUILD_STEP_KINDS   13   // values of BRChainRebuildStep
#define BR_CHAIN_REBUILD_STEP_COUNT   12   // steps of a rebuild
#define BR_CHAIN_REBUILD_FROM_COUNT   13   // steps of a rebuild from a height

// The rebuild, in order.
static const BRChainRebuildStep BRChainRebuildSteps[BR_CHAIN_REBUILD_STEP_COUNT] = {
    BR_CHAIN_REBUILD_STOP_SYNC,
#ifndef CHAIN_REBUILD_ORDER_RED
    BR_CHAIN_REBUILD_ARM_RERUN,
#endif
#ifndef CHAIN_REBUILD_FLOOR_RED
    BR_CHAIN_REBUILD_FLOOR_FROM_CACHE,
#endif
    BR_CHAIN_REBUILD_CLEAR_TX_CACHE,
#ifdef CHAIN_REBUILD_FLOOR_RED
    // RED ARM SEAM (scan_floor_kat): the cache's floor taken after the cache is gone.
    BR_CHAIN_REBUILD_FLOOR_FROM_CACHE,
#endif
    BR_CHAIN_REBUILD_CLEAR_FILTER_CHAIN,
    BR_CHAIN_REBUILD_CLEAR_SAVED_BLOCKS,
    BR_CHAIN_REBUILD_CLEAR_SYNC_STATE,
    BR_CHAIN_REBUILD_CLEAR_SCAN_LEDGER,
    BR_CHAIN_REBUILD_CLEAR_ABANDONMENT,
#ifdef CHAIN_REBUILD_ORDER_RED
    // RED ARM SEAM (scan_floor_kat): the rerun armed after the clears, so a cache written back in
    // between is loaded.
    BR_CHAIN_REBUILD_ARM_RERUN,
#endif
    BR_CHAIN_REBUILD_CLEAR_OUTGOING_STORE,
    BR_CHAIN_REBUILD_SET_FLOOR_AT_BIRTH,
    BR_CHAIN_REBUILD_RELOAD,
};

// The rebuild from a height, in order: the floor first, then the rebuild.
static const BRChainRebuildStep BRChainRebuildFromSteps[BR_CHAIN_REBUILD_FROM_COUNT] = {
    BR_CHAIN_REBUILD_LOWER_FLOOR_TO,
    BR_CHAIN_REBUILD_STOP_SYNC,
#ifndef CHAIN_REBUILD_ORDER_RED
    BR_CHAIN_REBUILD_ARM_RERUN,
#endif
#ifndef CHAIN_REBUILD_FLOOR_RED
    BR_CHAIN_REBUILD_FLOOR_FROM_CACHE,
#endif
    BR_CHAIN_REBUILD_CLEAR_TX_CACHE,
#ifdef CHAIN_REBUILD_FLOOR_RED
    BR_CHAIN_REBUILD_FLOOR_FROM_CACHE,
#endif
    BR_CHAIN_REBUILD_CLEAR_FILTER_CHAIN,
    BR_CHAIN_REBUILD_CLEAR_SAVED_BLOCKS,
    BR_CHAIN_REBUILD_CLEAR_SYNC_STATE,
    BR_CHAIN_REBUILD_CLEAR_SCAN_LEDGER,
    BR_CHAIN_REBUILD_CLEAR_ABANDONMENT,
#ifdef CHAIN_REBUILD_ORDER_RED
    BR_CHAIN_REBUILD_ARM_RERUN,
#endif
    BR_CHAIN_REBUILD_CLEAR_OUTGOING_STORE,
    BR_CHAIN_REBUILD_SET_FLOOR_AT_BIRTH,
    BR_CHAIN_REBUILD_RELOAD,
};

// RELOAD's sub-steps, in order.
typedef enum {
    BR_CHAIN_REBUILD_RERUN_ON_LOAD = 0,         // the armed rerun: written-back cache's floor, clear again, done
    BR_CHAIN_REBUILD_LOAD_SKIPS_CACHE,          // a rebuild in progress: the load does not read the cache
    BR_CHAIN_REBUILD_RESTORE_AT_FLOOR_TIME,     // creation time BRScanFloorRestoreCreationTime(stored, record time)
    BR_CHAIN_REBUILD_SYNC_START_FLOOR_STEP,     // BRScanFloorHintStep at sync start, then arm the scan
} BRChainRebuildReloadStep;

#define BR_CHAIN_REBUILD_RELOAD_COUNT 4

static const BRChainRebuildReloadStep BRChainRebuildReloadSteps[BR_CHAIN_REBUILD_RELOAD_COUNT] = {
    BR_CHAIN_REBUILD_RERUN_ON_LOAD,
    BR_CHAIN_REBUILD_LOAD_SKIPS_CACHE,
    BR_CHAIN_REBUILD_RESTORE_AT_FLOOR_TIME,
    BR_CHAIN_REBUILD_SYNC_START_FLOOR_STEP,
};

// What a rebuild keeps.
typedef enum {
    BR_CHAIN_REBUILD_KEEP_SEED = 0,           // the seed and every key derived from it
    BR_CHAIN_REBUILD_KEEP_SAVED_PEERS,        // the saved peer list
    BR_CHAIN_REBUILD_KEEP_WATCHED_ADDRESSES,  // addresses pinned into the filter watch set
    BR_CHAIN_REBUILD_KEEP_FLOOR_RECORD,       // BRScanFloor: height, time and pending
    BR_CHAIN_REBUILD_KEEP_SETTINGS,           // every setting other than the stored floor
} BRChainRebuildKeep;

#define BR_CHAIN_REBUILD_KEPT_COUNT 5

static const BRChainRebuildKeep BRChainRebuildKept[BR_CHAIN_REBUILD_KEPT_COUNT] = {
    BR_CHAIN_REBUILD_KEEP_SEED,
    BR_CHAIN_REBUILD_KEEP_SAVED_PEERS,
    BR_CHAIN_REBUILD_KEEP_WATCHED_ADDRESSES,
    BR_CHAIN_REBUILD_KEEP_FLOOR_RECORD,
    BR_CHAIN_REBUILD_KEEP_SETTINGS,
};

// The step at position index of the rebuild (fromHeight 0) or the rebuild from a height
// (fromHeight 1), or -1 out of range. Executors iterate this rather than hardcoding the order.
static inline int BRChainRebuildStepAt(int fromHeight, int index)
{
    if (fromHeight) return (index >= 0 && index < BR_CHAIN_REBUILD_FROM_COUNT) ? (int)BRChainRebuildFromSteps[index] : -1;
    return (index >= 0 && index < BR_CHAIN_REBUILD_STEP_COUNT) ? (int)BRChainRebuildSteps[index] : -1;
}

// The number of steps of the rebuild (fromHeight 0) or the rebuild from a height (fromHeight 1).
static inline int BRChainRebuildStepCount(int fromHeight)
{
    return fromHeight ? BR_CHAIN_REBUILD_FROM_COUNT : BR_CHAIN_REBUILD_STEP_COUNT;
}

// The position of step in the sequence, or -1 when it is not in it.
static inline int BRChainRebuildIndexOf(int fromHeight, BRChainRebuildStep step)
{
    for (int i = 0; i < BRChainRebuildStepCount(fromHeight); i++) {
        if (BRChainRebuildStepAt(fromHeight, i) == (int)step) return i;
    }
    return -1;
}

// Whether earlier runs before later in the sequence. Derived from the sequence, never from the
// enum values (which would hold whatever the sequence does).
static inline int BRChainRebuildMustPrecede(int fromHeight, BRChainRebuildStep earlier, BRChainRebuildStep later)
{
    int a = BRChainRebuildIndexOf(fromHeight, earlier), b = BRChainRebuildIndexOf(fromHeight, later);
    return a >= 0 && b >= 0 && a < b;
}

// RELOAD's sub-step at position index, or -1 out of range.
static inline int BRChainRebuildReloadStepAt(int index)
{
    return (index >= 0 && index < BR_CHAIN_REBUILD_RELOAD_COUNT) ? (int)BRChainRebuildReloadSteps[index] : -1;
}

// Whether the executor runs the steps after this one when it fails (see "Failures" above): 0 for
// the steps the clears depend on, which stop the rebuild; 1 for the rest.
static inline int BRChainRebuildContinuesAfterFailure(BRChainRebuildStep step)
{
    switch (step) {
        case BR_CHAIN_REBUILD_LOWER_FLOOR_TO:
        case BR_CHAIN_REBUILD_STOP_SYNC:
        case BR_CHAIN_REBUILD_ARM_RERUN:
        case BR_CHAIN_REBUILD_FLOOR_FROM_CACHE:
            return 0;
        default:
            return 1;
    }
}

// A stable name for a step, for logs and parity tests on both platforms; NULL for an unknown step.
static inline const char *BRChainRebuildStepName(BRChainRebuildStep step)
{
    switch (step) {
        case BR_CHAIN_REBUILD_LOWER_FLOOR_TO:       return "lowerFloorTo";
        case BR_CHAIN_REBUILD_STOP_SYNC:            return "stopSync";
        case BR_CHAIN_REBUILD_ARM_RERUN:            return "armRerun";
        case BR_CHAIN_REBUILD_FLOOR_FROM_CACHE:     return "floorFromCache";
        case BR_CHAIN_REBUILD_CLEAR_TX_CACHE:       return "clearTxCache";
        case BR_CHAIN_REBUILD_CLEAR_FILTER_CHAIN:   return "clearFilterChain";
        case BR_CHAIN_REBUILD_CLEAR_SAVED_BLOCKS:   return "clearSavedBlocks";
        case BR_CHAIN_REBUILD_CLEAR_SYNC_STATE:     return "clearSyncState";
        case BR_CHAIN_REBUILD_CLEAR_SCAN_LEDGER:    return "clearScanLedger";
        case BR_CHAIN_REBUILD_CLEAR_ABANDONMENT:    return "clearAbandonment";
        case BR_CHAIN_REBUILD_CLEAR_OUTGOING_STORE: return "clearOutgoingStore";
        case BR_CHAIN_REBUILD_SET_FLOOR_AT_BIRTH:   return "setFloorAtBirth";
        case BR_CHAIN_REBUILD_RELOAD:               return "reload";
        default:                                    return NULL;
    }
}

// A stable name for a reload sub-step; NULL for an unknown one.
static inline const char *BRChainRebuildReloadStepName(BRChainRebuildReloadStep step)
{
    switch (step) {
        case BR_CHAIN_REBUILD_RERUN_ON_LOAD:         return "rerunOnLoad";
        case BR_CHAIN_REBUILD_LOAD_SKIPS_CACHE:      return "loadSkipsCache";
        case BR_CHAIN_REBUILD_RESTORE_AT_FLOOR_TIME: return "restoreAtFloorTime";
        case BR_CHAIN_REBUILD_SYNC_START_FLOOR_STEP: return "syncStartFloorStep";
        default:                                     return NULL;
    }
}

// A stable name for a kept item; NULL for an unknown one.
static inline const char *BRChainRebuildKeepName(BRChainRebuildKeep keep)
{
    switch (keep) {
        case BR_CHAIN_REBUILD_KEEP_SEED:              return "seed";
        case BR_CHAIN_REBUILD_KEEP_SAVED_PEERS:       return "savedPeers";
        case BR_CHAIN_REBUILD_KEEP_WATCHED_ADDRESSES: return "watchedAddresses";
        case BR_CHAIN_REBUILD_KEEP_FLOOR_RECORD:      return "floorRecord";
        case BR_CHAIN_REBUILD_KEEP_SETTINGS:          return "settings";
        default:                                      return NULL;
    }
}

#ifdef __cplusplus
}
#endif

#endif // BRChainRebuild_h
