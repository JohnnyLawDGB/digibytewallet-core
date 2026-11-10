//
//  BRScanFloor.h
//
//  The compact-filter scan floor: the lowest height a rescan starts from, and the rules that move
//  it. A floor too high hides every transaction below it (a balance that is silently short); a
//  floor too low costs only a longer scan. So a floor is only ever LOWERED, and a floor of 0 is
//  never written: 0 would start the scan at genesis, the full chain, a scan of many hours that an
//  interruption restarts. Two wallets on one seed that move the floor differently disagree about
//  which heights they have looked at. Until 2026-11 these rules lived only in Android's Kotlin
//  (HistoryRebuildOnUpgrade.kt: lowerFloor, lowerFloorTo, the floor step of its run, clearFloorHint,
//  markNotNeeded, requestFloorAtAnchor; WalletManager.kt: cfBirthHeightToPersist,
//  creationTimeForRestore; CfRestorePreflight.kt: floorHintStep; and the bridge's
//  getCheckpointTimeAtOrBelow).
//
//  TWO STORED VALUES. The platform keeps:
//    - the STORED FLOOR (Android `cf_birth_height` in `dgb_settings`): the height the next scan of a
//      wallet that has not synced starts from (BRCFRestoreArmHeight in BRCFRestorePreflight.h). It
//      is present or absent; when absent the scan falls back to the wallet's birth checkpoint.
//      "Only lowered" is NOT a rule of the stored floor: a restore, a rebuild from chain
//      (BRChainRebuild.h SET_FLOOR_AT_BIRTH) and a cold-start reset overwrite it with the wallet's
//      current anchor (or remove it), and committing "has synced" removes it. Only the sync-start
//      step below lowers it, and only to the anchor.
//    - the FLOOR RECORD (BRScanFloor; Android `floor_hint`, `floor_time`, `floor_pending` in
//      `dgb_history_rebuild`): a floor asked for but not yet carried into the stored floor.
//      `height` is the lowest height the next rescan must reach (0 = none); `time` is the lowest
//      time (unix seconds) the header anchor must be chosen from (0 = none); `pending` says the
//      next sync start still has to carry the record into the stored floor. Every rule below
//      that changes the record only ever lowers its height and time; only APPLIED and FORGET
//      remove them.
//
//  PER NETWORK. Both values describe one network's chain and are kept per network (iOS keeps the
//  stored floor per network). Android keeps the floor record per network (`dgb_history_rebuild`
//  plus the network suffix) but `cf_birth_height` WITHOUT a suffix, in the network-independent
//  `dgb_settings`: a mainnet/testnet switch before the first sync therefore hands one network's
//  stored floor to the other (a mainnet floor read by testnet sits above testnet's whole chain, so
//  its scan sees nothing; a testnet floor read by mainnet only lengthens the scan), and the first
//  sync on either network removes the other's floor.
//
//  THE RULES:
//    - LOWER (BRScanFloorLower). The lower of two optional floors, 0 meaning "no floor": no floor
//      and a candidate gives the candidate (a negative candidate gives 0); a floor and no candidate
//      (0 or negative) keeps the floor; two floors give the lower. A floor is never raised.
//    - BIRTH (BRScanFloorBirthToPersist). The wallet's birth checkpoint becomes the stored floor
//      only when it is positive. A birth of 0 (unknown, or the genesis anchor) or below REMOVES the
//      stored floor; 0 is never written.
//    - CHECKPOINT TIME (BRScanFloorCheckpointTimeAtOrBelow). The timestamp of the highest compiled
//      block checkpoint at or below a height (the table is not assumed sorted); 0 when there is
//      none, the height is negative, or there is no table. The header anchor is chosen by TIME (the
//      latest checkpoint more than a week before it, BRRecoveryBirthCheckpointHeight), so a floor
//      time no later than this puts the anchor at or below the height whatever the records say.
//    - LOWER TO (BRScanFloorLowerTo). A floor carried down to a height (a reconcile reported
//      transactions at a height the wallet cannot check): for a height of 0 or below nothing
//      changes; otherwise the record's height is lowered to it, the checkpoint time at or below
//      the RESULTING height is looked up, the record's time is lowered to that, and the record is
//      pending. A lookup that finds nothing (0) leaves the time as it was.
//    - DISCARDED CACHE (BRScanFloorFromDiscardedCache). When a transaction cache is discarded so
//      history is re-derived from the chain, the record carries what it held: the height is lowered
//      to the oldest confirmed height it held; the time is lowered to its oldest record time
//      (confirmed or not) and then to the checkpoint time at or below the resulting height (looked
//      up only when that height is positive); pending is SET to whether either is now non-zero
//      (it may clear a pending flag that was set). The minima come from the blob's framing:
//      BRSavedTransactionsFloorMinima (BRSavedTransactions.h).
//    - ANCHOR REQUEST (BRScanFloorRequestAtAnchor). Pending, nothing else: the next sync start
//      carries the stored floor down to the wallet's anchor.
//    - APPLIED (BRScanFloorApplied). The record has been carried into the stored floor: the height
//      and pending go, the time stays (it keeps the header anchor low on later loads).
//    - FORGET (BRScanFloorForget). A different wallet (create, recover, seed change): the record
//      goes entirely. A rebuild of the same wallet keeps it.
//    - SYNC-START STEP (BRScanFloorHintStep). What the sync start does with the record, given the
//      loaded wallet's header anchor (its birth checkpoint; 0 is the genesis anchor, a valid one)
//      and the stored floor. In this order:
//        no height and not pending, or no wallet loaded        -> nothing (the record waits)
//        a height the anchor is above                          -> nothing, the record is kept and
//                                                                 the platform says so
//                                                                 (anchorAboveHint)
//        no stored floor                                       -> store the anchor (when positive)
//                                                                 and clear the record
//        a stored floor at or below the anchor                 -> clear the record only
//        a stored floor above the anchor                       -> store the anchor (when positive,
//                                                                 else remove the stored floor)
//                                                                 and clear the record
//      The target is min(height, anchor): the anchor the floor time chose is at or below the height.
//      The platform applies clearHint (BRScanFloorApplied) ONLY after the stored-floor write
//      (setBirth / removeBirth) has landed: a record cleared beside a write that did not land is a
//      floor lost. (Android's SyncService today applies it whatever the write's commit returned.)
//      A height below the anchor cannot be resolved by the in-memory header chain (the filter
//      fetch would clamp it back up), so it waits until the anchor comes down.
//    - RESTORE TIME (BRScanFloorRestoreCreationTime). The creation time handed to the wallet when
//      it is rebuilt from the stored seed: the stored creation time (or
//      BR_SCAN_FLOOR_DEFAULT_RESTORE_CREATION_TIME when none was stored), lowered to the record's
//      time when it has one. Never raised.
//
//  Heights and times are int64_t, as the Kotlin's Long, so a platform's out-of-range input reads
//  the same here. No I/O, no clock, no locking; the platform owns the stores and their commits.
//
//  Host KAT: digibytewallet-android native/src/test/host/scan_floor_kat/ (the Kotlin tests case for
//  case, a line-for-line model of the Kotlin compared against this header, and the checkpoint lookup
//  compared against the bridge's checkpoint_time.h on the real tables). Vectors:
//  vectors/scan-floor/, this header's answers on a fixed corpus. Header-only, static inline.
//

#ifndef BRScanFloor_h
#define BRScanFloor_h

#include "BRChainParams.h"   // BRCheckPoint
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The creation time a wallet rebuilt from its stored seed is given when none was stored
// (Android's DEFAULT_RESTORE_CREATION_TIME, 2026-03-23 08:00 UTC).
#define BR_SCAN_FLOOR_DEFAULT_RESTORE_CREATION_TIME 1774252800LL

// The floor record. height: the lowest height the next rescan must reach, 0 = none. time: the
// lowest time (unix seconds) the header anchor must be chosen from, 0 = none. pending: the next
// sync start must still carry the record into the stored floor (0 or 1).
typedef struct {
    int64_t height;
    int64_t time;
    int pending;
} BRScanFloor;

// LOWER: the lower of two optional (0 = none) floors. A floor is never raised.
static inline int64_t BRScanFloorLower(int64_t existing, int64_t candidate)
{
#ifdef SCAN_FLOOR_RAISE_RED
    // RED ARM SEAM (scan_floor_kat): the higher of the two, a floor that rises.
    if (existing <= 0) return candidate > 0 ? candidate : 0;
    if (candidate <= 0) return existing;
    return existing > candidate ? existing : candidate;
#else
    if (existing <= 0) return candidate > 0 ? candidate : 0;
    if (candidate <= 0) return existing;
    return existing < candidate ? existing : candidate;
#endif
}

// BIRTH: whether the wallet's birth checkpoint height rawBirth is stored as the floor. 1: store
// *persistOut (set to rawBirth). 0: REMOVE the stored floor (*persistOut is set to 0 and must not
// be written). persistOut may be NULL.
static inline int BRScanFloorBirthToPersist(int64_t rawBirth, int64_t *persistOut)
{
#ifdef SCAN_FLOOR_ZERO_RED
    // RED ARM SEAM (scan_floor_kat): a birth of 0 is written, flooring the scan at genesis.
    int persist = rawBirth >= 0;
#else
    int persist = rawBirth > 0;
#endif
    if (persistOut) *persistOut = persist ? rawBirth : 0;
    return persist;
}

// CHECKPOINT TIME: the timestamp of the highest checkpoint whose height is <= height, over a table
// that is not assumed sorted; 0 when there is none, height is negative, or checkpoints is NULL.
static inline int64_t BRScanFloorCheckpointTimeAtOrBelow(const BRCheckPoint *checkpoints, size_t count, int64_t height)
{
    int found = 0;
    uint32_t bestHeight = 0, bestTime = 0;

    if (height < 0) return 0;
    for (size_t i = 0; checkpoints && i < count; i++) {
#ifdef SCAN_FLOOR_CHECKPOINT_RED
        // RED ARM SEAM (scan_floor_kat): the lowest checkpoint at or ABOVE the height, whose time
        // anchors the headers above the floor.
        if ((int64_t)checkpoints[i].height >= height && (! found || checkpoints[i].height < bestHeight)) {
#else
        if ((int64_t)checkpoints[i].height <= height && (! found || checkpoints[i].height > bestHeight)) {
#endif
            found = 1;
            bestHeight = checkpoints[i].height;
            bestTime = checkpoints[i].timestamp;
        }
    }
    return found ? (int64_t)bestTime : 0;
}

// LOWER TO: carry the record down to height. Returns 0 and changes nothing for a height of 0 or
// below (or a NULL record); otherwise lowers the height, then the time to the checkpoint time at
// or below the resulting height, sets pending, and returns 1.
static inline int BRScanFloorLowerTo(BRScanFloor *floor, int64_t height, const BRCheckPoint *checkpoints, size_t count)
{
    if (! floor || height <= 0) return 0;
    floor->height = BRScanFloorLower(floor->height, height);
    floor->time = BRScanFloorLower(floor->time, BRScanFloorCheckpointTimeAtOrBelow(checkpoints, count, floor->height));
    floor->pending = 1;
    return 1;
}

// DISCARDED CACHE: carry into the record what a discarded transaction cache held. minConfirmedHeight
// is the lowest real block height among its records (0 = none); minRecordTime the lowest non-zero
// record time among its records, confirmed or not (0 = none). pending is SET from the result.
static inline void BRScanFloorFromDiscardedCache(BRScanFloor *floor, int64_t minConfirmedHeight, int64_t minRecordTime,
                                                 const BRCheckPoint *checkpoints, size_t count)
{
    if (! floor) return;
    int64_t height = BRScanFloorLower(floor->height, minConfirmedHeight);
    int64_t checkpointTime = height > 0 ? BRScanFloorCheckpointTimeAtOrBelow(checkpoints, count, height) : 0;
    int64_t time = BRScanFloorLower(BRScanFloorLower(floor->time, minRecordTime), checkpointTime);
    floor->height = height;
    floor->time = time;
#ifdef SCAN_FLOOR_PENDING_RED
    // RED ARM SEAM (scan_floor_kat): pending OR'd in, so a run with no floor keeps an old request.
    floor->pending = floor->pending || height > 0 || time > 0;
#else
    floor->pending = height > 0 || time > 0;
#endif
}

// ANCHOR REQUEST: the next sync start carries the stored floor down to the wallet's anchor.
static inline void BRScanFloorRequestAtAnchor(BRScanFloor *floor)
{
    if (floor) floor->pending = 1;
}

// APPLIED: the record was carried into the stored floor. The height and pending go; the time stays.
static inline void BRScanFloorApplied(BRScanFloor *floor)
{
    if (! floor) return;
    floor->height = 0;
    floor->pending = 0;
}

// FORGET: a different wallet. The whole record goes.
static inline void BRScanFloorForget(BRScanFloor *floor)
{
    if (! floor) return;
    floor->height = 0;
    floor->time = 0;
    floor->pending = 0;
}

// What the sync start does with the record (Android's FloorHintStep). Nothing is written when
// setBirth and removeBirth are both 0; the record is applied (BRScanFloorApplied) only when clearHint.
typedef struct {
    int setBirth;          // store `birth` as the stored floor
    int64_t birth;         // the floor to store (positive), when setBirth; else 0
    int removeBirth;       // remove the stored floor (the scan start falls back to the wallet birth)
    int clearHint;         // the record is applied: BRScanFloorApplied
    int anchorAboveHint;   // the anchor is still above the record's height: keep it, and say so
} BRScanFloorStep;

// SYNC-START STEP. walletLoaded: a wallet is loaded (otherwise the anchor is meaningless). anchor:
// the loaded wallet's header anchor (0 = genesis). The stored floor is read only when
// hasPersistedBirth. floorHeight and floorPending are the record's.
static inline BRScanFloorStep BRScanFloorHintStep(int walletLoaded, int64_t anchor, int hasPersistedBirth,
                                                  int64_t persistedBirth, int64_t floorHeight, int floorPending)
{
    BRScanFloorStep step = { 0, 0, 0, 0, 0 };

    if ((floorHeight <= 0 && ! floorPending) || ! walletLoaded) return step;
#ifdef SCAN_FLOOR_STEP_RED
    // RED ARM SEAM (scan_floor_kat): no wait for the anchor; a stored floor is set to an anchor
    // above the record's height, and the record is dropped.
#else
    if (floorHeight > 0 && anchor > floorHeight) {
        step.anchorAboveHint = 1;
        return step;
    }
#endif
    step.clearHint = 1;
    if (! hasPersistedBirth) {
        if (anchor > 0) { step.setBirth = 1; step.birth = anchor; }
        return step;
    }
    if (persistedBirth <= anchor) return step;
    if (anchor > 0) { step.setBirth = 1; step.birth = anchor; }
    else step.removeBirth = 1;
    return step;
}

// RESTORE TIME: the creation time handed to the wallet rebuilt from the stored seed. stored: the
// stored creation time (0 or below = none stored). floorTime: the record's time (0 or below = none).
static inline int64_t BRScanFloorRestoreCreationTime(int64_t stored, int64_t floorTime)
{
    int64_t base = stored > 0 ? stored : BR_SCAN_FLOOR_DEFAULT_RESTORE_CREATION_TIME;
#ifdef SCAN_FLOOR_RESTORE_RED
    // RED ARM SEAM (scan_floor_kat): the creation time raised to the floor time, anchoring the
    // headers above history the record says is there.
    return floorTime > 0 ? floorTime : base;
#else
    return (floorTime > 0 && floorTime < base) ? floorTime : base;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRScanFloor_h
