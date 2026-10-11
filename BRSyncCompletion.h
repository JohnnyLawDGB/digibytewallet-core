//
//  BRSyncCompletion.h
//
//  When the wallet may count itself synced ("has synced"): the moment the platform persists its
//  transaction checkpoint, stops treating the sync as unfinished, and (on Android) lets the next
//  launch resume near the tip instead of the birth floor. Declaring it early is how payments go
//  missing while the screen says the balance is final, so both platforms take the rule from here.
//  Until 2026-10 it lived in Kotlin (SyncService's keepalive loop and onSyncComplete, with
//  shouldMarkSynced in CfRestorePreflight.kt).
//
//  Compact filters only: the header chain races ahead of the filter SCAN (the paced convoy holds
//  it a window ahead on purpose), so the header tip alone is never enough. Measured on a Note 8,
//  2026-08-02: complete was declared at the header tip with 60 817 blocks never scanned.
//
//  The poll (BRSyncCompletionPollStep, every keepalive tick while not yet synced, 10 s):
//    at the real tip = the header height at or past the chain's newest checkpoint (a cohort of
//    stale peers reporting a low tip is not the tip), within BR_SYNC_HEADER_TIP_SLACK of the
//    peers' estimate, and the scan caught up: the scan frontier known (0 is "unknown", never
//    "caught up") and its last scanned height (frontier - 1) within BR_SYNC_CF_TIP_SLACK of the
//    estimate. BR_SYNC_TIP_GRACE_POLLS consecutive real-tip polls (with height and estimate known)
//    may mark the wallet synced; any other poll starts the count again.
//  The callback (BRSyncCompletionOnSyncStopped, the core's sync-complete callback): not below the
//    newest checkpoint, and the scan within BR_SYNC_CF_TIP_SLACK of the HEADER height. (As Android:
//    a header height of 0 passes both checks.)
//  The commit (BRSyncCompletionMayCommit): defer only while ledger state is held that has not
//    reached disk (a "synced" that outlives its scan ledger costs a full re-sync next launch); a
//    wallet with nothing pending must never be held back, or it would sync forever.
//  If the platform then fails to persist its checkpoint, BRSyncCompletionCheckpointFailed starts
//  the poll count again.
//
//  Host KAT: digibytewallet-android native/src/test/host/sync_completion_kat/ (the poll and
//  callback rules from SyncService, and CfRestorePreflightTest's shouldMarkSynced cases).
//  Header-only, static inline.
//

#ifndef BRSyncCompletion_h
#define BRSyncCompletion_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_SYNC_TIP_GRACE_POLLS     3       // consecutive keepalive polls (10 s each) at the real tip
#define BR_SYNC_HEADER_TIP_SLACK    5LL     // headers within this many blocks of the peers' estimate
#define BR_SYNC_CF_TIP_SLACK        10LL    // the last scanned height within this many of the tip

typedef struct {
    int atTipPolls;     // consecutive real-tip polls (zero it at process start)
} BRSyncCompletionState;

// One poll; latestCheckpoint is the chain's newest checkpoint height (the core's table). Returns 1
// when this poll may mark the wallet synced (the platform then commits, see MayCommit).
static inline int BRSyncCompletionPollStep(BRSyncCompletionState *s, int64_t height, int64_t estimatedHeight,
                                           int64_t scanFrontier, int64_t latestCheckpoint)
{
#ifdef SYNC_COMPLETION_RED
    // RED ARM SEAM (sync_completion_kat): the header tip alone (the 2026-08-02 Note 8 bug).
    int scanAtTip = 1;
    (void)scanFrontier;
#else
    int scanAtTip = scanFrontier > 0 && scanFrontier - 1 >= estimatedHeight - BR_SYNC_CF_TIP_SLACK;
#endif
    int atRealTip = height >= latestCheckpoint && height >= estimatedHeight - BR_SYNC_HEADER_TIP_SLACK && scanAtTip;

    if (! atRealTip) s->atTipPolls = 0;
    if (height > 0 && estimatedHeight > 0 && atRealTip) {
        s->atTipPolls++;
        return s->atTipPolls >= BR_SYNC_TIP_GRACE_POLLS;
    }
    return 0;
}

// The platform could not persist its transaction checkpoint: keep the sync unfinished and count
// the real-tip polls again.
static inline void BRSyncCompletionCheckpointFailed(BRSyncCompletionState *s)
{
    s->atTipPolls = 0;
}

// The core's sync-complete callback fired: may it mark the wallet synced?
static inline int BRSyncCompletionOnSyncStopped(int64_t height, int64_t scanFrontier, int64_t latestCheckpoint)
{
    if (height > 0 && height < latestCheckpoint) return 0;          // stale peers below the checkpoint floor
#ifndef SYNC_COMPLETION_RED
    if (height > 0 && (scanFrontier <= 0 || scanFrontier - 1 < height - BR_SYNC_CF_TIP_SLACK)) return 0;
#endif
    return 1;
}

// Android's shouldMarkSynced: hold the commit only while un-durable ledger state would be lost.
static inline int BRSyncCompletionMayCommit(int hasPendingLedger, int ledgerDurable)
{
    return (hasPendingLedger && ! ledgerDurable) ? 0 : 1;
}

#ifdef __cplusplus
}
#endif

#endif // BRSyncCompletion_h
