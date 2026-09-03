//
//  BRRecreateSequence.h
//
//  The order a mid-session peer-manager recreate must run in.
//
//  A recovery path that simply calls forceReconnect() then startSync() rebuilds
//  the native manager from the STALE cold-start g_savedBlocks -- populated once
//  at launch and never refreshed from the advancing chain -- so
//  manager->lastBlock floors to the wallet birth checkpoint and auto-fetch
//  re-arms at cf_birth_height. Measured on a Note 8: a scan at 24,052,509
//  dropped to 22,650,000 and spent ~6 hours climbing back.
//
//  The fix is sequencing rather than new machinery, and all three parts are
//  load-bearing:
//
//    0. flush live state to disk -- the steps below read the last PERSISTED
//       snapshot, and the rebuild destroys whatever was only in memory;
//    1. refresh the near-tip window -- BEFORE the rebuild, because the rebuild
//       consumes it;
//    2. mark the manager for recreate;
//    3. rebuild it;
//    4. restore the CF ledger and snap the resume cursor -- AFTER the new
//       manager exists.
//
//  Parts 1+2 without part 0 leave a one-save-interval give-back charged on every
//  recovery.
//
//  ## Why this header is a SPECIFICATION, not an executor
//
//  BRCFRecoveryPolicy.h and BRPublishOutcome.h are pure functions, so they moved
//  wholesale. This one cannot, and porting it mechanically would do harm.
//
//  The Kotlin original (core/sync/RecreateSequence.kt) takes five `suspend`
//  lambdas. Re-expressing that in C as a struct of function pointers would mean
//  C calling back into Kotlin, and a coroutine step cannot be driven from a C
//  callback without blocking the calling thread inside JNI. That is precisely the
//  hazard KeepaliveHealth.GIVE_UP_WEDGED exists to describe: Job.cancel() cannot
//  interrupt a thread inside a JNI call, so the thread is held indefinitely and
//  the shared Dispatchers.Default pool starves. Swift concurrency has the same
//  problem in a different dialect.
//
//  So what is shared here is the KNOWLEDGE -- the order, the names, and the
//  every-step-runs rule -- as data. Each platform keeps its own executor and its
//  own concurrency model, and asks this header what the order is instead of
//  hardcoding it. A reorder on one platform then fails a test rather than
//  silently costing a user six hours.
//
//  Header-only, no BRPeerManager, no locking, no I/O; testable standalone on the
//  host (see native/src/test/host/recreate_sequence_kat/).
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

#ifndef BRRecreateSequence_h
#define BRRecreateSequence_h

#ifdef __cplusplus
extern "C" {
#endif

// The steps, in the order they must run. The numeric values ARE the order --
// they are not arbitrary tags, and reordering them changes behaviour.
typedef enum {
    // Both restore steps below read the last PERSISTED snapshot, while the
    // freshest state is still in memory (the saved-blocks window until its save
    // boundary, the CF scan ledger until the coalesced writer's next tick).
    BRRecreateStepFlushPersistedState = 0,

    // BEFORE the rebuild: the rebuild consumes the near-tip window.
    BRRecreateStepReloadBlocksNearTip = 1,

    // Marks the manager for recreate.
    BRRecreateStepForceReconnect = 2,

    // Rebuilds it.
    BRRecreateStepStartSync = 3,

    // AFTER the new manager exists.
    BRRecreateStepRestoreLedgerAndSnap = 4,
} BRRecreateStep;

#define BR_RECREATE_STEP_COUNT 5

// The step at an ordinal position, or -1 if out of range. Call sites should
// iterate this rather than hardcoding the order.
static inline int BRRecreateStepAt(int index)
{
#ifdef RECREATE_RELOAD_AFTER_REBUILD_UNFIXED
    // RED-gate shape only: the pre-fix ordering, with the near-tip reload moved
    // AFTER the rebuild that consumes it. This is the shape that cost ~6 hours
    // on a Note 8. Never defined in a production build.
    {
        static const int unfixed[BR_RECREATE_STEP_COUNT] = {
            BRRecreateStepFlushPersistedState,
            BRRecreateStepForceReconnect,
            BRRecreateStepStartSync,
            BRRecreateStepReloadBlocksNearTip,
            BRRecreateStepRestoreLedgerAndSnap,
        };
        if (index < 0 || index >= BR_RECREATE_STEP_COUNT) return -1;
        return unfixed[index];
    }
#else
    if (index < 0 || index >= BR_RECREATE_STEP_COUNT) return -1;
    return index;   // the enum values are the order
#endif
}

// Stable identifier for a step, used to label a partial recovery. Matches the
// prefixes RecreateSequence.kt writes into its failure list, so a log line means
// the same thing on both platforms. NULL for an unknown step.
static inline const char *BRRecreateStepName(BRRecreateStep step)
{
    switch (step) {
        case BRRecreateStepFlushPersistedState:  return "flush";
        case BRRecreateStepReloadBlocksNearTip:  return "reload";
        case BRRecreateStepForceReconnect:       return "forceReconnect";
        case BRRecreateStepStartSync:            return "startSync";
        case BRRecreateStepRestoreLedgerAndSnap: return "restoreLedger";
        default:                                 return 0;
    }
}

// Whether the executor must continue after this step fails.
//
// Always true, and deliberately expressed as a function rather than a comment:
// these paths run during recovery, when something has already gone wrong.
// Aborting halfway would leave the wallet with a manager marked for rebuild and
// never rebuilt -- a worse state than the one being recovered from. A future
// step that wants abort-on-failure has to change this and face the KAT.
static inline int BRRecreateContinuesAfterFailure(BRRecreateStep step)
{
    (void)step;
    return 1;
}

// The ordinal position of a step in the sequence, or -1 if it does not appear.
static inline int BRRecreateIndexOf(BRRecreateStep step)
{
    int i;
    for (i = 0; i < BR_RECREATE_STEP_COUNT; i++) {
        if (BRRecreateStepAt(i) == (int)step) return i;
    }
    return -1;
}

// Whether step `earlier` actually runs before step `later`.
//
// Deliberately derived from BRRecreateStepAt rather than from the enum values.
// Comparing the enum values would be self-satisfying: they are the declared
// order, so the comparison would hold no matter what the sequence actually does,
// and a reordered sequence would still "pass". Asking the sequence is what makes
// this an assertion about behaviour instead of about a typedef.
static inline int BRRecreateMustPrecede(BRRecreateStep earlier, BRRecreateStep later)
{
    int a = BRRecreateIndexOf(earlier);
    int b = BRRecreateIndexOf(later);
    if (a < 0 || b < 0) return 0;
    return a < b;
}

// Whether a step may be skipped by a call site. None may: "no default -- skipping
// the flush must be a choice a call site writes down, not one it inherits."
static inline int BRRecreateStepIsSkippable(BRRecreateStep step)
{
    (void)step;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRRecreateSequence_h
