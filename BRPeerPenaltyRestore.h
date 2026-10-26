//
//  BRPeerPenaltyRestore.h
//
//  The ONE way to restore a persisted peer-penalty set into a new manager: lapsed
//  entries dropped (BRPeerPenaltyDeserialize), the peer CANON exempt (BRPeerCanon.h),
//  at most BR_PEER_PENALTY_RESTORE_MAX entries.
//
//  Why the canon is exempt: a penalty restored against the peers the wallet must reach
//  before it has any peers at all is the on-ramp to the 0-peer dead wedge
//  (BRPeerPenalty.h, BRPeerPenaltyDropExempt). Until 2026-10 this composition lived in
//  the Android JNI bridge (jni_peer.c, _loadPenaltiesExceptPriority), an Android-only
//  compilation unit the iOS XCFramework does not contain. A platform restoring the
//  stored blob as-is would dial a different set of peers after every cold start.
//
//  The decision of WHETHER to store or clear a freshly probed blob is the sibling
//  header BRPeerPenaltyPersist.h; this one is the restore half.
//
//  Host KAT: digibytewallet-android native/src/test/host/peer_penalty_restore_kat/.
//  Header-only, static inline; no locking of its own.
//

#ifndef BRPeerPenaltyRestore_h
#define BRPeerPenaltyRestore_h

#include "BRPeerPenalty.h"
#include "BRPeerCanon.h"
#include "BRPeerManager.h"
#include "BRNetwork.h"
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// At most this many entries carry over a restart (the manager itself holds up to 256).
// The same bound the JNI bridge used (PEER_PENALTY_RESTORE_MAX).
#define BR_PEER_PENALTY_RESTORE_MAX 32u
#define BR_PEER_PENALTY_RESTORE_BLOB_MAX \
    (BR_PEER_PENALTY_HEADER_BYTES + BR_PEER_PENALTY_RESTORE_MAX * BR_PEER_PENALTY_ENTRY_BYTES)

// Pure: from a stored blob, writes to out the blob that should be restored -- live
// entries only, none against the canon of the given network. Returns bytes written, or
// 0 when there is nothing to restore (or out is too small; never a truncated blob).
// exemptDropped, if not NULL, receives how many live entries were dropped as canon.
static inline size_t BRPeerPenaltyRestoreBlob(const uint8_t *blob, size_t blobLen, time_t now, int testnet,
                                              uint8_t *out, size_t outLen, size_t *exemptDropped)
{
    UInt128 addrs[BR_PEER_PENALTY_RESTORE_MAX];
    uint16_t ports[BR_PEER_PENALTY_RESTORE_MAX];
    time_t until[BR_PEER_PENALTY_RESTORE_MAX];
    UInt128 exempt[BR_PEER_CANON_MAX_COUNT];
    size_t count, kept, exemptCount;

    if (exemptDropped) *exemptDropped = 0;
    count = BRPeerPenaltyDeserialize(blob, blobLen, now, addrs, ports, until, BR_PEER_PENALTY_RESTORE_MAX);
    if (count == 0) return 0;

#ifdef PEER_PENALTY_RESTORE_CANON_UNFIXED
    // RED-gate shape only: the blob restored as-is, the canon NOT exempt. Never defined
    // in a production build.
    (void)exempt; (void)testnet;
    exemptCount = 0;
    kept = count;
#else
    exemptCount = BRPeerCanonAddrs(testnet, exempt, BR_PEER_CANON_MAX_COUNT);
    kept = BRPeerPenaltyDropExempt(addrs, ports, until, count, exempt, exemptCount);
#endif
    if (exemptDropped) *exemptDropped = count - kept;
    if (kept == 0) return 0;
    return BRPeerPenaltySerialize(addrs, ports, until, kept, now, out, outLen);
}

// Restores a stored penalty blob into manager: BRPeerPenaltyRestoreBlob for the current
// network (BRNetworkIsTestnet), then BRPeerManagerLoadPenalties. Call once, after the
// manager is built and before connecting. Returns the number of entries restored.
static inline size_t BRPeerManagerRestorePenalties(BRPeerManager *manager, const uint8_t *blob, size_t blobLen,
                                                   size_t *exemptDropped)
{
    uint8_t filtered[BR_PEER_PENALTY_RESTORE_BLOB_MAX];
    size_t written = BRPeerPenaltyRestoreBlob(blob, blobLen, time(NULL), BRNetworkIsTestnet(),
                                              filtered, sizeof(filtered), exemptDropped);

    if (written == 0) return 0;
    return BRPeerManagerLoadPenalties(manager, filtered, written);
}

#ifdef __cplusplus
}
#endif

#endif // BRPeerPenaltyRestore_h
