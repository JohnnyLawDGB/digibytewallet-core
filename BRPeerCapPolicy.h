//
//  BRPeerCapPolicy.h
//
//  How many peers the wallet holds: the full set while catching up, three once it is stably at
//  the tip. A wallet at the tip receives about one block every 15 s, which a few peers serve
//  easily, and thousands of synced, idle wallets each pinning eight slots on the small shared
//  filter-node fleet is load the fleet does not need. The count goes back to full the moment the
//  wallet falls behind. Until 2026-10 this lived in Kotlin (SyncService.runPeerCapController).
//
//  The rule, every BR_PEER_CAP_POLL_MS:
//    - at the tip = the wallet has reached sync (sticky), the block tip is within
//      BR_PEER_CAP_TIP_DELTA of the peers' estimated height (both known), and it holds at least
//      BR_PEER_CAP_SYNCED_COUNT peers;
//    - the at-tip clock starts at the first at-tip poll and resets on any other;
//    - after BR_PEER_CAP_REDUCE_GRACE_MS at the tip, hold BR_PEER_CAP_SYNCED_COUNT; otherwise
//      hold PEER_MAX_CONNECTIONS.
//  The caller applies the count with BRPeerManagerSetMaxConnectCount EVERY poll: it no-ops at the
//  target and re-applies after a manager recreate (which resets to the full default). The manager
//  never drops the download peer or a pinned own-node.
//
//  Host KAT: digibytewallet-android native/src/test/host/peer_cap_kat/.
//  Header-only, static inline.
//

#ifndef BRPeerCapPolicy_h
#define BRPeerCapPolicy_h

#include "BRPeerManager.h"   // PEER_MAX_CONNECTIONS
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_PEER_CAP_POLL_MS          15000LL
#define BR_PEER_CAP_REDUCE_GRACE_MS  60000LL
#define BR_PEER_CAP_SYNCED_COUNT     3
#define BR_PEER_CAP_TIP_DELTA        25LL

// One poll. *syncedSinceMs is the caller's at-tip clock (start it at 0). Returns the peer count to
// hold.
static inline int BRPeerCapStep(int64_t *syncedSinceMs, int hasReachedSynced, int64_t blockTip,
                                int64_t estimatedHeight, int peerCount, int64_t nowMs)
{
    int atTip = hasReachedSynced && blockTip > 0 && estimatedHeight > 0 &&
                estimatedHeight - blockTip <= BR_PEER_CAP_TIP_DELTA && peerCount >= BR_PEER_CAP_SYNCED_COUNT;

    *syncedSinceMs = atTip ? (*syncedSinceMs == 0 ? nowMs : *syncedSinceMs) : 0;
#ifdef PEER_CAP_RED
    // RED ARM SEAM (peer_cap_kat): drop on the first at-tip poll, with no grace (flaps on every tip block).
    return atTip ? BR_PEER_CAP_SYNCED_COUNT : PEER_MAX_CONNECTIONS;
#else
    return (atTip && (int64_t)((uint64_t)nowMs - (uint64_t)*syncedSinceMs) >= BR_PEER_CAP_REDUCE_GRACE_MS)
        ? BR_PEER_CAP_SYNCED_COUNT : PEER_MAX_CONNECTIONS;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRPeerCapPolicy_h
