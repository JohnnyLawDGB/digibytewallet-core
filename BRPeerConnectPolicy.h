#ifndef BRPeerConnectPolicy_h
#define BRPeerConnectPolicy_h

#include <stddef.h>

static inline int BRPeerManagerNeedsTopUp(size_t previousTarget, size_t target,
                                          size_t occupiedSlots)
{
#ifdef PEER_TOPUP_INCREASE_ONLY_UNFIXED
    return target > previousTarget;
#else
    (void)previousTarget;
    return occupiedSlots < target;
#endif
}

#endif
