#ifndef BRPeerServices_h
#define BRPeerServices_h

#include <stdint.h>
#include "BRPeer.h"         // SERVICES_NODE_COMPACT_FILTERS / _NETWORK

// Is a peer's advertised service set usable for the current sync mode? The
// wallet is CF-only (bloom excised, 4.0.0) — a peer is usable iff it serves
// compact filters.
//
// `syncMode` is unused now that bloom is gone; kept as a parameter (rather than
// changing the signature) so callers don't need a lockstep edit — the enum
// itself still has 3 values for ABI reasons (see BRSyncMode).
static inline int BRPeerServicesAllowedForSyncMode(uint64_t services, int syncMode)
{
    (void)syncMode;
    return (services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS ? 1 : 0;
}

static inline int BRPeerShouldRequestMempool(uint64_t services, int compactFiltersOnly)
{
    return !compactFiltersOnly &&
           (services & SERVICES_NODE_BLOOM) == SERVICES_NODE_BLOOM ? 1 : 0;
}

#endif // BRPeerServices_h
