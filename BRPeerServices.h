#ifndef BRPeerServices_h
#define BRPeerServices_h

#include <stdint.h>
#include "BRPeer.h"         // SERVICES_NODE_BLOOM / _NETWORK / _COMPACT_FILTERS
#include "BRPeerManager.h"  // BRSyncMode (BR_SYNC_MODE_BLOOM_ONLY)

// Is a peer's advertised service set usable for the current sync mode?
// A peer is usable if it serves bloom, OR — when the wallet is running
// BIP157/158 (any mode other than BLOOM_ONLY) — if it serves compact filters.
//
// This is the sync-mode-gated generalization of the former testnet-only
// compact-filter exception at the connect accept gate. It lets compact-filter-only
// nodes — modern DigiByte Core ships bloom OFF by default — be accepted on mainnet
// whenever the wallet is not in the legacy bloom-only mode.
static inline int BRPeerServicesAllowedForSyncMode(uint64_t services, int syncMode)
{
    if ((services & SERVICES_NODE_BLOOM) == SERVICES_NODE_BLOOM) return 1;
    if (syncMode != BR_SYNC_MODE_BLOOM_ONLY &&
        (services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS) return 1;
    return 0;
}

#endif // BRPeerServices_h
