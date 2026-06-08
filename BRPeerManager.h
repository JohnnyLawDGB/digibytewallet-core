//
//  BRPeerManager.h
//
//  Created by Aaron Voisine on 9/2/15.
//  Copyright (c) 2015 breadwallet LLC.
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

#ifndef BRPeerManager_h
#define BRPeerManager_h

#include "BRPeer.h"
#include "BRMerkleBlock.h"
#include "BRTransaction.h"
#include "BRWallet.h"
#include "BRChainParams.h"
#include "BRCompactFilterChain.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_MAX_CONNECTIONS 5

/* defines, how many blocks to be held in sqlite DB */
#define SAVE_BLOCK_COUNT 300
#define SAVE_BLOCK_INTERVAL 4000
    
/* OPTIONS FOR CLEARING MEMORY */
/*
Remarks:
    The authors of the original breadwallet core ensure that the application
    contains at least 2016 blocks, until a difficulty transition block gets relayed.
    Since Digibyte makes use of DigiShield (or more specifically MultiShield), on each and
    every block there occurs a difficulty transition.
    We need to keep some blocks in memory in case of forks, to walk the chain backwards.
    To clear memory we have introduced a trigger value: CLEAR_MEM_BLOCKS_COUNT_TRIGGER.
    If the BRPeerManager instance contains more than CLEAR_MEM_BLOCKS_COUNT_TRIGGER blocks in 'blocks',
    we trigger the memory cleanup. The first CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN blocks will be freed up.
    Note that we have to remove the tail, that is, we have to walk back the chain, until we reach the tail,
    then free up the remaining blocks.
 
    CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN is at least the SAVE_BLOCK_COUNT
        plus a reserve of CLEAR_MEM_BLOCKS_RESERVE_COUNT blocks.
*/
#define CLEAR_MEM_BLOCKS_COUNT_TRIGGER 5000
#define CLEAR_MEM_BLOCKS_RESERVE_COUNT 500
#define CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN (CLEAR_MEM_BLOCKS_COUNT_TRIGGER - SAVE_BLOCK_COUNT - CLEAR_MEM_BLOCKS_RESERVE_COUNT)

/* BIP 158: block headers at/above (cfTip - this margin) are never pruned, so
   the cfheaders driver can always walk prevBlock links back to its next batch's
   stop height. Without this, pruning frees the deficit region and cfheaders
   stalls forever with "no block hash for height H". In steady state cfTip
   tracks blockTip so the retained span collapses to the normal tail; it only
   expands transiently while a large cfTip deficit is being recovered. */
#define CLEAR_MEM_CF_RETENTION_MARGIN 144

/* BIP 158 continuity-failure recovery. If this many DISTINCT peers fail the
   cfheaders continuity check against our current tip since the last successful
   append, our chain is the outlier (it diverged via unverified TOFU) — re-anchor
   instead of marking the (honest) peers misbehavin'. Bounded per session so a
   persistently-divergent peer can't loop forever. */
#define CF_CONTINUITY_REANCHOR_K   2
#define CF_CONTINUITY_REANCHOR_MAX 3
    
/* Readability constants */
#define ADD_TO_SAVED_BLOCKS 0
#define REPLACE_SAVED_BLOCKS 1

// BIP 158 sync mode. Controls which peer protocols the manager uses to find
// wallet-relevant transactions. Set via BRPeerManagerSetSyncMode before
// BRPeerManagerConnect; changes after connect take effect on the next sync.
typedef enum {
    BR_SYNC_MODE_BLOOM_ONLY = 0,            // legacy BIP 37 SPV (default)
    BR_SYNC_MODE_COMPACT_FILTERS_ONLY = 1,  // BIP 157/158 only
    BR_SYNC_MODE_BOTH = 2,                  // both paths in parallel
} BRSyncMode;

typedef struct BRPeerManagerStruct BRPeerManager;

// returns a newly allocated BRPeerManager struct that must be freed by calling BRPeerManagerFree()
BRPeerManager* BRPeerManagerNew(const BRChainParams* params, BRWallet* wallet, uint32_t earliestKeyTime,
                                BRMerkleBlock* blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);

// Extension of the above. Accepts a custom initial block
BRPeerManager* BRPeerManagerNewEx(const BRChainParams* params, BRWallet* wallet, uint32_t earliestKeyTime,
                                  BRMerkleBlock* blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startSyncFrom);
    
// not thread-safe, set callbacks once before calling BRPeerManagerConnect()
// info is a void pointer that will be passed along with each callback call
// void syncStarted(void *) - called when blockchain syncing starts
// void syncStopped(void *, int) - called when blockchain syncing stops, error is an errno.h code
// void txStatusUpdate(void *) - called when transaction status may have changed such as when a new block arrives
// void saveBlocks(void *, int, BRMerkleBlock *[], size_t) - called when blocks should be saved to the persistent store
// - if replace is true, remove any previously saved blocks first
// void savePeers(void *, int, const BRPeer[], size_t) - called when peers should be saved to the persistent store
// - if replace is true, remove any previously saved peers first
// int networkIsReachable(void *) - must return true when networking is available, false otherwise
// void threadCleanup(void *) - called before a thread terminates to faciliate any needed cleanup
void BRPeerManagerSetCallbacks(BRPeerManager *manager, void *info,
                               void (*syncStarted)(void *info),
                               void (*syncStopped)(void *info, int error),
                               void (*txStatusUpdate)(void *info),
                               void (*saveBlocks)(void *info, int replace, BRMerkleBlock *blocks[], size_t blocksCount, uint64_t* memIntegrityCheck),
                               void (*savePeers)(void *info, int replace, const BRPeer peers[], size_t peersCount),
                               int (*networkIsReachable)(void *info),
                               void (*threadCleanup)(void *info));

// specifies a single fixed peer to use when connecting to the bitcoin network
// set address to UINT128_ZERO to revert to default behavior
void BRPeerManagerSetFixedPeer(BRPeerManager *manager, UInt128 address, uint16_t port);

// add a peer to the live candidate pool the manager picks from on the next
// BRPeerManagerConnect cycle. Idempotent — if the address+port pair is already
// present, this is a no-op. Returns 1 if the peer was newly added, 0 if it was
// already known. Use this to feed runtime-discovered peers (e.g. from a seeder
// API) into a manager that's already been built — passing them through the
// init-time savedPeers blob only works once and is lost on next connect cycle.
int BRPeerManagerAddPeer(BRPeerManager *manager, UInt128 address, uint16_t port,
                          uint64_t services);

// sets a custom start block
void BRPeerManagerSetStartBlock(BRPeerManager* manager, BRMerkleBlock* start);
    
// current connect status
BRPeerStatus BRPeerManagerConnectStatus(BRPeerManager *manager);

// connect to bitcoin peer-to-peer network (also call this whenever networkIsReachable() status changes)
void BRPeerManagerConnect(BRPeerManager *manager);

// disconnect from bitcoin peer-to-peer network (may cause syncFailed(), saveBlocks() or savePeers() callbacks to fire)
void BRPeerManagerDisconnect(BRPeerManager *manager);

// rescans blocks and transactions after earliestKeyTime (a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter)
void BRPeerManagerRescan(BRPeerManager *manager);

// the (unverified) best block height reported by connected peers
uint32_t BRPeerManagerEstimatedBlockHeight(BRPeerManager *manager);

// current proof-of-work verified best block height
uint32_t BRPeerManagerLastBlockHeight(BRPeerManager *manager);

// current proof-of-work verified best block timestamp (time interval since unix epoch)
uint32_t BRPeerManagerLastBlockTimestamp(BRPeerManager *manager);

// current network sync progress from 0 to 1
// startHeight is the block height of the most recent fully completed sync
double BRPeerManagerSyncProgress(BRPeerManager *manager, uint32_t startHeight);

// returns the number of currently connected peers
size_t BRPeerManagerPeerCount(BRPeerManager *manager);

// description of the peer most recently used to sync blockchain data
const char *BRPeerManagerDownloadPeerName(BRPeerManager *manager);

// publishes tx to bitcoin network (do not call BRTransactionFree() on tx afterward)
void BRPeerManagerPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                            void (*callback)(void *info, int error));

// number of connected peers that have relayed the given unconfirmed transaction
size_t BRPeerManagerRelayCount(BRPeerManager *manager, UInt256 txHash);

// ----------- BIP 158 compact-filter sync (opt-in) -----------
//
// The functions below are inert until BRPeerManagerSetSyncMode is called with
// a mode other than BR_SYNC_MODE_BLOOM_ONLY. With BLOOM_ONLY (the default)
// the manager behaves exactly as before.
//
// Lifecycle for a filter-sync-enabled wallet:
//   1) BRPeerManagerSetSyncMode(manager, BR_SYNC_MODE_COMPACT_FILTERS_ONLY)
//   2) Either pass a previously persisted chain via SetCompactFilterChain
//      (deserialize from SharedPreferences) or skip — the manager will lazily
//      create one anchored at startHeight=0 / UINT256_ZERO on the first
//      cfheaders batch.
//   3) Register saveFilterHeaders so the manager can persist progress every
//      time it successfully extends the chain.
//   4) BRPeerManagerConnect — peers advertising NODE_COMPACT_FILTERS will be
//      driven to send cfheaders/cfheaders/cfcheckpt; the chain accumulator
//      validates continuity and the manager misbehavin's any peer whose
//      batch breaks the chain.

// Set the sync mode. Must be called before BRPeerManagerConnect, or before
// the next BRPeerManagerRescan. No-op if the same mode is already set.
void BRPeerManagerSetSyncMode(BRPeerManager *manager, BRSyncMode mode);

BRSyncMode BRPeerManagerGetSyncMode(BRPeerManager *manager);

// Mid-run fallback: flips to BLOOM_ONLY and immediately pushes a bloom
// filterload to every connected peer. Use when the BIP158 watchdog
// determines filter peers are unreachable. After this returns, the
// wallet receives txs via merkleblocks/bloom; cfheaders/cfilters paths
// stay inert until the next mode change.
void BRPeerManagerFallbackToBloom(BRPeerManager *manager);

// Current compact-filter chain tip height (0 if no chain yet). Used by
// the watchdog to detect "filter peers connected but not making progress."
uint32_t BRPeerManagerCFChainTipHeight(BRPeerManager *manager);

// Re-anchor the compact-filter chain at the block floor when cfTip is stuck
// below the downloaded chain (legacy deficit). Returns 1 if re-anchored.
int BRPeerManagerReanchorCompactFilterChainAtFloor(BRPeerManager *manager);

// Provide a previously persisted filter-header chain. The manager takes
// ownership of the chain pointer; do not free it. Passing NULL clears any
// existing chain. Must be called before BRPeerManagerConnect.
void BRPeerManagerSetCompactFilterChain(BRPeerManager *manager,
                                         BRCompactFilterChain *chain);

// Borrowed pointer into the manager's chain (do NOT free). NULL when sync
// mode is BLOOM_ONLY or no batches have been received yet.
const BRCompactFilterChain *BRPeerManagerGetCompactFilterChain(BRPeerManager *manager);

// Persistence hook. Called from inside the manager lock after every
// successful BRCompactFilterChainAppend, with the chain pointer that was
// updated. The callback may serialize it via BRCompactFilterChainSerialize.
// Pass NULL to clear.
void BRPeerManagerSetSaveFilterHeaders(BRPeerManager *manager, void *info,
                                       void (*saveFilterHeaders)(void *info,
                                                                  const BRCompactFilterChain *chain));

// Request cfilters for the inclusive range [startHeight, stopHeight] from
// any filter-capable peer that is currently connected. Caps the range at
// MAX_CFILTERS_RESULTS; if the requested range is larger, only the first
// MAX_CFILTERS_RESULTS blocks are requested and the caller must call again
// with the remainder.
//
// Returns the number of blocks actually requested (0 if no eligible peer
// is connected, or both endpoints fall outside the in-memory block window).
size_t BRPeerManagerRequestCompactFilters(BRPeerManager *manager,
                                          uint32_t startHeight, uint32_t stopHeight);

// Enable automatic cfilter requesting. Once enabled, every successful
// cfheaders batch triggers a cfilter request for the new range capped at
// MAX_CFILTERS_RESULTS, starting from max(startHeight, lastRequested+1).
// "startHeight" should be the wallet's birth height (height of earliest
// block that could contain a wallet-relevant tx). Pass 0 to scan from
// genesis.
//
// SPV wallets only persist a window of block headers near the current
// tip, so passing a startHeight below that window would defer the first
// cfheaders batch forever (the driver can't produce a stopHash for an
// unknown block). The implementation snaps startHeight up to a height it
// can resolve, biased toward lastBlock. Use BRPeerManagerGetAutoFetchCFiltersStart
// to read back the value the manager actually committed to.
//
// Disable resets the auto-fetch cursor so the next Enable starts fresh.
void BRPeerManagerEnableAutoCompactFilterFetch(BRPeerManager *manager, uint32_t startHeight);
void BRPeerManagerDisableAutoCompactFilterFetch(BRPeerManager *manager);
uint32_t BRPeerManagerGetAutoFetchCFiltersStart(BRPeerManager *manager);

// ----------- end BIP 158 opt-in -----------

// frees memory allocated for manager (call BRPeerManagerDisconnect() first if connected)
void BRPeerManagerFree(BRPeerManager *manager);
	
/*
 * The following two methods sync the blockchain beginning from startBlock.
 *
 * Usage: Create a custom merkle block and pass it to BPPeerManagerMainNetNewEx()
 *     BRMerkleBlock* test = BRMerkleBlockNew();
 *     test->blockHash = UInt256Reverse(uint256("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496"));
 *     test->height = 0;
 *     test->timestamp = 1389388394;
 *     test->target = 0x1e0ffff0;
 */

BRPeerManager* BPPeerManagerMainNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock);

BRPeerManager* BPPeerManagerTestNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock);
    
// function to create Peermanager under for the mainnet directly
BRPeerManager *BPPeerManagerMainNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);

// function to create Peermanager under for the testnet directly
BRPeerManager *BPPeerManagerTestNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount);


#ifdef __cplusplus
}
#endif

#endif // BRPeerManager_h
