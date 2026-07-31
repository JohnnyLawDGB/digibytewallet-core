//
//  BRPeerManager.c
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

#include "BRPeerManager.h"
#include "BRSet.h"
#include "BRArray.h"
#include "BRInt.h"
#include "BRCompactFilterChain.h"
#include "BRCompactFilterCheckpoints.h"
#include "BRGCSFilter.h"
#include "BRWalletFilterElements.h"
#include "BRNetwork.h"
#include "BRPeerServices.h"
#include "BRPeerPenalty.h"
#include "BRPeerPin.h"
#include "BRPeerCFStatus.h"
#include "BRCFScanLedger.h"
#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PROTOCOL_TIMEOUT      20.0
#define MAX_CONNECT_FAILURES  20 // notify user of network problems after this many connect failures in a row
#define PEER_FLAG_SYNCED      0x01
#define PEER_FLAG_NEEDSUPDATE 0x02

// Session-scoped "don't re-dial this peer yet" penalty (churn fix). A peer
// rejected by _peerConnected as "node isn't synced" (BRPeerManager.c ~914)
// goes on this list so the filter-first dial loop (BRPeerManagerConnect,
// ~2448) skips it for PEER_PENALTY_SECONDS instead of immediately re-dialing
// the same still-behind peer every connect pass -- observed live as one
// peer dialed 122x in a tight loop while the wallet held 0 peers. Fixed-size
// ring buffer, not persisted across process restarts.
#define PEER_PENALTY_MAX     32
#define PEER_PENALTY_SECONDS (10*60) // 10 min; a genuinely-behind node is skipped this long

#define genesis_block_hash(params) UInt256Reverse((params)->checkpoints[0].hash)

#ifndef BITCOIN_TESTNET
#define BITCOIN_TESTNET 0
#endif

// Since many users experience data corruption issues on iOS, we
//  implement the following procedure in order to prevent the issues.
// We will pass 0xAAAAAAAAAAAAAAAA to the native side (iOS/android), which will then check its value before saving the blocks.
// Important: stackIntegrityCheck_val is marked as volatile memory in order to prevent the compiler from optimizing this variable to a constant.
// CORRECTED 2026-07-26: the memory corruption this canary was chasing was NOT an
// app-shutdown artifact ("iOS killing the C part first" — that story was wrong and
// misled diagnosis for years). It was a lock-release-then-use RACE: saveBlocks used
// to be handed LIVE pointers into manager->blocks AFTER manager->lock was released,
// and a concurrent peer thread's reorg (BRSetRemove + BRMerkleBlockFree) freed a
// block while the callback serialized it → heap-overflow / use-after-free. Fixed by
// serializing the blocks to bytes UNDER the lock (see _serializeSavedBlocks +
// _peerRelayedBlock) so no manager-owned pointer crosses the unlock. The canary is
// kept as belt-and-suspenders, but the real defect is closed at the source.
volatile uint64_t stackIntegrityCheck = 0xAAAAAAAAAAAAAAAA;

typedef struct {
    BRPeerManager *manager;
    const char *hostname;
    uint64_t services;
} BRFindPeersInfo;

typedef struct {
    BRPeer *peer;
    BRPeerManager *manager;
    UInt256 hash;
} BRPeerCallbackInfo;

typedef struct {
    BRTransaction *tx;
    void *info;
    void (*callback)(void *info, int error);
} BRPublishedTx;

typedef struct {
    UInt256 txHash;
    BRPeer *peers;
} BRTxPeerList;

// true if peer is contained in the list of peers associated with txHash
static int _BRTxPeerListHasPeer(const BRTxPeerList *list, UInt256 txHash, const BRPeer *peer)
{
    for (size_t i = array_count(list); i > 0; i--) {
        if (! UInt256Eq(list[i - 1].txHash, txHash)) continue;

        for (size_t j = array_count(list[i - 1].peers); j > 0; j--) {
            if (BRPeerEq(&list[i - 1].peers[j - 1], peer)) return 1;
        }
        
        break;
    }
    
    return 0;
}

// number of peers associated with txHash
static size_t _BRTxPeerListCount(const BRTxPeerList *list, UInt256 txHash)
{
    for (size_t i = array_count(list); i > 0; i--) {
        if (UInt256Eq(list[i - 1].txHash, txHash)) return array_count(list[i - 1].peers);
    }
    
    return 0;
}

// adds peer to the list of peers associated with txHash and returns the new total number of peers
static size_t _BRTxPeerListAddPeer(BRTxPeerList **list, UInt256 txHash, const BRPeer *peer)
{
    for (size_t i = array_count(*list); i > 0; i--) {
        if (! UInt256Eq((*list)[i - 1].txHash, txHash)) continue;
        
        for (size_t j = array_count((*list)[i - 1].peers); j > 0; j--) {
            if (BRPeerEq(&(*list)[i - 1].peers[j - 1], peer)) return array_count((*list)[i - 1].peers);
        }
        
        array_add((*list)[i - 1].peers, *peer);
        return array_count((*list)[i - 1].peers);
    }

    array_add(*list, ((BRTxPeerList) { txHash, NULL }));
    array_new((*list)[array_count(*list) - 1].peers, PEER_MAX_CONNECTIONS);
    array_add((*list)[array_count(*list) - 1].peers, *peer);
    return 1;
}

// removes peer from the list of peers associated with txHash, returns true if peer was found
static int _BRTxPeerListRemovePeer(BRTxPeerList *list, UInt256 txHash, const BRPeer *peer)
{
    for (size_t i = array_count(list); i > 0; i--) {
        if (! UInt256Eq(list[i - 1].txHash, txHash)) continue;
        
        for (size_t j = array_count(list[i - 1].peers); j > 0; j--) {
            if (! BRPeerEq(&list[i - 1].peers[j - 1], peer)) continue;
            array_rm(list[i - 1].peers, j - 1);
            return 1;
        }
        
        break;
    }
    
    return 0;
}

// comparator for sorting peers by timestamp, most recent first
inline static int _peerTimestampCompare(const void *peer, const void *otherPeer)
{
    if (((const BRPeer *)peer)->timestamp < ((const BRPeer *)otherPeer)->timestamp) return 1;
    if (((const BRPeer *)peer)->timestamp > ((const BRPeer *)otherPeer)->timestamp) return -1;
    return 0;
}

// returns a hash value for a block's prevBlock value suitable for use in a hashtable
inline static size_t _BRPrevBlockHash(const void *block)
{
    return (size_t)((const BRMerkleBlock *)block)->prevBlock.u32[0];
}

// true if block and otherBlock have equal prevBlock values
inline static int _BRPrevBlockEq(const void *block, const void *otherBlock)
{
    return UInt256Eq(((const BRMerkleBlock *)block)->prevBlock, ((const BRMerkleBlock *)otherBlock)->prevBlock);
}

// returns a hash value for a block's height value suitable for use in a hashtable
inline static size_t _BRBlockHeightHash(const void *block)
{
    // (FNV_OFFSET xor height)*FNV_PRIME
    return (size_t)((0x811C9dc5 ^ ((const BRMerkleBlock *)block)->height)*0x01000193);
}

// true if block and otherBlock have equal height values
inline static int _BRBlockHeightEq(const void *block, const void *otherBlock)
{
    return (((const BRMerkleBlock *)block)->height == ((const BRMerkleBlock *)otherBlock)->height);
}

struct BRPeerManagerStruct {
    const BRChainParams *params;
    BRWallet *wallet;
    int isConnected, connectFailureCount, misbehavinCount, dnsThreadCount, maxConnectCount, peerThreadCount;
    BRPeer *peers, *downloadPeer, fixedPeer, **connectedPeers;
    char downloadPeerName[INET6_ADDRSTRLEN + 6];
    uint32_t earliestKeyTime, syncStartHeight, estimatedHeight;
    BRSet *blocks, *orphans, *checkpoints;
    BRMerkleBlock *lastBlock, *lastOrphan;
    BRMerkleBlock *startSyncFrom;
    BRTxPeerList *txRelays, *txRequests;
    BRPublishedTx *publishedTx;
    UInt256 *publishedTxHashes;
    void *info;
    void (*syncStarted)(void *info);
    void (*syncStopped)(void *info, int error);
    void (*txStatusUpdate)(void *info);
    void (*saveBlocks)(void *info, int replace, const uint8_t *bytes, size_t len, uint64_t* stackIntegrityCheck);
    void (*savePeers)(void *info, int replace, const BRPeer peers[], size_t peersCount);
    int (*networkIsReachable)(void *info);
    void (*threadCleanup)(void *info);
    // Dandelion++ stem submission (broadcast-origin privacy)
    int dandelionEnabled;            // wallet setting: stem-submit on broadcast (default on)
    UInt128 *dandelionPeers;         // addresses known Dandelion-capable (no service bit exists)
    // BIP 158 compact-filter sync (inert unless syncMode != BLOOM_ONLY)
    BRSyncMode syncMode;
    BRCompactFilterChain *compactFilterChain;
    void *saveFilterHeadersInfo;
    void (*saveFilterHeaders)(void *info, const BRCompactFilterChain *chain);
    // Per-height CF scan-completeness ledger (Phase 1: observe-only). Populated by
    // the CF request/eval/drop paths while manager->lock is held; persisted via the
    // saveCFLedger callback (coalesced Kotlin-side, same as saveFilterHeaders).
    void *saveCFLedgerInfo;
    void (*saveCFLedger)(void *info, const uint8_t *bytes, size_t len);
    BRCFScanLedger cfLedger;
    // Cached BIP 158 wallet element set, reused across arriving cfilters. Rebuilding it
    // per filter was 98.8% of the per-filter cost (see _BRPeerManagerFilterElementsLocked).
    // cfElemsAddrCount is the address count the cache was built from and is the ONLY
    // validity condition — never a timer.
    BRWalletFilterElements *cfElems;
    // Self-clocked cfilter drive: how many blocks are requested-but-unanswered, and when
    // the current window opened. Deliberately NOT a ledger predicate — the ledger is
    // observe-only here, and its accounting goes lossy once it saturates.
    uint32_t cfFiltersInFlight;
    time_t   cfFiltersWindowStart;
    uint64_t cfElemsAddrGen;      // wallet's address-set generation the cache was built from
    size_t cfElemsAddrCount;      // ...and its address count (defence-in-depth)
    int cfElemsIsTestnet;         // ...and the network, which changes the encoded BYTES
    int autoFetchCFiltersEnabled;
    uint32_t autoFetchCFiltersStart;     // wallet birth height (inclusive)
    uint32_t autoFetchCFiltersThrough;   // highest height already requested (or
                                         // start-1 if no request has fired yet)
    // BIP 158 cfheaders are a linear chain — only one getcfheaders batch may be
    // in flight at a time, else the rapid per-block driver kicks send duplicate
    // requests whose late responses fail the continuity check and get filter
    // peers disconnected. These serialize the driver: the next batch isn't
    // requested until the in-flight one lands, fails, or times out.
    uint32_t cfHeadersRequestedThrough;  // batchEnd of the in-flight request (0 = none)
    time_t   cfHeadersRequestTime;       // when it was sent, for the timeout
    UInt128  cfHeadersPeerAddr;          // peer the in-flight request was sent to, so a
                                         // timed-out (blackholing) filter peer is rotated
                                         // away from on retry instead of re-dialed forever
    UInt128  cfTriedPeers[16];           // filter peers already tried for the CURRENT batch;
    uint8_t  cfTriedCount;               // when all connected filter peers are in here and
                                         // none answered, the whole set is stalled → drop one
                                         // for a fresh peer (self-heal). Reset on batch advance.
    // Lock-free mirrors of the scalar status values the Android UI polls for the
    // sync overlay. Written by the sync/worker threads WHERE THEY ALREADY HOLD
    // manager->lock (via _BRPeerManagerRefreshCachedStatus); read by the JNI status
    // accessors WITHOUT manager->lock. This stops a heavy compact-filter sync
    // (worker holding manager->lock ~continuously) from starving the UI thread into
    // a 10s ANR at the PIN screen. Relaxed ordering: values are monotonic-ish and a
    // one-cycle lag is harmless for a progress overlay.
    _Atomic uint32_t cachedLastHeight;
    _Atomic uint32_t cachedLastTimestamp;
    _Atomic uint32_t cachedEstimatedHeight;
    _Atomic uint32_t cachedSyncStartHeight;
    _Atomic uint32_t cachedCFTip;
    _Atomic int      cachedPeerCount;
    _Atomic int      cachedHasDownloadPeer;
    _Atomic int      cachedSyncMode;
    // Distinct peers that failed the cfheaders continuity check since the last
    // successful append. K of them disagreeing means WE are the outlier.
    UInt128  cfDisagreedPeers[CF_CONTINUITY_REANCHOR_K];
    uint8_t  cfDisagreedCount;
    uint8_t  cfReanchorCount;            // continuity-triggered re-anchors this session
    // When only ONE filter peer is connected the K-distinct-disagreers threshold
    // can never be met (the active probe reaches no other filter peer), so
    // cfDisagreedCount wedges at 1/K forever and cfheaders never advance. Count
    // CONSECUTIVE diverged rounds instead; at CF_SINGLE_PEER_REANCHOR_ROUNDS force
    // a (still CF_CONTINUITY_REANCHOR_MAX-bounded) re-anchor.
    uint8_t  cfSingleDisagreeRounds;
    // Session-scoped re-dial penalty (churn fix, see PEER_PENALTY_* above).
    // Ring buffer: penaltyCount only ever grows (mod PEER_PENALTY_MAX indexing
    // on insert), never shrinks -- entries just age out via BRPeerPenaltyContains'
    // until-vs-now check. Zero-initialized by BRPeerManagerNewEx's calloc.
    UInt128  penaltyAddr[PEER_PENALTY_MAX];
    uint16_t penaltyPort[PEER_PENALTY_MAX];
    time_t   penaltyUntil[PEER_PENALTY_MAX];
    size_t   penaltyCount;
    // Pinned own-node: a user-paired node kept as a reserved, never-churn-evicted
    // CF peer. pinnedPort == 0 means no pin. pinnedExclusive: dial ONLY this node.
    // Zero-initialized by BRPeerManagerNewEx's calloc (matching the penalty arrays).
    UInt128  pinnedAddr;
    uint16_t pinnedPort;
    int      pinnedExclusive;
    // Per-peer "answered cfheaders/cfilter this session" set (positive CF-served
    // signal; mirrors cfDisagreedPeers). Ring buffer, calloc-zeroed.
    UInt128  cfServedAddr[16];
    uint16_t cfServedPort[16];
    size_t   cfServedCount;
    pthread_mutex_t lock;
};

// Snapshot the scalar status values the Android UI polls into the lock-free atomic
// mirrors. MUST be called with manager->lock held (so lastBlock / compactFilterChain
// / connectedPeers are valid to read). Cheap: a few scalar reads plus one short walk
// of connectedPeers. Called from the worker/sync paths that already hold the lock so
// the JNI status accessors can read the mirrors WITHOUT the lock and never block
// behind a heavy compact-filter sync (which is what ANR'd the PIN screen).
static void _BRPeerManagerRefreshCachedStatus(BRPeerManager *manager)
{
    if (manager->lastBlock) {
        atomic_store_explicit(&manager->cachedLastHeight, manager->lastBlock->height, memory_order_relaxed);
        atomic_store_explicit(&manager->cachedLastTimestamp, manager->lastBlock->timestamp, memory_order_relaxed);
    }
    atomic_store_explicit(&manager->cachedEstimatedHeight, manager->estimatedHeight, memory_order_relaxed);
    atomic_store_explicit(&manager->cachedSyncStartHeight, manager->syncStartHeight, memory_order_relaxed);
    atomic_store_explicit(&manager->cachedHasDownloadPeer, manager->downloadPeer ? 1 : 0, memory_order_relaxed);
    atomic_store_explicit(&manager->cachedSyncMode, (int)manager->syncMode, memory_order_relaxed);

    uint32_t cfTip = manager->compactFilterChain
                     ? BRCompactFilterChainNextHeight(manager->compactFilterChain) : 0;
    atomic_store_explicit(&manager->cachedCFTip, cfTip, memory_order_relaxed);

    int pc = 0;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) != BRPeerStatusDisconnected) pc++;
    }
    atomic_store_explicit(&manager->cachedPeerCount, pc, memory_order_relaxed);
}

void BRPeerManagerSetStartBlock(BRPeerManager* manager, BRMerkleBlock* start) {
    if (!manager || !start) return;
    manager->startSyncFrom = start;
}

static void _BRPeerManagerPeerMisbehavin(BRPeerManager *manager, BRPeer *peer)
{
    for (size_t i = array_count(manager->peers); i > 0; i--) {
        if (BRPeerEq(&manager->peers[i - 1], peer)) array_rm(manager->peers, i - 1);
    }

    if (++manager->misbehavinCount >= 10) { // clear out stored peers so we get a fresh list from DNS for next connect
        manager->misbehavinCount = 0;
        array_clear(manager->peers);
    }

    BRPeerDisconnect(peer);
}

static void _BRPeerManagerSyncStopped(BRPeerManager *manager)
{
    manager->syncStartHeight = 0;

    if (manager->downloadPeer) {
        // don't cancel timeout if there's a pending tx publish callback
        for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
            if (manager->publishedTx[i - 1].callback != NULL) return;
        }
    
        BRPeerScheduleDisconnect(manager->downloadPeer, -1); // cancel sync timeout
    }
}

// adds transaction to list of tx to be published, along with any unconfirmed inputs
static void _BRPeerManagerAddTxToPublishList(BRPeerManager *manager, BRTransaction *tx, void *info,
                                             void (*callback)(void *, int))
{
    if (tx && tx->blockHeight == TX_UNCONFIRMED) {
        for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
            if (BRTransactionEq(manager->publishedTx[i - 1].tx, tx)) return;
        }
        
        array_add(manager->publishedTx, ((BRPublishedTx) { tx, info, callback }));
        array_add(manager->publishedTxHashes, tx->txHash);

        for (size_t i = 0; i < tx->inCount; i++) {
            _BRPeerManagerAddTxToPublishList(manager, BRWalletTransactionForHash(manager->wallet, tx->inputs[i].txHash),
                                             NULL, NULL);
        }
    }
}

static size_t _BRPeerManagerBlockLocators(BRPeerManager *manager, UInt256 locators[], size_t locatorsCount)
{
    // append 10 most recent block hashes, decending, then continue appending, doubling the step back each time,
    // finishing with the genesis block (top, -1, -2, -3, -4, -5, -6, -7, -8, -9, -11, -15, -23, -39, -71, -135, ..., 0)
    BRMerkleBlock *block = manager->lastBlock;
    int32_t step = 1, i = 0, j;
    
    while (block && block->height > 0) {
        if (locators && i < locatorsCount) locators[i] = block->blockHash;
        if (++i >= 10) step *= 2;
        
        for (j = 0; block && j < step; j++) {
            block = BRSetGet(manager->blocks, &block->prevBlock);
        }
    }
    
    if (locators && i < locatorsCount) locators[i] = genesis_block_hash(manager->params);
    return ++i;
}

static void _setApplyFreeBlock(void *info, void *block)
{
    BRMerkleBlockFree(block);
}

static size_t _BRPeerManagerAddPeer(BRPeerManager *manager, BRPeer *peer) {
	size_t add = 1;
	for (size_t i = array_count(manager->peers); i > 0; i--) {
		BRPeer* otherPeer = (BRPeer*) &(manager->peers[i - 1]);
		if (BRPeerEq(otherPeer, peer)) { i = 1; add = 0;}
	}
	if (add == 1) array_add(manager->peers, *peer);
	return add;
}

// Public wrapper around _BRPeerManagerAddPeer for runtime peer injection from
// e.g. a seeder API. The init-time savedPeers blob is consumed once at peer-
// manager creation and never reread, so injecting into that path after the
// fact is a silent no-op — callers seeing "0 peers" while their seeder is
// returning fresh peers want THIS function instead. Holds the manager lock
// because manager->peers may be mutated concurrently by the message handler.
int BRPeerManagerAddPeer(BRPeerManager *manager, UInt128 address, uint16_t port,
                          uint64_t services)
{
    assert(manager != NULL);
    BRPeer peer = (BRPeer){ address, port, services, (uint64_t)time(NULL), 0 };
    pthread_mutex_lock(&manager->lock);
    size_t added = _BRPeerManagerAddPeer(manager, &peer);
    pthread_mutex_unlock(&manager->lock);
    return (int)added;
}

// Generate the gap+100 look-ahead address window for every script type
// (segwit, legacy, taproot; external+internal) into the wallet's allAddrs.
// allAddrs feeds BOTH the bloom filter and compact filters
// (BRWalletGetFilterElements), so incoming payments up to ~100 indices ahead of
// the highest-used address stay watched. This is bloom-INDEPENDENT: it must run
// in COMPACT_FILTERS_ONLY too (where no bloom filter is ever loaded), otherwise
// the CF match window decays to the bare gap limit as addresses are consumed and
// a look-ahead receive is missed. BRWalletUnusedAddrs is idempotent once the
// window is generated; scriptType-2 no-ops until the BIP86 key is installed.
static void _BRPeerManagerPregenAddrWindow(BRPeerManager *manager)
{
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 1);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 1);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 0);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 0);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 2);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 2);
}

// Bloom filter loader + reload cluster (_BRPeerManagerLoadBloomFilter,
// _updateFilterRerequestDone/_updateFilterLoadDone/_updateFilterPingDone,
// _BRPeerManagerUpdateFilter) removed — CF-only mode never loaded a bloom
// filter (the loader early-returned for COMPACT_FILTERS_ONLY), so this was
// already dead weight. The gap+100 look-ahead these functions maintained is
// still generated by _BRPeerManagerPregenAddrWindow above, called directly
// from the CF path (_BRPeerManagerOnFilterCapablePeerConnected) and from
// _peerRelayedTx below.

static void _BRPeerManagerUpdateTx(BRPeerManager *manager, const UInt256 txHashes[], size_t txCount,
                                   uint32_t blockHeight, uint32_t timestamp)
{
    if (blockHeight != TX_UNCONFIRMED) { // remove confirmed tx from publish list and relay counts
        for (size_t i = 0; i < txCount; i++) {
            for (size_t j = array_count(manager->publishedTx); j > 0; j--) {
                BRTransaction *tx = manager->publishedTx[j - 1].tx;
                
                if (! UInt256Eq(txHashes[i], tx->txHash)) continue;
                array_rm(manager->publishedTx, j - 1);
                array_rm(manager->publishedTxHashes, j - 1);
                if (! BRWalletTransactionForHash(manager->wallet, tx->txHash)) BRTransactionFree(tx);
            }
            
            for (size_t j = array_count(manager->txRelays); j > 0; j--) {
                if (! UInt256Eq(txHashes[i], manager->txRelays[j - 1].txHash)) continue;
                array_free(manager->txRelays[j - 1].peers);
                array_rm(manager->txRelays, j - 1);
            }
        }
    }
    
    BRWalletUpdateTransactions(manager->wallet, txHashes, txCount, blockHeight, timestamp);
}

// unconfirmed transactions that aren't in the mempools of any of connected peers have likely dropped off the network
static void _requestUnrelayedTxGetdataDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    int isPublishing;
    size_t count = 0;

    free(info);
    pthread_mutex_lock(&manager->lock);
    if (success) peer->flags |= PEER_FLAG_SYNCED;
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        peer = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(peer) == BRPeerStatusConnected) count++;
        if ((peer->flags & PEER_FLAG_SYNCED) != 0) continue;
        count = 0;
        break;
    }

    // don't remove transactions until we're connected to maxConnectCount peers, and all peers have finished
    // relaying their mempools
    if (count >= manager->maxConnectCount) {
        size_t txCount = BRWalletTxUnconfirmedBefore(manager->wallet, NULL, 0, TX_UNCONFIRMED);
        BRTransaction *tx[(txCount < 10000) ? txCount : 10000];
        
        txCount = BRWalletTxUnconfirmedBefore(manager->wallet, tx, sizeof(tx)/sizeof(*tx), TX_UNCONFIRMED);

        for (size_t i = 0; i < txCount; i++) {
            isPublishing = 0;
            
            for (size_t j = array_count(manager->publishedTx); ! isPublishing && j > 0; j--) {
                if (BRTransactionEq(manager->publishedTx[j - 1].tx, tx[i]) &&
                    manager->publishedTx[j - 1].callback != NULL) isPublishing = 1;
            }
            
            if (! isPublishing && _BRTxPeerListCount(manager->txRelays, tx[i]->txHash) == 0 &&
                _BRTxPeerListCount(manager->txRequests, tx[i]->txHash) == 0) {
                // Don't remove unconfirmed transactions while still syncing.
                // Saved transactions are loaded with blockHeight=TX_UNCONFIRMED
                // (BRTransactionSerialize doesn't persist block heights). The
                // sync will re-confirm them, but this cleanup fires first and
                // deletes them because no peer relays old confirmed txs.
                // Only clean up after we've reached the chain tip.
                if (manager->lastBlock->height >= manager->estimatedHeight) {
                    // Even at chain tip, don't remove transactions the wallet
                    // has a stake in. Historical sends loaded from saved_txs
                    // sit here with blockHeight=TX_UNCONFIRMED and no peer
                    // still relaying them (they're old confirmed txs, long
                    // since out of every mempool), but they're part of the
                    // wallet's ledger — we spent our own UTXOs producing them
                    // or received coins in them. Removing them here is what
                    // caused users to see their sends flash into history on
                    // app launch and then vanish the moment the sync hit tip.
                    if (BRWalletAmountSentByTx(manager->wallet, tx[i]) == 0 &&
                        BRWalletAmountReceivedFromTx(manager->wallet, tx[i]) == 0) {
                        BRWalletRemoveTransaction(manager->wallet, tx[i]->txHash);
                    }
                }
            }
            else if (! isPublishing && _BRTxPeerListCount(manager->txRelays, tx[i]->txHash) < manager->maxConnectCount){
                // set timestamp 0 to mark as unverified
                _BRPeerManagerUpdateTx(manager, &tx[i]->txHash, 1, TX_UNCONFIRMED, 0);
            }
        }
    }

    pthread_mutex_unlock(&manager->lock);
}

static void _BRPeerManagerRequestUnrelayedTx(BRPeerManager *manager, BRPeer *peer)
{
    BRPeerCallbackInfo *info;
    size_t hashCount = 0, txCount = BRWalletTxUnconfirmedBefore(manager->wallet, NULL, 0, TX_UNCONFIRMED);
    BRTransaction *tx[txCount];
    UInt256 txHashes[txCount];
    
    txCount = BRWalletTxUnconfirmedBefore(manager->wallet, tx, txCount, TX_UNCONFIRMED);
    
    for (size_t i = 0; i < txCount; i++) {
        if (! _BRTxPeerListHasPeer(manager->txRelays, tx[i]->txHash, peer) &&
            ! _BRTxPeerListHasPeer(manager->txRequests, tx[i]->txHash, peer)) {
            txHashes[hashCount++] = tx[i]->txHash;
            _BRTxPeerListAddPeer(&manager->txRequests, tx[i]->txHash, peer);
        }
    }

    if (hashCount > 0) {
        BRPeerSendGetdata(peer, txHashes, hashCount, NULL, 0);
    
        if ((peer->flags & PEER_FLAG_SYNCED) == 0) {
            info = calloc(1, sizeof(*info));
            assert(info != NULL);
            info->peer = peer;
            info->manager = manager;
            BRPeerSendPing(peer, info, _requestUnrelayedTxGetdataDone);
        }
    }
    else peer->flags |= PEER_FLAG_SYNCED;
}

static void _BRPeerManagerPublishPendingTx(BRPeerManager *manager, BRPeer *peer)
{
    for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
        if (manager->publishedTx[i - 1].callback == NULL) continue;
        BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT); // schedule publish timeout
        break;
    }
    
    BRPeerSendInv(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes));
}

static void _mempoolDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    int syncFinished = 0;
    
    free(info);
    
    if (success) {
        peer_log(peer, "mempool request finished");
        pthread_mutex_lock(&manager->lock);
        if (manager->syncStartHeight > 0) {
            peer_log(peer, "sync succeeded");
            syncFinished = 1;
            _BRPeerManagerSyncStopped(manager);
        }

        _BRPeerManagerRequestUnrelayedTx(manager, peer);
        BRPeerSendGetaddr(peer); // request a list of other bitcoin peers
        pthread_mutex_unlock(&manager->lock);
        if (manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
        if (syncFinished && manager->syncStopped) manager->syncStopped(manager->info, 0);
    }
    else peer_log(peer, "mempool request failed");
}

static void _BRPeerManagerLoadMempools(BRPeerManager *manager)
{
    // after syncing, request mempools from connected peers. Formerly gated on
    // whether each peer's bloom filter was already fresh enough (fpRate check) to
    // skip a pre-mempool filter-reload ping; with bloom gone there is nothing to
    // wait on, so every peer goes straight to the same publish+mempool path the
    // "fresh filter" branch already used.
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *peer = manager->connectedPeers[i - 1];
        BRPeerCallbackInfo *info;

        if (BRPeerConnectStatus(peer) != BRPeerStatusConnected) continue;
        info = calloc(1, sizeof(*info));
        assert(info != NULL);
        info->peer = peer;
        info->manager = manager;

        _BRPeerManagerPublishPendingTx(manager, peer);
        BRPeerSendMempool(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes), info,
                          _mempoolDone);
    }
}

// returns a UINT128_ZERO terminated array of addresses for hostname that must be freed, or NULL if lookup failed
static UInt128 *_addressLookup(const char *hostname)
{
    struct addrinfo *servinfo, *p;
    UInt128 *addrList = NULL;
    size_t count = 0, i = 0;
    
    if (getaddrinfo(hostname, NULL, NULL, &servinfo) == 0) {
        for (p = servinfo; p != NULL; p = p->ai_next) count++;
        if (count > 0) addrList = calloc(count + 1, sizeof(*addrList));
        assert(addrList != NULL || count == 0);
        
        for (p = servinfo; p != NULL; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                addrList[i].u16[5] = 0xffff;
                addrList[i].u32[3] = ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr;
                i++;
            }
            else if (p->ai_family == AF_INET6) {
                addrList[i++] = *(UInt128 *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
            }
        }
        
        freeaddrinfo(servinfo);
    }
    
    return addrList;
}

static void *_findPeersThreadRoutine(void *arg)
{
    BRPeerManager *manager = ((BRFindPeersInfo *)arg)->manager;
    uint64_t services = ((BRFindPeersInfo *)arg)->services;
    UInt128 *addrList, *addr;
    time_t now = time(NULL), age;
    
    pthread_cleanup_push(manager->threadCleanup, manager->info);
    addrList = _addressLookup(((BRFindPeersInfo *)arg)->hostname);
    free(arg);
    pthread_mutex_lock(&manager->lock);
    
    for (addr = addrList; addr && ! UInt128IsZero(*addr); addr++) {
        age = 24*60*60 + BRRand(2*24*60*60); // add between 1 and 3 days
		BRPeer peer = {*addr, manager->params->standardPort, services, now - age, 0};
		_BRPeerManagerAddPeer(manager,&peer);
    }

    manager->dnsThreadCount--;
    pthread_mutex_unlock(&manager->lock);
    if (addrList) free(addrList);
    pthread_cleanup_pop(1);
    return NULL;
}

// DNS peer discovery
static void _BRPeerManagerFindPeers(BRPeerManager *manager)
{
    uint64_t services = SERVICES_NODE_NETWORK | SERVICES_NODE_COMPACT_FILTERS | manager->params->services;
    time_t now = time(NULL);
    struct timespec ts;
    pthread_t thread;
    pthread_attr_t attr;
    BRFindPeersInfo *info;
    
    if (! UInt128IsZero(manager->fixedPeer.address)) {
        array_set_count(manager->peers, 1);
        manager->peers[0] = manager->fixedPeer;
        manager->peers[0].services = services;
        manager->peers[0].timestamp = now;
    }
    else {
        // Resolve EVERY DNS seed on a detached worker thread, index 0 included. Seed[0] used to
        // be resolved SYNCHRONOUSLY here (getaddrinfo) while holding manager->lock, so a slow or
        // timing-out DNS lookup pinned the lock for seconds. During reconnect in the middle of a
        // heavy compact-filter rescan that starved the UI thread into an ANR on weaker devices
        // (Note 8 / API 28). Threading seed[0] too keeps all blocking DNS off the lock; the wait
        // loop below still gates the connect on peers arriving, but it RELEASES the lock while it
        // sleeps, so the UI thread can always acquire the lock between iterations.
        for (size_t i = 0; manager->params->dnsSeeds[i]; i++) {
            info = calloc(1, sizeof(BRFindPeersInfo));
            assert(info != NULL);
            info->manager = manager;
            info->hostname = manager->params->dnsSeeds[i];
            info->services = services;
            if (pthread_attr_init(&attr) == 0 && pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0 &&
                pthread_create(&thread, &attr, _findPeersThreadRoutine, info) == 0) manager->dnsThreadCount++;
        }

        ts.tv_sec = 0;
        ts.tv_nsec = 1;

        do {
            pthread_mutex_unlock(&manager->lock);
            nanosleep(&ts, NULL); // pthread_yield() isn't POSIX standard :(
            pthread_mutex_lock(&manager->lock);
        } while (manager->dnsThreadCount > 0 && array_count(manager->peers) < PEER_MAX_CONNECTIONS);
    
        qsort(manager->peers, array_count(manager->peers), sizeof(*manager->peers), _peerTimestampCompare);
    }
}

// Forward declarations — BIP 158 hooks used by _peerConnected and
// _peerRelayedCFHeaders. Definitions live near BRPeerManagerSetCallbacks
// alongside the rest of the compact-filter helpers.
static void _BRPeerManagerOnFilterCapablePeerConnected(BRPeerManager *manager, void *peerCbInfo, BRPeer *peer);
// outStop (may be NULL) receives the stop height ACTUALLY requested, which can be
// higher than the caller's stopHeight when the range had to be snapped up past a
// pruned band. Callers that advance a cursor must use it, not their own request
// range, or they will re-request the unresolvable band forever.
static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight,
                                                  BRPeer *preferred, uint32_t *outStop);
static BRPeer *_BRPeerManagerAnyFilterCapablePeer(BRPeerManager *manager);
static void _BRPeerManagerRequestNextCFHeaders(BRPeerManager *manager, BRPeer *peer);
static int _BRPeerManagerReanchorAtFloorLocked(BRPeerManager *manager, int force);
// Defined near BRPeerManagerRequestCompactFilters; forward-declared so the Phase 2
// buffered-drain trampolines (_cfBufEval, above BRPeerManagerKeepAlive) and
// BRPeerManagerKeepAlive's residual re-request driver can both use it.
static int _BRPeerManagerPeerCanServeFilters(BRPeer *p);
static void _BRPeerManagerDriveCFiltersLocked(BRPeerManager *manager, BRPeer *preferred);
static uint32_t _BRPeerManagerBlockFloor(BRPeerManager *manager);
static int _BRPeerManagerConnectedFilterPeerCount(BRPeerManager *manager); // defined below; used by the cfheaders stall-drop floor guard
static void _BRPeerManagerProbeOtherFilterPeersForCFHeaders(BRPeerManager *manager, BRPeer *current,
                                                            uint8_t filterType, uint32_t startHeight,
                                                            UInt256 stopHash);

// Ring-buffer insert/refresh for the churn-fix penalty set (see PEER_PENALTY_*
// above). If (addr, port) is already on the list its window is refreshed;
// otherwise it's inserted at penaltyCount % PEER_PENALTY_MAX (oldest entry
// evicted once the buffer wraps). Caller holds manager->lock.
static void _penalize(BRPeerManager *manager, UInt128 addr, uint16_t port, time_t now)
{
    for (size_t i = 0; i < manager->penaltyCount && i < PEER_PENALTY_MAX; i++) {
        if (manager->penaltyPort[i] == port && UInt128Eq(manager->penaltyAddr[i], addr)) {
            manager->penaltyUntil[i] = now + PEER_PENALTY_SECONDS;
            return;
        }
    }

    size_t idx = manager->penaltyCount % PEER_PENALTY_MAX;
    manager->penaltyAddr[idx] = addr;
    manager->penaltyPort[idx] = port;
    manager->penaltyUntil[idx] = now + PEER_PENALTY_SECONDS;
    manager->penaltyCount++;
}

// Record that `peer` answered a compact-filter request (positive served signal).
// Ring buffer of the last 16 distinct filter-serving peers; feeds the pinned
// own-node CF status accessor (SERVING vs CONNECTED_NOT_SERVING). Caller holds
// manager->lock (both call sites — _peerRelayedCFHeaders/_peerRelayedCFilter —
// already hold it); this must NOT lock (no double-lock). BRPeer stores addr/port
// as plain fields (no BRPeerAddress accessor exists), matching _penalize above.
static void _recordCFServed(BRPeerManager *manager, BRPeer *peer)
{
    UInt128 a = peer->address; uint16_t p = peer->port;
    for (size_t i = 0; i < manager->cfServedCount && i < 16; i++) {
        if (UInt128Eq(manager->cfServedAddr[i], a) && manager->cfServedPort[i] == p) return;
    }
    size_t idx = manager->cfServedCount % 16;
    manager->cfServedAddr[idx] = a; manager->cfServedPort[idx] = p;
    manager->cfServedCount++;
}

// Has (a, p) answered a cfheaders/cfilter this session? Read-only; caller holds
// manager->lock (only called from the locked status accessor). Must NOT lock.
static int _cfServedContains(const BRPeerManager *manager, UInt128 a, uint16_t p)
{
    size_t n = manager->cfServedCount < 16 ? manager->cfServedCount : 16;
    for (size_t i = 0; i < n; i++)
        if (UInt128Eq(manager->cfServedAddr[i], a) && manager->cfServedPort[i] == p) return 1;
    return 0;
}

static void _peerConnected(void *info)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRPeerCallbackInfo *peerInfo;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&manager->lock);
    if (peer->timestamp > now + 2*60*60 || peer->timestamp < now - 2*60*60) peer->timestamp = now; // sanity check
    
    // TODO: XXX does this work with 0.11 pruned nodes?
    if ((peer->services & manager->params->services) != manager->params->services) {
        peer_log(peer, "unsupported node type");
        BRPeerDisconnect(peer);
    }
    else if ((peer->services & SERVICES_NODE_NETWORK) != SERVICES_NODE_NETWORK) {
        peer_log(peer, "node doesn't carry full blocks");
        BRPeerDisconnect(peer);
    }
    else if (BRPeerLastBlock(peer) + 10 < manager->lastBlock->height) {
        peer_log(peer, "node isn't synced");
        // Churn fix: remember this (addr, port) for PEER_PENALTY_SECONDS so
        // the filter-first dial loop (BRPeerManagerConnect) doesn't
        // immediately re-dial the same still-behind peer on the very next
        // connect pass. See BRPeerPenalty.h. Never penalize the pinned own-node:
        // a transient reject must not park the user's paired node (Step 6 re-dials
        // it next Connect; a genuinely dead socket is still reaped by _peerDisconnected).
        if (! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort, peer->address, peer->port))
            _penalize(manager, peer->address, peer->port, now);
        BRPeerDisconnect(peer);
    }
    else if (BRPeerVersion(peer) >= 70011 &&
             ! BRPeerServicesAllowedForSyncMode(peer->services, manager->syncMode)) {
        // Bloom OR (compact filters while not in bloom-only mode). Generalizes the
        // former testnet-only compact-filter exception to mainnet so CF-only nodes
        // (bloom off by default on modern Core) are SPV-usable on the filter path.
        // NOTE: this also means testnet no longer keeps CF peers under BLOOM_ONLY —
        // intentional and unreachable, since the app always forces testnet to
        // COMPACT_FILTERS_ONLY. Gossip retention (BRPeerManager.c:1086-1096) is left
        // testnet-only here; its mainnet generalization ships with oracle-bootstrap.
        peer_log(peer, "node doesn't support SPV mode");
        // Penalize so the CF-first dial loop AND the shotgun fallback skip this bloom-off node for
        // PEER_PENALTY_SECONDS instead of re-dialing it (mirrors the "node isn't synced" penalty).
        // Exempt the pinned own-node (see the "node isn't synced" branch above).
        if (! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort, peer->address, peer->port))
            _penalize(manager, peer->address, peer->port, now);
        BRPeerDisconnect(peer);
    }
    else if (manager->downloadPeer && // check if we should stick with the existing download peer
             (BRPeerLastBlock(manager->downloadPeer) >= BRPeerLastBlock(peer) ||
              manager->lastBlock->height >= BRPeerLastBlock(peer))) {
        if (manager->lastBlock->height >= BRPeerLastBlock(peer)) { // already synced: request this peer's mempool too
            manager->connectFailureCount = 0; // also reset connect failure count if we're already synced
            _BRPeerManagerPublishPendingTx(manager, peer);
            peerInfo = calloc(1, sizeof(*peerInfo));
            assert(peerInfo != NULL);
            peerInfo->peer = peer;
            peerInfo->manager = manager;
            BRPeerSendMempool(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes), peerInfo,
                              _mempoolDone);
        }
    }
    else { // select the peer with the lowest ping time to download the chain from if we're behind
        // BUG: XXX a malicious peer can report a higher lastblock to make us select them as the download peer, if
        // two peers agree on lastblock, use one of those two instead
        for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            
            if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
            if ((BRPeerPingTime(p) < BRPeerPingTime(peer) && BRPeerLastBlock(p) >= BRPeerLastBlock(peer)) ||
                BRPeerLastBlock(p) > BRPeerLastBlock(peer)) peer = p;
        }
        
        if (manager->downloadPeer) BRPeerDisconnect(manager->downloadPeer);
        manager->downloadPeer = peer;
        manager->isConnected = 1;
        manager->estimatedHeight = BRPeerLastBlock(peer);
        BRPeerSetCurrentBlockHeight(peer, manager->lastBlock->height);
        _BRPeerManagerPublishPendingTx(manager, peer);
            
        if (manager->lastBlock->height < BRPeerLastBlock(peer)) { // start blockchain sync
            UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
            size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));
            
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT); // schedule sync timeout

            // request just block headers up to a week before earliestKeyTime, and then merkleblocks after that
            // we do not reset connect failure count yet incase this request times out
            if (manager->syncMode != BR_SYNC_MODE_COMPACT_FILTERS_ONLY &&
                manager->lastBlock->timestamp + 7*24*60*60 >= manager->earliestKeyTime) {
                BRPeerSendGetblocks(peer, locators, count, UINT256_ZERO);
            }
            else BRPeerSendGetheaders(peer, locators, count, UINT256_ZERO); // compact-only always pulls plain headers
        }
        else { // we're already synced
            manager->connectFailureCount = 0; // reset connect failure count
            _BRPeerManagerLoadMempools(manager);
        }
    }

    // If we didn't bounce the peer above and BIP 158 sync is enabled, register
    // the compact-filter callbacks and kick off the cfheaders fetch loop. The
    // peer's info pointer was already set by BRPeerSetCallbacks at connect, so
    // BRPeerSetCompactFilterCallbacks shares that same info struct.
    if (BRPeerConnectStatus(peer) == BRPeerStatusConnected) {
        _BRPeerManagerOnFilterCapablePeerConnected(manager, info, peer);
    }

    // Refresh peer-count/downloadPeer mirrors so the connect-phase overlay shows the
    // live peer count before the first block arrives.
    _BRPeerManagerRefreshCachedStatus(manager);
    pthread_mutex_unlock(&manager->lock);
}

static void _peerDisconnected(void *info, int error)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRTxPeerList *peerList;
    int willSave = 0, willReconnect = 0, txError = 0;
    size_t txCount = 0;
    
    //free(info);
    pthread_mutex_lock(&manager->lock);

    void *txInfo[array_count(manager->publishedTx)];
    void (*txCallback[array_count(manager->publishedTx)])(void *, int);
    
    if (error == EPROTO) { // if it's protocol error, the peer isn't following standard policy
        _BRPeerManagerPeerMisbehavin(manager, peer);
    }
    else if (error) { // timeout or some non-protocol related network error
        for (size_t i = array_count(manager->peers); i > 0; i--) {
            if (BRPeerEq(&manager->peers[i - 1], peer)) array_rm(manager->peers, i - 1);
        }
        
        manager->connectFailureCount++;
        
        // if it's a timeout and there's pending tx publish callbacks, the tx publish timed out
        // BUG: XXX what if it's a connect timeout and not a publish timeout?
        if (error == ETIMEDOUT && (peer != manager->downloadPeer || manager->syncStartHeight == 0 ||
                                   array_count(manager->connectedPeers) == 1)) txError = ETIMEDOUT;
    }
    
    for (size_t i = array_count(manager->txRelays); i > 0; i--) {
        peerList = &manager->txRelays[i - 1];

        for (size_t j = array_count(peerList->peers); j > 0; j--) {
            if (BRPeerEq(&peerList->peers[j - 1], peer)) array_rm(peerList->peers, j - 1);
        }
    }

    if (peer == manager->downloadPeer) { // download peer disconnected
        manager->isConnected = 0;
        manager->downloadPeer = NULL;
        if (manager->connectFailureCount > MAX_CONNECT_FAILURES) manager->connectFailureCount = MAX_CONNECT_FAILURES;
    }

    if (! manager->isConnected && manager->connectFailureCount == MAX_CONNECT_FAILURES) {
        _BRPeerManagerSyncStopped(manager);
        
        // clear out stored peers so we get a fresh list from DNS on next connect attempt
        array_clear(manager->peers);
        txError = ENOTCONN; // trigger any pending tx publish callbacks
        willSave = 1;
        peer_log(peer, "sync failed");
    }
    else if (manager->connectFailureCount < MAX_CONNECT_FAILURES) willReconnect = 1;
    
    if (txError) {
        for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
            if (manager->publishedTx[i - 1].callback == NULL) continue;
            peer_log(peer, "transaction canceled: %s", strerror(txError));
            txInfo[txCount] = manager->publishedTx[i - 1].info;
            txCallback[txCount] = manager->publishedTx[i - 1].callback;
            txCount++;
            BRTransactionFree(manager->publishedTx[i - 1].tx);
            array_rm(manager->publishedTxHashes, i - 1);
            array_rm(manager->publishedTx, i - 1);
        }
    }
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        if (manager->connectedPeers[i - 1] != peer) continue;
        array_rm(manager->connectedPeers, i - 1);
        break;
    }

    // Clear this disconnected peer off any outstanding CF-scan heights that targeted
    // it, so Phase 2's re-request driver picks a fresh peer. Cheap bookkeeping; a
    // no-op for Phase-1 reads. manager->lock is held here.
    BRCFScanLedgerReArmPeer(&manager->cfLedger, peer->address, peer->port);

    BRPeerFree(peer);
    // Peer left connectedPeers (and possibly was the downloadPeer) — refresh the
    // mirrors so the overlay's peer count reflects the drop without taking the lock.
    _BRPeerManagerRefreshCachedStatus(manager);
    pthread_mutex_unlock(&manager->lock);

    for (size_t i = 0; i < txCount; i++) {
        txCallback[i](txInfo[i], txError);
    }
    
    if (willSave && manager->savePeers) manager->savePeers(manager->info, 1, NULL, 0);
    if (willSave && manager->syncStopped) manager->syncStopped(manager->info, error);
    if (willReconnect) BRPeerManagerConnect(manager); // try connecting to another peer
    if (manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
}

static void _peerRelayedPeers(void *info, const BRPeer peers[], size_t peersCount)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    time_t now = time(NULL);

    pthread_mutex_lock(&manager->lock);
    peer_log(peer, "relayed %zu peer(s)", peersCount);

    // Retain any peer usable for the current sync mode: compact-filter (0x40) peers
    // whenever we're not in legacy BLOOM_ONLY, and bloom peers otherwise. Same policy
    // the connect accept gate uses (BRPeerServicesAllowedForSyncMode). Previously the
    // 0x40 exception was hardcoded to testnet only, so on MAINNET every gossiped
    // BIP157/158 node (modern DigiByte Core ships bloom OFF) was discarded — the
    // CF-only pool couldn't self-heal from churn and collapsed onto the injected
    // seeder set, stranding the wallet on a single filter peer.
    for (size_t i = 0; i < peersCount; i++) {
        if (BRPeerServicesAllowedForSyncMode(peers[i].services, manager->syncMode)) {
            _BRPeerManagerAddPeer(manager, (BRPeer *)&peers[i]);
        }
    }
    qsort(manager->peers, array_count(manager->peers), sizeof(*manager->peers), _peerTimestampCompare);

    // limit total to 2500 peers
    if (array_count(manager->peers) > 2500) array_set_count(manager->peers, 2500);
    peersCount = array_count(manager->peers);
    
    // remove peers more than 3 hours old, or until there are only 1000 left
    while (peersCount > 1000 && manager->peers[peersCount - 1].timestamp + 3*60*60 < now) peersCount--;
    array_set_count(manager->peers, peersCount);
    
    BRPeer save[peersCount];

    for (size_t i = 0; i < peersCount; i++) save[i] = manager->peers[i];
    pthread_mutex_unlock(&manager->lock);
    
    // peer relaying is complete when we receive <1000
    if (peersCount > 1 && peersCount < 1000 &&
        manager->savePeers) manager->savePeers(manager->info, 1, save, peersCount);
}

static void _peerRelayedTx(void *info, BRTransaction *tx)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    void *txInfo = NULL;
    void (*txCallback)(void *, int) = NULL;
    int isWalletTx = 0, hasPendingCallbacks = 0;
    size_t relayCount = 0;
    
    pthread_mutex_lock(&manager->lock);
    peer_log(peer, "relayed tx: %s", u256hex(tx->txHash));
    
    for (size_t i = array_count(manager->publishedTx); i > 0; i--) { // see if tx is in list of published tx
        if (UInt256Eq(manager->publishedTxHashes[i - 1], tx->txHash)) {
            txInfo = manager->publishedTx[i - 1].info;
            txCallback = manager->publishedTx[i - 1].callback;
            manager->publishedTx[i - 1].info = NULL;
            manager->publishedTx[i - 1].callback = NULL;
            relayCount = _BRTxPeerListAddPeer(&manager->txRelays, tx->txHash, peer);
        }
        else if (manager->publishedTx[i - 1].callback != NULL) hasPendingCallbacks = 1;
    }

    // cancel tx publish timeout if no publish callbacks are pending, and syncing is done or this is not downloadPeer
    if (! hasPendingCallbacks && (manager->syncStartHeight == 0 || peer != manager->downloadPeer)) {
        BRPeerScheduleDisconnect(peer, -1); // cancel publish tx timeout
    }

    if (manager->syncStartHeight == 0 || BRWalletContainsTransaction(manager->wallet, tx)) {
        isWalletTx = BRWalletRegisterTransaction(manager->wallet, tx);
        if (isWalletTx) tx = BRWalletTransactionForHash(manager->wallet, tx->txHash);
    }
    else {
        BRTransactionFree(tx);
        tx = NULL;
    }
    
    if (tx && isWalletTx) {
        // reschedule sync timeout
        if (manager->syncStartHeight > 0 && peer == manager->downloadPeer) {
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT);
        }
        
        if (BRWalletAmountSentByTx(manager->wallet, tx) > 0 && BRWalletTransactionIsValid(manager->wallet, tx)) {
            _BRPeerManagerAddTxToPublishList(manager, tx, NULL, NULL); // add valid send tx to mempool
        }

        // keep track of how many peers have or relay a tx, this indicates how likely the tx is to confirm
        // (we only need to track this after syncing is complete)
        if (manager->syncStartHeight == 0) relayCount = _BRTxPeerListAddPeer(&manager->txRelays, tx->txHash, peer);
        
        _BRTxPeerListRemovePeer(manager->txRequests, tx->txHash, peer);
        
        // The transaction likely consumed one or more wallet addresses. Extend the
        // taproot (P2TR / BIP86) gap so the next taproot window stays watched.
        // Taproot outputs are matched via BIP158 (BRWalletGetFilterElements reading
        // allAddrs), not a bloom filter, so there is no hash160 recheck here — the
        // pregen alone advances the watched window. Legacy/segwit gap extension is
        // covered by _BRPeerManagerPregenAddrWindow on filter-capable peer connect
        // (the former bloom-filter recheck-and-reset for those types is gone along
        // with the bloom filter it rebuilt).
        if (manager->wallet) {
            BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 2);
            BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 2);
        }
    }
    
    // set timestamp when tx is verified
    if (tx && relayCount >= manager->maxConnectCount && tx->blockHeight == TX_UNCONFIRMED && tx->timestamp == 0) {
        _BRPeerManagerUpdateTx(manager, &tx->txHash, 1, TX_UNCONFIRMED, (uint32_t)time(NULL));
    }
    
    pthread_mutex_unlock(&manager->lock);
    if (txCallback) txCallback(txInfo, 0);
}

static void _peerHasTx(void *info, UInt256 txHash)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRTransaction *tx;
    void *txInfo = NULL;
    void (*txCallback)(void *, int) = NULL;
    int isWalletTx = 0, hasPendingCallbacks = 0;
    size_t relayCount = 0;
    
    pthread_mutex_lock(&manager->lock);
    tx = BRWalletTransactionForHash(manager->wallet, txHash);
    peer_log(peer, "has tx: %s", u256hex(txHash));

    for (size_t i = array_count(manager->publishedTx); i > 0; i--) { // see if tx is in list of published tx
        if (UInt256Eq(manager->publishedTxHashes[i - 1], txHash)) {
            if (! tx) tx = manager->publishedTx[i - 1].tx;
            txInfo = manager->publishedTx[i - 1].info;
            txCallback = manager->publishedTx[i - 1].callback;
            manager->publishedTx[i - 1].info = NULL;
            manager->publishedTx[i - 1].callback = NULL;
            relayCount = _BRTxPeerListAddPeer(&manager->txRelays, txHash, peer);
        }
        else if (manager->publishedTx[i - 1].callback != NULL) hasPendingCallbacks = 1;
    }
    
    // cancel tx publish timeout if no publish callbacks are pending, and syncing is done or this is not downloadPeer
    if (! hasPendingCallbacks && (manager->syncStartHeight == 0 || peer != manager->downloadPeer)) {
        BRPeerScheduleDisconnect(peer, -1); // cancel publish tx timeout
    }

    if (tx) {
        isWalletTx = BRWalletRegisterTransaction(manager->wallet, tx);
        if (isWalletTx) tx = BRWalletTransactionForHash(manager->wallet, tx->txHash);

        // reschedule sync timeout
        if (manager->syncStartHeight > 0 && peer == manager->downloadPeer && isWalletTx) {
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT);
        }
        
        // keep track of how many peers have or relay a tx, this indicates how likely the tx is to confirm
        // (we only need to track this after syncing is complete)
        if (manager->syncStartHeight == 0) relayCount = _BRTxPeerListAddPeer(&manager->txRelays, txHash, peer);

        // set timestamp when tx is verified
        if (relayCount >= manager->maxConnectCount && tx && tx->blockHeight == TX_UNCONFIRMED && tx->timestamp == 0) {
            _BRPeerManagerUpdateTx(manager, &txHash, 1, TX_UNCONFIRMED, (uint32_t)time(NULL));
        }

        _BRTxPeerListRemovePeer(manager->txRequests, txHash, peer);
    }
    
    pthread_mutex_unlock(&manager->lock);
    if (txCallback) txCallback(txInfo, 0);
}

static void _peerRejectedTx(void *info, UInt256 txHash, uint8_t code)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRTransaction *tx, *t;

    pthread_mutex_lock(&manager->lock);
    peer_log(peer, "rejected tx: %s", u256hex(txHash));
    tx = BRWalletTransactionForHash(manager->wallet, txHash);
    _BRTxPeerListRemovePeer(manager->txRequests, txHash, peer);

    if (tx) {
        if (_BRTxPeerListRemovePeer(manager->txRelays, txHash, peer) && tx->blockHeight == TX_UNCONFIRMED) {
            // set timestamp 0 to mark tx as unverified
            _BRPeerManagerUpdateTx(manager, &txHash, 1, TX_UNCONFIRMED, 0);
        }

        // if we get rejected for any reason other than double-spend, the peer is likely misconfigured
        if (code != REJECT_SPENT && BRWalletAmountSentByTx(manager->wallet, tx) > 0) {
            for (size_t i = 0; i < tx->inCount; i++) { // check that all inputs are confirmed before dropping peer
                t = BRWalletTransactionForHash(manager->wallet, tx->inputs[i].txHash);
                if (! t || t->blockHeight != TX_UNCONFIRMED) continue;
                tx = NULL;
                break;
            }
            
            if (tx) _BRPeerManagerPeerMisbehavin(manager, peer);
        }
    }

    pthread_mutex_unlock(&manager->lock);
    if (manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
}

// reduce memory usage
// clear the tail that comes after 500 blocks.
// checkpoints will remain in the blocks-Set, until we are ahead of them.
static void _BRPeerManagerClearMemory(BRPeerManager* manager) {
    BRMerkleBlock* blockPtr = manager->lastBlock;
    UInt256 prevHash;
    size_t count = BRSetCount(manager->blocks);
    size_t i = 0;

    // BIP 158: never prune block headers at/above the compact-filter sync
    // frontier. The cfheaders driver computes a batch's stop hash by walking
    // prevBlock links from lastBlock down to that height; if those headers were
    // freed the chain can never catch up a cfTip deficit (the permanent
    // "no block hash for height H, deferring" stall). cfFloor tracks cfTip, so
    // once filters keep pace the retained span collapses back to the normal
    // tail. Zero in BLOOM_ONLY / no-chain so pruning behaves exactly as before.
    uint32_t cfFloor = 0;
    if (manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY) {
        if (manager->compactFilterChain) {
            uint32_t cfNext = BRCompactFilterChainNextHeight(manager->compactFilterChain);
            if (cfNext > CLEAR_MEM_CF_RETENTION_MARGIN) cfFloor = cfNext - CLEAR_MEM_CF_RETENTION_MARGIN;
            else if (cfNext > 0) cfFloor = 1;
        }
        else if (manager->autoFetchCFiltersEnabled && manager->autoFetchCFiltersStart > 0) {
            // Bootstrap: the compact-filter chain is created lazily on the FIRST
            // cfheaders RESPONSE. Until it exists, retain block headers at/above the
            // armed CF birth height so that first getcfheaders request can resolve
            // its stop hash. Without this the tail pruner frees the birth-height
            // block before the first request lands (header sync races ~80 blocks/sec
            // ahead while the birth may be 100k+ blocks below the tip); the stop hash
            // then becomes unresolvable, the driver defers forever, the chain is
            // never created, and pruning is never protected — a permanent "no block
            // hash for height H, deferring" deadlock on a fresh rescan. Once the
            // chain exists the cfNext branch above takes over and the retained span
            // collapses to the normal frontier window.
            uint32_t start = manager->autoFetchCFiltersStart;
            if (start > CLEAR_MEM_CF_RETENTION_MARGIN) cfFloor = start - CLEAR_MEM_CF_RETENTION_MARGIN;
            else cfFloor = 1;
        }
    }

    if (count >= CLEAR_MEM_BLOCKS_COUNT_TRIGGER) {
        // find the tail
        while (blockPtr && i++ <= (CLEAR_MEM_BLOCKS_COUNT_TRIGGER - CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN))
            blockPtr = BRSetGet(manager->blocks, &blockPtr->prevBlock);

        if (blockPtr) {
            prevHash = blockPtr->prevBlock;

            // clear the tail
            while (blockPtr && !UInt256IsZero(prevHash)) {

                // get the block
                blockPtr = BRSetGet(manager->blocks, &prevHash);
                if (!blockPtr) break;

                // get previous hash
                prevHash = blockPtr->prevBlock;

                // BIP 158: keep everything at/above the compact-filter frontier
                // so cfheaders can walk back to it. Heights descend as we walk,
                // so once we drop below cfFloor every remaining block is too —
                // but `continue` (not break) keeps the loop robust to any
                // non-monotonic ordering in the set.
                if (cfFloor > 0 && blockPtr->height >= cfFloor) continue;

                // remove the current block
                if (BRSetRemove(manager->blocks, blockPtr)) {
                    // free the actual memory
                    BRMerkleBlockFree(blockPtr);
                } else {
                    // nothing to remove
                    break;
                }
            }

            debug_log("[MEMORY]: Blocks reduced from %ld to %ld blocks\n", count, BRSetCount(manager->blocks));
        }
    }
}

static int _BRPeerManagerVerifyBlock(BRPeerManager *manager, BRMerkleBlock *block, BRMerkleBlock *prev, BRPeer *peer)
{
    uint32_t transitionTime = 0;
    int r = 1;
    
    // check if we hit a difficulty transition, and find previous transition time
    BRMerkleBlock *b = manager->lastBlock;
    UInt256 prevBlock;

    if (! b) {
        peer_log(peer, "missing previous difficulty tansition time, can't verify blockHash: %s",
                 u256hex(block->blockHash));
        r = 0;
    }
    else {
        transitionTime = b->timestamp;
        prevBlock = b->prevBlock;
    }

    // verify block difficulty
    if (r && ! manager->params->verifyDifficulty(block, prev, transitionTime)) {
        peer_log(peer, "relayed block with invalid difficulty target %x, blockHash: %s", block->target,
                 u256hex(block->blockHash));
        r = 0;
    }
    
    if (r) {
        BRMerkleBlock *checkpoint = BRSetGet(manager->checkpoints, block);

        // verify blockchain checkpoints
        if (checkpoint && ! BRMerkleBlockEq(block, checkpoint)) {
            peer_log(peer, "relayed a block that differs from the checkpoint at height %"PRIu32", blockHash: %s, "
                     "expected: %s", block->height, u256hex(block->blockHash), u256hex(checkpoint->blockHash));
            r = 0;
        }
    }

    return r;
}

// Serialize a set of saved blocks into the flat persistence buffer WHILE THE
// CALLER HOLDS manager->lock. Format (unchanged — the Kotlin onSaveBlocks parser
// relies on it): [u32 count][ per block: u32 serLen, u32 height, serLen bytes ].
// Doing this here, before the lock is released, is what closes the lock-release-
// then-use UAF: a concurrent reorg (BRSetRemove + BRMerkleBlockFree) cannot free
// a block mid-serialize because we still hold the lock, so no manager-owned block
// pointer is dereferenced after the unlock — only the returned flat bytes cross
// the JNI boundary. malloc'd (NOT a VLA: worst case ~24KB of headers, up to
// ~219KB one-time for legacy full merkleblocks); caller frees after the callback.
// Returns NULL (and *outLen = 0) on empty input or alloc failure.
static uint8_t *_serializeSavedBlocks(BRMerkleBlock *blocks[], size_t count, size_t *outLen)
{
    *outLen = 0;
    if (count == 0 || ! blocks) return NULL;

    size_t totalSize = 4; // leading u32 block count
    size_t *sizes = malloc(count * sizeof(size_t));
    if (! sizes) return NULL;
    for (size_t i = 0; i < count; i++) {
        sizes[i] = BRMerkleBlockSerialize(blocks[i], NULL, 0);
        totalSize += 4 + 4 + sizes[i]; // serLen + height + data
    }

    uint8_t *buf = malloc(totalSize);
    if (! buf) { free(sizes); return NULL; }

    size_t pos = 0;
    UInt32SetLE(&buf[pos], (uint32_t)count); pos += 4;
    for (size_t i = 0; i < count; i++) {
        UInt32SetLE(&buf[pos], (uint32_t)sizes[i]); pos += 4;
        UInt32SetLE(&buf[pos], blocks[i]->height);  pos += 4;
        BRMerkleBlockSerialize(blocks[i], &buf[pos], sizes[i]);
        pos += sizes[i];
    }
    free(sizes);
    *outLen = pos;
    return buf;
}

static void _peerRelayedBlock(void *info, BRMerkleBlock *block)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    size_t txCount = BRMerkleBlockTxHashes(block, NULL, 0);
    UInt256 _txHashes[(sizeof(UInt256)*txCount <= 0x1000) ? txCount : 0],
            *txHashes = (sizeof(UInt256)*txCount <= 0x1000) ? _txHashes : malloc(txCount*sizeof(*txHashes));
    size_t i, saveCount = 0;
    BRMerkleBlock orphan, *b, *b2, *prev, *next = NULL;
    uint32_t txTime = 0;
    
    assert(txHashes != NULL);
    txCount = BRMerkleBlockTxHashes(block, txHashes, txCount);
    
    pthread_mutex_lock(&manager->lock);
    prev = BRSetGet(manager->blocks, &block->prevBlock);

    if (prev) {
        txTime = block->timestamp/2 + prev->timestamp/2;
        block->height = prev->height + 1;
    }
    
    // Bloom filter false-positive-rate tracking (fpCount/averageTxPerBlock/fpRate)
    // removed along with the bloom filter fields themselves. `i` stays declared
    // above; it is reused by the save-blocks loop further down in this function.

    // ignore block headers that are newer than one week before earliestKeyTime (it's a header if it has 0 totalTx)
    if (manager->syncMode != BR_SYNC_MODE_COMPACT_FILTERS_ONLY &&
        block->totalTx == 0 && block->timestamp + 7*24*60*60 > manager->earliestKeyTime + 2*60*60) {
        BRMerkleBlockFree(block);
        block = NULL;
    }
    // Bloom bailout branch removed (CF-only: compact-only keeps bloomFilter==NULL
    // by design, so `manager->syncMode != COMPACT_FILTERS_ONLY && bloomFilter==NULL`
    // never fires in this mode; it guarded a bloom-mode-only re-request path).
    else if (! prev) { // block is an orphan
        peer_log(peer, "relayed orphan block %s, previous %s, last block is %s, height %"PRIu32,
                 log_u256_hex_encode(block->blockHash), log_u256_hex_encode(block->prevBlock), log_u256_hex_encode(manager->lastBlock->blockHash),
                 manager->lastBlock->height);
        
        if (block->timestamp + 7*24*60*60 < time(NULL)) { // ignore orphans older than one week ago
            BRMerkleBlockFree(block);
            block = NULL;
        }
        else {
            // Re-anchor to recover from a stale/minority (orphaned) tip. An orphan
            // whose parent isn't in our chain means our tip may be on a fork the
            // network abandoned; the connecting header sits BELOW the fork point, so
            // re-request with the FULL exponential block locators (which include shared
            // ancestors below the fork). A correct peer answers with the connecting
            // header, the stored orphans cascade-connect, and the reorg promotes the
            // main chain.
            //
            // This was previously gated on `lastBlock->height >= BRPeerLastBlock(peer)`,
            // which is FALSE exactly when we're BEHIND — i.e. the reorg case — so a
            // wallet stranded on an orphaned tip while behind the network NEVER
            // re-anchored and wedged forever (the CF-only forward-only getheaders
            // continuation in BRPeer.c only ever walks toward the tip, never back to the
            // fork). The bloom path used to self-heal forks via its inv/getblocks/
            // merkleblock machinery, excised in v4.0.0 — this restores the equivalent
            // for CF-only. Drop the precondition; keep the lastOrphan/prevBlock dedup as
            // the throttle so only the FIRST orphan of each new orphan-chain triggers a
            // request (no storm). Use getheaders, not the dead getblocks/inv detour —
            // CF-only pulls plain headers (mirrors the sync-start path above).
            if (! manager->lastOrphan || ! UInt256Eq(manager->lastOrphan->blockHash, block->prevBlock)) {
                UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
                size_t locatorsCount = _BRPeerManagerBlockLocators(manager, locators,
                                                                   sizeof(locators)/sizeof(*locators));

                peer_log(peer, "orphan re-anchor: getheaders with %zu locators (walk back to reorg)", locatorsCount);
                BRPeerSendGetheaders(peer, locators, locatorsCount, UINT256_ZERO);
            }

            BRSetAdd(manager->orphans, block); // BUG: limit total orphans to avoid memory exhaustion attack
            manager->lastOrphan = block;
        }
    }
    else if (! _BRPeerManagerVerifyBlock(manager, block, prev, peer)) { // block is invalid
        peer_log(peer, "relayed invalid block");
        BRMerkleBlockFree(block);
        block = NULL;
        _BRPeerManagerPeerMisbehavin(manager, peer);
    }
    else if (UInt256Eq(block->prevBlock, manager->lastBlock->blockHash)) { // new block extends main chain
        if ((block->height % 500) == 0 || txCount > 0 || block->height >= BRPeerLastBlock(peer)) {
            peer_log(peer, "adding block #%"PRIu32, block->height);
        }
        
        BRSetAdd(manager->blocks, block);
        manager->lastBlock = block;

        // Kick cfheaders driver — on fresh-boot the autoFetchCFiltersStart
        // height may sit above the checkpoint, so OnFilterCapablePeerConnected
        // saw tip<start and bailed. Each block that advances lastBlock gives
        // the driver another chance; it self-no-ops once caught up.
        if (manager->autoFetchCFiltersEnabled &&
            manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY) {
            BRPeer *fp = _BRPeerManagerAnyFilterCapablePeer(manager);
            if (fp) _BRPeerManagerRequestNextCFHeaders(manager, fp);
        }

        // clear some memory
        _BRPeerManagerClearMemory(manager);
        
        if (txCount > 0) _BRPeerManagerUpdateTx(manager, txHashes, txCount, block->height, txTime);
        if (manager->downloadPeer) BRPeerSetCurrentBlockHeight(manager->downloadPeer, block->height);
            
        if (block->height < manager->estimatedHeight && peer == manager->downloadPeer) {
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT); // reschedule sync timeout
            manager->connectFailureCount = 0; // reset failure count once we know our initial request didn't timeout
        }
        
        if ((block->height % SAVE_BLOCK_INTERVAL) == 0)
            saveCount = SAVE_BLOCK_COUNT; // save transition block immediately
        
        if (block->height == manager->estimatedHeight) { // chain download is complete
            saveCount = SAVE_BLOCK_COUNT;
            _BRPeerManagerLoadMempools(manager);
        }
    }
    else if (BRSetContains(manager->blocks, block)) { // we already have the block (or at least the header)
        if ((block->height % 500) == 0 || txCount > 0 || block->height >= BRPeerLastBlock(peer)) {
            peer_log(peer, "relayed existing block #%"PRIu32, block->height);
        }
        
        b = manager->lastBlock;
        while (b && b->height > block->height)
            b = BRSetGet(manager->blocks, &b->prevBlock); // is block in main chain?
        
        // b == NULL means the walk ran off the bottom of the resident set (see the
        // same guard in _peerRelayedBlockTxns): we cannot prove `block` is on the main
        // chain, so skip the height stamping rather than deref NULL in BRMerkleBlockEq.
        if (b && BRMerkleBlockEq(b, block)) { // if it's not on a fork, set block heights for its transactions
            if (txCount > 0) _BRPeerManagerUpdateTx(manager, txHashes, txCount, block->height, txTime);
            if (block->height == manager->lastBlock->height) manager->lastBlock = block;
        }
        
        b = BRSetAdd(manager->blocks, block);
        
        // check if another block with equal hash existed
        if (b != block) {
            // remove the block from orphans, if it exists
            if (BRSetGet(manager->orphans, b) == b) BRSetRemove(manager->orphans, b);
            if (manager->lastOrphan == b) manager->lastOrphan = NULL;
            BRMerkleBlockFree(b);
        }
    }
    else if (manager->lastBlock->height < BRPeerLastBlock(peer) &&
             block->height > manager->lastBlock->height + 1) { // special case, new block mined durring rescan
        peer_log(peer, "marking new block #%"PRIu32" as orphan until rescan completes", block->height);
        BRSetAdd(manager->orphans, block); // mark as orphan til we're caught up
        manager->lastOrphan = block;
    }
    else if (block->height <= manager->params->checkpoints[manager->params->checkpointsCount - 1].height) { // old fork
        peer_log(peer, "ignoring block on fork older than most recent checkpoint, block #%"PRIu32", hash: %s",
                 block->height, u256hex(block->blockHash));
        BRMerkleBlockFree(block);
        block = NULL;
    }
    else { // new block is on a fork
        peer_log(peer, "chain fork reached height %"PRIu32, block->height);
        BRSetAdd(manager->blocks, block);

        if (block->height > manager->lastBlock->height) { // check if fork is now longer than main chain
            b = block;
            b2 = manager->lastBlock;
            
            while (b && b2 && ! BRMerkleBlockEq(b, b2)) { // walk back to where the fork joins the main chain
                b = BRSetGet(manager->blocks, &b->prevBlock);
                if (b && b->height < b2->height) b2 = BRSetGet(manager->blocks, &b2->prevBlock);
            }
            
            // The loop condition guards b/b2 but these uses did not: the walk exits
            // with b == NULL when the fork's join point is not in the resident set —
            // reachable on any wallet, because the checkpoint stubs seeded by
            // BRPeerManagerNewEx have a zero prevBlock that terminates the walk far
            // below the retained window. No join point means no known height to roll
            // back to, so the un-confirm is skipped; the longer fork is still adopted
            // below, which is the safe direction (at worst a tx confirmed on the
            // abandoned branch keeps a stale height until it is re-relayed or the
            // chain is reconciled).
            if (b) {
                peer_log(peer, "reorganizing chain from height %"PRIu32", new height is %"PRIu32, b->height, block->height);

                BRWalletSetTxUnconfirmedAfter(manager->wallet, b->height); // mark tx after the join point as unconfirmed
            }
            else {
                peer_log(peer, "reorg fork-join point is not in the resident block set — adopting the longer "
                         "fork at height %"PRIu32" without a confirmation roll-back", block->height);
            }

            b = block;
        
            while (b && b2 && b->height > b2->height) { // set transaction heights for new main chain
                size_t count = BRMerkleBlockTxHashes(b, NULL, 0);
                uint32_t height = b->height, timestamp = b->timestamp;
                
                if (count > txCount) {
                    txHashes = (txHashes != _txHashes) ? realloc(txHashes, count*sizeof(*txHashes)) :
                               malloc(count*sizeof(*txHashes));
                    assert(txHashes != NULL);
                    txCount = count;
                }
                
                count = BRMerkleBlockTxHashes(b, txHashes, count);
                b = BRSetGet(manager->blocks, &b->prevBlock);
                if (b) timestamp = timestamp/2 + b->timestamp/2;
                if (count > 0) BRWalletUpdateTransactions(manager->wallet, txHashes, count, height, timestamp);
            }
        
            if (block)
            manager->lastBlock = block;
            
            if (block->height == manager->estimatedHeight) { // chain download is complete
                saveCount = SAVE_BLOCK_COUNT;
                _BRPeerManagerLoadMempools(manager);
            }
        }
    }
   
    if (txHashes != _txHashes) free(txHashes);
   
    if (block && block->height != BLOCK_UNKNOWN_HEIGHT) {
        if (block->height > manager->estimatedHeight) manager->estimatedHeight = block->height;
        
        // check if the next block was received as an orphan
        orphan.prevBlock = block->blockHash;
        next = BRSetRemove(manager->orphans, &orphan);
    }
    
    BRMerkleBlock* saveBlocks[saveCount]; // zero length arrays are allowed in C standard
    memset(&saveBlocks[0], 0, saveCount * sizeof(BRMerkleBlock*));
    
    for (i = 0, b = block; b && i < saveCount; i++) {
        if (b->height != BLOCK_UNKNOWN_HEIGHT) {
            saveBlocks[i] = b;
            b = BRSetGet(manager->blocks, &b->prevBlock);
        }
    }


    // Refresh the lock-free UI status mirrors before releasing the lock. This is the
    // hot path (runs on every relayed block) so it keeps height/estimate/peer-count/
    // cfTip current for the overlay without the UI ever taking manager->lock.
    _BRPeerManagerRefreshCachedStatus(manager);

    /* Serialize the saved blocks to a flat byte buffer WHILE HOLDING THE LOCK.
     * The saveBlocks[] entries are live pointers into manager->blocks, which a
     * concurrent peer thread's reorg can free; serializing here — before the
     * unlock, not in the callback after it — is the fix for the lock-release-
     * then-use UAF. Only the immutable bytes cross the unlock in THE SAVE PATH —
     * no saveBlocks[]/manager->blocks pointer is serialized after the lock drops.
     * (NB: the pre-existing `block->height` read below at the txStatusUpdate gate
     * is the SAME UAF class but predates this fix and its exposure is unchanged —
     * out of scope here; tracked as a follow-up.) */
    uint8_t *saveBuf = NULL;
    size_t   saveLen = 0;
    if (i > 0 && manager->saveBlocks) {
        debug_log("[STATS]: orphan_count = %ld, block_count = %ld\n", BRSetCount(manager->orphans), BRSetCount(manager->blocks));
        saveBuf = _serializeSavedBlocks(saveBlocks, i, &saveLen); // malloc'd under the lock
    }

    pthread_mutex_unlock(&manager->lock);

    /* Hand the immutable BYTES to the (lock-free) JNI upcall, then free them. */
    if (saveBuf) {
        manager->saveBlocks(manager->info, REPLACE_SAVED_BLOCKS, saveBuf, saveLen, (uint64_t*) &stackIntegrityCheck);
        free(saveBuf);
    }
    
    if (block && block->height != BLOCK_UNKNOWN_HEIGHT && block->height >= BRPeerLastBlock(peer) &&
        manager->txStatusUpdate) {
        manager->txStatusUpdate(manager->info); // notify that transaction confirmations may have changed
    }
    
    if (next) _peerRelayedBlock(info, next);
}

// Confirms wallet txs delivered via a compact-filter-driven full "block" message (see BRPeer.c
// _BRPeerAcceptBlockMessage). Chain extension for the block itself is handled entirely by the
// regular headers/merkleblock path (_peerRelayedBlock above); this handler only fires once that
// block's header is already known, so it can attach a confirmation height/timestamp to the txs.
static void _peerRelayedBlockTxns(void *info, UInt256 blockHash, const UInt256 txHashes[], size_t txCount)
{
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRMerkleBlock *b, *b2;
    int confirmed = 0;

    if (txCount == 0) return;

    pthread_mutex_lock(&manager->lock);
    b = BRSetGet(manager->blocks, &blockHash);

    if (! b) { // header not synced yet; the block will be re-requested/re-relayed once it is
        // Observe-only (Phase 1): record the wallet txs against this not-yet-connected
        // block so a pending-confirm hole is visible. Record only — do NOT drain.
        BRCFScanLedgerRecordPending(&manager->cfLedger, blockHash, txHashes, txCount, (uint32_t)time(NULL));
        debug_log("cf-ledger: pending-confirm hole — recorded %zu wallet tx(s) for not-yet-connected block %s\n",
                  txCount, log_u256_hex_encode(blockHash));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    b2 = manager->lastBlock;
    while (b2 && b2->height > b->height) b2 = BRSetGet(manager->blocks, &b2->prevBlock); // is block in main chain?

#ifdef RELAYEDBLOCKTXNS_MAINCHAIN_NULLGUARD_UNFIXED
    // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a production
    // build). b2 was assumed resident, so BRMerkleBlockEq derefs NULL. This is the
    // shape test4 in cf_confirm_kat crashes on (== RED).
    if (! BRMerkleBlockEq(b2, b)) { // block is on a fork, not the main chain; don't confirm against it
        pthread_mutex_unlock(&manager->lock);
        return;
    }
#else
    // b2 == NULL means the walk ran off the bottom of the resident block set before
    // reaching b's height: b is below everything we still hold, so we cannot prove it
    // is on the main chain. BRPeerManagerNewEx seeds every hardcoded checkpoint as a
    // stub into manager->blocks and never sets prevBlock, so each stub terminates the
    // walk at the zero hash while sitting millions of blocks below the retained
    // window — and this handler is not request-gated, so any peer we dial can name
    // one in an unsolicited "block" message. BRMerkleBlockEq (BRMerkleBlock.h) derefs
    // BOTH arguments, so reaching it with a NULL b2 is a remote NULL-deref crash.
    // Unprovable-main-chain is exactly as unconfirmable as on-a-fork, so both take
    // the same bail-out.
    if (! b2 || ! BRMerkleBlockEq(b2, b)) { // on a fork, or below the resident set; don't confirm against it
        pthread_mutex_unlock(&manager->lock);
        return;
    }
#endif

    UInt256 *walletHashes = malloc(txCount*sizeof(*walletHashes));
    size_t walletCount = 0;

    assert(walletHashes != NULL);

    for (size_t i = 0; i < txCount; i++) {
        if (BRWalletTransactionForHash(manager->wallet, txHashes[i])) walletHashes[walletCount++] = txHashes[i];
    }

    if (walletCount > 0) {
        _BRPeerManagerUpdateTx(manager, walletHashes, walletCount, b->height, b->timestamp);
        confirmed = 1;
    }

    free(walletHashes);
    pthread_mutex_unlock(&manager->lock);

    // notify outside the lock, matching _peerRelayedBlock's txStatusUpdate call below
    if (confirmed && manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
}

// CF-only new-tip driver. In COMPACT_FILTERS_ONLY the wallet loads no bloom filter and
// syncs headers with getheaders (never getblocks), so once caught up the only signal that
// the chain advanced is a block `inv`. _BRPeerAcceptInvMessage forwards each announced
// block hash here; we pull plain headers from our current tip so the new header connects
// via _peerRelayedBlock (which re-kicks the cfheaders/cfilter driver and, on a wallet
// match, the confirmation path). No-op if we already have the header, the peer dropped,
// or we're not in CF-only (BLOOM_ONLY/BOTH use the inv -> getdata(merkleblock) path).
static void _peerRelayedBlockInv(void *info, UInt256 blockHash)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);

    if (manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY && manager->lastBlock &&
        BRPeerConnectStatus(peer) == BRPeerStatusConnected &&
        ! BRSetGet(manager->blocks, &blockHash)) { // header not yet known — pull it from our tip
        UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
        size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));

        peer_log(peer, "cf-only: block inv %s — requesting headers from tip %"PRIu32,
                 log_u256_hex_encode(blockHash), manager->lastBlock->height);
        BRPeerSendGetheaders(peer, locators, count, UINT256_ZERO);
    }

    pthread_mutex_unlock(&manager->lock);
}

static void _peerDataNotfound(void *info, const UInt256 txHashes[], size_t txCount,
                             const UInt256 blockHashes[], size_t blockCount)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);

    for (size_t i = 0; i < txCount; i++) {
        _BRTxPeerListRemovePeer(manager->txRelays, txHashes[i], peer);
        _BRTxPeerListRemovePeer(manager->txRequests, txHashes[i], peer);
    }

    pthread_mutex_unlock(&manager->lock);
}

static void _peerSetFeePerKb(void *info, uint64_t feePerKb)
{
    BRPeer *p, *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    uint64_t maxFeePerKb = 0, secondFeePerKb = 0;
    
    pthread_mutex_lock(&manager->lock);
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) { // find second highest fee rate
        p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (BRPeerFeePerKb(p) > maxFeePerKb) secondFeePerKb = maxFeePerKb, maxFeePerKb = BRPeerFeePerKb(p);
    }
    
    if (secondFeePerKb*3/2 > DEFAULT_FEE_PER_KB && secondFeePerKb*3/2 <= MAX_FEE_PER_KB &&
        secondFeePerKb*3/2 > BRWalletFeePerKb(manager->wallet)) {
        peer_log(peer, "increasing feePerKb to %"PRIu64" based on feefilter messages from peers", secondFeePerKb*3/2);
        BRWalletSetFeePerKb(manager->wallet, secondFeePerKb*3/2);
    }

    pthread_mutex_unlock(&manager->lock);
}

//static void _peerRequestedTxPingDone(void *info, int success)
//{
//    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
//    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
//    UInt256 txHash = ((BRPeerCallbackInfo *)info)->hash;
//
//    free(info);
//    pthread_mutex_lock(&manager->lock);
//
//    if (success && ! _BRTxPeerListHasPeer(manager->txRequests, txHash, peer)) {
//        _BRTxPeerListAddPeer(&manager->txRequests, txHash, peer);
//        BRPeerSendGetdata(peer, &txHash, 1, NULL, 0); // check if peer will relay the transaction back
//    }
//    
//    pthread_mutex_unlock(&manager->lock);
//}

static BRTransaction *_peerRequestedTx(void *info, UInt256 txHash)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
//    BRPeerCallbackInfo *pingInfo;
    BRTransaction *tx = NULL;
    void *txInfo = NULL;
    void (*txCallback)(void *, int) = NULL;
    int hasPendingCallbacks = 0, error = 0;

    pthread_mutex_lock(&manager->lock);

    for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
        if (UInt256Eq(manager->publishedTxHashes[i - 1], txHash)) {
            tx = manager->publishedTx[i - 1].tx;
            txInfo = manager->publishedTx[i - 1].info;
            txCallback = manager->publishedTx[i - 1].callback;
            manager->publishedTx[i - 1].info = NULL;
            manager->publishedTx[i - 1].callback = NULL;
        
            if (tx && ! BRWalletTransactionIsValid(manager->wallet, tx)) {
                error = EINVAL;
                array_rm(manager->publishedTx, i - 1);
                array_rm(manager->publishedTxHashes, i - 1);
                
                if (! BRWalletTransactionForHash(manager->wallet, txHash)) {
                    BRTransactionFree(tx);
                    tx = NULL;
                }
            }
        }
        else if (manager->publishedTx[i - 1].callback != NULL) hasPendingCallbacks = 1;
    }

    // cancel tx publish timeout if no publish callbacks are pending, and syncing is done or this is not downloadPeer
    if (! hasPendingCallbacks && (manager->syncStartHeight == 0 || peer != manager->downloadPeer)) {
        BRPeerScheduleDisconnect(peer, -1); // cancel publish tx timeout
    }

    if (tx && ! error) {
        _BRTxPeerListAddPeer(&manager->txRelays, txHash, peer);
        BRWalletRegisterTransaction(manager->wallet, tx);
    }
    
//    pingInfo = calloc(1, sizeof(*pingInfo));
//    assert(pingInfo != NULL);
//    pingInfo->peer = peer;
//    pingInfo->manager = manager;
//    pingInfo->hash = txHash;
//    BRPeerSendPing(peer, pingInfo, _peerRequestedTxPingDone);
    pthread_mutex_unlock(&manager->lock);
    if (txCallback) txCallback(txInfo, error);
    return tx;
}

static int _peerNetworkIsReachable(void *info)
{
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    return (manager->networkIsReachable) ? manager->networkIsReachable(manager->info) : 1;
}

static void _peerThreadCleanup(void *info)
{
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);
    manager->peerThreadCount--;
    pthread_mutex_unlock(&manager->lock);
    
    free(info);
    if (manager->threadCleanup) manager->threadCleanup(manager->info);
}

static void _dummyThreadCleanup(void *info)
{
}

// returns a newly allocated BRPeerManager struct that must be freed by calling BRPeerManagerFree()
BRPeerManager *BRPeerManagerNew(const BRChainParams *params, BRWallet *wallet, uint32_t earliestKeyTime,
                                  BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount)
{
    return BRPeerManagerNewEx(params, wallet, earliestKeyTime, blocks, blocksCount, peers, peersCount, NULL);
}

// returns a newly allocated BRPeerManager struct that must be freed by calling BRPeerManagerFree()
BRPeerManager *BRPeerManagerNewEx(const BRChainParams *params, BRWallet *wallet, uint32_t earliestKeyTime,
                                BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startSyncFrom)
{
    BRPeerManager *manager = calloc(1, sizeof(*manager));
    BRMerkleBlock orphan, *block = NULL;
    
    assert(manager != NULL);
    assert(params != NULL);
    assert(wallet != NULL);
    assert(blocks != NULL || blocksCount == 0);
    assert(peers != NULL || peersCount == 0);
    // Born in the LIVE mode, not calloc's zero. BR_SYNC_MODE_BLOOM_ONLY is 0 for ABI
    // reasons, but BIP37 was excised in v4.0.0, so zero is a DEAD mode: a manager left in it
    // dials peers it can never CF-sync, times them out and penalizes each one, and wedges at
    // 0 peers until the process restarts (see the note at jni_peer.c's SetSyncMode call,
    // which is a shipped instance of exactly that). Every CF path also silently no-ops in
    // BLOOM_ONLY, so a missed SetSyncMode turns the whole compact-filter pipeline off
    // quietly rather than loudly. The JNI bridge re-applies the real mode on every manager
    // creation and that stays the source of truth; this only removes the dead-by-default
    // state so a caller that forgets degrades to "works" instead of "wedged".
    manager->syncMode = BR_SYNC_MODE_COMPACT_FILTERS_ONLY;
    manager->params = params;
    manager->wallet = wallet;
    manager->earliestKeyTime = earliestKeyTime;
    manager->maxConnectCount = PEER_MAX_CONNECTIONS;
    array_new(manager->peers, peersCount);
    if (peers)
        array_add_array(manager->peers, peers, peersCount);
    qsort(manager->peers, array_count(manager->peers), sizeof(*manager->peers), _peerTimestampCompare);
    array_new(manager->connectedPeers, PEER_MAX_CONNECTIONS);
    
    manager->blocks = BRSetNew(BRMerkleBlockHash, BRMerkleBlockEq, blocksCount);
    manager->orphans = BRSetNew(_BRPrevBlockHash, _BRPrevBlockEq, blocksCount); // orphans are indexed by prevBlock
    manager->checkpoints = BRSetNew(_BRBlockHeightHash, _BRBlockHeightEq, 100); // checkpoints are indexed by height
    manager->startSyncFrom = NULL;
    
    if (startSyncFrom) {
        manager->startSyncFrom = startSyncFrom;
        manager->earliestKeyTime = startSyncFrom->timestamp;
        BRSetAdd(manager->checkpoints, startSyncFrom);
        BRSetAdd(manager->blocks, startSyncFrom);
        manager->lastBlock = startSyncFrom;
    }
    
    for (size_t i = 0; i < manager->params->checkpointsCount; i++) {
        block = BRMerkleBlockNew();
        block->height = manager->params->checkpoints[i].height;
        block->blockHash = UInt256Reverse(manager->params->checkpoints[i].hash);
        block->timestamp = manager->params->checkpoints[i].timestamp;
        block->target = manager->params->checkpoints[i].target;
        
        BRSetAdd(manager->checkpoints, block);
        BRSetAdd(manager->blocks, block);
        
        if ((i == 0 && !startSyncFrom) || block->timestamp + 7*24*60*60 < manager->earliestKeyTime)
            manager->lastBlock = block;
    }
    
    block = NULL;
    
    for (size_t i = 0; blocks && i < blocksCount; i++) {
        
        // height must be saved/restored along with serialized block
        assert(blocks[i]->height != BLOCK_UNKNOWN_HEIGHT);
        
        // add to orphans
        BRSetAdd(manager->orphans, blocks[i]);

        // find last transition block
        if (!block || blocks[i]->height > block->height)
            block = blocks[i];
    }
    
    while (block) {
        BRSetAdd(manager->blocks, block);
        manager->lastBlock = block;
        orphan.prevBlock = block->prevBlock;
        BRSetRemove(manager->orphans, &orphan);
        orphan.prevBlock = block->blockHash;
        block = BRSetGet(manager->orphans, &orphan);
    }
    
    if (startSyncFrom) {
        manager->lastBlock = startSyncFrom;
    }
    
    printf("BITCOIN_TESTNET=%d\n", BITCOIN_TESTNET);
    
    printf("Starting sync from height: %d\n", manager->lastBlock->height);
    printf("Starting sync from timestamp: %d\n", manager->lastBlock->timestamp);
    
    array_new(manager->txRelays, 10);
    array_new(manager->txRequests, 10);
    array_new(manager->publishedTx, 10);
    array_new(manager->publishedTxHashes, 10);
    array_new(manager->dandelionPeers, 4);
    manager->dandelionEnabled = 1;   // default on; Kotlin overrides from the saved setting
    pthread_mutex_init(&manager->lock, NULL);
    manager->threadCleanup = _dummyThreadCleanup;
    // Initialize the lock-free UI status mirrors (safe here: manager is single-threaded
    // until Connect spawns peer threads). Without this the overlay reads 0 for
    // height/syncMode until the first block lands.
    _BRPeerManagerRefreshCachedStatus(manager);
    return manager;
}

// --- BIP 158 helpers ------------------------------------------------------
//
// All helpers below assume the caller holds manager->lock.

// Walk manager->lastBlock backwards via prevBlock until we reach `height`,
// returning the block hash at that height. Returns UINT256_ZERO if the
// height is outside the in-memory window. Bounded by the local chain
// length so it is at most O(chainLength).
static UInt256 _BRPeerManagerBlockHashAtHeight(BRPeerManager *manager, uint32_t height)
{
    BRMerkleBlock *b = manager->lastBlock;
    while (b && b->height > height) {
        b = BRSetGet(manager->blocks, &b->prevBlock);
    }
    if (b && b->height == height) return b->blockHash;
    return UINT256_ZERO;
}

// Returns 1 if the peer is eligible to serve BIP 158 messages given the
// manager's current sync mode, 0 otherwise.
static int _BRPeerManagerPeerSupportsCompactFilters(BRPeerManager *manager, BRPeer *peer)
{
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return 0;
    if (!peer) return 0;
    return (peer->services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS ? 1 : 0;
}

// Pick any connected filter-capable peer (returns NULL if none). Used
// to kick the cfheaders driver from non-peer-scoped contexts (e.g. when
// header sync catches up to the auto-fetch start height after a fresh
// boot). Caller must hold manager->lock.
static BRPeer *_BRPeerManagerAnyFilterCapablePeer(BRPeerManager *manager)
{
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (! BRPeerIsSocketOpen(p)) continue; // skip dead-socket zombie — don't hand the driver a dead peer
        if (_BRPeerManagerPeerSupportsCompactFilters(manager, p)) return p;
    }
    return NULL;
}

// Returns a connected filter-capable peer NOT already tried for the current
// cfheaders batch (i.e. not in manager->cfTriedPeers). This is how the driver
// cycles through ALL filter peers on successive timeouts instead of alternating
// two. Returns NULL when every connected filter peer has been tried. Caller must
// hold manager->lock.
static BRPeer *_BRPeerManagerNextUntriedFilterPeer(BRPeerManager *manager)
{
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (! BRPeerIsSocketOpen(p)) continue; // skip dead-socket zombie — rotate onto a live filter peer
        if (!_BRPeerManagerPeerSupportsCompactFilters(manager, p)) continue;
        int tried = 0;
        for (uint8_t k = 0; k < manager->cfTriedCount; k++) {
            if (UInt128Eq(manager->cfTriedPeers[k], p->address)) { tried = 1; break; }
        }
        if (!tried) return p;
    }
    return NULL;
}

// Self-heal for a cfheaders batch on which EVERY connected filter peer has stalled:
// disconnect the last-tried filter peer so the manager dials a fresh filter node in
// its place (what a manual app-restart used to do, but automatic). Dropping just one
// per stall round keeps the rest of the pool up while the set gradually refreshes.
// Caller must hold manager->lock (BRPeerDisconnect under the lock is the existing
// pattern in _peerConnected / _peerRelayedBlock; _peerDisconnected fires async).
static void _BRPeerManagerDropStalledFilterPeer(BRPeerManager *manager)
{
    if (UInt128IsZero(manager->cfHeadersPeerAddr)) return;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (UInt128Eq(p->address, manager->cfHeadersPeerAddr)) {
            peer_log(p, "cfheaders: whole filter set stalled on batch — dropping this peer to force a fresh one");
            BRPeerDisconnect(p);
            return;
        }
    }
}

// Drive the cfheaders fetch loop. Asks `peer` for the next batch
// starting at chain->NextHeight, capped at MAX_CFHEADERS_RESULTS and at
// the manager's known tip. No-op if the chain is already caught up or
// the peer is not filter-capable. If no chain exists yet, the first batch
// request runs anyway with startHeight=0 — the chain is created lazily in
// _peerRelayedCFHeaders when the response lands.
// If an in-flight cfheaders request gets no response within this many seconds
// (peer dropped, slow link), the serialization guard releases so another peer
// can retry the same batch.
// Self-clocked cfilter drive. MAX_INFLIGHT must be at least one full cfheaders batch
// (MAX_CFHEADERS_RESULTS) so a single cfheaders arrival can always be covered without the
// cursor falling behind — that shortfall is what used to grow unboundedly and freeze the
// scan. It is also kept at/below the ledger's outstanding capacity so the observe-only
// accounting stays intact rather than going lossy at saturation.
#define CF_FILTERS_MAX_INFLIGHT 2000u
// A window nobody answers must not wedge the driver forever. Generous relative to a normal
// batch round trip; the cursor has already advanced past the range, so the unanswered
// heights remain recorded ledger holes rather than being retried indefinitely.
#define CF_FILTERS_WINDOW_TIMEOUT_SECS 30

#define CF_HEADERS_REQUEST_TIMEOUT_SECS 5
// Tor circuits are slow to establish and high-latency; a 5s timeout mis-punishes
// a good-but-slow filter peer, churning peer rotation and forcing expensive
// circuit re-dials that push our thin fleet toward a 0-peer wedge. Widen the CF
// request timeout while a SOCKS proxy (Tor) is active. (R4, Neutrino review.)
#define CF_HEADERS_REQUEST_TIMEOUT_TOR_SECS 20
#define CF_REQUEST_TIMEOUT_SECS() (BRPeerHasSocksProxy() ? CF_HEADERS_REQUEST_TIMEOUT_TOR_SECS : CF_HEADERS_REQUEST_TIMEOUT_SECS)

static void _BRPeerManagerRequestNextCFHeaders(BRPeerManager *manager, BRPeer *peer)
{
    if (!_BRPeerManagerPeerSupportsCompactFilters(manager, peer)) return;
    if (!manager->lastBlock) return;

    // No chain yet → start from the configured wallet birth height (TOFU).
    // Genesis (next=0) would force a full-chain backfill we don't want.
    uint32_t next;
    if (manager->compactFilterChain) {
        next = BRCompactFilterChainNextHeight(manager->compactFilterChain);
    } else {
        next = manager->autoFetchCFiltersEnabled
               ? manager->autoFetchCFiltersStart
               : 0;
    }
    uint8_t filterType = manager->compactFilterChain
                         ? BRCompactFilterChainType(manager->compactFilterChain)
                         : FILTER_TYPE_BASIC;
    uint32_t tip = manager->lastBlock->height;
    if (next > tip) return; // already caught up

    // Serialize: if a batch covering `next` is already in flight and hasn't
    // timed out, don't send a duplicate. The driver is kicked on every
    // block-extend during the initial sync; without this it fires the same
    // [next..batchEnd] request at several filter peers, and the late
    // responses fail the continuity check (chain already moved) and get those
    // peers marked misbehavin' and disconnected — stalling cfheaders entirely.
    if (manager->cfHeadersRequestedThrough >= next &&
        (time(NULL) - manager->cfHeadersRequestTime) < CF_REQUEST_TIMEOUT_SECS()) {
        return;
    }

    // We got past the guard with a request already outstanding for this height only
    // if it timed out (the guard's < TIMEOUT arm is what would have returned). That
    // means the peer we last sent to never answered — rotate away from it below.
    int isTimeoutRetry = (manager->cfHeadersRequestedThrough >= next);

    // Advance the cfHEADER frontier in the SAME stride the cfILTER cursor can advance
    // in, not the larger wire maximum. This is the root cause of the permanent scan
    // freeze: the forward cfilter driver fires once per cfheaders arrival and requests at
    // most MAX_CFILTERS_RESULTS blocks, so asking for MAX_CFHEADERS_RESULTS (2000) here
    // shed ~1000 blocks of lag on EVERY round trip, by construction. The retention floor
    // is anchored to this frontier (cfNext - CLEAR_MEM_CF_RETENTION_MARGIN), so the lag
    // eventually put the headers the cursor still needed below the floor; once pruned,
    // the cursor's stop hash became unresolvable and it stopped advancing for good.
    // Matching the strides makes the lag non-growing: at most one in-flight batch.
    // cfheaders are 32 bytes per entry, so halving the batch costs round trips, not
    // bandwidth, and the cfheaders driver is not the bottleneck.
    // Full wire batch again. Capping this to MAX_CFILTERS_RESULTS was the stopgap that
    // stopped the cursor falling behind while forward fetching was clocked by, and limited
    // to, one batch per cfheaders arrival. _BRPeerManagerDriveCFiltersLocked now loops to
    // the validated frontier and is driven from three events, so it absorbs a full 2000
    // -header advance (CF_FILTERS_MAX_INFLIGHT >= MAX_CFHEADERS_RESULTS by construction) and
    // the stopgap would only be halving cfheaders throughput for nothing.
    uint32_t batchEnd = next + (MAX_CFHEADERS_RESULTS - 1);
    if (batchEnd > tip) batchEnd = tip;

    UInt256 stopHash = _BRPeerManagerBlockHashAtHeight(manager, batchEnd);
    if (UInt256IsZero(stopHash)) {
        // batchEnd is below the walkable block-header floor, so its hash can't be
        // resolved and the whole [next..batchEnd] batch is unreachable. This is the
        // post-rescan case: the rebuild armed the CF start (autoFetchCFiltersStart)
        // below the checkpoint the block-header chain actually anchored at. Headers
        // only walk back to their anchoring checkpoint — there is no block hash below
        // it — and CF scanning below the block floor is impossible anyway (no
        // in-memory block to match a filter against). So snap the CF start UP to the
        // resolvable block floor and retry, instead of busy-looping "no block hash for
        // height H, deferring" forever. The floor is <= the wallet's birth height
        // (the header chain anchors at the last checkpoint at/before wallet birth),
        // so this never skips a wallet transaction.
        uint32_t floor = _BRPeerManagerBlockFloor(manager);
        if (floor > next) {
            peer_log(peer, "cfheaders: CF start %u below block floor %u — snapping start up to floor",
                     next, floor);
            if (manager->compactFilterChain) {
                BRCompactFilterChainFree(manager->compactFilterChain);
                manager->compactFilterChain = NULL;
            }
            manager->autoFetchCFiltersEnabled  = 1;
            manager->autoFetchCFiltersStart    = floor;
            manager->autoFetchCFiltersThrough  = floor > 0 ? floor - 1 : 0;
            // Snap-up re-anchor rebuilds the CF scan-completeness ledger (Phase 1: observe-only).
            BRCFScanLedgerInit(&manager->cfLedger, floor);
#if CF_LEDGER_DRIVE_REREQUEST
            // Stale buffered raw filter bytes from the old floor must not survive a
            // floor change — Init already frees them internally, but this call is
            // explicit/defensive (Task 5 EDIT 4) so the invariant holds even if
            // Init's internals change.
            BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
            manager->cfHeadersRequestedThrough = 0;
            next     = floor;
            batchEnd = next + (MAX_CFHEADERS_RESULTS - 1);
            if (batchEnd > tip) batchEnd = tip;
            stopHash = _BRPeerManagerBlockHashAtHeight(manager, batchEnd);
        }
        if (UInt256IsZero(stopHash)) {
            peer_log(peer, "cfheaders: no block hash for height %u, deferring", batchEnd);
            return;
        }
    }

    // On a timeout retry, cycle to a filter peer we haven't tried yet for THIS batch.
    // The block-extend kick always hands us the same deterministic peer, so without
    // rotation one blackholing filter node pins cfheaders at a height forever. We track
    // every tried peer (cfTriedPeers) so successive timeouts walk through ALL connected
    // filter peers, not just alternate two. When the whole connected filter set has been
    // tried and none answered, self-heal: drop one stalled peer so a fresh filter node
    // connects, then start a new round. Falls back to `peer` if nothing better exists.
    BRPeer *reqPeer = peer;
    if (isTimeoutRetry) {
        if (!UInt128IsZero(manager->cfHeadersPeerAddr) &&
            manager->cfTriedCount < (uint8_t)(sizeof(manager->cfTriedPeers)/sizeof(manager->cfTriedPeers[0]))) {
            int present = 0;
            for (uint8_t k = 0; k < manager->cfTriedCount; k++) {
                if (UInt128Eq(manager->cfTriedPeers[k], manager->cfHeadersPeerAddr)) { present = 1; break; }
            }
            if (!present) manager->cfTriedPeers[manager->cfTriedCount++] = manager->cfHeadersPeerAddr;
        }

        BRPeer *alt = _BRPeerManagerNextUntriedFilterPeer(manager);
        if (!alt) {
            // Every connected filter peer tried, all stalled. Drop one for a fresh
            // peer ONLY while we'd keep a safe floor of filter peers — otherwise a
            // batch that NO peer can serve (e.g. a contested cfheaders range during a
            // rescan) turns a batch-level stall into a fleet-wipe: the drop primitive
            // has no min-peer guard, so it shreds one filter peer per full rotation
            // and drains the pool to 0, then oscillates 0↔few against the keepalive
            // forever. Below the floor, keep retrying on the survivors and let the
            // keepalive grow the pool back instead of racing a shredder.
            if (_BRPeerManagerConnectedFilterPeerCount(manager) > CF_MIN_FILTER_PEERS) {
                _BRPeerManagerDropStalledFilterPeer(manager);
                manager->cfTriedCount = 0;
                alt = _BRPeerManagerNextUntriedFilterPeer(manager);
            }
        }
        if (alt) {
            peer_log(alt, "cfheaders: rotating to untried filter peer for batch [%u..%u]", next, batchEnd);
            reqPeer = alt;
        }
    }

    if (!_BRPeerManagerPeerSupportsCompactFilters(manager, reqPeer)) return; // no usable filter peer this pass

    peer_log(reqPeer, "cfheaders: requesting [%u..%u] (%u headers)",
             next, batchEnd, batchEnd - next + 1);
    BRPeerSendGetCFHeaders(reqPeer, filterType, next, stopHash);
    manager->cfHeadersRequestedThrough = batchEnd;
    manager->cfHeadersRequestTime = time(NULL);
    manager->cfHeadersPeerAddr = reqPeer->address;
}

// On the FIRST continuity mismatch (one disagreer recorded, still below the
// re-anchor threshold), actively ask every OTHER connected filter peer about the
// SAME contested batch. Their responses are continuity-checked against our
// (divergent) tip too, so distinct disagreers accumulate to K within ~one round
// trip — instead of waiting for the driver to rotate peers, which it won't once a
// post-restore block rescan resets the block tip below cfTip and the driver goes
// dormant (next > tip). Each probe replays the exact getcfheaders the current
// peer just answered, so the replies align with our expected start height (the
// alignment guard in _peerRelayedCFHeaders rejects any that arrive after a
// re-anchor has already moved the chain). Peers already in the disagreed set are
// skipped, so this can't storm. Assumes manager->lock is held.
static void _BRPeerManagerProbeOtherFilterPeersForCFHeaders(BRPeerManager *manager, BRPeer *current,
                                                            uint8_t filterType, uint32_t startHeight,
                                                            UInt256 stopHash)
{
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerEq(p, current)) continue;
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (! _BRPeerManagerPeerSupportsCompactFilters(manager, p)) continue;

        int known = 0;
        for (uint8_t k = 0; k < manager->cfDisagreedCount; k++) {
            if (UInt128Eq(manager->cfDisagreedPeers[k], p->address)) { known = 1; break; }
        }
        if (known) continue;

        peer_log(p, "cfheaders: probing contested batch [%u..stop %s] to confirm divergence",
                 startHeight, log_u256_hex_encode(stopHash));
        BRPeerSendGetCFHeaders(p, filterType, startHeight, stopHash);
    }
}

// Consecutive diverged cfheaders rounds tolerated while only one filter peer is
// connected before forcing a re-anchor. With a single peer the K-distinct-
// disagreers path (CF_CONTINUITY_REANCHOR_K) can never fire — the probe loop
// reaches no other filter peer — so this is the escape hatch. Overall still
// bounded by CF_CONTINUITY_REANCHOR_MAX total re-anchors per session.
#define CF_SINGLE_PEER_REANCHOR_ROUNDS 3

// Count connected peers eligible to serve BIP 158 messages in the current sync
// mode. Mirrors the per-peer guards in the active-probe loop above
// (_BRPeerManagerProbeOtherFilterPeersForCFHeaders). Caller must hold manager->lock.
static int _BRPeerManagerConnectedFilterPeerCount(BRPeerManager *manager)
{
    int n = 0;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (! _BRPeerManagerPeerSupportsCompactFilters(manager, p)) continue;
        n++;
    }
    return n;
}

// --- BIP 158 peer callbacks -----------------------------------------------

static void _peerRelayedCFHeaders(void *info, uint8_t filterType, UInt256 stopHash,
                                  UInt256 prevFilterHeader,
                                  const UInt256 *filterHashes, size_t count)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);

    // Height-alignment guard. Compute the block height this batch claims to cover
    // (stop height − count + 1) and compare it to where our chain expects the next
    // batch to begin. This rejects responses that don't line up — in particular a
    // stale active-probe reply for the OLD contested range that lands AFTER a
    // re-anchor has already moved the chain start down to the block floor; without
    // this it would lazily anchor a fresh chain at the floor but fill it with the
    // contested range's filter hashes, mislabeling their heights. We only enforce
    // the guard when the stop block is known and the batch is non-empty; otherwise
    // we fall through to the existing continuity logic unchanged.
    {
        BRMerkleBlock *stopBlock = BRSetGet(manager->blocks, &stopHash);
        if (stopBlock && count > 0 && (uint32_t)stopBlock->height + 1 >= (uint32_t)count) {
            uint32_t batchStart = (uint32_t)stopBlock->height - (uint32_t)count + 1;
            uint32_t expectedStart = manager->compactFilterChain
                                     ? BRCompactFilterChainNextHeight(manager->compactFilterChain)
                                     : (manager->autoFetchCFiltersEnabled
                                        ? manager->autoFetchCFiltersStart : 0);
            if (batchStart != expectedStart) {
                peer_log(peer, "cfheaders: batch start %u != expected %u — stale/misaligned, ignoring",
                         batchStart, expectedStart);
                // Clear the in-flight marker (as the continuity-mismatch path below
                // does) so the next driver tick issues a FRESH request for the
                // expected height instead of seeing cfHeadersRequestedThrough still
                // set, treating it as a timeout-retry, and rotating the SAME
                // (unservable) batch forever.
                manager->cfHeadersRequestedThrough = 0;
                pthread_mutex_unlock(&manager->lock);
                return;
            }
        }
    }

    // Lazily allocate the chain on the first batch if persistence hadn't
    // restored one yet. Anchor TOFU-style at the wallet birth height with
    // the peer's claimed prevFilterHeader; Append() then succeeds because
    // the anchor it checks against equals the value we just stored.
    if (!manager->compactFilterChain) {
        uint32_t startHeight = manager->autoFetchCFiltersEnabled
                               ? manager->autoFetchCFiltersStart
                               : 0;
        manager->compactFilterChain = BRCompactFilterChainNew(filterType, startHeight, prevFilterHeader);
    }

    if (filterType != BRCompactFilterChainType(manager->compactFilterChain)) {
        peer_log(peer, "cfheaders: ignoring filter type %u (chain type %u)",
                 (unsigned)filterType, (unsigned)BRCompactFilterChainType(manager->compactFilterChain));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    int ok = BRCompactFilterChainAppend(manager->compactFilterChain, prevFilterHeader, filterHashes, count);

    // R1 (Neutrino review) — OBSERVE-MODE filter-header checkpoint cross-check.
    // The chain now covers the freshly-appended batch; compare any hardcoded
    // filter-header checkpoint that falls inside this batch against the wallet's
    // own computed header. OBSERVE ONLY: log MATCH/MISMATCH, never reject or ban.
    // This proves the compiled checkpoint data + byte order against honest chains
    // in the wild before Phase 2 turns it into enforced trust (reject+ban on
    // mismatch, gate single-peer re-anchor). Mainnet-only — the table is DGB
    // mainnet filter-headers; applying it on testnet would falsely mismatch.
    if (ok && manager->params->standardPort == BRMainNetParams.standardPort) {
        uint32_t newTip = BRCompactFilterChainStartHeight(manager->compactFilterChain) +
                          (uint32_t)BRCompactFilterChainCount(manager->compactFilterChain) - 1;
        uint32_t batchStart = ((uint32_t)count <= newTip) ? (newTip - (uint32_t)count + 1) : 0;
        for (size_t ci = 0; ci < BRMainNetCFCheckpointsCount; ci++) {
            uint32_t h = BRMainNetCFCheckpoints[ci].height;
            if (h < batchStart || h > newTip) continue;
            UInt256 computed = BRCompactFilterChainHeader(manager->compactFilterChain, h);
            if (UInt256Eq(computed, BRMainNetCFCheckpoints[ci].filterHeader)) {
                peer_log(peer, "cf-checkpoint: height %u MATCH (observe)", h);
            } else {
                // Separate calls: log_u256_hex_encode may reuse a static buffer.
                peer_log(peer, "cf-checkpoint: height %u *** MISMATCH (observe) *** computed=%s",
                         h, log_u256_hex_encode(computed));
                peer_log(peer, "cf-checkpoint: height %u *** MISMATCH (observe) *** pinned=%s",
                         h, log_u256_hex_encode(BRMainNetCFCheckpoints[ci].filterHeader));
            }
        }
    }

    if (!ok) {
        // Record this peer as one that disagrees with our tip (dedup by address).
        // Do NOT mark it misbehavin'/disconnect — if the majority disagrees, the
        // honest peers are right and OUR chain is the divergent outlier.
        int _known = 0;
        for (uint8_t i = 0; i < manager->cfDisagreedCount; i++) {
            if (UInt128Eq(manager->cfDisagreedPeers[i], peer->address)) { _known = 1; break; }
        }
        if (!_known && manager->cfDisagreedCount < CF_CONTINUITY_REANCHOR_K) {
            manager->cfDisagreedPeers[manager->cfDisagreedCount++] = peer->address;
        }
        manager->cfHeadersRequestedThrough = 0;  // let another peer be tried

        // Below the re-anchor threshold: actively probe the OTHER filter peers about
        // this same contested batch so distinct disagreers accumulate to K.
        //
        // Re-fire on EVERY mismatch while below K — not only on the first (fresh add).
        // The disagreeing peer is usually the priority peer (digiscope.me), which
        // connects first; the seeder's other filter peers finish their handshake a
        // few seconds LATER. A one-shot probe (gated on the fresh add) therefore loops
        // over a peer list that holds no other filter peer yet, reaches nobody, and the
        // count wedges at 1/K until an unrelated rescan resets it ~tens of minutes on.
        // Re-probing each round catches those peers the moment they connect. The probe
        // skips peers already in the disagreed set and we only reach here once per
        // cfheaders round-trip (the request is serialized), so it can't storm.
        if (manager->cfDisagreedCount < CF_CONTINUITY_REANCHOR_K) {
            _BRPeerManagerProbeOtherFilterPeersForCFHeaders(manager, peer, filterType,
                                                            BRCompactFilterChainNextHeight(manager->compactFilterChain),
                                                            stopHash);
        }

        if (manager->cfDisagreedCount >= CF_CONTINUITY_REANCHOR_K &&
            manager->cfReanchorCount < CF_CONTINUITY_REANCHOR_MAX) {
            manager->cfReanchorCount++;
            peer_log(peer, "cfheaders: %u peers disagree with our tip — chain is the outlier, "
                     "re-anchoring (attempt %u/%u)",
                     manager->cfDisagreedCount, manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
            _BRPeerManagerReanchorAtFloorLocked(manager, 1);
            pthread_mutex_unlock(&manager->lock);
            return;
        }

        // Single-filter-peer escape hatch. Runs only if the K-distinct-disagreers
        // path above did NOT fire. With a single connected filter peer that path can
        // never fire (the probe reaches no other filter peer, so cfDisagreedCount is
        // stuck at 1/K), and cfheaders would never advance — the wedge. Count
        // CONSECUTIVE diverged rounds instead; after N of them force a re-anchor,
        // still bounded by the same CF_CONTINUITY_REANCHOR_MAX total budget. A 1-peer
        // re-anchor may TOFU-accept a lying peer's chain, but bloom runs in parallel
        // (catches any missed tx), it's capped at MAX, and the watchdog falls back to
        // bloom after — acceptable for liveness. The moment a 2nd filter peer arrives
        // we prefer the safe K=2 path, so the round counter resets.
        if (_BRPeerManagerConnectedFilterPeerCount(manager) <= 1) {
            manager->cfSingleDisagreeRounds++;
            if (manager->cfSingleDisagreeRounds >= CF_SINGLE_PEER_REANCHOR_ROUNDS &&
                manager->cfReanchorCount < CF_CONTINUITY_REANCHOR_MAX) {
                manager->cfReanchorCount++;
                peer_log(peer, "cfheaders: single filter peer, %u rounds diverged — "
                         "forcing re-anchor (attempt %u/%u)",
                         manager->cfSingleDisagreeRounds,
                         manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
                _BRPeerManagerReanchorAtFloorLocked(manager, 1);
                pthread_mutex_unlock(&manager->lock);
                return;
            }
        } else {
            manager->cfSingleDisagreeRounds = 0;  // 2nd filter peer present → prefer K=2 path
        }

        // Below the K threshold, or re-anchor budget exhausted: don't append and
        // don't punish. If the budget is exhausted the chain stops advancing and
        // the SyncService watchdog falls back to bloom as today — pool never burned.
        peer_log(peer, "cfheaders: continuity mismatch (%u/%u disagree, reanchors %u/%u) — not appending",
                 manager->cfDisagreedCount, CF_CONTINUITY_REANCHOR_K,
                 manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    uint32_t chainTip = BRCompactFilterChainNextHeight(manager->compactFilterChain) - 1;
    // Mark the in-flight request satisfied through the actual new tip (a peer
    // may return fewer than MAX_CFHEADERS_RESULTS); the continuation below then
    // requests the next batch instead of being blocked by a stale guard value.
    manager->cfHeadersRequestedThrough = chainTip;
    manager->cfDisagreedCount = 0;   // appended cleanly — clear the disagreement window
    manager->cfSingleDisagreeRounds = 0;   // ...and the single-peer diverged-round counter
    manager->cfTriedCount = 0;       // batch advanced — fresh rotation round for the next one
    _recordCFServed(manager, peer);  // this peer answered cfheaders (positive CF-served signal)
    peer_log(peer, "cfheaders: chain extended to height %u (added %zu, stop %s)",
             chainTip, count, log_u256_hex_encode(stopHash));

    // ⚠️ LOCK-PLACEMENT INVARIANT (do NOT "optimize" by moving the unlock above this):
    // this hands the callback a LIVE manager-owned pointer (manager->compactFilterChain).
    // It is safe ONLY because manager->lock is still held here — the bridge copies the
    // chain into its own buffer under the lock and does not re-lock. Releasing the lock
    // before this call would make it byte-for-byte the saveBlocks lock-release-then-use
    // UAF (see _serializeSavedBlocks) on the CF header chain. The unlock MUST stay below.
    if (manager->saveFilterHeaders) {
        manager->saveFilterHeaders(manager->saveFilterHeadersInfo, manager->compactFilterChain);
    }

    // Persist the CF scan-completeness ledger alongside the filter headers. Size
    // first (NULL buf), then malloc + fill. Coalescing/throttling is the Kotlin
    // caller's job (same contract as saveFilterHeaders).
    if (manager->saveCFLedger) {
        size_t ledgerLen = BRCFScanLedgerSerialize(&manager->cfLedger, NULL, 0);
        uint8_t *ledgerBuf = (ledgerLen > 0) ? malloc(ledgerLen) : NULL;
        if (ledgerBuf) {
            size_t wrote = BRCFScanLedgerSerialize(&manager->cfLedger, ledgerBuf, ledgerLen);
            if (wrote == ledgerLen) manager->saveCFLedger(manager->saveCFLedgerInfo, ledgerBuf, ledgerLen);
            free(ledgerBuf);
        }
    }

    // Forward cfilter fetch. One call; the drive loops until the cursor reaches the
    // validated cfheader frontier or the in-flight window fills. It is also driven from
    // every cfilter arrival and from KeepAlive, so the pipeline is not clocked by this
    // event alone (see _BRPeerManagerDriveCFiltersLocked).
    _BRPeerManagerDriveCFiltersLocked(manager, peer);

    // Request the next batch if still behind the local block tip.
    _BRPeerManagerRequestNextCFHeaders(manager, peer);
    // cfheaders advanced — refresh cachedCFTip so the watchdog/overlay see progress
    // between blocks (cfheaders can climb faster than new blocks arrive).
    _BRPeerManagerRefreshCachedStatus(manager);
    pthread_mutex_unlock(&manager->lock);
}

// Drives forward cfilter fetching until the cursor reaches the validated cfheader
// frontier or the in-flight window is full. Caller holds manager->lock.
//
// WHY THIS IS A LOOP, AND WHY IT IS CALLED FROM THREE PLACES. Forward fetching used to
// happen at exactly ONE site — inline in _peerRelayedCFHeaders — issuing at most one batch
// per cfheaders arrival. That made the whole filter pipeline clocked by cfheaders alone, so
// when a peer stopped answering getcfheaders the filters stopped too, even though the peer
// loop was healthy and block headers kept arriving. Observed on device: cfilters stopped
// dead while headers advanced 23,739,000 -> 23,740,500 in 23 s, and the cfheaders driver sat
// on an unanswered request for minutes. Being clocked by a single upstream event is the
// defect; this is now driven by cfheaders arrival, by every cfilter arrival, and by the
// KeepAlive tick, so no single silent peer can stall it.
//
// The in-flight bound is a COUNT OF BLOCKS with a TIME-based retire, deliberately not a
// ledger predicate: the ledger is observe-only at this revision and its accounting goes
// lossy at saturation, so gating on it would couple liveness to diagnostics. A window that
// is never answered retires after CF_FILTERS_WINDOW_TIMEOUT_SECS so a silent peer cannot
// wedge the driver; the cursor has already advanced past that range, so the unanswered
// heights stay recorded as ledger holes rather than being retried forever.
static void _BRPeerManagerDriveCFiltersLocked(BRPeerManager *manager, BRPeer *preferred)
{
    if (! manager->autoFetchCFiltersEnabled) return;
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return;

    time_t now = time(NULL);

    // Retire a stale window FIRST, before any early return. Its whole purpose is to stop a
    // never-answered batch wedging the driver, so it must not be conditional on the filter
    // chain existing — a re-anchor that drops the chain while a window is in flight would
    // otherwise leave the count stuck at its old value forever.
    if (manager->cfFiltersInFlight > 0 &&
        (now - manager->cfFiltersWindowStart) >= CF_FILTERS_WINDOW_TIMEOUT_SECS) {
        // NB: `preferred` is NULL on the KeepAlive backstop path, and peer_log dereferences
        // its peer (BRPeerHost + ->port). Every log in this function must handle that.
        if (preferred) {
            peer_log(preferred, "cfilters: retiring a %u-block in-flight window unanswered after %llds",
                     manager->cfFiltersInFlight, (long long)(now - manager->cfFiltersWindowStart));
        }
        else {
            debug_log("cfilters: retiring a %u-block in-flight window unanswered after %llds\n",
                      manager->cfFiltersInFlight, (long long)(now - manager->cfFiltersWindowStart));
        }
        manager->cfFiltersInFlight = 0;
    }

    if (! manager->compactFilterChain) return;

    uint32_t cfNext = BRCompactFilterChainNextHeight(manager->compactFilterChain);
    if (cfNext == 0) return;

    uint32_t cfTip = cfNext - 1;   // highest height with a VALIDATED filter header

    while (manager->cfFiltersInFlight < CF_FILTERS_MAX_INFLIGHT) {
        uint32_t reqStart = manager->autoFetchCFiltersThrough + 1;
        if (reqStart < manager->autoFetchCFiltersStart) reqStart = manager->autoFetchCFiltersStart;
        if (reqStart > cfTip) break;                      // caught up to the validated frontier

        uint32_t reqStop = cfTip;
        if (reqStop > reqStart + (MAX_CFILTERS_RESULTS - 1)) {
            reqStop = reqStart + (MAX_CFILTERS_RESULTS - 1);
        }

        uint32_t sentStop = 0;
        size_t n = _BRPeerManagerRequestCFiltersLocked(manager, reqStart, reqStop, preferred, &sentStop);
        if (n == 0) break;   // no eligible peer, or unresolvable — that path logs its own reason

        // Advance to what was ACTUALLY requested: the range may have been snapped up past a
        // pruned band. Advancing to reqStop would leave the cursor below the resident floor
        // and re-request the same unresolvable range forever.
        if (sentStop > reqStop) reqStop = sentStop;
        manager->autoFetchCFiltersThrough = reqStop;

#if CF_LEDGER_DRIVE_REREQUEST
        uint32_t dLo = CF_LEDGER_NO_DROP, dHi = CF_LEDGER_NO_DROP;
        int nDropReq = BRCFScanLedgerRecordRequestedDropped(&manager->cfLedger, reqStart, reqStop,
                                      preferred ? preferred->address : UINT128_ZERO,
                                      preferred ? preferred->port : 0,
                                      (uint32_t)now, &dLo, &dHi);
        if (nDropReq > 0) {
            if (preferred) {
                peer_log(preferred, "cf-ledger: OUTSTANDING OVERFLOW — dropped %d oldest holes [%u..%u]",
                         nDropReq, dLo, dHi);
            }
            else {
                debug_log("cf-ledger: OUTSTANDING OVERFLOW — dropped %d oldest holes [%u..%u]\n",
                          nDropReq, dLo, dHi);
            }
        }
#else
        BRCFScanLedgerRecordRequested(&manager->cfLedger, reqStart, reqStop,
                                      preferred ? preferred->address : UINT128_ZERO,
                                      preferred ? preferred->port : 0, (uint32_t)now);
#endif

        if (manager->cfFiltersInFlight == 0) manager->cfFiltersWindowStart = now;
        manager->cfFiltersInFlight += (uint32_t)n;

        if (preferred) {
            peer_log(preferred, "cfilters: auto-requested [%u..%u] (%zu blocks, %u in flight)",
                     reqStart, reqStop, n, manager->cfFiltersInFlight);
        }
        else {
            debug_log("cfilters: auto-requested [%u..%u] (%zu blocks, %u in flight)\n",
                      reqStart, reqStop, n, manager->cfFiltersInFlight);
        }
    }
}

// Returns the wallet's BIP 158 element set, rebuilding it only when the wallet's address
// set has actually changed. Caller holds manager->lock and MUST NOT free the result — it
// is owned by the manager and freed in BRPeerManagerFree.
//
// Why this exists: BRWalletGetFilterElements enumerates every wallet address and calls
// BRAddressScriptPubKey twice per address (a sizing pass and a fill pass), each a
// base58check decode with SHA256d. It was called once per arriving cfilter — "up to 1000
// per batch, tens of millions across a deep sync", as BRWalletFilterElements.c already
// notes — which measured 1.90 ms per filter against the real DGB mainnet fixture in this
// tree, 98.8% of the per-filter cost, i.e. ~45 min of single-core CPU per 1.44M blocks.
// Cached, the per-filter cost is the GCS match alone (~41 us measured).
//
// THE INVALIDATION RULE. The element BYTES are a function of (address strings, network) —
// NOT of the address set alone: BRAddressScriptPubKey encodes per BRNetworkIsTestnet().
// So the cache key is a three-field tuple, all cheap, all compared before every use:
//
//   addrGen   monotonic, process-global, bumped at every append to an enumerated chain and
//             at wallet construction. Catches appends AND a change of WALLET — which a
//             count cannot see, because two different seeds yield identical address counts
//             with fully disjoint sets (measured: 1045 == 1045, 0 shared) — and being
//             process-global it is immune to malloc reusing the same chunk.
//   addrCount defence-in-depth. If a future author adds a chain mutation and forgets to
//             bump addrGen, the count still catches it, so a missed bump degrades to a
//             weaker check instead of to silent fund loss.
//   isTestnet a free global read. Without it a network switch leaves gen and count
//             unchanged while changing the elements — measured: count 645 -> 645,
//             elements 645 -> 0. The PARTIAL-drop variant is the dangerous one: some
//             addresses stop encoding while others still do, so the set stays non-empty
//             and the build-failure retry below never fires. Silent and permanent.
//
// gen and count are read in ONE lock hold (BRWalletAddrSetKey) because read separately they
// could straddle an append and yield a pair that never existed.
//
// The key is read BEFORE the rebuild and the PRE-build value is stamped. That looks like a
// bug and is load-bearing: because gen and count are monotonic, an append racing the build
// leaves the stamped key mismatched, so the next filter rebuilds. Stamping a post-build
// value could swallow that append. Do not "fix" the ordering.
//
// This is deliberately a probe rather than invalidation at known mutation sites, because the
// mutations are not all reachable from here. Three matter, and only a probe catches all
// three:
//   - a tx registered mid-scan: BRWalletRegisterTransaction extends all six chains, and
//     the very NEXT filter must already match the newly derived addresses. This is
//     self-referential — scanning is what grows the set it scans for.
//   - a receive address handed out on the Receive screen: BRWalletReceiveAddress extends a
//     chain from the JVM thread, with no peer-manager involvement at all.
//   - a watched address pinned over JNI, likewise off-thread.
// Getting this wrong does not degrade gracefully: a stale set means a filter that should
// have matched does not, the block is never fetched, and the payment is never seen.
// Silent, permanent, and it is money. Hence a rule that cannot miss a mutation site
// rather than a list of sites we believe is complete.
static BRWalletFilterElements *_BRPeerManagerFilterElementsLocked(BRPeerManager *manager)
{
    uint64_t addrGen = 0;
    size_t addrCount = 0;
    int isTestnet;

    BRWalletAddrSetKey(manager->wallet, &addrGen, &addrCount);
    isTestnet = BRNetworkIsTestnet() ? 1 : 0;

#ifdef CF_ELEMS_CACHE_NOINVALIDATE
    // NAIVE-CACHE shape — host-KAT red-before-green ONLY (never defined in a production
    // build). Caches once and never invalidates, so an address added after the first filter
    // is never matched: the exact silent missed receive this rule prevents.
    if (manager->cfElems) return manager->cfElems;
#elif defined(CF_ELEMS_CACHE_COUNT_ONLY)
    // COUNT-ONLY shape — host-KAT red-before-green ONLY. Keys on the address count alone,
    // which is UNSOUND: it misses a network switch (elements re-encode with gen and count
    // unchanged) and misses a wallet swap (disjoint sets, identical counts).
    if (manager->cfElems && manager->cfElemsAddrCount == addrCount) return manager->cfElems;
#else
    if (manager->cfElems &&
        manager->cfElemsAddrGen == addrGen &&
        manager->cfElemsAddrCount == addrCount &&
        manager->cfElemsIsTestnet == isTestnet) return manager->cfElems;
#endif

    BRWalletFilterElementsFree(manager->cfElems);   // NULL-safe
    manager->cfElems = BRWalletGetFilterElements(manager->wallet);
    // On a build failure leave the key mismatched so the next filter retries rather than
    // caching "no elements" — matching nothing forever would be a silent missed receive.
    // (Note this only saves the TOTAL-drop case; the partial-drop case is why isTestnet is
    // part of the key rather than relying on this.)
    manager->cfElemsAddrGen   = manager->cfElems ? addrGen : 0;
    manager->cfElemsAddrCount = manager->cfElems ? addrCount : 0;
    manager->cfElemsIsTestnet = isTestnet;
    return manager->cfElems;
}

// cfilter response handler. Three jobs:
//   1. Verify the filter against the chain (catches lying peers).
//   2. Match the wallet's address set against the decoded filter.
//   3. On match, ask the same peer for the full block via inv_block getdata.
//      The block message handler in BRPeer.c walks the txs and dispatches
//      each via the existing relayedTx callback, which is wired to
//      BRWalletRegisterTransaction. Idempotent on duplicate registers.
static void _peerRelayedCFilter(void *info, uint8_t filterType, UInt256 blockHash,
                                const uint8_t *encoded, size_t encodedLen)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);
    if (!manager->compactFilterChain ||
        filterType != BRCompactFilterChainType(manager->compactFilterChain)) {
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    // Account for the ARRIVAL here — after the "is this even our filter type" guard, and
    // BEFORE every other exit from this function. This handler has five exits: wrong
    // chain/type (above, not a response to anything we asked for), unknown/pruned block,
    // cfheader verify failure, filter parse failure, and success. The last four are all a
    // peer ANSWERING a height we requested, and all four used to return without releasing
    // the in-flight slot, because the decrement sat at the bottom past them.
    //
    // That leaked a slot per unevaluatable filter, and those are not rare: 367 to 1,741 per
    // run in measured syncs. The in-flight window therefore never drained, every window
    // eventually looked stalled to the drive's timeout, and once a retire was wired to rewind
    // the cursor it re-requested ranges that were arriving perfectly well — 10 rewinds and 17
    // give-ups in nine minutes, with throughput collapsing.
    //
    // Placed on this single line rather than repeated at each exit so a future exit added
    // below cannot forget it.
    if (manager->cfFiltersInFlight > 0) manager->cfFiltersInFlight--;
    // Any answer is progress: the retire must mean "nothing has arrived for a while", not
    // "this window has been open a while". A full window is ~2.6 MB of filters and can
    // legitimately outlive the timeout while it is still being delivered.
    manager->cfFiltersWindowStart = time(NULL);

    BRMerkleBlock *b = BRSetGet(manager->blocks, &blockHash);
    if (!b) {
        peer_log(peer, "cfilter: unknown block %s, dropping", log_u256_hex_encode(blockHash));
        // Observe-only (Phase 1): the height stays outstanding in the ledger (we do
        // NOT MarkEvaluated), so scannedThrough naturally holds below it.
        peer_log(peer, "cf-ledger: header-race hole (block %s unknown) — left outstanding",
                 log_u256_hex_encode(blockHash));
#if CF_LEDGER_DRIVE_REREQUEST
        // Phase 2: hold the raw (unverified) filter bytes keyed by blockHash so a
        // buffered-drain (BRPeerManagerKeepAlive) can evaluate it the moment the
        // block header AND cfheader both connect, instead of relying solely on the
        // slower residual re-request path for what is usually just a brief race.
        if (! BRCFScanLedgerBufferFilter(&manager->cfLedger, blockHash, encoded, encodedLen, (uint32_t)time(NULL)))
            ; /* too big / not stored — height stays outstanding for the residual re-request path */
#endif
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    if (!BRCompactFilterChainVerifyFilter(manager->compactFilterChain, b->height, encoded, encodedLen)) {
        peer_log(peer, "cfilter: filter for block %s does not match chain — misbehavin'",
                 log_u256_hex_encode(blockHash));
        _BRPeerManagerPeerMisbehavin(manager, peer);
        // Observe-only (Phase 1): height left outstanding (not MarkEvaluated).
        peer_log(peer, "cf-ledger: hole @ %u reason=verify_fail — left outstanding (scannedThrough=%u, outstanding=%zu)",
                 b->height, BRCFScanLedgerScannedThrough(&manager->cfLedger),
                 BRCFScanLedgerOutstandingCount(&manager->cfLedger));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    // The filter verified against the chain — this peer served a valid cfilter
    // (positive CF-served signal), independent of whether it hits our wallet.
    _recordCFServed(manager, peer);

    BRGCSFilter *gcs = BRGCSFilterBasicParse(encoded, encodedLen, blockHash);
    if (!gcs) {
        peer_log(peer, "cfilter: failed to parse filter for block %s",
                 log_u256_hex_encode(blockHash));
        // Observe-only (Phase 1): height left outstanding (not MarkEvaluated).
        peer_log(peer, "cf-ledger: hole @ %u reason=parse_fail — left outstanding (scannedThrough=%u, outstanding=%zu)",
                 b->height, BRCFScanLedgerScannedThrough(&manager->cfLedger),
                 BRCFScanLedgerOutstandingCount(&manager->cfLedger));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    // Manager-owned cache — do NOT free this (see _BRPeerManagerFilterElementsLocked).
    BRWalletFilterElements *fe = _BRPeerManagerFilterElementsLocked(manager);
    size_t feCount = (fe ? fe->count : 0);
    int hit = 0;
    if (fe && fe->count > 0) {
        hit = BRGCSFilterMatchAny(gcs, fe->elements, fe->elementLens, fe->count);
    }
    // DIAGNOSTIC (v3.10.8): compact-filter match decision, now GATED ON hit. The
    // per-block line used to fire for EVERY scanned block — thousands of lines
    // during catch-up that flooded logd and plausibly starved the binder buffer
    // on the acceptance rig (2026-07-26). Scan progress is already covered by the
    // `cf-ledger: scannedThrough=…` counts, so only log the rare, interesting
    // event: an actual match (how many elements matched, the filter's byte size,
    // and the first element as hex to cross-check against the block's outputs).
    if (hit) {
        peer_log(peer, "cfilter: block %u — matched %zu wallet element(s) vs %zu-byte filter",
                 b->height, feCount, encodedLen);
        if (feCount > 0 && fe->elementLens && fe->elements) {
            const uint8_t *e0 = fe->elements[0];
            size_t l0 = fe->elementLens[0];
            char hx[2*40 + 1];
            size_t hn = (l0 < 40 ? l0 : 40);
            for (size_t k = 0; k < hn; k++) sprintf(&hx[k*2], "%02x", e0[k]);
            hx[hn*2] = '\0';
            peer_log(peer, "cfilter:   sample wallet element[0] len=%zu spk=%s", l0, hx);
        }
    }
    BRGCSFilterFree(gcs);

    if (hit) {
        peer_log(peer, "cfilter: MATCH on block %s @ height %u, requesting full block",
                 log_u256_hex_encode(blockHash), b->height);
        // Send while holding the lock — matches the pattern used elsewhere
        // in this file (e.g. _BRPeerManagerRequestNextCFHeaders also sends
        // under the lock). The lock guards manager state, not the socket.
        BRPeerSendGetdataBlocks(peer, &blockHash, 1);
    }

    // The cfilter was evaluated (matched above or cleanly missed) — remove this
    // height from the ledger's outstanding set and advance scannedThrough.
    BRCFScanLedgerMarkEvaluated(&manager->cfLedger, b->height);

    // This response retires one block of the in-flight window and re-clocks the drive, so
    // the pipeline pulls itself along on filter arrivals instead of waiting for the next
    // cfheaders message. Without this the whole pipeline stalls whenever the cfheaders peer
    // goes quiet.
    _BRPeerManagerDriveCFiltersLocked(manager, peer);

    pthread_mutex_unlock(&manager->lock);
}

// B2 stub: cfcheckpt is informational at the moment. C1+ may use checkpoints
// to bootstrap a chain anchor from a height other than 0.
static void _peerRelayedCFCheckpt(void *info, uint8_t filterType, UInt256 stopHash,
                                  const UInt256 *filterHeaders, size_t count)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    peer_log(peer, "cfcheckpt: received %zu header(s) for filter type %u, stop %s",
             count, (unsigned)filterType, log_u256_hex_encode(stopHash));
}

// Public-facing hook called from _peerConnected when a filter-capable peer
// finishes handshake.
static void _BRPeerManagerOnFilterCapablePeerConnected(BRPeerManager *manager, void *peerCbInfo,
                                                       BRPeer *peer)
{
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return;
    if (!_BRPeerManagerPeerSupportsCompactFilters(manager, peer)) return;

    BRPeerSetCompactFilterCallbacks(peer, _peerRelayedCFHeaders, _peerRelayedCFilter, _peerRelayedCFCheckpt);
    // Maintain the gap+100 look-ahead window on the compact-filter path — the bloom
    // path does this in _BRPeerManagerLoadBloomFilter, which early-returns in
    // CF-only. Without it the cfilter match set decays to the bare gap limit as
    // addresses are used and a look-ahead receive would be missed. Follows the same
    // manager->wallet lock ordering as the bloom path's pregen.
    _BRPeerManagerPregenAddrWindow(manager);
    _BRPeerManagerRequestNextCFHeaders(manager, peer);
}

// not thread-safe, set callbacks once before calling BRPeerManagerConnect()
// info is a void pointer that will be passed along with each callback call
// void syncStarted(void *) - called when blockchain syncing starts
// void syncStopped(void *, int) - called when blockchain syncing stops, error is an errno.h code
// void txStatusUpdate(void *) - called when transaction status may have changed such as when a new block arrives
// void saveBlocks(void *, int, const uint8_t *bytes, size_t len) - called when blocks should be saved to the
//   persistent store. The core serializes the blocks to `bytes` UNDER its lock and hands the immutable buffer
//   here (NOT live block pointers), so the callback is free to do a slow JNI upcall without racing a reorg free.
// - if replace is true, remove any previously saved blocks first
// void savePeers(void *, int, const BRPeer[], size_t) - called when peers should be saved to the persistent store
// - if replace is true, remove any previously saved peers first
// int networkIsReachable(void *) - must return true when networking is available, false otherwise
// void threadCleanup(void *) - called before a thread terminates to faciliate any needed cleanup
void BRPeerManagerSetCallbacks(BRPeerManager *manager, void *info,
                               void (*syncStarted)(void *info),
                               void (*syncStopped)(void *info, int error),
                               void (*txStatusUpdate)(void *info),
                               void (*saveBlocks)(void *info, int replace, const uint8_t *bytes, size_t len, uint64_t* memIntegrityCheck),
                               void (*savePeers)(void *info, int replace, const BRPeer peers[], size_t peersCount),
                               int (*networkIsReachable)(void *info),
                               void (*threadCleanup)(void *info))
{
    assert(manager != NULL);
    manager->info = info;
    manager->syncStarted = syncStarted;
    manager->syncStopped = syncStopped;
    manager->txStatusUpdate = txStatusUpdate;
    manager->saveBlocks = saveBlocks;
    manager->savePeers = savePeers;
    manager->networkIsReachable = networkIsReachable;
    manager->threadCleanup = (threadCleanup) ? threadCleanup : _dummyThreadCleanup;
}

// specifies a single fixed peer to use when connecting to the bitcoin network
// set address to UINT128_ZERO to revert to default behavior
void BRPeerManagerSetFixedPeer(BRPeerManager *manager, UInt128 address, uint16_t port)
{
    assert(manager != NULL);
    BRPeerManagerDisconnect(manager);
    pthread_mutex_lock(&manager->lock);
    manager->maxConnectCount = UInt128IsZero(address) ? PEER_MAX_CONNECTIONS : 1;
    manager->fixedPeer = ((BRPeer) { address, port, 0, 0, 0 });
    array_clear(manager->peers);
    pthread_mutex_unlock(&manager->lock);
}

// Dynamically set the target connection count (demand-side load-spread): the wallet holds the
// full PEER_MAX_CONNECTIONS while CATCHING UP (fast sync + wedge buffer), then drops to a small
// count once SYNCED so thousands of idle wallets stop each pinning 8 slots on the shared
// filter-node fleet. Reducing gently schedule-disconnects the excess via the SAME async path
// idle-eviction uses (BRPeerScheduleDisconnect) — NEVER the download peer (it drives the sync)
// or the pinned own-node. maxConnectCount then gates re-dials so the reduced set is maintained;
// increasing (fell behind → catch up) tops back up via BRPeerManagerConnect.
void BRPeerManagerSetMaxConnectCount(BRPeerManager *manager, size_t count)
{
    assert(manager != NULL);
    if (count < 1) count = 1;
    pthread_mutex_lock(&manager->lock);
    size_t prev = manager->maxConnectCount;
    manager->maxConnectCount = count;
    if (count < prev) {
        size_t keeping = array_count(manager->connectedPeers);
        for (size_t i = array_count(manager->connectedPeers); i > 0 && keeping > count; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            if (p == manager->downloadPeer) continue;                 // keep the sync driver
            if (BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort,
                               p->address, p->port)) continue;        // keep the pinned own-node
            if (BRPeerConnectStatus(p) == BRPeerStatusDisconnected) continue;
            BRPeerScheduleDisconnect(p, 0);
            keeping--;
        }
    }
    pthread_mutex_unlock(&manager->lock);
    if (count > prev) BRPeerManagerConnect(manager);                  // fell behind — top back up
}

// current connect status
BRPeerStatus BRPeerManagerConnectStatus(BRPeerManager *manager)
{
    BRPeerStatus status = BRPeerStatusDisconnected;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    if (manager->isConnected != 0) status = BRPeerStatusConnected;

    for (size_t i = array_count(manager->connectedPeers); i > 0 && status == BRPeerStatusDisconnected; i--) {
        if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) == BRPeerStatusDisconnected) continue;
        status = BRPeerStatusConnecting;
    }

    pthread_mutex_unlock(&manager->lock);
    return status;
}

// Pin a user-paired own-node as a reserved, never-churn-evicted CF peer. exclusive
// != 0 makes the dialer contact ONLY this node. Takes manager->lock itself (the JNI
// caller holds the separate PEER_GUARD, not this lock). port == 0 clears the pin.
void BRPeerManagerSetPinnedPeer(BRPeerManager *manager, UInt128 addr, uint16_t port, int exclusive)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->pinnedAddr = addr;
    manager->pinnedPort = port;
    manager->pinnedExclusive = exclusive ? 1 : 0;
    pthread_mutex_unlock(&manager->lock);
}

// Clear any pinned own-node (reverts to normal dial/eviction behavior). Takes
// manager->lock itself.
void BRPeerManagerClearPinnedPeer(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->pinnedAddr = UINT128_ZERO;
    manager->pinnedPort = 0;
    manager->pinnedExclusive = 0;
    pthread_mutex_unlock(&manager->lock);
}

// Compact-filter status of the peer at addr:port for the own-node connectivity UI:
// UNKNOWN (not in pool) / CONNECTING (in pool, not connected) / CONNECTED_NOT_SERVING
// / SERVING (has answered a cfheaders/cfilter this session). Takes manager->lock
// itself. manager->peers is a BRPeer value array; connectedPeers a BRPeer* array —
// both store addr/port as plain fields (no BRPeerAddress accessor exists).
int BRPeerManagerCompactFilterPeerStatus(BRPeerManager *manager, UInt128 addr, uint16_t port)
{
    assert(manager != NULL);
    int inPool = 0, connected = 0, served = 0;
    pthread_mutex_lock(&manager->lock);
    for (size_t i = 0; i < array_count(manager->peers); i++) {
        if (! UInt128Eq(manager->peers[i].address, addr) || manager->peers[i].port != port) continue;
        inPool = 1; break;
    }
    for (size_t i = 0; inPool && i < array_count(manager->connectedPeers); i++) {
        BRPeer *p = manager->connectedPeers[i];
        if (! UInt128Eq(p->address, addr) || p->port != port) continue;
        connected = (BRPeerConnectStatus(p) == BRPeerStatusConnected && BRPeerIsSocketOpen(p)) ? 1 : 0;
        break;
    }
    served = _cfServedContains(manager, addr, port);
    pthread_mutex_unlock(&manager->lock);
    return BRComputeCFPeerStatus(inPool, connected, served);
}

// Begin an async connect to a copy of `tmpl`, wiring all manager callbacks and
// adding it to connectedPeers. Caller must hold manager->lock. Mirrors the inline
// connect block in BRPeerManagerConnect so the BIP158 filter-first pre-pass and the
// regular bloom selection share identical setup.
static void _BRPeerManagerBeginConnect(BRPeerManager *manager, const BRPeer *tmpl)
{
    BRPeerCallbackInfo *info = calloc(1, sizeof(*info));
    assert(info != NULL);
    info->manager = manager;
    info->peer = BRPeerNew(manager->params->magicNumber);
    *info->peer = *tmpl;
    manager->peerThreadCount++;
    array_add(manager->connectedPeers, info->peer);
    BRPeerSetCallbacks(info->peer, info, _peerConnected, _peerDisconnected, _peerRelayedPeers,
                       _peerRelayedTx, _peerHasTx, _peerRejectedTx, _peerRelayedBlock, _peerRelayedBlockTxns,
                       _peerRelayedBlockInv, _peerDataNotfound, _peerSetFeePerKb, _peerRequestedTx,
                       _peerNetworkIsReachable, _peerThreadCleanup);
    BRPeerSetEarliestKeyTime(info->peer, manager->earliestKeyTime);
    BRPeerSetCompactFiltersOnly(info->peer, manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY);
    BRPeerConnect(info->peer);

    if (BRPeerConnectStatus(info->peer) == BRPeerStatusDisconnected) {
        pthread_mutex_unlock(&manager->lock);
        _peerDisconnected(info, ENOTCONN);
        pthread_mutex_lock(&manager->lock);
        manager->peerThreadCount--;
    }
}

// Count peers in the candidate pool (manager->peers) that are compact-filter capable, NOT already
// connected, and NOT penalized — exactly the set the filter-first pre-pass will dial. Read-only;
// caller holds manager->lock. Never peer_log's a bare manager->peers element.
static size_t _BRPeerManagerCountDialableFilterPeers(BRPeerManager *manager, time_t now)
{
    size_t n = 0;
    for (size_t k = 0; k < array_count(manager->peers); k++) {
        if ((manager->peers[k].services & SERVICES_NODE_COMPACT_FILTERS) != SERVICES_NODE_COMPACT_FILTERS)
            continue;
        int already = 0;
        for (size_t j = array_count(manager->connectedPeers); j > 0; j--) {
            if (BRPeerEq(&manager->peers[k], manager->connectedPeers[j - 1])) { already = 1; break; }
        }
        if (already) continue;
        if (BRPeerPenaltyContains(manager->penaltyAddr, manager->penaltyPort, manager->penaltyUntil,
                                  manager->penaltyCount < PEER_PENALTY_MAX ? manager->penaltyCount : PEER_PENALTY_MAX,
                                  manager->peers[k].address, manager->peers[k].port, now))
            continue;
        n++;
    }
    return n;
}

// Count connected filter peers whose socket is still LIVE (excludes dead-socket zombies). Combined
// with the dialable count this answers "do we have any real filter peer to work with" — so the
// wallet only falls back to the discovery/own-node path when the known filter set is truly
// exhausted. Read-only; caller holds manager->lock.
static size_t _BRPeerManagerCountLiveFilterPeers(BRPeerManager *manager)
{
    size_t n = 0;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) == BRPeerStatusDisconnected) continue;
        if (! BRPeerIsSocketOpen(p)) continue; // dead-socket zombie is not a live filter peer
        if ((p->services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS) n++;
    }
    return n;
}

// connect to bitcoin peer-to-peer network (also call this whenever networkIsReachable() status changes)
void BRPeerManagerConnect(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    if (manager->connectFailureCount >= MAX_CONNECT_FAILURES) manager->connectFailureCount = 0; //this is a manual retry
    
    if ((! manager->downloadPeer || manager->lastBlock->height < manager->estimatedHeight) &&
        manager->syncStartHeight == 0) {
        manager->syncStartHeight = manager->lastBlock->height + 1;
        pthread_mutex_unlock(&manager->lock);
        if (manager->syncStarted) manager->syncStarted(manager->info);
        pthread_mutex_lock(&manager->lock);
    }
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];

        if (BRPeerConnectStatus(p) == BRPeerStatusConnecting) BRPeerConnect(p);
    }
    
    if (array_count(manager->connectedPeers) < manager->maxConnectCount) {
        time_t now = time(NULL);
        BRPeer *peers;

        // CF-first (COMPACT_FILTERS_ONLY): dial the KNOWN validated filter peers as the primary
        // set and SUPPRESS the random DNS/bloom shotgun while we have any filter peer to work with
        // (a dialable candidate OR one already connected/connecting). The keepalive ping keeps
        // those known peers up, so this rarely trips to exhaustion. Only when the known filter set
        // is TRULY exhausted (all down) do we fall back to discovery — which is the point at which
        // the app should nudge the user toward their own-node option (the sovereignty upgrade)
        // rather than shotgunning bloom-off nodes. Never wedges at 0 peers (fallback still runs).
        int cfOnly = (manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY);
        int cfExhausted = 1;
        if (cfOnly) {
            cfExhausted = (_BRPeerManagerCountDialableFilterPeers(manager, now) == 0 &&
                           _BRPeerManagerCountLiveFilterPeers(manager) == 0);
        }

		if (cfExhausted &&
		    ((array_count(manager->peers) < (4 * manager->maxConnectCount)) ||
			((manager->peers[manager->maxConnectCount - 1].timestamp + 3*24*60*60) < now))) {
            _BRPeerManagerFindPeers(manager);
        }

        // Reserved slot: always dial the pinned own-node first if it's set, not
        // already connected, and a slot is free. Timestamp-ordered qsort/dial cutoffs
        // in the loops below can otherwise bury it past the cutoff. _BRPeerManagerBeginConnect
        // array_add's it to connectedPeers, so the count checks below see it filled.
        // No penalty check: the pinned node is the never-churn reserved slot (it is
        // also exempt from _penalize, see _peerConnected).
        if (manager->pinnedPort != 0 &&
            array_count(manager->connectedPeers) < manager->maxConnectCount) {
            int already = 0;
            for (size_t i = 0; i < array_count(manager->connectedPeers); i++) {
                if (UInt128Eq(manager->connectedPeers[i]->address, manager->pinnedAddr) &&
                    manager->connectedPeers[i]->port == manager->pinnedPort) { already = 1; break; }
            }
            if (! already) {
                for (size_t k = 0; k < array_count(manager->peers); k++) {
                    if (! UInt128Eq(manager->peers[k].address, manager->pinnedAddr) ||
                        manager->peers[k].port != manager->pinnedPort) continue;
                    _BRPeerManagerBeginConnect(manager, &manager->peers[k]);
                    break;
                }
            }
        }

        // BIP 158: filter-first. The cfheaders driver only runs once a
        // NODE_COMPACT_FILTERS peer is connected, but those are a tiny minority
        // of the candidate pool (a few seeder nodes among hundreds of random
        // bloom peers). The random bloom selection below almost never picks one
        // inside the watchdog's fallback window, so connect the filter-capable
        // peers up front. Skips any already connected; the bloom pass fills any
        // slots left over (filter peers are full nodes, so block download still
        // works either way). Inert in BLOOM_ONLY mode (failsafe fallback).
        if (manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY) {
            for (size_t k = 0; k < array_count(manager->peers) &&
                               array_count(manager->connectedPeers) < manager->maxConnectCount; k++) {
                // Exclusive-pin mode: contact ONLY the pinned own-node (it is dialed
                // by the reserved-slot block above); skip every other candidate.
                if (manager->pinnedExclusive &&
                    ! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort,
                                     manager->peers[k].address, manager->peers[k].port)) continue;
                if ((manager->peers[k].services & SERVICES_NODE_COMPACT_FILTERS) != SERVICES_NODE_COMPACT_FILTERS)
                    continue;

                int alreadyConnected = 0;
                for (size_t j = array_count(manager->connectedPeers); j > 0; j--) {
                    if (BRPeerEq(&manager->peers[k], manager->connectedPeers[j - 1])) { alreadyConnected = 1; break; }
                }
                if (alreadyConnected) continue;

                // Churn fix: skip a candidate we rejected as "not synced" (or
                // otherwise penalized) within the last PEER_PENALTY_SECONDS,
                // instead of re-dialing it every single connect pass. See
                // BRPeerPenalty.h / _penalize.
                if (BRPeerPenaltyContains(manager->penaltyAddr, manager->penaltyPort, manager->penaltyUntil,
                                          manager->penaltyCount < PEER_PENALTY_MAX ? manager->penaltyCount : PEER_PENALTY_MAX,
                                          manager->peers[k].address, manager->peers[k].port, now))
                    continue;

                // NOTE: manager->peers holds plain BRPeer structs, NOT BRPeerContext.
                // peer_log() -> BRPeerHost() casts the arg to BRPeerContext* and writes
                // the formatted host string into ctx->host, which lives PAST the end of a
                // bare BRPeer (host is after {BRPeer peer; uint32_t magicNumber;}). On a
                // candidate-array element that write lands in the NEXT array slot,
                // corrupting peers[k+1]'s address (and compounding down the loop). Format
                // the IPv4 octets from a LOCAL copy instead so the log is memory-safe.
                {
                    const uint8_t *ip = (const uint8_t *)&manager->peers[k].address.u32[3];
                    _peer_log("%u.%u.%u.%u:%"PRIu16" BIP158: connecting filter-capable peer first\n",
                              ip[0], ip[1], ip[2], ip[3], manager->peers[k].port);
                }
                _BRPeerManagerBeginConnect(manager, &manager->peers[k]);
            }
        }

        // Shotgun fallback: the random-peer dial pass. In COMPACT_FILTERS_ONLY this runs
        // ONLY when the known filter set is exhausted (cfExhausted) — otherwise the filter-first
        // pre-pass above is the sole dialer. Prioritizes CF-capable candidates so filter peers
        // aren't sorted to the back of a shotgun pass full of non-CF nodes (risk: modern nodes
        // ship bloom OFF by default, so a bloom-keyed prioritization here would starve the exact
        // peers CF-only needs).
        if (cfExhausted) {
        array_new(peers, 100);

        // Prioritize CF-capable peers: add them to the candidate list first,
        // then fill remaining slots with other peers. This ensures all 5
        // connection slots go to filter-capable peers when enough are available.
        {
            size_t totalAvail = array_count(manager->peers);
            size_t added = 0;

            // First pass: CF-capable peers only
            for (size_t k = 0; k < totalAvail && added < 100; k++) {
                // Exclusive-pin mode: only the pinned own-node may enter the shotgun list.
                if (manager->pinnedExclusive &&
                    ! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort,
                                     manager->peers[k].address, manager->peers[k].port)) continue;
                if ((manager->peers[k].services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS) {
                    array_add(peers, manager->peers[k]);
                    added++;
                }
            }
            // Second pass: fill remaining slots with any peer
            for (size_t k = 0; k < totalAvail && added < 100; k++) {
                if (manager->pinnedExclusive &&
                    ! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort,
                                     manager->peers[k].address, manager->peers[k].port)) continue;
                if ((manager->peers[k].services & SERVICES_NODE_COMPACT_FILTERS) != SERVICES_NODE_COMPACT_FILTERS) {
                    array_add(peers, manager->peers[k]);
                    added++;
                }
            }
        }

        while ((array_count(peers) > 0) && (array_count(manager->connectedPeers) < manager->maxConnectCount)) {
            size_t filterCount = 0;
            for (size_t bc = 0; bc < array_count(peers); bc++) {
                if ((peers[bc].services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS) filterCount++;
            }

            size_t i;
            BRPeerCallbackInfo *info;

            if (filterCount > 0) {
                // Pick randomly from CF-capable peers only (they're at the front)
                i = BRRand((uint32_t)filterCount);
            } else {
                // No CF-capable peers left, fall back to random from full list
                i = BRRand((uint32_t)array_count(peers));
                i = i*i/array_count(peers); // bias toward recent timestamp
            }
        
            for (size_t j = array_count(manager->connectedPeers); i != SIZE_MAX && j > 0; j--) {
                if (! BRPeerEq(&peers[i], manager->connectedPeers[j - 1])) continue;
                array_rm(peers, i); // already in connectedPeers
                i = SIZE_MAX;
            }
            
            if (i != SIZE_MAX) {
                info = calloc(1, sizeof(*info));
                assert(info != NULL);
                info->manager = manager;
                info->peer = BRPeerNew(manager->params->magicNumber);
                *info->peer = peers[i];
                array_rm(peers, i);
                array_add(manager->connectedPeers, info->peer);
                manager->peerThreadCount++;
                BRPeerSetCallbacks(info->peer, info, _peerConnected, _peerDisconnected, _peerRelayedPeers,
                                   _peerRelayedTx, _peerHasTx, _peerRejectedTx, _peerRelayedBlock,
                                   _peerRelayedBlockTxns, _peerRelayedBlockInv, _peerDataNotfound, _peerSetFeePerKb,
                                   _peerRequestedTx, _peerNetworkIsReachable, _peerThreadCleanup);
                BRPeerSetEarliestKeyTime(info->peer, manager->earliestKeyTime);
                BRPeerSetCompactFiltersOnly(info->peer, manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY);
                BRPeerConnect(info->peer);
                
                if (BRPeerConnectStatus(info->peer) == BRPeerStatusDisconnected) {
                    pthread_mutex_unlock(&manager->lock);
                    _peerDisconnected(info, ENOTCONN);
                    pthread_mutex_lock(&manager->lock);
                    manager->peerThreadCount--;
                }
            }
        }

        array_free(peers);
        } // end cfExhausted shotgun-fallback gate
    }

    if (array_count(manager->connectedPeers) == 0) {
        // Was peer_log(&BR_PEER_NONE, ...) — peer_log casts to BRPeerContext* and writes the host
        // past the bare sentinel (OOB). Use the peer-less _peer_log.
        _peer_log("sync failed — no peers connected\n");
        _BRPeerManagerSyncStopped(manager);
        pthread_mutex_unlock(&manager->lock);
        if (manager->syncStopped) manager->syncStopped(manager->info, ENETUNREACH);
    }
    else pthread_mutex_unlock(&manager->lock);
}

// Send a keepalive PING to every connected peer. Bloom sync keeps its single download peer hot
// via continuous merkleblock traffic; CF sync juggles multiple filter peers, only one of which is
// actively serving cfheaders at a time, so the others go idle and the remote node (or a NAT) drops
// them ("Connection reset" / dead-socket zombies) — then the cfheaders driver rotates onto those
// dead sockets. A periodic ping keeps every connection active so filter peers stay available.
// Fire-and-forget (NULL pong callback — the pong just refreshes pingTime). Call periodically
// (the app's ~10s keepalive tick). Safe anytime; no-op if not connected.
//
// ANR fix #2 (.superpowers/sdd/anr-fix2-native-design.md): this runs under
// manager->lock, which is nested inside the JNI PEER_GUARD, and manager->lock is NOT
// released between peers (releasing it would let a peer's own read thread free it out
// from under this loop -- BRPeer has no refcount, see the design doc's UAF analysis).
// Previously each BRPeerSendPing could block up to MESSAGE_TIMEOUT (10s) on a
// half-dead socket, so K wedged peers could pin manager->lock/PEER_GUARD for up to
// K*10s -- long enough to ANR any other PEER_GUARD-taking JNI entry point. Two bounds
// now cap that instead of touching lock order or duration-vs-safety tradeoffs:
//   1. BRPeerSendPingProbe caps the send itself at KEEPALIVE_SEND_TIMEOUT (~1.5s) --
//      a wedged socket hits BRPeerDisconnect (existing error path, unchanged) fast
//      instead of after 10s.
//   2. A per-tick wall-clock budget bounds the WHOLE sweep at KEEPALIVE_TICK_BUDGET
//      regardless of connectedPeers count; any peers not reached this tick are picked
//      up on the next ~10s tick.
// Dead-socket zombies (BRPeerIsSocketOpen false) are skipped so budget isn't burned on
// already-dead sockets, matching the existing zombie-skip selectors elsewhere in this
// file. Idle-but-not-currently-wedged peers (e.g. a dropped NAT mapping with no
// outbound stall to trigger #1) get a real disconnectTime via BRPeerScheduleDisconnect
// once BRPeerLastRecvTime shows no inbound read in PEER_INBOUND_IDLE_LIMIT -- this
// replaces the DBL_MAX idle sentinel with the real deadline the read loop's existing
// `time >= ctx->disconnectTime` check was already built to honor, reaping the peer
// within ~1s via the single existing _peerDisconnected free path. Neither mechanism
// frees or array_rm's anything itself; both are idempotent no-ops on an
// already-evicted peer.
// ---------------------------------------------------------------------------
// Phase 2 (Task 5): buffered header-race filter drain.
//
// BRCFScanLedgerDrainConnected (BRCFScanLedger.c, pure module) reaches this
// BRPeerManager-aware logic only through the two function pointers below, so
// the ledger module itself stays BRPeerManager-free / host-KAT-testable.
//
// THE crux invariant: on a wallet HIT, the block is fetched via getdata
// (BRPeerSendGetdataBlocks) BEFORE MarkEvaluated -- that fetch is what
// actually credits the receive. Marking the height evaluated without
// dispatching getdata would silently lose a payment that arrived during a
// header race. A hit with no CF-capable peer connected KEEPS the entry
// buffered (returns 0, not 1) so the very next drive tick retries instead of
// the payment being lost. This mirrors the live match path's own
// getdata-then-MarkEvaluated order at _peerRelayedCFilter above.
#if CF_LEDGER_DRIVE_REREQUEST
struct _cfDrainCtx { BRPeerManager *m; BRWalletFilterElements *elems; };  // elems fetched ONCE per drain batch (perf)

// isReady: both the block header (in manager->blocks) AND its cfheader (the
// compact-filter chain must have advanced past this height) must be present.
// Buffered bytes are raw/unverified -- BRCompactFilterChainVerifyFilter below
// needs the cfheader at this height to exist or it can never succeed.
static int _cfBufIsReady(void *vctx, UInt256 h, uint32_t *outH)
{
    BRPeerManager *m = ((struct _cfDrainCtx *)vctx)->m;
    BRMerkleBlock *b = BRSetGet(m->blocks, &h);
    if (! b || b->height == BLOCK_UNKNOWN_HEIGHT) return 0;                 // block header not connected
    if (BRCompactFilterChainNextHeight(m->compactFilterChain) <= b->height) return 0; // cfheader not yet present
    *outH = b->height;
    return 1;
}

static int _cfBufEval(void *vctx, uint32_t height, UInt256 blockHash, const uint8_t *bytes, size_t len)
{
    struct _cfDrainCtx *c = vctx;
    BRPeerManager *m = c->m;

    if (! BRCompactFilterChainVerifyFilter(m->compactFilterChain, height, bytes, len)) return 1; // bad bytes: drop, leave outstanding (re-request)
    BRGCSFilter *gcs = BRGCSFilterBasicParse(bytes, len, blockHash);        // blockHash is the SipHash key (3-arg)
    if (! gcs) return 1;                                                   // unparseable: drop, leave outstanding

    int hit = (c->elems && c->elems->count > 0)
              ? BRGCSFilterMatchAny(gcs, c->elems->elements, c->elems->elementLens, c->elems->count) // real match (see _peerRelayedCFilter)
              : 0;
    BRGCSFilterFree(gcs);

    if (hit) {
        BRPeer *p = NULL;                                                  // a connected CF-capable peer for the getdata
        for (size_t i = array_count(m->connectedPeers); i > 0; i--) {
            if (_BRPeerManagerPeerCanServeFilters(m->connectedPeers[i - 1])) { p = m->connectedPeers[i - 1]; break; }
        }
        if (! p) return 0;                                                 // hit but no peer -> KEEP buffered, stay outstanding, retry
        BRPeerSendGetdataBlocks(p, &blockHash, 1);                         // credit: fetch the block -> tx registered on arrival
    }

    BRCFScanLedgerMarkEvaluated(&m->cfLedger, height);                     // scanned (hit dispatched, or clean verified miss)
    return 1;                                                              // remove from buffer
}
#endif // CF_LEDGER_DRIVE_REREQUEST

void BRPeerManagerKeepAlive(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);

    // Liveness backstop for the cfilter pipeline. cfheaders arrivals and cfilter arrivals
    // normally clock the drive; this tick is what guarantees it restarts when BOTH have
    // gone quiet — a silent peer, a retired in-flight window, or a filter batch that was
    // simply never answered. Cheap: it returns immediately once the cursor has caught up to
    // the validated cfheader frontier. Passing NULL lets the request path pick any eligible
    // filter peer rather than pinning the choice to whoever spoke last.
    _BRPeerManagerDriveCFiltersLocked(manager, NULL);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double t0 = tv.tv_sec + (double)tv.tv_usec/1000000;

    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (! BRPeerIsSocketOpen(p)) continue; // dead-socket zombie -- don't burn tick budget pinging it

        gettimeofday(&tv, NULL);
        double now = tv.tv_sec + (double)tv.tv_usec/1000000;
        if (now - t0 > KEEPALIVE_TICK_BUDGET) break; // bounded hold; remaining peers get the next tick

        BRPeerSendPingProbe(p, NULL, NULL);

        gettimeofday(&tv, NULL);
        now = tv.tv_sec + (double)tv.tv_usec/1000000;
        // Never idle-evict the pinned own-node (it still got pinged above to stay hot).
        // A genuinely dead pinned socket is reaped by the read loop / _peerDisconnected
        // and re-dialed by BRPeerManagerConnect's reserved slot — the intended dark→recover.
        if (now - BRPeerLastRecvTime(p) > PEER_INBOUND_IDLE_LIMIT &&
            ! BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort, p->address, p->port)) {
            BRPeerScheduleDisconnect(p, 0); // real deadline instead of the DBL_MAX idle sentinel
        }
    }

#if CF_LEDGER_DRIVE_REREQUEST
    // Phase 2 driver: (1) drain any buffered header-race filters whose block
    // header + cfheader have since connected (the crux credit path above) and
    // age out stale buffered bytes, then (2) best-effort re-request the RESIDUAL
    // drop set (verify/parse/disconnect holes) via peek/commit EVERY tick. The
    // old global `if (BufferedCount == 0)` gate is DELETED (Task 4): a header
    // re-sync can orphan buffered hashes, and those stale entries kept
    // BufferedCount>0 forever, starving residual re-request for every height
    // (the production livelock). Instead a per-height O(1) reverse-map suppressor
    // skips only heights whose canonical block is currently buffered (in-flight),
    // so undrained header-race heights are still not duplicate-requested — without
    // any single stale buffered hash being able to wedge the whole path shut.
    {
        uint32_t nowSec = (uint32_t)time(NULL);
        uint8_t scratch[2048];                              // >= max cfilter (675 B observed); 3x headroom vs a
                                                            // protocol change / unusually dense block making
                                                            // ~675 B history. A filter beyond this still self-heals
                                                            // via the residual re-request path (no loss), but this
                                                            // keeps the fast buffer-drain covering all realistic sizes.
        struct _cfDrainCtx dctx = { manager, BRWalletGetFilterElements(manager->wallet) }; // elements ONCE per batch
        BRCFScanLedgerDrainConnected(&manager->cfLedger, _cfBufIsReady, &dctx,
                                     scratch, sizeof scratch, _cfBufEval, CF_FILTER_DRAIN_PER_TICK);
        BRWalletFilterElementsFree(dctx.elems);             // free once (accepts NULL)

        // Task 3 byte-reclamation backstop, once per tick: age out any pruned/
        // orphaned buffered filter a peer keeps re-serving (BufferFilter's de-dup
        // resets `at`, so an `at`-keyed age-out never fires; this keys off the
        // immutable firstAt). Now that the buffer no longer gates the residual
        // path, this must run every tick so those bytes are eventually reclaimed.
        BRCFScanLedgerEvictAgedFilters(&manager->cfLedger, nowSec);

        BRCFScanLedgerRetireCapped(&manager->cfLedger);

        // Build the reverse-map skip set ONCE per tick (before the peek loop):
        // enumerate the SMALL buffered hash set and resolve each to its main-chain
        // height via manager->blocks (BRSetGet, O(1) per hash). This is the whole
        // point of the reverse map — NEVER compute canonical(H) by a forward
        // prevBlock walk (thousands of derefs deep in the floor/recovery regime,
        // under manager->lock, would ANR). An orphaned/pruned/header-not-connected
        // hash resolves to NULL and contributes no skip height (correct: its
        // outstanding height is still re-requested). Heap-sized to the ACTUAL
        // buffered count (not the CF_FILTER_BUF_SLOTS=2048 worst case), so
        // KeepAlive's stack frame carries no ~72 KiB fixed reservation --
        // KeepAlive runs ~every 10s under the lock, so a per-tick malloc/free is
        // negligible. If the buffer is empty or a malloc fails, nSkip stays 0 ->
        // no suppression this tick (the bounded, harmless redundant re-fetch the
        // volume analysis already accepts), never a crash.
        size_t nBuf = BRCFScanLedgerBufferedCount(&manager->cfLedger);
        UInt256  *bufHashes   = nBuf ? malloc(nBuf * sizeof(*bufHashes))   : NULL;
        uint32_t *skipHeights = nBuf ? malloc(nBuf * sizeof(*skipHeights)) : NULL;
        size_t nSkip = 0;
        if (bufHashes && skipHeights) {
            size_t got = BRCFScanLedgerBufferedHashes(&manager->cfLedger, bufHashes, nBuf);
            for (size_t i = 0; i < got; i++) {
                BRMerkleBlock *b = BRSetGet(manager->blocks, &bufHashes[i]);
                if (b && b->height != BLOCK_UNKNOWN_HEIGHT) skipHeights[nSkip++] = b->height;
            }
        }

        uint32_t tipH = manager->lastBlock ? manager->lastBlock->height : 0, minH = 0;
        for (unsigned n = 0; n < CF_REREQ_BATCH_PER_TICK; n++) {
            uint32_t rs = 0, re = 0;
            if (! BRCFScanLedgerPeekRerequestRange(&manager->cfLedger, nowSec, minH, &rs, &re)) break;

            // Reverse-map suppressor: rs's canonical block is currently buffered
            // (in-flight via the buffer-drain path) -- skip past just rs so the
            // next peek can still offer rs+1..re, the same skip-past idiom as the
            // tip clip below. A buffered height sparse mid-run may ride along in a
            // coalesced range: the accepted, bounded (backoff x 5-cap) redundant
            // fetch -- deliberately NOT prevented here (no per-candidate walk).
            int rsInFlight = 0;
            for (size_t i = 0; i < nSkip; i++) { if (skipHeights[i] == rs) { rsInFlight = 1; break; } }
            if (rsInFlight) { minH = rs + 1; continue; }

            uint32_t cap = (re <= tipH) ? re : tipH;
            if (cap < rs) { minH = re + 1; continue; }  // whole offered run is beyond the tip -- skip past it

            // Rotate away from whichever peer this hole's lowest height was last
            // sent to (if any) -- same "don't re-dial the peer that just dropped
            // it" intent as the forward driver's peer selection.
            UInt128 avoidA = UINT128_ZERO;
            uint16_t avoidP = 0;
            for (size_t i = 0; i < manager->cfLedger.outstandingCount; i++) {
                if (manager->cfLedger.outstanding[i].height == rs) {
                    avoidA = manager->cfLedger.outstanding[i].peer;
                    avoidP = manager->cfLedger.outstanding[i].port;
                    break;
                }
            }

            BRPeer *chosen = NULL, *any = NULL;
            for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
                BRPeer *p = manager->connectedPeers[i - 1];
                if (! _BRPeerManagerPeerCanServeFilters(p)) continue;
                if (! any) any = p;
                if (avoidP != 0 && p->port == avoidP && UInt128Eq(p->address, avoidA)) continue;
                chosen = p;
                break;
            }
            if (! chosen) chosen = any;
            if (! chosen) break; // no CF-capable peer connected at all -- nothing to do this tick

            size_t sent = _BRPeerManagerRequestCFiltersLocked(manager, rs, cap, chosen, NULL);
            if (sent > 0) {
                BRCFScanLedgerCommitRerequest(&manager->cfLedger, rs, cap, chosen->address, chosen->port, nowSec);
                peer_log(chosen, "cf-ledger: re-requested residual holes [%u..%u]", rs, cap);
            }
            minH = re + 1;
        }
        free(bufHashes);      // per-tick heap skip-set (free(NULL) is safe)
        free(skipHeights);
        manager->cfLedger.lastDriveAt = nowSec;
    }
#endif // CF_LEDGER_DRIVE_REREQUEST

    pthread_mutex_unlock(&manager->lock);
}

void BRPeerManagerDisconnect(BRPeerManager *manager)
{
    struct timespec ts;
    size_t peerThreadCount, dnsThreadCount, maxConnectCount;
    BRPeer *p;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    
    // prevent new peers from being spawned
    maxConnectCount = manager->maxConnectCount;
    manager->maxConnectCount = 0;
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        p = manager->connectedPeers[i - 1];
        manager->connectFailureCount = MAX_CONNECT_FAILURES; // prevent futher automatic reconnect attempts
        BRPeerDisconnect(p);
        if (BRPeerConnectStatus(p) == BRPeerStatusConnecting) manager->peerThreadCount--; // waiting for network
    }
    
    peerThreadCount = manager->peerThreadCount;
    dnsThreadCount = manager->dnsThreadCount;
    pthread_mutex_unlock(&manager->lock);
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    
    while (peerThreadCount > 0 || dnsThreadCount > 0) {
        nanosleep(&ts, NULL); // pthread_yield() isn't POSIX standard :(
        pthread_mutex_lock(&manager->lock);
        peerThreadCount = manager->peerThreadCount;
        dnsThreadCount = manager->dnsThreadCount;
        pthread_mutex_unlock(&manager->lock);
    }
    
    pthread_mutex_lock(&manager->lock);
    manager->maxConnectCount = maxConnectCount;
    pthread_mutex_unlock(&manager->lock);
}

// rescans blocks and transactions after earliestKeyTime (a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter)
void BRPeerManagerRescan(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    
    if (manager->isConnected) {
        // start the chain download from the most recent checkpoint that's at least a week older than earliestKeyTime
        
        if (manager->startSyncFrom != NULL) {
            // There is a block, from which we want to start the sync
            // startSyncFrom must be added in initialization
            manager->lastBlock = manager->startSyncFrom;
            BRSetAdd(manager->blocks, manager->lastBlock);
        } else {
            for (size_t i = manager->params->checkpointsCount; i > 0; i--) {
                if (i - 1 == 0 || manager->params->checkpoints[i - 1].timestamp + 7*24*60*60 < manager->earliestKeyTime) {
                    UInt256 hash = UInt256Reverse(manager->params->checkpoints[i - 1].hash);

                    BRMerkleBlock* temp = BRSetGet(manager->blocks, &hash);
                    if (temp != NULL)
                        manager->lastBlock = temp;
                    break;
                }
            }
        }
        
        if (manager->downloadPeer) { // disconnect the current download peer so a new random one will be selected
            for (size_t i = array_count(manager->peers); i > 0; i--) {
                if (BRPeerEq(&manager->peers[i - 1], manager->downloadPeer)) array_rm(manager->peers, i - 1);
            }
            
            BRPeerDisconnect(manager->downloadPeer);
        }

        manager->syncStartHeight = 0; // a syncStartHeight of 0 indicates that syncing hasn't started yet
        pthread_mutex_unlock(&manager->lock);
        BRPeerManagerConnect(manager);
    }
    else pthread_mutex_unlock(&manager->lock);
}

// the (unverified) best block height reported by connected peers
uint32_t BRPeerManagerEstimatedBlockHeight(BRPeerManager *manager)
{
    assert(manager != NULL);
    // Lock-free read of the cached mirrors (_BRPeerManagerRefreshCachedStatus keeps
    // them current under the lock). Avoids blocking the UI thread behind a heavy sync.
    uint32_t last = atomic_load_explicit(&manager->cachedLastHeight, memory_order_relaxed);
    uint32_t est  = atomic_load_explicit(&manager->cachedEstimatedHeight, memory_order_relaxed);
    return (last < est) ? est : last;
}

// current proof-of-work verified best block height
uint32_t BRPeerManagerLastBlockHeight(BRPeerManager *manager)
{
    assert(manager != NULL);
    return atomic_load_explicit(&manager->cachedLastHeight, memory_order_relaxed);
}

// current proof-of-work verified best block timestamp (time interval since unix epoch)
uint32_t BRPeerManagerLastBlockTimestamp(BRPeerManager *manager)
{
    assert(manager != NULL);
    return atomic_load_explicit(&manager->cachedLastTimestamp, memory_order_relaxed);
}

// current network sync progress from 0 to 1
// startHeight is the block height of the most recent fully completed sync
double  BRPeerManagerSyncProgress(BRPeerManager *manager, uint32_t startHeight)
{
    assert(manager != NULL);
    // Lock-free: recompute from the cached mirrors so the overlay poll can't block
    // behind a heavy compact-filter sync holding manager->lock.
    uint32_t last      = atomic_load_explicit(&manager->cachedLastHeight, memory_order_relaxed);
    uint32_t est       = atomic_load_explicit(&manager->cachedEstimatedHeight, memory_order_relaxed);
    uint32_t syncStart = atomic_load_explicit(&manager->cachedSyncStartHeight, memory_order_relaxed);
    int hasDownloadPeer = atomic_load_explicit(&manager->cachedHasDownloadPeer, memory_order_relaxed);
    double progress;

    if (startHeight == 0) startHeight = syncStart;

    if (! hasDownloadPeer && syncStart == 0) {
        progress = 0.0;
    }
    else if (! hasDownloadPeer || last < est) {
        if (last > startHeight && est > startHeight) {
            progress = 0.001 + 0.999 * (last - startHeight)/(double)(est - startHeight);
        }
        else progress = 0.001;
    }
    else progress = 1.0;

    return progress;
}

// returns the number of currently connected peers
size_t BRPeerManagerPeerCount(BRPeerManager *manager)
{
    assert(manager != NULL);
    int c = atomic_load_explicit(&manager->cachedPeerCount, memory_order_relaxed);
    return (c > 0) ? (size_t)c : 0;
}

// description of the peer most recently used to sync blockchain data
const char *BRPeerManagerDownloadPeerName(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);

    if (manager->downloadPeer) {
        sprintf(manager->downloadPeerName, "%s:%d", BRPeerHost(manager->downloadPeer), manager->downloadPeer->port);
    }
    else manager->downloadPeerName[0] = '\0';
    
    pthread_mutex_unlock(&manager->lock);
    return manager->downloadPeerName;
}

static void _publishTxInvDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    
    free(info);
    pthread_mutex_lock(&manager->lock);
    _BRPeerManagerRequestUnrelayedTx(manager, peer);
    pthread_mutex_unlock(&manager->lock);
}

// publishes tx to bitcoin network (do not call BRTransactionFree() on tx afterward)
void BRPeerManagerSetDandelionEnabled(BRPeerManager *manager, int enabled)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->dandelionEnabled = (enabled != 0);
    pthread_mutex_unlock(&manager->lock);
}

void BRPeerManagerAddDandelionPeer(BRPeerManager *manager, UInt128 address)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    int known = 0;
    for (size_t i = array_count(manager->dandelionPeers); i > 0; i--) {
        if (UInt128Eq(manager->dandelionPeers[i - 1], address)) { known = 1; break; }
    }
    if (! known) array_add(manager->dandelionPeers, address);
    pthread_mutex_unlock(&manager->lock);
}

// caller must hold manager->lock
static int _BRPeerManagerPeerIsDandelionCapable(BRPeerManager *manager, BRPeer *peer)
{
    for (size_t i = array_count(manager->dandelionPeers); i > 0; i--) {
        if (UInt128Eq(manager->dandelionPeers[i - 1], peer->address)) return 1;
    }
    return 0;
}

// caller must hold manager->lock; returns first connected Dandelion-capable peer or NULL
static BRPeer *_BRPeerManagerAnyDandelionPeer(BRPeerManager *manager)
{
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if (_BRPeerManagerPeerIsDandelionCapable(manager, p)) return p;
    }
    return NULL;
}

int BRPeerManagerHasDandelionPeer(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    int r = manager->dandelionEnabled && _BRPeerManagerAnyDandelionPeer(manager) != NULL;
    pthread_mutex_unlock(&manager->lock);
    return r;
}

int BRPeerManagerStemPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                               void (*callback)(void *info, int error))
{
    assert(manager != NULL && tx != NULL);
    if (! BRTransactionIsSigned(tx)) return 0;   // let the flood path report EINVAL
    pthread_mutex_lock(&manager->lock);

    if (! manager->isConnected) { pthread_mutex_unlock(&manager->lock); return 0; }

    BRPeer *stem = manager->dandelionEnabled ? _BRPeerManagerAnyDandelionPeer(manager) : NULL;
    if (! stem) { pthread_mutex_unlock(&manager->lock); return 0; }   // caller floods instead

    tx->is_dandelion = 1;
    tx->timestamp = (uint32_t)time(NULL);
    _BRPeerManagerAddTxToPublishList(manager, tx, info, callback);

    BRPeerCallbackInfo *peerInfo = calloc(1, sizeof(*peerInfo));
    assert(peerInfo != NULL);
    peerInfo->peer = stem;
    peerInfo->manager = manager;
    _BRPeerManagerPublishPendingTx(manager, stem);      // inv(inv_tx) to the stem peer only
    BRPeerSendPing(stem, peerInfo, _publishTxInvDone);  // ping→pong confirms the inv was sent

    peer_log(stem, "dandelion: stem-submitted tx %s to single peer", u256hex(tx->txHash));
    pthread_mutex_unlock(&manager->lock);
    return 1;
}

void BRPeerManagerFluffTx(BRPeerManager *manager, UInt256 txHash)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);

    BRTransaction *tx = NULL;
    for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
        if (UInt256Eq(manager->publishedTx[i - 1].tx->txHash, txHash)) {
            tx = manager->publishedTx[i - 1].tx; break;
        }
    }
    if (! tx) { pthread_mutex_unlock(&manager->lock); return; }
    tx->is_dandelion = 0;   // fluff: a normal tx from here on

    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *peer = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(peer) != BRPeerStatusConnected) continue;
        _BRPeerManagerPublishPendingTx(manager, peer);
        BRPeerCallbackInfo *peerInfo = calloc(1, sizeof(*peerInfo));
        assert(peerInfo != NULL);
        peerInfo->peer = peer;
        peerInfo->manager = manager;
        BRPeerSendPing(peer, peerInfo, _publishTxInvDone);
    }
    // Peer-less log (see the _peer_log note at the "sync failed" site above): passing
    // the bare BR_PEER_NONE sentinel to peer_log casts it to BRPeerContext* and writes
    // inet_ntop's host string past the end of the ~40-byte stack temporary — a stack
    // buffer overflow (-fstack-protector abort). Use the peer-less _peer_log.
    _peer_log("dandelion: embargo fluff — flooded tx %s to all peers\n", u256hex(txHash));
    pthread_mutex_unlock(&manager->lock);
}

void BRPeerManagerPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                            void (*callback)(void *info, int error))
{
    assert(manager != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));
    if (tx) pthread_mutex_lock(&manager->lock);
    
    if (tx && ! BRTransactionIsSigned(tx)) {
        pthread_mutex_unlock(&manager->lock);
        BRTransactionFree(tx);
        tx = NULL;
        if (callback) callback(info, EINVAL); // transaction not signed
    }
    else if (tx && ! manager->isConnected) {
        int connectFailureCount = manager->connectFailureCount;

        pthread_mutex_unlock(&manager->lock);

        if (connectFailureCount >= MAX_CONNECT_FAILURES ||
            (manager->networkIsReachable && ! manager->networkIsReachable(manager->info))) {
            BRTransactionFree(tx);
            tx = NULL;
            if (callback) callback(info, ENOTCONN); // not connected to bitcoin network
        }
        else pthread_mutex_lock(&manager->lock);
    }
    
    if (tx) {
        size_t i, count = 0;
        
        tx->timestamp = (uint32_t)time(NULL); // set timestamp to publish time
        _BRPeerManagerAddTxToPublishList(manager, tx, info, callback);

        for (i = array_count(manager->connectedPeers); i > 0; i--) {
            if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) == BRPeerStatusConnected) count++;
        }

        for (i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *peer = manager->connectedPeers[i - 1];
            BRPeerCallbackInfo *peerInfo;

            if (BRPeerConnectStatus(peer) != BRPeerStatusConnected) continue;
            
            // instead of publishing to all peers, leave out downloadPeer to see if tx propogates/gets relayed back
            // TODO: XXX connect to a random peer with an empty or fake bloom filter just for publishing
            if (peer != manager->downloadPeer || count == 1) {
                _BRPeerManagerPublishPendingTx(manager, peer);
                peerInfo = calloc(1, sizeof(*peerInfo));
                assert(peerInfo != NULL);
                peerInfo->peer = peer;
                peerInfo->manager = manager;
                BRPeerSendPing(peer, peerInfo, _publishTxInvDone);
            }
        }

        pthread_mutex_unlock(&manager->lock);
    }
}

// number of connected peers that have relayed the given unconfirmed transaction
size_t BRPeerManagerRelayCount(BRPeerManager *manager, UInt256 txHash)
{
    size_t count = 0;

    assert(manager != NULL);
    assert(! UInt256IsZero(txHash));
    pthread_mutex_lock(&manager->lock);
    
    for (size_t i = array_count(manager->txRelays); i > 0; i--) {
        if (! UInt256Eq(manager->txRelays[i - 1].txHash, txHash)) continue;
        count = array_count(manager->txRelays[i - 1].peers);
        break;
    }
    
    pthread_mutex_unlock(&manager->lock);
    return count;
}

// frees memory allocated for manager
void BRPeerManagerFree(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    array_free(manager->peers);
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) BRPeerFree(manager->connectedPeers[i - 1]);
    array_free(manager->connectedPeers);
    BRSetApply(manager->blocks, NULL, _setApplyFreeBlock);
    BRSetFree(manager->blocks);
    BRSetApply(manager->orphans, NULL, _setApplyFreeBlock);
    BRSetFree(manager->orphans);
    BRSetFree(manager->checkpoints);
    for (size_t i = array_count(manager->txRelays); i > 0; i--) array_free(manager->txRelays[i - 1].peers);
    array_free(manager->txRelays);
    for (size_t i = array_count(manager->txRequests); i > 0; i--) array_free(manager->txRequests[i - 1].peers);
    array_free(manager->txRequests);
    array_free(manager->publishedTx);
    array_free(manager->publishedTxHashes);
    array_free(manager->dandelionPeers);
    if (manager->compactFilterChain) {
        BRCompactFilterChainFree(manager->compactFilterChain);
        manager->compactFilterChain = NULL;
    }
    BRCFScanLedgerFree(&manager->cfLedger); // frees any still-buffered raw filter bytes (Phase 2 Task 2)
    BRWalletFilterElementsFree(manager->cfElems); // NULL-safe; cached BIP 158 element set
    manager->cfElems = NULL;
    manager->cfElemsAddrGen = 0;
    manager->cfElemsAddrCount = 0;
    pthread_mutex_unlock(&manager->lock);
    pthread_mutex_destroy(&manager->lock);
    free(manager);
}

// --- BIP 158 public API ---------------------------------------------------

void BRPeerManagerSetSyncMode(BRPeerManager *manager, BRSyncMode mode)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->syncMode = mode;
    _BRPeerManagerRefreshCachedStatus(manager);
    pthread_mutex_unlock(&manager->lock);
}

BRSyncMode BRPeerManagerGetSyncMode(BRPeerManager *manager)
{
    // Defense-in-depth: a NULL manager (no wallet loaded yet) defaults to
    // compact-filters-only. The wallet always runs CF-only (bloom is never
    // selected — see syncModeFor in CustomNode.kt); the old BLOOM_ONLY
    // null-default predated that decision.
    if (!manager) return BR_SYNC_MODE_COMPACT_FILTERS_ONLY;
    return (BRSyncMode)atomic_load_explicit(&manager->cachedSyncMode, memory_order_relaxed);
}

// BRPeerManagerFallbackToBloom removed — no live caller (the Kotlin watchdog
// never invoked fallbackToBloom(); every former bloom-fallback branch stays on
// filters). Its JNI wrapper (Java_..._fallbackToBloom) is removed alongside it.

// Current cfheaders tip height (height of the last header we've stored).
// 0 if no chain yet. Used by the watchdog to detect "no progress."
uint32_t BRPeerManagerCFChainTipHeight(BRPeerManager *manager)
{
    if (!manager) return 0;
    // Lock-free: cachedCFTip mirrors BRCompactFilterChainNextHeight (start+count);
    // the tip is one below that. 0 means no chain yet.
    uint32_t next = atomic_load_explicit(&manager->cachedCFTip, memory_order_relaxed);
    return next > 0 ? next - 1 : 0;
}

// Lowest contiguous block height reachable by walking prevBlock links from
// lastBlock through the block set — i.e. the deepest height the cfheaders
// stop-hash lookup can still resolve. Returns 0 if there is no lastBlock.
// Caller must hold manager->lock.
static uint32_t _BRPeerManagerBlockFloor(BRPeerManager *manager)
{
    BRMerkleBlock *b = manager->lastBlock;
    if (!b) return 0;
    for (;;) {
        BRMerkleBlock *prev = BRSetGet(manager->blocks, &b->prevBlock);
        if (!prev) break;
        b = prev;
    }
    return b->height;
}

// Re-anchor the compact-filter chain at the current block floor when cfTip has
// fallen below the lowest contiguous downloaded block — a legacy deficit the
// header-retention fix cannot bridge, because the gap blocks were never
// re-downloaded this session. Discards the stuck chain so the next cfheaders
// response TOFU-creates a fresh one at the floor (the existing lazy-create path
// in _peerRelayedCFHeaders). Returns 1 if it re-anchored, 0 otherwise.
//
// The historical gap [old cfTip, floor] is intentionally skipped: those blocks
// were already scanned by bloom in prior sessions. The caller (SyncService
// watchdog) gates this on has_synced, which is that guarantee.
// Discard the compact-filter chain and re-anchor at the block floor. Caller MUST
// hold manager->lock. With force=0 (watchdog path) only re-anchors when cfTip is
// below the floor (the unbridgeable-gap case). With force=1 (continuity-failure
// recovery) re-anchors regardless — the chain is divergent wherever cfTip sits.
// Returns 1 if it re-anchored, 0 otherwise.
static int _BRPeerManagerReanchorAtFloorLocked(BRPeerManager *manager, int force)
{
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY || !manager->compactFilterChain) return 0;

    uint32_t next  = BRCompactFilterChainNextHeight(manager->compactFilterChain);
    uint32_t floor = _BRPeerManagerBlockFloor(manager);
    if (floor == 0) return 0;
    if (!force && next >= floor) return 0;   // watchdog path keeps the cfTip<floor guard

    // Peer-less log (see the _peer_log note at the "sync failed" site above): passing the
    // bare BR_PEER_NONE sentinel to peer_log casts it to BRPeerContext* and writes
    // inet_ntop's host string past the end of the ~40-byte stack temporary — a stack
    // buffer overflow (-fstack-protector abort). This re-anchor line is the CONFIRMED
    // crash site (tombstone: SIGABRT "stack corruption detected", Galaxy S25 Ultra,
    // v3.10.29). Use the peer-less _peer_log.
    _peer_log("cfheaders: re-anchoring filter chain (force=%d) from tip %u to block floor %u\n",
              force, next > 0 ? next - 1 : 0, floor);

    BRCompactFilterChainFree(manager->compactFilterChain);
    manager->compactFilterChain = NULL;
    // Arm auto-fetch so the chain-less driver resolves `next` to the floor (not
    // genesis) and the lazy-create in _peerRelayedCFHeaders uses it.
    manager->autoFetchCFiltersEnabled  = 1;
    manager->autoFetchCFiltersStart    = floor;
    manager->autoFetchCFiltersThrough  = floor > 0 ? floor - 1 : 0;
    // Re-anchor rebuilds the CF scan-completeness ledger at the floor (Phase 1: observe-only).
    BRCFScanLedgerInit(&manager->cfLedger, floor);
#if CF_LEDGER_DRIVE_REREQUEST
    // Explicit/defensive (Task 5 EDIT 4): stale buffered raw filter bytes from the
    // pre-reanchor chain must not survive — Init already frees them internally.
    BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
    manager->cfHeadersRequestedThrough = 0;
    manager->cfDisagreedCount          = 0;   // fresh disagreement window
    manager->cfSingleDisagreeRounds    = 0;   // fresh single-peer diverged-round window

    // Kick recovery immediately if a filter peer is connected; otherwise the
    // next block-extend kick handles it once filter-first connects one.
    BRPeer *fp = _BRPeerManagerAnyFilterCapablePeer(manager);
    if (fp) _BRPeerManagerRequestNextCFHeaders(manager, fp);
    return 1;
}

int BRPeerManagerReanchorCompactFilterChainAtFloor(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    int r = _BRPeerManagerReanchorAtFloorLocked(manager, 0);
    pthread_mutex_unlock(&manager->lock);
    return r;
}

// Proactively re-issue a FULL-LOCATOR getheaders to every connected peer. All
// getheaders senders are otherwise reactive (sync-start, relayed inv/orphan,
// headers-continuation), so once the wallet reaches its stale estimatedHeight it
// goes idle — a tip with live-but-silent peers (half-dead socket answering pings,
// non-announcing/lagging download peer) then freezes forever and stops confirming
// txs. The Kotlin tip-stall watchdog calls this on a clock (peers>0 AND blockTip
// frozen N min) to un-stick BOTH modes: behind-and-stopped resumes; a connectable
// dead-branch walks back via the shared ancestors in the full locators (same
// _BRPeerManagerBlockLocators + BRPeerSendGetheaders the orphan re-anchor uses).
// Benign no-op on a healthy at-tip wallet: peers reply 0 headers ("reached tip"),
// no reorg, no disconnect. Returns the number of peers the request was sent to.
int BRPeerManagerRerequestHeadersFromTip(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    int sent = 0;
    if (manager->isConnected && array_count(manager->connectedPeers) > 0) {
        UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
        size_t locatorsCount = _BRPeerManagerBlockLocators(manager, locators,
                                                           sizeof(locators) / sizeof(*locators));
        for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *peer = manager->connectedPeers[i - 1];
            if (BRPeerConnectStatus(peer) != BRPeerStatusConnected) continue;
            BRPeerSendGetheaders(peer, locators, locatorsCount, UINT256_ZERO);
            sent++;
        }
        if (sent > 0) {
            _peer_log("tip-stall: re-requested headers (full locator) from %d peer(s)\n", sent);
        }
    }
    pthread_mutex_unlock(&manager->lock);
    return sent;
}

void BRPeerManagerSetCompactFilterChain(BRPeerManager *manager, BRCompactFilterChain *chain)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    if (manager->compactFilterChain && manager->compactFilterChain != chain) {
        BRCompactFilterChainFree(manager->compactFilterChain);
    }
    manager->compactFilterChain = chain;
    pthread_mutex_unlock(&manager->lock);
}

const BRCompactFilterChain *BRPeerManagerGetCompactFilterChain(BRPeerManager *manager)
{
    // Borrowed pointer — caller must not call this concurrently with
    // SetCompactFilterChain/Free. PeerManager's normal usage pattern is
    // single-owner inside JNI, so this matches existing accessors like
    // BRPeerManagerLastBlockHeight.
    return manager ? manager->compactFilterChain : NULL;
}

void BRPeerManagerSetSaveFilterHeaders(BRPeerManager *manager, void *info,
                                       void (*saveFilterHeaders)(void *info,
                                                                  const BRCompactFilterChain *chain))
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->saveFilterHeadersInfo = info;
    manager->saveFilterHeaders = saveFilterHeaders;
    pthread_mutex_unlock(&manager->lock);
}

// ---- CF scan-completeness ledger accessors (Phase 1: guarded reads) --------
// These take manager->lock for every read; the lock-free bridge mirror (like the
// cachedCFTip pattern) is a later sequence. Safe on a zeroed/never-armed ledger.

void BRPeerManagerCFLedgerCounts(BRPeerManager *manager, uint32_t *scannedThrough, uint32_t *outstanding,
                                 uint32_t *gaveUp, uint32_t *pending)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    if (scannedThrough) *scannedThrough = BRCFScanLedgerScannedThrough(&manager->cfLedger);
    if (outstanding)    *outstanding    = (uint32_t)BRCFScanLedgerOutstandingCount(&manager->cfLedger);
    if (gaveUp)         *gaveUp         = (uint32_t)BRCFScanLedgerGaveUpCount(&manager->cfLedger);
    if (pending)        *pending        = (uint32_t)manager->cfLedger.pendingCount;
    pthread_mutex_unlock(&manager->lock);
}

size_t BRPeerManagerCFLedgerHoleRanges(BRPeerManager *manager, uint32_t *outStarts, uint32_t *outEnds, size_t cap)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    size_t n = BRCFScanLedgerHoleRanges(&manager->cfLedger, outStarts, outEnds, cap);
    pthread_mutex_unlock(&manager->lock);
    return n;
}

size_t BRPeerManagerCFLedgerSerialize(BRPeerManager *manager, uint8_t *buf, size_t buflen)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    size_t n = BRCFScanLedgerSerialize(&manager->cfLedger, buf, buflen);
    pthread_mutex_unlock(&manager->lock);
    return n;
}

int BRPeerManagerCFLedgerRestore(BRPeerManager *manager, const uint8_t *buf, size_t buflen)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    int ok = BRCFScanLedgerParse(&manager->cfLedger, buf, buflen);
    pthread_mutex_unlock(&manager->lock);
    return ok;
}

void BRPeerManagerSetSaveCFLedger(BRPeerManager *manager, void *info,
                                  void (*callback)(void *info, const uint8_t *bytes, size_t len))
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->saveCFLedgerInfo = info;
    manager->saveCFLedger = callback;
    pthread_mutex_unlock(&manager->lock);
}

// Lock-held internal helper. Caller must hold manager->lock. Returns the
// number of blocks actually requested or 0 if no eligible peer was found.
static int _BRPeerManagerPeerCanServeFilters(BRPeer *p)
{
    return p && BRPeerConnectStatus(p) == BRPeerStatusConnected &&
           BRPeerIsSocketOpen(p) &&
           (p->services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS;
}

static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight,
                                                  BRPeer *preferred, uint32_t *outStop)
{
    if (outStop) *outStop = 0;
    if (stopHeight < startHeight) return 0;
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return 0;

    uint32_t cap = startHeight + (MAX_CFILTERS_RESULTS - 1);
    if (stopHeight > cap) stopHeight = cap;

    UInt256 stopHash = _BRPeerManagerBlockHashAtHeight(manager, stopHeight);

#ifndef CFILTER_REQUEST_SILENT_STOPHASH_UNFIXED
    if (UInt256IsZero(stopHash)) {
        // The stop hash is resolved by walking prevBlock links down from lastBlock, so it
        // is unresolvable exactly when stopHeight has fallen below the resident block
        // floor. That happens routinely and by design: _BRPeerManagerClearMemory anchors
        // its floor to the CFHEADER frontier (cfNext - CLEAR_MEM_CF_RETENTION_MARGIN),
        // cfheaders advance 2000 per message while this driver advances at most
        // MAX_CFILTERS_RESULTS per cfheaders arrival, so the filter cursor falls further
        // behind cfNext on every message until the headers it still needs are pruned.
        //
        // This used to be a bare `return 0`. The caller only advances
        // autoFetchCFiltersThrough when something was sent, so returning 0 froze the
        // cursor PERMANENTLY — no further getcfilters, ever, not even at the tip, so
        // incoming transactions stopped being detected. Silently: there was no log line,
        // and no watchdog reads the scan frontier (deriveSyncFrontier consumes cfTip,
        // which keeps tracking the tip), so the wallet went on reporting Synced.
        // Reproduced on a FRESH wallet, API 33: frozen 25,928 blocks short of the tip.
        //
        // Forward progress now takes priority over contiguity. Snap the request up to the
        // resolvable floor so the tip keeps getting covered; the skipped band stays in the
        // ledger's outstanding set, so it is visible (Network Info) and recoverable
        // (rescan / node reconcile) instead of being an invisible permanent hole. Losing
        // tip coverage is strictly worse than a recorded gap: it hides incoming money.
        uint32_t floorH = _BRPeerManagerBlockFloor(manager);

        if (floorH > startHeight) {
            // Take a FULL batch from the floor. Do NOT clamp to the caller's stopHeight:
            // that value is below the floor by construction here (it is what we could not
            // resolve), so clamping to it yields a 1-height request — measured on device
            // as "skipping 1999 height(s) ... requesting [H..H]", i.e. skipping 99.95% of
            // the chain while appearing to progress. The real ceiling is the validated
            // cfheader frontier: requesting filters above it would leave them unverifiable.
            uint32_t cfTipH = manager->compactFilterChain
                              ? BRCompactFilterChainNextHeight(manager->compactFilterChain)
                              : 0;
            if (cfTipH > 0) cfTipH -= 1;

            uint32_t snapStop = floorH + (MAX_CFILTERS_RESULTS - 1);
            if (cfTipH > 0 && snapStop > cfTipH) snapStop = cfTipH;
            if (snapStop < floorH) snapStop = floorH;

            UInt256 snapHash = _BRPeerManagerBlockHashAtHeight(manager, snapStop);
            if (! UInt256IsZero(snapHash)) {
                // preferred may be NULL (KeepAlive backstop / the public request entry point),
                // and peer_log dereferences it.
                if (preferred) {
                    peer_log(preferred, "cfilters: [%u..%u] is below the resident block floor %u — "
                             "skipping %u height(s) to keep the tip covered, requesting [%u..%u] "
                             "(the skipped band stays a recorded hole)",
                             startHeight, stopHeight, floorH, floorH - startHeight, floorH, snapStop);
                }
                else {
                    debug_log("cfilters: [%u..%u] is below the resident block floor %u — skipping %u "
                              "height(s) to keep the tip covered, requesting [%u..%u]\n",
                              startHeight, stopHeight, floorH, floorH - startHeight, floorH, snapStop);
                }
                startHeight = floorH;
                stopHeight = snapStop;
                stopHash = snapHash;
            }
        }
    }

    if (UInt256IsZero(stopHash)) {
        // Never silent: if even the floor could not be resolved we make no progress this
        // round, but say so, because this is the shape of the permanent freeze.
        if (preferred) {
            peer_log(preferred, "cfilters: cannot resolve a stop hash for [%u..%u] (resident floor %u, "
                     "lastBlock %u) — no filters requested this round",
                     startHeight, stopHeight, _BRPeerManagerBlockFloor(manager),
                     manager->lastBlock ? manager->lastBlock->height : 0);
        }
        else {
            debug_log("cfilters: cannot resolve a stop hash for [%u..%u] (resident floor %u, "
                      "lastBlock %u) — no filters requested this round\n",
                      startHeight, stopHeight, _BRPeerManagerBlockFloor(manager),
                      manager->lastBlock ? manager->lastBlock->height : 0);
        }
        return 0;
    }
#else
    // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a production
    // build). A bare, silent return that freezes the cursor forever.
    if (UInt256IsZero(stopHash)) return 0;
#endif

    uint8_t filterType = manager->compactFilterChain
                         ? BRCompactFilterChainType(manager->compactFilterChain)
                         : FILTER_TYPE_BASIC;

    // R3 (Neutrino review): prefer the peer that just delivered these cfheaders.
    // It's a proven-responsive filter peer, and because the cfheaders driver
    // rotates that peer off on stall, cfilters follow the rotation (implicit
    // failover) instead of pinning the FIRST connected peer — which may be slow
    // or a dead-socket zombie, stranding the tail of the sync ("stuck at 99%").
    // Fall back to the first LIVE (socket-open) filter peer, skipping zombies.
    BRPeer *target = _BRPeerManagerPeerCanServeFilters(preferred) ? preferred : NULL;
    if (!target) {
        // Prefer a peer that is NOT servicing the in-flight cfheaders request. A bulk
        // cfilter burst shares that peer's socket, and the cfheaders driver times its
        // response out after CF_REQUEST_TIMEOUT_SECS (5 s) — so head-of-line blocking it
        // trips rotation and, after a full rotation, _BRPeerManagerDropStalledFilterPeer.
        // That is peer churn caused by our own throughput, which is exactly what the
        // self-clocked drive would otherwise make worse.
        for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            if (! _BRPeerManagerPeerCanServeFilters(p)) continue;
            if (! UInt128IsZero(manager->cfHeadersPeerAddr) &&
                UInt128Eq(p->address, manager->cfHeadersPeerAddr)) continue;   // busy with cfheaders
            target = p;
            break;
        }
    }
    if (!target) {
        // Second pass without the exclusion: one filter peer is better than none.
        for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            if (! _BRPeerManagerPeerCanServeFilters(p)) continue;
            target = p;
            break;
        }
    }
    if (!target) return 0;

    BRPeerSendGetCFilters(target, filterType, startHeight, stopHash);
    if (outStop) *outStop = stopHeight;
    return stopHeight - startHeight + 1;
}

size_t BRPeerManagerRequestCompactFilters(BRPeerManager *manager,
                                          uint32_t startHeight, uint32_t stopHeight)
{
    if (!manager) return 0;
    pthread_mutex_lock(&manager->lock);
    size_t n = _BRPeerManagerRequestCFiltersLocked(manager, startHeight, stopHeight, NULL, NULL);
    pthread_mutex_unlock(&manager->lock);
    return n;
}

void BRPeerManagerEnableAutoCompactFilterFetch(BRPeerManager *manager, uint32_t startHeight)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);

    // Clamp startHeight up to a value the in-memory block window can
    // resolve. _BRPeerManagerBlockHashAtHeight walks lastBlock backwards
    // via prevBlock pointers; if startHeight is below that window the
    // cfheaders driver defers forever (stopHash for batchEnd never
    // exists). Callers commonly request startHeight=0 either because a
    // fresh wallet has not loaded saved blocks yet or because the caller
    // can't resolve the wallet's birth height pre-startSync; either way
    // we still want filters to work, so anchor near lastBlock.
    if (manager->lastBlock && startHeight < manager->lastBlock->height) {
        UInt256 startHash = _BRPeerManagerBlockHashAtHeight(manager, startHeight);
        if (UInt256IsZero(startHash)) {
            uint32_t tipHeight = manager->lastBlock->height;
            // Back off by one cfheaders batch from tip so the first batch
            // is filled and subsequent batches advance forward. Subsequent
            // batches resolve their own stopHash via the filter chain so
            // don't need a margin.
            uint32_t margin = (MAX_CFHEADERS_RESULTS > 1) ? (MAX_CFHEADERS_RESULTS - 1) : 0;
            startHeight = (tipHeight > margin) ? tipHeight - margin : 0;
            // Belt-and-suspenders: if the clamped value is still
            // unreachable (e.g. fresh wallet with only a sparse checkpoint
            // in manager->blocks), fall back to lastBlock->height itself
            // which is always resolvable.
            UInt256 clampedHash = _BRPeerManagerBlockHashAtHeight(manager, startHeight);
            if (UInt256IsZero(clampedHash)) startHeight = tipHeight;
        }
    }

    manager->autoFetchCFiltersEnabled = 1;
    manager->autoFetchCFiltersStart = startHeight;
    // Reset cursor to (start - 1) so the first cfheaders batch covering the
    // range immediately triggers a cfilter fetch at startHeight.
    manager->autoFetchCFiltersThrough = (startHeight > 0) ? startHeight - 1 : 0;
    // Rebuild the CF scan-completeness ledger at the same floor (Phase 1: observe-only).
    BRCFScanLedgerInit(&manager->cfLedger, startHeight);
#if CF_LEDGER_DRIVE_REREQUEST
    // Explicit/defensive (Task 5 EDIT 4): re-arm must not carry stale buffered raw
    // filter bytes from before this (re-)enable — Init already frees them internally.
    BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
    pthread_mutex_unlock(&manager->lock);
}

void BRPeerManagerDisableAutoCompactFilterFetch(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->autoFetchCFiltersEnabled = 0;
    manager->autoFetchCFiltersStart = 0;
    manager->autoFetchCFiltersThrough = 0;
#if CF_LEDGER_DRIVE_REREQUEST
    // Hygiene (Task 5 EDIT 4): a disable must not leave stale buffered bytes
    // lingering — unlike the re-anchor/re-arm sites, Disable does NOT call
    // BRCFScanLedgerInit, so this is the only place that clears them here.
    BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
    pthread_mutex_unlock(&manager->lock);
}

uint32_t BRPeerManagerGetAutoFetchCFiltersStart(BRPeerManager *manager)
{
    if (!manager) return 0;
    pthread_mutex_lock(&manager->lock);
    uint32_t height = manager->autoFetchCFiltersStart;
    pthread_mutex_unlock(&manager->lock);
    return height;
}

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

BRPeerManager* BPPeerManagerMainNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock) {
    return BRPeerManagerNewEx(&BRMainNetParams, wallet, earliestKeyTime, blocks, blocksCount, peers, peersCount, startBlock);
}
BRPeerManager* BPPeerManagerTestNetNewEx(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount, BRMerkleBlock* startBlock) {
    return BRPeerManagerNewEx(&BRTestNetParams, wallet, earliestKeyTime,blocks, blocksCount, peers, peersCount, startBlock);
}

// function to create Peermanager under for the mainnet directly
BRPeerManager *BPPeerManagerMainNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount) {


    
    return BRPeerManagerNew(&BRMainNetParams, wallet, earliestKeyTime, blocks, blocksCount, peers, peersCount);
}

// function to create Peermanager under for the testnet directly
BRPeerManager *BPPeerManagerTestNetNew(BRWallet *wallet, uint32_t earliestKeyTime,
									   BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount) {
	return BRPeerManagerNew(&BRTestNetParams, wallet, earliestKeyTime,blocks, blocksCount, peers,peersCount);
}

