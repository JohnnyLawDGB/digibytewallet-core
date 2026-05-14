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
#include "BRBloomFilter.h"
#include "BRSet.h"
#include "BRArray.h"
#include "BRInt.h"
#include "BRCompactFilterChain.h"
#include "BRGCSFilter.h"
#include "BRWalletFilterElements.h"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
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

#define genesis_block_hash(params) UInt256Reverse((params)->checkpoints[0].hash)

#ifndef BITCOIN_TESTNET
#define BITCOIN_TESTNET 0
#endif

// Since many users experience data corruption issues on iOS, we
//  implement the following procedure in order to prevent the issues.
// We will pass 0xAAAAAAAAAAAAAAAA to the native side (iOS/android), which will then check its value before saving the blocks.
// Important: stackIntegrityCheck_val is marked as volatile memory in order to prevent the compiler from optimizing this variable to a constant.
// Explanation: Assuming that the saveBlocks callback gets called successfully, the stack has to be valid in that very moment. So it's not the stack that's corrupted when calling the callback, but rather the allocated memory of the c-application. Perhaps iOS is killing the C part of the app first, shortly after that, it's killing the native side. Between these two, memory corruption can occur.
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
    uint32_t earliestKeyTime, syncStartHeight, filterUpdateHeight, estimatedHeight;
    BRBloomFilter *bloomFilter;
    double fpRate, averageTxPerBlock;
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
    void (*saveBlocks)(void *info, int replace, BRMerkleBlock *blocks[], size_t blocksCount, uint64_t* stackIntegrityCheck);
    void (*savePeers)(void *info, int replace, const BRPeer peers[], size_t peersCount);
    int (*networkIsReachable)(void *info);
    void (*threadCleanup)(void *info);
    // BIP 158 compact-filter sync (inert unless syncMode != BLOOM_ONLY)
    BRSyncMode syncMode;
    BRCompactFilterChain *compactFilterChain;
    void *saveFilterHeadersInfo;
    void (*saveFilterHeaders)(void *info, const BRCompactFilterChain *chain);
    int autoFetchCFiltersEnabled;
    uint32_t autoFetchCFiltersStart;     // wallet birth height (inclusive)
    uint32_t autoFetchCFiltersThrough;   // highest height already requested (or
                                         // start-1 if no request has fired yet)
    pthread_mutex_t lock;
};

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

static void _BRPeerManagerLoadBloomFilter(BRPeerManager *manager, BRPeer *peer)
{
    // Privacy-first: skip bloom filterload entirely when the wallet is
    // running compact-filters-only. The wallet still receives merkleblock
    // headers without a filterload (peer assumes empty filter == match-all),
    // but the address set never leaves the device. The Kotlin watchdog
    // flips syncMode to BLOOM_ONLY if filter peers don't progress within
    // 120s, after which this function runs normally on the next call.
    if (manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY) return;

    // every time a new wallet address is added, the bloom filter has to be rebuilt, and each address is only used
    // for one transaction, so here we generate some spare addresses to avoid rebuilding the filter each time a
    // wallet transaction is encountered during the chain sync
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 1);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 1);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 0);
    BRWalletUnusedAddrs(manager->wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 0);
    
    BRSetApply(manager->orphans, NULL, _setApplyFreeBlock);
    BRSetClear(manager->orphans); // clear out orphans that may have been received on an old filter
    manager->lastOrphan = NULL;
    manager->filterUpdateHeight = manager->lastBlock->height;
    manager->fpRate = BLOOM_REDUCED_FALSEPOSITIVE_RATE;
    
    size_t addrsCount = BRWalletAllAddrs(manager->wallet, NULL, 0);
    BRAddress *addrs = malloc(addrsCount * sizeof(*addrs));
    size_t utxosCount = BRWalletUTXOs(manager->wallet, NULL, 0);
    BRUTXO *utxos = malloc(utxosCount * sizeof(*utxos));
    uint32_t blockHeight = (manager->lastBlock->height > 100) ? manager->lastBlock->height - 100 : 0;
    size_t txCount = BRWalletTxUnconfirmedBefore(manager->wallet, NULL, 0, blockHeight);
    BRTransaction **transactions = malloc(txCount*sizeof(*transactions));
    BRBloomFilter *filter;
    
    assert(addrs != NULL);
    assert(utxos != NULL);
    assert(transactions != NULL);
    addrsCount = BRWalletAllAddrs(manager->wallet, addrs, addrsCount);
    utxosCount = BRWalletUTXOs(manager->wallet, utxos, utxosCount);
    txCount = BRWalletTxUnconfirmedBefore(manager->wallet, transactions, txCount, blockHeight);

    peer_log(peer, "bloom filter: %zu addrs, %zu utxos, %zu txs, fpRate=%.6f",
             addrsCount, utxosCount, txCount, manager->fpRate);

    filter = BRBloomFilterNew(manager->fpRate, addrsCount + utxosCount + txCount + 100, (uint32_t) BRPeerHash(peer),
                              BLOOM_UPDATE_ALL); // BUG: XXX txCount not the same as number of spent wallet outputs

    size_t insertedCount = 0;
    size_t failedCount = 0;
    for (size_t i = 0; i < addrsCount; i++) { // add addresses to watch for tx receiving money to the wallet
        UInt160 hash = UINT160_ZERO;

        BRAddressHash160(&hash, addrs[i].s);

        if (! UInt160IsZero(hash) && ! BRBloomFilterContainsData(filter, hash.u8, sizeof(hash))) {
            BRBloomFilterInsertData(filter, hash.u8, sizeof(hash));
            insertedCount++;

            /* Also insert the full P2WPKH witness program (OP_0 + push20 + hash160)
             * so peers that match against the serialized scriptPubKey (not just data
             * elements) will find segwit transactions. Without this, BIP37 bloom
             * filter matching fails for segwit outputs on some node implementations. */
            uint8_t witnessProgram[22];
            witnessProgram[0] = 0x00;  /* OP_0 (witness version 0) */
            witnessProgram[1] = 0x14;  /* push 20 bytes */
            memcpy(&witnessProgram[2], hash.u8, 20);
            if (! BRBloomFilterContainsData(filter, witnessProgram, sizeof(witnessProgram))) {
                BRBloomFilterInsertData(filter, witnessProgram, sizeof(witnessProgram));
            }
        } else if (UInt160IsZero(hash)) {
            peer_log(peer, "bloom filter: FAILED to hash addr[%zu] = '%.10s...'", i, addrs[i].s);
            failedCount++;
        }
    }

    peer_log(peer, "bloom filter: inserted %zu address hashes, %zu failed", insertedCount, failedCount);
    if (addrsCount > 0) {
        peer_log(peer, "bloom filter: first addr = '%s'", addrs[0].s);
    }

    free(addrs);
        
    for (size_t i = 0; i < utxosCount; i++) { // add UTXOs to watch for tx sending money from the wallet
        uint8_t o[sizeof(UInt256) + sizeof(uint32_t)];
        
        UInt256Set(o, utxos[i].hash);
        UInt32SetLE(&o[sizeof(UInt256)], utxos[i].n);
        if (! BRBloomFilterContainsData(filter, o, sizeof(o))) BRBloomFilterInsertData(filter, o, sizeof(o));
    }
    
    free(utxos);
        
    for (size_t i = 0; i < txCount; i++) { // also add TXOs spent within the last 100 blocks
        for (size_t j = 0; j < transactions[i]->inCount; j++) {
            BRTxInput *input = &transactions[i]->inputs[j];
            BRTransaction *tx = BRWalletTransactionForHash(manager->wallet, input->txHash);
            uint8_t o[sizeof(UInt256) + sizeof(uint32_t)];
            
            if (tx && input->index < tx->outCount &&
                BRWalletContainsAddress(manager->wallet, tx->outputs[input->index].address)) {
                UInt256Set(o, input->txHash);
                UInt32SetLE(&o[sizeof(UInt256)], input->index);
                if (! BRBloomFilterContainsData(filter, o, sizeof(o))) BRBloomFilterInsertData(filter, o,sizeof(o));
            }
        }
    }
    
    free(transactions);
    if (manager->bloomFilter) BRBloomFilterFree(manager->bloomFilter);
    manager->bloomFilter = filter;
    // TODO: XXX if already synced, recursively add inputs of unconfirmed receives

    uint8_t data[BRBloomFilterSerialize(filter, NULL, 0)];
    size_t len = BRBloomFilterSerialize(filter, data, sizeof(data));
    
    BRPeerSendFilterload(peer, data, len);
}

static void _updateFilterRerequestDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    
    free(info);
    
    if (success) {
        pthread_mutex_lock(&manager->lock);

        if ((peer->flags & PEER_FLAG_NEEDSUPDATE) == 0) {
            UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
            size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));
            
            BRPeerSendGetblocks(peer, locators, count, UINT256_ZERO);
        }

        pthread_mutex_unlock(&manager->lock);
    }
}

static void _updateFilterLoadDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRPeerCallbackInfo *peerInfo;

    free(info);
    
    if (success) {
        pthread_mutex_lock(&manager->lock);
        BRPeerSetNeedsFilterUpdate(peer, 0);
        peer->flags &= ~PEER_FLAG_NEEDSUPDATE;
        
        if (manager->lastBlock->height < manager->estimatedHeight) { // if syncing, rerequest blocks
            peerInfo = calloc(1, sizeof(*peerInfo));
            assert(peerInfo != NULL);
            peerInfo->peer = peer;
            peerInfo->manager = manager;
            BRPeerRerequestBlocks(manager->downloadPeer, manager->lastBlock->blockHash);
            BRPeerSendPing(manager->downloadPeer, peerInfo, _updateFilterRerequestDone);
        }
        else BRPeerSendMempool(peer, NULL, 0, NULL, NULL); // if not syncing, request mempool
        
        pthread_mutex_unlock(&manager->lock);
    }
}

static void _updateFilterPingDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRPeerCallbackInfo *peerInfo;
    
    if (success) {
        pthread_mutex_lock(&manager->lock);
        peer_log(peer, "updating filter with newly created wallet addresses");
        if (manager->bloomFilter) BRBloomFilterFree(manager->bloomFilter);
        manager->bloomFilter = NULL;

        if (manager->lastBlock->height < manager->estimatedHeight) { // if we're syncing, only update download peer
            if (manager->downloadPeer) {
                _BRPeerManagerLoadBloomFilter(manager, manager->downloadPeer);
                BRPeerSendPing(manager->downloadPeer, info, _updateFilterLoadDone); // wait for pong so filter is loaded
            }
            else free(info);
        }
        else {
            free(info);
            
            for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
                if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) != BRPeerStatusConnected) continue;
                peerInfo = calloc(1, sizeof(*peerInfo));
                assert(peerInfo != NULL);
                peerInfo->peer = manager->connectedPeers[i - 1];
                peerInfo->manager = manager;
                _BRPeerManagerLoadBloomFilter(manager, peerInfo->peer);
                BRPeerSendPing(peerInfo->peer, peerInfo, _updateFilterLoadDone); // wait for pong so filter is loaded
            }
        }

         pthread_mutex_unlock(&manager->lock);
    }
    else free(info);
}

static void _BRPeerManagerUpdateFilter(BRPeerManager *manager)
{
    BRPeerCallbackInfo *info;

    if (manager->downloadPeer && (manager->downloadPeer->flags & PEER_FLAG_NEEDSUPDATE) == 0) {
        BRPeerSetNeedsFilterUpdate(manager->downloadPeer, 1);
        manager->downloadPeer->flags |= PEER_FLAG_NEEDSUPDATE;
        peer_log(manager->downloadPeer, "filter update needed, waiting for pong");
        info = calloc(1, sizeof(*info));
        assert(info != NULL);
        info->peer = manager->downloadPeer;
        info->manager = manager;
        // wait for pong so we're sure to include any tx already sent by the peer in the updated filter
        BRPeerSendPing(manager->downloadPeer, info, _updateFilterPingDone);
    }
}

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

static void _loadBloomFilterDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);
    
    if (success) {
        BRPeerSendMempool(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes), info,
                          _mempoolDone);
        pthread_mutex_unlock(&manager->lock);
    }
    else {
        free(info);
        
        if (peer == manager->downloadPeer) {
            peer_log(peer, "sync succeeded");
            _BRPeerManagerSyncStopped(manager);
            pthread_mutex_unlock(&manager->lock);
            if (manager->syncStopped) manager->syncStopped(manager->info, 0);
        }
        else pthread_mutex_unlock(&manager->lock);
    }
}

static void _BRPeerManagerLoadMempools(BRPeerManager *manager)
{
    // after syncing, load filters and get mempools from other peers
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *peer = manager->connectedPeers[i - 1];
        BRPeerCallbackInfo *info;

        if (BRPeerConnectStatus(peer) != BRPeerStatusConnected) continue;
        info = calloc(1, sizeof(*info));
        assert(info != NULL);
        info->peer = peer;
        info->manager = manager;
        
        if (peer != manager->downloadPeer || manager->fpRate > BLOOM_REDUCED_FALSEPOSITIVE_RATE*5.0) {
            _BRPeerManagerLoadBloomFilter(manager, peer);
            _BRPeerManagerPublishPendingTx(manager, peer);
            BRPeerSendPing(peer, info, _loadBloomFilterDone); // load mempool after updating bloomfilter
        }
        else BRPeerSendMempool(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes), info,
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
    uint64_t services = SERVICES_NODE_NETWORK | SERVICES_NODE_BLOOM | manager->params->services;
    time_t now = time(NULL);
    struct timespec ts;
    pthread_t thread;
    pthread_attr_t attr;
    UInt128 *addr, *addrList;
    BRFindPeersInfo *info;
    
    if (! UInt128IsZero(manager->fixedPeer.address)) {
        array_set_count(manager->peers, 1);
        manager->peers[0] = manager->fixedPeer;
        manager->peers[0].services = services;
        manager->peers[0].timestamp = now;
    }
    else {
        for (size_t i = 1; manager->params->dnsSeeds[i]; i++) {
            info = calloc(1, sizeof(BRFindPeersInfo));
            assert(info != NULL);
            info->manager = manager;
            info->hostname = manager->params->dnsSeeds[i];
            info->services = services;
            if (pthread_attr_init(&attr) == 0 && pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0 &&
                pthread_create(&thread, &attr, _findPeersThreadRoutine, info) == 0) manager->dnsThreadCount++;
        }

        for (addr = addrList = _addressLookup(manager->params->dnsSeeds[0]); addr && ! UInt128IsZero(*addr); addr++) {
			BRPeer peer = {*addr, manager->params->standardPort, services, now, 0};
			_BRPeerManagerAddPeer(manager,&peer);
        }

        if (addrList) free(addrList);
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
static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight);
static BRPeer *_BRPeerManagerAnyFilterCapablePeer(BRPeerManager *manager);
static void _BRPeerManagerRequestNextCFHeaders(BRPeerManager *manager, BRPeer *peer);

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
        BRPeerDisconnect(peer);
    }
    else if (BRPeerVersion(peer) >= 70011 && (peer->services & SERVICES_NODE_BLOOM) != SERVICES_NODE_BLOOM) {
        peer_log(peer, "node doesn't support SPV mode");
        BRPeerDisconnect(peer);
    }
    else if (manager->downloadPeer && // check if we should stick with the existing download peer
             (BRPeerLastBlock(manager->downloadPeer) >= BRPeerLastBlock(peer) ||
              manager->lastBlock->height >= BRPeerLastBlock(peer))) {
        if (manager->lastBlock->height >= BRPeerLastBlock(peer)) { // only load bloom filter if we're done syncing
            manager->connectFailureCount = 0; // also reset connect failure count if we're already synced
            _BRPeerManagerLoadBloomFilter(manager, peer);
            _BRPeerManagerPublishPendingTx(manager, peer);
            peerInfo = calloc(1, sizeof(*peerInfo));
            assert(peerInfo != NULL);
            peerInfo->peer = peer;
            peerInfo->manager = manager;
            BRPeerSendPing(peer, peerInfo, _loadBloomFilterDone);
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
        _BRPeerManagerLoadBloomFilter(manager, peer);
        BRPeerSetCurrentBlockHeight(peer, manager->lastBlock->height);
        _BRPeerManagerPublishPendingTx(manager, peer);
            
        if (manager->lastBlock->height < BRPeerLastBlock(peer)) { // start blockchain sync
            UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
            size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));
            
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT); // schedule sync timeout

            // request just block headers up to a week before earliestKeyTime, and then merkleblocks after that
            // we do not reset connect failure count yet incase this request times out
            if (manager->lastBlock->timestamp + 7*24*60*60 >= manager->earliestKeyTime) {
                BRPeerSendGetblocks(peer, locators, count, UINT256_ZERO);
            }
            else BRPeerSendGetheaders(peer, locators, count, UINT256_ZERO);
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

    BRPeerFree(peer);
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

    // Only add peers that advertise NODE_BLOOM — non-bloom peers are useless
    // for SPV mode and flood the pool, drowning out bloom seeder peers.
    for (size_t i = 0; i < peersCount; i++) {
        if ((peers[i].services & SERVICES_NODE_BLOOM) == SERVICES_NODE_BLOOM) {
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
        
        if (manager->bloomFilter != NULL) { // check if bloom filter is already being updated
            BRAddress addrs[SEQUENCE_GAP_LIMIT_EXTERNAL + SEQUENCE_GAP_LIMIT_INTERNAL];
            UInt160 hash;
            
            // the transaction likely consumed one or more wallet addresses, so check that at least the next <gap limit>
            // unused addresses are still matched by the bloom filter
            BRWalletUnusedAddrs(manager->wallet, addrs, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 0);
            BRWalletUnusedAddrs(manager->wallet, addrs + SEQUENCE_GAP_LIMIT_EXTERNAL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 0);

            for (size_t i = 0; i < SEQUENCE_GAP_LIMIT_EXTERNAL + SEQUENCE_GAP_LIMIT_INTERNAL; i++) {
                if (! BRAddressHash160(&hash, addrs[i].s) ||
                    BRBloomFilterContainsData(manager->bloomFilter, hash.u8, sizeof(hash))) continue;
                if (manager->bloomFilter) BRBloomFilterFree(manager->bloomFilter);
                manager->bloomFilter = NULL; // reset bloom filter so it's recreated with new wallet addresses
                _BRPeerManagerUpdateFilter(manager);
                break;
            }
            
            // Do the same for segwit addresses again
            BRWalletUnusedAddrs(manager->wallet, addrs, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 1);
            BRWalletUnusedAddrs(manager->wallet, addrs + SEQUENCE_GAP_LIMIT_EXTERNAL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 1);
            
            for (size_t i = 0; i < SEQUENCE_GAP_LIMIT_EXTERNAL + SEQUENCE_GAP_LIMIT_INTERNAL; i++) {
                if (! BRAddressHash160(&hash, addrs[i].s) ||
                    BRBloomFilterContainsData(manager->bloomFilter, hash.u8, sizeof(hash))) continue;
                if (manager->bloomFilter) BRBloomFilterFree(manager->bloomFilter);
                manager->bloomFilter = NULL; // reset bloom filter so it's recreated with new wallet addresses
                _BRPeerManagerUpdateFilter(manager);
                break;
            }
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

static void _peerRelayedBlock(void *info, BRMerkleBlock *block)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    size_t txCount = BRMerkleBlockTxHashes(block, NULL, 0);
    UInt256 _txHashes[(sizeof(UInt256)*txCount <= 0x1000) ? txCount : 0],
            *txHashes = (sizeof(UInt256)*txCount <= 0x1000) ? _txHashes : malloc(txCount*sizeof(*txHashes));
    size_t i, fpCount = 0, saveCount = 0;
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
    
    // track the observed bloom filter false positive rate using a low pass filter to smooth out variance
    if (peer == manager->downloadPeer && block->totalTx > 0) {
        for (i = 0; i < txCount; i++) { // wallet tx are not false-positives
            if (! BRWalletTransactionForHash(manager->wallet, txHashes[i])) fpCount++;
        }
        
        // moving average number of tx-per-block
        manager->averageTxPerBlock = manager->averageTxPerBlock*0.999 + block->totalTx*0.001;
        
        // 1% low pass filter, also weights each block by total transactions, compared to the avarage
        manager->fpRate = manager->fpRate*(1.0 - 0.01*block->totalTx/manager->averageTxPerBlock) +
                          0.01*fpCount/manager->averageTxPerBlock;
        
        // false positive rate sanity check
        if (BRPeerConnectStatus(peer) == BRPeerStatusConnected &&
            manager->fpRate > BLOOM_DEFAULT_FALSEPOSITIVE_RATE*10.0) {
            peer_log(peer, "bloom filter false positive rate %f too high after %"PRIu32" blocks, disconnecting...",
                     manager->fpRate, manager->lastBlock->height + 1 - manager->filterUpdateHeight);
            BRPeerDisconnect(peer);
        }
        else if (manager->lastBlock->height + 500 < BRPeerLastBlock(peer) &&
                 manager->fpRate > BLOOM_REDUCED_FALSEPOSITIVE_RATE*10.0) {
            _BRPeerManagerUpdateFilter(manager); // rebuild bloom filter when it starts to degrade
        }
    }

    // ignore block headers that are newer than one week before earliestKeyTime (it's a header if it has 0 totalTx)
    if (block->totalTx == 0 && block->timestamp + 7*24*60*60 > manager->earliestKeyTime + 2*60*60) {
        BRMerkleBlockFree(block);
        block = NULL;
    }
    else if (manager->bloomFilter == NULL) { // ingore potentially incomplete blocks when a filter update is pending
        BRMerkleBlockFree(block);
        block = NULL;

        if (peer == manager->downloadPeer && manager->lastBlock->height < manager->estimatedHeight) {
            BRPeerScheduleDisconnect(peer, PROTOCOL_TIMEOUT); // reschedule sync timeout
            manager->connectFailureCount = 0; // reset failure count once we know our initial request didn't timeout
        }
    }
    else if (! prev) { // block is an orphan
        peer_log(peer, "relayed orphan block %s, previous %s, last block is %s, height %"PRIu32,
                 log_u256_hex_encode(block->blockHash), log_u256_hex_encode(block->prevBlock), log_u256_hex_encode(manager->lastBlock->blockHash),
                 manager->lastBlock->height);
        
        if (block->timestamp + 7*24*60*60 < time(NULL)) { // ignore orphans older than one week ago
            BRMerkleBlockFree(block);
            block = NULL;
        }
        else {
            // call getblocks, unless we already did with the previous block, or we're still syncing
            if (manager->lastBlock->height >= BRPeerLastBlock(peer) &&
                (! manager->lastOrphan || ! UInt256Eq(manager->lastOrphan->blockHash, block->prevBlock))) {
                UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
                size_t locatorsCount = _BRPeerManagerBlockLocators(manager, locators,
                                                                   sizeof(locators)/sizeof(*locators));
                
                peer_log(peer, "calling getblocks");
                BRPeerSendGetblocks(peer, locators, locatorsCount, UINT256_ZERO);
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
            peer_log(peer, "adding block #%"PRIu32", false positive rate: %f", block->height, manager->fpRate);
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
        
        if (BRMerkleBlockEq(b, block)) { // if it's not on a fork, set block heights for its transactions
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
            
            peer_log(peer, "reorganizing chain from height %"PRIu32", new height is %"PRIu32, b->height, block->height);
        
            BRWalletSetTxUnconfirmedAfter(manager->wallet, b->height); // mark tx after the join point as unconfirmed

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
    

    
    /* save the blocks */
    pthread_mutex_unlock(&manager->lock);
    
    if (i > 0 && manager->saveBlocks) {
        debug_log("[STATS]: orphan_count = %ld, block_count = %ld\n", BRSetCount(manager->orphans), BRSetCount(manager->blocks));
        manager->saveBlocks(manager->info, REPLACE_SAVED_BLOCKS, saveBlocks, i, (uint64_t*) &stackIntegrityCheck);
    }
    
    if (block && block->height != BLOCK_UNKNOWN_HEIGHT && block->height >= BRPeerLastBlock(peer) &&
        manager->txStatusUpdate) {
        manager->txStatusUpdate(manager->info); // notify that transaction confirmations may have changed
    }
    
    if (next) _peerRelayedBlock(info, next);
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
    manager->params = params;
    manager->wallet = wallet;
    manager->earliestKeyTime = earliestKeyTime;
    manager->averageTxPerBlock = 1400;
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
    pthread_mutex_init(&manager->lock, NULL);
    manager->threadCleanup = _dummyThreadCleanup;
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
        if (_BRPeerManagerPeerSupportsCompactFilters(manager, p)) return p;
    }
    return NULL;
}

// Drive the cfheaders fetch loop. Asks `peer` for the next batch
// starting at chain->NextHeight, capped at MAX_CFHEADERS_RESULTS and at
// the manager's known tip. No-op if the chain is already caught up or
// the peer is not filter-capable. If no chain exists yet, the first batch
// request runs anyway with startHeight=0 — the chain is created lazily in
// _peerRelayedCFHeaders when the response lands.
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

    uint32_t batchEnd = next + (MAX_CFHEADERS_RESULTS - 1);
    if (batchEnd > tip) batchEnd = tip;

    UInt256 stopHash = _BRPeerManagerBlockHashAtHeight(manager, batchEnd);
    if (UInt256IsZero(stopHash)) {
        peer_log(peer, "cfheaders: no block hash for height %u, deferring", batchEnd);
        return;
    }

    peer_log(peer, "cfheaders: requesting [%u..%u] (%u headers)",
             next, batchEnd, batchEnd - next + 1);
    BRPeerSendGetCFHeaders(peer, filterType, next, stopHash);
}

// --- BIP 158 peer callbacks -----------------------------------------------

static void _peerRelayedCFHeaders(void *info, uint8_t filterType, UInt256 stopHash,
                                  UInt256 prevFilterHeader,
                                  const UInt256 *filterHashes, size_t count)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    pthread_mutex_lock(&manager->lock);

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
    if (!ok) {
        peer_log(peer, "cfheaders: continuity check failed, treating peer as misbehavin'");
        _BRPeerManagerPeerMisbehavin(manager, peer);
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    uint32_t chainTip = BRCompactFilterChainNextHeight(manager->compactFilterChain) - 1;
    peer_log(peer, "cfheaders: chain extended to height %u (added %zu, stop %s)",
             chainTip, count, log_u256_hex_encode(stopHash));

    if (manager->saveFilterHeaders) {
        manager->saveFilterHeaders(manager->saveFilterHeadersInfo, manager->compactFilterChain);
    }

    // Auto-fetch cfilters for the newly validated range, capped at the spec
    // MAX_CFILTERS_RESULTS. The driver requests one batch per cfheaders
    // arrival; consecutive cfheaders responses advance the cursor through
    // the chain until it catches up to the block tip.
    if (manager->autoFetchCFiltersEnabled) {
        uint32_t reqStart = manager->autoFetchCFiltersThrough + 1;
        if (reqStart < manager->autoFetchCFiltersStart) reqStart = manager->autoFetchCFiltersStart;
        if (reqStart <= chainTip) {
            uint32_t reqStop = chainTip;
            if (reqStop > reqStart + (MAX_CFILTERS_RESULTS - 1)) {
                reqStop = reqStart + (MAX_CFILTERS_RESULTS - 1);
            }
            size_t n = _BRPeerManagerRequestCFiltersLocked(manager, reqStart, reqStop);
            if (n > 0) {
                manager->autoFetchCFiltersThrough = reqStop;
                peer_log(peer, "cfilters: auto-requested [%u..%u] (%zu blocks)",
                         reqStart, reqStop, n);
            }
        }
    }

    // Request the next batch if still behind the local block tip.
    _BRPeerManagerRequestNextCFHeaders(manager, peer);
    pthread_mutex_unlock(&manager->lock);
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

    BRMerkleBlock *b = BRSetGet(manager->blocks, &blockHash);
    if (!b) {
        peer_log(peer, "cfilter: unknown block %s, dropping", log_u256_hex_encode(blockHash));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    if (!BRCompactFilterChainVerifyFilter(manager->compactFilterChain, b->height, encoded, encodedLen)) {
        peer_log(peer, "cfilter: filter for block %s does not match chain — misbehavin'",
                 log_u256_hex_encode(blockHash));
        _BRPeerManagerPeerMisbehavin(manager, peer);
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    BRGCSFilter *gcs = BRGCSFilterBasicParse(encoded, encodedLen, blockHash);
    if (!gcs) {
        peer_log(peer, "cfilter: failed to parse filter for block %s",
                 log_u256_hex_encode(blockHash));
        pthread_mutex_unlock(&manager->lock);
        return;
    }

    BRWalletFilterElements *fe = BRWalletGetFilterElements(manager->wallet);
    int hit = 0;
    if (fe && fe->count > 0) {
        hit = BRGCSFilterMatchAny(gcs, fe->elements, fe->elementLens, fe->count);
    }
    BRWalletFilterElementsFree(fe);
    BRGCSFilterFree(gcs);

    if (hit) {
        peer_log(peer, "cfilter: MATCH on block %s @ height %u, requesting full block",
                 log_u256_hex_encode(blockHash), b->height);
        // Send while holding the lock — matches the pattern used elsewhere
        // in this file (e.g. _BRPeerManagerRequestNextCFHeaders also sends
        // under the lock). The lock guards manager state, not the socket.
        BRPeerSendGetdataBlocks(peer, &blockHash, 1);
    }

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
    _BRPeerManagerRequestNextCFHeaders(manager, peer);
}

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

		if ((array_count(manager->peers) < (4 * manager->maxConnectCount)) ||
			((manager->peers[manager->maxConnectCount - 1].timestamp + 3*24*60*60) < now)) {
            _BRPeerManagerFindPeers(manager);
        }
        
        array_new(peers, 100);

        // Prioritize bloom-capable peers: add them to the candidate list first,
        // then fill remaining slots with other peers. This ensures all 5
        // connection slots go to bloom peers when enough are available.
        {
            size_t totalAvail = array_count(manager->peers);
            size_t added = 0;

            // First pass: bloom-capable peers only
            for (size_t k = 0; k < totalAvail && added < 100; k++) {
                if ((manager->peers[k].services & SERVICES_NODE_BLOOM) == SERVICES_NODE_BLOOM) {
                    array_add(peers, manager->peers[k]);
                    added++;
                }
            }
            // Second pass: fill remaining slots with any peer
            for (size_t k = 0; k < totalAvail && added < 100; k++) {
                if ((manager->peers[k].services & SERVICES_NODE_BLOOM) != SERVICES_NODE_BLOOM) {
                    array_add(peers, manager->peers[k]);
                    added++;
                }
            }
        }

        while ((array_count(peers) > 0) && (array_count(manager->connectedPeers) < manager->maxConnectCount)) {
            size_t bloomCount = 0;
            for (size_t bc = 0; bc < array_count(peers); bc++) {
                if ((peers[bc].services & SERVICES_NODE_BLOOM) == SERVICES_NODE_BLOOM) bloomCount++;
            }

            size_t i;
            BRPeerCallbackInfo *info;

            if (bloomCount > 0) {
                // Pick randomly from bloom peers only (they're at the front)
                i = BRRand((uint32_t)bloomCount);
            } else {
                // No bloom peers left, fall back to random from full list
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
                                   _peerRelayedTx, _peerHasTx, _peerRejectedTx, _peerRelayedBlock, _peerDataNotfound,
                                   _peerSetFeePerKb, _peerRequestedTx, _peerNetworkIsReachable, _peerThreadCleanup);
                BRPeerSetEarliestKeyTime(info->peer, manager->earliestKeyTime);
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
    }
    
    if (array_count(manager->connectedPeers) == 0) {
        peer_log(&BR_PEER_NONE, "sync failed");
        _BRPeerManagerSyncStopped(manager);
        pthread_mutex_unlock(&manager->lock);
        if (manager->syncStopped) manager->syncStopped(manager->info, ENETUNREACH);
    }
    else pthread_mutex_unlock(&manager->lock);
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
    uint32_t height;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    height = (manager->lastBlock->height < manager->estimatedHeight) ? manager->estimatedHeight :
             manager->lastBlock->height;
    pthread_mutex_unlock(&manager->lock);
    return height;
}

// current proof-of-work verified best block height
uint32_t BRPeerManagerLastBlockHeight(BRPeerManager *manager)
{
    uint32_t height;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    height = manager->lastBlock->height;
    pthread_mutex_unlock(&manager->lock);
    return height;
}

// current proof-of-work verified best block timestamp (time interval since unix epoch)
uint32_t BRPeerManagerLastBlockTimestamp(BRPeerManager *manager)
{
    uint32_t timestamp;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    timestamp = manager->lastBlock->timestamp;
    pthread_mutex_unlock(&manager->lock);
    return timestamp;
}

// current network sync progress from 0 to 1
// startHeight is the block height of the most recent fully completed sync
double  BRPeerManagerSyncProgress(BRPeerManager *manager, uint32_t startHeight)
{
    double progress;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    if (startHeight == 0) startHeight = manager->syncStartHeight;
    
    if (! manager->downloadPeer && manager->syncStartHeight == 0) {
        progress = 0.0;
    }
    else if (! manager->downloadPeer || manager->lastBlock->height < manager->estimatedHeight) {
        if (manager->lastBlock->height > startHeight && manager->estimatedHeight > startHeight) {
            progress = 0.001 + 0.999 * (manager->lastBlock->height - startHeight)/(manager->estimatedHeight - startHeight);
        }
        else progress = 0.001;
    }
    else progress = 1.0;

    pthread_mutex_unlock(&manager->lock);
    return progress;
}

// returns the number of currently connected peers
size_t BRPeerManagerPeerCount(BRPeerManager *manager)
{
    size_t count = 0;
    
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) != BRPeerStatusDisconnected) count++;
    }
    
    pthread_mutex_unlock(&manager->lock);
    return count;
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
    if (manager->compactFilterChain) {
        BRCompactFilterChainFree(manager->compactFilterChain);
        manager->compactFilterChain = NULL;
    }
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
    pthread_mutex_unlock(&manager->lock);
}

BRSyncMode BRPeerManagerGetSyncMode(BRPeerManager *manager)
{
    if (!manager) return BR_SYNC_MODE_BLOOM_ONLY;
    pthread_mutex_lock(&manager->lock);
    BRSyncMode m = manager->syncMode;
    pthread_mutex_unlock(&manager->lock);
    return m;
}

// Mid-run fallback: flip syncMode to BLOOM_ONLY AND push a freshly-built
// bloom filterload to every currently-connected peer. Required because
// _peerConnected only fires on new connections — peers that handshook
// while syncMode==COMPACT_FILTERS_ONLY never received our filter, so they
// won't relay matching txs after the mode change without an explicit
// reload. Called from JNI when the Kotlin watchdog times out.
void BRPeerManagerFallbackToBloom(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->syncMode = BR_SYNC_MODE_BLOOM_ONLY;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) == BRPeerStatusConnected) {
            _BRPeerManagerLoadBloomFilter(manager, p);
        }
    }
    pthread_mutex_unlock(&manager->lock);
}

// Current cfheaders tip height (height of the last header we've stored).
// 0 if no chain yet. Used by the watchdog to detect "no progress."
uint32_t BRPeerManagerCFChainTipHeight(BRPeerManager *manager)
{
    if (!manager) return 0;
    pthread_mutex_lock(&manager->lock);
    uint32_t h = 0;
    if (manager->compactFilterChain) {
        // NextHeight is start + count; tip is one below, but if count==0
        // there's no tip yet — return start-1 as "anchor seen, no headers"
        // marker, or 0 if no chain at all.
        uint32_t next = BRCompactFilterChainNextHeight(manager->compactFilterChain);
        h = next > 0 ? next - 1 : 0;
    }
    pthread_mutex_unlock(&manager->lock);
    return h;
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

// Lock-held internal helper. Caller must hold manager->lock. Returns the
// number of blocks actually requested or 0 if no eligible peer was found.
static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight)
{
    if (stopHeight < startHeight) return 0;
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return 0;

    uint32_t cap = startHeight + (MAX_CFILTERS_RESULTS - 1);
    if (stopHeight > cap) stopHeight = cap;

    UInt256 stopHash = _BRPeerManagerBlockHashAtHeight(manager, stopHeight);
    if (UInt256IsZero(stopHash)) return 0;

    uint8_t filterType = manager->compactFilterChain
                         ? BRCompactFilterChainType(manager->compactFilterChain)
                         : FILTER_TYPE_BASIC;

    BRPeer *target = NULL;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) != BRPeerStatusConnected) continue;
        if ((p->services & SERVICES_NODE_COMPACT_FILTERS) != SERVICES_NODE_COMPACT_FILTERS) continue;
        target = p;
        break;
    }
    if (!target) return 0;

    BRPeerSendGetCFilters(target, filterType, startHeight, stopHash);
    return stopHeight - startHeight + 1;
}

size_t BRPeerManagerRequestCompactFilters(BRPeerManager *manager,
                                          uint32_t startHeight, uint32_t stopHeight)
{
    if (!manager) return 0;
    pthread_mutex_lock(&manager->lock);
    size_t n = _BRPeerManagerRequestCFiltersLocked(manager, startHeight, stopHeight);
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
    pthread_mutex_unlock(&manager->lock);
}

void BRPeerManagerDisableAutoCompactFilterFetch(BRPeerManager *manager)
{
    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    manager->autoFetchCFiltersEnabled = 0;
    manager->autoFetchCFiltersStart = 0;
    manager->autoFetchCFiltersThrough = 0;
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

