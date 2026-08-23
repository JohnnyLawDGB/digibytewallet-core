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

#include <arpa/inet.h>   // inet_ntop for IPv6-correct peer logging
#include "BRPeerManager.h"
#include "BRPeerConnectPolicy.h"
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
//
// SIZED FOR THE REAL WORKING SET (raised 32 -> 256, 2026-08-02). 32 was far below the
// number of distinct peers that pass through this table in normal operation, and the
// insert policy evicted the OLDEST INSERT unconditionally, so a live 10-minute
// "doesn't support SPV mode" ban was routinely thrown out by an unrelated 30-second
// redial cooldown. Measured on a Note 8 during a deep restore: 41 distinct non-SPV
// peers producing 3,520 disconnects in about ONE MINUTE (~86 redials each), which
// consumed every connection slot. Adding PEER_REDIAL_COOLDOWN_SECONDS on every clean
// disconnect (same day) made it worse by pumping evictions with short-lived entries.
// 256 entries x (16 + 2 + 8) B ~= 6.6 KB -- irrelevant next to the churn it prevents.
#define PEER_PENALTY_MAX     256
#define PEER_PENALTY_SECONDS (10*60) // 10 min; a genuinely-behind node is skipped this long
// Short cooldown applied after ANY disconnect, INCLUDING a clean one (error == 0).
// _peerDisconnected only removes a peer from the pool when error != 0, so a clean
// disconnect left it immediately re-dialable and the next connect pass picked it
// straight back up. Measured on a Note 8, 2026-08-02, one fresh-wallet run:
// 12,677 connect attempts / 12,670 disconnects against only 8 connect errors, i.e.
// the churn was almost entirely self-inflicted redialling, not peers refusing us.
// Deliberately far shorter than PEER_PENALTY_SECONDS: a peer that merely dropped has
// done nothing wrong and must come back quickly. This only stops the redial storm.
// After this change the same window measured 884 attempts / 878 disconnects (~14x less).
#define PEER_REDIAL_COOLDOWN_SECONDS 30

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

// ---- CF full-block SOLICITATION table (C1 request-gate) ---------------------
// A CF scan height is completed (BRCFScanLedgerMarkEvaluated) by the arrival of the full
// block for that height, in _peerRelayedBlockTxns. That handler is fed by BRPeer.c's
// `block` message path, which is NOT request-gated (BRPeer.c dispatches MSG_BLOCK
// unconditionally) and does NOT check the delivered tx list against the header's committed
// merkle root. So without this table, ANY peer the wallet dials can complete an outstanding
// height with an unsolicited `block` (real public header + one arbitrary tx), or the peer
// serving that height can answer our getdata with the real header and the wallet's payment
// STRIPPED out of the tx list. Either way scannedThrough sails past a height that was never
// scanned, the ledger persists it, and the receive is invisible until a manual rescan.
//
// So: every getdata dispatched after a cfilter that VERIFIED against the committed cfheader
// chain and MATCHED is recorded here, and only a block found here may complete a height.
//
// Deliberately NOT keyed by peer: content integrity is proven by the merkle-root check
// against OUR OWN header, so it does not matter which peer hands us the bytes; the table's
// job is only "did this wallet ever ask for this height at all".
//
// Manager-INLINE and bounded: no allocation, so nothing new to free (BRPeerManagerFree is
// untouched). When full, the OLDEST solicitation is evicted; losing an entry only costs a
// re-request (the height simply stays outstanding), never a silent completion. Entries are
// dropped on successful completion and the whole table is cleared whenever the scan is
// re-anchored/re-armed/disabled/restored (the solicitation belongs to the old scan) and on
// BRPeerManagerDisconnect (the getdata died with the connections).
#define CF_SOLICITED_BLOCKS_MAX 256

typedef struct {
    UInt256  blockHash;
    uint32_t height;   // the height we believed this hash sat at when we asked
    uint64_t seq;      // insertion order, for oldest-first eviction (0 == free slot)
    int      used;
} BRCFSolicitedBlock;

struct BRPeerManagerStruct {
    const BRChainParams *params;
    BRWallet *wallet;
    int isConnected, connectFailureCount, misbehavinCount, dnsThreadCount, maxConnectCount, peerThreadCount;
    // DISCONNECT LEDGER (BRPeer.h). Running histogram of WHO closed each connection, so an
    // overnight run answers "are we being evicted, or are we hanging up on ourselves?" from
    // one summary line instead of a hand-count over thousands of scattered log lines.
    // Written only under manager->lock in _peerDisconnected.
    uint32_t closeCounts[BR_CLOSE_CAUSE_COUNT];
    uint32_t closeTagCounts[BR_DISC_TAG_COUNT];
    uint32_t closeTotal;
    double   closeShortLived;   // count of closes with lifetime < CLOSE_LEDGER_SHORT_SECS
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
    // C1 request-gate: full blocks THIS wallet asked for after a verified cfilter match.
    // See BRCFSolicitedBlock above. calloc'd with the manager -> starts empty.
    BRCFSolicitedBlock cfSolicitedBlocks[CF_SOLICITED_BLOCKS_MAX];
    uint64_t cfSolicitedSeq;
    // Cached BIP 158 wallet element set, reused across arriving cfilters. Rebuilding it
    // per filter was 98.8% of the per-filter cost (see _BRPeerManagerFilterElementsLocked).
    // cfElemsAddrCount is the address count the cache was built from and is the ONLY
    // validity condition — never a timer.
    BRWalletFilterElements *cfElems;
    uint64_t cfElemsAddrGen;      // wallet's address-set generation the cache was built from
    size_t cfElemsAddrCount;      // ...and its address count (defence-in-depth)
    int cfElemsIsTestnet;         // ...and the network, which changes the encoded BYTES
    int autoFetchCFiltersEnabled;
    uint32_t autoFetchCFiltersStart;     // wallet birth height (inclusive)
    uint32_t autoFetchCFiltersThrough;   // highest height already requested (or
                                         // start-1 if no request has fired yet)
    uint32_t autoFetchCFiltersRequested; // the floor the APP asked for, BEFORE
                                         // BRPeerManagerEnableAutoCompactFilterFetch's
                                         // resolvability clamp moved it (0 = never armed).
                                         // Kept so the resume reconciliation can tell a
                                         // ledger that was CLAMPED above the requested floor
                                         // (and never restored) from one that legitimately
                                         // starts there — see C-1 in
                                         // BRPeerManagerSnapAutoFetchThroughToScanFrontier.
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
    // PACED-CONVOY driver B1.3 (spec Part B1 step 3): the block-header tip seen at
    // the END of the previous KeepAlive tick. The getheaders re-kick fires only
    // when the header frontier did NOT advance across a whole tick — unlike the
    // cfheaders half, BRPeerSendGetheaders has no in-flight serialize guard of its
    // own, so an unconditional per-tick re-issue would duplicate every 2000-header
    // batch during ordinary open-window sync (~0.44 MB per tick of redundant
    // traffic on exactly the deep restore the convoy exists to make cheap). 0 on a
    // calloc'd manager, so the first tick only samples (never re-kicks).
    uint32_t convoyLastHdrTip;
    // ...and a frozen tip alone is NOT sufficient: BRPeer.c issues its continuation
    // BEFORE the relay loop, so lastBlock stays put until the whole ~440 KB batch is
    // parsed, and a stale-HIGH estimatedHeight (only ever raised) keeps a synced
    // wallet permanently "frozen below the network tip". So the re-kick is also
    // rate-limited: convoyLastHdrKickAt stamps the last one, convoyHdrKickBackoff is
    // the interval before the next (doubling while unproductive, capped at
    // CF_CONVOY_HDR_REKICK_MAX_SECS, RESET to CF_CONVOY_HDR_REKICK_BASE_SECS the
    // moment the header tip actually advances). Both 0 on a calloc'd manager: 0
    // backoff reads as BASE, 0 stamp reads as "never kicked" (immediately due).
    time_t   convoyLastHdrKickAt;
    uint32_t convoyHdrKickBackoff;
    // ...and the header-window verdict at the END of the previous tick, so the
    // GATED->open transition can be detected. The backoff punishes UNPRODUCTIVE
    // RE-KICKS, and a gated period contains no re-kicks at all, so it must not
    // carry a penalty across: a reopen is exactly the event B1.3 exists to serve
    // (the held continuation has to resume) and is served on the very next tick.
    // Without this the two predicates drift apart -- CF_CONVOY_HDR_GATED can flip
    // open->full->open purely from scanFrontier movement (B1.2's floor-snap /
    // re-anchor) with lastBlock->height never advancing, so the !hdrFrozen reset
    // never fires and a reopen waits out a stale, pre-gate interval (up to
    // CF_CONVOY_HDR_REKICK_MAX_SECS). 0 on a calloc'd manager == "was open".
    uint8_t  convoyHdrWasGated;
    // ---- F1: memoized resident block FLOOR ---------------------------------
    // _BRPeerManagerBlockFloor is an O(chainLen) prevBlock descent. The
    // getcfilters start-height clamp (F1, in
    // _BRPeerManagerRequestCFiltersWithStopHashLocked) needs the floor once per
    // SEND, and the residual driver sends up to CF_REREQ_BATCH_PER_TICK (64)
    // ranges per tick — 64 full descents under the NON-recursive manager->lock
    // would re-introduce exactly the under-the-lock walk cost the Pass A/B/C
    // restructure was built to remove (the raised-floor ANR class). So the floor
    // is memoized against a key that CHANGES on every mutation of the chain view
    // that could move it: the `blocks` set identity + cardinality, and lastBlock's
    // identity + height. Every mutator of manager->blocks either adds or removes
    // (so cardinality moves) and every prune (_BRPeerManagerClearMemory) runs only
    // from the _peerRelayedBlock branch that has just moved lastBlock, so a stale
    // hit is not reachable — and _BRPeerManagerClearMemory additionally
    // invalidates explicitly. floorMemoValid == 0 on a calloc'd manager, so the
    // first read always walks. Guarded by manager->lock like the rest of these.
    // Lock-hold profiler state (see MGR_LOCK/MGR_UNLOCK). manager->lock is initialized with NULL
    // attributes, i.e. NON-RECURSIVE, so exactly one holder exists at a time and a single
    // timestamp cannot be clobbered by nesting.
    double      lockHeldSinceMs;
    const char *lockHolderFn;
    int         lockHolderLine;

    uint8_t  floorMemoValid;
    BRSet   *floorMemoBlocks;
    size_t   floorMemoBlockCount;
    BRMerkleBlock *floorMemoTip;
    uint32_t floorMemoTipHeight;
    uint32_t floorMemoFloor;
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
    uint32_t         lastSpanClampLog;   // rate-limits the retention-span-clamp WARN

    // TOTAL heights this manager has actually written off, accumulated across every
    // surfacing event. Lives on the MANAGER, not the ledger, and that placement is the
    // whole point: three paths re-Init the ledger mid-session (the cfheaders floor snap
    // :3220, the CF chain re-anchor :6088, and the arming clamp :6514), and
    // BRCFScanLedgerInit memsets the ledger and resets `start` to the NEW floor. Because
    // BRPeerManagerAbandonedCount reports `abandonedBelow - start`, it therefore reads
    // ZERO immediately after the single largest abandonment event in the system — the
    // floor snap abandons a band and then reports none of it. A ledger-resident counter
    // would be wiped by the same memset. This one survives, and is zeroed only by the
    // calloc of a genuinely new manager (fresh wallet / wipe / rescan), which is exactly
    // when the count SHOULD restart.
    size_t           cfAbandonedHeightsTotal;

    // Highest cfFloor at which a FULL descent found nothing to free. Blocks are only
    // ever appended at the TIP, so the resident bottom never grows downward, and a
    // block can only BECOME prunable when cfFloor RISES above it. So if we already
    // walked the whole chain at floor F and freed nothing, any later call with
    // cfFloor <= F cannot free anything either and the walk can be skipped outright.
    // 0 = no such observation (always walk). Reset whenever a walk DOES free.
    uint32_t         clearMemNoopFloor;

    // cfFloor at which the last FULL descent actually ran. The no-op memo above cannot
    // help once CF_RETENTION_SPAN_MAX binds -- the floor then rises by 1 per block-add,
    // so `cfFloor <= clearMemNoopFloor` is false forever AND each freed block resets the
    // memo. This defers the next descent until the floor has moved CLEAR_MEM_PRUNE_STRIDE,
    // turning O(resident)-per-block into O(resident)/STRIDE. 0 = never descended yet.
    uint32_t         lastPruneFloor;

    // Convoy header-hold bookkeeping (CF_CONVOY_HOLD_MAX_SECS).
    //
    // KEYED ON (addr, port), NOT ON THE BRPeer POINTER. An earlier version of this held a
    // raw BRPeer* "identity token, never dereferenced" and argued a stale pointer could only
    // FAIL the equality test and so only shorten a hold. That is wrong in the direction that
    // matters: peers are individually calloc'd (BRPeer.c:1506) and freed (BRPeer.c:2190) at
    // the same size class, and _peerDisconnected never cleared this field, so the very next
    // BRPeerNew commonly gets the dead peer's chunk back. The NEW peer then compares EQUAL to
    // the dead one, inherits its already-expired hold clock, is never refreshed, and self-kills
    // 20 s after election -- silently restoring the exact churn this cap exists to stop.
    // (addr, port) cannot alias that way: a different remote node has a different key, and the
    // SAME node reconnecting inheriting its clock is correct — a node must not escape the cap
    // by reconnecting.
    UInt128          convoyHoldAddr;
    uint16_t         convoyHoldPort;
    time_t           convoyHoldSince;

#ifdef CF_PRUNE_INSTRUMENT
    // Host-KAT only (never defined in a production build): counts what the amortisation
    // is supposed to reduce, so the gate can assert on WORK rather than on wall clock.
    uint64_t         pruneDescents;   // full descents entered
    uint64_t         pruneSetGets;    // BRSetGet calls inside the descent loop
#endif

#ifdef CF_RECV_DIAG
    // ---- RECEIVE-PATH ACCOUNTING (diagnostic build only) ---------------------
    // Stage 0 proved the NETWORK is not the problem: a bare socket gets 1000/1000
    // filters from these same peers in 0.2-1.3s, while the wallet credits ~30% of
    // what it asks for. So the loss is between recv() and MarkEvaluated. The
    // existing [CF-ARR] diag is WINDOWED on the pin, so it cannot see the bulk.
    // These are unconditional. INVARIANT: recvTotal == sum(every exit below).
    // Any drift means an exit path exists that this accounting does not know about.
    uint32_t cfRecvTotal;      // entered _peerRelayedCFilter
    uint32_t cfExitNoChain;    // no compactFilterChain / filter-type mismatch  (SILENT before this)
    uint32_t cfExitUnknownBuf; // block unknown, raw bytes buffered for later drain
    uint32_t cfExitUnknownDrop;// block unknown, buffer REFUSED the bytes (lost)
    uint32_t cfExitVerifyFail; // filter hash != cfheader chain
    uint32_t cfExitParseFail;  // GCS parse failed
    uint32_t cfExitEvaluated;  // reached MarkEvaluated (the only good outcome)

    // ---- TIMING (CF_RECV_DIAG): where does the wall clock actually go? -------
    // The network hands us 1000 filters in 0.2s (measured, bare socket) but the
    // wallet processes ~28/s. This splits that gap three ways so the fix is aimed
    // at the real constraint rather than at the network:
    //   lockWait  - blocked on manager->lock (contention with KeepAlive/block-add)
    //   evalNanos - inside the GCS build+match against the wallet element set
    //   gapNanos  - wall clock BETWEEN arrivals (idle => we are network-bound)
    uint64_t cfLockWaitNanos;
    uint64_t cfEvalNanos;
    uint64_t cfGapNanos;
    uint64_t cfLastArrivalNanos;
    uint32_t cfTimedSamples;
#endif
    _Atomic int      cachedHasDownloadPeer;
    _Atomic int      cachedSyncMode;
    // Distinct peers that failed the cfheaders continuity check since the last
    // successful append, and each one's claimed prevFilterHeader (parallel
    // array, same index). Task 5 (cfcheckpt-active-rejection): the multi-peer
    // re-anchor decision no longer trusts raw disagreement count alone — it
    // requires a plurality of these stored prevFilterHeader values to AGREE
    // (see the quorum decision in _peerRelayedCFHeaders). Sized on the
    // always-defined CF_DISAGREED_CAP, not on CF_CONTINUITY_REANCHOR_FLOOR
    // (which is undefined under -DCF_QUORUM_UNFIXED — see BRPeerManager.h).
    UInt128  cfDisagreedPeers[CF_DISAGREED_CAP];
    UInt256  cfDisagreedPrev[CF_DISAGREED_CAP];
    uint8_t  cfDisagreedCount;
    uint8_t  cfReanchorCount;            // continuity-triggered re-anchors this session

    // ── Abandoned-band backfill (2026-08-21) ──────────────────────────────
    // Re-fetching the block headers under an abandoned band so the band can be
    // retired, instead of the only cure being a full rebuild from wallet birth.
    //
    // Why a tracked tip rather than a walk: contiguity builds UPWARD from a block
    // checkpoint (getheaders returns C+1, C+2, …) but BRMerkleBlock only links
    // BACKWARD via prevBlock, so the top of a partially-rebuilt run cannot be
    // found by walking. It has to be remembered as it grows.
    //
    // Deliberately NOT persisted: the ledger's abandonedBelow is the durable state,
    // and a restart simply re-derives the starting locator from the checkpoint table.
    // Losing this costs one re-walk, never correctness.
    UInt256  cfBackfillTipHash;         // last header accepted into the backfill run
    uint32_t cfBackfillTipHeight;       // its height; 0 = run not started
    uint32_t cfBackfillTarget;          // the abandonedBelow value this run is chasing
    // When only ONE filter peer is connected the K-distinct-disagreers threshold
    // can never be met (the active probe reaches no other filter peer), so
    // cfDisagreedCount wedges at 1/K forever and cfheaders never advance. Count
    // CONSECUTIVE diverged rounds instead; at CF_SINGLE_PEER_REANCHOR_ROUNDS force
    // a (still CF_CONTINUITY_REANCHOR_MAX-bounded) re-anchor.
    uint8_t  cfSingleDisagreeRounds;
    // Session-scoped re-dial penalty (churn fix, see PEER_PENALTY_* above).
    // penaltyCount only ever grows and is CLAMPED to PEER_PENALTY_MAX by every reader
    // (both BRPeerPenaltyContains call sites pass `min(penaltyCount, PEER_PENALTY_MAX)`;
    // that helper does no bounds checking of its own). Entries age out via its
    // until-vs-now check. Once full, inserts evict by EXPIRY, not insertion order --
    // see _penalizeFor. Zero-initialized by BRPeerManagerNewEx's calloc.
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

// ---- LOCK-HOLD PROFILER ------------------------------------------------------------------
//
// manager->lock serializes the entire peer manager. While it is held, every peer thread, the
// keepalive, and the CF scan driver are stopped. A hold measured in SECONDS is therefore never
// acceptable, and one measured in MINUTES is an outage.
//
// Measured on a Note 8, 2026-08-05: the lock was held CONTINUOUSLY FOR 43 MINUTES while a single
// thread burned 915 seconds of user CPU and 93 of the process's 103 threads sat in futex behind
// it. ASan was silent throughout, so it is not corruption — it is an algorithmic hold. Two
// suspects (_BRPeerManagerClearMemory, _BRPeerManagerBlockFloor) were instrumented individually
// first and BOTH came back clean, which is why this now wraps the lock itself: guessing at
// candidate functions one at a time is exactly the treadmill this is meant to end.
//
// Not behind a debug flag, and not sampled. Cost is one gettimeofday per acquire/release against
// a threshold healthy code never approaches, and the whole reason that hold went unexplained for
// two days is that nothing measured it.
//
// SAFE BECAUSE THE LOCK IS NON-RECURSIVE (pthread_mutex_init(..., NULL) at BRPeerManagerNew): one
// holder at a time, so the single timestamp cannot be clobbered by nesting.
#ifndef CF_SLOW_PHASE_MS
#define CF_SLOW_PHASE_MS 2000.0
#endif

// Its OWN log channel, deliberately NOT CF_RETENTION_WLOG. The host KATs hijack that macro to
// count warnings and assert the count — cf_scan_ledger_drive_kat does
// check(g_wlogCount == wlogBefore, "no ABANDONED warn-log on the clean retain path"). Routing
// profiler output through it made a timing-dependent line increment a counter the ledger tests
// treat as semantic, and that KAT went red. A diagnostic must never share a channel whose
// silence other tests assert.
#ifndef CF_SLOW_WLOG
#if defined(__ANDROID__)
#define CF_SLOW_WLOG(...) __android_log_print(ANDROID_LOG_WARN, "bread", __VA_ARGS__)
#elif defined(TARGET_OS_MAC)
#define CF_SLOW_WLOG(...) NSLog(__VA_ARGS__)
#else
#define CF_SLOW_WLOG(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#endif
#endif

static inline double _cfNowMs(void)
{
    struct timeval _tv;
    gettimeofday(&_tv, NULL);
    return (double)_tv.tv_sec * 1000.0 + (double)_tv.tv_usec / 1000.0;
}

// Holder identity lives in FILE-STATIC ATOMICS, not in the manager struct, for one reason: the
// whole point is to read it from a thread that is BLOCKED and cannot take the lock — and, since
// the guard that normally protects g_peerManager is exactly the thing that is stuck, it must also
// be readable WITHOUT touching the manager pointer at all. A global cannot dangle.
//
// Non-recursive lock + one manager in practice, so a single slot is accurate. Reads are racy by
// construction; that is fine for a diagnostic, and the function pointer is always a __func__
// string literal in static storage, so it is never a dangling read.
static _Atomic double       g_lockHeldSinceMs = 0.0;
static const char * _Atomic g_lockHolderFn    = NULL;
static _Atomic int          g_lockHolderLine  = 0;

// Milliseconds the peer-manager lock has been held right now, 0 if free. Takes NO lock.
double BRPeerManagerLockHeldMs(const char **outFn, int *outLine)
{
    double since = atomic_load_explicit(&g_lockHeldSinceMs, memory_order_relaxed);
    if (outFn)   *outFn   = atomic_load_explicit(&g_lockHolderFn, memory_order_relaxed);
    if (outLine) *outLine = atomic_load_explicit(&g_lockHolderLine, memory_order_relaxed);
    if (since <= 0.0) return 0.0;
    return _cfNowMs() - since;
}

// WAIT time, not hold time. MGR_UNLOCK below reports how long a holder KEPT the lock, and
// during the 2026-08-07 restore it never once fired — yet eight peer threads sat inside
// `headers` dispatch for up to 699s. Both facts are consistent only if the time is spent
// WAITING to acquire, which nothing measured. pthread mutexes are not fair: with 8 threads
// each acquiring ~2000 times per headers message, a barging waiter can starve for minutes
// while every individual hold stays microseconds. This distinguishes "someone holds it too
// long" (hold log) from "too many acquisitions, unfairly scheduled" (this log) — which point
// at completely different fixes, so guessing between them is not acceptable.
#define MGR_LOCK(m)                                                                          \
    do {                                                                                     \
        double _waitStart = _cfNowMs();                                                       \
        pthread_mutex_lock(&(m)->lock);                                                      \
        double _waited = _cfNowMs() - _waitStart;                                            \
        if (_waited >= CF_SLOW_PHASE_MS) {                                                   \
            CF_SLOW_WLOG("[CF-SLOW] manager->lock WAITED %.1fs to acquire at %s:%d "          \
                         "(holder on entry %s:%d) — long WAIT with short HOLDS is lock "      \
                         "starvation, not a slow critical section",                           \
                         _waited / 1000.0, __func__, __LINE__,                                \
                         (m)->lockHolderFn ? (m)->lockHolderFn : "?", (m)->lockHolderLine);   \
        }                                                                                     \
        atomic_store_explicit(&g_lockHeldSinceMs, _cfNowMs(), memory_order_relaxed);         \
        atomic_store_explicit(&g_lockHolderFn, __func__, memory_order_relaxed);              \
        atomic_store_explicit(&g_lockHolderLine, __LINE__, memory_order_relaxed);            \
        (m)->lockHeldSinceMs = _cfNowMs();                                                   \
        (m)->lockHolderFn    = __func__;                                                     \
        (m)->lockHolderLine  = __LINE__;                                                     \
    } while (0)

#define MGR_UNLOCK(m)                                                                        \
    do {                                                                                     \
        double      _held = _cfNowMs() - (m)->lockHeldSinceMs;                               \
        const char *_fn   = (m)->lockHolderFn;                                               \
        int         _ln   = (m)->lockHolderLine;                                             \
        (m)->lockHeldSinceMs = 0.0;                                                          \
        atomic_store_explicit(&g_lockHeldSinceMs, 0.0, memory_order_relaxed);                \
        pthread_mutex_unlock(&(m)->lock);                                                    \
        if (_held >= CF_SLOW_PHASE_MS) {                                                     \
            CF_SLOW_WLOG("[CF-SLOW] manager->lock held %.1fs — acquired at %s:%d, released "  \
                         "at %s:%d", _held / 1000.0, _fn ? _fn : "?", _ln, __func__,          \
                         __LINE__);                                                          \
        }                                                                                    \
    } while (0)

// Phase timer for a specific span INSIDE a critical section, when knowing which lock holder is
// slow is not enough and the sub-phase matters.
#define CF_PHASE_START(v) double v = _cfNowMs()
#define CF_PHASE_END(v, name, fmt, ...)                                                      \
    do {                                                                                     \
        double _el = _cfNowMs() - (v);                                                       \
        if (_el >= CF_SLOW_PHASE_MS) {                                                       \
            CF_SLOW_WLOG("[CF-SLOW] %s took %.1fs — " fmt, (name), _el / 1000.0, __VA_ARGS__); \
        }                                                                                    \
    } while (0)

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

    BRPeerDisconnectTagged(peer, BR_DISC_TAG_MISBEHAVIN);
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
    MGR_LOCK(manager);
    size_t added = _BRPeerManagerAddPeer(manager, &peer);
    MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);
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

    MGR_UNLOCK(manager);
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
        BRPeerScheduleDisconnectTagged(peer, PROTOCOL_TIMEOUT, BR_DISC_TAG_PUBLISH); // schedule publish timeout
        break;
    }
    
    BRPeerSendInv(peer, manager->publishedTxHashes, array_count(manager->publishedTxHashes));
}

static void _postSyncDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    int syncFinished = 0;
    
    free(info);
    
    if (success) {
        peer_log(peer, "post-sync peer ready");
        MGR_LOCK(manager);
        if (manager->syncStartHeight > 0) {
            peer_log(peer, "sync succeeded");
            syncFinished = 1;
            _BRPeerManagerSyncStopped(manager);
        }

        _BRPeerManagerRequestUnrelayedTx(manager, peer);
        BRPeerSendGetaddr(peer); // request a list of other bitcoin peers
        MGR_UNLOCK(manager);
        if (manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
        if (syncFinished && manager->syncStopped) manager->syncStopped(manager->info, 0);
    }
    else peer_log(peer, "post-sync peer probe failed");
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
        if (BRPeerShouldRequestMempool(
                peer->services, manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY)) {
            BRPeerSendMempool(peer, manager->publishedTxHashes,
                              array_count(manager->publishedTxHashes), info, _postSyncDone);
        }
        else {
            BRPeerSendPing(peer, info, _postSyncDone);
        }
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
    MGR_LOCK(manager);
    
    for (addr = addrList; addr && ! UInt128IsZero(*addr); addr++) {
        age = 24*60*60 + BRRand(2*24*60*60); // add between 1 and 3 days
		BRPeer peer = {*addr, manager->params->standardPort, services, now - age, 0};
		_BRPeerManagerAddPeer(manager,&peer);
    }

    manager->dnsThreadCount--;
    MGR_UNLOCK(manager);
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
            MGR_UNLOCK(manager);
            nanosleep(&ts, NULL); // pthread_yield() isn't POSIX standard :(
            MGR_LOCK(manager);
        } while (manager->dnsThreadCount > 0 && array_count(manager->peers) < PEER_MAX_CONNECTIONS);
    
        qsort(manager->peers, array_count(manager->peers), sizeof(*manager->peers), _peerTimestampCompare);
    }
}

// Forward declarations — BIP 158 hooks used by _peerConnected and
// _peerRelayedCFHeaders. Definitions live near BRPeerManagerSetCallbacks
// alongside the rest of the compact-filter helpers.
static void _BRPeerManagerOnFilterCapablePeerConnected(BRPeerManager *manager, void *peerCbInfo, BRPeer *peer);
static void _BRPeerManagerInstallSavedBlock(BRPeerManager *manager, BRMerkleBlock *block);
static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight,
                                                  BRPeer *preferred);
// Task 3: pre-resolved-hash sibling of the above. The residual batch resolves
// every range's stop hash in ONE descent (Pass B) and hands the result straight
// through here (Pass C) so this never re-walks manager->blocks. Same send/return
// contract as the resolving wrapper, minus the _BRPeerManagerBlockHashAtHeight
// walk. Forward-declared so BRPeerManagerKeepAlive (above the definition) can
// call it.
static size_t _BRPeerManagerRequestCFiltersWithStopHashLocked(BRPeerManager *manager,
                                                             uint32_t startHeight, uint32_t stopHeight,
                                                             UInt256 stopHash, BRPeer *preferred);
static BRPeer *_BRPeerManagerAnyFilterCapablePeer(BRPeerManager *manager);
// isConvoyAdvance: 1 == this is a routine CONVOY ADVANCE toward the tip (the
// clean-append continuation / the block-extend kick) and may be suppressed by
// the paced-convoy gate; 0 == this is a SYNC-START or RECOVERY send (filter-peer
// connect, floor re-anchor) that must ALWAYS go out -- gating one of those
// deadlocks the convoy from the other side. See the per-call-site table in the
// definition below.
static void _BRPeerManagerRequestNextCFHeaders(BRPeerManager *manager, BRPeer *peer, int isConvoyAdvance);
static int _BRPeerManagerReanchorAtFloorLocked(BRPeerManager *manager, int force);
// Defined near BRPeerManagerRequestCompactFilters; forward-declared so the Phase 2
// buffered-drain trampolines (_cfBufEval, above BRPeerManagerKeepAlive) and
// BRPeerManagerKeepAlive's residual re-request driver can both use it.
static int _BRPeerManagerPeerCanServeFilters(BRPeer *p);
static uint32_t _BRPeerManagerBlockFloor(BRPeerManager *manager);
#ifdef CF_KAT_COUNT_MAINCHAIN_WALK
// Host-KAT-only: counts prevBlock steps taken by the "is block in main chain?" descent in
// _peerRelayedBlock, so a gate can assert the walk is SKIPPED when its answer is unused.
// A gate on wall-clock could not distinguish a skipped walk from a fast machine.
unsigned long _cfMainChainWalkSteps = 0;
#endif
#ifdef CF_KAT_COUNT_FLOOR_WALKS
// Host-KAT-only: counts actual _BRPeerManagerBlockFloor descents so the KAT can
// assert the F1 clamp costs ONE walk per tick, not one per send. Never defined in
// any production build (and never read by production code).
static unsigned long _cfBlockFloorWalks = 0;
#endif
static int _BRPeerManagerConnectedFilterPeerCount(BRPeerManager *manager); // defined below; used by the cfheaders stall-drop floor guard
static void _BRPeerManagerProbeOtherFilterPeersForCFHeaders(BRPeerManager *manager, BRPeer *current,
                                                            uint8_t filterType, uint32_t startHeight,
                                                            UInt256 stopHash);

// ---- PACED-CONVOY FETCH: the two window predicates -------------------------
// (spec 2026-07-28-paced-convoy-fetch-design.md, Part A)
//
// Both windows are keyed on the CF SCAN frontier -- BRCFScanLedgerLowestNeededHeight,
// NOT raw scannedThrough: after an abandonment `abandonedBelow` jumps WITHOUT
// _cfLedgerAdvance running, so LowestNeededHeight is current where scannedThrough
// lags, and a gate keyed on the lagging value would stay shut after the valve
// deliberately re-opened the convoy.
//
// LOCKING (load-bearing): manager->lock is a NON-recursive mutex
// (pthread_mutex_init(..., NULL)). Every caller of these -- the KeepAlive tick,
// _peerRelayedBlock, _peerRelayedBlockInv, _BRPeerManagerRequestNextCFHeaders --
// ALREADY HOLDS it. So these read manager->cfLedger DIRECTLY via the lock-free
// ledger-level BRCFScanLedgerLowestNeededHeight and must NEVER call the public
// BRPeerManagerLowestNeededHeight accessor, which takes manager->lock itself and
// would self-deadlock. Caller must hold manager->lock.

// ARMING GUARD (wedge-class; do not remove). The convoy only paces a LIVE
// compact-filter scan. Until the scan is armed, manager->cfLedger is still the
// calloc'd zero state -- scannedThrough == 0 makes LowestNeededHeight == 1,
// which against a mainnet checkpoint tip scores BOTH windows as permanently full
// and would suppress the very block-header sync that has to run FIRST (and that
// EnableAutoCompactFilterFetch needs a tip from before it can even pick a floor):
// a permanent sync wedge on every fresh start. syncMode likewise defaults to
// BR_SYNC_MODE_BLOOM_ONLY (== 0) on a calloc'd manager, and there is no CF scan
// to pace in that mode at all. Every path that arms the scan
// (BRPeerManagerEnableAutoCompactFilterFetch, the cfheaders floor snap, the
// floor re-anchor) sets autoFetchCFiltersEnabled and BRCFScanLedgerInits the
// ledger at a real floor together under this same lock, so this one flag is a
// sound proxy for "the ledger holds a real scan frontier". Caller holds the lock.
static int _cfConvoyScanArmed(BRPeerManager *manager)
{
    return (manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY && manager->autoFetchCFiltersEnabled) ? 1 : 0;
}

// W_hdr: does the BLOCK-HEADER frontier already lead the scan frontier by a full
// window? Underflow-guarded -- the scan frontier can legitimately sit ABOVE
// lastBlock->height (e.g. an abandonment watermark past a not-yet-synced tip),
// and an unsigned wrap there would read as "permanently full" and wedge sync.
static int _cfConvoyHdrGated(BRPeerManager *manager)
{
    if (! _cfConvoyScanArmed(manager)) return 0;
    if (! manager->lastBlock) return 0;
    uint32_t scanFrontier = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
    uint32_t hdrFrontier  = manager->lastBlock->height;
    if (hdrFrontier <= scanFrontier) return 0;
    return (hdrFrontier - scanFrontier) >= CF_CONVOY_WINDOW ? 1 : 0;
}

// W_cfh: does the CFHEADER frontier already lead the scan frontier by a full
// window?
//
// NULL-CHAIN CARVE-OUT (spec blocker B-3, do not "simplify" away):
// compactFilterChain is created LAZILY on the first cfheaders RESPONSE, so on a
// fresh restore it is NULL and BRCompactFilterChainNextHeight(NULL) == 0. The
// naive `NextHeight - 1` would therefore underflow to 0xFFFFFFFF, score the
// window as permanently FULL, and suppress the very FIRST cfheaders request --
// which is the only thing that would ever create the chain. That deadlocks every
// fresh deep restore forever. A NULL chain (and a genesis-anchored empty chain,
// NextHeight == 0) is an OPEN gate.
static int _cfConvoyCfhGated(BRPeerManager *manager)
{
    if (! _cfConvoyScanArmed(manager)) return 0;   // see _cfConvoyScanArmed (wedge-class guard)
    uint32_t scanFrontier = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
#ifndef CONVOY_NULLCHAIN_NAIVE
    if (! manager->compactFilterChain) return 0;   // carve-out: no chain yet -> gate OPEN
#endif
    uint32_t next = BRCompactFilterChainNextHeight(manager->compactFilterChain);
#ifndef CONVOY_NULLCHAIN_NAIVE
    if (next == 0) return 0;                       // carve-out: nothing appended -> gate OPEN
#endif
    uint32_t cfhFrontier = next - 1;
    if (cfhFrontier <= scanFrontier) return 0;
    return (cfhFrontier - scanFrontier) >= CF_CONVOY_WINDOW ? 1 : 0;
}

// The SUPPRESSION sites go through these macros so the host KAT can build the
// pre-fix shape (-DCONVOY_UNGATED) for its red-before-green gate while the
// predicates above stay live as pure measurement -- what that build proves red
// is the GATE, not the arithmetic. -DCONVOY_UNGATED is never defined in any
// production build.
#ifdef CONVOY_UNGATED
#define CF_CONVOY_HDR_GATED(m) (0)
#define CF_CONVOY_CFH_GATED(m) (0)
#else
#define CF_CONVOY_HDR_GATED(m) _cfConvoyHdrGated(m)
#define CF_CONVOY_CFH_GATED(m) _cfConvoyCfhGated(m)
#endif

// A reconnect or download-peer election is another header continuation, not a
// recovery escape hatch. When the CF scan is armed and the header window is
// full, KeepAlive will restart getheaders after the scan frontier advances.
static int _cfConvoyCanStartHeaderRequest(BRPeerManager *manager)
{
    return (manager->syncMode != BR_SYNC_MODE_COMPACT_FILTERS_ONLY ||
            ! CF_CONVOY_HDR_GATED(manager)) ? 1 : 0;
}

// B1.3 getheaders re-kick RATE LIMIT (see CF_CONVOY_HDR_REKICK_BASE_SECS in
// BRPeerManager.h for the full cost argument in both directions). A zero stamp
// means "never re-kicked" == immediately due. Routed through a macro for the same
// reason as the gate above: -DCONVOY_HDR_REKICK_UNTHROTTLED builds the pre-fix
// shape (re-kick on EVERY frozen tick) with the backoff bookkeeping still live,
// so what the host KAT proves red is the THROTTLE, not the arithmetic. Never
// defined in any production build.
#ifdef CONVOY_HDR_REKICK_UNTHROTTLED
#define CF_CONVOY_HDR_REKICK_DUE(m, backoff) (1)
#else
#define CF_CONVOY_HDR_REKICK_DUE(m, backoff) \
    ((m)->convoyLastHdrKickAt == 0 || \
     (time(NULL) - (m)->convoyLastHdrKickAt) >= (time_t)(backoff))
#endif

// ...and the GATED->open episode reset (see convoyHdrWasGated). Same -D idiom:
// -DCONVOY_HDR_REKICK_STALE_ACROSS_GATE builds the pre-fix shape (the backoff
// survives a gated period and a reopen waits it out) with the convoyHdrWasGated
// tracking still live, so what the host KAT proves red is the RESET, not the
// transition detection. Never defined in any production build.
#ifdef CONVOY_HDR_REKICK_STALE_ACROSS_GATE
#define CF_CONVOY_HDR_REKICK_GATE_RESET 0
#else
#define CF_CONVOY_HDR_REKICK_GATE_RESET 1
#endif

// Recompute the header window ONCE and stamp the verdict onto every connected
// peer, so BRPeer.c's CF-only header continuation (_BRPeerAcceptHeadersMessage,
// which runs on each peer's read thread with no access to the opaque manager)
// can read it lock-free. Called on every block-add and every KeepAlive tick;
// deliberately no locking on the peer side -- see BRPeerSetConvoyHdrGated.
// Caller must hold manager->lock.
// True while any published tx still owns a callback. BRPeer's `disconnectTime` is ONE
// field (BRPeer.c:207) shared by the SYNC deadline and the tx-PUBLISH deadline (armed at
// _BRPeerManagerPublishTx), so anything that moves it must not silently swallow a publish
// timeout. _BRPeerManagerSyncStopped open-codes this same loop; kept separate here rather
// than refactoring that one, to keep this change's blast radius to the new call site.
static int _BRPeerManagerHasPendingPublish(BRPeerManager *manager)
{
    for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
        if (manager->publishedTx[i - 1].callback != NULL) return 1;
    }
    return 0;
}

static void _BRPeerManagerPushConvoyHdrGate(BRPeerManager *manager)
{
    int gated = CF_CONVOY_HDR_GATED(manager);
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeerSetConvoyHdrGated(manager->connectedPeers[i - 1], gated);
    }

#ifndef CONVOY_HOLD_SELFKILL_UNFIXED
    // ---- THE CONVOY MUST NOT KILL THE PEER IT JUST SILENCED --------------------
    //
    // MEASURED (Note 8, 2026-08-02, deep restore): the gate shuts here at :2056, and
    // BRPeer.c:649 then deliberately sends no continuation -- but :2076 re-armed a
    // 20 s PROTOCOL_TIMEOUT on the SAME relayed blocks, and that deadline is ABSOLUTE
    // (BRPeer.c:1403 compares it against wall clock; inbound traffic only refreshes
    // lastRecvTime at :1402). So 20 s after we choose silence, our own download peer
    // is disconnected with ETIMEDOUT -> downloadPeer = NULL (:1319) -> reconnect ->
    // handshake -> election -> ANOTHER un-paced full-locator getheaders -> another
    // 20,000 headers. connectFailureCount is reset at :2078 so MAX_CONNECT_FAILURES
    // never trips. That loop is where C ~ 3.55 comes from: 16 elections / 33
    // handshakes, and it is the gate manufacturing the very chains it exists to stop.
    //
    // The deadline means "we ASKED and got nothing". While the gate holds we did not
    // ask, so the peer is not late -- it is obeying us. REFRESH the deadline rather
    // than cancelling it:
    //   * refresh, not cancel, so it stays ARMED -- if the hold lifts and the peer
    //     then goes genuinely silent, it still fires within PROTOCOL_TIMEOUT. A
    //     cancel here would leave only the 90 s inbound-idle reaper (:4302), which a
    //     live-but-unhelpful peer defeats by sending pings.
    //   * this runs on every block-add AND both ends of the ~10 s KeepAlive tick
    //     (the three _BRPeerManagerPushConvoyHdrGate call sites) vs a 20 s deadline.
    //     NOTE there are NO block-adds during a hold, so the KeepAlive sites are the
    //     ones that carry it. If the heartbeat itself stops (KeepAlive starved),
    //     behaviour degrades to exactly TODAY'S -- never to a new wedge.
    //   * guarded on pending publish: refreshing would otherwise postpone a tx
    //     publish timeout indefinitely, and unlike the per-block re-arm in
    //     _peerRelayedBlock (which only fires while blocks are arriving) a hold can
    //     last a long time.
    //
    // HONEST SCOPE, from review: while `gated` holds, the ~10 s refresh against a 20 s
    // deadline means this deadline can never fire. So DURING a hold this is operationally
    // a cancel, and the two guards below are what keep it from being the unbounded cancel
    // that an earlier design was refuted for:
    //
    //   (1) AGREE WITH THE IDLE REAPER, don't race it. KeepAlive pushes the gate, then
    //       runs the 90 s inbound-idle reaper (BRPeerScheduleDisconnect(p, 0)), then
    //       pushes the gate AGAIN at the end of the tick. disconnectTime is one
    //       last-write-wins double, so an unconditional refresh in that second push
    //       REVERTS the reaper's verdict for the download peer -- and the peer's read
    //       thread only samples the field about once a second (1 s SO_RCVTIMEO), so the
    //       reap would survive only by winning a millisecond-wide race. Testing the same
    //       lastRecvTime predicate the reaper uses makes the two agree by construction.
    //   (2) BOUND THE HOLD. `gated` is a pure function of the SCAN frontier, so a frozen
    //       frontier is a permanent hold, and an indefinitely refreshed deadline makes a
    //       ping-answering-but-useless download peer immortal (idle reaper defeated by
    //       pings, socket open so no read-loop reap, stalled-filter drop only targets the
    //       cfheaders peer). CF_CONVOY_HOLD_MAX_SECS lets exactly one real timeout through
    //       per cap period. Wall clock always advances, so unlike a frontier-keyed brake
    //       this can never latch shut.
    if (! gated || ! manager->downloadPeer) {
        manager->convoyHoldAddr = UINT128_ZERO;
        manager->convoyHoldPort = 0;
        manager->convoyHoldSince = 0;
    }
    // START THE CLOCK on `convoyHoldSince == 0`, not on the (addr, port) key. The key's
    // cleared state is (0, 0), which a peer whose port is genuinely 0 compares EQUAL to --
    // so keying the restart on identity alone left the clock at 0, and the refresh's own
    // `convoyHoldSince != 0` test then failed forever: the hold never engaged at all. A
    // wall-clock second is never legitimately 0, so it is the safe sentinel.
    else if (manager->convoyHoldSince == 0 ||
             manager->convoyHoldPort != manager->downloadPeer->port ||
             ! UInt128Eq(manager->convoyHoldAddr, manager->downloadPeer->address)) {
        manager->convoyHoldAddr  = manager->downloadPeer->address;
        manager->convoyHoldPort  = manager->downloadPeer->port;
        manager->convoyHoldSince = time(NULL);
    }

    if (gated && manager->downloadPeer &&
        BRPeerConnectStatus(manager->downloadPeer) == BRPeerStatusConnected &&
        ! _BRPeerManagerHasPendingPublish(manager)) {
        struct timeval htv;
        gettimeofday(&htv, NULL);
        double hnow = htv.tv_sec + (double)htv.tv_usec/1000000;

        if (hnow - BRPeerLastRecvTime(manager->downloadPeer) <= PEER_INBOUND_IDLE_LIMIT &&
            manager->convoyHoldSince != 0 &&
            (time(NULL) - manager->convoyHoldSince) <= CF_CONVOY_HOLD_MAX_SECS) {
            BRPeerScheduleDisconnectTagged(manager->downloadPeer, PROTOCOL_TIMEOUT, BR_DISC_TAG_SYNC);
        }
    }
#endif
}

// Ring-buffer insert/refresh for the churn-fix penalty set (see PEER_PENALTY_*
// above). If (addr, port) is already on the list its window is refreshed;
// otherwise it's inserted at penaltyCount % PEER_PENALTY_MAX (oldest entry
// evicted once the buffer wraps). Caller holds manager->lock.
static void _penalizeFor(BRPeerManager *manager, UInt128 addr, uint16_t port, time_t now, time_t secs)
{
    for (size_t i = 0; i < manager->penaltyCount && i < PEER_PENALTY_MAX; i++) {
        if (manager->penaltyPort[i] == port && UInt128Eq(manager->penaltyAddr[i], addr)) {
            // Never SHORTEN an existing penalty: a 10-minute "node isn't synced" ban must
            // not be downgraded to a 30-second redial cooldown by a later clean disconnect.
            if (now + secs > manager->penaltyUntil[i]) manager->penaltyUntil[i] = now + secs;
            return;
        }
    }

    // Not full yet: append.
    if (manager->penaltyCount < PEER_PENALTY_MAX) {
        size_t idx = manager->penaltyCount;
        manager->penaltyAddr[idx] = addr;
        manager->penaltyPort[idx] = port;
        manager->penaltyUntil[idx] = now + secs;
        manager->penaltyCount++;
        return;
    }

#ifndef PENALTY_EVICT_UNFIXED   // host-KAT red arm keeps the old oldest-insert ring
    // FULL: evict by EXPIRY, never by insertion order.
    //
    // The old policy was `idx = penaltyCount % PEER_PENALTY_MAX` — overwrite the oldest
    // INSERT. That silently discarded whatever happened to be oldest, including a live
    // 10-minute "doesn't support SPV mode" ban, in favour of an unrelated 30-second
    // redial cooldown. The evicted peer became instantly re-dialable, reconnected, was
    // rejected again, and re-penalised — evicting someone else in turn. Measured: 41
    // distinct peers, 3,520 disconnects in ~1 minute, every connection slot consumed.
    //
    // Prefer an ALREADY-EXPIRED slot (free real estate). Otherwise take the soonest to
    // expire, and only if the newcomer actually outlives it — a 30s cooldown must never
    // be able to displace a ban with minutes left to run. If it cannot, we simply drop
    // the new penalty: failing to cool down one peer for 30s is strictly less harmful
    // than un-banning a node we already know is unusable.
    size_t victim = 0;
    for (size_t i = 1; i < PEER_PENALTY_MAX; i++) {
        if (manager->penaltyUntil[i] < manager->penaltyUntil[victim]) victim = i;
    }
    if (manager->penaltyUntil[victim] > now && manager->penaltyUntil[victim] >= now + secs) return;
#else
    size_t victim = manager->penaltyCount % PEER_PENALTY_MAX;
#endif

    manager->penaltyAddr[victim] = addr;
    manager->penaltyPort[victim] = port;
    manager->penaltyUntil[victim] = now + secs;
    manager->penaltyCount++;
}

static void _penalize(BRPeerManager *manager, UInt128 addr, uint16_t port, time_t now)
{
    _penalizeFor(manager, addr, port, now, PEER_PENALTY_SECONDS);
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

// Download-peer election reuses and may reassign _peerConnected's local `peer`.
// Compact-filter callbacks belong to the peer whose handshake invoked this call:
// replies are parsed on that peer's BRPeerContext. Registering them on the elected
// download peer leaves the actual responder with NULL callbacks, so valid cfheaders
// are parsed and then silently discarded forever.
static BRPeer *_BRPeerManagerCompactFilterCallbackPeer(BRPeerCallbackInfo *info, BRPeer *electedPeer)
{
#ifdef CF_CALLBACK_ELECTION_UNFIXED
    return electedPeer;
#else
    return info->peer;
#endif
}

static void _peerConnected(void *info)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRPeerCallbackInfo *peerInfo;
    time_t now = time(NULL);
    
    MGR_LOCK(manager);
    if (peer->timestamp > now + 2*60*60 || peer->timestamp < now - 2*60*60) peer->timestamp = now; // sanity check

    // Keep a newly connected peer in the same pacing state as the existing
    // set. Otherwise its BRPeer-side 20,000-header continuation starts ungated
    // until the next block or KeepAlive tick refreshes the pushed verdict.
    BRPeerSetConvoyHdrGated(peer, CF_CONVOY_HDR_GATED(manager));
    
    // TODO: XXX does this work with 0.11 pruned nodes?
    if ((peer->services & manager->params->services) != manager->params->services) {
        peer_log(peer, "unsupported node type");
        BRPeerDisconnectTagged(peer, BR_DISC_TAG_UNUSABLE_PEER);
    }
    else if ((peer->services & SERVICES_NODE_NETWORK) != SERVICES_NODE_NETWORK) {
        peer_log(peer, "node doesn't carry full blocks");
        BRPeerDisconnectTagged(peer, BR_DISC_TAG_UNUSABLE_PEER);
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
        BRPeerDisconnectTagged(peer, BR_DISC_TAG_NOT_SYNCED);
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
        BRPeerDisconnectTagged(peer, BR_DISC_TAG_UNUSABLE_PEER);
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
            if (BRPeerShouldRequestMempool(
                    peer->services, manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY)) {
                BRPeerSendMempool(peer, manager->publishedTxHashes,
                                  array_count(manager->publishedTxHashes), peerInfo, _postSyncDone);
            }
            else {
                BRPeerSendPing(peer, peerInfo, _postSyncDone);
            }
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
        
        if (manager->downloadPeer) BRPeerDisconnectTagged(manager->downloadPeer, BR_DISC_TAG_DOWNLOAD_SWAP);
        manager->downloadPeer = peer;
        manager->isConnected = 1;
        manager->estimatedHeight = BRPeerLastBlock(peer);
        BRPeerSetCurrentBlockHeight(peer, manager->lastBlock->height);
        _BRPeerManagerPublishPendingTx(manager, peer);
            
        if (manager->lastBlock->height < BRPeerLastBlock(peer)) { // start blockchain sync
            UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
            size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));
            
            if (! _cfConvoyCanStartHeaderRequest(manager)) {
                peer_log(peer, "paced convoy: holding new download-peer header request (header frontier a full window ahead of the CF scan)");
            }
            else {
                BRPeerScheduleDisconnectTagged(peer, PROTOCOL_TIMEOUT, BR_DISC_TAG_SYNC); // schedule sync timeout

                // request just block headers up to a week before earliestKeyTime, and then merkleblocks after that
                // we do not reset connect failure count yet incase this request times out
                if (manager->syncMode != BR_SYNC_MODE_COMPACT_FILTERS_ONLY &&
                    manager->lastBlock->timestamp + 7*24*60*60 >= manager->earliestKeyTime) {
                    BRPeerSendGetblocks(peer, locators, count, UINT256_ZERO);
                }
                else BRPeerSendGetheaders(peer, locators, count, UINT256_ZERO); // compact-only always pulls plain headers
            }
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
    BRPeer *filterPeer = _BRPeerManagerCompactFilterCallbackPeer((BRPeerCallbackInfo *)info, peer);
    if (BRPeerConnectStatus(filterPeer) == BRPeerStatusConnected) {
        _BRPeerManagerOnFilterCapablePeerConnected(manager, info, filterPeer);
    }

    // Refresh peer-count/downloadPeer mirrors so the connect-phase overlay shows the
    // live peer count before the first block arrives.
    _BRPeerManagerRefreshCachedStatus(manager);
    MGR_UNLOCK(manager);
}

/* ---------- DISCONNECT LEDGER emission (BRPeer.h) ----------
 *
 * A close is "short-lived" below this many seconds. Eviction off a saturated node lands
 * here (Core evicts shortly after the handshake when it has no free inbound slot); a peer
 * we used for a while and then timed out does not. The split is what separates "we cannot
 * GET a slot" from "we cannot HOLD one".
 */
#define CLOSE_LEDGER_SHORT_SECS   30.0
/* Emit the running histogram every Nth close. Cheap, self-contained, and makes an overnight
 * capture readable without parsing every per-close line. */
#define CLOSE_LEDGER_SUMMARY_EVERY 10

// Formats the histogram into buf. Call with manager->lock held.
static void _BRPeerManagerFormatCloseLedger(BRPeerManager *manager, char *buf, size_t bufLen)
{
    size_t off = 0;
    int n;

    n = snprintf(buf, bufLen, "closes=%u shortLived(<%.0fs)=%u |",
                 manager->closeTotal, CLOSE_LEDGER_SHORT_SECS, (unsigned)manager->closeShortLived);
    if (n > 0 && (size_t)n < bufLen) off = (size_t)n; else return;

    for (int c = 1; c < BR_CLOSE_CAUSE_COUNT; c++) {
        if (manager->closeCounts[c] == 0) continue;
        n = snprintf(buf + off, bufLen - off, " %s=%u",
                     BRPeerCloseCauseName((BRPeerCloseCause)c), manager->closeCounts[c]);
        if (n <= 0 || (size_t)n >= bufLen - off) return;
        off += (size_t)n;
    }

    n = snprintf(buf + off, bufLen - off, " | tags:");
    if (n <= 0 || (size_t)n >= bufLen - off) return;
    off += (size_t)n;

    for (int t = 1; t < BR_DISC_TAG_COUNT; t++) {
        if (manager->closeTagCounts[t] == 0) continue;
        n = snprintf(buf + off, bufLen - off, " %s=%u",
                     BRPeerDisconnectTagName((BRPeerDisconnectTag)t), manager->closeTagCounts[t]);
        if (n <= 0 || (size_t)n >= bufLen - off) return;
        off += (size_t)n;
    }
}

static void _peerDisconnected(void *info, int error)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRTxPeerList *peerList;
    int willSave = 0, willReconnect = 0, txError = 0;
    size_t txCount = 0;

    //free(info);
    MGR_LOCK(manager);

    /* ---- DISCONNECT LEDGER: record this close before any teardown touches the peer ----
     * peer is BRPeerFree'd at the bottom of this function, so everything must be read here.
     * The download-peer flag matters most: a close on the download peer stalls the sync,
     * while a close on a spare costs nothing — mixing them hides the signal. */
    {
        BRPeerCloseCause    cause = BRPeerCloseCauseOf(peer);
        BRPeerDisconnectTag tag   = BRPeerDisconnectTagOf(peer);
        double              life  = BRPeerConnectedSecs(peer);
        int                 isDl  = (peer == manager->downloadPeer);

        if ((size_t)cause < BR_CLOSE_CAUSE_COUNT) manager->closeCounts[cause]++;
        if ((size_t)tag < BR_DISC_TAG_COUNT)      manager->closeTagCounts[tag]++;
        manager->closeTotal++;
        if (life > 0 && life < CLOSE_LEDGER_SHORT_SECS) manager->closeShortLived++;

        /* lastRecvAgo must be differenced against a FRACTIONAL clock. time(NULL) floors to
         * whole seconds while lastRecvTime is a gettimeofday double, so the subtraction
         * printed values up to a second negative — nonsense for an "age", and it would
         * misjudge exactly the sub-second window that separates "went quiet then closed"
         * from "closed mid-traffic". */
        struct timeval ltv;
        gettimeofday(&ltv, NULL);
        double lnow = ltv.tv_sec + (double)ltv.tv_usec/1000000;
        double lastRecv = BRPeerLastRecvTime(peer);

        peer_log(peer, "[PEER-LEDGER] close cause=%s tag=%s dl=%d err=%d life=%.1fs "
                       "in=%llub/%umsg out=%llub/%umsg handshake=%d lastRecvAgo=%.1fs",
                 BRPeerCloseCauseName(cause), BRPeerDisconnectTagName(tag), isDl, error, life,
                 (unsigned long long)BRPeerBytesIn(peer), BRPeerMsgsIn(peer),
                 (unsigned long long)BRPeerBytesOut(peer), BRPeerMsgsOut(peer),
                 BRPeerCompletedHandshake(peer),
                 (lastRecv > 0) ? (lnow - lastRecv) : -1.0);

        if (manager->closeTotal % CLOSE_LEDGER_SUMMARY_EVERY == 0) {
            char summary[512];
            _BRPeerManagerFormatCloseLedger(manager, summary, sizeof(summary));
            peer_log(peer, "[PEER-LEDGER] %s", summary);
        }
    }

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
        //
        // The upstream "BUG: XXX what if it's a connect timeout and not a publish timeout?"
        // that used to sit here was real, and it cost a live user their DigiAsset sends.
        // Measured 2026-08-23 on an S25 Ultra:
        //
        //   04:55:47.678  64.20.49.248  sending inv          <- tx published to a HEALTHY peer
        //   04:55:49.685  192.42.116.14 disconnected
        //                   cause=CONNECT_FAIL err=110 life=0.0s handshake=0 in=0b/0msg
        //   04:55:49.685  192.42.116.14 transaction canceled: Connection timed out
        //   04:55:51.855  64.20.49.248  got getdata with 1 item(s)   <- 2s TOO LATE, tx freed
        //
        // An unrelated address that never even completed a handshake failed to dial, and its
        // connect timeout cancelled a publish sitting on a different, working peer — which
        // then asked for the transaction and found it gone. That is the whole "my send needs
        // an app restart to go through" report: the wallet dials constantly, so a failed dial
        // inside the publish window is common, and rebroadcastStrandedSends only runs at sync
        // start, so a restart was the only thing that re-sent it.
        //
        // A peer that never handshook was never sent an inv, so its timeout says nothing
        // about any publish. Requiring BRPeerCompletedHandshake() keeps the genuine
        // publish-timeout case (a peer we really did publish to, going quiet) while removing
        // the connect-failure case entirely.
        if (error == ETIMEDOUT && BRPeerCompletedHandshake(peer) &&
            (peer != manager->downloadPeer || manager->syncStartHeight == 0 ||
             array_count(manager->connectedPeers) == 1)) txError = ETIMEDOUT;
        else if (error == ETIMEDOUT) {
            peer_log(peer, "connect timeout on a peer that never handshook — NOT cancelling "
                     "%zu pending publish(es)", array_count(manager->publishedTx));
        }
    }
    
    // REDIAL COOLDOWN — every disconnect, clean or not. Only the `error` branch above
    // removes a peer from the pool, so a clean disconnect (error == 0) left it instantly
    // re-dialable. _penalizeFor never shortens an existing entry, so this cannot downgrade
    // a 10-minute "not synced" ban.
    _penalizeFor(manager, peer->address, peer->port, time(NULL), PEER_REDIAL_COOLDOWN_SECONDS);

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
    MGR_UNLOCK(manager);

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

    MGR_LOCK(manager);
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
    MGR_UNLOCK(manager);
    
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
    
    MGR_LOCK(manager);
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
            BRPeerScheduleDisconnectTagged(peer, PROTOCOL_TIMEOUT, BR_DISC_TAG_SYNC);
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
    
    MGR_UNLOCK(manager);
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
    
    MGR_LOCK(manager);
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
            BRPeerScheduleDisconnectTagged(peer, PROTOCOL_TIMEOUT, BR_DISC_TAG_SYNC);
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
    
    MGR_UNLOCK(manager);
    if (txCallback) txCallback(txInfo, 0);
}

static void _peerRejectedTx(void *info, UInt256 txHash, uint8_t code)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRTransaction *tx, *t;

    MGR_LOCK(manager);
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

    MGR_UNLOCK(manager);
    if (manager->txStatusUpdate) manager->txStatusUpdate(manager->info);
}

// Warn-level, operator-visible log for a CF-scan ABANDONMENT (the B2 valve in
// BRPeerManagerKeepAlive). peer_log needs a peer and debug_log is silent in
// release; this call site has no peer and the event MUST be visible at WARN level
// (a real, countable loss — "N blocks abandoned, rescan/reconcile to recover"),
// so it routes straight to the platform logger at WARN (tag "bread", matching
// peer_log). The host KATs pre-#define CF_RETENTION_WLOG to capture the line and
// assert it fired (or, on every must-NOT-abandon path, assert it did NOT), so the
// production definition is #ifndef-guarded.
#ifndef CF_RETENTION_WLOG
#if defined(__ANDROID__)
#define CF_RETENTION_WLOG(...) __android_log_print(ANDROID_LOG_WARN, "bread", __VA_ARGS__)
#elif defined(TARGET_OS_MAC)
#define CF_RETENTION_WLOG(...) NSLog(__VA_ARGS__)
#else
#define CF_RETENTION_WLOG(...) printf(__VA_ARGS__)
#endif
#endif

// A filter can be evaluated only while its block header is resident. If the scan
// frontier falls below the resident header floor, or a proven-unservable hole pins
// it, the band must be written off — but NEVER silently. This is the single funnel
// that does it: raise abandonedBelow, accumulate the honest running total, and WARN
// with the byte-stable "[CF-SCAN] ABANDONED %u height(s) [%u..%u]" prefix operators
// and the host KATs key on.
//
// WHY IT MUST ABANDON, not merely log (fix-wave C2/I3). The lab reduced this to a
// bare "RECOVERY REQUIRED" log line and left the ledger untouched. abandonedBelow
// then had NO writer in any production path, so `CfAbandonmentStore` was never
// populated, the "Scan for missing transactions" banner was unreachable, and the
// pinning hole held BRCFScanLedgerLowestNeededHeight — and therefore both convoy
// windows — forever, with the wallet showing "Syncing" and no recovery affordance.
// Refusing to skip is only honest if the refusal is VISIBLE and BOUNDED; a hole
// that no retry can ever serve has to become a surfaced, recoverable band.
//
// `lo` is the low edge observed BEFORE the floor moved. Caller MUST hold
// manager->lock, so this uses the lock-free BRCFScanLedger* API only.
static void _BRPeerManagerSurfaceUnscannableLocked(BRPeerManager *manager, uint32_t lo,
                                                   uint32_t floor, const char *why)
{
#ifdef CF_SURFACE_LOG_ONLY_UNFIXED
    // RED-before-green shape ONLY (never in a production build): the lab's log-only
    // funnel. The band is announced but nothing raises abandonedBelow, so the hole
    // keeps pinning the frontier and no recovery affordance can ever appear.
    (void)manager;
    if (lo > 0 && floor > lo) {
        CF_RETENTION_WLOG("[CF-SCAN] RECOVERY REQUIRED [%u..%u] — resident block headers do not cover "
                          "the scan frontier (%s). Refusing to skip; rebuild headers from wallet birth.\n",
                          lo, floor - 1, why ? why : "");
    }
    return;
#else
    uint32_t cnt = 0;
    BRCFScanLedgerAbandonUnscannableBelow(&manager->cfLedger, lo, floor, &cnt);
    // Determinism, same shape as the B2 valve: cnt>0 <=> abandonedBelow advanced
    // <=> this WARN. "abandonedBelow == 0" therefore stays a verified log fact.
    if (cnt > 0) {
#ifndef ABANDON_TOTAL_UNFIXED
        // Accumulate BEFORE the WARN so the logged running total includes this event.
        // `cnt` is the only trustworthy figure here: it is what the ledger actually
        // dropped, computed inside AbandonUnscannableBelow. Anything derived from
        // (abandonedBelow - start) is destroyed by the next ledger re-Init.
        manager->cfAbandonedHeightsTotal += (size_t)cnt;
#endif
        // The CAUSE comes from `why` — do NOT re-assert one in the format string.
        // `floor` is the new watermark, so it is labelled as exactly that. The
        // "ABANDONED %u height(s) [%u..%u]" prefix is deliberately byte-identical —
        // that is what operators and the host KATs key on. `totalAbandoned` is
        // APPENDED, never spliced into the prefix.
        CF_RETENTION_WLOG("[CF-SCAN] ABANDONED %u height(s) [%u..%u] — unscannable this session (%s); "
                          "abandonedBelow=%u totalAbandoned=%zu. Surfaced for recovery "
                          "(rescan or 'Scan for missing transactions').\n",
                          cnt, lo, floor - 1, why ? why : "", floor,
                          manager->cfAbandonedHeightsTotal);
    }
#endif
}

// Retire as much of an abandoned band as the RESIDENT block headers can currently
// support, and return how many heights were retired (0 if none).
//
// This is the enforcement half of BRCFScanLedgerRetireAbandonedTo's contract. The ledger
// deliberately cannot see the block set, so it cannot check whether the headers for the
// range are back; this can. _BRPeerManagerBlockFloor is exactly the right question — it
// returns the lowest height still reachable by walking prevBlock links from lastBlock,
// i.e. the deepest height for which a getcfilters stop hash can still be resolved.
//
// Retiring only down to that floor is what makes the operation safe to call at ANY time,
// including before any header backfill has run: with no extra headers it simply retires
// nothing. A backfill then lowers the block floor, and calling this again retires further.
// Header-first, floor-second, enforced here rather than trusted.
//
// Caller must hold manager->lock.
static uint32_t _BRPeerManagerRetireAbandonedToResidentLocked(BRPeerManager *manager)
{
    uint32_t abandoned = BRCFScanLedgerAbandonedBelow(&manager->cfLedger);
    if (abandoned == 0) return 0;                      // nothing abandoned

    uint32_t floor = _BRPeerManagerBlockFloor(manager);
    if (floor == 0 || floor >= abandoned) return 0;    // no headers below the floor to help

    uint32_t retired = BRCFScanLedgerRetireAbandonedTo(&manager->cfLedger, floor);
    if (retired > 0) {
        CF_RETENTION_WLOG("[CF-SCAN] RETIRED %u abandoned height(s) — headers are resident "
                     "down to %u, so those heights are requestable again (abandonedBelow %u -> %u)",
                     retired, floor, abandoned, floor);
    }
    return retired;
}

// Public entry point: same as above but takes the lock itself.
uint32_t BRPeerManagerRetireAbandonedBand(BRPeerManager *manager)
{
    if (!manager) return 0;
    MGR_LOCK(manager);
    uint32_t retired = _BRPeerManagerRetireAbandonedToResidentLocked(manager);
    MGR_UNLOCK(manager);
    return retired;
}

// Note a header admitted into the backfill run, so the next request can use it as a
// locator. Called from the fork branch of _peerRelayedBlock, which is where a header
// below lastBlock lands. Caller must hold manager->lock.
static void _BRPeerManagerNoteBackfillHeaderLocked(BRPeerManager *manager, const BRMerkleBlock *block)
{
    if (!manager->cfBackfillTarget || !block) return;
    // Only headers that extend the run upward are interesting. A peer answering an old
    // request can deliver something below the current tip; ignoring it keeps the locator
    // moving in one direction and stops a stale reply rewinding progress.
    if (block->height <= manager->cfBackfillTipHeight) return;
    if (block->height >= manager->cfBackfillTarget) return;   // past the band, nothing to do
    manager->cfBackfillTipHeight = block->height;
    manager->cfBackfillTipHash   = block->blockHash;
}

// One step of the abandoned-band backfill. Safe to call on any tick: it retires whatever
// the resident headers already allow, then asks one peer for the next stretch.
//
// Stateless with respect to progress — every call re-derives what to do from the ledger
// and the block set, so a missed tick, a dropped peer or a process restart costs nothing
// but time. Returns the number of heights retired by THIS call.
//
// Returns without requesting anything when there is no band, when the whole band is
// already retired, or when no filter peer is available.
uint32_t BRPeerManagerBackfillAbandonedBandStep(BRPeerManager *manager)
{
    if (!manager) return 0;
    MGR_LOCK(manager);

    uint32_t abandoned = BRCFScanLedgerAbandonedBelow(&manager->cfLedger);
    if (abandoned == 0) {                       // nothing to do; forget any stale run
        manager->cfBackfillTarget   = 0;
        manager->cfBackfillTipHeight = 0;
        MGR_UNLOCK(manager);
        return 0;
    }

    // Free progress first: headers may already reach further down than when the band was
    // raised (an ordinary re-anchor, a restore, or an earlier step of this backfill).
    uint32_t retired = _BRPeerManagerRetireAbandonedToResidentLocked(manager);
    abandoned = BRCFScanLedgerAbandonedBelow(&manager->cfLedger);
    if (abandoned == 0) {
        manager->cfBackfillTarget = 0;
        manager->cfBackfillTipHeight = 0;
        MGR_UNLOCK(manager);
        return retired;
    }

    // (Re)start the run whenever the target moves — a band raised again while a backfill
    // was in flight must not be chased with a locator derived from the old one.
    if (manager->cfBackfillTarget != abandoned) {
        manager->cfBackfillTarget    = abandoned;
        manager->cfBackfillTipHeight = 0;
    }

    // Locator: the run's own tip once it exists, otherwise the highest BLOCK checkpoint
    // at or below the band. Those checkpoints are inserted into manager->blocks at
    // construction, so one is always available — which is what makes a pruned range
    // reachable at all.
    UInt256 locator = UINT256_ZERO;
    if (manager->cfBackfillTipHeight > 0) {
        locator = manager->cfBackfillTipHash;
    }
    else {
        uint32_t best = 0;
        for (size_t i = 0; i < manager->params->checkpointsCount; i++) {
            uint32_t h = manager->params->checkpoints[i].height;
            if (h < abandoned && h > best) {
                best = h;
                locator = UInt256Reverse(manager->params->checkpoints[i].hash);
            }
        }
        if (best == 0) { MGR_UNLOCK(manager); return retired; }   // no anchor below the band
        manager->cfBackfillTipHeight = best;
        manager->cfBackfillTipHash   = locator;
    }

    // Any connected filter peer will do — this is ordinary header data, not filter data,
    // so it needs no special capability beyond being connected.
    BRPeer *peer = NULL;
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        BRPeer *p = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(p) == BRPeerStatusConnected) { peer = p; break; }
    }
    if (!peer) { MGR_UNLOCK(manager); return retired; }

    UInt256 locators[1] = { locator };
    peer_log(peer, "cf-backfill: requesting headers from %u toward abandoned floor %u "
             "(%u height(s) still condemned)",
             manager->cfBackfillTipHeight, abandoned, abandoned - manager->cfBackfillTipHeight);
    BRPeerSendGetheaders(peer, locators, 1, UINT256_ZERO);

    MGR_UNLOCK(manager);
    return retired;
}

#if CF_LEDGER_DRIVE_REREQUEST
// May the forward cfilter drive issue the NEXT batch this tick? (fix-wave I3)
//
// SELF-RELEASING BACK-PRESSURE, not an all-or-nothing gate. The only thing the
// forward drive must not do is outrun the ledger's in-flight ceiling: once
// `outstanding` reaches CF_OUTSTANDING_LOWWATER, pausing keeps it from growing
// toward CF_OUTSTANDING_MAX, where the oldest holes would start being evicted.
// It releases on its own as the residual driver drains the backlog.
//
// WHY NOT `outstanding == 0 && gaveUp == 0` (the lab's BRCFScanLedgerCanRequestForward).
// That makes ONE unresolved height close the whole forward frontier: the height the
// currently-connected CF subset refuses pins the fetch, the paced convoy then freezes
// the header and cfheader frontiers at scanFrontier + CF_CONVOY_WINDOW, and the wallet
// stalls indefinitely with the UI still reading "Syncing".
//
// It is also unnecessary for the "never silently skip" property the strict gate was
// written for: _cfLedgerAdvance caps scannedThrough at min(outstanding[0], gaveUp[0]) - 1,
// so forward FETCH proceeding can never move the scan frontier across a hole. The
// hole still pins the frontier; what changes is that throughput above it continues,
// so the convoy keeps supplying headers and the hole's own retry keeps getting peers.
static int _cfForwardFetchAllowed(const BRPeerManager *manager)
{
#ifdef CF_FORWARD_GATE_ALL_OR_NOTHING_UNFIXED
    // RED-before-green shape ONLY (never in a production build): the lab's
    // all-or-nothing gate. One unservable height closes the forward frontier.
    return BRCFScanLedgerCanRequestForward(&manager->cfLedger);
#else
    return BRCFScanLedgerOutstandingCount(&manager->cfLedger) < CF_OUTSTANDING_LOWWATER;
#endif
}
#endif // CF_LEDGER_DRIVE_REREQUEST

// NOTE (paced-convoy Task 5): the tip-anchored DEPTH CEILING that used to live
// here (_cfApplyRetentionCeiling, `tip - floorH > CF_RETENTION_MAX_SPAN` →
// abandon the gaveUp prefix) is DELETED — as is the CF_RETENTION_MAX_SPAN
// #define itself, together with the app-layer refusal gate that read it via
// jni_peer.c. It was a depth refusal — "this history
// is too old to keep trying" — and the paced convoy removes depth refusal
// outright: with the header/cfheader frontiers paced to CF_CONVOY_WINDOW of the
// scan frontier, the resident header span is flat at ~2.2 MB at ANY restore
// depth, so depth is no longer a reason to give up on a height.
//
// The abandonment it doubled as is NOT gone — it moved, with a far better
// trigger, to the B2 valve in BRPeerManagerKeepAlive: abandon only what a live,
// connected CF-peer subset has provably been OFFERED and REFUSED across
// CF_CONVOY_REARM_MAX fresh retry cycles. AbandonGaveUpBelow + abandonedBelow +
// the WARN + the determinism guard are all retained there.
//
// The retention FLOOR below (min(cfNext, LowestNeededHeight) - margin) is a
// DIFFERENT mechanism and is untouched: it is what keeps the scan-floor headers
// alive for the buffer-drain and the residual re-request.

// reduce memory usage
// clear the tail that comes after 500 blocks.
// checkpoints will remain in the blocks-Set, until we are ahead of them.
static void _BRPeerManagerClearMemory(BRPeerManager* manager) {
    BRMerkleBlock* blockPtr = manager->lastBlock;
    UInt256 prevHash;
    size_t count = BRSetCount(manager->blocks);
    size_t i = 0;
    CF_PHASE_START(_phaseT0);

    // BIP 158: never prune block headers the compact-filter SCAN (or its
    // residual re-request) still needs. The floor tracks the lowest height the
    // SCAN still needs a header for — NOT the cfHEADER frontier. cfheaders burst
    // to the tip while the cfilter scan lags at a floor cluster; a floor pinned
    // to the cfheader frontier prunes the scan-floor headers out from under the
    // buffer-drain (_cfBufIsReady → BRSetGet NULL) and the residual re-request
    // (stop-hash → ZERO), the permanent on-device wedge. floorH = min(cfNext,
    // lowestNeeded) collapses to the old cfNext-144 in steady state (scan caught
    // up → lowestNeeded == cfNext), so there is no regression; the span is bounded
    // by the PACED CONVOY (CF_CONVOY_WINDOW), not by a depth ceiling — the header
    // frontier can no longer race the scan frontier by more than a window, so the
    // retained span is flat at any restore depth. Zero in BLOOM_ONLY / no-chain so
    // pruning behaves exactly as before.
    uint32_t cfFloor = 0;
    if (manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY) {
        if (manager->compactFilterChain) {
            uint32_t cfNext = BRCompactFilterChainNextHeight(manager->compactFilterChain);
#ifdef RETENTION_UNFIXED
            // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a
            // production build). The floor tracked the cfHEADER frontier, which
            // races ahead of the cfilter SCAN, so the scan-floor headers got
            // pruned; this is the wedge the retention KAT reproduces (RED here).
            if (cfNext > CLEAR_MEM_CF_RETENTION_MARGIN) cfFloor = cfNext - CLEAR_MEM_CF_RETENTION_MARGIN;
            else if (cfNext > 0) cfFloor = 1;
#else
            uint32_t lowestNeeded = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
            uint32_t floorH = (lowestNeeded < cfNext) ? lowestNeeded : cfNext;   // min(cfNext, lowestNeeded)
            cfFloor = (floorH > CLEAR_MEM_CF_RETENTION_MARGIN) ? floorH - CLEAR_MEM_CF_RETENTION_MARGIN
                    : (floorH > 0 ? 1 : 0);
#endif
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
#ifdef RETENTION_UNFIXED
            if (start > CLEAR_MEM_CF_RETENTION_MARGIN) cfFloor = start - CLEAR_MEM_CF_RETENTION_MARGIN;
            else cfFloor = 1;
#else
            // The ledger is ALWAYS Init'd(start) together with autoFetchCFiltersStart
            // (every call site sets the two in lockstep), and lowestNeeded only ever
            // grows from `start`, so min(start, lowestNeeded) == start here — this
            // retains at/above the armed birth height exactly as before. No depth
            // ceiling: the convoy bounds the resident span at ANY birth depth.
            uint32_t lowestNeeded = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
            uint32_t floorH = (lowestNeeded < start) ? lowestNeeded : start;   // min(start, lowestNeeded)
            cfFloor = (floorH > CLEAR_MEM_CF_RETENTION_MARGIN) ? floorH - CLEAR_MEM_CF_RETENTION_MARGIN
                    : (floorH > 0 ? 1 : 0);
#endif
        }
    }

#ifndef CF_RETENTION_NO_SPAN_CLAMP
    // Make the retained span UNCONDITIONALLY bounded. The floor above is anchored to the
    // SCAN (min(cfNext, lowestNeeded) - margin), which is correct, but its bound is
    // conditional on the convoy keeping the frontiers within a window of that scan. A frozen
    // scan frontier freezes the floor with it, and then every header from there to the tip is
    // retained without limit — measured at 145,894 resident with the pruner freeing nothing.
    //
    // Clamping the FLOOR UP (never down) can only ever retain LESS, so this cannot resurrect
    // the pruning wedge the scan anchor fixed: it only refuses to hold an unbounded span.
    // Heights that fall below the clamped floor become unrequestable and are reported by the
    // existing surfacing path rather than skipped silently.
    if (manager->lastBlock && manager->lastBlock->height > CF_RETENTION_SPAN_MAX) {
        uint32_t spanFloor = manager->lastBlock->height - CF_RETENTION_SPAN_MAX;
        if (cfFloor < spanFloor) {
            // Rate-limited: once the clamp binds it binds on EVERY block-add, and this is a
            // WARN. Log only when the clamped floor has moved materially since the last line,
            // so the condition stays visible without flooding logd (which this project has
            // already had starve out its own diagnostics once).
            if (spanFloor >= manager->lastSpanClampLog + CLEAR_MEM_BLOCKS_COUNT_TRIGGER ||
                manager->lastSpanClampLog == 0) {
                CF_RETENTION_WLOG("[CF-SCAN] retention span clamped: floor %u -> %u (tip %u, cap %u) — "
                                  "the scan frontier is too far behind to retain every header; "
                                  "heights below the new floor are surfaced, not silently skipped",
                                  cfFloor, spanFloor, manager->lastBlock->height,
                                  (unsigned)CF_RETENTION_SPAN_MAX);
                manager->lastSpanClampLog = spanFloor;
            }
            cfFloor = spanFloor;
        }
    }
#endif

    // ---- O(1) NO-OP SHORT-CIRCUIT ------------------------------------------------
    //
    // This runs on EVERY block-add. The descent below skips (continue) every block at
    // or above cfFloor, so when the whole resident chain sits above the floor it walks
    // the entire set and frees NOTHING. Measured on a Note 8, fresh wallet: ~20,800
    // BRSetGet lookups per block, forever, with `[MEMORY]: Blocks reduced from 20586 to
    // 20586` repeating — pure cost, under manager->lock, on the hot path.
    //
    // Sound because prunability is MONOTONE IN cfFloor: blocks are only ever appended
    // at the tip (a reorg replaces the tip, it does not extend the chain downward), so
    // the resident bottom cannot move down, and a block can only become prunable when
    // cfFloor rises above it. Having walked the whole chain at floor F and freed
    // nothing, no floor <= F can free anything.
    //
    // Deliberately does NOT invalidate floorMemoValid: skipping means we did not touch
    // the block set, so the resident floor is unchanged and its memo stays valid.
    if (manager->clearMemNoopFloor != 0 && cfFloor <= manager->clearMemNoopFloor) return;

    // ---- AMORTISE THE DESCENT (the short-circuit above CANNOT cover this) ----------
    //
    // Once CF_RETENTION_SPAN_MAX binds, cfFloor becomes `tip - 150000` and rises by ONE
    // on every block-add. That defeats the memo above twice: `cfFloor <= clearMemNoopFloor`
    // is never true again, and freeing the single block that just dropped below the floor
    // sets clearMemNoopFloor = 0 anyway. Every block-add then pays a FULL O(resident)
    // descent to free ONE block. Measured on device: 77 ms/header, one core pegged, and
    // because the descent holds manager->lock it starves BRPeerManagerKeepAlive -- so the
    // residual re-request driver never runs, outstanding heights are never retried, the
    // scan frontier never advances, and the clamp keeps binding. Self-sustaining wedge.
    //
    // Deferring costs at most CLEAR_MEM_PRUNE_STRIDE extra resident blocks (~459 KB) and
    // is safe in BOTH directions: a lower resident floor makes MORE heights requestable,
    // never fewer. Guarded on cfFloor > 0 so a mode with no CF floor (cfFloor == 0) keeps
    // pruning on the old schedule instead of latching shut -- an unguarded compare would
    // make `0 < lastPruneFloor + STRIDE` true forever and leak the whole chain.
#ifndef PRUNE_STRIDE_UNFIXED   // host-KAT red arm compiles the amortisation OUT
    if (cfFloor > 0 && manager->lastPruneFloor != 0 &&
        cfFloor < manager->lastPruneFloor + CLEAR_MEM_PRUNE_STRIDE) return;
#endif

    // F1: from here on this function CAN raise the resident block floor, so drop the
    // memo. Moved below the short-circuit deliberately: a skipped call touches nothing,
    // and invalidating there would force a full O(chain) floor recompute on the next
    // reader — re-introducing on the read side exactly the per-block walk the
    // short-circuit just removed. (The memo key would catch a change anyway, but a
    // floor cache whose only defence is a derived key is one refactor away from being
    // stale, and a stale-HIGH floor would over-clamp getcfilters.)
    manager->floorMemoValid = 0;

    if (count >= CLEAR_MEM_BLOCKS_COUNT_TRIGGER) {
        // find the tail
        while (blockPtr && i++ <= (CLEAR_MEM_BLOCKS_COUNT_TRIGGER - CLEAR_MEM_BLOCKS_COUNT_TAIL_LEN))
            blockPtr = BRSetGet(manager->blocks, &blockPtr->prevBlock);

        if (blockPtr) {
            prevHash = blockPtr->prevBlock;
#ifdef CF_PRUNE_INSTRUMENT
            manager->pruneDescents++;
#endif

            // clear the tail
            while (blockPtr && !UInt256IsZero(prevHash)) {

                // get the block
                blockPtr = BRSetGet(manager->blocks, &prevHash);
#ifdef CF_PRUNE_INSTRUMENT
                manager->pruneSetGets++;
#endif
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
                    // DO NOT free a block manager->checkpoints also holds. BRPeerManagerNewEx adds
                    // the SAME BRMerkleBlock* to both sets (the BRSetAdd pair after
                    // BRMerkleBlockNew), but only manager->blocks governs its lifetime here.
                    //
                    // The comment above this function records the original assumption --
                    // "checkpoints will remain in the blocks-Set, until we are ahead of them" --
                    // true while pruning trailed the chain tip. It is FALSE under CF-era pruning:
                    // the floor is anchored to the compact-filter SCAN frontier, so once the scan
                    // advances past a checkpoint height that checkpoint block is pruned and freed,
                    // leaving manager->checkpoints holding a dangling pointer. The next relayed
                    // header then calls BRSetGet(manager->checkpoints, block) and _BRBlockHeightEq
                    // dereferences ->height on freed memory.
                    //
                    // ASan on-device 2026-08-06, full stack:
                    //   _peerThreadRoutine -> _BRPeerAcceptMessage -> _BRPeerAcceptHeadersMessage
                    //   -> _peerRelayedBlock -> _BRPeerManagerVerifyBlock (:2114) -> BRSetGet
                    //   -> _BRBlockHeightEq (:227)   heap-use-after-free
                    //
                    // POINTER IDENTITY, not BRSetGet equality: checkpoints is keyed by
                    // _BRBlockHeightEq, so a lookup can return a DIFFERENT block that merely shares
                    // this height. Only the very same object must be spared.
#ifdef CHECKPOINT_ALIAS_UNFIXED
                    // RED ARM ONLY (checkpoint_alias_uaf_kat) — never defined in a production
                    // build. The pre-fix shape: free unconditionally, leaving checkpoints dangling.
                    BRMerkleBlockFree(blockPtr);
#else
                    if (BRSetGet(manager->checkpoints, blockPtr) != blockPtr) {
                        // free the actual memory
                        BRMerkleBlockFree(blockPtr);
                    }
#endif
                } else {
                    // nothing to remove
                    break;
                }
            }

            size_t after = BRSetCount(manager->blocks);

            // We paid for a full descent at this floor. Record it whether or not anything
            // was freed: the cost we are amortising is the WALK, not the freeing. (The
            // clearMemNoopFloor memo below answers a different question -- "can any floor
            // <= F free anything" -- and is reset the moment a walk frees, which is exactly
            // why it cannot bound the clamped regime on its own.)
            manager->lastPruneFloor = cfFloor;

            if (after < count) {
                // Freed something: the floor moved, so any earlier no-op observation is
                // stale and the next call must walk again.
                manager->clearMemNoopFloor = 0;
                debug_log("[MEMORY]: Blocks reduced from %ld to %ld blocks\n", count, after);
            }
            else {
                // Full descent, nothing prunable at this floor. Remember it so the next
                // block-add costs one comparison instead of another full walk.
                manager->clearMemNoopFloor = cfFloor;
            }
        }
    }

    CF_PHASE_END(_phaseT0, "ClearMemory", "resident=%zu cfFloor=%u tip=%u",
                 BRSetCount(manager->blocks), cfFloor,
                 manager->lastBlock ? manager->lastBlock->height : 0);
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

// Caller holds manager->lock. The callback copies the bytes before returning.
static void _BRPeerManagerPersistCFLedgerLocked(BRPeerManager *manager)
{
    if (!manager->saveCFLedger) return;
    size_t ledgerLen = BRCFScanLedgerSerialize(&manager->cfLedger, NULL, 0);
    uint8_t *ledgerBuf = (ledgerLen > 0) ? malloc(ledgerLen) : NULL;
    if (!ledgerBuf) return;
    size_t wrote = BRCFScanLedgerSerialize(&manager->cfLedger, ledgerBuf, ledgerLen);
    if (wrote == ledgerLen) {
        manager->saveCFLedger(manager->saveCFLedgerInfo, ledgerBuf, ledgerLen);
    }
    free(ledgerBuf);
}

// ---- CF full-block solicitation table (C1 request-gate) --------------------
// Contract and rationale: see BRCFSolicitedBlock at the top of this file. All three
// require manager->lock.

// Records that WE dispatched getdata for `blockHash` (resolved at `height`) because a
// cfilter that verified against the committed cfheader chain matched the wallet.
static void _BRPeerManagerRecordSolicitedBlockLocked(BRPeerManager *manager, UInt256 blockHash, uint32_t height)
{
    size_t slot = SIZE_MAX, oldest = 0;

    for (size_t i = 0; i < CF_SOLICITED_BLOCKS_MAX; i++) {
        if (manager->cfSolicitedBlocks[i].used &&
            UInt256Eq(manager->cfSolicitedBlocks[i].blockHash, blockHash)) { // re-request of the same block
            manager->cfSolicitedBlocks[i].height = height;
            manager->cfSolicitedBlocks[i].seq    = ++manager->cfSolicitedSeq;
            return;
        }

        if (slot == SIZE_MAX && ! manager->cfSolicitedBlocks[i].used) slot = i;
        if (manager->cfSolicitedBlocks[i].seq < manager->cfSolicitedBlocks[oldest].seq) oldest = i;
    }

    if (slot == SIZE_MAX) { // table full: evict the oldest in-flight solicitation
        slot = oldest;
        _peer_log("cf-ledger: solicited-block table full (%d) — evicting the getdata for height %u; "
                  "that height stays outstanding and is re-requested\n",
                  CF_SOLICITED_BLOCKS_MAX, manager->cfSolicitedBlocks[slot].height);
    }

    manager->cfSolicitedBlocks[slot].blockHash = blockHash;
    manager->cfSolicitedBlocks[slot].height    = height;
    manager->cfSolicitedBlocks[slot].seq       = ++manager->cfSolicitedSeq;
    manager->cfSolicitedBlocks[slot].used      = 1;
}

// Returns the table index of an OUTSTANDING solicitation for exactly this (blockHash, height)
// pair, or -1. Deliberately does NOT consume: a forged/stripped delivery must not be able to
// burn the solicitation and lock the honest block out of completing the height.
static int _BRPeerManagerFindSolicitedBlockLocked(BRPeerManager *manager, UInt256 blockHash, uint32_t height)
{
    for (size_t i = 0; i < CF_SOLICITED_BLOCKS_MAX; i++) {
        if (manager->cfSolicitedBlocks[i].used &&
            manager->cfSolicitedBlocks[i].height == height &&
            UInt256Eq(manager->cfSolicitedBlocks[i].blockHash, blockHash)) return (int)i;
    }

    return -1;
}

// Drops every recorded solicitation. Called wherever the scan they belong to goes away.
static void _BRPeerManagerClearSolicitedBlocksLocked(BRPeerManager *manager)
{
    memset(manager->cfSolicitedBlocks, 0, sizeof(manager->cfSolicitedBlocks));
    manager->cfSolicitedSeq = 0;
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
    
    MGR_LOCK(manager);
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
        
        _BRPeerManagerInstallSavedBlock(manager, block);
        manager->lastBlock = block;

        // Paced-convoy: lastBlock just advanced, so the header window changed —
        // recompute it once and re-push the verdict to every connected peer
        // before anything else this pass reads it. (KeepAlive re-pushes on its
        // own ~10 s tick as the backstop for every other lastBlock mutation.)
        _BRPeerManagerPushConvoyHdrGate(manager);

        // Kick cfheaders driver — on fresh-boot the autoFetchCFiltersStart
        // height may sit above the checkpoint, so OnFilterCapablePeerConnected
        // saw tip<start and bailed. Each block that advances lastBlock gives
        // the driver another chance; it self-no-ops once caught up.
        // isConvoyAdvance=1: this kick races the tip alongside header sync, so it
        // is exactly what the convoy paces.
        if (manager->autoFetchCFiltersEnabled &&
            manager->syncMode != BR_SYNC_MODE_BLOOM_ONLY) {
            BRPeer *fp = _BRPeerManagerAnyFilterCapablePeer(manager);
            if (fp) _BRPeerManagerRequestNextCFHeaders(manager, fp, /*isConvoyAdvance=*/1);
        }

        // clear some memory
        _BRPeerManagerClearMemory(manager);
        
        if (txCount > 0) _BRPeerManagerUpdateTx(manager, txHashes, txCount, block->height, txTime);
        if (manager->downloadPeer) BRPeerSetCurrentBlockHeight(manager->downloadPeer, block->height);
            
        if (block->height < manager->estimatedHeight && peer == manager->downloadPeer) {
            BRPeerScheduleDisconnectTagged(peer, PROTOCOL_TIMEOUT, BR_DISC_TAG_SYNC); // reschedule sync timeout
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
        
        // ---- SKIP THE MAIN-CHAIN DESCENT WHEN ITS ANSWER IS UNUSED ------------------
        //
        // The descent below walks prevBlock from the tip down to block->height purely to
        // answer "is `block` on the main chain?". That answer is consumed ONLY by the two
        // statements in the `if` beneath it, and each of those is ITSELF conditional:
        // stamping tx heights needs txCount > 0, and re-pointing lastBlock needs
        // block->height == lastBlock->height. When neither holds the entire walk is dead
        // work and its result is discarded (`b` is reassigned by BRSetAdd immediately after).
        //
        // Neither holds during header catch-up: headers carry no transactions, and an
        // ALREADY-KNOWN header is by definition below the tip. Meanwhile 8 peers send
        // overlapping header ranges, so this branch runs for most arriving headers.
        //
        // MEASURED on a Note 8, deep restore from block 12,100,000 (2026-08-08), with every
        // other profiled section reading ZERO:
        //     51ms/37,711 it   53ms/49,846 it   58ms/51,953 it
        //     52ms/55,474 it   53ms/56,824 it   53ms/61,085 it
        // The iteration count GROWS with the resident set, so cost per block RISES as the
        // restore proceeds — the self-amplifying shape behind the "deep restore never
        // finishes" class: more headers -> longer walk -> slower processing -> more headers.
        //
        // Equivalence is exact, not approximate: under the negated guard both consumers are
        // no-ops, so skipping changes nothing observable.
        int needChainCheck = (txCount > 0) ||
                             (manager->lastBlock && block->height == manager->lastBlock->height);
#ifdef MAINCHAIN_WALK_UNFIXED
        needChainCheck = 1;   // host-KAT red arm: always descend, as before this fix
#endif
        b = NULL;
        if (needChainCheck) {
            b = manager->lastBlock;
            while (b && b->height > block->height) {
                b = BRSetGet(manager->blocks, &b->prevBlock); // is block in main chain?
#ifdef CF_KAT_COUNT_MAINCHAIN_WALK
                _cfMainChainWalkSteps++;   // host-KAT only; never defined in production
#endif
            }
        }
        
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
            int freeable = 1;
#ifdef CHECKPOINT_STUB_FREE_UNGUARDED_UNFIXED
            // RED ARM ONLY (checkpoint_stub_free_guard_kat) — never defined in a production
            // build. Pre-fix shape: repoints checkpoints by HEIGHT, trusting an assert() that
            // is compiled out under NDEBUG, then frees `b` unconditionally below (P1).
            if (BRSetGet(manager->checkpoints, b) == b) {
                BRMerkleBlock *checkpoint = BRSetAdd(manager->checkpoints, block);
                assert(checkpoint == b);
            }
#else
            if (BRSetGet(manager->checkpoints, b) == b) {
                // checkpoints is keyed by HEIGHT, `b`/manager->blocks by HASH: the repoint
                // below only lands on `b`'s slot when the two heights agree. If they don't,
                // BRSetAdd(checkpoints, block) inserts under a DIFFERENT key and `b` stays
                // resident in manager->checkpoints — freeing it at the bottom of this branch
                // would then leave a dangling pointer in a set nothing ever removes from
                // (P1). Gate the free on the repoint having actually landed, at runtime.
                if (b->height == block->height) {
                    BRMerkleBlock *checkpoint = BRSetAdd(manager->checkpoints, block);
                    assert(checkpoint == b);
                    if (checkpoint != b) freeable = 0;   // still held elsewhere — leak, not dangle
                } else {
                    freeable = 0;   // heights disagree: leave the stub owned by checkpoints
                }
            }
#endif
            // remove the block from orphans, if it exists
            if (BRSetGet(manager->orphans, b) == b) BRSetRemove(manager->orphans, b);
            if (manager->lastOrphan == b) manager->lastOrphan = NULL;

            // ...and re-point lastBlock, for exactly the same reason lastOrphan is cleared above.
            //
            // `b` is the DISPLACED block that BRSetAdd evicted — a previously-resident header with
            // this same hash. manager->lastBlock may still point at it, and freeing it below then
            // leaves lastBlock dangling. Every later deref is a use-after-free:
            // `manager->lastBlock->height` a few lines up at the height-stamping branch, the fork
            // comparisons below it, and _BRPeerManagerBlockFloor's prevBlock descent.
            //
            // `block` is the identical header by hash (that is why BRSetAdd displaced `b`) and is
            // the copy now resident in manager->blocks, so it is the correct replacement rather
            // than a NULL that would strand the chain tip.
            //
            // Note this is the ONLY free in _peerRelayedBlock that does not null its pointer: the
            // other four all do `BRMerkleBlockFree(block); block = NULL;`, which is why the reads
            // further down are guarded by `if (block && ...)`. This one had no such guard.
            //
            // ASan on-device 2026-08-06, alloc _BRPeerAcceptHeadersMessage:804 -> free here ->
            // read in the same headers message. Also drop the floor memo, which caches lastBlock
            // as floorMemoTip and would otherwise key off a freed pointer.
            if (manager->lastBlock == b) {
                manager->lastBlock = block;
                manager->floorMemoValid = 0;
            }
            if (manager->floorMemoTip == b) manager->floorMemoValid = 0;
            if (manager->startSyncFrom == b) manager->startSyncFrom = block;

#ifdef CHECKPOINT_STUB_FREE_UNGUARDED_UNFIXED
            BRMerkleBlockFree(b);
#else
            if (freeable) {
                BRMerkleBlockFree(b);
            }
            // else: `b` leaks — still resident in manager->checkpoints under a height key
            // that disagrees with `block`'s. The correct degradation per P1: a leak is safe,
            // a dangling checkpoints entry is not.
#endif
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
        // A backfilled header (below lastBlock, above the newest block checkpoint) lands
        // here too — it is not really a fork, it is a height we already pruned. Note it
        // so the backfill's next locator advances, and keep quiet: a 20k-height backfill
        // would otherwise emit 20k "chain fork" lines.
        int isBackfill = (manager->cfBackfillTarget != 0 &&
                          block->height < manager->cfBackfillTarget);
        if (!isBackfill) peer_log(peer, "chain fork reached height %"PRIu32, block->height);
        BRSetAdd(manager->blocks, block);
        if (isBackfill) _BRPeerManagerNoteBackfillHeaderLocked(manager, block);

        if (block->height > manager->lastBlock->height) { // check if fork is now longer than main chain
            b = block;
            b2 = manager->lastBlock;
            
            while (b && b2 && ! BRMerkleBlockEq(b, b2)) { // walk back to where the fork joins the main chain
                b = BRSetGet(manager->blocks, &b->prevBlock);
                if (b && b->height < b2->height) b2 = BRSetGet(manager->blocks, &b2->prevBlock);
            }
            
#ifdef REORG_NULLGUARD_UNFIXED
            // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a
            // production build). The join point was assumed resident, so both uses
            // below dereference `b` unguarded and a pruned join is a SIGSEGV. This
            // is the shape test_reorg_below_window_no_crash crashes on (== RED).
            peer_log(peer, "reorganizing chain from height %"PRIu32", new height is %"PRIu32, b->height, block->height);

            BRWalletSetTxUnconfirmedAfter(manager->wallet, b->height); // mark tx after the join point as unconfirmed
#else
            // The paced convoy makes manager->blocks a bounded WINDOW, so the walk
            // above can exit with b == NULL: the fork's join point may have been
            // pruned below the retention floor between the fork's first block
            // arriving and the one that overtakes the main chain. Before the window
            // existed the join was always resident; now it is not, and dereferencing
            // b here is a SIGSEGV on a real reorg. No join point means no known
            // height to roll back to, so the un-confirm is skipped — the longer fork
            // is still adopted below, which is the safe direction (nothing is lost;
            // at worst a tx confirmed on the abandoned branch keeps a stale height
            // until it is re-relayed or the chain is reconciled).
            if (b) {
                peer_log(peer, "reorganizing chain from height %"PRIu32", new height is %"PRIu32, b->height, block->height);

                BRWalletSetTxUnconfirmedAfter(manager->wallet, b->height); // mark tx after the join point as unconfirmed
            }
            else {
                peer_log(peer, "reorg fork-join point is no longer in the retained block window — adopting the "
                         "longer fork at height %"PRIu32" without a confirmation roll-back", block->height);
            }
#endif

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
    
    BRMerkleBlock **saveBlocks = saveCount ? calloc(saveCount, sizeof(*saveBlocks)) : NULL;
    if (! saveBlocks) saveCount = 0;
    
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

    MGR_UNLOCK(manager);
    free(saveBlocks);

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
static void _peerRelayedBlockTxns(void *info, UInt256 blockHash, UInt256 merkleRoot,
                                  const UInt256 txHashes[], size_t txCount)
{
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    BRMerkleBlock *b, *b2;
    int confirmed = 0;

    if (txCount == 0) return;

    MGR_LOCK(manager);
    b = BRSetGet(manager->blocks, &blockHash);

    if (! b) { // header not synced yet; the block will be re-requested/re-relayed once it is
        // Observe-only (Phase 1): record the wallet txs against this not-yet-connected
        // block so a pending-confirm hole is visible. Record only — do NOT drain.
        BRCFScanLedgerRecordPending(&manager->cfLedger, blockHash, txHashes, txCount, (uint32_t)time(NULL));
        debug_log("cf-ledger: pending-confirm hole — recorded %zu wallet tx(s) for not-yet-connected block %s\n",
                  txCount, log_u256_hex_encode(blockHash));
        MGR_UNLOCK(manager);
        return;
    }

    b2 = manager->lastBlock;
    while (b2 && b2->height > b->height) b2 = BRSetGet(manager->blocks, &b2->prevBlock); // is block in main chain?

#ifdef RELAYEDBLOCKTXNS_MAINCHAIN_NULLGUARD_UNFIXED
    // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a production
    // build). b2 was assumed resident, so BRMerkleBlockEq derefs NULL. This is the
    // shape test4 in cf_confirm_kat crashes on (== RED).
    if (! BRMerkleBlockEq(b2, b)) { // block is on a fork, not the main chain; don't confirm against it
        MGR_UNLOCK(manager);
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
        MGR_UNLOCK(manager);
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

#ifndef CF_MATCH_MARK_ON_REQUEST_UNFIXED
    // Every transaction in the full block was parsed and handed through relayedTx
    // before this callback. Only now is a matched filter durably complete.
#ifdef CF_BLOCK_COMPLETION_UNGATED_UNFIXED
    // PRE-FIX shape — host-KAT red-before-green ONLY (never defined in a production build).
    // Completion trusts the `block` message outright: any dialed peer's UNSOLICITED block
    // clears an outstanding hole, and a SOLICITED block with the wallet's payment stripped
    // out of its tx list completes the height with the receive uncredited. See the
    // cf_block_completion_gate_kat RED arm.
    BRCFScanLedgerMarkEvaluated(&manager->cfLedger, b->height);
    _BRPeerManagerPersistCFLedgerLocked(manager);
#else
    // C1 (fund safety). Two things must hold before this delivery is allowed to retire a
    // scan height, because BRPeer.c's `block` path proves NEITHER on its own:
    //
    //   1. WE asked for it. BRPeer.c:_BRPeerAcceptBlockMessage is dispatched with no
    //      request-gating at all, and the callback is wired on every connected peer — so
    //      without this, any peer can erase a hole another peer was asked to fill (and
    //      RecordRequested puts an ENTIRE requested range into `outstanding` at getcfilters
    //      time, so a peer that withholds its cfilters and sprays blocks could drive
    //      scannedThrough to requestedThrough with ZERO filters ever evaluated).
    //
    //   2. The delivered tx list is the block's ACTUAL tx list. Nothing upstream checks it
    //      against the header's committed merkle root, so the peer serving the height can
    //      answer our own getdata with the real 80-byte header (correct blockHash, resolves
    //      here, passes the main-chain walk) and a tx list with the wallet's payment removed.
    //      Recomputing the root over the delivered txids is exactly what catches that.
    //
    // `merkleRoot` is the root committed by the DELIVERED header (BRPeer.c hands up msg[36..68]
    // from the same 80 bytes blockHash is the double-SHA256 of). Since blockHash just resolved
    // in our own header set, that root is authentic — and it is the right one to check against,
    // because our RESIDENT header can be a hardcoded checkpoint stub with no merkleRoot at all
    // (BRPeerManagerNewEx seeds every checkpoint as a stub, and the scan floor sits on one).
    // Checking a stub's zero root instead would refuse every honest delivery at the floor and
    // wedge the scan there forever. b->merkleRoot is still cross-checked when it HAS one.
    //
    // A verified block with NO wallet transactions still completes the height — the question
    // is "did I ask for this, and does it verify", never "did it pay me". On either failure
    // the height stays OUTSTANDING and the ordinary re-request driver retries it, which is
    // the safe direction: re-scanning a height costs a round trip, skipping one hides a
    // receive until a manual rescan.
    int solicited = _BRPeerManagerFindSolicitedBlockLocked(manager, blockHash, b->height);

    if (solicited >= 0) {
        UInt256 deliveredRoot = UINT256_ZERO;

        if (! BRMerkleRootFromTxHashes(&deliveredRoot, txHashes, txCount)) {
            _peer_log("cf-ledger: block %u tx list is not a usable merkle preimage (%zu tx, "
                      "duplicate-subtree mutation?) — height stays outstanding\n", b->height, txCount);
        }
        else if (! UInt256Eq(deliveredRoot, merkleRoot)) {
            // Stripped/substituted/reordered tx list: it does not hash to what this block's own
            // header commits to, so it proves nothing about what height b->height contains.
            _peer_log("cf-ledger: block %u tx list does NOT hash to the header's committed merkle "
                      "root — refusing to complete the height, left outstanding for re-request\n",
                      b->height);
        }
        else if (! UInt256IsZero(b->merkleRoot) && ! UInt256Eq(merkleRoot, b->merkleRoot)) {
            // Defence in depth: unreachable while blockHash resolution is sound (the hash commits
            // to the header the root lives in), so reaching it means our resident header and the
            // delivered one disagree — do not complete on that.
            _peer_log("cf-ledger: block %u delivered header's merkle root disagrees with our "
                      "resident header — refusing to complete the height\n", b->height);
        }
        else {
            manager->cfSolicitedBlocks[solicited].used = 0; // consume ONLY on success
            manager->cfSolicitedBlocks[solicited].seq  = 0;
            BRCFScanLedgerMarkEvaluated(&manager->cfLedger, b->height);
            _BRPeerManagerPersistCFLedgerLocked(manager);
        }
    }
    else {
        _peer_log("cf-ledger: full block for height %u was never solicited by this wallet — "
                  "not completing its scan height\n", b->height);
    }
#endif
#endif

    free(walletHashes);
    MGR_UNLOCK(manager);

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
// Pick the sole peer allowed to drive the block-header stream. This mirrors
// Neutrino's explicit syncPeer: without one owner, the same block inv arriving
// from N peers queues N full DigiByte 20,000-header responses. Caller holds lock.
static BRPeer *_BRPeerManagerHeaderSyncPeer(BRPeerManager *manager)
{
    BRPeer *peer = manager->downloadPeer;
    if (peer && BRPeerConnectStatus(peer) == BRPeerStatusConnected && BRPeerIsSocketOpen(peer)) return peer;

    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        peer = manager->connectedPeers[i - 1];
        if (BRPeerConnectStatus(peer) == BRPeerStatusConnected && BRPeerIsSocketOpen(peer)) return peer;
    }
    return NULL;
}

static void _peerRelayedBlockInv(void *info, UInt256 blockHash)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    MGR_LOCK(manager);

    // PACED-CONVOY GATE, getheaders half (spec Part A). This is the second
    // tip-racing continuation: every block inv pulls headers from our tip, so on
    // a deep restore it drags the header frontier toward the tip in lockstep with
    // BRPeer.c's batch continuation. Suppressed on the same window; unlike the
    // BRPeer.c:622 site this one runs in-manager under the lock, so it reads the
    // predicate directly instead of a pushed flag. Download-peer sync-start is
    // gated separately in _peerConnected; orphan re-anchor and tip-stall
    // recovery are separate call sites that are not this driver.
    BRPeer *syncPeer = _BRPeerManagerHeaderSyncPeer(manager);
    if (manager->syncMode == BR_SYNC_MODE_COMPACT_FILTERS_ONLY && manager->lastBlock &&
        BRPeerConnectStatus(peer) == BRPeerStatusConnected &&
#ifndef CF_INV_ANY_PEER_UNFIXED
        peer == syncPeer &&
#endif
        ! CF_CONVOY_HDR_GATED(manager) &&
        ! BRSetGet(manager->blocks, &blockHash)) { // header not yet known — pull it from our tip
        UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
        size_t count = _BRPeerManagerBlockLocators(manager, locators, sizeof(locators)/sizeof(*locators));

        peer_log(peer, "cf-only: block inv %s — requesting headers from tip %"PRIu32,
                 log_u256_hex_encode(blockHash), manager->lastBlock->height);
        BRPeerSendGetheaders(peer, locators, count, UINT256_ZERO);
    }

    MGR_UNLOCK(manager);
}

static void _peerDataNotfound(void *info, const UInt256 txHashes[], size_t txCount,
                             const UInt256 blockHashes[], size_t blockCount)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    MGR_LOCK(manager);

    for (size_t i = 0; i < txCount; i++) {
        _BRTxPeerListRemovePeer(manager->txRelays, txHashes[i], peer);
        _BRTxPeerListRemovePeer(manager->txRequests, txHashes[i], peer);
    }

    MGR_UNLOCK(manager);
}

static void _peerSetFeePerKb(void *info, uint64_t feePerKb)
{
    BRPeer *p, *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    uint64_t maxFeePerKb = 0, secondFeePerKb = 0;
    
    MGR_LOCK(manager);
    
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

    MGR_UNLOCK(manager);
}

//static void _peerRequestedTxPingDone(void *info, int success)
//{
//    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
//    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
//    UInt256 txHash = ((BRPeerCallbackInfo *)info)->hash;
//
//    free(info);
//    MGR_LOCK(manager);
//
//    if (success && ! _BRTxPeerListHasPeer(manager->txRequests, txHash, peer)) {
//        _BRTxPeerListAddPeer(&manager->txRequests, txHash, peer);
//        BRPeerSendGetdata(peer, &txHash, 1, NULL, 0); // check if peer will relay the transaction back
//    }
//    
//    MGR_UNLOCK(manager);
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

    MGR_LOCK(manager);

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
    MGR_UNLOCK(manager);
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

    MGR_LOCK(manager);
    manager->peerThreadCount--;
    MGR_UNLOCK(manager);
    
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

// Install a persisted header into the live main-chain set. A persisted run may
// cross a hardcoded checkpoint whose hash-only stub is already in both sets.
// Replace that stub in BOTH indexes with the real serialized header so its
// prevBlock keeps the restored chain connected and ownership remains singular.
static void _BRPeerManagerInstallSavedBlock(BRPeerManager *manager, BRMerkleBlock *block)
{
    BRMerkleBlock *replaced = BRSetAdd(manager->blocks, block);
#ifdef CHECKPOINT_STUB_FREE_UNGUARDED_UNFIXED
    // RED ARM ONLY (checkpoint_stub_free_guard_kat) — never defined in a production build.
    // Pre-fix shape: manager->blocks matched `replaced` by HASH but manager->checkpoints
    // is repointed by HEIGHT, and the only guard against the two disagreeing was
    // assert(checkpoint == replaced) — a no-op under NDEBUG. If block->height differs
    // from replaced->height, BRSetAdd(checkpoints, block) inserts under a different key,
    // `replaced` stays resident in manager->checkpoints, and this frees it anyway (P1).
    if (replaced && replaced != block &&
        BRSetGet(manager->checkpoints, replaced) == replaced) {
        BRMerkleBlock *checkpoint = BRSetAdd(manager->checkpoints, block);
        assert(checkpoint == replaced);
        BRMerkleBlockFree(replaced);
    }
#else
    if (replaced && replaced != block &&
        BRSetGet(manager->checkpoints, replaced) == replaced) {
        // checkpoints is keyed by HEIGHT, blocks is keyed by HASH: the repoint below
        // only lands on `replaced`'s slot when the two heights agree. If they don't,
        // BRSetAdd(checkpoints, block) inserts under a DIFFERENT key and `replaced`
        // stays resident in manager->checkpoints — freeing it here would then leave a
        // dangling pointer in a set nothing ever removes from (P1). Gate the free on
        // the repoint having actually landed, at runtime, not just via assert().
        if (replaced->height == block->height) {
            BRMerkleBlock *checkpoint = BRSetAdd(manager->checkpoints, block);
            assert(checkpoint == replaced);
            if (checkpoint == replaced) {
                BRMerkleBlockFree(replaced);
            }
            // else: checkpoints still holds `replaced` under some other key — leak
            // rather than dangle. Should be unreachable given the height check above;
            // kept as the runtime backstop the assert alone cannot provide.
        }
        // else: heights disagree — leave the stub owned by checkpoints and manager->blocks
        // alone now points at `block`. `replaced` leaks (the pre-diff behavior) instead of
        // dangling in manager->checkpoints.
    }
#endif
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
    
    // ---- Chain the persisted run DOWNWARD (fix wave R2) --------------------
    //
    // This loop used to chain FORWARD: it added `block` (the HIGHEST saved
    // header) to manager->blocks, then looked in `orphans` — which is indexed by
    // prevBlock — for that block's CHILD. The highest saved header has no child,
    // so BRSetGet returned NULL and the loop exited after exactly ONE iteration.
    // Exactly one of the SAVE_BLOCK_COUNT persisted headers ever reached
    // manager->blocks; the other 299 stayed stranded in `orphans`, unreachable
    // for the whole session and freed at teardown.
    //
    // Consequence: on EVERY resume the resolvable block FLOOR
    // (_BRPeerManagerBlockFloor — a prevBlock walk through manager->blocks) was
    // the saved TIP, so every height below it was unservable in both directions
    // (getcfilters stop hash can't resolve; a volunteered cfilter is dropped by
    // _peerRelayedCFilter as an unknown block). The CF scan ledger is persisted on
    // a 20-s coalescing timer while saved blocks are written on every save
    // callback, so an abrupt kill of a HEALTHY, fully-synced wallet routinely left
    // the restored ledger 1–2 heights below the restored block tip — and those
    // heights, though genuinely scanned, then had to be SURFACED as an abandoned
    // band (non-dismissible banner, "Synced" withheld). Walking prevBlock DOWNWARD
    // makes the whole persisted [tip-299..tip] run resident, so the floor is
    // savedTip-(SAVE_BLOCK_COUNT-1) and that entire class is simply resolvable
    // again — no band is surfaced at all. (It does NOT cure the deep-restore band:
    // 300 << CF_CONVOY_WINDOW, so a resumed deep descent still surfaces, correctly.)
    //
    // SET MEMBERSHIP IS LOAD-BEARING — BRPeerManagerFree frees `blocks` and
    // `orphans` SEPARATELY (BRSetApply(..., _setApplyFreeBlock) on each, :4634-4637),
    // so a block living in BOTH sets is DOUBLE-FREED. Every header this loop adds
    // to `blocks` is therefore removed from `orphans` first, keyed by its own
    // prevBlock (the `orphans` index). If some other block — a saved sibling on a
    // fork sharing the same parent, which BRSetAdd would have collapsed onto that
    // one key — is what actually sat under the key, it is put straight back, so it
    // stays owned by exactly one set too.
    //
    // `savedByHash` is a lookup index ONLY: it is needed because `orphans` is keyed
    // by prevBlock and the downward step needs a lookup BY blockHash. BRSetFree
    // releases only the hash table, never the items (unlike the BRSetApply pairs in
    // BRPeerManagerFree), so it never competes for ownership of a header.
#ifdef RESUME_FLOOR_UNFIXED
    // Pre-fix shape, built ONLY by the host-KAT red-before-green gate
    // (-DRESUME_FLOOR_UNFIXED). Chains FORWARD from the highest saved block:
    // looks for a child, finds none, exits after ONE iteration. Everything else
    // in the resume path stays live, so what is proven red is the DIRECTION of
    // the chaining, not the surrounding machinery.
    while (block) {
        BRSetAdd(manager->blocks, block);
        manager->lastBlock = block;
        orphan.prevBlock = block->prevBlock;
        BRSetRemove(manager->orphans, &orphan);
        orphan.prevBlock = block->blockHash;
        block = BRSetGet(manager->orphans, &orphan);
    }
#else
    if (block) {
        BRSet *savedByHash = BRSetNew(BRMerkleBlockHash, BRMerkleBlockEq, blocksCount);

        for (size_t i = 0; blocks && i < blocksCount; i++) BRSetAdd(savedByHash, blocks[i]);

        manager->lastBlock = block;   // the TOP of the run — set ONCE, not per step
                                      // (the forward loop's per-iteration assignment
                                      // ended on the highest block; walking down, that
                                      // is where we START, so it must not be re-assigned)

        // Bounded by blocksCount: a corrupt saved blob whose prevBlock links form a
        // cycle can never spin here, and the BRSetContains check stops the walk the
        // moment it would revisit a header already made resident.
        for (size_t i = 0; block && i < blocksCount; i++) {
            _BRPeerManagerInstallSavedBlock(manager, block);
            orphan.prevBlock = block->prevBlock;
            BRMerkleBlock *dropped = BRSetRemove(manager->orphans, &orphan);
            if (dropped && dropped != block) BRSetAdd(manager->orphans, dropped);   // a sibling: keep it owned
            block = BRSetGet(savedByHash, &block->prevBlock);
            if (block) {
                BRMerkleBlock *resident = BRSetGet(manager->blocks, block);
#ifdef RESUME_CHECKPOINT_STUB_UNFIXED
                if (resident) block = NULL;
#else
                BRMerkleBlock *checkpoint = BRSetGet(manager->checkpoints, block);
                if (resident && resident != checkpoint) block = NULL;
#endif
            }

        }

        BRSetFree(savedByHash);
    }
#endif  // RESUME_FLOOR_UNFIXED

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

#if CF_LEDGER_DRIVE_REREQUEST
// Resolve N heights to block hashes in ONE descent from lastBlock. Equivalent to
// calling _BRPeerManagerBlockHashAtHeight for each height, but O(chainLen) once
// instead of O(chainLen)*N. Per-call scratch, no persistent state, correct-by-
// construction from the current chain view. outHashes[i] corresponds to
// heights[i] (UINT256_ZERO if the height is above the tip or not in the
// in-memory window). heights[] may be unsorted and may contain duplicates.
// Caller must hold manager->lock.
//
// A persistent height->hash index was deliberately REJECTED (a stale entry
// would hand getcfilters a wrong stop-hash = silent wrong-range fetch); this
// per-call resolver is correct-by-construction and cannot go stale.
static void _BRPeerManagerResolveHashesAtHeightsLocked(BRPeerManager *manager,
                                                       const uint32_t *heights, size_t n,
                                                       UInt256 *outHashes)
{
    if (n == 0 || heights == NULL || outHashes == NULL) return;

    // Default every slot to ZERO up front: an early return (malloc failure) or a
    // height that never matches leaves the clean "not found" sentinel, not garbage.
    for (size_t i = 0; i < n; i++) outHashes[i] = UINT256_ZERO;

    // Per-call scratch of (height, originalIndex) pairs. No persistent state, so
    // a reorg between ticks can never resurface a stale hash. n is bounded by the
    // residual tick's CF_REREQ_BATCH_PER_TICK-derived range count, but malloc/free
    // per call keeps this correct for any n with no fixed-cap overflow risk.
    typedef struct { uint32_t height; size_t idx; } cfResolveReq;
    cfResolveReq *req = malloc(n * sizeof(*req));
    if (req == NULL) return; // outHashes already all-ZERO -> safe conservative no-op
    for (size_t i = 0; i < n; i++) { req[i].height = heights[i]; req[i].idx = i; }

    // Insertion sort DESCENDING by height. n is small (the CF residual batch) and
    // this O(n^2) sort is independent of chain length, so it is dwarfed by the
    // single O(chainLen) descent below — the whole point of batching.
    for (size_t i = 1; i < n; i++) {
        cfResolveReq key = req[i];
        size_t j = i;
        while (j > 0 && req[j - 1].height < key.height) { req[j] = req[j - 1]; j--; }
        req[j] = key;
    }

    // ONE descent from lastBlock. Because the requested heights are now
    // non-increasing, the walk pointer only ever moves DOWN — each height
    // continues from where the previous (higher) one stopped. `b` is always on
    // lastBlock's prevBlock chain, so continuing is identical to restarting from
    // lastBlock: it reaches exactly the blocks N independent naive walks would,
    // including hitting the SAME severed prevBlock link (-> ZERO) on a gap and
    // NEVER an orphan/fork block off the main chain.
    BRMerkleBlock *b = manager->lastBlock;
    for (size_t k = 0; k < n; k++) {
        uint32_t h = req[k].height;
        while (b && b->height > h) b = BRSetGet(manager->blocks, &b->prevBlock);
        if (b && b->height == h) outHashes[req[k].idx] = b->blockHash;
        // else: leave the pre-set UINT256_ZERO (above tip, off the bottom, or a
        // severed link) — byte-identical to what _BRPeerManagerBlockHashAtHeight
        // returns for that height.
    }

    free(req);
}
#endif // CF_LEDGER_DRIVE_REREQUEST

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
            BRPeerDisconnectTagged(p, BR_DISC_TAG_CF_STALL);
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
#define CF_HEADERS_REQUEST_TIMEOUT_SECS 5
// Tor circuits are slow to establish and high-latency; a 5s timeout mis-punishes
// a good-but-slow filter peer, churning peer rotation and forcing expensive
// circuit re-dials that push our thin fleet toward a 0-peer wedge. Widen the CF
// request timeout while a SOCKS proxy (Tor) is active. (R4, Neutrino review.)
#define CF_HEADERS_REQUEST_TIMEOUT_TOR_SECS 20
#define CF_REQUEST_TIMEOUT_SECS() (BRPeerHasSocksProxy() ? CF_HEADERS_REQUEST_TIMEOUT_TOR_SECS : CF_HEADERS_REQUEST_TIMEOUT_SECS)

// PACED-CONVOY GATE, getcfheaders half (spec Part A). `isConvoyAdvance` is
// supplied per CALL SITE — this function serves both roles and the classification
// is NOT re-derivable from inside it:
//   isConvoyAdvance = 1 (GATEABLE, races the tip):
//     * continuation on a clean cfheaders append (_peerRelayedCFHeaders)
//     * the block-extend kick in _peerRelayedBlock
//   isConvoyAdvance = 0 (NEVER gated — suppressing one wedges sync forever):
//     * sync-start on filter-capable peer connect (_BRPeerManagerOnFilterCapablePeerConnected)
//     * floor re-anchor recovery (_BRPeerManagerReanchorAtFloorLocked)
// Two more never-gated paths are structural rather than call-site-tagged: the
// TIMEOUT RETRY is a branch INSIDE this function (isTimeoutRetry below, excluded
// from the gate condition), and the CONTINUITY PROBE sends via
// _BRPeerManagerProbeOtherFilterPeersForCFHeaders -> BRPeerSendGetCFHeaders
// directly, never through here.
static void _BRPeerManagerRequestNextCFHeaders(BRPeerManager *manager, BRPeer *peer, int isConvoyAdvance)
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
        // height H, deferring" forever.
        //
        // ⚠️ THE OLD RATIONALE HERE WAS FALSE AND IS CORRECTED (paced-convoy C-1).
        // It read: "The floor is <= the wallet's birth height (the header chain
        // anchors at the last checkpoint at/before wallet birth), so this never skips
        // a wallet transaction." That holds only on a FRESH sync. On a RESUME the
        // header chain anchors just under the SAVED TIP, not at a checkpoint
        // (BRPeerManagerNewEx makes only the persisted
        // [savedTip-(SAVE_BLOCK_COUNT-1) .. savedTip] run resident) — the floor is then far ABOVE the wallet's
        // birth height and this snap DOES skip history. A stale rationale on a safety
        // guard is how the guard gets deleted later by someone who believes it, so:
        // the snap still happens, but the skipped band is now SURFACED below.
        // (Fix wave R2 moved that resume floor down to savedTip-(SAVE_BLOCK_COUNT-1);
        // it is still far above a deep-restore birth height, so nothing here changes.)
        uint32_t floor = _BRPeerManagerBlockFloor(manager);
        if (floor > next) {
            uint32_t lowestBefore = _cfConvoyScanArmed(manager)
                                    ? BRCFScanLedgerLowestNeededHeight(&manager->cfLedger) : 0;
            if (lowestBefore > 0 && lowestBefore < floor) {
                _BRPeerManagerSurfaceUnscannableLocked(manager, lowestBefore, floor,
                                                       "cfheaders floor mismatch");
                return;
            }

            uint32_t restart = (lowestBefore > floor) ? lowestBefore : floor;
            peer_log(peer, "cfheaders: rebuilding filter chain at recoverable scan frontier %u "
                     "(block floor %u)", restart, floor);
            if (manager->compactFilterChain) {
                BRCompactFilterChainFree(manager->compactFilterChain);
                manager->compactFilterChain = NULL;
            }
            manager->autoFetchCFiltersEnabled  = 1;
            manager->autoFetchCFiltersStart    = restart;
            manager->autoFetchCFiltersThrough  = restart > 0 ? restart - 1 : 0;
            BRCFScanLedgerInit(&manager->cfLedger, restart);
            _BRPeerManagerClearSolicitedBlocksLocked(manager); // C1: in-flight solicitations belong to the scan just replaced
#if CF_LEDGER_DRIVE_REREQUEST
            BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
            manager->cfHeadersRequestedThrough = 0;
            next     = restart;
            batchEnd = next + (MAX_CFHEADERS_RESULTS - 1);
            if (batchEnd > tip) batchEnd = tip;
            stopHash = _BRPeerManagerBlockHashAtHeight(manager, batchEnd);
        }
        if (UInt256IsZero(stopHash)) {
            peer_log(peer, "cfheaders: no block hash for height %u, deferring", batchEnd);
            return;
        }
    }

    // ---- PACED-CONVOY GATE (spec Part A) -----------------------------------
    // Deliberately placed BELOW the isTimeoutRetry determination and BELOW the
    // floor-snap/re-anchor branch above, so neither recovery path is ever
    // suppressed:
    //   * a TIMEOUT RETRY is excluded explicitly (`! isTimeoutRetry`) — the
    //     previous request went unanswered, so re-sending it is recovery, not an
    //     advance;
    //   * a FLOOR SNAP has already run by this point and freed compactFilterChain,
    //     which opens the window predicate via the NULL-chain carve-out, so the
    //     re-anchored request continues out on this same pass.
    // Suppressing here (rather than at BRPeerSendGetCFHeaders) also leaves
    // cfHeadersRequestedThrough / cfHeadersRequestTime untouched, so a held
    // advance records no phantom in-flight batch and the next tick re-evaluates
    // cleanly. The KeepAlive convoy driver re-issues the advance once the scan
    // frontier climbs back inside the window.
    if (isConvoyAdvance && ! isTimeoutRetry && CF_CONVOY_CFH_GATED(manager)) {
        return;
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

// Task 4 (cfcheckpt-active-rejection) — close the single-peer-liar hole. Both
// re-anchor triggers below (the K-distinct-disagreers quorum path and the
// single-peer escape hatch) exist to recover when OUR chain is the divergent
// outlier. But if a pinned mainnet filter-header checkpoint falls at or below
// the contested height AND our own committed chain's header there matches the
// pin exactly, our chain is independently proven correct at that point — a
// disagreeing peer (quorum or lone) is the one that's wrong, whether lying or
// stuck on a fork. Vetoing the re-anchor there closes the hole where a single
// lying peer (CF_SINGLE_PEER_REANCHOR_ROUNDS consecutive diverged rounds)
// could otherwise force the wallet off a checkpoint-confirmed chain and onto
// its fork. Returns 0 (do not veto — proceed with the re-anchor) whenever the
// checkpoint can't vouch for us: mainnet-only, no checkpoint at/below
// `contested`, chain not yet resident that far, or our own header there
// simply doesn't match (i.e. WE are the ones off the confirmed chain, and
// re-anchoring away is the correct call). Caller must hold manager->lock.
static int _BRPeerManagerCheckpointConfirmsOurChainLocked(BRPeerManager *manager, uint32_t contested)
{
    if (manager->params->standardPort != BRMainNetParams.standardPort) return 0;
#ifndef CF_VETO_TIP_UNFIXED
    // Checkpoints vouch only for the historical region up to the top pin; above it
    // (the tip region) they say nothing, so a tip-region divergence must fall through
    // to the quorum path (design Piece 2). Without this, a historical checkpoint match
    // vetoes a legitimate tip re-anchor and bans honest peers — the near-tip wedge.
    if (contested > BRCFTopCheckpointHeight()) return 0;
#endif
    const BRCFCheckpoint *cp = BRCFHighestCheckpointAtOrBelow(contested);
    if (! cp) return 0;
    if (BRCompactFilterChainCount(manager->compactFilterChain) == 0) return 0;
    if (BRCompactFilterChainStartHeight(manager->compactFilterChain) > cp->height) return 0;
    return UInt256Eq(BRCompactFilterChainHeader(manager->compactFilterChain, cp->height),
                     cp->filterHeader);
}

// --- BIP 158 peer callbacks -----------------------------------------------

static void _peerRelayedCFHeaders(void *info, uint8_t filterType, UInt256 stopHash,
                                  UInt256 prevFilterHeader,
                                  const UInt256 *filterHashes, size_t count)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

    MGR_LOCK(manager);

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
                MGR_UNLOCK(manager);
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
        MGR_UNLOCK(manager);
        return;
    }

    // Task 3 (cfcheckpt-active-rejection) — PRE-COMMIT checkpoint enforcement.
    // Before this batch is allowed to touch the chain at all, fold it forward
    // (without mutating anything — BRCompactFilterChainBatchViolatesCheckpoint
    // is pure) and compare against any pinned mainnet filter-header checkpoint
    // that falls inside it. A mismatch means this peer is either lying or
    // stuck on a divergent fork; reject the whole batch, ban the peer, and
    // leave cfHeadersRequestedThrough untouched so the existing "no advance"
    // continuity path re-requests it from someone else. Mainnet-only — the
    // checkpoint table is DGB mainnet filter-headers; testnet26 has none.
    // Guarded behind CF_CHECKPOINT_ENFORCE_UNFIXED so the red arm of
    // cf_checkpoint_enforce_kat can restore the pre-Task-3 observe-only shape
    // (append-then-log) and prove the gate is load-bearing.
#ifndef CF_CHECKPOINT_ENFORCE_UNFIXED
    if (manager->params->standardPort == BRMainNetParams.standardPort) {
        uint32_t vh; UInt256 vc;
        if (BRCompactFilterChainBatchViolatesCheckpoint(manager->compactFilterChain,
                filterHashes, count, &vh, &vc)) {
            const BRCFCheckpoint *pinned = BRCFHighestCheckpointAtOrBelow(vh);
            peer_log(peer, "cf-checkpoint: height %u *** ENFORCE REJECT *** computed=%s pinned=%s",
                     vh, log_u256_hex_encode(vc),
                     pinned ? log_u256_hex_encode(pinned->filterHeader) : "?");
            _BRPeerManagerPeerMisbehavin(manager, peer);   // crypto-proof ban
            manager->cfHeadersRequestedThrough = 0;  // let another (honest) peer be tried immediately
            // Do NOT append, do NOT advance cfHeadersRequestedThrough — the
            // existing "no advance" path (see the !ok branch below) re-requests
            // on the next driver tick via a fresh peer.
            MGR_UNLOCK(manager);
            return;
        }
    }
#endif

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
                // Separate calls, and this is safe even though both compute a hex
                // string for the same peer_log() format: log_u256_hex_encode is a
                // compound-literal macro (BRInt.h ((const char[]){…})), so each
                // expansion produces its own distinct block-scoped array — no
                // shared/static buffer to alias between the two calls below.
                peer_log(peer, "cf-checkpoint: height %u *** MISMATCH (observe) *** computed=%s",
                         h, log_u256_hex_encode(computed));
                peer_log(peer, "cf-checkpoint: height %u *** MISMATCH (observe) *** pinned=%s",
                         h, log_u256_hex_encode(BRMainNetCFCheckpoints[ci].filterHeader));
            }
        }
    }

    if (!ok) {
        // Task 4 (cfcheckpt-active-rejection) — the height the divergent batch
        // would have written had it appended. The append above failed, so
        // manager->compactFilterChain is untouched and NextHeight is still the
        // base this (and every subsequent, same-round) contested batch tries to
        // extend; stable for the rest of this !ok block since nothing here
        // mutates the chain. Used by both re-anchor gates below.
        uint32_t contestedHeight = BRCompactFilterChainNextHeight(manager->compactFilterChain);

        // Record this peer as one that disagrees with our tip (dedup by address),
        // alongside the prevFilterHeader IT claims (Task 5: the quorum decision
        // below needs to know whether disagreers describe the SAME alternate
        // chain or are just independent noise). Do NOT mark it misbehavin'/
        // disconnect here — if a genuine majority disagrees, the honest peers
        // are right and OUR chain is the divergent outlier.
        int _known = 0;
        for (uint8_t i = 0; i < manager->cfDisagreedCount; i++) {
            if (UInt128Eq(manager->cfDisagreedPeers[i], peer->address)) { _known = 1; break; }
        }
        if (!_known && manager->cfDisagreedCount < CF_DISAGREED_CAP) {
            manager->cfDisagreedPrev[manager->cfDisagreedCount] = prevFilterHeader;
            manager->cfDisagreedPeers[manager->cfDisagreedCount++] = peer->address;
        }
        manager->cfHeadersRequestedThrough = 0;  // let another peer be tried

        // Below the collection cap: actively probe the OTHER filter peers about
        // this same contested batch so distinct disagreers accumulate toward the
        // quorum floor.
        //
        // Re-fire on EVERY mismatch while below the cap — not only on the first
        // (fresh add). The disagreeing peer is usually the priority peer
        // (digiscope.me), which connects first; the seeder's other filter peers
        // finish their handshake a few seconds LATER. A one-shot probe (gated on
        // the fresh add) therefore loops over a peer list that holds no other
        // filter peer yet, reaches nobody, and the count wedges short of the
        // floor until an unrelated rescan resets it ~tens of minutes on.
        // Re-probing each round catches those peers the moment they connect. The
        // probe skips peers already in the disagreed set and we only reach here
        // once per cfheaders round-trip (the request is serialized), so it can't
        // storm. Capped on CF_DISAGREED_CAP (not the old K) so probing keeps
        // running until CF_CONTINUITY_REANCHOR_FLOOR agreeing disagreers can
        // actually be collected — capping this at the old K==2 would silently
        // wedge collection two short of a 3-agreeing-disagreer floor, recreating
        // the exact "count wedges" failure mode this comment describes, just one
        // threshold higher.
        if (manager->cfDisagreedCount < CF_DISAGREED_CAP) {
            _BRPeerManagerProbeOtherFilterPeersForCFHeaders(manager, peer, filterType,
                                                            BRCompactFilterChainNextHeight(manager->compactFilterChain),
                                                            stopHash);
        }

        // Task 5 (cfcheckpt-active-rejection) — quorum-reliability. The old
        // trigger was "CF_CONTINUITY_REANCHOR_K distinct disagreers, any
        // complaint" — two peers with UNRELATED complaints (different claimed
        // prevFilterHeader, i.e. independent transients rather than a coherent
        // alternate chain) could force a re-anchor. Replace it with "a strict
        // majority of connected filter peers AND >= CF_CONTINUITY_REANCHOR_FLOOR
        // distinct disagreers that agree with EACH OTHER on the claimed
        // prevFilterHeader": compute the plurality prevFilterHeader among the
        // stored disagreers (O(N^2) over N <= CF_DISAGREED_CAP ==
        // PEER_MAX_CONNECTIONS (8), trivial — 64 comparisons worst case) and
        // require the largest agreeing bucket to clear both the floor and a
        // majority of the currently connected filter-peer population.
        //
        // CF_DISAGREED_CAP is sized to the FULL connected-peer pool (not just
        // CF_CONTINUITY_REANCHOR_FLOOR) precisely so this majority half stays
        // satisfiable at healthy fleet size: since bestAgree <= cfDisagreedCount
        // <= CF_DISAGREED_CAP, capping storage at the floor (3) would make
        // "bestAgree > connected/2" structurally impossible the moment >=6
        // filter peers are connected (3 can never exceed 6/2==3), even when a
        // real majority of 6-8 honest peers coherently disagrees — see
        // BRPeerManager.h's CF_DISAGREED_CAP comment.
#ifndef CF_QUORUM_UNFIXED
        uint8_t bestAgree = 0;
        for (uint8_t i = 0; i < manager->cfDisagreedCount; i++) {
            uint8_t agree = 0;
            for (uint8_t j = 0; j < manager->cfDisagreedCount; j++) {
                if (UInt256Eq(manager->cfDisagreedPrev[i], manager->cfDisagreedPrev[j])) agree++;
            }
            if (agree > bestAgree) bestAgree = agree;
        }
        int quorumMet = (bestAgree >= CF_CONTINUITY_REANCHOR_FLOOR) &&
                        (bestAgree > _BRPeerManagerConnectedFilterPeerCount(manager) / 2);
#else
        // Red KAT arm only: restores the pre-Task-5 "K distinct disagreers,
        // any complaint" trigger — CF_CONTINUITY_REANCHOR_FLOOR does not exist
        // in this arm, so the decision cannot reference it.
        int quorumMet = (manager->cfDisagreedCount >= CF_CONTINUITY_REANCHOR_K);
#endif

        if (quorumMet &&
            manager->cfReanchorCount < CF_CONTINUITY_REANCHOR_MAX) {
#ifndef CF_CHECKPOINT_VETO_UNFIXED
            // Task 4 — a checkpoint-confirmed chain vetoes the re-anchor. The
            // quorum above is normally trustworthy, but if our own chain is
            // independently proven correct at the contested height by a pinned
            // checkpoint, the "quorum" is itself wrong (colluding or
            // coincidentally all stuck on the same fork) — do not throw away
            // confirmed history for it. Ban the disagreeing peer instead.
            if (_BRPeerManagerCheckpointConfirmsOurChainLocked(manager, contestedHeight)) {
                peer_log(peer, "cf-checkpoint: re-anchor VETOED (quorum path, %u disagreers) — "
                         "our chain is checkpoint-confirmed at/below height %u",
                         manager->cfDisagreedCount, contestedHeight);
                _BRPeerManagerPeerMisbehavin(manager, peer);  // the disagreeing peer is the liar
                MGR_UNLOCK(manager);
                return;
            }
#endif
            manager->cfReanchorCount++;
            peer_log(peer, "cfheaders: %u peers disagree with our tip — chain is the outlier, "
                     "re-anchoring (attempt %u/%u)",
                     manager->cfDisagreedCount, manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
            _BRPeerManagerReanchorAtFloorLocked(manager, 1);
            MGR_UNLOCK(manager);
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
#ifndef CF_CHECKPOINT_VETO_UNFIXED
                // Task 4 — close the single-peer-liar hole. Without this, one
                // lying (or fork-stuck) lone peer can run out the clock on
                // CF_SINGLE_PEER_REANCHOR_ROUNDS and force the wallet to tear
                // down and re-anchor a chain that a pinned checkpoint has
                // already independently confirmed as correct.
                if (_BRPeerManagerCheckpointConfirmsOurChainLocked(manager, contestedHeight)) {
                    peer_log(peer, "cf-checkpoint: re-anchor VETOED (single-peer escape hatch, "
                             "%u rounds) — our chain is checkpoint-confirmed at/below height %u",
                             manager->cfSingleDisagreeRounds, contestedHeight);
                    _BRPeerManagerPeerMisbehavin(manager, peer);  // the lone disagreer is the liar
                    MGR_UNLOCK(manager);
                    return;
                }
#endif
                manager->cfReanchorCount++;
                peer_log(peer, "cfheaders: single filter peer, %u rounds diverged — "
                         "forcing re-anchor (attempt %u/%u)",
                         manager->cfSingleDisagreeRounds,
                         manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
                _BRPeerManagerReanchorAtFloorLocked(manager, 1);
                MGR_UNLOCK(manager);
                return;
            }
        } else {
            manager->cfSingleDisagreeRounds = 0;  // 2nd filter peer present → prefer K=2 path
        }

        // Below the quorum, or re-anchor budget exhausted: don't append and
        // don't punish (the below-quorum case may still recover as more
        // agreeing peers arrive — acting on it here would false-alarm).
#ifndef CF_NEVERBRICK_UNFIXED
        // NEVER-BRICK (Task 6, cfcheckpt-active-rejection). Once the re-anchor
        // budget is truly EXHAUSTED (cfReanchorCount >= CF_CONTINUITY_REANCHOR_MAX),
        // no further re-anchor can EVER fire again for this manager — both gates
        // above are `cfReanchorCount < CF_CONTINUITY_REANCHOR_MAX` — so unlike the
        // below-quorum case there is nothing left to wait for; act on the very
        // first mismatch that reaches here once exhausted, whatever the quorum
        // state happens to be that round. Silently stopping used to be excused by
        // "the SyncService watchdog falls back to bloom" — that fallback no longer
        // exists (bloom/BIP37 was fully excised in v4.0.0), so a silent stop here
        // is a permanent brick: no data path is left to catch what the CF chain can
        // no longer verify. Park the forward-fetch cursor at the nearest TRUSTED
        // mainnet checkpoint instead — a compiled-in table value, never anything a
        // peer supplied in this batch — and surface the unverifiable band through
        // the same abandonedBelow funnel every other unscannable-band site uses, so
        // "Scan for missing transactions" becomes reachable instead of the wallet
        // spinning on "Syncing" forever. Mainnet-only (the checkpoint table is DGB
        // mainnet filter-headers; testnet26 has none).
        if (manager->cfReanchorCount >= CF_CONTINUITY_REANCHOR_MAX &&
            manager->params->standardPort == BRMainNetParams.standardPort) {
            uint32_t tip = manager->compactFilterChain
                          ? BRCompactFilterChainNextHeight(manager->compactFilterChain) - 1 : 0;
            const BRCFCheckpoint *cp = BRCFHighestCheckpointAtOrBelow(tip);
            if (cp) {
                // THE REAL resume cursor. Every forward-fetch request site computes
                // reqStart = autoFetchCFiltersThrough + 1, clamped UP to
                // autoFetchCFiltersStart (see :4280-4281 and the residual driver at
                // :5969-5970) — Through, not Start, is what actually governs where
                // the next fetch resumes. Setting only autoFetchCFiltersStart (a
                // literal reading of this task's brief pseudocode) would be a NO-OP
                // here: Through already sits at/above the checkpoint height from the
                // header chain's own prior advance, so max(Through+1, Start) would
                // still resolve to that old, unverified value. Snap BOTH — same
                // idiom every other "park the cursor at X" site in this file uses
                // (_BRPeerManagerReanchorAtFloorLocked, the C-1 snap-down in
                // BRPeerManagerSnapAutoFetchThroughToScanFrontier, the abandon-band
                // snap at :7407-7408): Start=X, Through=X-1, so reqStart resolves to
                // exactly X on the next cycle — pinned to the checkpoint table, never
                // a peer-supplied value.
                manager->autoFetchCFiltersStart   = cp->height;
                manager->autoFetchCFiltersThrough = (cp->height > 0) ? cp->height - 1 : 0;

                // Parking the cursor above IS the anti-brick action: the next cycle
                // re-fetches from a checkpoint-pinned height, so progress resumes. Whether
                // to ALSO abandon the band is a separate and much heavier question, because
                // abandoning marks those heights permanently unscannable (abandonedBelow is
                // monotonic) and raises a user-facing "history gap" that no rescan can clear.
                //
                // Shipped in v4.0.41 with no quorum gate at all — "act on the very first
                // mismatch that reaches here once exhausted, whatever the quorum state" —
                // which is wrong. Measured 2026-08-21 on a wallet ~6h into a session:
                //
                //   continuity mismatch (1/8 disagreers collected, reanchors 3/3)
                //   ABANDONED 20273 height(s) [24050000..24070272]
                //
                // ONE peer out of eight disagreed, and 20k heights were condemned. The
                // re-anchor budget is never reset, so any long session eventually spends it
                // on ordinary tip churn; after that a single disagreeing peer — routine
                // noise at the tip, where a reorg is often in flight — was enough.
                //
                // Require the SAME corroboration the re-anchor itself requires: a largest
                // agreeing bucket that clears CF_CONTINUITY_REANCHOR_FLOOR and a majority of
                // connected filter peers. A lone disagreer no longer condemns anything; it
                // just costs a re-fetch from the checkpoint.
                // Guarded so cf_checkpoint_neverbrick_kat's red arm
                // (-DCF_NEVERBRICK_QUORUM_UNFIXED) can restore the ungated v4.0.41 shape and
                // prove this corroboration check is load-bearing. Without a dedicated guard
                // the only red arm available removes Task 6 wholesale, which cannot
                // distinguish "no never-brick" from "never-brick without a quorum gate" —
                // and it is exactly that missing distinction which shipped the field bug.
#ifdef CF_NEVERBRICK_QUORUM_UNFIXED
                int nbCorroborated = 1;   // v4.0.41: act on ANY mismatch once exhausted
                (void)0;
#else
                uint8_t nbBestAgree = 0;
                for (uint8_t i = 0; i < manager->cfDisagreedCount; i++) {
                    uint8_t agree = 0;
                    for (uint8_t j = 0; j < manager->cfDisagreedCount; j++) {
                        if (UInt256Eq(manager->cfDisagreedPrev[i], manager->cfDisagreedPrev[j])) agree++;
                    }
                    if (agree > nbBestAgree) nbBestAgree = agree;
                }
                size_t nbFilterPeers = _BRPeerManagerConnectedFilterPeerCount(manager);
                int nbCorroborated = (nbBestAgree >= CF_NEVERBRICK_CORROBORATION_FLOOR) &&
                                     (nbFilterPeers > 0) &&
                                     ((size_t)nbBestAgree * 2 > nbFilterPeers);
#endif
                if (nbCorroborated) {
                    _BRPeerManagerSurfaceUnscannableLocked(manager, cp->height, tip + 1,
                        "filter-header chain could not be verified against checkpoints");
                } else {
#ifndef CF_NEVERBRICK_QUORUM_UNFIXED
                    peer_log(peer, "cf-checkpoint: parked fetch at trusted checkpoint %u "
                             "(reanchors exhausted); NOT abandoning — only %u/%zu filter peers "
                             "corroborate the divergence",
                             cp->height, nbBestAgree, nbFilterPeers);
#endif
                }
            }
            // cp == NULL means tip sits below the lowest pinned checkpoint — no
            // trusted anchor exists yet to park at; fall through to the log below
            // with no action (unreachable in practice: the lowest checkpoint is
            // height 50000, far below any wallet birth height that could reach
            // three exhausted re-anchor attempts).
        }
#endif
        peer_log(peer, "cfheaders: continuity mismatch (%u/%u disagreers collected, reanchors %u/%u) — not appending",
                 manager->cfDisagreedCount, CF_DISAGREED_CAP,
                 manager->cfReanchorCount, CF_CONTINUITY_REANCHOR_MAX);
        MGR_UNLOCK(manager);
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
    _BRPeerManagerPersistCFLedgerLocked(manager);

    // Auto-fetch cfilters for the newly validated range, capped at the spec
    // MAX_CFILTERS_RESULTS. The driver requests one batch per cfheaders
    // arrival; consecutive cfheaders responses advance the cursor through
    // the chain until it catches up to the block tip.
    //
    // Phase 2 back-pressure: once the ledger's outstanding set reaches
    // CF_OUTSTANDING_LOWWATER, pause forward auto-fetch so a stalled/slow
    // filter peer can't keep growing outstanding toward CF_OUTSTANDING_MAX
    // (which would start silently evicting the oldest holes). The residual
    // re-request driver (BRPeerManagerKeepAlive) keeps working the existing
    // backlog down in the meantime.
    if (manager->autoFetchCFiltersEnabled
#if CF_LEDGER_DRIVE_REREQUEST
        && _cfForwardFetchAllowed(manager)
#endif
        ) {
        uint32_t reqStart = manager->autoFetchCFiltersThrough + 1;
        if (reqStart < manager->autoFetchCFiltersStart) reqStart = manager->autoFetchCFiltersStart;
        if (reqStart <= chainTip) {
            uint32_t reqStop = chainTip;
            if (reqStop > reqStart + (MAX_CFILTERS_RESULTS - 1)) {
                reqStop = reqStart + (MAX_CFILTERS_RESULTS - 1);
            }
            size_t n = _BRPeerManagerRequestCFiltersLocked(manager, reqStart, reqStop, peer);
            if (n > 0) {
                manager->autoFetchCFiltersThrough = reqStop;
#if CF_LEDGER_DRIVE_REREQUEST
                // Never silent about CF_OUTSTANDING_MAX overflow (Phase 2): log the
                // dropped-oldest-holes range so a hole caused by hitting the hard cap
                // is loud instead of a silent missed-scan.
                uint32_t dLo = CF_LEDGER_NO_DROP, dHi = CF_LEDGER_NO_DROP;
                int nDropReq = BRCFScanLedgerRecordRequestedDropped(&manager->cfLedger, reqStart, reqStop,
                                              peer->address, peer->port, (uint32_t)time(NULL), &dLo, &dHi);
                if (nDropReq > 0) {
                    peer_log(peer, "cf-ledger: OUTSTANDING OVERFLOW — dropped %d oldest holes [%u..%u]",
                             nDropReq, dLo, dHi);
                }
#else
                BRCFScanLedgerRecordRequested(&manager->cfLedger, reqStart, reqStop,
                                              peer->address, peer->port, (uint32_t)time(NULL));
#endif
                peer_log(peer, "cfilters: auto-requested [%u..%u] (%zu blocks)",
                         reqStart, reqStop, n);
            }
        }
    }

    // Request the next batch if still behind the local block tip.
    // isConvoyAdvance=1: THE tip-racing cfheaders continuation — this is the
    // self-sustaining loop the convoy paces (a clean append immediately asks for
    // the next 2000). Held when the cfheader frontier is already a full window
    // ahead of the scan; the KeepAlive convoy driver re-fires it.
    _BRPeerManagerRequestNextCFHeaders(manager, peer, /*isConvoyAdvance=*/1);
    // cfheaders advanced — refresh cachedCFTip so the watchdog/overlay see progress
    // between blocks (cfheaders can climb faster than new blocks arrive).
    _BRPeerManagerRefreshCachedStatus(manager);
    MGR_UNLOCK(manager);
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
#ifdef CF_RECV_DIAG
static uint64_t _cfNowNanos(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif

static void _peerRelayedCFilter(void *info, uint8_t filterType, UInt256 blockHash,
                                const uint8_t *encoded, size_t encodedLen)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;

#ifdef CF_RECV_DIAG
    uint64_t _tPre = _cfNowNanos();
#endif
    MGR_LOCK(manager);
#ifdef CF_RECV_DIAG
    {
        uint64_t _tPost = _cfNowNanos();
        manager->cfLockWaitNanos += (_tPost - _tPre);
        if (manager->cfLastArrivalNanos) manager->cfGapNanos += (_tPre - manager->cfLastArrivalNanos);
        manager->cfLastArrivalNanos = _tPre;
        manager->cfTimedSamples++;
    }
    manager->cfRecvTotal++;
#endif
    if (!manager->compactFilterChain ||
        filterType != BRCompactFilterChainType(manager->compactFilterChain)) {
#ifdef CF_RECV_DIAG
        // Previously a wholly SILENT drop — no log, no counter. A filter arriving
        // while the chain is NULL (fresh arm, manager recreate, mid re-anchor) or
        // for a mismatched type vanished without trace.
        manager->cfExitNoChain++;
#endif
        MGR_UNLOCK(manager);
        return;
    }

#ifdef CF_PIN_DIAG
    // ---- ARRIVAL-SIDE DIAGNOSTIC (never a production build) --------------------------
    // The send side is now fully accounted for; what stays dark is the path from "a cfilter
    // arrived" to MarkEvaluated. This tags every filter landing in the PIN's window and
    // names which of the five exits it takes, so a height that is requested, arrives, and
    // still never advances the frontier is no longer invisible.
    uint32_t arrPinH = 0; int arrPinOfferable = 1;
    uint8_t  arrCyc = 0, arrLive = 0;
    int      arrHavePin = BRCFScanLedgerPinningHole(&manager->cfLedger, &arrPinH,
                                                    &arrPinOfferable, &arrCyc, &arrLive);
    int      arrInWindow = 0;   // decided once the height is known (or not)
#endif

    BRMerkleBlock *b = BRSetGet(manager->blocks, &blockHash);

#ifdef CF_PIN_DIAG
    if (arrHavePin) {
        if (b && b->height != BLOCK_UNKNOWN_HEIGHT) {
            arrInWindow = (b->height >= arrPinH && b->height < arrPinH + CF_REREQ_MAX_RANGE);
            if (arrInWindow) {
                debug_log("[CF-ARR] h=%u pin=%u ARRIVED len=%zu — block resolved\n",
                          b->height, arrPinH, encodedLen);
            }
        }
        else {
            // Height unknown: cannot tell if it is the pin's, but this IS the
            // "unknown block, dropping" class, so count it against the pin window.
            debug_log("[CF-ARR] pin=%u ARRIVED but BLOCK UNRESOLVED (hash %s) — buffered/dropped, "
                      "no MarkEvaluated possible\n", arrPinH, log_u256_hex_encode(blockHash));
        }
    }
#endif
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
        if (! BRCFScanLedgerBufferFilter(&manager->cfLedger, blockHash, encoded, encodedLen, (uint32_t)time(NULL))) {
            /* too big / not stored — height stays outstanding for the residual re-request path */
#ifdef CF_RECV_DIAG
            manager->cfExitUnknownDrop++;   /* buffer REFUSED the bytes: they are lost */
#endif
        }
        else {
#ifdef CF_RECV_DIAG
            manager->cfExitUnknownBuf++;    /* held for the buffered-drain path */
#endif
        }
#else
#ifdef CF_RECV_DIAG
        manager->cfExitUnknownDrop++;
#endif
#endif
        MGR_UNLOCK(manager);
        return;
    }

    if (!BRCompactFilterChainVerifyFilter(manager->compactFilterChain, b->height, encoded, encodedLen)) {
#ifdef CF_PIN_DIAG
        if (arrInWindow) debug_log("[CF-ARR] h=%u EXIT=verify_fail (chain mismatch) — no MarkEvaluated\n", b->height);
#endif
        peer_log(peer, "cfilter: filter for block %s does not match chain — misbehavin'",
                 log_u256_hex_encode(blockHash));
        _BRPeerManagerPeerMisbehavin(manager, peer);
        // Observe-only (Phase 1): height left outstanding (not MarkEvaluated).
#ifdef CF_RECV_DIAG
        manager->cfExitVerifyFail++;   /* filter hash != cfheader chain */
#endif
        peer_log(peer, "cf-ledger: hole @ %u reason=verify_fail — left outstanding (scannedThrough=%u, outstanding=%zu)",
                 b->height, BRCFScanLedgerScannedThrough(&manager->cfLedger),
                 BRCFScanLedgerOutstandingCount(&manager->cfLedger));
        MGR_UNLOCK(manager);
        return;
    }

    // The filter verified against the chain — this peer served a valid cfilter
    // (positive CF-served signal), independent of whether it hits our wallet.
    _recordCFServed(manager, peer);

    BRGCSFilter *gcs = BRGCSFilterBasicParse(encoded, encodedLen, blockHash);
    if (!gcs) {
#ifdef CF_PIN_DIAG
        if (arrInWindow) debug_log("[CF-ARR] h=%u EXIT=parse_fail — no MarkEvaluated\n", b->height);
#endif
        peer_log(peer, "cfilter: failed to parse filter for block %s",
                 log_u256_hex_encode(blockHash));
        // Observe-only (Phase 1): height left outstanding (not MarkEvaluated).
#ifdef CF_RECV_DIAG
        manager->cfExitParseFail++;   /* GCS parse failed */
#endif
        peer_log(peer, "cf-ledger: hole @ %u reason=parse_fail — left outstanding (scannedThrough=%u, outstanding=%zu)",
                 b->height, BRCFScanLedgerScannedThrough(&manager->cfLedger),
                 BRCFScanLedgerOutstandingCount(&manager->cfLedger));
        MGR_UNLOCK(manager);
        return;
    }

#ifdef CF_RECV_DIAG
    uint64_t _tEval0 = _cfNowNanos();
#endif
    // CACHED, MANAGER-OWNED. Rebuilding this per filter was ~98.8% of the per-filter
    // cost: a full address-set copy plus two BRAddressScriptPubKey passes over ~645
    // addresses, twice, with two allocations — every arrival. Keyed on
    // (addrGen, addrCount, isTestnet); see _BRPeerManagerFilterElementsLocked.
    // DO NOT FREE: the manager owns it and reuses it across arrivals.
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
    // NOTE: fe is the manager-owned cache — freeing it here would dangle
    // manager->cfElems and the NEXT arrival would use-after-free it.
    BRGCSFilterFree(gcs);
#ifdef CF_RECV_DIAG
    manager->cfEvalNanos += (_cfNowNanos() - _tEval0);
#endif

    if (hit) {
        peer_log(peer, "cfilter: MATCH on block %s @ height %u, requesting full block",
                 log_u256_hex_encode(blockHash), b->height);
        // C1 request-gate: record the solicitation BEFORE the send, so the answer can
        // never race ahead of the record. Only a block in this table may complete a scan
        // height in _peerRelayedBlockTxns.
        _BRPeerManagerRecordSolicitedBlockLocked(manager, blockHash, b->height);
        // Send while holding the lock — matches the pattern used elsewhere
        // in this file (e.g. _BRPeerManagerRequestNextCFHeaders also sends
        // under the lock). The lock guards manager state, not the socket.
        BRPeerSendGetdataBlocks(peer, &blockHash, 1);
    }

    // A clean miss is complete immediately. A match is not: the requested full
    // block still has to be parsed and registered into the wallet, so its height
    // remains outstanding until _peerRelayedBlockTxns.
#ifdef CF_PIN_DIAG
    if (arrInWindow) {
        debug_log("[CF-ARR] h=%u EXIT=evaluated (hit=%d) — scannedThrough before=%u\n",
                  b->height, hit, BRCFScanLedgerScannedThrough(&manager->cfLedger));
    }
#endif
#ifdef CF_RECV_DIAG
    manager->cfExitEvaluated++;   /* the only good outcome */
#endif
    if (!hit) {
        BRCFScanLedgerMarkEvaluated(&manager->cfLedger, b->height);
    }
#ifdef CF_MATCH_MARK_ON_REQUEST_UNFIXED
    else {
        BRCFScanLedgerMarkEvaluated(&manager->cfLedger, b->height);
    }
#else
    else {
        peer_log(peer, "cf-ledger: matched block @ %u left outstanding until full block delivery",
                 b->height);
    }
#endif

    MGR_UNLOCK(manager);
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
    // isConvoyAdvance=0: SYNC-START. This is the only thing that gets cfheaders
    // moving when a filter-capable peer connects (including the first peer of a
    // fresh restore, and the first filter peer after a fleet-wide drop). Gating
    // it would leave the convoy with no starter — a permanent 0-progress wedge.
    _BRPeerManagerRequestNextCFHeaders(manager, peer, /*isConvoyAdvance=*/0);
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
    MGR_LOCK(manager);
    manager->maxConnectCount = UInt128IsZero(address) ? PEER_MAX_CONNECTIONS : 1;
    manager->fixedPeer = ((BRPeer) { address, port, 0, 0, 0 });
    array_clear(manager->peers);
    MGR_UNLOCK(manager);
}

// Dynamically set the target connection count (demand-side load-spread): the wallet holds the
// full PEER_MAX_CONNECTIONS while CATCHING UP (fast sync + wedge buffer), then drops to a small
// count once SYNCED so thousands of idle wallets stop each pinning 8 slots on the shared
// filter-node fleet. Reducing gently schedule-disconnects the excess via the SAME async path
// idle-eviction uses (BRPeerScheduleDisconnect) — NEVER the download peer (it drives the sync)
// or the pinned own-node. maxConnectCount then gates re-dials so the reduced set is maintained.
// Every application also repairs an underfilled pool, even when the target itself is unchanged.
void BRPeerManagerSetMaxConnectCount(BRPeerManager *manager, size_t count)
{
    assert(manager != NULL);
    if (count < 1) count = 1;
    MGR_LOCK(manager);
    size_t prev = manager->maxConnectCount;
    manager->maxConnectCount = count;
    int needsTopUp = BRPeerManagerNeedsTopUp(prev, count, array_count(manager->connectedPeers));
    if (count < prev) {
        size_t keeping = array_count(manager->connectedPeers);
        for (size_t i = array_count(manager->connectedPeers); i > 0 && keeping > count; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            if (p == manager->downloadPeer) continue;                 // keep the sync driver
            if (BRPeerIsPinned(manager->pinnedAddr, manager->pinnedPort,
                               p->address, p->port)) continue;        // keep the pinned own-node
            if (BRPeerConnectStatus(p) == BRPeerStatusDisconnected) continue;
            BRPeerScheduleDisconnectTagged(p, 0, BR_DISC_TAG_MAXCONN_TRIM);
            keeping--;
        }
    }
    MGR_UNLOCK(manager);
    if (needsTopUp) BRPeerManagerConnect(manager);                    // maintain the requested target
}

// current connect status
BRPeerStatus BRPeerManagerConnectStatus(BRPeerManager *manager)
{
    BRPeerStatus status = BRPeerStatusDisconnected;
    
    assert(manager != NULL);
    MGR_LOCK(manager);
    if (manager->isConnected != 0) status = BRPeerStatusConnected;

    for (size_t i = array_count(manager->connectedPeers); i > 0 && status == BRPeerStatusDisconnected; i--) {
        if (BRPeerConnectStatus(manager->connectedPeers[i - 1]) == BRPeerStatusDisconnected) continue;
        status = BRPeerStatusConnecting;
    }

    MGR_UNLOCK(manager);
    return status;
}

// Pin a user-paired own-node as a reserved, never-churn-evicted CF peer. exclusive
// != 0 makes the dialer contact ONLY this node. Takes manager->lock itself (the JNI
// caller holds the separate PEER_GUARD, not this lock). port == 0 clears the pin.
void BRPeerManagerSetPinnedPeer(BRPeerManager *manager, UInt128 addr, uint16_t port, int exclusive)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->pinnedAddr = addr;
    manager->pinnedPort = port;
    manager->pinnedExclusive = exclusive ? 1 : 0;
    MGR_UNLOCK(manager);
}

// Clear any pinned own-node (reverts to normal dial/eviction behavior). Takes
// manager->lock itself.
void BRPeerManagerClearPinnedPeer(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->pinnedAddr = UINT128_ZERO;
    manager->pinnedPort = 0;
    manager->pinnedExclusive = 0;
    MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);
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
    MGR_UNLOCK(manager);
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
        MGR_UNLOCK(manager);
        _peerDisconnected(info, ENOTCONN);
        MGR_LOCK(manager);
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
    MGR_LOCK(manager);
    if (manager->connectFailureCount >= MAX_CONNECT_FAILURES) manager->connectFailureCount = 0; //this is a manual retry
    
    if ((! manager->downloadPeer || manager->lastBlock->height < manager->estimatedHeight) &&
        manager->syncStartHeight == 0) {
        manager->syncStartHeight = manager->lastBlock->height + 1;
        MGR_UNLOCK(manager);
        if (manager->syncStarted) manager->syncStarted(manager->info);
        MGR_LOCK(manager);
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
                // Render IPv4 and IPv6 candidates CORRECTLY. This printed
                // address.u32[3] as four octets unconditionally, so every NATIVE IPv6
                // peer showed as its interface-identifier tail — commonly "0.0.0.1".
                // Ten distinct IPv6 peers rendered as that same string, which reads like
                // one malformed entry being dialled hundreds of times; it sent a whole
                // investigation after a peer that did not exist (2026-08-02, Note 8).
                //
                // Formatted from a LOCAL copy, never peer_log()/BRPeerHost() on a bare
                // manager->peers element: BRPeerHost casts to BRPeerContext* and writes
                // into ctx->host, which on a bare BRPeer lands in the NEXT array slot and
                // corrupts peers[k+1]'s address.
                {
                    const UInt128 a = manager->peers[k].address;
                    const uint16_t prt = manager->peers[k].port;
                    if (a.u64[0] == 0 && a.u16[4] == 0 && a.u16[5] == 0xffff) {
                        const uint8_t *ip = (const uint8_t *)&a.u32[3];
                        _peer_log("%u.%u.%u.%u:%"PRIu16" BIP158: connecting filter-capable peer first\n",
                                  ip[0], ip[1], ip[2], ip[3], prt);
                    }
                    else {
                        char h[INET6_ADDRSTRLEN] = "";
                        inet_ntop(AF_INET6, &a, h, sizeof(h));
                        _peer_log("[%s]:%"PRIu16" BIP158: connecting filter-capable peer first\n",
                                  h[0] ? h : "?", prt);
                    }
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
                    MGR_UNLOCK(manager);
                    _peerDisconnected(info, ENOTCONN);
                    MGR_LOCK(manager);
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
        MGR_UNLOCK(manager);
        if (manager->syncStopped) manager->syncStopped(manager->info, ENETUNREACH);
    }
    else MGR_UNLOCK(manager);
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
// actually credits the receive. Marking the height evaluated before the full
// block is delivered would silently lose a payment if the process dies after
// getdata. A hit with no CF-capable peer connected KEEPS the entry buffered
// (returns 0, not 1) so the very next drive tick retries instead of the payment
// being lost. Like the live match path, a dispatched hit stays outstanding
// until _peerRelayedBlockTxns has parsed and registered the full block.
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
        _BRPeerManagerRecordSolicitedBlockLocked(m, blockHash, height);    // C1: record BEFORE the send (see _peerRelayedBlockTxns)
        BRPeerSendGetdataBlocks(p, &blockHash, 1);                         // credit: fetch the block -> tx registered on arrival
#ifdef CF_MATCH_MARK_ON_REQUEST_UNFIXED
        BRCFScanLedgerMarkEvaluated(&m->cfLedger, height);
#else
        peer_log(p, "cf-ledger: buffered matched block height %u left outstanding until full block delivery",
                 height);
#endif
        return 1;                                                          // request dispatched; remove bytes, retain ledger hole
    }

    BRCFScanLedgerMarkEvaluated(&m->cfLedger, height);                     // clean verified miss is complete immediately
    return 1;                                                              // remove from buffer
}
#endif // CF_LEDGER_DRIVE_REREQUEST

void BRPeerManagerKeepAlive(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);

#ifdef CF_RECV_DIAG
    // ---- RECEIVE-PATH LEDGER (diagnostic build only) -------------------------
    // recvTotal is every cfilter that reached _peerRelayedCFilter. The exits below
    // must sum to it exactly; `unaccounted` being non-zero means a drop path exists
    // that this instrumentation does not know about, which is itself the finding.
    //
    // Compare recvTotal against the peer-side "got cfilter" log count: a shortfall
    // there means the loss is BELOW the manager (socket read / dispatch), not here.
    {
        uint32_t acc = manager->cfExitNoChain + manager->cfExitUnknownBuf +
                       manager->cfExitUnknownDrop + manager->cfExitVerifyFail +
                       manager->cfExitParseFail + manager->cfExitEvaluated;
        debug_log("[CF-RECV] recv=%u evaluated=%u | noChain=%u unknownBuf=%u unknownDrop=%u "
                  "verifyFail=%u parseFail=%u | unaccounted=%d\n",
                  manager->cfRecvTotal, manager->cfExitEvaluated,
                  manager->cfExitNoChain, manager->cfExitUnknownBuf,
                  manager->cfExitUnknownDrop, manager->cfExitVerifyFail,
                  manager->cfExitParseFail, (int)manager->cfRecvTotal - (int)acc);
        // WHERE THE WALL CLOCK GOES. gap dominating => we are NETWORK/idle bound and
        // the constraint is upstream of this function. lock dominating => contention
        // with KeepAlive / block-add is throttling the drain. eval dominating => the
        // GCS match against the wallet element set is the constraint.
        if (manager->cfTimedSamples > 0) {
            uint32_t n = manager->cfTimedSamples;
            debug_log("[CF-TIME] n=%u | lockWait=%llu us/filter | eval=%llu us/filter | "
                      "gapBetweenArrivals=%llu us/filter | totals(ms) lock=%llu eval=%llu gap=%llu\n",
                      n,
                      (unsigned long long)(manager->cfLockWaitNanos / n / 1000),
                      (unsigned long long)(manager->cfEvalNanos     / n / 1000),
                      (unsigned long long)(manager->cfGapNanos      / n / 1000),
                      (unsigned long long)(manager->cfLockWaitNanos / 1000000),
                      (unsigned long long)(manager->cfEvalNanos     / 1000000),
                      (unsigned long long)(manager->cfGapNanos      / 1000000));
        }
    }
#endif

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double t0 = tv.tv_sec + (double)tv.tv_usec/1000000;

    // Paced-convoy: re-stamp the header-window verdict on every connected peer.
    // _peerRelayedBlock pushes on each block-add; this is the periodic backstop
    // that covers every OTHER way the window can move — the scan frontier
    // climbing (which no block-add signals), an abandonment jumping
    // abandonedBelow, a reorg, and peers that connected since the last push.
    // Without it a peer that went gated during the descent would never be told
    // the window re-opened. Not inside the tick-budget loop below: this is a
    // plain int store per peer, no I/O, and it must reach ALL peers every tick.
    _BRPeerManagerPushConvoyHdrGate(manager);

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
            BRPeerScheduleDisconnectTagged(p, 0, BR_DISC_TAG_IDLE_REAPER); // real deadline instead of the DBL_MAX idle sentinel
        }
    }

#ifndef CONVOY_C1_UNFIXED
    // ---- UNSERVABLE-HOLE backstop (paced-convoy fix wave, C-1 variant) ------
    //
    // Runs BEFORE the residual driver and the B2 valve, because a HOLE below the
    // in-memory block floor is exactly the hole neither of them can ever act on:
    // its getcfilters stop hash cannot resolve, so
    // _BRPeerManagerRequestCFiltersWithStopHashLocked returns 0, Pass C commits
    // only on `sent > 0`, `attempts` never increments, RetireCapped never fires —
    // so it can never reach gaveUp and the B2 valve is structurally BLIND to it.
    // Meanwhile _cfLedgerAdvance caps scannedThrough at min(outstanding[0],
    // gaveUp[0]) - 1, so that one hole pins the scan frontier the whole convoy
    // keys on, FOREVER and INVISIBLY. (Even a volunteered cfilter would not help:
    // _peerRelayedCFilter drops a response whose block is not in manager->blocks.)
    //
    // SCOPE, deliberately narrow. This covers the PIN — a hole that exists and can
    // never be served. The other half of C-1, a resumed frontier below the floor
    // with NO hole at all, is owned by BRPeerManagerSnapAutoFetchThroughToScanFrontier
    // (which SyncService calls on every sync start, right after the ledger restore
    // — the only moment that state can be created), and the two re-Init-at-a-new-
    // floor sites surface their own skipped band. Keeping this predicate keyed on a
    // real hole also keeps it silent through the steady state, where holes sit
    // comfortably above the retention floor (min(cfNext, LowestNeededHeight) - 144).
    if (_cfConvoyScanArmed(manager)) {
        uint32_t pinH = UINT32_MAX;
        if (manager->cfLedger.outstandingCount > 0) pinH = manager->cfLedger.outstanding[0].height;
        if (manager->cfLedger.gaveUpCount > 0 && manager->cfLedger.gaveUp[0] < pinH) {
            pinH = manager->cfLedger.gaveUp[0];
        }
        if (pinH != UINT32_MAX) {
            uint32_t c1Floor = _BRPeerManagerBlockFloor(manager);
            if (c1Floor > 0 && pinH < c1Floor) {
                uint32_t c1Lowest = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
                _BRPeerManagerSurfaceUnscannableLocked(manager, c1Lowest, c1Floor,
                                                       "KeepAlive: a hole below the in-memory block floor "
                                                       "that no retry could ever serve");
                // RECONCILE THE FORWARD-FETCH CURSOR TO THE SURFACED FRONTIER —
                // the same Step-2 reconciliation BRPeerManagerSnapAutoFetchThrough-
                // ToScanFrontier does, and for the same reason. The other three
                // surfacing sites (the arming clamp, the cfheaders floor snap and
                // the floor re-anchor) all set start/cursor to the new floor
                // THEMSELVES; this one did not, and left alone it re-opens the very
                // silent skip the surfacing exists to close: the cursor can sit
                // ABOVE the frontier (e.g. armed at the saved tip by the
                // EnableAutoCompactFilterFetch clamp), so the next forward fetch
                // starts above it and RecordRequested raises requestedThrough
                // NON-CONTIGUOUSLY over the gap — and _cfLedgerAdvance then sails
                // scannedThrough across heights that were never requested and are
                // NOT below abandonedBelow. Before fix-wave R2 that gap was zero by
                // coincidence (the resume floor WAS the clamped cursor + 1); with
                // the floor now SAVE_BLOCK_COUNT-1 lower it is a real 299-height
                // hole, so the reconciliation has to be explicit.
                //
                // Order matters, exactly as in the snap: clamp DOWN to what was
                // actually requested (cfLedger.requestedThrough is the persisted
                // truth — a cursor above it means the range in between was never on
                // the wire), then UP to frontier-1, so the result is always >= the
                // frontier and the next reqStart == the frontier itself.
                uint32_t c1After = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
#ifdef CONVOY_C1_NO_CURSOR_RECONCILE
                c1After = 0;   // RED-before-green shape ONLY: the surfacing still runs,
                               // only the cursor reconciliation is compiled out.
#endif
                if (c1After > 0) {
                    if (manager->autoFetchCFiltersStart > c1After) manager->autoFetchCFiltersStart = c1After;
                    if (manager->autoFetchCFiltersThrough > manager->cfLedger.requestedThrough) {
                        manager->autoFetchCFiltersThrough = manager->cfLedger.requestedThrough;
                    }
                    if ((c1After - 1) > manager->autoFetchCFiltersThrough) {
                        manager->autoFetchCFiltersThrough = c1After - 1;
                    }
                }
            }
        }
    }
#endif

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


        // ---- B2: THE ABANDONMENT VALVE (spec Part B2) -----------------------
        //
        // WHY IT EXISTS. RetireCapped (immediately above) is the ONLY thing that
        // creates gaveUp entries, and once a height is in gaveUp NO driver ever
        // re-requests it: both BRCFScanLedgerNextRerequest and
        // BRCFScanLedgerPeekRerequestRange iterate `outstanding` only. Because
        // _cfLedgerAdvance caps scannedThrough at min(outstanding[0], gaveUp[0])-1,
        // that single hole pins BRCFScanLedgerLowestNeededHeight — the frontier the
        // whole paced convoy keys its windows on — FOREVER. An un-retired gaveUp
        // hole is a permanent, silent sync wedge.
        //
        // WHY IT IS NOT "gaveUp => abandon". gaveUp means only "5 retries elapsed",
        // which is a HEURISTIC for unservable. During a convoy climb retries can
        // exhaust for transient, convoy-induced reasons — the peer set rotated, the
        // fleet was momentarily saturated, the range was briefly unavailable. A
        // gaveUp on a canonical in-chain height during a healthy convoy is a PACING
        // BUG SIGNAL, not a licence to abandon; abandoning there silently drops a
        // real wallet receive. So the valve proves CONNECTED-CF-SUBSET REFUSAL:
        //   1. If NO connected CF-capable peer exists, do NOTHING — this stall is
        //      not the height's fault and not this valve's to own. Wait for a peer.
        //   2. Otherwise RE-ARM the hole against the CURRENT (possibly healed) peer
        //      set: back to `outstanding`, attempts = 0, removed from gaveUp so it
        //      has exactly one home. The residual driver above then rotates it
        //      across every connected CF peer over a full 30/60/120/120/120 cycle.
        //   3. Abandon ONLY on re-exhaustion that was provably OFFERED AND REFUSED:
        //      rearmCycles >= CF_CONVOY_REARM_MAX (=2, so one unlucky peer-rotation
        //      cycle cannot false-positive) AND every offer in the deciding cycle
        //      actually reached a connected CF peer (the offersReachedLivePeer
        //      latch) AND >= 1 CF peer is connected right now.
        //
        // ---- F4 Part B: TWO DEFECTS IN THE ABOVE, BOTH FIXED HERE ---------------
        //
        // (B-i) THE ARM PREDICATE WAS BLIND TO A CAPPED OUTSTANDING HOLE. It read
        // "gaveUp[0] < outstanding[0].height", i.e. it treated every outstanding
        // entry as recoverable-and-being-retried. An outstanding entry at
        // CF_REREQ_MAX_ATTEMPTS is not: NextRerequest skips it and
        // PeekRerequestRange never selects it, so no driver will ever offer it
        // again. It is a parked hole that merely failed to reach gaveUp (because
        // _cfLedgerMoveToGaveUp found gaveUp full), and it pins the frontier
        // forever while the valve reads its own predicate as FALSE. That is exactly
        // the state the frozen-frontier field trace terminated in
        // (outstanding[0] = F+1 at attempts 5, gaveUp[0] = F+2, gaveUp at its
        // ceiling). F4 Part A removes the easy route in by sizing CF_GAVEUP_MAX to
        // CF_OUTSTANDING_MAX; this removes the last one. The valve now asks
        // BRCFScanLedgerPinningHole for the lowest hole in EITHER list and acts iff
        // that hole is not OFFERABLE — so a capped outstanding hole and a gaveUp
        // hole get the same treatment, which is the only honest reading of "no
        // driver will ever touch this again".
        //
        // (B-ii) IT ACTED ON ONE HEIGHT PER CYCLE. Holes arrive in runs — Peek
        // coalesces up to CF_REREQ_MAX_RANGE (1000) contiguous heights into ONE
        // getcfilters, and a dead range that size retires as a block. Re-arming and
        // abandoning ONE height per (1 + CF_CONVOY_REARM_MAX) x 7.5-min sequence
        // would take ~15 DAYS to clear a 1000-height band: an escape that exists on
        // paper and not in the field. Both halves now act on the contiguous parked
        // RUN at the pin, bounded by CF_REREQ_MAX_RANGE — the same unit the driver
        // already re-requests as one message, so the whole run shares one retry
        // cycle and one offered-and-refused verdict, and the band clears in one
        // ~22.5-min sequence. The DECISION is unchanged and still per-run-member:
        // BRCFScanLedgerAbandonableRunFrom only extends the abandonment run across
        // heights that individually satisfy rearmCycles >= rearmMax AND
        // offersReachedLivePeer — the first that does not ends the run and becomes
        // the next tick's pin.
        //
        // THE INVARIANT (outranks liveness, unchanged by any of this): NOTHING here
        // advances scannedThrough over a height that never received MarkEvaluated.
        // Both abandonment primitives raise abandonedBelow FIRST and only then let
        // _cfLedgerAdvance climb, and both report the count so the WARN below is
        // exactly a WARN on any advance — the band is SURFACED (abandonedBelow →
        // CfAbandonmentStore → banner → rescan / node-reconcile), never silently
        // skipped. AbandonGaveUpBelow additionally clamps its target at the lowest
        // still-OUTSTANDING hole, so it can never pass a height that is still being
        // retried.
        //
        // HONEST SCOPE — do NOT widen this claim. What is proven is refusal by the
        // CURRENTLY-CONNECTED CF-peer subset, NOT fleet-wide unservability. Under
        // fleet saturation (a canon oracle that HAS the filter sitting at
        // maxconnections, so we never connect to it) a SERVABLE height can still be
        // abandoned here. That residual is deliberately accepted because the
        // abandoned band stays surfaced and recoverable (node-reconcile covers any
        // height CF-independently; a full rescan re-covers it) — a recoverable
        // inconvenience, never a silent loss. It is bounded, not eliminated.
        //
        // LOCKING: manager->lock is NON-recursive and is HELD here, so every read
        // goes through the lock-free BRCFScanLedger* API — NEVER the public
        // BRPeerManagerLowestNeededHeight/AbandonedBelow accessors, which take this
        // same lock and would self-deadlock.
#ifndef CONVOY_NO_B2_VALVE
        {
            uint32_t gvH = 0;
            uint8_t  gvCycles = 0, gvOffersLive = 0;
            int      pinArmed = 0;    // is the pinning hole the valve's business this tick?

            // Only the hole that actually PINS the scan frontier is the valve's
            // business. _cfLedgerAdvance caps scannedThrough at
            // min(outstanding[0], gaveUp[0]) - 1, so the pinning hole is exactly the
            // LOWEST hole of either kind — and the valve acts iff NO DRIVER WILL EVER
            // OFFER IT AGAIN (a gaveUp hole, or a capped outstanding one: see F4
            // Part B-i above). A hole sitting ABOVE a still-retrying one is NOT what
            // blocks the convoy, and abandoning it would drop coverage nothing was
            // waiting on.
            //
            // Deliberately NOT written as `pin == LowestNeededHeight`: that reads
            // scannedThrough, which only ever moves in MarkEvaluated, so a floor gap
            // that has not been evaluated yet (a fresh/resumed scan whose lowest
            // heights were never requested) would leave LowestNeededHeight below the
            // hole and the valve permanently inert — the wedge, back again.
#ifdef CONVOY_B2_ARM_PREDICATE_UNFIXED
            // RED-before-green shape ONLY (never in a production build): the PRE-F4
            // predicate. It reads outstanding[0] as recoverable regardless of its
            // attempt count, so a CAPPED outstanding hole below gaveUp[0] — one no
            // driver will ever offer again — reads as "being retried" and the valve
            // stays inert while that hole pins the frontier forever.
            pinArmed = (BRCFScanLedgerLowestGaveUp(&manager->cfLedger, &gvH, &gvCycles, &gvOffersLive) &&
                        (manager->cfLedger.outstandingCount == 0 ||
                         gvH < manager->cfLedger.outstanding[0].height));
#else
            {
                int pinOfferable = 1;
                pinArmed = BRCFScanLedgerPinningHole(&manager->cfLedger, &gvH, &pinOfferable,
                                                     &gvCycles, &gvOffersLive) && ! pinOfferable;
            }
#endif
            if (pinArmed) {
                // Where the pin LIVES decides which abandonment primitive can reach
                // it. AbandonGaveUpBelow only drops gaveUp entries; a capped
                // OUTSTANDING pin needs the surfacing path
                // (_BRPeerManagerSurfaceUnscannableLocked → AbandonUnscannableBelow),
                // which drops from both lists. Both raise abandonedBelow and WARN, so
                // either way the band is surfaced, never silently skipped. Read
                // through the lock-free struct fields — manager->lock is HELD.
                const int pinInGaveUp = (manager->cfLedger.gaveUpCount > 0 &&
                                         manager->cfLedger.gaveUp[0] == gvH);

                // Count with the SAME predicate the residual driver's Pass A uses to
                // pick `chosen`, so "a CF peer is connected" means exactly "the
                // driver could have offered this hole to somebody". Counted in FULL
                // (no early break): the number goes in the abandonment WARN, and
                // "refused across 1 connected peer" vs "across 8" is exactly the
                // evidence the REARM_MAX tuning signal is read from.
                int cfPeers = 0;
                for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
                    if (_BRPeerManagerPeerCanServeFilters(manager->connectedPeers[i - 1])) cfPeers++;
                }

#ifdef CONVOY_B2_PEER_BLIND
                // RED-before-green shape ONLY (never in a production build): the
                // valve stops caring whether any CF peer is connected, so a hole
                // that was never offered to ANYONE gets abandoned.
                cfPeers = 1;
#endif
#ifdef CONVOY_B2_IGNORE_OFFER_LATCH
                // RED-before-green shape ONLY: the valve checks CF-peer presence at
                // the abandon INSTANT instead of THROUGHOUT the deciding cycle, so a
                // mid-cycle peer flap reads identically to five live refusals.
                gvOffersLive = 1;
#endif
#ifdef CONVOY_B2_REARM_ONCE
                const uint32_t rearmMax = 1;   // RED-before-green shape ONLY: pins the =2 tuning
#else
                const uint32_t rearmMax = CF_CONVOY_REARM_MAX;
#endif
#ifdef CONVOY_B2_SINGLE_HEIGHT_STEP
                // RED-before-green shape ONLY: the PRE-F4 one-height-per-cycle valve.
                // Correct per height, but ~15 days to clear one CF_REREQ_MAX_RANGE
                // dead band — an escape that exists on paper only (F4 Part B-ii).
                const size_t runCap = 1;
#else
                const size_t runCap = CF_REREQ_MAX_RANGE;
#endif

                if (cfPeers > 0) {
                    if (gvCycles >= rearmMax && gvOffersLive) {
                        // ---- ABANDON: offered-and-refused by live CF peers across a
                        // full deciding cycle, with a CF peer connected right now.
                        // Extend across the contiguous parked run whose EVERY member
                        // individually carries the same proof; the first that does not
                        // ends the run and becomes the next tick's pin.
                        uint32_t runHi = gvH;
                        size_t   runN  = BRCFScanLedgerAbandonableRunFrom(&manager->cfLedger, gvH, runCap,
                                                                          (uint8_t)rearmMax, &runHi);
                        if (runN > 0) {
                            uint32_t cnt = 0, lo = 0, hi = 0;
                            if (pinInGaveUp) {
                                BRCFScanLedgerAbandonGaveUpBelow(&manager->cfLedger, runHi + 1u,
                                                                 &cnt, &lo, &hi);
                                // Determinism guard (retained): abandonedBelow advances IFF
                                // gaveUp was actually dropped, so cnt>0 <=> advance <=> WARN.
                                if (cnt > 0) {
                                    CF_RETENTION_WLOG("[CF-SCAN] ABANDONED %u height(s) [%u..%u] — refused by every "
                                                      "connected CF peer across %u re-arm cycle(s) (%d CF peer(s) "
                                                      "connected); abandonedBelow=%u — reconcile or rescan to recover",
                                                      cnt, lo, hi, (unsigned)gvCycles, cfPeers,
                                                      BRCFScanLedgerAbandonedBelow(&manager->cfLedger));
                                }
                            }
                            else {
                                // The capped-OUTSTANDING pin (gaveUp was full when it
                                // re-exhausted). Same evidence, same surfacing contract —
                                // abandonedBelow + WARN — via the primitive that can
                                // actually drop an outstanding entry. It warns internally
                                // on cnt>0, so the determinism shape is identical.
                                _BRPeerManagerSurfaceUnscannableLocked(manager, gvH, runHi + 1u,
                                        "B2: retry-exhausted and un-parkable (gaveUp at its ceiling), "
                                        "offered and refused by every connected CF peer");
                            }
                        }
                    }
                    else {
                        // ---- RE-ARM: give it a fresh full retry cycle against the
                        // CURRENT peer set. Also the path a TAINTED deciding cycle
                        // takes (gvOffersLive == 0) — a cycle whose offers did not all
                        // reach a live peer can never be the one that abandons, so the
                        // hole keeps being worked instead. Run-wide (bounded by
                        // CF_REREQ_MAX_RANGE) so the whole band shares ONE cycle and
                        // Peek coalesces it back into ONE getcfilters.
                        size_t n = BRCFScanLedgerReArmParkedRun(&manager->cfLedger, gvH, runCap);
                        if (n > 0) {
                            // Peer-less log: passing the bare BR_PEER_NONE sentinel to
                            // peer_log casts it to BRPeerContext* and writes inet_ntop's
                            // host string past the end of the stack temporary (see the
                            // "sync failed — no peers connected" site). Use _peer_log.
                            _peer_log("cf-ledger: B2 re-armed %zu parked hole(s) from %u for a fresh retry "
                                      "cycle (cycle %u, %d CF peer(s) connected, prev cycle %s, pin was %s)\n",
                                      n, gvH, (unsigned)(gvCycles + 1), cfPeers,
                                      gvOffersLive ? "fully offered to live peers"
                                                   : "TAINTED (an offer missed a live peer)",
                                      pinInGaveUp ? "parked in gaveUp"
                                                  : "CAPPED in outstanding (gaveUp at its ceiling)");
                        }
                    }
                }
                // cfPeers == 0 -> deliberately nothing at all (step 1).
            }
        }
#endif // CONVOY_NO_B2_VALVE

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

        // Task 3 — single-descent residual tick, restructured into three passes
        // so all stop hashes resolve in ONE O(chainLen) descent (Pass B) instead
        // of up to CF_REREQ_BATCH_PER_TICK deep _BRPeerManagerBlockHashAtHeight
        // walks under manager->lock (the raised-floor ANR class). The passes are
        // behaviour-identical to the old fused peek->send->commit loop:
        //   Pass A collects the SAME (rs,cap,chosen) tuples the fused loop would
        //          have sent — same suppressor skip, same tip-clip, same rotate-
        //          away peer selection, same minH advance, same break conditions;
        //   Pass B resolves every collected stop height to its hash in one descent;
        //   Pass C sends each range with its pre-resolved stop hash and commits
        //          ONLY on a real send (sent>0), exactly as before.
        // Per-tick fixed-size scratch (no malloc), bounded by CF_REREQ_BATCH_PER_TICK.
        struct { uint32_t rs; uint32_t cap; BRPeer *chosen; } collected[CF_REREQ_BATCH_PER_TICK];
        size_t nCollected = 0;

        uint32_t tipH = manager->lastBlock ? manager->lastBlock->height : 0, minH = 0;

#ifdef CF_PIN_DIAG
        // ---- DIAGNOSTIC ONLY (never a production build): why is the PIN not sent? -----
        // The B2 valve arms only on a PARKED pin, parked means attempts >= MAX, and attempts
        // only advance on a SEND that reaches the wire. So a pin that can never be sent can
        // never park and the valve is permanently inert. This dumps the pin's full state and
        // is followed by a marker in Pass A recording whether Peek actually offered it, which
        // together name which of the six skip reasons applies.
        uint32_t diagPinH = 0; int diagPinOfferable = 1;
        uint8_t  diagCycles = 0, diagOffersLive = 0;
        int      diagHavePin = BRCFScanLedgerPinningHole(&manager->cfLedger, &diagPinH,
                                                         &diagPinOfferable, &diagCycles, &diagOffersLive);
        if (diagHavePin) {
            const BRCFOutstanding *pe = NULL;
            for (size_t i = 0; i < manager->cfLedger.outstandingCount; i++) {
                if (manager->cfLedger.outstanding[i].height == diagPinH) { pe = &manager->cfLedger.outstanding[i]; break; }
            }
            int inGaveUp = (manager->cfLedger.gaveUpCount > 0 && manager->cfLedger.gaveUp[0] == diagPinH);
            uint32_t floorH = _BRPeerManagerBlockFloor(manager);
            UInt256  pinHash = _BRPeerManagerBlockHashAtHeight(manager, diagPinH);
            int cfp = 0;
            for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
                if (_BRPeerManagerPeerCanServeFilters(manager->connectedPeers[i - 1])) cfp++;
            }
            debug_log("[CF-PIN] h=%u where=%s offerable=%d attempts=%u/%u cycles=%u offersLive=%u "
                      "due=%d(reqAt=%u now=%u) blockFloor=%u belowFloor=%d hashResolvable=%d "
                      "cfPeers=%d tip=%u scanned=%u outstanding=%zu gaveUp=%zu\n",
                      diagPinH, inGaveUp ? "gaveUp" : (pe ? "outstanding" : "NEITHER"),
                      diagPinOfferable,
                      (unsigned)(pe ? pe->attempts : 0), (unsigned)CF_REREQ_MAX_ATTEMPTS,
                      (unsigned)diagCycles, (unsigned)diagOffersLive,
                      pe ? (int)(nowSec >= pe->requestedAt) : -1,
                      (unsigned)(pe ? pe->requestedAt : 0), (unsigned)nowSec,
                      floorH, (int)(diagPinH < floorH), (int)(! UInt256IsZero(pinHash)),
                      cfp, tipH,
                      BRCFScanLedgerScannedThrough(&manager->cfLedger),
                      BRCFScanLedgerOutstandingCount(&manager->cfLedger),
                      BRCFScanLedgerGaveUpCount(&manager->cfLedger));
        }
        int diagPinOffered = 0;
#endif

        // ---- Pass A: collect (no resolve, no send, no commit) ----
        for (unsigned n = 0; n < CF_REREQ_BATCH_PER_TICK; n++) {
            uint32_t rs = 0, re = 0;
            if (! BRCFScanLedgerPeekRerequestRange(&manager->cfLedger, nowSec, minH, &rs, &re)) break;
#ifdef CF_PIN_DIAG
            if (diagHavePin && rs <= diagPinH && diagPinH <= re) diagPinOffered = 1;
#endif

            // Reverse-map suppressor: rs's canonical block is currently buffered
            // (in-flight via the buffer-drain path) -- skip past just rs so the
            // next peek can still offer rs+1..re, the same skip-past idiom as the
            // tip clip below. A buffered height sparse mid-run may ride along in a
            // coalesced range: the accepted, bounded (backoff x 5-cap) redundant
            // fetch -- deliberately NOT prevented here (no per-candidate walk).
            int rsInFlight = 0;
            for (size_t i = 0; i < nSkip; i++) { if (skipHeights[i] == rs) { rsInFlight = 1; break; } }
            if (rsInFlight) {
#ifdef CF_PIN_DIAG
                if (diagHavePin && rs == diagPinH) debug_log("[CF-PIN] skip=reverse-map-suppressed h=%u\n", rs);
#endif
                minH = rs + 1; continue;
            }

            uint32_t cap = (re <= tipH) ? re : tipH;
            if (cap < rs) {
#ifdef CF_PIN_DIAG
                if (diagHavePin && rs == diagPinH) debug_log("[CF-PIN] skip=beyond-tip h=%u re=%u tip=%u\n", rs, re, tipH);
#endif
                minH = re + 1; continue;   // whole offered run is beyond the tip -- skip past it
            }

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
            if (! chosen) {
                // No CF-capable peer connected at all -- nothing to do this tick.
                // B2 latch: this run was DUE and got no offer, so the elapsed backoff
                // was NOT productive retry time against a live peer. Taint the cycle
                // so it can never be the deciding (abandoning) one -- an un-offered
                // height must never read as an offered-and-refused one.
                BRCFScanLedgerMarkOffersMissedLivePeer(&manager->cfLedger, rs, re);
                break;
            }

            collected[nCollected].rs     = rs;
            collected[nCollected].cap    = cap;
            collected[nCollected].chosen = chosen;
            nCollected++;
            minH = re + 1;
        }

#ifdef CF_PIN_DIAG
        if (diagHavePin && ! diagPinOffered) {
            debug_log("[CF-PIN] NOT OFFERED by Peek this tick (h=%u) — Peek skipped it: not due, "
                      "attempts>=MAX, or not a candidate\n", diagPinH);
        }
#endif

        // ---- Pass B: resolve every collected stop height in ONE descent ----
        // The getcfilters wire message carries startHeight as an integer and the
        // STOP as a hash, so only the cap heights need resolving (resolving the
        // start too would be dead work — and gating on a start-hash miss would
        // suppress a send the fused loop makes, breaking send-set identity). n is
        // bounded by CF_REREQ_BATCH_PER_TICK (<= 2*CF_REREQ_BATCH_PER_TICK).
        uint32_t stopHeights[CF_REREQ_BATCH_PER_TICK];
        UInt256  stopHashes[CF_REREQ_BATCH_PER_TICK];
        for (size_t c = 0; c < nCollected; c++) stopHeights[c] = collected[c].cap;
        _BRPeerManagerResolveHashesAtHeightsLocked(manager, stopHeights, nCollected, stopHashes);

        // ---- Pass C: send each range with its pre-resolved stop hash + commit ----
        for (size_t c = 0; c < nCollected; c++) {
            uint32_t rs = collected[c].rs, cap = collected[c].cap;
            BRPeer  *chosen = collected[c].chosen;

            // Between-pass staleness guard (defensive operator condition): a
            // height collected in Pass A may have DRAINED (MarkEvaluated) before
            // Pass C reaches it. Nothing drains between passes within one locked
            // tick today, but re-check the range's LOWEST height (rs) is still
            // outstanding so a future change can't silently double-request or
            // mis-commit a resolved height. If rs is gone, skip both the send
            // and the commit — no getcfilters, no attempt bump.
            int rsStillOutstanding = 0;
            for (size_t i = 0; i < manager->cfLedger.outstandingCount; i++) {
                if (manager->cfLedger.outstanding[i].height == rs) { rsStillOutstanding = 1; break; }
            }
            if (! rsStillOutstanding) continue;

            size_t sent = _BRPeerManagerRequestCFiltersWithStopHashLocked(manager, rs, cap, stopHashes[c], chosen);
            if (sent > 0) {
                BRCFScanLedgerCommitRerequest(&manager->cfLedger, rs, cap, chosen->address, chosen->port, nowSec);
                peer_log(chosen, "cf-ledger: re-requested residual holes [%u..%u]", rs, cap);
            }
            else {
                // Nothing went on the wire (unresolvable stop hash, dead socket, ...).
                // No attempt was burned, but the retry opportunity passed WITHOUT
                // reaching a live CF peer -- taint the cycle for the same reason as
                // the no-peer break in Pass A.
#ifdef CF_PIN_DIAG
                if (diagHavePin && rs <= diagPinH && diagPinH <= cap) {
                    debug_log("[CF-PIN] send FAILED for range [%u..%u] containing pin %u — "
                              "stopHashResolved=%d\n", rs, cap, diagPinH,
                              (int)(! UInt256IsZero(stopHashes[c])));
                }
#endif
                BRCFScanLedgerMarkOffersMissedLivePeer(&manager->cfLedger, rs, cap);
            }
        }
        free(bufHashes);      // per-tick heap skip-set (free(NULL) is safe)
        free(skipHeights);
        manager->cfLedger.lastDriveAt = nowSec;
    }
#endif // CF_LEDGER_DRIVE_REREQUEST

    // ---- PACED-CONVOY DRIVER B1 (spec Part B1) -----------------------------
    //
    // WHY THIS EXISTS AT ALL — read before touching either half. The Part-A gate
    // suppresses the two TIP-RACING continuations, and suppressing a continuation
    // REMOVES THE ONLY THING THAT RE-FIRES IT. Worse, the forward getcfilters
    // auto-fetch has exactly ONE production trigger anywhere in this file: a
    // cfheaders arrival (_peerRelayedCFHeaders). So the gate alone is a silent
    // permanent wedge, and this block is its un-suppressor — they ship together.
    //
    // The sharpest case is the DRAIN TROUGH: a wallet killed and resumed
    // mid-descent at the moment the ledger had drained EMPTY — outstanding == 0,
    // gaveUp == 0 — while the restored cfheader frontier still sits above
    // scannedThrough+1. There is no hole for the residual driver above (both
    // NextRerequest and PeekRerequestRange iterate `outstanding` only) and no
    // cfheaders arrival for the forward fetch. Nothing can create the first
    // outstanding entry, the scan never advances, the window never re-opens, and
    // deep history is silently never scanned while the wallet reports itself
    // progressing. B1.1 below is what breaks that.
    //
    // LOCKING: manager->lock is NON-recursive and is HELD here. Every ledger read
    // below goes through the lock-free ledger-level API (BRCFScanLedger*), never
    // the public BRPeerManager* accessors, which take this same lock (self-deadlock).
    //
    // NO ELIGIBLE PEER == DO NOTHING THIS TICK. Every leg selects its own peer and
    // silently skips when none is connected; that stall is the connect path's, not
    // this driver's.
#ifndef CONVOY_NO_B1_DRIVER
    if (_cfConvoyScanArmed(manager)) {
        uint32_t blockTip = manager->lastBlock ? manager->lastBlock->height : 0;
        uint32_t cfhNext  = manager->compactFilterChain
                            ? BRCompactFilterChainNextHeight(manager->compactFilterChain) : 0;

        // ---- B1.1: forward cfilter drive (THE load-bearing fix) -------------
        // Deliberately NOT window-gated: the forward cfilter fetch ADVANCES the
        // scan frontier the whole convoy is keyed on — gating it would deadlock
        // the convoy from the other side. Its back-pressure is CF_OUTSTANDING_LOWWATER,
        // which is orthogonal to the window (spec Part A, "never gated").
        //
        // This MIRRORS the caller-side steps of the cfheaders-arrival path in
        // _peerRelayedCFHeaders (the `autoFetchCFiltersEnabled` block there),
        // because _BRPeerManagerRequestCFiltersLocked does NEITHER of them
        // internally — it only resolves the stop hash and sends:
        //   (1) advance autoFetchCFiltersThrough to reqStop on a REAL send. Omit
        //       it and this drive re-requests the same batch every 10 s forever.
        //   (2) BRCFScanLedgerRecordRequested(Dropped) the range. Omit it and the
        //       in-flight heights are untracked, so _cfLedgerAdvance sails
        //       scannedThrough PAST an unscanned height — a silent missed receive,
        //       the exact bug class this subsystem exists to prevent.
        // Keep the two paths byte-comparable; if one changes, change both.
        if (cfhNext > 0
#if CF_LEDGER_DRIVE_REREQUEST
            && _cfForwardFetchAllowed(manager)
#endif
            ) {
            uint32_t cfhFrontier = cfhNext - 1;   // NextHeight is one PAST the last appended cfheader

            // ---- REMOVED: the forward-gap gate (CF_FORWARD_GAP_MAX) ------------------
            //
            // It used to hold the forward fetch whenever the cursor led scannedThrough by
            // >= 2 * MAX_CFILTERS_RESULTS, on the theory that the budget was better spent
            // letting the residual driver close the contiguous prefix (measured: 89.3% of
            // arrivals landing outside the pinning hole's window).
            //
            // Its comment claimed "Not a deadlock: if the prefix is genuinely unservable the
            // B2 valve raises abandonedBelow, which reopens this gate." That is FALSE when
            // the pin is not yet PARKED. Reproduced on a Note 8, 2026-08-02, fresh wallet:
            //
            //   cf-ledger: scannedThrough=23899999 outstanding=2000 gaveUp=0 pending=0
            //   paced convoy: holding forward cfilters — cursor 23901999 is 2000 ahead of
            //                 the scan frontier 23899999 (cap 2000)
            //
            // Height 23,900,000 (the filter-chain anchor) was never served by any peer, so
            // scannedThrough could not advance; the gap sat at EXACTLY the cap, so the gate
            // held; the valve never armed because `attempts` stayed at 2/5 and gaveUp was
            // empty. Ten minutes, 733 filters delivered, frontier moved zero blocks. The
            // escape the comment relied on requires the valve to have PARKED the pin first,
            // which the gate itself helps prevent by starving the drive.
            //
            // AND IT WAS REDUNDANT. Back-pressure on a runaway cursor already exists two
            // lines above, in the forward driver's own precondition:
            //     BRCFScanLedgerOutstandingCount(&manager->cfLedger) < CF_OUTSTANDING_LOWWATER
            // That brake keys on the OUTSTANDING COUNT, which drains on every arrival, so it
            // always releases itself. The gate keyed on the SCAN FRONTIER, which can freeze —
            // and a frozen frontier latches it shut permanently. Same goal, but one is
            // self-releasing and the other is not. Measured on the Note 8 after removal:
            // outstanding oscillated 2716 -> 3328 -> 3050 -> 3729 around LOWWATER (3072)
            // while the frontier climbed ~580 blocks/min, i.e. the surviving brake does the
            // job the gate was added for.
            //
            // The waste it targeted is real but self-correcting; this converted it into a
            // hard stop. If a cursor brake is ever wanted again, key it on something that
            // drains (outstanding count, in-flight bytes) — never on the frontier.

            uint32_t reqStart = manager->autoFetchCFiltersThrough + 1;
            if (reqStart < manager->autoFetchCFiltersStart) reqStart = manager->autoFetchCFiltersStart;
            if (reqStart <= cfhFrontier) {        // == "autoFetchCFiltersThrough < cfHeadersFrontier", post-clamp
                uint32_t reqStop = cfhFrontier;
                if (reqStop > reqStart + (MAX_CFILTERS_RESULTS - 1)) {
                    reqStop = reqStart + (MAX_CFILTERS_RESULTS - 1);
                }
                // Select with the SAME predicate _BRPeerManagerRequestCFiltersLocked
                // uses for its own fallback, so the peer recorded in the ledger is
                // provably the peer the getcfilters went to (the residual driver's
                // rotate-away logic keys on that record).
                BRPeer *fp = NULL;
                for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
                    if (_BRPeerManagerPeerCanServeFilters(manager->connectedPeers[i - 1])) {
                        fp = manager->connectedPeers[i - 1];
                        break;
                    }
                }
                if (fp) {
                    size_t n = _BRPeerManagerRequestCFiltersLocked(manager, reqStart, reqStop, fp);
                    if (n > 0) {
                        manager->autoFetchCFiltersThrough = reqStop;
#if CF_LEDGER_DRIVE_REREQUEST
                        // Never silent about CF_OUTSTANDING_MAX overflow (Phase 2):
                        // log the dropped-oldest-holes range so a hole caused by
                        // hitting the hard cap is loud instead of a silent missed-scan.
                        uint32_t dLo = CF_LEDGER_NO_DROP, dHi = CF_LEDGER_NO_DROP;
                        int nDropReq = BRCFScanLedgerRecordRequestedDropped(&manager->cfLedger, reqStart, reqStop,
                                                      fp->address, fp->port, (uint32_t)time(NULL), &dLo, &dHi);
                        if (nDropReq > 0) {
                            peer_log(fp, "cf-ledger: OUTSTANDING OVERFLOW — dropped %d oldest holes [%u..%u]",
                                     nDropReq, dLo, dHi);
                        }
#else
                        BRCFScanLedgerRecordRequested(&manager->cfLedger, reqStart, reqStop,
                                                      fp->address, fp->port, (uint32_t)time(NULL));
#endif
                        peer_log(fp, "paced convoy: forward cfilters [%u..%u] (%zu blocks) — KeepAlive drive "
                                 "(no cfheaders arrival needed)", reqStart, reqStop, n);
                    }
                }
            }
        }

        // ---- B1.2: cfheaders advance re-kick --------------------------------
        // The window predicate is recomputed LIVE (B1.1 above may have moved the
        // scan frontier's accounting, and the ledger is the single source). The
        // "more work exists" bound is the BLOCK-HEADER tip, not estimatedHeight:
        // _BRPeerManagerRequestNextCFHeaders clamps its own batchEnd to
        // lastBlock->height (so cfheaders can never overtake the header frontier)
        // and returns early once `next > tip`. cfhNext == 0 means NULL/empty chain,
        // where the FIRST batch is still owed. No extra throttle is needed or wanted:
        // that function's cfHeadersRequestedThrough/cfHeadersRequestTime guard
        // already serializes one batch in flight, so a per-tick call self-no-ops.
        if (! CF_CONVOY_CFH_GATED(manager) && manager->lastBlock &&
            (cfhNext == 0 || cfhNext <= blockTip)) {
            BRPeer *fp = _BRPeerManagerAnyFilterCapablePeer(manager);
            if (fp) _BRPeerManagerRequestNextCFHeaders(manager, fp, /*isConvoyAdvance=*/1);
        }

        // ---- B1.3: getheaders advance re-kick -------------------------------
        // Re-issues the CF-only header continuation BRPeer.c holds while the window
        // is full. Full exponential locators (same primitive as the orphan re-anchor
        // and the tip-stall watchdog) so a walk-back is possible, not just a forward
        // pull. Prefer the download peer; fall back to any live peer, since a
        // resumed manager can have downloadPeer == NULL while peers are connected.
        //
        // TWO conditions, both load-bearing (see CF_CONVOY_HDR_REKICK_BASE_SECS in
        // BRPeerManager.h for the full cost argument):
        //   (i)  an OBSERVED FROZEN TIP (convoyLastHdrTip) -- BRPeerSendGetheaders
        //        has no in-flight guard of its own and BRPeer.c's own continuation
        //        is already running while the window is open, so firing on an
        //        ADVANCING tip would duplicate every 2000-header batch;
        //   (ii) a RATE LIMIT on top, because "frozen" cannot tell "nothing is in
        //        flight" from "a ~440 KB reply is in flight and not parsed yet"
        //        (BRPeer.c issues its continuation BEFORE the relay loop). Without
        //        it a slow link gets one injected getheaders per ~10 s tick, each
        //        reply spawning its own persistent lockstep continuation chain
        //        (N x ~2.2 MB of duplicate headers per window-open period), and a
        //        stale-HIGH estimatedHeight -- which is only ever RAISED, never
        //        lowered -- leaves a fully-synced wallet permanently "below the
        //        network tip" with the window permanently open, i.e. ~10 MB/day of
        //        0-header round trips forever. The interval doubles while
        //        unproductive and RESETS on real tip progress below, so an ordinary
        //        descent always pays only BASE.
        uint32_t hdrTip    = manager->lastBlock ? manager->lastBlock->height : 0;
        int      hdrFrozen = (hdrTip <= manager->convoyLastHdrTip);
        // ONE evaluation of the window verdict, reused by both the episode reset and
        // the send condition, so the two can never disagree within a tick. Read AFTER
        // B1.2 deliberately: a floor-snap/re-anchor there has already moved the scan
        // frontier, and this must see the post-snap verdict.
        int      hdrGated  = CF_CONVOY_HDR_GATED(manager);

        if (! hdrFrozen) {
            // The continuation chain is demonstrably alive: forget the backoff so the
            // NEXT stall is re-kicked at BASE rather than at the ceiling.
            manager->convoyHdrKickBackoff = CF_CONVOY_HDR_REKICK_BASE_SECS;
        }
        // GATED -> OPEN: end of episode (fix round 2). The backoff is a penalty for
        // UNPRODUCTIVE RE-KICKS, and a gated period issues none, so it can neither
        // earn one nor carry one across. Crucially this is NOT covered by the
        // !hdrFrozen reset above: hdrFrozen and hdrGated are INDEPENDENT --
        // _cfConvoyHdrGated can flip open->full->open purely from scanFrontier
        // movement (B1.2's floor-snap/re-anchor, or the scan simply falling a full
        // window behind) with lastBlock->height never advancing, so a genuinely
        // stalled tip that had already escalated to the ceiling would make the reopen
        // wait out up to CF_CONVOY_HDR_REKICK_MAX_SECS -- in exactly the resume-a-
        // held-continuation case B1.3 exists to serve. Clearing the stamp too (rather
        // than only resetting the backoff) restores the pre-throttle behaviour that a
        // reopen is served on the VERY NEXT tick.
        //
        // NOT A BYPASS: the reopen re-kick immediately re-arms the interval at BASE
        // and the backoff resumes doubling from there, so a pathological gate flap
        // costs at most one ~1.2 KB getheaders per full open->gated->open cycle -- and
        // a cycle requires the header frontier to actually cross CF_CONVOY_WINDOW
        // (10 000 blocks) in both directions, which cannot happen per-tick. Round-1's
        // property is untouched: a permanently OPEN window never transitions, so a
        // permanently frozen tip still decays to the 600 s ceiling.
        if (CF_CONVOY_HDR_REKICK_GATE_RESET && ! hdrGated && manager->convoyHdrWasGated) {
            manager->convoyHdrKickBackoff = CF_CONVOY_HDR_REKICK_BASE_SECS;
            manager->convoyLastHdrKickAt  = 0;   // == "never re-kicked" -> immediately due
        }
        manager->convoyHdrWasGated = (uint8_t)(hdrGated ? 1 : 0);

        if (hdrFrozen && ! hdrGated && manager->lastBlock &&
            hdrTip < manager->estimatedHeight) {
            uint32_t backoff = manager->convoyHdrKickBackoff
                               ? manager->convoyHdrKickBackoff : CF_CONVOY_HDR_REKICK_BASE_SECS;
            if (CF_CONVOY_HDR_REKICK_DUE(manager, backoff)) {
                BRPeer *dp = _BRPeerManagerHeaderSyncPeer(manager);
                if (dp) {
                    UInt256 locators[_BRPeerManagerBlockLocators(manager, NULL, 0)];
                    size_t locatorsCount = _BRPeerManagerBlockLocators(manager, locators,
                                                                       sizeof(locators)/sizeof(*locators));
                    peer_log(dp, "paced convoy: re-kicking held header continuation from tip %"PRIu32
                             " (window open, header frontier frozen; next re-kick in >=%us)",
                             hdrTip, backoff);
                    BRPeerSendGetheaders(dp, locators, locatorsCount, UINT256_ZERO);
                    // Stamp + back off ONLY on a real send, so a tick with no eligible
                    // peer neither consumes the interval nor escalates the backoff.
                    manager->convoyLastHdrKickAt  = time(NULL);
                    manager->convoyHdrKickBackoff = (backoff >= CF_CONVOY_HDR_REKICK_MAX_SECS / 2)
                                                    ? CF_CONVOY_HDR_REKICK_MAX_SECS : backoff * 2;
                }
            }
        }
        manager->convoyLastHdrTip = hdrTip;

        // B1.2 can floor-snap/re-anchor (BRCFScanLedgerInit at a new floor +
        // compactFilterChain freed), which moves the scan frontier and therefore the
        // HEADER window verdict pushed at the top of this tick. Recompute + re-push
        // so BRPeer.c's continuation reads this tick's truth, not the pre-drive one.
        _BRPeerManagerPushConvoyHdrGate(manager);
    }
#endif // CONVOY_NO_B1_DRIVER

#ifdef CF_AGE_DIAG
    // ---- WHY IS `outstanding` PINNED NEAR ITS CEILING? (diagnostic build only) ----
    //
    // Measured 2026-08-03, armed Phase-2 deep restore: outstanding sat at 3300-4044
    // against CF_OUTSTANDING_MAX 4096, so the forward back-pressure gates
    // (BRCFScanLedgerOutstandingCount < CF_OUTSTANDING_LOWWATER, which exist ONLY when
    // armed) stayed shut and only 49 getcfilters went out in 10 minutes -- scan rate
    // 1418 blk/min against ~5250 blk/min of headers.
    //
    // TWO EXPLANATIONS, OPPOSITE FIXES, and the logs cannot tell them apart:
    //   (A) the entries are mostly YOUNG -- a normal in-flight pipeline that is simply
    //       deeper than a 4096 buffer. Fix: bigger buffer / paced issuance.
    //   (B) the entries are mostly OLD -- heights stuck mid-ladder occupying slots for
    //       the full 30/60/120/120/120 = 7.5 min. Fix: the retry ladder, not the buffer.
    // Guessing between them is how four designs died this session. So: measure.
    //
    // Buckets are age since the LAST request (requestedAt, unix secs), plus the attempts
    // histogram, which separates "waiting on a first answer" from "deep in the ladder".
    {
        BRCFScanLedger *_l = &manager->cfLedger;
        time_t _now = time(NULL);
        unsigned _a5 = 0, _a30 = 0, _a120 = 0, _a300 = 0, _aOld = 0, _aNever = 0;
        unsigned _att[CF_REREQ_MAX_ATTEMPTS + 1];
        memset(_att, 0, sizeof(_att));
        for (size_t _i = 0; _i < _l->outstandingCount; _i++) {
            uint8_t _n = _l->outstanding[_i].attempts;
            if (_n <= CF_REREQ_MAX_ATTEMPTS) _att[_n]++;
            uint32_t _ra = _l->outstanding[_i].requestedAt;
            if (_ra == 0) { _aNever++; continue; }
            long _age = (long)_now - (long)_ra;
            if (_age < 5)        _a5++;
            else if (_age < 30)  _a30++;
            else if (_age < 120) _a120++;
            else if (_age < 300) _a300++;
            else                 _aOld++;
        }
        _peer_log("[CF-AGE] outstanding=%zu (max %u, lowwater %u) | age: <5s=%u <30s=%u "
                  "<2m=%u <5m=%u older=%u never-requested=%u | attempts: 0=%u 1=%u 2=%u "
                  "3=%u 4=%u 5=%u\n",
                  _l->outstandingCount, (unsigned)CF_OUTSTANDING_MAX,
                  (unsigned)CF_OUTSTANDING_LOWWATER,
                  _a5, _a30, _a120, _a300, _aOld, _aNever,
                  _att[0], _att[1], _att[2], _att[3], _att[4], _att[5]);
    }
#endif // CF_AGE_DIAG

    MGR_UNLOCK(manager);
}

void BRPeerManagerDisconnect(BRPeerManager *manager)
{
    struct timespec ts;
    // SIGNED, matching the struct fields (BRPeerManagerStruct declares peerThreadCount,
    // dnsThreadCount and maxConnectCount as `int`). These were `size_t` locals, which turned a
    // transient NEGATIVE count into an infinite wait: copying int -1 into a size_t yields
    // 18,446,744,073,709,551,615, so `peerThreadCount > 0` is true forever and this function
    // never returns — while startSync holds PEER_GUARD, wedging the whole wallet.
    //
    // A negative count is reachable. There are five decrement sites, and the one below at the
    // "waiting for network" branch decrements on the ASSUMPTION that a Connecting peer's thread
    // will not also decrement on its way out. If it does, the count goes to -1. One double
    // decrement is enough to hang the process permanently.
    //
    // The bounded wait added alongside this makes the hang survivable; signed types make it
    // unreachable by this route. Both are wanted: the bound is containment, this is the fix.
    int peerThreadCount, dnsThreadCount, maxConnectCount;
    BRPeer *p;
    
    assert(manager != NULL);
    MGR_LOCK(manager);
    
    // prevent new peers from being spawned
    maxConnectCount = manager->maxConnectCount;
    manager->maxConnectCount = 0;
    // C1: every in-flight getdata dies with these connections. A block arriving after a
    // reconnect was not solicited by the reconnected session, so it must not complete a height.
    _BRPeerManagerClearSolicitedBlocksLocked(manager);
    
    for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
        p = manager->connectedPeers[i - 1];
        manager->connectFailureCount = MAX_CONNECT_FAILURES; // prevent futher automatic reconnect attempts
        BRPeerDisconnectTagged(p, BR_DISC_TAG_MANAGER_STOP);
        // "Waiting for network": a peer still in Connecting has a thread parked in connect(), which
        // this pre-decrement assumes will not decrement itself on the way out. If that assumption
        // is ever wrong the count goes negative — historically an infinite wait, because the loop
        // below read it through a size_t local. Clamped so the count can never go below zero
        // regardless of who else decrements.
        if (BRPeerConnectStatus(p) == BRPeerStatusConnecting && manager->peerThreadCount > 0) {
            manager->peerThreadCount--;
        }
    }

    // Defensive: if any other path has already driven these negative, treat them as drained rather
    // than waiting on a count that can never be satisfied.
    if (manager->peerThreadCount < 0) manager->peerThreadCount = 0;
    if (manager->dnsThreadCount < 0)  manager->dnsThreadCount = 0;

    peerThreadCount = manager->peerThreadCount;
    dnsThreadCount = manager->dnsThreadCount;
    MGR_UNLOCK(manager);
    // BOUNDED WAIT. This loop previously had NO exit condition -- it spun until the counts hit
    // zero, on a ONE-NANOSECOND nanosleep, i.e. a busy-wait re-acquiring manager->lock thousands
    // of times a second.
    //
    // That is fatal because of WHO CALLS IT: startSync runs BRPeerManagerDisconnect +
    // BRPeerManagerFree while holding PEER_GUARD, the global JNI mutex every bridge entry point
    // needs. If a peer thread never decrements peerThreadCount, this spins forever with that
    // guard held and the ENTIRE wallet stops -- keepalive, CF scan, status reads, all of it.
    // Measured on a Note 8, 2026-08-06:
    //
    //     07:57:45  startSync: recreating peer manager
    //     08:02:53  PEER_GUARD=308.7s startSync:762    <- still climbing, never released
    //
    // ...while peer threads were STILL RELAYING BLOCKS (#23012500, #23036000) five minutes in,
    // so the count was never going to reach zero. One thread had burned ~900s of CPU in this
    // spin and 93 of 103 threads sat queued behind the guard. The wallet also never persisted
    // its CF ledger while wedged, so the NEXT launch abandoned 333,701 blocks from the birth
    // height instead of resuming.
    //
    // A teardown that cannot complete must not be able to hold the process hostage. Give up
    // after PEER_DISCONNECT_WAIT_SECS and say so with the counts, so the underlying
    // "thread never exits" defect stays visible instead of being silently absorbed.
    //
    // 1 ms rather than 1 ns: the old value turned this into a lock-contention generator that
    // starved the very threads it was waiting on.
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000; // 1 ms

    double _discStart = _cfNowMs();
    while (peerThreadCount > 0 || dnsThreadCount > 0) {
#ifdef DISCONNECT_WAIT_UNBOUNDED
        // RED ARM ONLY (peer_disconnect_bounded_kat) — never defined in a production build.
        // Restores the pre-fix shape: no deadline, so a thread that never exits hangs here
        // forever with PEER_GUARD held by the caller.
        if (0) {
#else
        if (_cfNowMs() - _discStart >= (double)PEER_DISCONNECT_WAIT_SECS * 1000.0) {
#endif
            CF_SLOW_WLOG("[CF-SLOW] BRPeerManagerDisconnect gave up after %us waiting for %d "
                         "peer thread(s) and %d dns thread(s) to exit — proceeding rather than "
                         "holding the peer-manager guard forever",
                         (unsigned)PEER_DISCONNECT_WAIT_SECS,
                         peerThreadCount, dnsThreadCount);

            // WHERE are they stuck?
            //
            // The first on-device sighting (2026-08-07) answered the previous version of this
            // question and REFUTED the hypothesis written here: all 8 threads reported
            // status=Connected with socketOpen=**0**, not open. That combination cannot occur in
            // the read loop — BRPeerDisconnect sets socket=-1, both loops in _peerThreadRoutine
            // re-read ctx->socket every iteration and exit, and the routine then sets
            // status=Disconnected. So the threads are in message DISPATCH, which reaches the
            // manager callbacks below and takes THIS lock. The remaining unknown is which message
            // and for how long, which BRPeerCurrentMessageType/Secs now report.
            //
            // TRYLOCK, not MGR_LOCK. The suspected wedge is a thread holding manager->lock, and
            // blocking here would hang inside the very bounded wait that exists to stop this
            // function hanging — the diagnostic would become the outage. If the lock is held we
            // say so and report what can be read lock-free, which for the dispatch fields is
            // everything that matters.
            // BOUNDED RETRY, not a single try. The first cut used one trylock and lost to
            // ordinary contention on its very first on-device firing: it reported the holder as
            // _peerRelayedBlock held for 0.0s — i.e. a momentary, healthy hold — and skipped the
            // peer census, which is the entire reason this block exists. One attempt answers
            // "was the lock free at this instant", which is not a question anyone asked.
            //
            // Retrying for DIAG_LOCK_WAIT_MS keeps the useful case (transient contention: we get
            // the census) without reintroducing the unbounded wait this whole function exists to
            // avoid. If it is still unavailable after the budget, the lock really is being held
            // or convoyed, and THAT is the finding — reported with the holder, not silently.
            enum { DIAG_LOCK_WAIT_MS = 500, DIAG_LOCK_STEP_MS = 10 };
            int _diagLocked = 0;
            for (int _w = 0; _w < DIAG_LOCK_WAIT_MS / DIAG_LOCK_STEP_MS; _w++) {
                if (pthread_mutex_trylock(&manager->lock) == 0) { _diagLocked = 1; break; }
                struct timespec _dts = { 0, DIAG_LOCK_STEP_MS * 1000000L };
                nanosleep(&_dts, NULL);
            }
            if (! _diagLocked) {
                const char *_hf = NULL;
                int         _hl = 0;
                double      _hms = BRPeerManagerLockHeldMs(&_hf, &_hl);
                CF_SLOW_WLOG("[CF-SLOW]   manager->lock UNAVAILABLE for %dms (holder now %s:%d, "
                             "held %.1fs) — peer census skipped. A holder that keeps changing with "
                             "a small held-time is a CONVOY (many short holds starving the "
                             "dispatchers), not one long hold",
                             (int)DIAG_LOCK_WAIT_MS, _hf ? _hf : "?", _hl, _hms / 1000.0);
            }
            for (size_t i = _diagLocked ? array_count(manager->connectedPeers) : 0; i > 0; i--) {
                BRPeer *sp = manager->connectedPeers[i - 1];
                const char *inMsg = BRPeerCurrentMessageType(sp);
                double      inFor = BRPeerCurrentMessageSecs(sp);
                CF_SLOW_WLOG("[CF-SLOW]   stuck peer %s:%u status=%d socketOpen=%d lastRecv=%.0fs ago "
                             "dispatching=%s for %.1fs",
                             BRPeerHost(sp), (unsigned)sp->port,
                             (int)BRPeerConnectStatus(sp), BRPeerIsSocketOpen(sp) ? 1 : 0,
                             (double)time(NULL) - BRPeerLastRecvTime(sp),
                             (inMsg && inMsg[0]) ? inMsg : "(not in dispatch)", inFor);
            }
            if (_diagLocked) pthread_mutex_unlock(&manager->lock);
            break;
        }
        nanosleep(&ts, NULL); // pthread_yield() isn't POSIX standard :(
        MGR_LOCK(manager);
        peerThreadCount = manager->peerThreadCount;
        dnsThreadCount = manager->dnsThreadCount;
        MGR_UNLOCK(manager);
    }
    
    MGR_LOCK(manager);
    manager->maxConnectCount = maxConnectCount;
    MGR_UNLOCK(manager);
}

// rescans blocks and transactions after earliestKeyTime (a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter)
void BRPeerManagerRescan(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    
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
            
            BRPeerDisconnectTagged(manager->downloadPeer, BR_DISC_TAG_DOWNLOAD_SWAP);
        }

        manager->syncStartHeight = 0; // a syncStartHeight of 0 indicates that syncing hasn't started yet
        MGR_UNLOCK(manager);
        BRPeerManagerConnect(manager);
    }
    else MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);

    if (manager->downloadPeer) {
        sprintf(manager->downloadPeerName, "%s:%d", BRPeerHost(manager->downloadPeer), manager->downloadPeer->port);
    }
    else manager->downloadPeerName[0] = '\0';
    
    MGR_UNLOCK(manager);
    return manager->downloadPeerName;
}

static void _publishTxInvDone(void *info, int success)
{
    BRPeer *peer = ((BRPeerCallbackInfo *)info)->peer;
    BRPeerManager *manager = ((BRPeerCallbackInfo *)info)->manager;
    
    free(info);
    MGR_LOCK(manager);
    _BRPeerManagerRequestUnrelayedTx(manager, peer);
    MGR_UNLOCK(manager);
}

// publishes tx to bitcoin network (do not call BRTransactionFree() on tx afterward)
void BRPeerManagerSetDandelionEnabled(BRPeerManager *manager, int enabled)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->dandelionEnabled = (enabled != 0);
    MGR_UNLOCK(manager);
}

void BRPeerManagerAddDandelionPeer(BRPeerManager *manager, UInt128 address)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    int known = 0;
    for (size_t i = array_count(manager->dandelionPeers); i > 0; i--) {
        if (UInt128Eq(manager->dandelionPeers[i - 1], address)) { known = 1; break; }
    }
    if (! known) array_add(manager->dandelionPeers, address);
    MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);
    int r = manager->dandelionEnabled && _BRPeerManagerAnyDandelionPeer(manager) != NULL;
    MGR_UNLOCK(manager);
    return r;
}

int BRPeerManagerStemPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                               void (*callback)(void *info, int error))
{
    assert(manager != NULL && tx != NULL);
    if (! BRTransactionIsSigned(tx)) return 0;   // let the flood path report EINVAL
    MGR_LOCK(manager);

    if (! manager->isConnected) { MGR_UNLOCK(manager); return 0; }

    BRPeer *stem = manager->dandelionEnabled ? _BRPeerManagerAnyDandelionPeer(manager) : NULL;
    if (! stem) { MGR_UNLOCK(manager); return 0; }   // caller floods instead

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
    MGR_UNLOCK(manager);
    return 1;
}

void BRPeerManagerFluffTx(BRPeerManager *manager, UInt256 txHash)
{
    assert(manager != NULL);
    MGR_LOCK(manager);

    BRTransaction *tx = NULL;
    for (size_t i = array_count(manager->publishedTx); i > 0; i--) {
        if (UInt256Eq(manager->publishedTx[i - 1].tx->txHash, txHash)) {
            tx = manager->publishedTx[i - 1].tx; break;
        }
    }
    if (! tx) { MGR_UNLOCK(manager); return; }
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
    MGR_UNLOCK(manager);
}

void BRPeerManagerPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                            void (*callback)(void *info, int error))
{
    assert(manager != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));
    if (tx) MGR_LOCK(manager);
    
    if (tx && ! BRTransactionIsSigned(tx)) {
        MGR_UNLOCK(manager);
        BRTransactionFree(tx);
        tx = NULL;
        if (callback) callback(info, EINVAL); // transaction not signed
    }
    else if (tx && ! manager->isConnected) {
        int connectFailureCount = manager->connectFailureCount;

        MGR_UNLOCK(manager);

        if (connectFailureCount >= MAX_CONNECT_FAILURES ||
            (manager->networkIsReachable && ! manager->networkIsReachable(manager->info))) {
            BRTransactionFree(tx);
            tx = NULL;
            if (callback) callback(info, ENOTCONN); // not connected to bitcoin network
        }
        else MGR_LOCK(manager);
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

        MGR_UNLOCK(manager);
    }
}

// number of connected peers that have relayed the given unconfirmed transaction
size_t BRPeerManagerRelayCount(BRPeerManager *manager, UInt256 txHash)
{
    size_t count = 0;

    assert(manager != NULL);
    assert(! UInt256IsZero(txHash));
    MGR_LOCK(manager);
    
    for (size_t i = array_count(manager->txRelays); i > 0; i--) {
        if (! UInt256Eq(manager->txRelays[i - 1].txHash, txHash)) continue;
        count = array_count(manager->txRelays[i - 1].peers);
        break;
    }
    
    MGR_UNLOCK(manager);
    return count;
}

// frees memory allocated for manager
// Serialize the penalty set so it survives a process restart. Without this the set is
// session-scoped, and every cold start re-dials peers the previous session had already
// learned were behind — the "one peer dialled 122x" churn, once per launch. Returns
// bytes written, 0 if the buffer is too small (never a truncated blob).
size_t BRPeerManagerSerializePenalties(BRPeerManager *manager, uint8_t *buf, size_t bufLen)
{
    size_t written, count;

    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    count = manager->penaltyCount < PEER_PENALTY_MAX ? manager->penaltyCount : PEER_PENALTY_MAX;
    written = BRPeerPenaltySerialize(manager->penaltyAddr, manager->penaltyPort, manager->penaltyUntil,
                                     count, time(NULL), buf, bufLen);
    pthread_mutex_unlock(&manager->lock);
    return written;
}

// Restore penalties saved by BRPeerManagerSerializePenalties, dropping any whose window
// has since lapsed. Replaces the live set rather than merging: it is only called before
// the first dial pass, when the live set is empty. Returns the number restored.
size_t BRPeerManagerLoadPenalties(BRPeerManager *manager, const uint8_t *buf, size_t bufLen)
{
    size_t loaded;

    assert(manager != NULL);
    pthread_mutex_lock(&manager->lock);
    loaded = BRPeerPenaltyDeserialize(buf, bufLen, time(NULL), manager->penaltyAddr, manager->penaltyPort,
                                      manager->penaltyUntil, PEER_PENALTY_MAX);
    manager->penaltyCount = loaded;
    pthread_mutex_unlock(&manager->lock);
    return loaded;
}

void BRPeerManagerFree(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
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
    MGR_UNLOCK(manager);
    pthread_mutex_destroy(&manager->lock);
    free(manager);
}

// --- BIP 158 public API ---------------------------------------------------

void BRPeerManagerSetSyncMode(BRPeerManager *manager, BRSyncMode mode)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->syncMode = mode;
    _BRPeerManagerRefreshCachedStatus(manager);
    MGR_UNLOCK(manager);
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
    CF_PHASE_START(_floorT0);
    size_t _floorSteps = 0;
    if (!b) return 0;
#ifdef CF_KAT_COUNT_FLOOR_WALKS
    // Host-KAT-only walk counter (never defined in any production build). The
    // memo below exists to keep this at ONE walk per changed chain view; a gate
    // that cannot see the walk COUNT could not tell a memo from 64 descents, and
    // "walk cost invisible at test scale" is how a perf regression ships green.
    _cfBlockFloorWalks++;
#endif
    for (;;) {
        BRMerkleBlock *prev = BRSetGet(manager->blocks, &b->prevBlock);
        if (!prev) break;
        b = prev;
        _floorSteps++;
    }
    // This descent is O(resident) and runs with manager->lock HELD. The memo above cannot
    // absorb it during active sync — its key includes the resident block COUNT, which changes on
    // every block-add — and three call sites (:3071, :4492, :4869) skip the memo entirely. Log
    // the step count alongside the time so a slow walk is distinguishable from a slow machine.
    CF_PHASE_END(_floorT0, "BlockFloor descent", "steps=%zu resident=%zu floor=%u",
                 _floorSteps, BRSetCount(manager->blocks), b->height);
    return b->height;
}

// F1: _BRPeerManagerBlockFloor, memoized for as long as the chain view that
// determines it is unchanged. See the floorMemo* field comments in
// BRPeerManagerStruct for the invalidation argument. Caller must hold
// manager->lock (it reads/writes the memo fields and walks manager->blocks).
static uint32_t _BRPeerManagerBlockFloorCached(BRPeerManager *manager)
{
    BRMerkleBlock *tip = manager->lastBlock;
    if (! tip) return 0;                       // no chain: nothing to clamp against
    size_t n = BRSetCount(manager->blocks);
    if (manager->floorMemoValid &&
        manager->floorMemoBlocks     == manager->blocks &&
        manager->floorMemoBlockCount == n &&
        manager->floorMemoTip        == tip &&
        manager->floorMemoTipHeight  == tip->height) {
        return manager->floorMemoFloor;
    }
    // MEMO MISS. The key includes floorMemoBlockCount, and the resident count changes on EVERY
    // block-add — so during active sync this memo can essentially never hit. The walk itself is
    // instrumented (see _BRPeerManagerBlockFloor), which also covers the THREE call sites that
    // bypass this wrapper entirely (:3071, :4492, :4869) and pay a full descent every time.
    uint32_t floorH = _BRPeerManagerBlockFloor(manager);
    manager->floorMemoBlocks     = manager->blocks;
    manager->floorMemoBlockCount = n;
    manager->floorMemoTip        = tip;
    manager->floorMemoTipHeight  = tip->height;
    manager->floorMemoFloor      = floorH;
    manager->floorMemoValid      = 1;
    return floorH;
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

    // Capture the scan frontier BEFORE Init wipes it (paced-convoy C-1): the
    // "historical gap is intentionally skipped" line above dates from the bloom era
    // ("those blocks were already scanned by bloom in prior sessions") and bloom was
    // excised in v4.0.0 — nothing re-covers that gap now, so it must be SURFACED
    // rather than silently discarded.
    uint32_t lowestBefore = _cfConvoyScanArmed(manager)
                            ? BRCFScanLedgerLowestNeededHeight(&manager->cfLedger) : 0;
    if (lowestBefore > 0 && lowestBefore < floor) {
        _BRPeerManagerSurfaceUnscannableLocked(manager, lowestBefore, floor,
                                               "CF chain floor re-anchor");
        return 0;
    }
    uint32_t restart = (lowestBefore > floor) ? lowestBefore : floor;

    BRCompactFilterChainFree(manager->compactFilterChain);
    manager->compactFilterChain = NULL;
    // Arm auto-fetch so the chain-less driver resolves `next` to the floor (not
    // genesis) and the lazy-create in _peerRelayedCFHeaders uses it.
    manager->autoFetchCFiltersEnabled  = 1;
    manager->autoFetchCFiltersStart    = restart;
    manager->autoFetchCFiltersThrough  = restart > 0 ? restart - 1 : 0;
    BRCFScanLedgerInit(&manager->cfLedger, restart);
    _BRPeerManagerClearSolicitedBlocksLocked(manager); // C1: in-flight solicitations belong to the scan just replaced
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
    // isConvoyAdvance=0: RECOVERY. The re-anchor just tore the CF chain down and
    // rebuilt the ledger at the floor; this send is how the rebuilt chain gets
    // its first batch. Gating it would strand the wallet in the very stall the
    // re-anchor exists to escape.
    BRPeer *fp = _BRPeerManagerAnyFilterCapablePeer(manager);
    if (fp) _BRPeerManagerRequestNextCFHeaders(manager, fp, /*isConvoyAdvance=*/0);
    return 1;
}

int BRPeerManagerReanchorCompactFilterChainAtFloor(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    int r = _BRPeerManagerReanchorAtFloorLocked(manager, 0);
    MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);
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
    MGR_UNLOCK(manager);
    return sent;
}

void BRPeerManagerSetCompactFilterChain(BRPeerManager *manager, BRCompactFilterChain *chain)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    if (manager->compactFilterChain && manager->compactFilterChain != chain) {
        BRCompactFilterChainFree(manager->compactFilterChain);
    }
    manager->compactFilterChain = chain;
    MGR_UNLOCK(manager);
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
    MGR_LOCK(manager);
    manager->saveFilterHeadersInfo = info;
    manager->saveFilterHeaders = saveFilterHeaders;
    MGR_UNLOCK(manager);
}

// ---- CF scan-completeness ledger accessors (Phase 1: guarded reads) --------
// These take manager->lock for every read; the lock-free bridge mirror (like the
// cachedCFTip pattern) is a later sequence. Safe on a zeroed/never-armed ledger.

void BRPeerManagerCFLedgerCounts(BRPeerManager *manager, uint32_t *scannedThrough, uint32_t *outstanding,
                                 uint32_t *gaveUp, uint32_t *pending)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    if (scannedThrough) *scannedThrough = BRCFScanLedgerScannedThrough(&manager->cfLedger);
    if (outstanding)    *outstanding    = (uint32_t)BRCFScanLedgerOutstandingCount(&manager->cfLedger);
    if (gaveUp)         *gaveUp         = (uint32_t)BRCFScanLedgerGaveUpCount(&manager->cfLedger);
    if (pending)        *pending        = (uint32_t)manager->cfLedger.pendingCount;
    MGR_UNLOCK(manager);
}

size_t BRPeerManagerCFLedgerHoleRanges(BRPeerManager *manager, uint32_t *outStarts, uint32_t *outEnds, size_t cap)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    size_t n = BRCFScanLedgerHoleRanges(&manager->cfLedger, outStarts, outEnds, cap);
    MGR_UNLOCK(manager);
    return n;
}

size_t BRPeerManagerCFLedgerSerialize(BRPeerManager *manager, uint8_t *buf, size_t buflen)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    size_t n = BRCFScanLedgerSerialize(&manager->cfLedger, buf, buflen);
    MGR_UNLOCK(manager);
    return n;
}

int BRPeerManagerCFLedgerRestore(BRPeerManager *manager, const uint8_t *buf, size_t buflen)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    int ok = BRCFScanLedgerParse(&manager->cfLedger, buf, buflen);
    // C1: the restored ledger is a different scan state than whatever this manager had in
    // flight — a solicitation recorded against the old one must not complete a hole in it.
    _BRPeerManagerClearSolicitedBlocksLocked(manager);
    MGR_UNLOCK(manager);
    return ok;
}

// ---- CF scan-frontier + abandonment accessors (paced-convoy fetch, Task 1) -
// Lock -> read the ledger's CF-retention scan-floor API -> unlock, same shape
// as the Phase 1 accessors above. These are the frontier reads the paced-
// convoy gate/driver/valve/watchdogs poll.

uint32_t BRPeerManagerLowestNeededHeight(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    uint32_t h = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
    MGR_UNLOCK(manager);
    return h;
}

uint32_t BRPeerManagerAbandonedBelow(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    uint32_t h = BRCFScanLedgerAbandonedBelow(&manager->cfLedger);
    MGR_UNLOCK(manager);
    return h;
}

uint32_t BRPeerManagerScanLedgerStart(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    uint32_t h = BRCFScanLedgerStartHeight(&manager->cfLedger);
    MGR_UNLOCK(manager);
    return h;
}

size_t BRPeerManagerAbandonedCount(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    uint32_t start = manager->cfLedger.start;
    uint32_t abandonedBelow = manager->cfLedger.abandonedBelow;
    MGR_UNLOCK(manager);
    return (abandonedBelow > start) ? (size_t)(abandonedBelow - start) : 0;
}

// The honest counterpart to BRPeerManagerAbandonedCount. See the field comment on
// cfAbandonedHeightsTotal for why the older accessor cannot answer this question:
// it derives from (abandonedBelow - start), and the three ledger re-Init paths reset
// `start` to the new floor, so it reads ZERO right after the biggest abandonment
// event and over-reports (the whole span below the watermark, including heights that
// were legitimately scanned) the rest of the time. Neither accessor is being changed
// — the UI already routes around the old one deliberately (it renders a RANGE, never
// a count) and the drive KAT pins its span semantics. This one is additive.
size_t BRPeerManagerAbandonedHeightsTotal(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    size_t total = manager->cfAbandonedHeightsTotal;
    MGR_UNLOCK(manager);
    return total;
}

void BRPeerManagerCloseLedgerSummary(BRPeerManager *manager, char *buf, size_t bufLen)
{
    assert(manager != NULL);
    if (! buf || bufLen == 0) return;
    buf[0] = '\0';
    MGR_LOCK(manager);
    _BRPeerManagerFormatCloseLedger(manager, buf, bufLen);
    MGR_UNLOCK(manager);
}

// B2-valve/watchdog ordering signal (see the header for the full contract and the
// MANDATORY suppression bound). Returns cycles+1 of the frontier-pinning hole the
// valve currently owns, or 0 when the valve owns nothing.
//
// TWO states count as "pending" — the watchdog defers while a gaveUp abandonment is
// "pending re-arm/abandonment", and a re-arm cycle IN FLIGHT is the larger half of
// that window (~7.5 min of rotated retry vs. the instant of the decision itself):
//   (a) PARKED: the pinning hole is a gaveUp entry — the valve decides on it at the
//       next KeepAlive tick (re-arm, or abandon once refusal is proven);
//   (b) RE-ARM IN FLIGHT: the pinning hole is OUTSTANDING with rearmCycles > 0 —
//       the valve put it back for a fresh retry cycle and the residual driver is
//       rotating it across the connected CF peers right now.
// An ordinary outstanding hole (rearmCycles == 0) is NOT the valve's — the residual
// driver owns it and the watchdog is right to keep watching it — so it reads 0.
//
// WHY THE rearmCycles > 0 EXCLUSION IS LOAD-BEARING (fix-wave C2). The lab dropped
// it, making this "1 whenever ANY height is in flight". Every forward cfilter batch
// inserts its whole requested range as outstanding, so on a healthy descent this
// read is 1 essentially always — and Kotlin conjoins it into EVERY recovery branch.
// The corrupt-cfheader wedge (every honest cfilter fails verification and is LEFT
// outstanding by design) then reads "pending" forever and stands down the very heal
// built for it. This accessor must report RETRY OWNERSHIP, not hole existence.
//
// "Pinning" is deliberately the SAME shape the valve itself uses in
// BRPeerManagerKeepAlive (the LOWEST hole of either kind, since _cfLedgerAdvance
// caps scannedThrough at min(outstanding[0], gaveUp[0]) - 1) rather than a
// comparison against LowestNeededHeight: LowestNeededHeight reads scannedThrough,
// which only moves in MarkEvaluated, so a floor gap that was never evaluated would
// leave it BELOW the hole and this accessor would report "nothing pending" for a
// hole the valve is actively working. Keep the two in step.
uint32_t BRPeerManagerHasPendingAbandonment(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);

    const BRCFScanLedger *l = &manager->cfLedger;
    uint32_t gvH = 0, pending = 0;
    uint8_t  gvCycles = 0;
    int      haveGaveUp = BRCFScanLedgerLowestGaveUp(l, &gvH, &gvCycles, NULL);
    int      haveOut    = (l->outstandingCount > 0);
    uint32_t outH       = haveOut ? l->outstanding[0].height      : 0;
    uint8_t  outCycles  = haveOut ? l->outstanding[0].rearmCycles : 0;

#ifdef CF_PENDING_ANY_HOLE_UNFIXED
    // RED-before-green shape ONLY (never in a production build): the lab's
    // existence-keyed accessor. Any hole at all reads "pending", so the signal is 1
    // through a healthy descent and every watchdog tier that conjoins it is dead.
    outCycles = 1;
    gvCycles  = 0;
#endif

    // uint8_t + 1 widened to uint32_t: cannot wrap, so a saturated cycle counter can
    // never be misread as "not pending".
    if (haveGaveUp && (! haveOut || gvH < outH)) {
        pending = (uint32_t)gvCycles + 1;    // (a) parked, awaiting the valve's decision
    }
    else if (haveOut && (! haveGaveUp || outH < gvH) && outCycles > 0) {
        pending = (uint32_t)outCycles + 1;   // (b) a valve-granted re-arm cycle in flight
    }

    MGR_UNLOCK(manager);
    return pending;
}

void BRPeerManagerSetSaveCFLedger(BRPeerManager *manager, void *info,
                                  void (*callback)(void *info, const uint8_t *bytes, size_t len))
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->saveCFLedgerInfo = info;
    manager->saveCFLedger = callback;
    MGR_UNLOCK(manager);
}

// Lock-held internal helper. Caller must hold manager->lock. Returns the
// number of blocks actually requested or 0 if no eligible peer was found.
static int _BRPeerManagerPeerCanServeFilters(BRPeer *p)
{
    return p && BRPeerConnectStatus(p) == BRPeerStatusConnected &&
           BRPeerIsSocketOpen(p) &&
           (p->services & SERVICES_NODE_COMPACT_FILTERS) == SERVICES_NODE_COMPACT_FILTERS;
}

// Send getcfilters([startHeight..stopHeight]) with a PRE-RESOLVED stop hash —
// the walk-free half of _BRPeerManagerRequestCFiltersLocked. Same contract as
// the resolving wrapper below, except the caller supplies stopHash (resolved
// once per residual tick in the Pass B batch descent) instead of this function
// walking manager->blocks. Returns the number of filters requested (0 on any
// no-send condition: empty range, bloom mode, unresolvable stop, or no peer).
static size_t _BRPeerManagerRequestCFiltersWithStopHashLocked(BRPeerManager *manager,
                                                             uint32_t startHeight, uint32_t stopHeight,
                                                             UInt256 stopHash, BRPeer *preferred)
{
    if (stopHeight < startHeight) return 0;
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return 0;

    // The caller resolved stopHash at exactly `stopHeight`. Every caller keeps
    // the range within one getcfilters window (the resolving wrapper clamps to
    // startHeight + MAX_CFILTERS_RESULTS - 1 BEFORE resolving; the residual peek
    // coalesces at most CF_REREQ_MAX_RANGE == MAX_CFILTERS_RESULTS heights), so
    // stopHash always corresponds to the height that goes on the wire. A stop
    // beyond that window would mean the hash is for a DIFFERENT height than the
    // getcfilters stop — precisely the silent wrong-range fetch the single-
    // descent design rejects a persistent index to avoid; assert it can't happen.
    assert(stopHeight <= startHeight + (MAX_CFILTERS_RESULTS - 1));

    if (UInt256IsZero(stopHash)) return 0;   // stop height not in the in-memory window -> don't send (as before)

#ifndef CF_REQ_FLOOR_UNFIXED
    // ---- F1: NEVER ASK BELOW OUR OWN RESIDENT BLOCK FLOOR --------------------
    //
    // The getcfilters STOP is a hash, so an unresolvable stop is already refused
    // above. But startHeight goes on the wire as a BARE INTEGER, and nothing here
    // checked it against the in-memory block window. So a range that STRADDLES the
    // floor (start below it, stop above it) was sent verbatim: the stop resolved,
    // the send went out, and the peer honestly answered with filters for heights
    // whose HEADERS WE NO LONGER HOLD. _peerRelayedCFilter's BRSetGet then misses,
    // the arrival takes the "header-race hole ... left outstanding" branch and the
    // bytes are BUFFERED — against the 256 KiB budget, evicting live buffered
    // filters — where they can never drain, because the block they need is gone.
    // We asked for something we had already made ourselves unable to use.
    //
    // Clamping start UP to the floor keeps the servable part of the range on the
    // wire (never suppress the whole send: that would strand the heights we CAN
    // still serve) and drops only the part we could not have evaluated anyway. If
    // the ENTIRE range is below the floor there is nothing askable — return 0, the
    // same "nothing went on the wire" answer the unresolvable-stop refusal gives,
    // so Pass C's else-branch taints the retry cycle (MarkOffersMissedLivePeer)
    // instead of burning an attempt on an offer that never happened.
    //
    // THIS IS NOT AN ESCAPE VALVE AND MUST NOT BECOME ONE. It changes what we ASK
    // for; it does not advance any cursor and does not touch cfLedger. Heights
    // below the floor stay outstanding and remain owned by the paths that surface
    // them (_BRPeerManagerSurfaceUnscannableLocked → abandonedBelow + WARN).
    // Nothing here may ever mark them scanned.
    //
    // Cost: _BRPeerManagerBlockFloorCached, so a 64-range residual tick pays ONE
    // O(chainLen) descent, not 64 (see the floorMemo* fields).
#ifdef CF_REQ_FLOOR_NO_MEMO
    // Un-memoized shape, built ONLY by the host KAT's walk-cost red-before-green
    // gate (never defined in a production build): one full O(chainLen) descent PER
    // SEND, which is what the memo exists to prevent. The clamp itself is
    // unchanged, so what that build proves red is the MEMO, not the arithmetic.
    uint32_t reqFloor = _BRPeerManagerBlockFloor(manager);
#else
    uint32_t reqFloor = _BRPeerManagerBlockFloorCached(manager);
#endif
    if (reqFloor > 0 && startHeight < reqFloor) {
        // Whole range below the floor -> nothing askable. DEFENSIVE, not reachable
        // through today's callers: both of them resolve stopHash by descending from
        // lastBlock, so a stop hash that RESOLVED is at/above the floor by
        // construction and a fully-sub-floor range is already refused by the
        // UInt256IsZero check above. This exists because the caller SUPPLIES the
        // hash here — a future caller with its own hash source must not be able to
        // slip a wholly-unservable send through.
        if (stopHeight < reqFloor) return 0;
        startHeight = reqFloor;
    }
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
        for (size_t i = array_count(manager->connectedPeers); i > 0; i--) {
            BRPeer *p = manager->connectedPeers[i - 1];
            if (! _BRPeerManagerPeerCanServeFilters(p)) continue;
            target = p;
            break;
        }
    }
    if (!target) return 0;

    BRPeerSendGetCFilters(target, filterType, startHeight, stopHash);
    return stopHeight - startHeight + 1;
}

static size_t _BRPeerManagerRequestCFiltersLocked(BRPeerManager *manager,
                                                  uint32_t startHeight, uint32_t stopHeight,
                                                  BRPeer *preferred)
{
    if (stopHeight < startHeight) return 0;
    if (manager->syncMode == BR_SYNC_MODE_BLOOM_ONLY) return 0;

    uint32_t cap = startHeight + (MAX_CFILTERS_RESULTS - 1);
    if (stopHeight > cap) stopHeight = cap;

    // Resolve the stop hash HERE (the deep, ≤64/tick walk on the residual path)
    // then delegate to the pre-resolved sibling. The clamp above guarantees the
    // sibling's window assert holds. The residual batch skips this wrapper and
    // resolves all its stops in one descent (Pass B) instead.
    UInt256 stopHash = _BRPeerManagerBlockHashAtHeight(manager, stopHeight);
    return _BRPeerManagerRequestCFiltersWithStopHashLocked(manager, startHeight, stopHeight, stopHash, preferred);
}

size_t BRPeerManagerRequestCompactFilters(BRPeerManager *manager,
                                          uint32_t startHeight, uint32_t stopHeight)
{
    if (!manager) return 0;
    MGR_LOCK(manager);
    size_t n = _BRPeerManagerRequestCFiltersLocked(manager, startHeight, stopHeight, NULL);
    MGR_UNLOCK(manager);
    return n;
}

void BRPeerManagerEnableAutoCompactFilterFetch(BRPeerManager *manager, uint32_t startHeight)
{
    assert(manager != NULL);
    MGR_LOCK(manager);

    // Remember what the APP asked for, before the clamp below can move it. On a
    // RESUME the clamp lands on the saved-blocks tip (see C-1), so a ledger that is
    // Init'd here and then NOT restored would start ~CF_CONVOY_WINDOW above the
    // requested floor with nothing recording that fact. The resume reconciliation
    // reads this to tell that case from a ledger that legitimately starts here.
    manager->autoFetchCFiltersRequested = startHeight;

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
    //
    // NOTE (2026-08-02, Note 8): do NOT "fix" a stalled scan by arming at startHeight + 1.
    // The anchor height looked unservable for 10 minutes (4 requests, 0 answers) but was
    // DELIVERED on the 5th attempt; the frontier then unstuck on its own with no
    // abandonment. The stall was the forward-gap gate freezing the drive while the
    // residual driver slowly retried, not anything special about the anchor. Skipping it
    // would silently drop a height the wallet does scan.
    BRCFScanLedgerInit(&manager->cfLedger, startHeight);
    _BRPeerManagerClearSolicitedBlocksLocked(manager); // C1: in-flight solicitations belong to the scan just replaced
#if CF_LEDGER_DRIVE_REREQUEST
    // Explicit/defensive (Task 5 EDIT 4): re-arm must not carry stale buffered raw
    // filter bytes from before this (re-)enable — Init already frees them internally.
    BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
    MGR_UNLOCK(manager);
}

void BRPeerManagerDisableAutoCompactFilterFetch(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
    manager->autoFetchCFiltersEnabled = 0;
    manager->autoFetchCFiltersStart = 0;
    manager->autoFetchCFiltersThrough = 0;
    manager->autoFetchCFiltersRequested = 0;   // hygiene: no stale requested floor for the next arm
    _BRPeerManagerClearSolicitedBlocksLocked(manager); // C1: nothing may complete a height after the scan is disarmed
#if CF_LEDGER_DRIVE_REREQUEST
    // Hygiene (Task 5 EDIT 4): a disable must not leave stale buffered bytes
    // lingering — unlike the re-anchor/re-arm sites, Disable does NOT call
    // BRCFScanLedgerInit, so this is the only place that clears them here.
    BRCFScanLedgerClearFilterBuffer(&manager->cfLedger);
#endif
    MGR_UNLOCK(manager);
}

// Runtime-readable convoy constants — see the contract in BRPeerManager.h. The
// Kotlin watchdogs DERIVE their copies from these so there is no hand-mirrored
// second value to drift when the operator tunes CF_CONVOY_REARM_MAX.
uint32_t BRPeerManagerConvoyWindow(void)   { return (uint32_t)CF_CONVOY_WINDOW; }
uint32_t BRPeerManagerConvoyRearmMax(void) { return (uint32_t)CF_CONVOY_REARM_MAX; }

uint32_t BRPeerManagerGetAutoFetchCFiltersStart(BRPeerManager *manager)
{
    if (!manager) return 0;
    MGR_LOCK(manager);
    uint32_t height = manager->autoFetchCFiltersStart;
    MGR_UNLOCK(manager);
    return height;
}

uint32_t BRPeerManagerGetAutoFetchCFiltersThrough(BRPeerManager *manager)
{
    if (!manager) return 0;
    MGR_LOCK(manager);
    uint32_t height = manager->autoFetchCFiltersThrough;
    MGR_UNLOCK(manager);
    return height;
}

// ---- Resume cursor reconciliation (paced-convoy fetch, Task 4) -------------
// See the contract comment on the declaration in BRPeerManager.h. Guarded by
// RESUME_SNAP_UNFIXED so the host KAT can build the pre-fix shape (the snap
// compiles to a no-op, cursor stays at birth-1) for its red-before-green gate --
// same #ifndef-a-fix-flag pattern as CONVOY_NO_B1_DRIVER above.
void BRPeerManagerSnapAutoFetchThroughToScanFrontier(BRPeerManager *manager)
{
    assert(manager != NULL);
    MGR_LOCK(manager);
#ifndef RESUME_SNAP_UNFIXED

    // ---- C-1 STEP 1: surface anything the resumed manager can never scan -----
    //
    // BRPeerManagerEnableAutoCompactFilterFetch ran BEFORE the ledger restore, and
    // on a resume its clamp lands at or just under the SAVED-BLOCKS TIP: the deep
    // birth height does not resolve, because BRPeerManagerNewEx only makes the
    // persisted [tip-(SAVE_BLOCK_COUNT-1) .. tip] run resident (fix wave R2 —
    // before that it was ONE saved block and the floor was the tip itself). So
    // after the restore the scan frontier can still sit ~CF_CONVOY_WINDOW BELOW
    // the block floor (10000 >> 300), and that
    // band is unservable for the whole session in both directions (no resolvable
    // getcfilters stop hash; a volunteered cfilter would be dropped by
    // _peerRelayedCFilter as an unknown block). Left alone it is either a silent
    // ~CF_CONVOY_WINDOW skip (the forward fetch starts at the clamped cursor and
    // _cfLedgerAdvance sails scannedThrough up to it) or an invisible permanent pin
    // (a restored outstanding hole whose stop hash never resolves never burns an
    // attempt, so it can never reach gaveUp and the B2 valve can never see it).
    // Surface it instead.
    uint32_t lowest = BRCFScanLedgerLowestNeededHeight(&manager->cfLedger);
#ifndef CONVOY_C1_UNFIXED
    if (_cfConvoyScanArmed(manager)) {
        // Low edge of the band. Normally the restored scan frontier. But if the
        // ledger's own start is ABOVE the floor the app asked for, no ledger was
        // restored over the clamped Init at all, so nothing has ever covered
        // [requested .. start-1] either — take the requested floor as the low edge.
        uint32_t lo = lowest;
        if (manager->autoFetchCFiltersRequested > 0 &&
            manager->cfLedger.start > manager->autoFetchCFiltersRequested) {
            lo = manager->autoFetchCFiltersRequested;
        }
        uint32_t floor = _BRPeerManagerBlockFloor(manager);
        if (lo > 0 && floor > 0 && lo < floor) {
            _BRPeerManagerSurfaceUnscannableLocked(manager, lo, floor,
                                                   "resume frontier below saved block window");
            manager->autoFetchCFiltersStart = lo;
            manager->autoFetchCFiltersThrough = lo - 1;
            MGR_UNLOCK(manager);
            return;
        }
    }
#endif

    // ---- C-1 STEP 2: reconcile the forward-fetch window to that frontier -----
    //
    // RAISE (Task 4): the cursor was armed at birth-1 before the restore, so a
    // resumed descent must not re-request already-scanned history from birth.
    // lowest - 1, NEVER lowest itself -- reqStart is autoFetchCFiltersThrough+1,
    // so snapping to `lowest` would make the next forward fetch start at
    // lowest+1 and silently skip height `lowest` forever. Guard lowest==0 (an
    // unarmed ledger).
    //
    // LOWER (C-1): the clamp can leave BOTH `start` and the cursor ABOVE the
    // restored frontier, and every forward-fetch site clamps reqStart UP to
    // autoFetchCFiltersStart — so a raise-only snap can never pull them back and
    // the next request starts at the clamped tip, which is exactly the silent skip.
    // The cursor may never sit above what was actually REQUESTED either
    // (cfLedger.requestedThrough is the persisted truth): a cursor above it means
    // the gap in between was never requested, and recording a non-contiguous range
    // is what lets _cfLedgerAdvance sail. Order matters: clamp DOWN to
    // requestedThrough first, then UP to lowest-1, so the result is always >= the
    // frontier.
    if (lowest > 0) {
#ifndef CONVOY_C1_UNFIXED
        if (manager->autoFetchCFiltersStart > lowest) manager->autoFetchCFiltersStart = lowest;
        if (manager->autoFetchCFiltersThrough > manager->cfLedger.requestedThrough) {
            manager->autoFetchCFiltersThrough = manager->cfLedger.requestedThrough;
        }
#endif
        if ((lowest - 1) > manager->autoFetchCFiltersThrough) {
            manager->autoFetchCFiltersThrough = lowest - 1;
        }
    }
#endif
    MGR_UNLOCK(manager);
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

