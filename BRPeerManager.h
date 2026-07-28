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

// Max simultaneous peer connections. Raised 5 -> 8 (Bitcoin Core's default
// outbound) to improve discovery of scarce compact-filter (BIP157/158) peers on
// mainnet: with only ~a handful of filter-serving nodes, 5 slots were too few to
// reliably hold a synced filter peer. Revisit toward 12-16 as the filter-node
// population grows (oracle-bootstrap). Bloom-mode sync is unaffected.
#define PEER_MAX_CONNECTIONS 8

// ANR fix #2 (native peer-manager keepalive lock-starvation,
// .superpowers/sdd/anr-fix2-native-design.md). Robustness eviction for peers that are
// dead but not currently being pinged (e.g. NAT silently dropped the return path, no
// outbound stall yet to trip the send-path eviction). BRPeerManagerKeepAlive schedules
// a real disconnect for any connected peer whose last inbound read
// (BRPeerLastRecvTime) is older than this, replacing the DBL_MAX idle sentinel
// _BRPeerDidConnect sets. Safely longer than the ~10s keepalive tick interval so a
// responsive peer -- which gets pinged, and thus reads a pong, every tick -- never
// trips it.
#define PEER_INBOUND_IDLE_LIMIT 90.0

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

/* CF-retention memory ceiling (scan-floor retention). The retained block-header
   span is bounded to this many blocks BELOW the chain tip. gaveUp-inclusive
   retention means a single permanent (retry-exhausted) hole would otherwise pin
   the retention floor forever — the span is NOT self-bounding — so this ceiling
   is a ROUTINE bound, not a rare backstop. When the scan floor would sit deeper
   than the tip minus this span, _BRPeerManagerClearMemory abandons ONLY
   retry-exhausted (gaveUp) heights below the clamp (NEVER a still-outstanding,
   recoverable hole) and warn-logs the VISIBLE abandonment. ~6.6 MB at
   ~220 B/header. #ifndef-guarded so the host retention KAT can -D-override it
   small to exercise the ceiling without building a 30k-block chain. */
#ifndef CF_RETENTION_MAX_SPAN
#define CF_RETENTION_MAX_SPAN 30000
#endif

/* PACED-CONVOY FETCH WINDOW (spec 2026-07-28-paced-convoy-fetch-design.md,
   Parts A + C). The maximum number of blocks the block-header frontier
   (manager->lastBlock->height) and the cfheader frontier
   (BRCompactFilterChainNextHeight - 1) may lead the CF SCAN frontier
   (BRCFScanLedgerLowestNeededHeight) by. Beyond it the two TIP-RACING
   continuations -- BRPeer.c's CF-only 2000-header continuation and
   _BRPeerManagerRequestNextCFHeaders' clean-append advance -- are suppressed, so
   the header/cfheader/scan frontiers climb birth->tip as one convoy instead of
   the headers fast-forwarding to the tip and filling manager->blocks with
   [birth..tip] before the scan has processed anything (the deep-restore OOM).
   RECOVERY and SYNC-START sends are NEVER gated -- suppressing one deadlocks the
   convoy from the other side.

   The value is a floor-derived bound, not a magic number: it must exceed
   (1) the scan lookahead CF_OUTSTANDING_MAX(4096) + MAX_CFILTERS_RESULTS(1000),
   (2) the cfheader quantum MAX_CFHEADERS_RESULTS(2000), and
   (3) a re-kick-latency margin at DGB's ~15 s blocks.
   At 10000 the resident header span is ~(W + CLEAR_MEM_CF_RETENTION_MARGIN)
   * ~220 B ~= 2.2 MB, FLAT at any restore depth, and the tip-down prevBlock walk
   is bounded to ~W by construction. */
#define CF_CONVOY_WINDOW 10000

/* PACED-CONVOY driver B1.3 -- the getheaders re-kick's RATE LIMIT (spec Part B1
   step 3). KeepAlive re-issues the header continuation BRPeer.c holds while the
   window is full; the trigger (a header frontier frozen across a whole ~10 s
   tick) is necessary but NOT sufficient, because "frozen" cannot distinguish
   "the continuation was suppressed and nothing is in flight" (re-kick wanted)
   from "a reply IS in flight and just hasn't been parsed yet" (re-kick harmful).
   BRPeer.c issues its continuation BEFORE the relay loop, so lastBlock does not
   move until the whole ~440 KB batch is parsed -- on a slow link that is minutes
   of "frozen". So the re-kick is additionally rate-limited by an interval that
   BACKS OFF while unproductive and RESETS the moment the header tip actually
   advances. Same 'delay = min(BASE << n, CAP), reset on progress' idiom the CF
   scan-ledger's residual re-request driver already uses (CF_REREQ_BASE_SECS /
   CF_REREQ_BACKOFF_CAP_SECS) -- deliberately not a new mechanism.

   Sequence: 30, 60, 120, 240, 480, 600, 600, ... An EPISODE ends -- and the
   interval resets to 30 -- on either of the two things that mean the accumulated
   penalty no longer describes reality: real header-tip progress (the chain is
   alive), or a GATED->open transition (a gated period issues no re-kicks, so it
   can neither earn a penalty nor carry one across; the reopen is served on the
   very next tick, which is what B1.3 exists for). Note those two are INDEPENDENT:
   the window can close and reopen from scanFrontier movement alone, with the
   header tip never advancing.

   TOO SHORT costs bandwidth, and it COMPOUNDS: each injected getheaders is
   answered with a full 2000-header batch, and because count >= 2000 every reply
   spawns its OWN independent, lockstep continuation chain that persists until
   the gate shuts it -- N re-kicks during one slow batch means N x ~2.2 MB of
   duplicate headers per window-open period, recurring on every re-open of a
   multi-hour deep restore, amplifying exactly on the slow mobile links the
   convoy exists to make cheap. It also has a STEADY-STATE leak: estimatedHeight
   is only ever RAISED, so a peer that advertised a height we never reach leaves
   lastBlock->height < estimatedHeight forever on a fully-synced wallet (where
   W_hdr ~ 0, i.e. the window is permanently open) -- at the bare 10 s tick that
   is a ~1.2 KB full-locator getheaders every 10 s forever (~10 MB/day upstream),
   each answered with 0 headers. The 600 s ceiling bounds that to ~170 KB/day.

   TOO LONG costs window-reopen recovery latency: after the scan climbs enough to
   re-open the window, the header frontier stays frozen until the next re-kick is
   due. BASE is what that path actually pays, because the previous batch landing
   is itself tip progress and RESETS the backoff -- so an ordinary descent always
   re-kicks at 30 s, never at the ceiling. At 30 s the header supply is ~4000
   headers per interval (the M-2 two-batch overshoot: BRPeer.c reads the gate
   flag one batch stale), i.e. ~133 heights/s, which stays ahead of the scan's
   ceiling of MAX_CFILTERS_RESULTS(1000) per ~10 s tick == 100 heights/s. So the
   convoy is never header-starved by this throttle. */
#define CF_CONVOY_HDR_REKICK_BASE_SECS 30
#define CF_CONVOY_HDR_REKICK_MAX_SECS  600

/* BIP 158 continuity-failure recovery. If this many DISTINCT peers fail the
   cfheaders continuity check against our current tip since the last successful
   append, our chain is the outlier (it diverged via unverified TOFU) — re-anchor
   instead of marking the (honest) peers misbehavin'. Bounded per session so a
   persistently-divergent peer can't loop forever. */
#define CF_CONTINUITY_REANCHOR_K   2
#define CF_CONTINUITY_REANCHOR_MAX 3

/* Floor of connected filter peers below which the cfheaders stall-recovery must
   NOT disconnect a peer. A batch no peer can serve (e.g. a contested range during
   a rescan) would otherwise shred the whole filter-peer pool to 0 one peer per
   rotation; keep at least this many so the keepalive can grow the pool instead of
   racing the shredder. */
#define CF_MIN_FILTER_PEERS 2
    
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
// void saveBlocks(void *, int, const uint8_t *bytes, size_t len) - called when blocks should be saved to the
//   persistent store. The core serializes the blocks UNDER its lock and hands the immutable `bytes` buffer (NOT
//   live block pointers), so the callback can do a slow JNI upcall without racing a concurrent reorg free.
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
                               void (*threadCleanup)(void *info));

// specifies a single fixed peer to use when connecting to the bitcoin network
// set address to UINT128_ZERO to revert to default behavior
void BRPeerManagerSetFixedPeer(BRPeerManager *manager, UInt128 address, uint16_t port);

// dynamically set the target peer connection count (full while catching up, fewer once synced);
// reducing gently disconnects the excess (never the download peer or the pinned own-node)
void BRPeerManagerSetMaxConnectCount(BRPeerManager *manager, size_t count);

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

// Own-node first-class pairing. Pin a user-paired node (addr:port) as a reserved,
// never-churn-evicted compact-filter peer that BRPeerManagerConnect always dials
// first. exclusive != 0 makes the dialer contact ONLY the pinned node. These take
// manager->lock internally; call them from the JNI layer (which holds PEER_GUARD).
void BRPeerManagerSetPinnedPeer(BRPeerManager *manager, UInt128 addr, uint16_t port, int exclusive);

// Clear any pinned own-node, reverting to normal dial/eviction behavior.
void BRPeerManagerClearPinnedPeer(BRPeerManager *manager);

// Compact-filter status of the peer at addr:port, for the own-node connectivity UI:
// one of BR_CF_PEER_{UNKNOWN,CONNECTING,CONNECTED_NOT_SERVING,SERVING} (see
// BRPeerCFStatus.h). SERVING means it has answered a cfheaders/cfilter this session.
int BRPeerManagerCompactFilterPeerStatus(BRPeerManager *manager, UInt128 addr, uint16_t port);

// connect to bitcoin peer-to-peer network (also call this whenever networkIsReachable() status changes)
void BRPeerManagerConnect(BRPeerManager *manager);

// disconnect from bitcoin peer-to-peer network (may cause syncStopped() or savePeers() callbacks to fire; NOT
// saveBlocks() — in this codebase saveBlocks fires only from _peerRelayedBlock, never from a disconnect)
void BRPeerManagerDisconnect(BRPeerManager *manager);

// send a keepalive ping to every connected peer so idle CF filter-peer connections don't get
// dropped by the remote node / NAT inactivity timeout (call periodically, e.g. every ~10-20s)
void BRPeerManagerKeepAlive(BRPeerManager *manager);

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

// Enable/disable Dandelion stem submission (default on). Thread-safe.
void BRPeerManagerSetDandelionEnabled(BRPeerManager *manager, int enabled);

// Register a peer address as Dandelion-capable (sourced from the seeder + the
// priority peer; there is no service bit to read). Idempotent, thread-safe.
void BRPeerManagerAddDandelionPeer(BRPeerManager *manager, UInt128 address);

// 1 if Dandelion is enabled AND a connected peer is Dandelion-capable.
int BRPeerManagerHasDandelionPeer(BRPeerManager *manager);

// Stem-submit a signed tx to ONE Dandelion-capable peer (sets is_dandelion=1 and
// invs only that peer; the peer's getdata then pulls the dandeliontx). Returns 1
// if stemmed, 0 if no capable peer was available (caller should then fall back to
// BRPeerManagerPublishTx for a normal flood). Do not BRTransactionFree(tx) after.
int BRPeerManagerStemPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info,
                               void (*callback)(void *info, int error));

// Re-broadcast (flood) a previously stem-submitted tx to all connected peers,
// clearing the dandelion flag. Idempotent; no-op if the tx isn't in the publish list.
void BRPeerManagerFluffTx(BRPeerManager *manager, UInt256 txHash);

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

// Current compact-filter chain tip height (0 if no chain yet). Used by
// the watchdog to detect "filter peers connected but not making progress."
uint32_t BRPeerManagerCFChainTipHeight(BRPeerManager *manager);

// Re-anchor the compact-filter chain at the block floor when cfTip is stuck
// below the downloaded chain (legacy deficit). Returns 1 if re-anchored.
int BRPeerManagerReanchorCompactFilterChainAtFloor(BRPeerManager *manager);

// Proactively re-issue a full-locator getheaders to all connected peers to un-stick
// a frozen block-header tip (all other getheaders senders are reactive). Called by
// the Kotlin tip-stall watchdog. Returns the peer count the request was sent to.
int BRPeerManagerRerequestHeadersFromTip(BRPeerManager *manager);

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

// ---- CF scan-completeness ledger (Phase 1: observe-only) -------------------
// Per-height BIP157/158 scan-completeness bookkeeping. The manager owns one
// ledger, populated under manager->lock by the CF request/eval/drop paths. In
// Phase 1 these accessors are read-only reporting for the UI/JNI; nothing here
// alters sync behavior. Each takes manager->lock for the duration of the call.

// Snapshot the ledger's scalar counts. Any out-pointer may be NULL to skip it.
void BRPeerManagerCFLedgerCounts(BRPeerManager *manager, uint32_t *scannedThrough, uint32_t *outstanding,
                                 uint32_t *gaveUp, uint32_t *pending);

// Coalesce the outstanding + gaveUp heights into ascending [start..end] ranges.
// Writes up to `cap` ranges into outStarts/outEnds; returns the number written.
size_t BRPeerManagerCFLedgerHoleRanges(BRPeerManager *manager, uint32_t *outStarts, uint32_t *outEnds, size_t cap);

// Serialize the ledger into buf. Returns the byte count the blob needs; writes it
// iff buflen is large enough (call with buf NULL / buflen 0 to size first).
size_t BRPeerManagerCFLedgerSerialize(BRPeerManager *manager, uint8_t *buf, size_t buflen);

// Restore a ledger blob produced by BRPeerManagerCFLedgerSerialize. Returns 1 on
// success, 0 on a garbled/short blob (ledger left empty for the caller to rebuild).
int BRPeerManagerCFLedgerRestore(BRPeerManager *manager, const uint8_t *buf, size_t buflen);

// Persistence hook. Called from inside the manager lock after each successful
// cfheaders extend, with the serialized ledger blob. Pass NULL to clear.
void BRPeerManagerSetSaveCFLedger(BRPeerManager *manager, void *info,
                                  void (*callback)(void *info, const uint8_t *bytes, size_t len));

// ---- CF scan-frontier + abandonment accessors (paced-convoy fetch, Task 1) -
// Read-only wrappers around the ledger's CF-retention scan-floor API (see
// BRCFScanLedger.h "CF-retention scan-floor (Task 1)"). Each takes
// manager->lock for the duration of the call, same as the Phase 1 accessors
// above. The paced-convoy fetch gate/driver's fetch frontier is
// LowestNeededHeight, NOT scannedThrough — LowestNeededHeight folds in the
// hard abandonedBelow floor, scannedThrough alone does not.

// Lowest height the CF scan still needs a header retained for:
// max(scannedThrough+1, abandonedBelow). O(1).
uint32_t BRPeerManagerLowestNeededHeight(BRPeerManager *manager);

// The retention hard-floor watermark: heights below this have been
// permanently abandoned (too deep to retain) and are never re-requested.
// MONOTONIC (only ever advances).
uint32_t BRPeerManagerAbandonedBelow(BRPeerManager *manager);

// Cumulative count of heights abandoned so far: heights in
// [start .. abandonedBelow-1], i.e. max(abandonedBelow - start, 0).
size_t BRPeerManagerAbandonedCount(BRPeerManager *manager);

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
