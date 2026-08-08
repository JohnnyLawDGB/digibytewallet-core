//
//  BRPeer.h
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

#ifndef BRPeer_h
#define BRPeer_h

#include "BRTransaction.h"
#include "BRMerkleBlock.h"
#include "BRAddress.h"
#include "BRInt.h"
#include <stddef.h>
#include <inttypes.h>

#define peer_log(peer, ...) _peer_log("%s:%"PRIu16" " _va_first(__VA_ARGS__, NULL) "\n", BRPeerHost(peer),\
                                      (peer)->port, _va_rest(__VA_ARGS__, NULL))
#define _va_first(first, ...) first
#define _va_rest(first, ...) __VA_ARGS__

#if defined(TARGET_OS_MAC)
#include <Foundation/Foundation.h>
#define _peer_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
#include <android/log.h>
#define _peer_log(...) __android_log_print(ANDROID_LOG_INFO, "bread", __VA_ARGS__)
#else
#include <stdio.h>
    #ifdef DEBUG
        #define _peer_log(...) printf(__VA_ARGS__)
    #else
        #define _peer_log(...)
    #endif
#endif

#if defined(TARGET_OS_MAC)
    #include <Foundation/Foundation.h>
    #define debug_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
    #include <android/log.h>
    #define debug_log(...) __android_log_print(ANDROID_LOG_DEBUG, "digiwallet", __VA_ARGS__)
#else
    #include <stdio.h>
    #ifdef DEBUG
        #define debug_log(...) printf(__VA_ARGS__)
    #else
        #define debug_log(...)
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SERVICES_NODE_NETWORK         0x01 // services value indicating a node carries full blocks, not just headers
#define SERVICES_NODE_BLOOM           0x04 // BIP111: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki
#define SERVICES_NODE_WITNESS         0x08 // BIP144: required to request SegWit witness data from 8.26+ peers
#define SERVICES_NODE_COMPACT_FILTERS 0x40 // BIP157: peer serves cfheaders/cfilter/cfcheckpt for basic filters

#define BR_VERSION "1.0.0"
#define USER_AGENT "/digiwallet:" BR_VERSION "/"

// explanation of message types at: https://en.bitcoin.it/wiki/Protocol_specification
#define MSG_VERSION      "version"
#define MSG_VERACK       "verack"
#define MSG_ADDR         "addr"
#define MSG_INV          "inv"
#define MSG_GETDATA      "getdata"
#define MSG_NOTFOUND     "notfound"
#define MSG_GETBLOCKS    "getblocks"
#define MSG_GETHEADERS   "getheaders"
#define MSG_TX           "tx"
#define MSG_DANDELION_TX "dandeliontx"
#define MSG_BLOCK        "block"
#define MSG_HEADERS      "headers"
#define MSG_GETADDR      "getaddr"
#define MSG_MEMPOOL      "mempool"
#define MSG_PING         "ping"
#define MSG_PONG         "pong"
#define MSG_ALERT        "alert"
#define MSG_REJECT       "reject"   // described in BIP61: https://github.com/bitcoin/bips/blob/master/bip-0061.mediawiki
#define MSG_FEEFILTER    "feefilter"// described in BIP133 https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki

// BIP 157 compact-filter messages. https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
#define MSG_GETCFILTERS    "getcfilters"
#define MSG_CFILTER        "cfilter"
#define MSG_GETCFHEADERS   "getcfheaders"
#define MSG_CFHEADERS      "cfheaders"
#define MSG_GETCFCHECKPT   "getcfcheckpt"
#define MSG_CFCHECKPT      "cfcheckpt"

// BIP 158 basic filter type. The only filter type defined by the spec to date.
#define FILTER_TYPE_BASIC 0x00

// BIP 157 wire limits.
#define MAX_CFHEADERS_RESULTS 2000u  // max filter_hashes in one cfheaders message
#define MAX_CFILTERS_RESULTS  1000u  // max blocks one getcfilters may request
// Hard cap on filter_headers in a cfcheckpt message. cfcheckpt sends one
// header per 1000 blocks of the chain; 30k entries covers a 30M-block chain.
#define MAX_CFCHECKPT_RESULTS 30000u

#define REJECT_INVALID     0x10 // transaction is invalid for some reason (invalid signature, output value > input, etc)
#define REJECT_SPENT       0x12 // an input is already spent
#define REJECT_NONSTANDARD 0x40 // not mined/relayed because it is "non-standard" (type or version unknown by server)
#define REJECT_DUST        0x41 // one or more output amounts are below the 'dust' threshold
#define REJECT_LOWFEE      0x42 // transaction does not have enough fee/priority to be relayed or mined

typedef enum {
    BRPeerStatusDisconnected = 0,
    BRPeerStatusConnecting,
    BRPeerStatusConnected
} BRPeerStatus;

typedef struct {
    UInt128 address; // IPv6 address of peer
    uint16_t port; // port number for peer connection
    uint64_t services; // bitcoin network services supported by peer
    uint64_t timestamp; // timestamp reported by peer
    uint8_t flags; // scratch variable
} BRPeer;

#define BR_PEER_NONE ((BRPeer) { UINT128_ZERO, 0, 0, 0, 0 })

// NOTE: BRPeer functions are not thread-safe

// returns a newly allocated BRPeer struct that must be freed by calling BRPeerFree()
BRPeer *BRPeerNew(uint32_t magicNumber);

// info is a void pointer that will be passed along with each callback call
// void connected(void *) - called when peer handshake completes successfully
// void disconnected(void *, int) - called when peer connection is closed, error is an errno.h code
// void relayedPeers(void *, const BRPeer[], size_t) - called when an "addr" message is received from peer
// void relayedTx(void *, BRTransaction *) - called when a "tx" message is received from peer
// void hasTx(void *, UInt256 txHash) - called when an "inv" message with an already-known tx hash is received from peer
// void rejectedTx(void *, UInt256 txHash, uint8_t) - called when a "reject" message is received from peer
// void relayedBlock(void *, BRMerkleBlock *) - called when a "merkleblock" or "headers" message is received from peer
// void relayedBlockTxns(void *, UInt256, const UInt256[], size_t) - called after a full "block" message's txs are
//     all delivered via relayedTx, with the block hash and the hashes of the txs just delivered (BIP158 CF
//     confirmation path: lets the manager confirm those txs into the block once its header/height is known)
// void relayedBlockInv(void *, UInt256) - called when an "inv" announces a block hash while compactFiltersOnly is
//     set. In CF-only there is no bloom filter and no getblocks, so inv is the only new-tip signal; the manager
//     responds by pulling plain headers (getheaders) so the header connects and re-kicks the cfheaders/cfilter
//     driver. Not fired in BLOOM_ONLY/BOTH, which use the inv -> getdata(merkleblock) path.
// void notfound(void *, const UInt256[], size_t, const UInt256[], size_t) - called when "notfound" message is received
// BRTransaction *requestedTx(void *, UInt256) - called when "getdata" message with a tx hash is received from peer
// int networkIsReachable(void *) - must return true when networking is available, false otherwise
// void threadCleanup(void *) - called before a thread terminates to faciliate any needed cleanup
void BRPeerSetCallbacks(BRPeer *peer, void *info,
                        void (*connected)(void *info),
                        void (*disconnected)(void *info, int error),
                        void (*relayedPeers)(void *info, const BRPeer peers[], size_t peersCount),
                        void (*relayedTx)(void *info, BRTransaction *tx),
                        void (*hasTx)(void *info, UInt256 txHash),
                        void (*rejectedTx)(void *info, UInt256 txHash, uint8_t code),
                        void (*relayedBlock)(void *info, BRMerkleBlock *block),
                        void (*relayedBlockTxns)(void *info, UInt256 blockHash, const UInt256 txHashes[],
                                                  size_t txCount),
                        void (*relayedBlockInv)(void *info, UInt256 blockHash),
                        void (*notfound)(void *info, const UInt256 txHashes[], size_t txCount,
                                         const UInt256 blockHashes[], size_t blockCount),
                        void (*setFeePerKb)(void *info, uint64_t feePerKb),
                        BRTransaction *(*requestedTx)(void *info, UInt256 txHash),
                        int (*networkIsReachable)(void *info),
                        void (*threadCleanup)(void *info));

// set earliestKeyTime to wallet creation time in order to speed up initial sync
void BRPeerSetEarliestKeyTime(BRPeer *peer, uint32_t earliestKeyTime);

// In BR_SYNC_MODE_COMPACT_FILTERS_ONLY the manager sets this so the headers handler keeps
// requesting plain block headers to the chain tip and never switches to getblocks/merkleblocks
// (there is no bloom filter to match against). Set once before BRPeerConnect. Default 0 = legacy.
void BRPeerSetCompactFiltersOnly(BRPeer *peer, int compactFiltersOnly);

// Paced-convoy fetch gate (BRPeerManager.h CF_CONVOY_WINDOW). Set nonzero by the
// manager while the block-header frontier is already a full convoy window ahead
// of the CF scan frontier: the CF-only header handler then HOLDS its getheaders
// continuation (the headers already received are still processed -- only the
// request for the NEXT 2000-header batch is suppressed) so header sync cannot
// fast-forward to the chain tip ahead of the compact-filter scan. Unlike
// BRPeerSetCompactFiltersOnly this FLIPS over the life of the connection: the
// manager recomputes and re-pushes it on every block-add and every KeepAlive
// tick. Read lock-free from the peer's read thread; a stale read costs at most
// one extra 2000-header batch and self-corrects on the next one.
void BRPeerSetConvoyHdrGated(BRPeer *peer, int gated);

// call this when local best block height changes (helps detect tarpit nodes)
void BRPeerSetCurrentBlockHeight(BRPeer *peer, uint32_t currentBlockHeight);

// current connection status
BRPeerStatus BRPeerConnectStatus(BRPeer *peer);

// nonzero if the peer's socket fd is still open (distinguishes a live Connected peer from a
// dead-socket zombie whose status is still Connected but whose fd is already -1)
int BRPeerIsSocketOpen(BRPeer *peer);

// WHERE a peer thread is, for diagnosing threads that never exit.
//
// A peer reporting status=Connected together with socketOpen=0 CANNOT be in the read
// loop: BRPeerDisconnect sets socket=-1, both read loops re-read ctx->socket every
// iteration and exit, and the thread routine then sets status=Disconnected. It is
// therefore in message DISPATCH, which reaches manager callbacks that take
// manager->lock. These two report which message and for how long — the fact that
// separates "a slow callback" from "one thread computing under the lock".
//
// Both are LOCK-FREE on purpose: the caller is typically diagnosing a suspected lock
// wedge, and acquiring anything here could block on the mutex under investigation.
// Type is "" and secs is 0 when the thread is not dispatching.
const char *BRPeerCurrentMessageType(BRPeer *peer);
double BRPeerCurrentMessageSecs(BRPeer *peer);

// ---------------------------------------------------------------------------
// DISCONNECT LEDGER — WHO HUNG UP, AND WHY?
//
// Every churn theory this wallet has (peer-side eviction, self-inflicted timeout,
// OS freeze) predicts a different disconnect mix, and until now NOTHING recorded
// which one actually happened. `error` alone cannot answer it, for two reasons:
//
//   1. An ORDERLY close by the remote (read() == 0, i.e. FIN) is reported by the
//      read loops as ECONNRESET — the same value a genuine RST produces. Core's
//      eviction (AttemptToEvictConnection -> CloseSocketDisconnect) closes
//      ORDERLY, so on the current code an eviction and a network reset are
//      literally indistinguishable. That conflation is why "are we being
//      evicted?" has never been answerable from our own logs.
//   2. ETIMEDOUT is produced by THREE different local deadlines (the scheduled
//      disconnectTime, the mid-message MESSAGE_TIMEOUT, and the send deadline),
//      and the scheduled one is armed by ~8 distinct call sites in
//      BRPeerManager.c (20s PROTOCOL_TIMEOUT on the download peer, the 90s
//      inbound-idle reaper, publish timeouts). "ETIMEDOUT" tells us we hung up;
//      it does not tell us which of our own rules did it.
//
// The cause is recorded ALONGSIDE `error`, never instead of it — `error` keeps
// its exact existing values and every consumer (strerror logging, the ETIMEDOUT
// test in _peerDisconnected) is untouched. This is purely additive.
typedef enum {
    BR_CLOSE_UNKNOWN = 0,
    BR_CLOSE_CONNECT_FAIL,       // never completed _BRPeerOpenSocket
    BR_CLOSE_LOCAL_SCHEDULED,    // WE hung up: ctx->disconnectTime fired (tag says which rule)
    BR_CLOSE_LOCAL_MSG_TIMEOUT,  // WE hung up: stalled mid-message (MESSAGE_TIMEOUT)
    BR_CLOSE_LOCAL_SEND_TIMEOUT, // WE hung up: send deadline (half-dead / zero-window socket)
    BR_CLOSE_LOCAL_PROTOCOL,     // WE hung up: EPROTO (malformed, bad checksum, handler reject)
    BR_CLOSE_LOCAL_EXPLICIT,     // WE hung up: BRPeerDisconnect() (tag says which caller)
    BR_CLOSE_PEER_FIN,           // THEY hung up, ORDERLY — this is the eviction signature
    BR_CLOSE_PEER_RST,           // THEY hung up, ECONNRESET
    BR_CLOSE_SOCKET_ERR,         // some other errno off the socket
    BR_CLOSE_CAUSE_COUNT
} BRPeerCloseCause;

// Which local rule armed the deadline / called the disconnect. Only meaningful for
// the BR_CLOSE_LOCAL_* causes.
typedef enum {
    BR_DISC_TAG_NONE = 0,
    BR_DISC_TAG_SYNC,           // PROTOCOL_TIMEOUT on the sync / download path
    BR_DISC_TAG_PUBLISH,        // PROTOCOL_TIMEOUT waiting on a tx publish
    BR_DISC_TAG_IDLE_REAPER,    // inbound-idle eviction (ScheduleDisconnect(p, 0))
    BR_DISC_TAG_MANAGER_STOP,   // BRPeerManagerDisconnect / teardown
    BR_DISC_TAG_MISBEHAVIN,     // peer misbehaved
    BR_DISC_TAG_NOT_SYNCED,     // peer too far behind to be useful
    BR_DISC_TAG_SEND_STALL,     // send deadline blew
    BR_DISC_TAG_MAXCONN_TRIM,   // shed to satisfy a lowered maxConnectCount
    BR_DISC_TAG_UNUSABLE_PEER,  // capability reject at handshake (services / no SPV / no full blocks)
    BR_DISC_TAG_DOWNLOAD_SWAP,  // dropped to hand the download role to a better peer
    BR_DISC_TAG_CF_STALL,       // dropped by the cfheaders stall watchdog
    BR_DISC_TAG_COUNT
} BRPeerDisconnectTag;

// Classifies one read()/send() return into a close cause. Pure — no peer state — so the
// host KAT can drive it with the exact (n, err) tuples the socket loops produce.
// n > 0 (progress) yields BR_CLOSE_UNKNOWN.
BRPeerCloseCause BRPeerClassifySocketResult(long n, int err);

// Ledger readout. All lock-free, same rationale as BRPeerLastRecvTime below: written by
// this peer's own thread, read by the manager thread while it tears the peer down. They
// are only read AFTER that thread has left its loop, so there is no live race to lose;
// a torn read of a diagnostic counter would be harmless regardless.
BRPeerCloseCause    BRPeerCloseCauseOf(BRPeer *peer);
BRPeerDisconnectTag BRPeerDisconnectTagOf(BRPeer *peer);
const char *BRPeerCloseCauseName(BRPeerCloseCause cause);
const char *BRPeerDisconnectTagName(BRPeerDisconnectTag tag);
double   BRPeerConnectedSecs(BRPeer *peer);  // 0 if it never got a socket
uint64_t BRPeerBytesIn(BRPeer *peer);
uint64_t BRPeerBytesOut(BRPeer *peer);
uint32_t BRPeerMsgsIn(BRPeer *peer);
uint32_t BRPeerMsgsOut(BRPeer *peer);
int      BRPeerCompletedHandshake(BRPeer *peer); // got verack — separates "never usable" from "went bad"

// open connection to peer and perform handshake
void BRPeerConnect(BRPeer *peer);

// close connection to peer
void BRPeerDisconnect(BRPeer *peer);

// Same as BRPeerDisconnect, but records WHICH rule closed the peer. Prefer this at every
// deliberate call site; the untagged form remains for teardown paths where the tag is set already.
void BRPeerDisconnectTagged(BRPeer *peer, BRPeerDisconnectTag tag);

// call this to (re)schedule a disconnect in the given number of seconds, or < 0 to cancel (useful for sync timeout)
void BRPeerScheduleDisconnect(BRPeer *peer, double seconds);

// As above, but stamps the rule that armed the deadline so the ledger can attribute the
// resulting ETIMEDOUT. seconds < 0 (cancel) clears the tag.
void BRPeerScheduleDisconnectTagged(BRPeer *peer, double seconds, BRPeerDisconnectTag tag);

// display name of peer address
const char *BRPeerHost(BRPeer *peer);

// connected peer version number
uint32_t BRPeerVersion(BRPeer *peer);

// connected peer user agent string
const char *BRPeerUserAgent(BRPeer *peer);

// best block height reported by connected peer
uint32_t BRPeerLastBlock(BRPeer *peer);

// minimum tx fee rate peer will accept
uint64_t BRPeerFeePerKb(BRPeer *peer);

// average ping time for connected peer
double BRPeerPingTime(BRPeer *peer);

// monotonic wall-clock timestamp (gettimeofday-based) of the last successful (n > 0)
// socket read from this peer, updated on connect and on every inbound read. Used by
// BRPeerManagerKeepAlive's inbound-idle eviction (PEER_INBOUND_IDLE_LIMIT,
// BRPeerManager.h) -- BRPeerContext is private to BRPeer.c so this getter is the only
// way BRPeerManager.c can read it, mirroring BRPeerPingTime/BRPeerLastBlock.
double BRPeerLastRecvTime(BRPeer *peer);

// ANR fix #2 (native peer-manager keepalive lock-starvation, see
// .superpowers/sdd/anr-fix2-native-design.md). BRPeerManagerKeepAlive holds
// manager->lock/PEER_GUARD across the ping; on a half-dead socket the plain
// MESSAGE_TIMEOUT (10s) send deadline lets one wedged peer pin those locks for up
// to 10s, and K wedged peers for up to K*10s -- long enough to ANR any other
// PEER_GUARD-taking JNI entry point. KEEPALIVE_SEND_TIMEOUT bounds the keepalive
// ping specifically (one SO_SNDTIMEO cycle + slack); a healthy socket absorbs the
// 32-byte ping on the first cycle, only a wedged one hits the cap.
#define KEEPALIVE_SEND_TIMEOUT 1.5

// Per-tick wall-clock budget for BRPeerManagerKeepAlive's sweep over connectedPeers
// (BRPeerManager.c). Once elapsed time in the sweep exceeds this, the loop breaks and
// defers the rest to the next ~10s keepalive tick, so manager->lock/PEER_GUARD is held
// for O(KEEPALIVE_TICK_BUDGET) regardless of how many peers are connected, instead of
// O(peerCount * sendTimeout).
#define KEEPALIVE_TICK_BUDGET 1.5

// sends a bitcoin protocol message to peer
void BRPeerSendMessage(BRPeer *peer, const uint8_t *msg, size_t msgLen, const char *type);
void BRPeerSendMempool(BRPeer *peer, const UInt256 knownTxHashes[], size_t knownTxCount, void *info,
                       void (*completionCallback)(void *info, int success));
void BRPeerSendGetheaders(BRPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void BRPeerSendGetblocks(BRPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void BRPeerSendInv(BRPeer *peer, const UInt256 txHashes[], size_t txCount);
void BRPeerSendGetdata(BRPeer *peer, const UInt256 txHashes[], size_t txCount, const UInt256 blockHashes[],
                       size_t blockCount);
void BRPeerSendGetaddr(BRPeer *peer);
void BRPeerSendPing(BRPeer *peer, void *info, void (*pongCallback)(void *info, int success));

// Same as BRPeerSendPing, but the send is bounded by KEEPALIVE_SEND_TIMEOUT instead of
// the normal MESSAGE_TIMEOUT. Used exclusively by BRPeerManagerKeepAlive so a wedged /
// half-dead socket can't pin manager->lock/PEER_GUARD for up to MESSAGE_TIMEOUT per
// peer (ANR fix #2). Every other caller of BRPeerSendPing / BRPeerSendMessage is
// unaffected -- see .superpowers/sdd/anr-fix2-native-design.md.
void BRPeerSendPingProbe(BRPeer *peer, void *info, void (*pongCallback)(void *info, int success));

// BIP 157 send helpers. May be called only after a successful handshake.
// startHeight is inclusive; stopHash bounds the range. For getcfheaders the
// range is up to MAX_CFHEADERS_RESULTS headers; for getcfilters up to
// MAX_CFILTERS_RESULTS filters. getcfcheckpt has no start height — peer
// replies with every 1000th filter header up to stopHash.
void BRPeerSendGetCFHeaders(BRPeer *peer, uint8_t filterType, uint32_t startHeight, UInt256 stopHash);
void BRPeerSendGetCFilters(BRPeer *peer, uint8_t filterType, uint32_t startHeight, UInt256 stopHash);
void BRPeerSendGetCFCheckpt(BRPeer *peer, uint8_t filterType, UInt256 stopHash);

// BIP 158 full-block fetch. getdata with inv_block (vs the inv_filtered_block
// used by BRPeerSendGetdata, which only makes sense once a bloom filter is
// loaded). Triggered when a cfilter matches one of the wallet's elements.
void BRPeerSendGetdataBlocks(BRPeer *peer, const UInt256 blockHashes[], size_t blockCount);

// Subscribe to BIP 157 reply messages. Callbacks are optional (pass NULL to
// ignore a message type) and receive borrowed pointers that must not be
// retained past the call. Set once before BRPeerConnect; not thread-safe.
//
// relayedCFHeaders is invoked with the decoded cfheaders payload. filterHashes
// borrows from a thread-local buffer; copy if you need to retain.
//
// relayedCFilter is invoked with the encoded filter bytes still owned by the
// caller; pass them straight to BRGCSFilterBasicParse or copy. Length is
// already validated to be <= BR_GCS_MAX_ENCODED_SIZE.
//
// relayedCFCheckpt is invoked with the decoded cfcheckpt payload. filterHeaders
// borrows from a thread-local buffer; copy if you need to retain.
void BRPeerSetCompactFilterCallbacks(BRPeer *peer,
                                     void (*relayedCFHeaders)(void *info, uint8_t filterType, UInt256 stopHash,
                                                              UInt256 prevFilterHeader,
                                                              const UInt256 *filterHashes, size_t count),
                                     void (*relayedCFilter)(void *info, uint8_t filterType, UInt256 blockHash,
                                                            const uint8_t *encoded, size_t encodedLen),
                                     void (*relayedCFCheckpt)(void *info, uint8_t filterType, UInt256 stopHash,
                                                              const UInt256 *filterHeaders, size_t count));

// useful to get additional tx after a bloom filter update
void BRPeerRerequestBlocks(BRPeer *peer, UInt256 fromBlock);

// returns a hash value for peer suitable for use in a hashtable
inline static size_t BRPeerHash(const void *peer)
{
    uint32_t address = ((const BRPeer *)peer)->address.u32[3], port = ((const BRPeer *)peer)->port;
 
    // (((FNV_OFFSET xor address)*FNV_PRIME) xor port)*FNV_PRIME
    return (size_t)((((0x811C9dc5 ^ address)*0x01000193) ^ port)*0x01000193);
}

// true if a and b have the same address and port
inline static int BRPeerEq(const void *peer, const void *otherPeer)
{
    return (peer == otherPeer ||
            (UInt128Eq(((const BRPeer *)peer)->address, ((const BRPeer *)otherPeer)->address) &&
             ((const BRPeer *)peer)->port == ((const BRPeer *)otherPeer)->port));
}

// frees memory allocated for peer
void BRPeerFree(BRPeer *peer);

// SOCKS5 proxy support — set ONCE before peer connections are established.
// Changing the proxy requires stopping and restarting sync.
void BRPeerSetSocksProxy(const char *host, int port);
void BRPeerClearSocksProxy(void);
int  BRPeerHasSocksProxy(void);

#ifdef __cplusplus
}
#endif

#endif // BRPeer_h
