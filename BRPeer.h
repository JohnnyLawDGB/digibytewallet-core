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
#define MSG_FILTERLOAD   "filterload"
#define MSG_FILTERADD    "filteradd"
#define MSG_FILTERCLEAR  "filterclear"
#define MSG_MERKLEBLOCK  "merkleblock"
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
                        void (*notfound)(void *info, const UInt256 txHashes[], size_t txCount,
                                         const UInt256 blockHashes[], size_t blockCount),
                        void (*setFeePerKb)(void *info, uint64_t feePerKb),
                        BRTransaction *(*requestedTx)(void *info, UInt256 txHash),
                        int (*networkIsReachable)(void *info),
                        void (*threadCleanup)(void *info));

// set earliestKeyTime to wallet creation time in order to speed up initial sync
void BRPeerSetEarliestKeyTime(BRPeer *peer, uint32_t earliestKeyTime);

// call this when local best block height changes (helps detect tarpit nodes)
void BRPeerSetCurrentBlockHeight(BRPeer *peer, uint32_t currentBlockHeight);

// current connection status
BRPeerStatus BRPeerConnectStatus(BRPeer *peer);

// open connection to peer and perform handshake
void BRPeerConnect(BRPeer *peer);

// close connection to peer
void BRPeerDisconnect(BRPeer *peer);

// call this to (re)schedule a disconnect in the given number of seconds, or < 0 to cancel (useful for sync timeout)
void BRPeerScheduleDisconnect(BRPeer *peer, double seconds);

// set this to true when wallet addresses need to be added to bloom filter
void BRPeerSetNeedsFilterUpdate(BRPeer *peer, int needsFilterUpdate);

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

// sends a bitcoin protocol message to peer
void BRPeerSendMessage(BRPeer *peer, const uint8_t *msg, size_t msgLen, const char *type);
void BRPeerSendFilterload(BRPeer *peer, const uint8_t *filter, size_t filterLen);
void BRPeerSendMempool(BRPeer *peer, const UInt256 knownTxHashes[], size_t knownTxCount, void *info,
                       void (*completionCallback)(void *info, int success));
void BRPeerSendGetheaders(BRPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void BRPeerSendGetblocks(BRPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void BRPeerSendInv(BRPeer *peer, const UInt256 txHashes[], size_t txCount);
void BRPeerSendGetdata(BRPeer *peer, const UInt256 txHashes[], size_t txCount, const UInt256 blockHashes[],
                       size_t blockCount);
void BRPeerSendGetaddr(BRPeer *peer);
void BRPeerSendPing(BRPeer *peer, void *info, void (*pongCallback)(void *info, int success));

// BIP 157 send helpers. May be called only after a successful handshake.
// startHeight is inclusive; stopHash bounds the range. For getcfheaders the
// range is up to MAX_CFHEADERS_RESULTS headers; for getcfilters up to
// MAX_CFILTERS_RESULTS filters. getcfcheckpt has no start height — peer
// replies with every 1000th filter header up to stopHash.
void BRPeerSendGetCFHeaders(BRPeer *peer, uint8_t filterType, uint32_t startHeight, UInt256 stopHash);
void BRPeerSendGetCFilters(BRPeer *peer, uint8_t filterType, uint32_t startHeight, UInt256 stopHash);
void BRPeerSendGetCFCheckpt(BRPeer *peer, uint8_t filterType, UInt256 stopHash);

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
