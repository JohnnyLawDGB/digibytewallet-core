//
//  BRCompactFilterChain.h
//
//  BIP 157 filter-header chain accumulator. Owns the running chain of
//  filterHeader values per (filter_type, height) and validates new
//  batches for continuity. Pure data structure — no peer interaction,
//  no socket I/O, no threading.
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#ifndef BRCompactFilterChain_h
#define BRCompactFilterChain_h

#include <stddef.h>
#include <stdint.h>
#include "BRInt.h"

#ifdef __cplusplus
extern "C" {
#endif

// Hard cap on retained filter headers. A 2M-header window covers roughly
// 23 days of DigiByte at 15-second blocks, or a wallet birth ~22 months
// back. Callers that need to sync further back should re-anchor against
// a recent cfcheckpt rather than grow the in-memory chain unbounded.
#ifndef BR_COMPACT_FILTER_CHAIN_MAX
#define BR_COMPACT_FILTER_CHAIN_MAX (2u * 1024u * 1024u)
#endif

typedef struct BRCompactFilterChain BRCompactFilterChain;

/**
 * Create an empty chain anchored at (startHeight - 1) with the given
 * previous filter header. Subsequent appends extend the chain forward
 * from startHeight.
 *
 * For a sync from genesis, pass startHeight=0 and anchorPrevHeader=
 * UINT256_ZERO (BIP 158 §Header Chain).
 */
BRCompactFilterChain *BRCompactFilterChainNew(uint8_t filterType,
                                              uint32_t startHeight,
                                              UInt256 anchorPrevHeader);

void BRCompactFilterChainFree(BRCompactFilterChain *chain);

/** Filter type this chain tracks. */
uint8_t BRCompactFilterChainType(const BRCompactFilterChain *chain);

/** Height at which the chain begins (anchorPrevHeader covers startHeight - 1). */
uint32_t BRCompactFilterChainStartHeight(const BRCompactFilterChain *chain);

/** Number of headers currently stored, i.e. tipHeight - startHeight + 1
 *  if non-empty, 0 if no headers have been appended yet. */
size_t BRCompactFilterChainCount(const BRCompactFilterChain *chain);

/**
 * Height of the next filter header that a successful append would land at.
 * Equals startHeight + count. The peer should be asked for cfheaders
 * beginning at this height.
 */
uint32_t BRCompactFilterChainNextHeight(const BRCompactFilterChain *chain);

/**
 * Current tip filter header. If count == 0 (chain is empty), returns the
 * anchorPrevHeader passed at construction.
 */
UInt256 BRCompactFilterChainTipHeader(const BRCompactFilterChain *chain);

/**
 * Look up the filter header at exactly the given height. Returns
 * UINT256_ZERO if height is outside [startHeight, startHeight + count).
 * Returns the anchor when height == startHeight - 1.
 */
UInt256 BRCompactFilterChainHeader(const BRCompactFilterChain *chain, uint32_t height);

/**
 * Append a batch from a cfheaders response.
 *
 *   prevFilterHeader  must equal BRCompactFilterChainTipHeader(chain).
 *                     Otherwise this batch can't possibly continue the
 *                     chain — likely indicates a malicious or out-of-sync
 *                     peer.
 *   filterHashes      contiguous filter hashes starting at NextHeight().
 *   count             number of hashes; 0 is a no-op success.
 *
 * On success, computes filterHeader_i = dSHA256(filterHash_i || prev) for
 * each i and appends. Returns 1 on success, 0 on continuity failure or
 * cap overflow. On failure the chain is left unchanged.
 */
int BRCompactFilterChainAppend(BRCompactFilterChain *chain,
                                UInt256 prevFilterHeader,
                                const UInt256 *filterHashes, size_t count);

/**
 * Check whether a pending cfheaders batch -- folded forward from the
 * chain's current tip at NextHeight() WITHOUT mutating the chain -- would
 * disagree with any pinned mainnet checkpoint whose height falls inside
 * the batch's range [NextHeight, NextHeight + count - 1]. Consults
 * BRCFCheckpointsInRange / BRMainNetCFCheckpoints (BRCompactFilterCheckpoints.h);
 * mainnet-only in effect, since that table is mainnet-only.
 *
 *   chain          the chain to fold from (read-only; never mutated).
 *   filterHashes   contiguous filter hashes starting at NextHeight(), same
 *                  semantics as BRCompactFilterChainAppend's filterHashes.
 *   count          number of hashes; 0 is never a violation.
 *   outHeight      if non-NULL and a violation is found, set to the first
 *                  mismatching checkpoint's height.
 *   outComputed    if non-NULL and a violation is found, set to the
 *                  computed (wrong) filter header at that height.
 *
 * Returns 1 if the fold disagrees with an in-range checkpoint (outHeight/
 * outComputed set to the first divergence), 0 if every in-range checkpoint
 * matches or none are in range. Never allocates, never mutates chain.
 */
int BRCompactFilterChainBatchViolatesCheckpoint(const BRCompactFilterChain *chain,
                                                 const UInt256 *filterHashes, size_t count,
                                                 uint32_t *outHeight, UInt256 *outComputed);

/**
 * Verify a freshly-decoded filter against the chain.
 *
 * Given the encoded filter bytes for a block at the named height, computes
 * dSHA256(encoded) and chains it onto the previous-height filter header.
 * Returns 1 if the recomputed header matches the chain at this height, 0
 * if it differs (filter is wrong, peer is lying, or height is outside the
 * chain's range).
 */
int BRCompactFilterChainVerifyFilter(const BRCompactFilterChain *chain,
                                      uint32_t height,
                                      const uint8_t *encoded, size_t encodedLen);

/**
 * Serialize chain state into a flat byte buffer for persistence.
 * Layout (little-endian where multi-byte):
 *   magic       (4 bytes, BR_COMPACT_FILTER_CHAIN_MAGIC)
 *   version     (1 byte, currently 1)
 *   filterType  (1 byte)
 *   startHeight (4 bytes)
 *   anchorPrev  (32 bytes)
 *   count       (4 bytes)
 *   headers     (32 * count)
 *
 * Pass buf=NULL to query required size. Returns 0 on overflow or when
 * the chain exceeds 2^32 - 1 headers.
 */
size_t BRCompactFilterChainSerialize(const BRCompactFilterChain *chain,
                                      uint8_t *buf, size_t bufLen);

/**
 * Inverse of Serialize. Returns NULL on:
 *  - too-short buffer, bad magic, unsupported version
 *  - count exceeding BR_COMPACT_FILTER_CHAIN_MAX
 *  - allocation failure
 *
 * Caller owns the returned chain and must BRCompactFilterChainFree it.
 */
BRCompactFilterChain *BRCompactFilterChainDeserialize(const uint8_t *buf, size_t bufLen);

#ifdef __cplusplus
}
#endif

#endif // BRCompactFilterChain_h
