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

// Hard cap on retained filter headers. 2^21 headers at DigiByte's 15-second
// blocks is about 364 days of chain (2,097,152 x 15 s = 31,457,280 s). A wallet
// whose filter scan starts further back than that reaches the cap during its
// sync; the chain is never allowed to stop there. Reaching the cap is reported
// by BRCompactFilterChainAppendEx as BR_CF_APPEND_LIMIT (distinct from a
// continuity mismatch), and the owner then drops the headers the scan no longer
// needs (BRCompactFilterChainDropBelow), keeping the header just below the new
// start as the anchor, and appends again.
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
 * Outcome of BRCompactFilterChainAppendEx. Only BR_CF_APPEND_MISMATCH says
 * anything about the batch: the other two failures are the chain's own
 * storage state, and the batch would have continued the chain.
 */
typedef enum {
    BR_CF_APPEND_MISMATCH = 0,  // prevFilterHeader != tip (or no chain / no hashes)
    BR_CF_APPEND_OK       = 1,  // appended
    BR_CF_APPEND_LIMIT    = 2,  // continues the chain, but count would exceed BR_COMPACT_FILTER_CHAIN_MAX
    BR_CF_APPEND_NOMEM    = 3,  // continues the chain, but growing the store failed
} BRCompactFilterChainAppendResult;

/**
 * Append a batch from a cfheaders response.
 *
 *   prevFilterHeader  must equal BRCompactFilterChainTipHeader(chain).
 *                     Otherwise this batch does not continue the chain.
 *   filterHashes      contiguous filter hashes starting at NextHeight().
 *   count             number of hashes; 0 is a no-op success.
 *
 * Continuity is checked first, so BR_CF_APPEND_LIMIT / BR_CF_APPEND_NOMEM are
 * returned only for a batch that does continue the chain. On success, computes
 * filterHeader_i = dSHA256(filterHash_i || prev) for each i and appends. On any
 * other result the chain is left unchanged.
 */
BRCompactFilterChainAppendResult BRCompactFilterChainAppendEx(BRCompactFilterChain *chain,
                                                              UInt256 prevFilterHeader,
                                                              const UInt256 *filterHashes, size_t count);

/**
 * BRCompactFilterChainAppendEx collapsed to 1 (BR_CF_APPEND_OK) / 0 (anything
 * else). Kept with this 0/1 contract for the callers that test it as a truth
 * value; a caller that must tell the size limit from a mismatch calls
 * BRCompactFilterChainAppendEx.
 */
int BRCompactFilterChainAppend(BRCompactFilterChain *chain,
                                UInt256 prevFilterHeader,
                                const UInt256 *filterHashes, size_t count);

/**
 * Drop every header at or above `nextHeight`, so that NextHeight() == nextHeight
 * afterwards. Used when the block chain reorganises: the headers above the fork
 * describe blocks that are no longer on the best chain.
 *
 * Returns 1 when NextHeight() == nextHeight after the call (including the no-op
 * case nextHeight == NextHeight()), 0 when nextHeight is below StartHeight() (the
 * fork is below the anchor, which itself describes an abandoned block) or above
 * NextHeight(); the chain is unchanged on 0. O(1).
 */
int BRCompactFilterChainTruncate(BRCompactFilterChain *chain, uint32_t nextHeight);

/**
 * Drop every header below `newStart`, keeping the header at newStart - 1 as the
 * new anchor, so StartHeight() == newStart afterwards. Used at the size limit to
 * keep only what the filter scan still needs.
 *
 * Requires StartHeight() < newStart <= NextHeight(); returns the number of
 * headers dropped, or 0 (chain unchanged) otherwise. O(retained headers).
 */
size_t BRCompactFilterChainDropBelow(BRCompactFilterChain *chain, uint32_t newStart);

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
 * if it differs or the height is outside the chain's range. A caller that
 * judges the peer by the result must first check the range itself
 * (StartHeight() <= height < NextHeight()): a 0 for a height outside it says
 * nothing about the filter.
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
