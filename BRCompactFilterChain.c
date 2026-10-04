//
//  BRCompactFilterChain.c
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRCompactFilterChain.h"
#include "BRGCSFilter.h"
#include "BRCrypto.h"
#include "BRCompactFilterCheckpoints.h"

#include <stdlib.h>
#include <string.h>

#define BR_COMPACT_FILTER_CHAIN_MAGIC   0x46434243u // "BCFC"
#define BR_COMPACT_FILTER_CHAIN_VERSION 1u

// filterHeader_i = dSHA256(filterHash_i || prev). Single source of truth for
// the fold math -- both BRCompactFilterChainAppend (commits) and
// BRCompactFilterChainBatchViolatesCheckpoint (never commits) call this, so
// the two can never diverge.
static UInt256 _foldHeader(UInt256 prev, UInt256 filterHash)
{
    return BRGCSFilterHeader(filterHash, prev);
}

#define HEADER_LEN (4u + 1u + 1u + 4u + 32u + 4u) // magic+ver+type+start+anchor+count = 46 bytes

struct BRCompactFilterChain {
    uint8_t  filterType;
    uint32_t startHeight;
    UInt256  anchorPrevHeader;
    UInt256 *headers;   // headers[i] = filter header at (startHeight + i)
    size_t   count;
    size_t   capacity;
};

// Reserve room for at least `need` total headers. Doubles capacity to
// amortize. Returns BR_CF_APPEND_OK on success, BR_CF_APPEND_LIMIT when `need`
// is past the hard cap, BR_CF_APPEND_NOMEM when the allocation fails.
static BRCompactFilterChainAppendResult _chain_reserve(BRCompactFilterChain *chain, size_t need)
{
    if (need > BR_COMPACT_FILTER_CHAIN_MAX) return BR_CF_APPEND_LIMIT;
    if (need <= chain->capacity) return BR_CF_APPEND_OK;

    size_t newCap = chain->capacity ? chain->capacity : 64;
    while (newCap < need) {
        if (newCap > BR_COMPACT_FILTER_CHAIN_MAX / 2) {
            newCap = BR_COMPACT_FILTER_CHAIN_MAX;
            break;
        }
        newCap *= 2;
    }
    if (newCap < need) return BR_CF_APPEND_LIMIT;

    UInt256 *resized = (UInt256 *)realloc(chain->headers, newCap * sizeof(UInt256));
    if (!resized) return BR_CF_APPEND_NOMEM;
    chain->headers = resized;
    chain->capacity = newCap;
    return BR_CF_APPEND_OK;
}

BRCompactFilterChain *BRCompactFilterChainNew(uint8_t filterType,
                                              uint32_t startHeight,
                                              UInt256 anchorPrevHeader)
{
    BRCompactFilterChain *chain = (BRCompactFilterChain *)calloc(1, sizeof(*chain));
    if (!chain) return NULL;
    chain->filterType = filterType;
    chain->startHeight = startHeight;
    chain->anchorPrevHeader = anchorPrevHeader;
    return chain;
}

void BRCompactFilterChainFree(BRCompactFilterChain *chain)
{
    if (!chain) return;
    free(chain->headers);
    free(chain);
}

uint8_t BRCompactFilterChainType(const BRCompactFilterChain *chain)
{
    return chain ? chain->filterType : 0;
}

uint32_t BRCompactFilterChainStartHeight(const BRCompactFilterChain *chain)
{
    return chain ? chain->startHeight : 0;
}

size_t BRCompactFilterChainCount(const BRCompactFilterChain *chain)
{
    return chain ? chain->count : 0;
}

uint32_t BRCompactFilterChainNextHeight(const BRCompactFilterChain *chain)
{
    if (!chain) return 0;
    return chain->startHeight + (uint32_t)chain->count;
}

UInt256 BRCompactFilterChainTipHeader(const BRCompactFilterChain *chain)
{
    if (!chain) return UINT256_ZERO;
    if (chain->count == 0) return chain->anchorPrevHeader;
    return chain->headers[chain->count - 1];
}

UInt256 BRCompactFilterChainHeader(const BRCompactFilterChain *chain, uint32_t height)
{
    if (!chain) return UINT256_ZERO;
    if (chain->startHeight > 0 && height == chain->startHeight - 1) {
        return chain->anchorPrevHeader;
    }
    if (height < chain->startHeight) return UINT256_ZERO;
    size_t idx = (size_t)(height - chain->startHeight);
    if (idx >= chain->count) return UINT256_ZERO;
    return chain->headers[idx];
}

BRCompactFilterChainAppendResult BRCompactFilterChainAppendEx(BRCompactFilterChain *chain,
                                                              UInt256 prevFilterHeader,
                                                              const UInt256 *filterHashes, size_t count)
{
    if (!chain) return BR_CF_APPEND_MISMATCH;
    if (count == 0) return BR_CF_APPEND_OK;
    if (!filterHashes) return BR_CF_APPEND_MISMATCH;

    // Continuity first: LIMIT / NOMEM are only ever reported for a batch that
    // would have continued the chain, so they can never hide a mismatch.
    UInt256 tip = BRCompactFilterChainTipHeader(chain);
    if (!UInt256Eq(prevFilterHeader, tip)) return BR_CF_APPEND_MISMATCH;

    size_t need = chain->count + count;
#ifdef CF_CHAIN_LIMIT_UNFIXED
    // Reference arm for cf_chain_limit_kat only; never defined in a production build.
    // The earlier shape: the size limit reads exactly like a continuity mismatch.
    if (_chain_reserve(chain, need) != BR_CF_APPEND_OK) return BR_CF_APPEND_MISMATCH;
#else
    BRCompactFilterChainAppendResult r = _chain_reserve(chain, need);
    if (r != BR_CF_APPEND_OK) return r;
#endif

    UInt256 prev = tip;
    for (size_t i = 0; i < count; i++) {
        UInt256 hdr = _foldHeader(prev, filterHashes[i]);
        chain->headers[chain->count + i] = hdr;
        prev = hdr;
    }
    chain->count = need;
    return BR_CF_APPEND_OK;
}

int BRCompactFilterChainAppend(BRCompactFilterChain *chain,
                                UInt256 prevFilterHeader,
                                const UInt256 *filterHashes, size_t count)
{
    return BRCompactFilterChainAppendEx(chain, prevFilterHeader, filterHashes, count) == BR_CF_APPEND_OK;
}

int BRCompactFilterChainTruncate(BRCompactFilterChain *chain, uint32_t nextHeight)
{
    if (!chain) return 0;
    if (nextHeight < chain->startHeight) return 0;               // the anchor itself is above the cut
    size_t keep = (size_t)(nextHeight - chain->startHeight);
    if (keep > chain->count) return 0;                           // nothing there to cut back to
    chain->count = keep;
    return 1;
}

size_t BRCompactFilterChainDropBelow(BRCompactFilterChain *chain, uint32_t newStart)
{
    if (!chain) return 0;
    if (newStart <= chain->startHeight) return 0;
    size_t drop = (size_t)(newStart - chain->startHeight);
    if (drop > chain->count) return 0;
    // The header at newStart - 1 becomes the anchor; Header(newStart - 1) keeps
    // answering it, and VerifyFilter(newStart) chains onto it.
    chain->anchorPrevHeader = chain->headers[drop - 1];
    if (chain->count > drop) {
        memmove(chain->headers, chain->headers + drop, (chain->count - drop) * sizeof(UInt256));
    }
    chain->count -= drop;
    chain->startHeight = newStart;
    return drop;
}

// Core comparator: folds filterHashes forward from the chain's current tip
// WITHOUT mutating the chain, checking the folded header at each height
// against every checkpoint in cps[0..nc). Returns 1 (and sets *outHeight/
// *outComputed) on the first mismatch; 0 if every checkpoint checked
// matches, or nc == 0. Factored out from BRCompactFilterChainBatchViolates-
// Checkpoint (which always looks up cps from the real BRMainNetCFCheckpoints
// table via BRCFCheckpointsInRange) so a host test can exercise this exact
// fold+compare logic against a self-consistent synthetic checkpoint --
// matching one of the real pinned mainnet values from constructed data is a
// SHA256d preimage problem, not something a test can forge from scratch.
static int _batchViolatesCheckpoints(const BRCompactFilterChain *chain,
        const UInt256 *filterHashes, size_t count,
        const BRCFCheckpoint * const *cps, size_t nc,
        uint32_t *outHeight, UInt256 *outComputed)
{
    if (nc == 0) return 0;

    uint32_t start = BRCompactFilterChainNextHeight(chain);
    UInt256 h = BRCompactFilterChainTipHeader(chain);

    for (size_t i = 0; i < count; i++) {
        h = _foldHeader(h, filterHashes[i]);
        uint32_t height = start + (uint32_t)i;
        for (size_t c = 0; c < nc; c++) {
            if (cps[c]->height == height && ! UInt256Eq(h, cps[c]->filterHeader)) {
                if (outHeight) *outHeight = height;
                if (outComputed) *outComputed = h;
                return 1;
            }
        }
    }
    return 0;
}

int BRCompactFilterChainBatchViolatesCheckpoint(const BRCompactFilterChain *chain,
        const UInt256 *filterHashes, size_t count,
        uint32_t *outHeight, UInt256 *outComputed)
{
    if (!chain) return 0;
    if (count == 0) return 0; // no-op batch; also avoids start+count-1 underflow below
    if (!filterHashes) return 0;

    uint32_t start = BRCompactFilterChainNextHeight(chain);
    const BRCFCheckpoint *cps[16];
    size_t nc = BRCFCheckpointsInRange(start, start + (uint32_t)count - 1, cps, 16);
    if (nc == 0) return 0;

    return _batchViolatesCheckpoints(chain, filterHashes, count, cps, nc, outHeight, outComputed);
}

int BRCompactFilterChainVerifyFilter(const BRCompactFilterChain *chain,
                                      uint32_t height,
                                      const uint8_t *encoded, size_t encodedLen)
{
    if (!chain || !encoded) return 0;
    if (height < chain->startHeight) return 0;
    size_t idx = (size_t)(height - chain->startHeight);
    if (idx >= chain->count) return 0;

    // Reconstruct filterHash via dSHA256(encoded) and chain it onto the
    // previous-height header to recover what filterHeader[height] should
    // be. Compare to what we hold.
    UInt256 filterHash;
    BRSHA256_2(&filterHash, encoded, encodedLen);

    UInt256 prev;
    if (height == chain->startHeight) prev = chain->anchorPrevHeader;
    else prev = chain->headers[idx - 1];

    UInt256 recomputed = BRGCSFilterHeader(filterHash, prev);
    return UInt256Eq(recomputed, chain->headers[idx]) ? 1 : 0;
}

size_t BRCompactFilterChainSerialize(const BRCompactFilterChain *chain,
                                      uint8_t *buf, size_t bufLen)
{
    if (!chain) return 0;
    if (chain->count > 0xffffffffu) return 0; // count fits in 4 bytes

    size_t need = HEADER_LEN + chain->count * sizeof(UInt256);
    if (!buf) return need;
    if (bufLen < need) return 0;

    size_t off = 0;
    UInt32SetLE(&buf[off], BR_COMPACT_FILTER_CHAIN_MAGIC);
    off += 4;
    buf[off++] = (uint8_t)BR_COMPACT_FILTER_CHAIN_VERSION;
    buf[off++] = chain->filterType;
    UInt32SetLE(&buf[off], chain->startHeight);
    off += 4;
    memcpy(&buf[off], chain->anchorPrevHeader.u8, sizeof(UInt256));
    off += sizeof(UInt256);
    UInt32SetLE(&buf[off], (uint32_t)chain->count);
    off += 4;
    if (chain->count > 0) {
        memcpy(&buf[off], chain->headers, chain->count * sizeof(UInt256));
        off += chain->count * sizeof(UInt256);
    }
    return off;
}

BRCompactFilterChain *BRCompactFilterChainDeserialize(const uint8_t *buf, size_t bufLen)
{
    if (!buf || bufLen < HEADER_LEN) return NULL;

    size_t off = 0;
    uint32_t magic = UInt32GetLE(&buf[off]);
    off += 4;
    if (magic != BR_COMPACT_FILTER_CHAIN_MAGIC) return NULL;

    uint8_t version = buf[off++];
    if (version != BR_COMPACT_FILTER_CHAIN_VERSION) return NULL;

    uint8_t filterType = buf[off++];
    uint32_t startHeight = UInt32GetLE(&buf[off]);
    off += 4;
    UInt256 anchorPrev;
    memcpy(anchorPrev.u8, &buf[off], sizeof(UInt256));
    off += sizeof(UInt256);
    uint32_t count = UInt32GetLE(&buf[off]);
    off += 4;

    if (count > BR_COMPACT_FILTER_CHAIN_MAX) return NULL;
    if (bufLen < off + (size_t)count * sizeof(UInt256)) return NULL;

    BRCompactFilterChain *chain = BRCompactFilterChainNew(filterType, startHeight, anchorPrev);
    if (!chain) return NULL;

    if (count > 0) {
        if (_chain_reserve(chain, count) != BR_CF_APPEND_OK) {
            BRCompactFilterChainFree(chain);
            return NULL;
        }
        memcpy(chain->headers, &buf[off], (size_t)count * sizeof(UInt256));
        chain->count = count;
    }
    return chain;
}
