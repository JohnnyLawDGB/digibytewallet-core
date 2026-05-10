//
//  BRCompactFilterChain.c
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRCompactFilterChain.h"
#include "BRGCSFilter.h"
#include "BRCrypto.h"

#include <stdlib.h>
#include <string.h>

#define BR_COMPACT_FILTER_CHAIN_MAGIC   0x46434243u // "BCFC"
#define BR_COMPACT_FILTER_CHAIN_VERSION 1u

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
// amortize. Returns 1 on success, 0 on allocation failure or overflow
// past the hard cap.
static int _chain_reserve(BRCompactFilterChain *chain, size_t need)
{
    if (need > BR_COMPACT_FILTER_CHAIN_MAX) return 0;
    if (need <= chain->capacity) return 1;

    size_t newCap = chain->capacity ? chain->capacity : 64;
    while (newCap < need) {
        if (newCap > BR_COMPACT_FILTER_CHAIN_MAX / 2) {
            newCap = BR_COMPACT_FILTER_CHAIN_MAX;
            break;
        }
        newCap *= 2;
    }
    if (newCap < need) return 0;

    UInt256 *resized = (UInt256 *)realloc(chain->headers, newCap * sizeof(UInt256));
    if (!resized) return 0;
    chain->headers = resized;
    chain->capacity = newCap;
    return 1;
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

int BRCompactFilterChainAppend(BRCompactFilterChain *chain,
                                UInt256 prevFilterHeader,
                                const UInt256 *filterHashes, size_t count)
{
    if (!chain) return 0;
    if (count == 0) return 1;
    if (!filterHashes) return 0;

    UInt256 tip = BRCompactFilterChainTipHeader(chain);
    if (!UInt256Eq(prevFilterHeader, tip)) return 0;

    size_t need = chain->count + count;
    if (!_chain_reserve(chain, need)) return 0;

    UInt256 prev = tip;
    for (size_t i = 0; i < count; i++) {
        UInt256 hdr = BRGCSFilterHeader(filterHashes[i], prev);
        chain->headers[chain->count + i] = hdr;
        prev = hdr;
    }
    chain->count = need;
    return 1;
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
        if (!_chain_reserve(chain, count)) {
            BRCompactFilterChainFree(chain);
            return NULL;
        }
        memcpy(chain->headers, &buf[off], (size_t)count * sizeof(UInt256));
        chain->count = count;
    }
    return chain;
}
