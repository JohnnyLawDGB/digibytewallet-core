//
//  BRGCSFilter.h
//
//  BIP 158 Golomb-coded Set compact block filter.
//
//  Copyright (c) 2026 JohnnyLawDGB. Ported from Bitcoin Core v26.2's
//  src/blockfilter.{h,cpp} (Copyright (c) 2014-2025 The Bitcoin Core
//  developers), MIT license.
//

#ifndef BRGCSFilter_h
#define BRGCSFilter_h

#include <stdint.h>
#include <stddef.h>
#include "BRInt.h"

#ifdef __cplusplus
extern "C" {
#endif

// BIP 158 basic filter parameters (filter type 0x00).
#define BR_GCS_BASIC_FILTER_P  19u
#define BR_GCS_BASIC_FILTER_M  784931u

// Hard safety cap on encoded filter size. Bitcoin Core rejects encoded
// filters larger than its 4 MiB MAX_BLOCK_WEIGHT-derived bound; on a
// 23 M-block DigiByte chain we're bounded by block size too. Any peer
// sending more than this in a single cfilter is malformed; reject before
// allocating.
#define BR_GCS_MAX_ENCODED_SIZE  (100u * 1024u)

typedef struct BRGCSFilter BRGCSFilter;

/**
 * Parse an encoded BIP 158 basic filter for the given block.
 * k0 and k1 are derived from the first 16 bytes of blockHash (in raw
 * wire order — not hex-string reversed), per BIP 158 §Parameters.
 *
 * Returns NULL on any parse error: oversize input, malformed CompactSize,
 * N ≥ 2^32, extra data after the last Golomb-Rice value, bit-stream
 * underflow, or allocation failure.
 *
 * The returned filter owns a copy of the encoded bytes and the
 * pre-decoded sorted hash array. Free with BRGCSFilterFree.
 */
BRGCSFilter *BRGCSFilterBasicParse(const uint8_t *bytes, size_t len,
                                    UInt256 blockHash);

/**
 * Parse with explicit parameters. Intended for BIP 158 appendix test
 * vectors and future non-basic filter types. For basic filters against
 * a block hash, prefer BRGCSFilterBasicParse.
 */
BRGCSFilter *BRGCSFilterParse(const uint8_t *bytes, size_t len,
                               uint64_t siphashK0, uint64_t siphashK1,
                               uint8_t P, uint32_t M);

/**
 * Test whether an element may be in the filter.
 * Returns 1 on potential match (false-positive rate = 1/M), 0 on
 * definite miss. Does not allocate.
 */
int BRGCSFilterMatch(const BRGCSFilter *f,
                      const uint8_t *element, size_t elemLen);

/**
 * Test whether any of n elements may be in the filter. More efficient
 * than n separate Match calls because both sides are sorted. Allocates
 * a small temporary buffer for the sorted query-hash array.
 */
int BRGCSFilterMatchAny(const BRGCSFilter *f,
                         const uint8_t * const *elements,
                         const size_t *elemLens, size_t n);

/**
 * Double-SHA-256 of the filter's raw encoded bytes. This is the
 * "filterHash" that goes into cfheaders messages and into the
 * filter-header chain computation.
 */
UInt256 BRGCSFilterHash(const BRGCSFilter *f);

/**
 * filterHeader_H = dSHA256(filterHash_H || prevFilterHeader).
 * For the genesis filter header, pass UINT256_ZERO as prevHeader.
 * Pure function; does not require a parsed filter.
 */
UInt256 BRGCSFilterHeader(UInt256 filterHash, UInt256 prevHeader);

/** Raw encoded bytes, for persistence or hash recomputation. */
const uint8_t *BRGCSFilterEncoded(const BRGCSFilter *f, size_t *len);

/** Number of elements encoded in the filter. */
uint32_t BRGCSFilterN(const BRGCSFilter *f);

/** Release memory. Accepts NULL. */
void BRGCSFilterFree(BRGCSFilter *f);

#ifdef __cplusplus
}
#endif

#endif // BRGCSFilter_h
