//
//  BRMerkleBlock.h
//
//  Created by Aaron Voisine on 8/6/15.
//  Copyright (c) 2015 breadwallet LLC
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

#ifndef BRMerkleBlock_h
#define BRMerkleBlock_h

#include "BRInt.h"
#include <stddef.h>
#include <inttypes.h>

#if defined(TARGET_OS_MAC) && defined(__OBJC__)
#include <Foundation/Foundation.h>
#define digi_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
#include <android/log.h>
#define digi_log(...) __android_log_print(ANDROID_LOG_ERROR, "digi", __VA_ARGS__)
#else
#include <stdio.h>
#define digi_log(...) printf(__VA_ARGS__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCK_DIFFICULTY_INTERVAL 1 // number of blocks between difficulty target adjustments
#define BLOCK_UNKNOWN_HEIGHT      INT32_MAX
#define BLOCK_MAX_TIME_DRIFT      (2*60*60) // the furthest in the future a block is allowed to be timestamped

// Compile-time level for the header proof-of-work check (BRMerkleBlockIsValid) and the
// allowed-algorithm-by-height check (_BRPeerManagerVerifyBlock):
//   0  neither check is compiled in; verdicts are those of the builds before the level existed
//   1  both are computed; a header that fails either is logged ("pow-mismatch" / "algo-by-height")
//      and counted (BRMerkleBlockPoWMismatchCount), but the verdict is unchanged
//   2  a header that fails either is rejected
// The app's native build sets the shipped level (native/build.gradle.kts); host KATs set it per arm.
#ifndef DGB_HEADER_POW_CHECK
#define DGB_HEADER_POW_CHECK 0
#endif

// Compile-time level for the header difficulty-target check (_BRPeerManagerVerifyBlock): a header at a height the
// reference client's MultiShield V4 rule governs must carry exactly the target (compact form) that rule computes
// from the header's resident ancestors (BRDifficultyV4Target):
//   0  not computed
//   1  computed; a header whose target differs is logged ("diff-mismatch") and counted, the verdict is unchanged
//   2  a header whose target differs is rejected; the peer is treated as misbehaving
// At levels 1 and 2 a header whose ancestors are not resident far enough back to compute the target is not judged:
// it is logged ("diff-skip") and counted, and is never rejected for that.
// The app's native build sets the shipped level (native/build.gradle.kts); host KATs set it per arm.
#ifndef DGB_HEADER_DIFF_CHECK
#define DGB_HEADER_DIFF_CHECK 0
#endif

#define BR_DIFF_V4_NUM_ALGOS   5    // reference client NUM_ALGOS: the algorithms the averaging window spans
#define BR_DIFF_V4_MEDIAN_SPAN 11   // reference client CBlockIndex::nMedianTimeSpan (median time past)

// The reference client's consensus parameters for MultiShield V4, per network (BRChainParams carries one).
typedef struct {
    uint32_t workComputationHeight;    // V4 governs a header whose PREVIOUS block's height is >= this
                                       // (reference client workComputationChangeTarget)
    uint32_t averagingInterval;        // nAveragingInterval: the window is BR_DIFF_V4_NUM_ALGOS*this blocks
    int64_t averagingTargetTimespan;   // nAveragingTargetTimespanV4 (seconds)
    int64_t minActualTimespan;         // nMinActualTimespanV4
    int64_t maxActualTimespan;         // nMaxActualTimespanV4
    uint32_t localTargetAdjustment;    // nLocalTargetAdjustment (percent per block of distance)
    uint32_t powLimitShift;            // powLimit = (2^256 - 1) >> powLimitShift
    int allowMinDifficultyBlocks;      // fPowAllowMinDifficultyBlocks
    int64_t targetSpacing;             // nTargetSpacing (read only when allowMinDifficultyBlocks is set)
} BRDifficultyV4Params;

// the reference client's arith_uint256::SetCompact: the 256-bit target (little-endian, u8[31] most significant) a
// compact value encodes; *negative and *tooLarge (either may be NULL) receive its two flags: the sign bit set on a
// nonzero mantissa, and a value wider than 256 bits
UInt256 BRTargetFromCompact(uint32_t compact, int *negative, int *tooLarge);

// the reference client's arith_uint256::GetCompact(negative)
uint32_t BRTargetToCompact(UInt256 target, int negative);

// the compact form of the network's powLimit
uint32_t BRDifficultyV4PowLimitCompact(const BRDifficultyV4Params *params);

// The reference client's GetNextWorkRequiredV4 with its inputs gathered by the caller from the header's ancestors:
//   lastTimes[BR_DIFF_V4_MEDIAN_SPAN]   timestamps of the header's parent (pindexLast) and its 10 predecessors
//   firstTimes[BR_DIFF_V4_MEDIAN_SPAN]  timestamps of pindexFirst (the parent's ancestor BR_DIFF_V4_NUM_ALGOS *
//                                       averagingInterval blocks back) and its 10 predecessors
//   prevAlgoTarget                      target of the last block of the header's own algorithm at or below the parent
//   prevAlgoDistance                    the parent's height minus that block's height
// returns the target, compact form, the header must carry
uint32_t BRDifficultyV4Target(const BRDifficultyV4Params *params, const uint32_t lastTimes[],
                              const uint32_t firstTimes[], uint32_t prevAlgoTarget, uint32_t prevAlgoDistance);

// Difficulty-target verdicts counted by the manager when DGB_HEADER_DIFF_CHECK >= 1 (always 0 at level 0).
// BR_DIFF_MATCH and BR_DIFF_MISMATCH are judged headers; BR_DIFF_SKIP is a header whose history is not resident.
#define BR_DIFF_MATCH    0
#define BR_DIFF_SKIP     1
#define BR_DIFF_MISMATCH 2
void BRMerkleBlockDiffCountAdd(int verdict);
uint32_t BRMerkleBlockDiffCount(int verdict);        // process-wide total
uint32_t BRMerkleBlockDiffThreadCount(int verdict);  // the calling thread's total (a headers batch reads the delta)

typedef struct {
    UInt256 blockHash;
    UInt256 powHash;
    uint32_t version;
    UInt256 prevBlock;
    UInt256 merkleRoot;
    uint32_t timestamp; // time interval since unix epoch
    uint32_t target;
    uint32_t nonce;
    uint32_t totalTx;
    UInt256 *hashes;
    size_t hashesCount;
    uint8_t *flags;
    size_t flagsLen;
    uint32_t height;
} BRMerkleBlock;
    
// Taken from https://github.com/digibyte/digibyte/blob/ce4e150f6d77abdd533a3b289ffd9f19fe8af277/src/primitives/block.h
typedef enum {
    // primary version
    BLOCK_VERSION_DEFAULT        = 2,
    
    // algo
    BLOCK_VERSION_ALGO           = (15 << 8),
    BLOCK_VERSION_SCRYPT         = (0 << 8),
    BLOCK_VERSION_SHA256D        = (2 << 8), // 512
    BLOCK_VERSION_GROESTL        = (4 << 8), // 1024
    BLOCK_VERSION_SKEIN          = (6 << 8), // 1536
    BLOCK_VERSION_QUBIT          = (8 << 8), // 2048
    //BLOCK_VERSION_EQUIHASH       = (10 << 8),
    //BLOCK_VERSION_ETHASH         = (12 << 8),
    BLOCK_VERSION_ODO            = (14 << 8), // 3584

    // returned by BRMerkleBlockAlgo() for any version whose algorithm bits are not one of the six
    // above (including any value with bit 8 set); such a header has no proof-of-work hash
    BLOCK_ALGO_UNKNOWN           = -1,
} BLOCKHASH_ALGO;

#define BR_MERKLE_BLOCK_NONE\
    ((BRMerkleBlock) { UINT256_ZERO, 0, UINT256_ZERO, UINT256_ZERO, 0, 0, 0, 0, NULL, 0, NULL, 0, 0 })

// returns a newly allocated merkle block struct that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockNew(void);

// returns a deep copy of block and that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockCopy(const BRMerkleBlock *block);

// buf must contain either a serialized merkleblock or header
// returns a merkle block struct that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockParse(const uint8_t *buf, size_t bufLen);

// returns number of bytes written to buf, or total bufLen needed if buf is NULL (block->height is not serialized)
size_t BRMerkleBlockSerialize(const BRMerkleBlock *block, uint8_t *buf, size_t bufLen);

// populates txHashes with the matched tx hashes in the block
// returns number of tx hashes written, or the total hashesCount needed if txHashes is NULL
size_t BRMerkleBlockTxHashes(const BRMerkleBlock *block, UInt256 *txHashes, size_t hashesCount);

// computes a block's merkle root from the COMPLETE, in-order list of its transaction hashes (txids),
// i.e. the form a full "block" message delivers -- compare the result against a header's committed
// merkleRoot to prove the delivered tx list is the block's actual, unmodified tx list
// returns 1 and writes *root on success; returns 0 (leaving *root untouched) on an empty list, an
// allocation failure, or a CVE-2012-2459 duplicate-subtree mutation
int BRMerkleRootFromTxHashes(UInt256 *root, const UInt256 *txHashes, size_t txCount);

// sets the hashes and flags fields for a block created with BRMerkleBlockNew()
void BRMerkleBlockSetTxHashes(BRMerkleBlock *block, const UInt256 hashes[], size_t hashesCount,
                              const uint8_t *flags, size_t flagsLen);

// the proof-of-work algorithm named by the header's version field: one of BLOCK_VERSION_SCRYPT,
// BLOCK_VERSION_SHA256D, BLOCK_VERSION_GROESTL, BLOCK_VERSION_SKEIN, BLOCK_VERSION_QUBIT, BLOCK_VERSION_ODO,
// or BLOCK_ALGO_UNKNOWN. The mask is BLOCK_VERSION_ALGO (15 << 8), as in the reference client.
int BRMerkleBlockAlgo(const BRMerkleBlock *block);

// short lower-case name of an algorithm value from BRMerkleBlockAlgo(), for logs ("unknown" for any other value)
const char *BRMerkleBlockAlgoName(int algo);

// computes the proof-of-work hash of the 80-byte header with the algorithm its version names
// (the Odocrypt key interval follows the selected network, see BRNetworkIsTestnet)
// returns 1 and writes *out on success; returns 0 and leaves *out untouched for an unknown algorithm
// nothing is cached: the powHash struct field is never written and stays zero
int BRMerkleBlockPoWHash(const BRMerkleBlock *block, UInt256 *out);

// number of headers whose computed proof-of-work hash did not meet the header's target or whose algorithm was
// unknown, counted by BRMerkleBlockIsValid() when DGB_HEADER_POW_CHECK >= 1 (always 0 at level 0)
uint32_t BRMerkleBlockPoWMismatchCount(void);

// true if merkle tree and timestamp are valid, and proof-of-work matches the stated difficulty target
// NOTE: this only checks if the block difficulty matches the difficulty target in the header, it does not check if the
// target is correct for the block's height in the chain - use BRMerkleBlockVerifyDifficulty() for that
// the proof-of-work hash is computed and compared only when DGB_HEADER_POW_CHECK >= 1 (rejected only at >= 2)
int BRMerkleBlockIsValid(const BRMerkleBlock *block, uint32_t currentTime);

// true if the given tx hash is known to be included in the block
int BRMerkleBlockContainsTxHash(const BRMerkleBlock *block, UInt256 txHash);

// verifies the block difficulty target is correct for the block's position in the chain
// transitionTime is the timestamp of the block at the previous difficulty transition
// transitionTime may be 0 if block->height is not a multiple of BLOCK_DIFFICULTY_INTERVAL
int BRMerkleBlockVerifyDifficulty(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime);

// returns a hash value for block suitable for use in a hashtable
inline static size_t BRMerkleBlockHash(const void *block)
{
    return (size_t)((const BRMerkleBlock *)block)->blockHash.u32[0];
}

// true if block and otherBlock have equal blockHash values
inline static int BRMerkleBlockEq(const void *block, const void *otherBlock)
{
    return (block == otherBlock ||
            UInt256Eq(((const BRMerkleBlock *)block)->blockHash, ((const BRMerkleBlock *)otherBlock)->blockHash));
}

// frees memory allocated for block
void BRMerkleBlockFree(BRMerkleBlock *block);

#ifdef __cplusplus
}
#endif

#endif // BRMerkleBlock_h
