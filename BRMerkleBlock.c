//
//  BRMerkleBlock.c
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

#include "BRMerkleBlock.h"
#include "BRCrypto.h"
#include "BRAddress.h"
#include "BRNetwork.h"
#include "crypto/odocrypt.h"
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>

#define MAX_PROOF_OF_WORK 0x1e0fffff    // highest value for difficulty target (higher values are less difficult)
#define TARGET_TIMESPAN (0.10*24*60*60) // the targeted timespan between difficulty target adjustments

inline static int _ceil_log2(int x)
{
    int r = (x & (x - 1)) ? 1 : 0;
    
    while ((x >>= 1) != 0) r++;
    return r;
}

// from https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
// Merkle trees are binary trees of hashes. Merkle trees in bitcoin use a double SHA-256, the SHA-256 hash of the
// SHA-256 hash of something. If, when forming a row in the tree (other than the root of the tree), it would have an odd
// number of elements, the final double-hash is duplicated to ensure that the row has an even number of hashes. First
// form the bottom row of the tree with the ordered double-SHA-256 hashes of the byte streams of the transactions in the
// block. Then the row above it consists of half that number of hashes. Each entry is the double-SHA-256 of the 64-byte
// concatenation of the corresponding two hashes below it in the tree. This procedure repeats recursively until we reach
// a row consisting of just a single double-hash. This is the merkle root of the tree.
//
// from https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#Partial_Merkle_branch_format
// The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
// signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
// are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
// Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
// depth-first traversal is performed, consuming bits and hashes as they were written during encoding.
//
// example tree with three transactions, where only tx2 is matched by the bloom filter:
//
//     merkleRoot
//      /     \
//    m1       m2
//   /  \     /  \
// tx1  tx2 tx3  tx3
//
// flag bits (little endian): 00001011 [merkleRoot = 1, m1 = 1, tx1 = 0, tx2 = 1, m2 = 0, byte padding = 000]
// hashes: [tx1, tx2, m2]
//
// NOTE: this merkle tree design has a security vulnerability (CVE-2012-2459), which can be defended against by
// considering the merkle root invalid if there are duplicate hashes in any rows with an even number of elements

// returns a newly allocated merkle block struct that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockNew(void)
{
    BRMerkleBlock *block = calloc(1, sizeof(*block));

    assert(block != NULL);
    
    block->height = BLOCK_UNKNOWN_HEIGHT;
    return block;
}

// returns a deep copy of block and that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockCopy(const BRMerkleBlock *block)
{
    BRMerkleBlock *cpy = BRMerkleBlockNew();

    assert(block != NULL);
    *cpy = *block;
    cpy->hashes = NULL;
    cpy->flags = NULL;
    BRMerkleBlockSetTxHashes(cpy, block->hashes, block->hashesCount, block->flags, block->flagsLen);
    return cpy;
}

// buf must contain either a serialized merkleblock or header
// returns a merkle block struct that must be freed by calling BRMerkleBlockFree()
BRMerkleBlock *BRMerkleBlockParse(const uint8_t *buf, size_t bufLen)
{
    BRMerkleBlock *block = (buf && 80 <= bufLen) ? BRMerkleBlockNew() : NULL;
    size_t off = 0, len = 0;
    
    assert(buf != NULL || bufLen == 0);
    
    if (block) {
        block->version = UInt32GetLE(&buf[off]);
        off += sizeof(uint32_t);
        block->prevBlock = UInt256Get(&buf[off]);
        off += sizeof(UInt256);
        block->merkleRoot = UInt256Get(&buf[off]);
        off += sizeof(UInt256);
        block->timestamp = UInt32GetLE(&buf[off]);
        off += sizeof(uint32_t);
        block->target = UInt32GetLE(&buf[off]);
        off += sizeof(uint32_t);
        block->nonce = UInt32GetLE(&buf[off]);
        off += sizeof(uint32_t);
        
        if (off + sizeof(uint32_t) <= bufLen) {
            block->totalTx = UInt32GetLE(&buf[off]);
            off += sizeof(uint32_t);
            block->hashesCount = (size_t)BRVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
            off += len;
#ifndef WIRE_COUNT_BOUNDS_UNFIXED
            // invariant: the hash count is bounded by the bytes that remain, so
            // the size computation below cannot wrap. Each hash is 32 bytes on
            // the wire; a larger count cannot be present in the buffer.
            if (block->hashesCount > (off <= bufLen ? (bufLen - off) / sizeof(UInt256) : 0))
                block->hashesCount = 0;
#endif
            len = block->hashesCount*sizeof(UInt256);
            block->hashes = (off + len <= bufLen) ? malloc(len) : NULL;
            if (block->hashes) memcpy(block->hashes, &buf[off], len);
            off += len;
            block->flagsLen = (size_t)BRVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
            off += len;
            len = block->flagsLen;
            block->flags = (off + len <= bufLen) ? malloc(len) : NULL;
            if (block->flags) memcpy(block->flags, &buf[off], len);
        }
        
        BRSHA256_2(&block->blockHash, buf, 80);
    }
    
    return block;
}

// writes the 80-byte block header (version, prevBlock, merkleRoot, timestamp, target, nonce) in wire order
static void _BRMerkleBlockHeaderBytes(const BRMerkleBlock *block, uint8_t buf[80])
{
    size_t off = 0;

    UInt32SetLE(&buf[off], block->version);
    off += sizeof(uint32_t);
    UInt256Set(&buf[off], block->prevBlock);
    off += sizeof(UInt256);
    UInt256Set(&buf[off], block->merkleRoot);
    off += sizeof(UInt256);
    UInt32SetLE(&buf[off], block->timestamp);
    off += sizeof(uint32_t);
    UInt32SetLE(&buf[off], block->target);
    off += sizeof(uint32_t);
    UInt32SetLE(&buf[off], block->nonce);
}

// returns number of bytes written to buf, or total bufLen needed if buf is NULL (block->height is not serialized)
size_t BRMerkleBlockSerialize(const BRMerkleBlock *block, uint8_t *buf, size_t bufLen)
{
    size_t off = 0, len = 80;
    
    assert(block != NULL);
    
    if (block->totalTx > 0) {
        len += sizeof(uint32_t) + BRVarIntSize(block->hashesCount) + block->hashesCount*sizeof(UInt256) +
               BRVarIntSize(block->flagsLen) + block->flagsLen;
    }
    
    if (buf && len <= bufLen) {
        _BRMerkleBlockHeaderBytes(block, buf);
        off = 80;
    
        if (block->totalTx > 0) {
            UInt32SetLE(&buf[off], block->totalTx);
            off += sizeof(uint32_t);
            off += BRVarIntSet(&buf[off], (off <= bufLen ? bufLen - off : 0), block->hashesCount);
            if (block->hashes) memcpy(&buf[off], block->hashes, block->hashesCount*sizeof(UInt256));
            off += block->hashesCount*sizeof(UInt256);
            off += BRVarIntSet(&buf[off], (off <= bufLen ? bufLen - off : 0), block->flagsLen);
            if (block->flags) memcpy(&buf[off], block->flags, block->flagsLen);
            off += block->flagsLen;
        }
    }
    
    return (! buf || len <= bufLen) ? len : 0;
}

static size_t _BRMerkleBlockTxHashesR(const BRMerkleBlock *block, UInt256 *txHashes, size_t hashesCount, size_t *idx,
                                      size_t *hashIdx, size_t *flagIdx, int depth)
{
    uint8_t flag;
    
    if (*flagIdx/8 < block->flagsLen && *hashIdx < block->hashesCount) {
        flag = (block->flags[*flagIdx/8] & (1 << (*flagIdx % 8)));
        (*flagIdx)++;
    
        if (! flag || depth == _ceil_log2(block->totalTx)) {
            if (flag && *idx < hashesCount) {
                if (txHashes) txHashes[*idx] = block->hashes[*hashIdx]; // leaf
                (*idx)++;
            }
        
            (*hashIdx)++;
        }
        else {
            _BRMerkleBlockTxHashesR(block, txHashes, hashesCount, idx, hashIdx, flagIdx, depth + 1); // left branch
            _BRMerkleBlockTxHashesR(block, txHashes, hashesCount, idx, hashIdx, flagIdx, depth + 1); // right branch
        }
    }

    return *idx;
}

// populates txHashes with the matched tx hashes in the block
// returns number of hashes written, or the total hashesCount needed if txHashes is NULL
size_t BRMerkleBlockTxHashes(const BRMerkleBlock *block, UInt256 *txHashes, size_t hashesCount)
{
    size_t idx = 0, hashIdx = 0, flagIdx = 0;

    assert(block != NULL);
    
    return _BRMerkleBlockTxHashesR(block, txHashes, (txHashes) ? hashesCount : SIZE_MAX, &idx, &hashIdx, &flagIdx, 0);
}

// sets the hashes and flags fields for a block created with BRMerkleBlockNew()
void BRMerkleBlockSetTxHashes(BRMerkleBlock *block, const UInt256 hashes[], size_t hashesCount,
                              const uint8_t *flags, size_t flagsLen)
{
    assert(block != NULL);
    assert(hashes != NULL || hashesCount == 0);
    assert(flags != NULL || flagsLen == 0);
    
    if (block->hashes) free(block->hashes);
    block->hashes = (hashesCount > 0) ? malloc(hashesCount*sizeof(UInt256)) : NULL;
    if (block->hashes) memcpy(block->hashes, hashes, hashesCount*sizeof(UInt256));
    if (block->flags) free(block->flags);
    block->flags = (flagsLen > 0) ? malloc(flagsLen) : NULL;
    if (block->flags) memcpy(block->flags, flags, flagsLen);
}

// Computes a block's merkle root from the COMPLETE, in-order list of its transaction hashes (txids) --
// the form a full "block" message delivers (BRPeer.c _BRPeerAcceptBlockMessage), as opposed to the
// partial tree BRMerkleBlockParse/_BRMerkleBlockRootR walk for a "merkleblock". This is what lets a
// caller check a delivered tx list against the header's committed merkleRoot: omitting, adding, or
// substituting any transaction changes the computed root.
//
// NOTE (CVE-2012-2459): the tree duplicates the last node of an odd row, so a mutated list can
// reproduce an honest root. Any row containing an adjacent duplicate pair is therefore rejected
// outright (returns 0) rather than reduced -- a valid block can never contain duplicate txids
// (BIP30), so this only ever rejects a mutation.
//
// Returns 1 and writes *root on success. Returns 0 (leaving *root untouched) on a NULL/empty list,
// an allocation failure, or a mutated tree.
int BRMerkleRootFromTxHashes(UInt256 *root, const UInt256 *txHashes, size_t txCount)
{
    if (! root || ! txHashes || txCount == 0) return 0;
    if (txCount == 1) { *root = txHashes[0]; return 1; } // coinbase-only block: root == the single txid

    // +1 so an odd row can duplicate its last entry in place
    UInt256 *row = malloc((txCount + 1)*sizeof(*row));
    size_t n = txCount;

    if (! row) return 0;
    memcpy(row, txHashes, txCount*sizeof(*row));

    while (n > 1) {
        for (size_t i = 0; i + 1 < n; i += 2) { // pre-duplication row: same comparison Bitcoin Core's mutation check makes
            if (UInt256Eq(row[i], row[i + 1])) { free(row); return 0; }
        }

        if (n & 1) { row[n] = row[n - 1]; n++; } // odd row: duplicate the last entry

        for (size_t i = 0; i < n/2; i++) {
            UInt256 pair[2] = { row[2*i], row[2*i + 1] };

            BRSHA256_2(&row[i], pair, sizeof(pair)); // same concat-then-double-SHA256 _BRMerkleBlockRootR uses
        }

        n /= 2;
    }

    *root = row[0];
    free(row);
    return 1;
}

// recursively walks the merkle tree to calculate the merkle root
// NOTE: this merkle tree design has a security vulnerability (CVE-2012-2459), which can be defended against by
// considering the merkle root invalid if there are duplicate hashes in any rows with an even number of elements
static UInt256 _BRMerkleBlockRootR(const BRMerkleBlock *block, size_t *hashIdx, size_t *flagIdx, int depth)
{
    uint8_t flag;
    UInt256 hashes[2], md = UINT256_ZERO;

    if (*flagIdx/8 < block->flagsLen && *hashIdx < block->hashesCount) {
        flag = (block->flags[*flagIdx/8] & (1 << (*flagIdx % 8)));
        (*flagIdx)++;

        if (flag && depth != _ceil_log2(block->totalTx)) {
            hashes[0] = _BRMerkleBlockRootR(block, hashIdx, flagIdx, depth + 1); // left branch
            hashes[1] = _BRMerkleBlockRootR(block, hashIdx, flagIdx, depth + 1); // right branch

            if (! UInt256IsZero(hashes[0]) && ! UInt256Eq(hashes[0], hashes[1])) {
                if (UInt256IsZero(hashes[1])) hashes[1] = hashes[0]; // if right branch is missing, dup left branch
                BRSHA256_2(&md, hashes, sizeof(hashes));
            }
            else *hashIdx = SIZE_MAX; // defend against (CVE-2012-2459)
        }
        else md = block->hashes[(*hashIdx)++]; // leaf
    }
    
    return md;
}

// the proof-of-work algorithm named by the header's version field, or BLOCK_ALGO_UNKNOWN
// mask (15 << 8) as in the reference client: a version with bit 8 set names no algorithm
int BRMerkleBlockAlgo(const BRMerkleBlock *block)
{
    assert(block != NULL);

    switch (block->version & BLOCK_VERSION_ALGO) {
        case BLOCK_VERSION_SCRYPT:  return BLOCK_VERSION_SCRYPT;
        case BLOCK_VERSION_SHA256D: return BLOCK_VERSION_SHA256D;
        case BLOCK_VERSION_GROESTL: return BLOCK_VERSION_GROESTL;
        case BLOCK_VERSION_SKEIN:   return BLOCK_VERSION_SKEIN;
        case BLOCK_VERSION_QUBIT:   return BLOCK_VERSION_QUBIT;
        case BLOCK_VERSION_ODO:     return BLOCK_VERSION_ODO;
        default:                    return BLOCK_ALGO_UNKNOWN;
    }
}

const char *BRMerkleBlockAlgoName(int algo)
{
    switch (algo) {
        case BLOCK_VERSION_SCRYPT:  return "scrypt";
        case BLOCK_VERSION_SHA256D: return "sha256d";
        case BLOCK_VERSION_GROESTL: return "groestl";
        case BLOCK_VERSION_SKEIN:   return "skein";
        case BLOCK_VERSION_QUBIT:   return "qubit";
        case BLOCK_VERSION_ODO:     return "odo";
        default:                    return "unknown";
    }
}

// computes the proof-of-work hash of the 80-byte header with the algorithm its version names
// returns 1 and writes *out, or returns 0 (leaving *out untouched) for an unknown algorithm
// the struct's powHash field is never written; nothing is cached
int BRMerkleBlockPoWHash(const BRMerkleBlock *block, UInt256 *out)
{
    uint8_t buf[80];
    UInt256 h;

    assert(block != NULL);
    assert(out != NULL);
    _BRMerkleBlockHeaderBytes(block, buf);

    switch (BRMerkleBlockAlgo(block)) {
        case BLOCK_VERSION_SHA256D:
            BRSHA256_2(&h, buf, 80);
            break;

        case BLOCK_VERSION_SCRYPT:
            BRScrypt(&h, sizeof(h), buf, 80, buf, 80, 1024, 1, 1);
            break;

        case BLOCK_VERSION_GROESTL:
            BRGroestl((const char *)buf, (char *)h.u8);
            break;

        case BLOCK_VERSION_SKEIN:
            BRSkein((const char *)buf, (char *)h.u8);
            break;

        case BLOCK_VERSION_QUBIT:
            BRQubit((const char *)buf, (char *)h.u8);
            break;

        case BLOCK_VERSION_ODO:
            // the key changes once per shapechange interval of the header's own timestamp; the
            // interval is a chain parameter (10 days on mainnet, 1 day on testnet)
            BROdocrypt((const char *)buf, block->timestamp,
                       BRNetworkIsTestnet() ? ODOCRYPT_SHAPECHANGE_INTERVAL_TESTNET : ODOCRYPT_CHAPECHANGE_INTERVAL,
                       h.u8);
            break;

        default:
            return 0;
    }

    *out = h;
    return 1;
}

// headers whose computed proof-of-work hash did not meet the header's target, or whose algorithm was unknown;
// counted only when DGB_HEADER_POW_CHECK >= 1 (peer threads validate concurrently, hence atomic)
static atomic_uint _powMismatchCount = 0;

uint32_t BRMerkleBlockPoWMismatchCount(void)
{
    return atomic_load(&_powMismatchCount);
}

// true if merkle tree and timestamp are valid, and proof-of-work matches the stated difficulty target
// NOTE: this only checks if the block difficulty matches the difficulty target in the header, it does not check if the
// target is correct for the block's height in the chain - use BRMerkleBlockVerifyDifficulty() for that
int BRMerkleBlockIsValid(const BRMerkleBlock *block, uint32_t currentTime)
{
    assert(block != NULL);
    
    // target is in "compact" format, where the most significant byte is the size of resulting value in bytes, the next
    // bit is the sign, and the remaining 23bits is the value after having been right shifted by (size - 3)*8 bits
    static const uint32_t maxsize = MAX_PROOF_OF_WORK >> 24, maxtarget = MAX_PROOF_OF_WORK & 0x00ffffff;
    const uint32_t size = block->target >> 24, target = block->target & 0x00ffffff;
    size_t hashIdx = 0, flagIdx = 0;
    UInt256 merkleRoot = _BRMerkleBlockRootR(block, &hashIdx, &flagIdx, 0), t = UINT256_ZERO;
    int r = 1;
    
    // check if merkle root is correct
    if (block->totalTx > 0 && ! UInt256Eq(merkleRoot, block->merkleRoot)) {
        r = 0;

        digi_log("invalid merkleRoot: %s - %s", u256hex(merkleRoot), u256hex(block->merkleRoot));
    }
    
    // check if timestamp is too far in future
    if (block->timestamp > currentTime + BLOCK_MAX_TIME_DRIFT) {
        r = 0;

        digi_log("timestamp too far in future for block (%s, height = %d): %d - %d", u256hex(block->blockHash), block->height, block->timestamp, (currentTime + BLOCK_MAX_TIME_DRIFT));
    }
    
    // check if proof-of-work target is out of range
    if (target == 0 || target & 0x00800000 || size > maxsize || (size == maxsize && target > maxtarget)) {
        r = 0;

        digi_log("target is out of range: %x - %x - %x - %x", target, maxtarget, size, maxsize);
    }
    
#if DGB_HEADER_POW_CHECK >= 1
    // check proof-of-work: the hash computed with the header's own algorithm must not exceed the target
    // (only for a header that passed the checks above, so a header already refused is not hashed)
    if (r) {
        UInt256 pow;
        int algo = BRMerkleBlockAlgo(block), meets = BRMerkleBlockPoWHash(block, &pow);

        if (size > 3) UInt32SetLE(&t.u8[size - 3], target);
        else UInt32SetLE(t.u8, target >> (3 - size)*8);

        for (int i = sizeof(t) - 1; meets && i >= 0; i--) {
            if (pow.u8[i] < t.u8[i]) break;
            if (pow.u8[i] > t.u8[i]) meets = 0;
        }

        if (! meets) {
            atomic_fetch_add(&_powMismatchCount, 1);
            digi_log("pow-mismatch v=%08" PRIx32 " h=%" PRIu32 " algo=%s hash=%s pow=%s target=%08" PRIx32,
                     block->version, block->height, BRMerkleBlockAlgoName(algo), u256hex(block->blockHash),
                     (algo != BLOCK_ALGO_UNKNOWN) ? u256hex(pow) : "-", block->target);
#if DGB_HEADER_POW_CHECK >= 2
            r = 0;
#endif
        }
    }
#else
    (void)t;   // level 0: no proof-of-work hash is computed and the target is not compared
#endif

    return r;
}

// true if the given tx hash is known to be included in the block
int BRMerkleBlockContainsTxHash(const BRMerkleBlock *block, UInt256 txHash)
{
    int r = 0;
    
    assert(block != NULL);
    assert(! UInt256IsZero(txHash));
    
    for (size_t i = 0; ! r && i < block->hashesCount; i++) {
        if (UInt256Eq(block->hashes[i], txHash)) r = 1;
    }
    
    return r;
}

// verifies the block difficulty target is correct for the block's position in the chain
// transitionTime is the timestamp of the block at the previous difficulty transition
// transitionTime may be 0 if block->height is not a multiple of BLOCK_DIFFICULTY_INTERVAL
//
// The difficulty target algorithm is called Multishield.
int BRMerkleBlockVerifyDifficulty(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime)
{
    int r = 1;
    assert(block != NULL);
    
    if (!previous || !UInt256Eq(block->prevBlock, previous->blockHash) || block->height != previous->height + 1)
        r = 0;

    if (BRNetworkIsTestnet()) {
        // TODO: implement testnet difficulty rule check
        return r; // don't worry about difficulty on testnet for now
    }

    // TODO: fix difficulty target check for Digibyte (Multishield)
    /*if (r && (block->height % BLOCK_DIFFICULTY_INTERVAL) == 0) {
        // target is in "compact" format, where the most significant byte is the size of resulting value in bytes, next
        // bit is the sign, and the remaining 23bits is the value after having been right shifted by (size - 3)*8 bits
        static const uint32_t maxsize = MAX_PROOF_OF_WORK >> 24, maxtarget = MAX_PROOF_OF_WORK & 0x00ffffff;
        int timespan = (int)((int64_t)previous->timestamp - (int64_t)transitionTime), size = previous->target >> 24;
        uint64_t target = previous->target & 0x00ffffff;
    
        // limit difficulty transition to -75% or +400%
        if (timespan < TARGET_TIMESPAN/4) timespan = TARGET_TIMESPAN/4;
        if (timespan > TARGET_TIMESPAN*4) timespan = TARGET_TIMESPAN*4;
    
        // TARGET_TIMESPAN happens to be a multiple of 256, and since timespan is at least TARGET_TIMESPAN/4, we don't
        // lose precision when target is multiplied by timespan and then divided by TARGET_TIMESPAN/256
        target *= timespan;
        target /= TARGET_TIMESPAN >> 8;
        size--; // decrement size since we only divided by TARGET_TIMESPAN/256
    
        while (size < 1 || target > 0x007fffff) target >>= 8, size++; // normalize target for "compact" format
    
        // limit to MAX_PROOF_OF_WORK
        if (size > maxsize || (size == maxsize && target > maxtarget)) target = maxtarget, size = maxsize;
    
        if (block->target != ((uint32_t)target | size << 24)) r = 0;
    }
    else if (r && block->target != previous->target) r = 0;*/
    
    return r;
}

// frees memory allocated by BRMerkleBlockParse
void BRMerkleBlockFree(BRMerkleBlock *block)
{
    assert(block != NULL);
    
    if (block->hashes) free(block->hashes);
    if (block->flags) free(block->flags);
    free(block);
}
