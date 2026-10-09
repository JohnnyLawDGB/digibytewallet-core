//
//  BRSavedBlocks.h
//
//  Parsing the persisted saved-blocks blob back into BRMerkleBlocks.
//
//  Every SPV wallet keeps a window of block headers near the tip so a restart
//  resumes there instead of re-scanning from a checkpoint. The core produces
//  that blob (the `saveBlocks` callback hands the host an immutable serialized
//  buffer); this reads it back. Until now only Android could: the parser lived
//  in `native/src/main/jni/bridge/saved_blocks_deserialize.h`, an Android-only
//  compilation unit the XCFramework does not contain, so the iOS port had no
//  way to resume and re-synced ~126,000 blocks on every launch.
//
//  It is pure and always was -- no JNI, no locking, no I/O -- which is why this
//  is a move rather than a rewrite. The Android bridge header now forwards here
//  so both platforms parse with one implementation. A second parser for a
//  persistence format is how two wallets on the same seed come to disagree
//  about which blocks they have.
//
//  THE GUARD IS THE POINT, and it is fund-safety-adjacent rather than cosmetic.
//  A corrupt or truncated blob can carry an absurd leading 4-byte count.
//  Allocating `count * sizeof(BRMerkleBlock *)` unconditionally and not
//  checking the result means that on a memory-constrained device a huge count
//  makes malloc return NULL and the first `blocks[loaded++] = block` write is a
//  NULL dereference -- on EVERY subsequent launch, because the same corrupt
//  blob is reloaded each time. That is an unrecoverable boot loop, fixed only
//  by clearing app data, i.e. by the user losing a wallet they may not have
//  backed up. Rejecting absurd counts up front and null-checking the allocation
//  makes the load fail closed: return 0, the caller drops the blob and
//  re-syncs, which costs minutes instead of everything.
//
//  The ceiling mirrors the sibling guard in `loadSerializedTransactions`
//  (`jni_transaction_persist.c`), which rejects `txCount == 0 || txCount >
//  10000`. Saved blocks get a higher one because a long-lived wallet's retained
//  segment runs to tens of thousands of headers -- but never near a garbage
//  32-bit count.
//
//  Header-only static-inline; testable standalone on the host
//  (native/src/test/host/saved_blocks_core_kat/), where it is driven against
//  the real BRMerkleBlockParse rather than a stand-in.
//
//  C ONLY -- it includes BRInt.h, which is not valid C++ (anonymous unions
//  inside cast expressions, a GNU C extension, plus narrowing conversions in
//  initializer lists). Harmless for Swift, whose C interop uses the C compiler;
//  the consequence is that an Objective-C++ bridging file must not include
//  this. Same constraint as BRPeerPenaltyPersist.h -- see push-down-recipe.md.
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

#ifndef BRSavedBlocks_h
#define BRSavedBlocks_h

#include <stdint.h>
#include <stdlib.h>

#include "BRInt.h"
#include "BRMerkleBlock.h"

#ifdef __cplusplus
extern "C" {
#endif

// Absurd-count ceiling. See the banner: this is what stands between a corrupt
// blob and an unrecoverable boot loop.
#define BR_SAVED_BLOCKS_MAX_COUNT 100000

// Parse a persisted saved-blocks buffer:
//
//   [4 bytes: LE block count]
//   repeated: [4 bytes blockLen][4 bytes height][blockLen bytes serialized block]
//
// On a sane, in-range count, allocates *outBlocks and returns the number of
// blocks actually parsed (<= count, and further bounded by the buffer length
// through the per-iteration `pos + N <= len` checks, so a truncated blob yields
// a short read rather than an overrun).
//
// OWNERSHIP: the caller owns the returned array AND each BRMerkleBlock * in it
// -- until it hands them to BRPeerManagerNew, which ADOPTS the block pointers
// and frees them individually as it prunes. After that the caller must free
// only the array and must never touch the elements again. Getting this wrong is
// not theoretical: on Android both layers once freed the same blocks, and ASan
// on-device reported 21 heap-buffer-overflows and 4 use-after-frees, every one
// on a 192-byte region -- exactly sizeof(BRMerkleBlock).
//
// On a corrupt count (0, or above BR_SAVED_BLOCKS_MAX_COUNT) or a failed
// allocation, sets *outBlocks = NULL and returns 0 without ever sizing an
// allocation from that count again.
static inline size_t BRSavedBlocksDeserialize(const uint8_t *b, size_t len,
                                              BRMerkleBlock ***outBlocks)
{
    size_t pos = 0, loaded = 0;
    uint32_t count, i;
    BRMerkleBlock **blocks;

    if (! outBlocks) return 0;
    *outBlocks = NULL;
    if (! b || len < 4) return 0;

    count = UInt32GetLE(&b[pos]); pos += 4;
#ifndef SAVED_BLOCKS_COUNT_UNGUARDED
    if (count == 0 || count > BR_SAVED_BLOCKS_MAX_COUNT) return 0;
#else
    // RED-gate shape only: the pre-fix code, which sized an allocation straight
    // from an attacker- or corruption-supplied 32-bit count. Never defined in a
    // production build.
#endif

    blocks = (BRMerkleBlock **)malloc((size_t)count * sizeof(BRMerkleBlock *));
    if (! blocks) return 0;

    for (i = 0; i < count && pos + 8 <= len; i++) {
        uint32_t blockLen = UInt32GetLE(&b[pos]); pos += 4;
        uint32_t height   = UInt32GetLE(&b[pos]); pos += 4;
        BRMerkleBlock *block;

#ifdef BB_2026_10_09_HARLEY_UNFIXED
        if (pos + blockLen > len) break;   // comparison shape: wraps on a 32-bit size_t
#else
        if (blockLen > len - pos) break;   // pos <= len holds here (loop condition)
#endif
        block = BRMerkleBlockParse(&b[pos], blockLen);
        pos += blockLen;

        if (block) {
            block->height = height;
            blocks[loaded++] = block;
        }
    }

    *outBlocks = blocks;
    return loaded;
}

#ifdef __cplusplus
}
#endif

#endif // BRSavedBlocks_h
