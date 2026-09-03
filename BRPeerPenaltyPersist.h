//
//  BRPeerPenaltyPersist.h
//
//  Persistence policy for the peer re-dial penalty set.
//
//  The whole point of this header is one distinction: **"nothing to save" and
//  "can't tell right now" are different answers.** An empty penalty set still
//  serializes to a 4-byte count header (see BRPeerPenalty.h's wire format), so a
//  NULL blob means the native side could not answer -- the peer manager was
//  momentarily absent, or the probe threw. Treating that as "empty" would delete
//  penalties already banked, which is the opposite of what a transient hiccup
//  should cost.
//
//  The same "unknown is not empty" rule guards the asset spent-state reconcile
//  and the owned-script cache; this is the peer-side instance of it.
//
//  Ported from core/sync/PeerPenaltyPersist.kt. The reason it belongs here
//  rather than in platform code: the 4-byte floor is not a policy choice, it is
//  a fact about BRPeerPenaltySerialize's output. A platform that carries its own
//  copy of that number is a platform that can disagree with the serializer --
//  and the failure mode is silently discarding a wallet's banked penalties,
//  which is the on-ramp to the 0-peer dead wedge the penalty set exists to
//  prevent.
//
//  Hex encoding stays on the platform side: it is a storage detail (Android
//  puts the blob in SharedPreferences as a String), not a wallet-state decision.
//  What must not differ across platforms is the empty/unknown/store CHOICE.
//
//  Header-only static-inline predicate over caller-supplied scalars -- no
//  BRPeerManager, no locking, no I/O; testable standalone on the host (see
//  native/src/test/host/peer_penalty_persist_kat/).
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

#ifndef BRPeerPenaltyPersist_h
#define BRPeerPenaltyPersist_h

#include <stdint.h>
#include <stddef.h>

// For BR_PEER_PENALTY_HEADER_BYTES. Deliberately included rather than
// redefined.
//
// This is the whole lesson of this file in miniature. The 4-byte floor was
// ALREADY a C constant (BRPeerPenalty.h:73, alongside
// BR_PEER_PENALTY_ENTRY_BYTES) -- PeerPenaltyPersist.kt duplicated it as a
// Kotlin `const val HEADER_BYTES = 4`, and the first draft of this header
// duplicated it a THIRD time as sizeof(uint32_t). The compiler caught that one
// with a macro-redefinition warning; nothing catches the Kotlin copy, which is
// exactly why the parity test exists.
//
// A platform that carries its own copy of this number can disagree with
// BRPeerPenaltySerialize, and the failure mode is silently discarding a
// wallet's banked penalties -- the on-ramp to the 0-peer dead wedge the penalty
// set exists to prevent.
#include "BRPeerPenalty.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    // Can't tell -- leave any stored blob exactly as it is.
    BRPeerPenaltyActionKeep = 0,

    // Definitely empty -- drop the stored blob so it isn't restored next launch.
    BRPeerPenaltyActionClear = 1,

    // Live entries to persist.
    BRPeerPenaltyActionStore = 2,
} BRPeerPenaltyAction;

// What to do with a freshly-probed penalty blob.
//
//   blob == NULL                     the probe could not answer  -> Keep
//   blobLen <  HEADER_BYTES          a truncated/garbage answer   -> Keep
//   blobLen == HEADER_BYTES          a real, empty set            -> Clear
//   blobLen >  HEADER_BYTES          live entries                 -> Store
//
// The short-blob case folds into Keep deliberately. A blob too small to hold
// even its own count header is not evidence of emptiness -- it is evidence the
// read went wrong -- and the asymmetry is the same as the NULL case: wrongly
// keeping stale penalties costs a few skipped dials, wrongly clearing them
// hands the wallet back to a fleet that is refusing it.
static inline BRPeerPenaltyAction BRPeerPenaltyDecide(const uint8_t *blob, size_t blobLen)
{
#ifdef PEER_PENALTY_NULL_IS_EMPTY_UNFIXED
    // RED-gate shape only: the pre-fix behaviour, where a probe that could not
    // answer was read as "empty" and cleared the stored set. Never defined in a
    // production build.
    if (blob == 0 || blobLen <= BR_PEER_PENALTY_HEADER_BYTES) return BRPeerPenaltyActionClear;
    return BRPeerPenaltyActionStore;
#endif
    if (blob == 0 || blobLen < BR_PEER_PENALTY_HEADER_BYTES) return BRPeerPenaltyActionKeep;
    if (blobLen == BR_PEER_PENALTY_HEADER_BYTES) return BRPeerPenaltyActionClear;
    return BRPeerPenaltyActionStore;
}

// Convenience: does this length alone imply a decision? Exposed so a caller that
// has a length but not the buffer (a JNI array length, a file stat) asks the same
// question rather than reimplementing the thresholds. A length with no buffer is
// still Keep when it is short.
static inline BRPeerPenaltyAction BRPeerPenaltyDecideLength(size_t blobLen)
{
    if (blobLen < BR_PEER_PENALTY_HEADER_BYTES) return BRPeerPenaltyActionKeep;
    if (blobLen == BR_PEER_PENALTY_HEADER_BYTES) return BRPeerPenaltyActionClear;
    return BRPeerPenaltyActionStore;
}

#ifdef __cplusplus
}
#endif

#endif // BRPeerPenaltyPersist_h
