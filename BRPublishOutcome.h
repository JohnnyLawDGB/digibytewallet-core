//
//  BRPublishOutcome.h
//
//  What the app should do with the result of a transaction publish.
//
//  Until v4.0.42 nothing could reach this decision: the JNI passed a NULL
//  callback to BRPeerManagerPublishTx, so a send the network refused was
//  indistinguishable from one it accepted -- and the wallet had already marked
//  its inputs spent either way. The callback is now wired; this turns the errno
//  it delivers into an action.
//
//  ## Why ETIMEDOUT is the interesting one
//
//  Peers do not announce rejections -- BIP61 reject messages are long gone -- so
//  SILENCE IS THE ONLY EVIDENCE a transaction was refused. That is exactly the
//  live failure this work came from: an asset transfer that published, reported
//  six relays, and existed in no mempool and no block, because it spent an output
//  no other node had ever seen.
//
//  But silence is also what a merely-slow relay looks like, so it is deliberately
//  NOT terminal. The asymmetry is the whole point: WRONGLY RETRYING COSTS A
//  LITTLE RADIO; WRONGLY DESTROYING A SEND LOSES A TRANSACTION THAT WAS STILL
//  PROPAGATING. Only Rejected -- where the core itself says the transaction is
//  malformed -- may be terminal, and an unrecognised code always falls back to
//  retryable.
//
//  ## Why this moved out of Kotlin (core/sync/PublishOutcome.kt)
//
//  The Kotlin original hardcoded the errno values as literals:
//
//      const val EINVAL = 22
//      const val ENOTCONN = 107
//      const val ETIMEDOUT = 110
//
//  with the comment "named here so the policy reads without a platform header."
//  Those are LINUX values. On Darwin, ENOTCONN is 57 and ETIMEDOUT is 60. The
//  same core compiled for iOS would deliver 60 for a timeout, match no case, and
//  fall to the default -- so UnconfirmedDelivery would be UNREACHABLE on iOS and
//  the one failure mode this file exists to surface would go invisible. It fails
//  safe (both branches retry, neither is terminal), which is precisely why it
//  would have shipped unnoticed.
//
//  The fix is not a second table of Darwin numbers. It is to stop hardcoding:
//  this header includes <errno.h> and switches on the SYMBOLS, so it is correct
//  on every platform the core compiles for, by construction.
//
//  Callers should prefer BRPublishOutcomeOf() over comparing raw errno at the
//  call site, for the same reason.
//
//  Header-only static-inline predicate over a caller-supplied scalar -- no
//  BRPeerManager, no locking, no I/O -- so it is testable standalone on the host
//  (see native/src/test/host/publish_outcome_kat/). Same shape as
//  BRCFRecoveryPolicy.h and BRPeerCFStatus.h.
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

#ifndef BRPublishOutcome_h
#define BRPublishOutcome_h

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    // A peer relayed it back to us. The network has it.
    BRPublishKindAccepted = 0,

    // The core refused it outright -- malformed or unsigned. Never acceptable.
    BRPublishKindRejected = 1,

    // It never reached the wire (offline, or the publish was cancelled).
    BRPublishKindNotDelivered = 2,

    // It reached the wire and no peer echoed it back. Suspicious, not conclusive.
    BRPublishKindUnconfirmedDelivery = 3,
} BRPublishKind;

typedef struct {
    BRPublishKind kind;

    // Worth publishing again. 0 only when the send is finished or provably hopeless.
    int shouldRetry;

    // Proven never-acceptable, so the wallet may stop treating its inputs as spent.
    int isTerminal;
} BRPublishOutcome;

// Map a publish errno -- as delivered by BRPeerManagerPublishTx and its
// cancellation paths -- to an action.
//
//   0          a peer relayed the transaction back: genuine acceptance
//   EINVAL     the transaction is not signed / malformed
//   ENOTCONN   not connected, or a disconnect cancelled the pending publish
//   ETIMEDOUT  it went out and NO peer echoed it back before the timeout
//
// ENOTCONN is listed explicitly even though it shares the default's action: the
// two mean different things to a reader, and collapsing them would hide that the
// default is a deliberate fail-safe rather than an oversight.
static inline BRPublishOutcome BRPublishOutcomeOf(int error)
{
    BRPublishOutcome o;

#ifdef PUBLISH_OUTCOME_LINUX_LITERALS_UNFIXED
    // RED-gate shape only: the pre-fix Kotlin table, with Linux errno values
    // written as literals. Never defined in a production build. On Linux this is
    // INDISTINGUISHABLE from the correct code -- which is precisely why the bug
    // survived -- so the host KAT only enforces the gate on a platform whose
    // ETIMEDOUT is not 110.
    switch (error) {
        case 0:   o.kind = BRPublishKindAccepted;
                  o.shouldRetry = 0; o.isTerminal = 0; return o;
        case 22:  o.kind = BRPublishKindRejected;
                  o.shouldRetry = 0; o.isTerminal = 1; return o;
        case 110: o.kind = BRPublishKindUnconfirmedDelivery;
                  o.shouldRetry = 1; o.isTerminal = 0; return o;
        case 107:
        default:  o.kind = BRPublishKindNotDelivered;
                  o.shouldRetry = 1; o.isTerminal = 0; return o;
    }
#endif

    switch (error) {
        case 0:
            o.kind = BRPublishKindAccepted;
            o.shouldRetry = 0; o.isTerminal = 0; break;

        case EINVAL:
            o.kind = BRPublishKindRejected;
            o.shouldRetry = 0; o.isTerminal = 1; break;

        case ETIMEDOUT:
            o.kind = BRPublishKindUnconfirmedDelivery;
            o.shouldRetry = 1; o.isTerminal = 0; break;

        case ENOTCONN:
            o.kind = BRPublishKindNotDelivered;
            o.shouldRetry = 1; o.isTerminal = 0; break;

        default:
            // Assume the transaction is fine and the delivery was not. Fails safe
            // -- see the asymmetry note at the top. NOTHING may reach isTerminal
            // by accident.
            o.kind = BRPublishKindNotDelivered;
            o.shouldRetry = 1; o.isTerminal = 0; break;
    }

    return o;
}

// True only for Accepted -- the one state that may honestly be shown as "sent".
static inline int BRPublishOutcomeUserVisiblySent(int error)
{
    return BRPublishOutcomeOf(error).kind == BRPublishKindAccepted;
}

// The platform's own errno values, exposed so a consumer that must carry its own
// copy of this table (the Kotlin mirror) can assert its constants against the
// platform rather than against a comment. Returns 0 for an index out of range.
//
// Index: 0 = EINVAL, 1 = ENOTCONN, 2 = ETIMEDOUT.
#define BR_PUBLISH_ERRNO_EINVAL_IDX    0
#define BR_PUBLISH_ERRNO_ENOTCONN_IDX  1
#define BR_PUBLISH_ERRNO_ETIMEDOUT_IDX 2

static inline int BRPublishErrnoValue(int index)
{
    switch (index) {
        case BR_PUBLISH_ERRNO_EINVAL_IDX:    return EINVAL;
        case BR_PUBLISH_ERRNO_ENOTCONN_IDX:  return ENOTCONN;
        case BR_PUBLISH_ERRNO_ETIMEDOUT_IDX: return ETIMEDOUT;
        default: return 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif // BRPublishOutcome_h
