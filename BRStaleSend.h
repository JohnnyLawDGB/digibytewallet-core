//
//  BRStaleSend.h
//
//  The stale-send clear's decision (Android 4.1.3, review R8): whether one of the wallet's own
//  unconfirmed sends, valid and not orphaned, went nowhere, so the clear removes it and its
//  coins come back. Every unconfirmed DigiDollar send is held pending, so a send that never
//  relayed kept its coins for good until this rule.
//
//  A send is STALE when both hold:
//    - it is old enough: it has a timestamp (above 0) and is BR_STALE_SEND_MIN_AGE_S (one day)
//      old or more. A send with no timestamp is never old enough; time differences wrap as
//      Kotlin's Long does.
//    - the network never took it, on the evidence of the PINNED node alone (the wallet's own
//      default endpoint; a custom endpoint may be blocksonly or keep no transaction index, so
//      it is never asked):
//        1. the send has at least one input (a send with none is never asked about);
//        2. the node's answer for the txid is its own "Transaction not found"
//           (BRStaleSendTxUnknown); confirmed, in the mempool, or no usable answer stops it;
//        3. every input, asked in order, is still unspent there by the node's explicit answer
//           (BRStaleSendInputUnspent); "spent" or no answer stops it, and no later input is
//           asked. A send the network did take has its inputs spent there, confirmed or not, so
//           this catches a node that merely failed to index it.
//
//  The platform does the network calls; the core says which one comes next. The caller starts
//  with BRStaleSendTxNotAsked and no inputs asked, and calls BRStaleSendNextStep again after
//  each answer, until it answers BRStaleSendNotShown or BRStaleSendNeverRelayed. Ask only when
//  BRStaleSendOldEnough holds (the node is asked about no younger send), then decide with
//  BRStaleSendIsStale. Any value this header does not define reads as "no evidence": the send
//  is kept. A kept send is the safe side, since a removed one gives its coins back.
//
//  Until 2026-11 this rule lived in Android Kotlin (StaleSendPredicate in WalletManager.kt and
//  DgbNodeClient.sendNeverRelayed), out of reach of the iOS build. Android now calls it through
//  JNI (jni_stale_send.c). The parse of the node's HTTP answers into the codes below stays the
//  platform's (DgbNodeClient: parseTxNetworkStatus, parseSpendingAnswer).
//
//  Host KAT: digibytewallet-android native/src/test/host/stale_send_kat/. Two comparison seams,
//  each failing only its own cases: STALE_SEND_AGE_RED (the age) and STALE_SEND_RELAY_RED (the
//  node's evidence).
//  Header-only, static inline, libc only.
//

#ifndef BRStaleSend_h
#define BRStaleSend_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// One day. A plain literal, so Swift's C importer sees it (it skips expression macros).
#define BR_STALE_SEND_MIN_AGE_S  86400LL

// The node's answer for the send's txid. The values are fixed: the platforms pass them as ints.
typedef enum {
    BRStaleSendTxNotAsked    = 0, // not asked yet
    BRStaleSendTxConfirmed   = 1, // known, in a block
    BRStaleSendTxInMempool   = 2, // known, unconfirmed
    BRStaleSendTxUnknown     = 3, // the node's own "Transaction not found"
    BRStaleSendTxUnavailable = 4  // anything else: an error, a foreign 404, no network
} BRStaleSendTxStatus;

// The node's answer for one input (an output of the transaction it spends).
typedef enum {
    BRStaleSendInputNoAnswer = 0, // no usable answer
    BRStaleSendInputUnspent  = 1, // the explicit "spent": false
    BRStaleSendInputSpent    = 2  // the explicit "spent": true
} BRStaleSendInputAnswer;

// What the caller does next.
typedef enum {
    BRStaleSendNotShown      = 0, // stop: the evidence does not show the network never took it
    BRStaleSendNeverRelayed  = 1, // stop: the network never took it
    BRStaleSendAskTx         = 2, // ask the node for the txid
    BRStaleSendAskInput      = 3  // ask the node for input number inputsAsked (from 0)
} BRStaleSendStep;

// Whether a send with this timestamp is old enough to ask the node about at nowS (seconds).
static inline int BRStaleSendOldEnough(int64_t timestampS, int64_t nowS)
{
    int64_t age = (int64_t)((uint64_t)nowS - (uint64_t)timestampS);
#ifdef STALE_SEND_AGE_RED
    // RED ARM SEAM (stale_send_kat): no timestamp guard, and exactly one day is not yet old enough.
    return age > BR_STALE_SEND_MIN_AGE_S;
#else
    return timestampS > 0 && age >= BR_STALE_SEND_MIN_AGE_S;
#endif
}

// The next step in asking the node whether the network never took a send.
//   pinnedNode       nonzero when the node is the wallet's own default endpoint
//   inputCount       the send's inputs
//   txStatus         a BRStaleSendTxStatus: the node's answer for the txid, or BRStaleSendTxNotAsked
//   inputsAsked      inputs asked so far, in order
//   lastInputAnswer  a BRStaleSendInputAnswer for input inputsAsked - 1 (ignored when none asked)
static inline BRStaleSendStep BRStaleSendNextStep(int pinnedNode, size_t inputCount, int txStatus,
                                                  size_t inputsAsked, int lastInputAnswer)
{
#ifdef STALE_SEND_RELAY_RED
    // RED ARM SEAM (stale_send_kat): any node is asked, and an input with no answer reads as
    // unspent (only an explicit "spent" stops it).
    (void)pinnedNode;
    if (inputCount == 0) return BRStaleSendNotShown;
    if (txStatus == BRStaleSendTxNotAsked) return BRStaleSendAskTx;
    if (txStatus != BRStaleSendTxUnknown) return BRStaleSendNotShown;
    if (inputsAsked > 0 && lastInputAnswer == BRStaleSendInputSpent) return BRStaleSendNotShown;
#else
    if (! pinnedNode || inputCount == 0) return BRStaleSendNotShown;
    if (txStatus == BRStaleSendTxNotAsked) return BRStaleSendAskTx;
    if (txStatus != BRStaleSendTxUnknown) return BRStaleSendNotShown;
    if (inputsAsked > 0 && lastInputAnswer != BRStaleSendInputUnspent) return BRStaleSendNotShown;
#endif
    if (inputsAsked > inputCount) return BRStaleSendNotShown;  // more answers than inputs: misuse
    if (inputsAsked < inputCount) return BRStaleSendAskInput;
    return BRStaleSendNeverRelayed;
}

// Whether the send is stale: old enough, and the node's evidence (BRStaleSendNextStep's
// BRStaleSendNeverRelayed) says the network never took it.
static inline int BRStaleSendIsStale(int64_t timestampS, int64_t nowS, int neverRelayed)
{
    return BRStaleSendOldEnough(timestampS, nowS) && neverRelayed;
}

#ifdef __cplusplus
}
#endif

#endif // BRStaleSend_h
