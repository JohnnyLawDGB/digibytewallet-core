//
//  BRPreparedSend.h
//
//  The two decisions between a DGB send's review and its signature: the fee its confirmation
//  shows, and whether the bytes about to be signed are still the send that was approved. They
//  decide what is signed, so both platforms take them from here. Until 2026-10 they lived in the
//  Android JNI bridge (prepared_send.h, called by jni_transaction.c's quoteTransaction and
//  signPreparedTransaction), which the iOS XCFramework does not contain.
//
//  Not everything the signer checks. Since Android 4.1.2 its signer also refuses a coin another
//  signed-but-unregistered send has claimed (bridge coin_reservation.h; released as BRWalletSend.h
//  step 1b describes) and re-checks the inputs are unspent (spend_guard.h). BRPreparedSendCheck asks
//  BRWalletOutpointSelectable, which already leaves out coins a pending send spends, but it cannot
//  see two prepared sends signed before either is registered. A platform that can sign two sends at once
//  needs the reservation too (a push-down candidate).
//
//  The flow. A send is built (BRWalletCreateTransactionAtFeePerKb) and quoted at review, before
//  the credential prompt, and the SAME bytes are signed after it. The prepared state is those
//  bytes plus their quote -- never a live BRTransaction -- so nothing native outlives the prompt.
//  The wallet can change while the prompt is up: another send can spend a coin, asset detection
//  can hold one out of the plain set, a coin's transaction can leave the wallet. So:
//
//    BRPreparedSendQuote   the fee a confirmation shows: the transaction's inputs minus its
//                          outputs, looked up in the wallet's own transactions (serialized bytes
//                          carry no input amounts), and the virtual size it was built at. None
//                          when an input is not a transaction the wallet holds: the fee is then
//                          unknown, and no figure may be shown in its place.
//
//    BRPreparedSendCheck   only what was approved is signed: the outputs are exactly the approved
//                          payment (that amount to that script) plus at most one change output to
//                          an address of this wallet, they pay exactly the approved fee, and every
//                          coin they spend is still one the wallet's own selection would spend
//                          (SEND-GATE-SET, BRPreparedSendCoinOK): never an unconfirmed coin someone
//                          else sent, an asset-held, ONE-FAMILY-held or unsignable output.
//                          Call it twice: on the parsed bytes BEFORE signing (sign only on
//                          BRPreparedSendOK), and on the signed transaction AFTER signing (hand the
//                          signed bytes back to be broadcast only on BRPreparedSendOK). Signing
//                          changes no output or amount, so the second call passes unless something
//                          else is wrong -- and then nothing is broadcast.
//
//  The approved fee is the quote shown at review, carried with the bytes; never a figure computed
//  again after the prompt.
//
//  SEND-GATE-SET (Android 4.1.4, bridge prepared_send.h, the same rule): the coins a prepared send
//  may spend are the coins the wallet's own selection would spend (BRWalletSelectableUTXOs), not the
//  raw set its balance sums (BRWalletUTXOs, which also holds an unconfirmed coin someone else sent
//  and an output the wallet cannot sign). Each input is asked alone (BRWalletOutpointSelectable, its
//  own walk budget), so a wallet with many unconfirmed coins cannot use up one shared budget before
//  the check reaches a coin selection already took.
//
//  Ownership: nothing here keeps a pointer past the call or takes ownership of anything. The
//  wallet, transaction and payment script stay the caller's. BRPreparedSendCheck asks the wallet
//  once per input (under the wallet's own lock each time); the caller must not hold the wallet's
//  lock.
//
//  MACRO CONVENTION: PREPARED_SEND_UNFIXED is tested by VALUE (#if). =1 is the host KATs'
//  comparison arm, the behaviour before these rules: the typical-send figure every confirmation
//  showed (BRFeePolicy.h's BR_FEE_DEFAULT_ESTIMATE_SATS at BR_FEE_TYPICAL_TX_VSIZE), and nothing
//  checked before signing. Unset or =0 is what ships; =0 never builds the comparison arm. Never
//  defined in a production build.
//
//  SEND_GATE_SET_UNFIXED, also tested by VALUE, the SEND-GATE-SET comparison arms (the bridge copy's
//  values): =1 is the membership set before that item (BRWalletUTXOs, the raw set the balance sums);
//  =2 is the selectable set enumerated whole (BRWalletSelectableUTXOs), whose one walk budget can run
//  out before the check reaches a coin selection took. Unset or =0 ships: each input asked alone
//  (BRWalletOutpointSelectable). Never defined in a production build.
//
//  The rules are the bridge copy's (digibytewallet-android native/src/main/jni/bridge/prepared_send.h)
//  name for name: prepared_send_quote, prepared_send_check, prepared_send_coin_ok and PREPARED_SEND_*
//  are BRPreparedSendQuote, BRPreparedSendCheck, BRPreparedSendCoinOK and BRPreparedSend*, with the
//  same verdict values and the same seams, so the bridge can include this header in its place.
//
//  Host KATs: digibytewallet-android native/src/test/host/prepared_send_core_kat/ (this header
//  against fee_quote_kat's cases, every arm) and fee_quote_kat/ (the bridge copy).
//  Header-only, static inline; no I/O.
//

#ifndef BRPreparedSend_h
#define BRPreparedSend_h

#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRInt.h"
#include "BRFeePolicy.h"   // BR_FEE_TYPICAL_TX_VSIZE, BR_FEE_DEFAULT_ESTIMATE_SATS (the comparison arm)
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PREPARED_SEND_UNFIXED
#define PREPARED_SEND_UNFIXED 0
#endif

#ifndef SEND_GATE_SET_UNFIXED
#define SEND_GATE_SET_UNFIXED 0
#endif

typedef enum {
    BRPreparedSendOK = 0,
    BRPreparedSendFeeUnknown = 1,        // an input is not a transaction the wallet holds: the fee cannot be told
    BRPreparedSendFeeChanged = 2,        // the transaction does not pay exactly the approved fee
    BRPreparedSendCoinUnavailable = 3,   // a coin it spends is not one the wallet's own selection would spend
    BRPreparedSendNotApproved = 4        // its outputs are not the approved payment plus change to a wallet address
} BRPreparedSendVerdict;

// The quote for a transaction the wallet built: 1 with *feeOut (satoshis) and *vsizeOut (vbytes)
// set, or 0 when there is none -- the fee is unknown (an input is not a transaction the wallet
// holds, or the transaction has no inputs) or does not fit a signed 64-bit value -- with both left
// as they were.
static inline int BRPreparedSendQuote(BRWallet *wallet, const BRTransaction *tx, uint64_t *feeOut,
                                      uint64_t *vsizeOut)
{
#if PREPARED_SEND_UNFIXED
    // RED ARM SEAM (fee_quote_kat, prepared_send_kat): the typical figure, whatever was built.
    (void)wallet; (void)tx;
    *feeOut = BR_FEE_DEFAULT_ESTIMATE_SATS;
    *vsizeOut = BR_FEE_TYPICAL_TX_VSIZE;
    return 1;
#else
    uint64_t fee;
    size_t vsize;

    if (! wallet || ! tx || ! feeOut || ! vsizeOut || tx->inCount == 0) return 0;
    fee = BRWalletFeeForTx(wallet, tx);                  // UINT64_MAX: an input the wallet does not hold
    vsize = BRTransactionVSize(tx);
    if (fee == UINT64_MAX || fee > (uint64_t)INT64_MAX || vsize == 0) return 0;
    *feeOut = fee;
    *vsizeOut = (uint64_t)vsize;
    return 1;
#endif
}

// 1 when tx's outputs are exactly the approved payment -- payAmount to payScript -- plus at most
// one change output paying an address of this wallet; 0 for anything else: another recipient,
// another amount, an output nobody approved, change to an address that is not the wallet's, a
// zero-value change output, or no approved payment (payScript NULL or empty, payAmount 0).
static inline int BRPreparedSendPaysAsApproved(BRWallet *wallet, const BRTransaction *tx,
                                               const uint8_t *payScript, size_t payScriptLen,
                                               uint64_t payAmount)
{
    size_t payments = 0, change = 0;

    if (! wallet || ! tx) return 0;
    if (! payScript || payScriptLen == 0 || payAmount == 0 || tx->outCount == 0 || tx->outCount > 2) return 0;
    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];

        if (payments == 0 && o->amount == payAmount && o->script && o->scriptLen == payScriptLen &&
            memcmp(o->script, payScript, payScriptLen) == 0) payments++;
        else if (o->amount > 0 && o->address[0] != '\0' && BRWalletContainsAddress(wallet, o->address)) change++;
        else return 0;
    }
    return payments == 1 && change <= 1;
}

// 1 when the outpoint (hash, n) is among utxos[0..count).
static inline int BRPreparedSendHasCoin(const BRUTXO *utxos, size_t count, UInt256 hash, uint32_t n)
{
    for (size_t i = 0; utxos && i < count; i++) {
        if (utxos[i].n == n && UInt256Eq(utxos[i].hash, hash)) return 1;
    }
    return 0;
}

// SEND-GATE-SET: 1 when the coin (hash, n) is one a prepared send may spend -- one the wallet's own
// selection would spend -- else 0 (also for a NULL wallet, and when a comparison arm cannot copy its
// list). Asked of that outpoint alone (BRWalletOutpointSelectable, its own walk budget).
static inline int BRPreparedSendCoinOK(BRWallet *wallet, UInt256 hash, uint32_t n)
{
#if SEND_GATE_SET_UNFIXED == 1 || SEND_GATE_SET_UNFIXED == 2
    // RED ARM SEAM (prepared_send_core_kat): =1 the raw set the balance sums; =2 the whole selectable
    // set enumerated under one walk budget.
    size_t count;
    BRUTXO *u;
    int r;

    if (! wallet) return 0;
#if SEND_GATE_SET_UNFIXED == 1
    count = BRWalletUTXOs(wallet, NULL, 0);
#else
    count = BRWalletSelectableUTXOs(wallet, NULL, 0);
#endif
    u = calloc(count ? count : 1, sizeof(*u));
    if (! u) return 0;
#if SEND_GATE_SET_UNFIXED == 1
    count = BRWalletUTXOs(wallet, u, count);
#else
    count = BRWalletSelectableUTXOs(wallet, u, count);
#endif
    r = BRPreparedSendHasCoin(u, count, hash, n);
    free(u);
    return r;
#else
    if (! wallet) return 0;
    return BRWalletOutpointSelectable(wallet, hash, n) ? 1 : 0;
#endif
}

// Whether tx may be signed -- or, once signed, handed back to be broadcast -- as the approved
// send: payAmount to payScript (plus change to the wallet), at approvedFee, from coins still the
// wallet's. Anything but BRPreparedSendOK refuses. The first failing rule is reported, in this
// order: fee unknown (also a NULL wallet or tx), fee changed, outputs not approved, coin
// unavailable (the first input BRPreparedSendCoinOK refuses; no input at all is unavailable too).
static inline BRPreparedSendVerdict BRPreparedSendCheck(BRWallet *wallet, const BRTransaction *tx,
                                                        const uint8_t *payScript, size_t payScriptLen,
                                                        uint64_t payAmount, uint64_t approvedFee)
{
#if PREPARED_SEND_UNFIXED
    // RED ARM SEAM (fee_quote_kat, prepared_send_kat): nothing checked before or after signing.
    (void)wallet; (void)tx; (void)payScript; (void)payScriptLen; (void)payAmount; (void)approvedFee;
    return BRPreparedSendOK;
#else
    uint64_t fee;
    BRPreparedSendVerdict verdict = BRPreparedSendOK;

    if (! wallet || ! tx) return BRPreparedSendFeeUnknown;
    fee = BRWalletFeeForTx(wallet, tx);
    if (fee == UINT64_MAX) return BRPreparedSendFeeUnknown;
    if (fee != approvedFee) return BRPreparedSendFeeChanged;
    if (! BRPreparedSendPaysAsApproved(wallet, tx, payScript, payScriptLen, payAmount)) return BRPreparedSendNotApproved;
    if (tx->inCount == 0) return BRPreparedSendCoinUnavailable;

    // Each coin must be one the wallet's own selection would spend now (SEND-GATE-SET): spent coins,
    // asset carriers, DigiDollar and ONE-FAMILY-held outputs, unsignable outputs and unconfirmed coins
    // someone else sent are not. Each is asked alone, under the wallet's lock. A coin that changed
    // between the two calls can only refuse -- and reviewing again builds afresh.
    for (size_t i = 0; i < tx->inCount && verdict == BRPreparedSendOK; i++) {
        if (! BRPreparedSendCoinOK(wallet, tx->inputs[i].txHash, tx->inputs[i].index))
            verdict = BRPreparedSendCoinUnavailable;
    }
    return verdict;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRPreparedSend_h
