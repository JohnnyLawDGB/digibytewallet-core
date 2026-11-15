//
//  BRAssetSignGate.h
//
//  ASSET-SIGN-GATE: the check a DigiAsset transfer passes on the transaction about to be signed, and again
//  on the signed transaction before its bytes are handed back to be broadcast. BRWalletBuildAssetTransfer
//  (BRAssetSend.h, checks 15b and 18a) calls it both times; the Android bridge's
//  NativeBridge_buildAndSignAssetTransferTx calls its own copy (native/src/main/jni/bridge/asset_sign_gate.h)
//  the same two times.
//
//  BRAssetSignCheck(wallet, tx, recipScript, recipScriptLen, recipSats, planFee, approvedMaxFee) is
//  BR_ASSET_SIGN_OK only when tx spends only wallet or asset coins, at the amounts the wallet holds, and pays
//  only the approved outputs and the approved fee:
//
//    every input   is an output of a transaction the wallet holds, paying one of the wallet's addresses,
//                  listed at that output's own amount and script; and it is either one of the coins the
//                  wallet's own selection would spend (BRWalletOutpointSelectable, the predicate of
//                  BRWalletSelectableUTXOs asked of that coin) or an output the wallet holds as a DigiAsset
//                  holding (BRWalletAssetUTXOs) that is still unspent, valid and of no other token family
//                  (BRWalletOutpointAssetState == 1);
//    the recipient is paid by exactly one output, at exactly recipSats (the DigiAsset marker): no second
//                  output to it and no other amount. When the recipient is one of the wallet's own addresses
//                  (a send to oneself) its other outputs are the wallet's change, so only one output at
//                  recipSats is required;
//    every other   output pays one of the wallet's addresses, or is the one zero-value data output
//                  (OP_RETURN): at most one;
//    the fee       -- the inputs, at the amounts the wallet holds, minus the outputs -- is exactly planFee,
//                  the fee of the plan being signed, and planFee is no more than approvedMaxFee, the fee the
//                  confirmation showed.
//
//  The amounts are the wallet's, never the transaction's own: a legacy input's signature does not commit to
//  its amount. The outputs are read first, so nothing of the wallet is read for a transaction that pays
//  someone not approved. Not checked here: the asset quantity the data output's instructions assign
//  (BRWalletBuildAssetTransfer checks that itself, checks 10-12).
//
//  The verdicts, in the order they are decided:
//    no wallet, no tx or no inputs                                                  -> COIN_UNKNOWN
//    no outputs, or no recipient script                                             -> NOT_APPROVED
//    recipSats 0                                                                    -> RECIPIENT_CHANGED
//    planFee above approvedMaxFee                                                   -> FEE_ABOVE_APPROVED
//    an output that is neither the recipient's, the wallet's nor a zero-value data output, or a second
//    data output                                                                    -> NOT_APPROVED
//    an output sum that does not fit 64 bits                                        -> FEE_CHANGED
//    the recipient not paid by exactly one output at recipSats (by at least one, to oneself)
//                                                                                   -> RECIPIENT_CHANGED
//    the held DigiAsset outputs cannot be copied (no memory: cannot tell)           -> COIN_UNKNOWN
//    per input, in order: the wallet holds no such output                           -> COIN_UNKNOWN
//                         listed at another amount or script than that output       -> AMOUNT_MISMATCH
//                         the output pays no address of the wallet's, or is neither
//                         selectable nor a held DigiAsset output in state 1          -> COIN_NOT_WALLETS
//                         an input sum that does not fit 64 bits                     -> FEE_CHANGED
//    the inputs less the outputs are not exactly planFee                            -> FEE_CHANGED
//
//  Ownership and locking: nothing is kept past the call. The held DigiAsset outputs are copied once under the
//  wallet's lock; each other question is asked of the wallet alone, under its own lock each time, so a coin
//  that changes between two of them can only refuse. The caller must not hold the wallet's lock.
//
//  The rules are the bridge copy's name for name: asset_sign_check, AssetSignVerdict and ASSET_SIGN_* are
//  BRAssetSignCheck, BRAssetSignVerdict and BR_ASSET_SIGN_*, with the same verdict values and the same seam,
//  so the bridge can include this header in its place.
//
//  MACRO CONVENTION: ASSET_SIGN_GATE_UNFIXED is tested by VALUE (#if), the bridge copy's seam and values.
//  =1 is a comparison arm: nothing checked, every verdict OK. =2 is a comparison arm: the recipient checked by
//  script alone, any number of data outputs, and the fee checked against planFee only. Unset or =0 is what
//  ships. Never defined in a production build.
//
//  Host KATs: digibytewallet-android native/src/test/host/asset_sign_gate_core_kat/ (this header against
//  asset_sign_gate_kat's cases, every arm) and asset_send_kat/ (BRWalletBuildAssetTransfer).
//  Header-only, static inline; no I/O.
//

#ifndef BRAssetSignGate_h
#define BRAssetSignGate_h

#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRInt.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_SIGN_GATE_UNFIXED
#define ASSET_SIGN_GATE_UNFIXED 0
#endif

typedef enum {
    BR_ASSET_SIGN_OK = 0,
    BR_ASSET_SIGN_COIN_UNKNOWN = 1,         // an input is not an output of a transaction the wallet holds
    BR_ASSET_SIGN_AMOUNT_MISMATCH = 2,      // an input is listed at another amount or script than that output
    BR_ASSET_SIGN_COIN_NOT_WALLETS = 3,     // an input is neither a coin selection would spend nor a held DigiAsset coin
    BR_ASSET_SIGN_NOT_APPROVED = 4,         // an output pays neither the recipient nor the wallet and is not the one
                                            // zero-value data output
    BR_ASSET_SIGN_FEE_CHANGED = 5,          // the transaction does not pay exactly the plan's fee
    BR_ASSET_SIGN_RECIPIENT_CHANGED = 6,    // the recipient is not paid by exactly one output at the approved amount
    BR_ASSET_SIGN_FEE_ABOVE_APPROVED = 7    // the plan's fee is above the fee the confirmation showed
} BRAssetSignVerdict;

#if ! (ASSET_SIGN_GATE_UNFIXED == 1)
// 1 when the outpoint (hash, n) is among list[0, count).
static inline int _BRAssetSignHasCoin(const BRUTXO *list, size_t count, UInt256 hash, uint32_t n)
{
    for (size_t i = 0; i < count; i++) {
        if (list[i].n == n && UInt256Eq(list[i].hash, hash)) return 1;
    }
    return 0;
}

static inline int _BRAssetSignIsDataOutput(const BRTxOutput *o)
{
    return o->amount == 0 && o->script && o->scriptLen > 0 && o->script[0] == 0x6a;   // OP_RETURN
}
#endif

// Whether tx may be signed -- or, once signed, handed back to be broadcast -- as the approved DigiAsset send:
// recipSats to recipScript by one output, the wallet and one data output otherwise, at planFee, which is no
// more than approvedMaxFee, from the wallet's coins.
static inline BRAssetSignVerdict BRAssetSignCheck(BRWallet *wallet, const BRTransaction *tx,
                                                  const uint8_t *recipScript, size_t recipScriptLen,
                                                  uint64_t recipSats, uint64_t planFee, uint64_t approvedMaxFee)
{
#if ASSET_SIGN_GATE_UNFIXED == 1
    (void)wallet; (void)tx; (void)recipScript; (void)recipScriptLen; (void)recipSats; (void)planFee;
    (void)approvedMaxFee;
    return BR_ASSET_SIGN_OK;
#else
    BRAssetSignVerdict verdict = BR_ASSET_SIGN_OK;
    uint64_t totalIn = 0, totalOut = 0;
    size_t nAsset = 0, nData = 0, nRecip = 0, nRecipAt = 0;
    int recipIsWallet = 0;
    BRUTXO *assets;

    if (! wallet || ! tx || tx->inCount == 0) return BR_ASSET_SIGN_COIN_UNKNOWN;
    if (tx->outCount == 0 || ! recipScript || recipScriptLen == 0) return BR_ASSET_SIGN_NOT_APPROVED;
#if ASSET_SIGN_GATE_UNFIXED != 2
    if (recipSats == 0) return BR_ASSET_SIGN_RECIPIENT_CHANGED;
    if (planFee > approvedMaxFee) return BR_ASSET_SIGN_FEE_ABOVE_APPROVED;
#else
    (void)recipSats; (void)approvedMaxFee;
#endif

    // Outputs first: nothing of the wallet is read for a transaction that pays someone not approved.
    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];
        int toRecipient = o->script && o->scriptLen == recipScriptLen &&
                          memcmp(o->script, recipScript, recipScriptLen) == 0;
        int toWallet = o->address[0] != '\0' && BRWalletContainsAddress(wallet, o->address);
        int isData = _BRAssetSignIsDataOutput(o);

        if (! isData && ! toRecipient && ! toWallet) return BR_ASSET_SIGN_NOT_APPROVED;
        if (isData) nData++;
        if (toRecipient) {
            nRecip++;
            if (o->amount == recipSats) nRecipAt++;
            if (toWallet) recipIsWallet = 1;
        }
        if (o->amount > UINT64_MAX - totalOut) return BR_ASSET_SIGN_FEE_CHANGED;
        totalOut += o->amount;
    }
#if ASSET_SIGN_GATE_UNFIXED != 2
    if (nData > 1) return BR_ASSET_SIGN_NOT_APPROVED;
    if (recipIsWallet ? nRecipAt < 1 : (nRecip != 1 || nRecipAt != 1)) return BR_ASSET_SIGN_RECIPIENT_CHANGED;
#else
    (void)nData; (void)nRecip; (void)nRecipAt; (void)recipIsWallet;
#endif

    // One copy of the held DigiAsset outputs, taken under the wallet's lock; each plain coin is asked of the
    // wallet alone. A coin that changed between the two can only refuse -- and the send is planned again.
    {
        size_t count = BRWalletAssetUTXOs(wallet, NULL, 0);

        assets = (BRUTXO *)calloc(count ? count : 1, sizeof(*assets));
        if (! assets) return BR_ASSET_SIGN_COIN_UNKNOWN;   // cannot tell
        nAsset = BRWalletAssetUTXOs(wallet, assets, count);
    }

    for (size_t i = 0; i < tx->inCount && verdict == BR_ASSET_SIGN_OK; i++) {
        const BRTxInput *in = &tx->inputs[i];
        BRTransaction *parent = BRWalletCopyTransactionForHash(wallet, in->txHash);
        const BRTxOutput *held;

        if (! parent || in->index >= parent->outCount) {
            verdict = BR_ASSET_SIGN_COIN_UNKNOWN;
        } else {
            held = &parent->outputs[in->index];
            if (in->amount != held->amount || ! in->script || in->scriptLen != held->scriptLen ||
                memcmp(in->script, held->script, held->scriptLen) != 0) {
                verdict = BR_ASSET_SIGN_AMOUNT_MISMATCH;
            } else if (held->address[0] == '\0' || ! BRWalletContainsAddress(wallet, held->address)) {
                verdict = BR_ASSET_SIGN_COIN_NOT_WALLETS;
            } else if (! BRWalletOutpointSelectable(wallet, in->txHash, in->index) &&
                       ! (_BRAssetSignHasCoin(assets, nAsset, in->txHash, in->index) &&
                          BRWalletOutpointAssetState(wallet, in->txHash, in->index) == 1)) {
                verdict = BR_ASSET_SIGN_COIN_NOT_WALLETS;
            } else if (held->amount > UINT64_MAX - totalIn) {
                verdict = BR_ASSET_SIGN_FEE_CHANGED;
            } else {
                totalIn += held->amount;
            }
        }
        if (parent) BRTransactionFree(parent);
    }
    free(assets);
    if (verdict != BR_ASSET_SIGN_OK) return verdict;

    if (totalOut > totalIn || totalIn - totalOut != planFee) return BR_ASSET_SIGN_FEE_CHANGED;
    return BR_ASSET_SIGN_OK;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetSignGate_h
