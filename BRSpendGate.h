//
//  BRSpendGate.h
//
//  The checks a transaction passes before its signature may leave a signer. Moved from the Android JNI bridge
//  (bridge/spend_guard.h, bridge/signed_spend_gate.h), unchanged, so a second signer on another platform applies the
//  same checks against the same reservation (BRCoinReservation.h).
//
//  BRSpendGuardInputsUnspent(wallet, tx): 1 when no input of tx spends an outpoint the wallet holds as spent
//  (BRWalletOutpointSpent: DGB, DigiAsset and DigiDollar spends alike); 0 otherwise, or when there is no wallet or no
//  transaction (it cannot tell).
//
//  BRSignedSpendGate(wallet, tx, now), for a transaction already signed:
//    1. no tx, or no inputs                                        -> 0
//    2. a wallet is given and an input is spent there              -> 0, nothing claimed
//    3. BRCoinReservationClaim(tx->txHash, inputs, now) refused    -> 0, nothing claimed
//    4. a wallet is given and an input is spent there now (a send that registered meanwhile released its claim at
//       registration)                                              -> the claim is released (BRCoinReservationRelease
//                                                                     of tx->txHash), 0
//    5. otherwise                                                  -> 1; the claim stays until the publish releases it
//  With wallet NULL only the claim is asked (a recovery signer with no wallet loaded).
//
//  The caller keeps wallet and tx alive for the whole call; the wallet's own lock covers BRWalletOutpointSpent.
//  Host KAT: digibytewallet-android native/src/test/host/coin_reservation_core_kat/.
//  Comparison arms for that KAT only (tested by value or presence, in the consumer's unit): BR_SPEND_GUARD_UNFIXED=1
//  (the guard allows everything), BR_SIGNED_SPEND_GATE_UNFIXED=1 (the gate lets everything through),
//  BR_SIGNED_SPEND_GATE_RED_NO_RECHECK (step 4 is skipped).
//  Header-only, static inline; no lock or clock of its own.
//

#ifndef BRSpendGate_h
#define BRSpendGate_h

#include "BRCoinReservation.h"
#include "BRTransaction.h"
#include "BRWallet.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BR_SPEND_GUARD_UNFIXED
#define BR_SPEND_GUARD_UNFIXED 0
#endif

#ifndef BR_SIGNED_SPEND_GATE_UNFIXED
#define BR_SIGNED_SPEND_GATE_UNFIXED 0
#endif

// 1 when no input of tx spends an outpoint the wallet holds as spent; 0 otherwise, or when it cannot tell.
static inline int BRSpendGuardInputsUnspent(BRWallet *wallet, const BRTransaction *tx)
{
#if BR_SPEND_GUARD_UNFIXED
    (void)wallet; (void)tx;
    return 1;
#else
    if (! wallet || ! tx) return 0;

    for (size_t i = 0; i < tx->inCount; i++) {
        if (BRWalletOutpointSpent(wallet, tx->inputs[i].txHash, tx->inputs[i].index)) return 0;
    }

    return 1;
#endif
}

// 1 when the signed transaction tx may leave the signer; its inputs are then claimed for tx->txHash.
static inline int BRSignedSpendGate(BRWallet *wallet, BRTransaction *tx, double now)
{
#if BR_SIGNED_SPEND_GATE_UNFIXED
    (void)wallet; (void)tx; (void)now;
    return 1;
#else
    if (! tx || tx->inCount == 0) return 0;
    if (wallet && ! BRSpendGuardInputsUnspent(wallet, tx)) return 0;
    if (! BRCoinReservationClaim(tx->txHash, tx->inputs, tx->inCount, now)) return 0;
#ifndef BR_SIGNED_SPEND_GATE_RED_NO_RECHECK
    if (wallet && ! BRSpendGuardInputsUnspent(wallet, tx)) {
        BRCoinReservationRelease(tx->txHash);
        return 0;
    }
#endif
    return 1;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRSpendGate_h
