//
//  BROneFamilyGate.h
//
//  ONE-FAMILY at a signer: the last check before the inputs of a transaction are signed. BRWalletBuildAssetTransfer
//  (BRAssetSend.h, check 15a) calls it; the Android bridge calls its own copy
//  (native/src/main/jni/bridge/one_family_gate.h) from NativeBridge_buildAndSignAssetTransferTx and from the
//  generic signTransaction.
//
//  BRWalletTxInputsOneFamilyOK(wallet, tx) is 1 when no input of tx is an output the wallet holds as DigiDollar or
//  an output of a transaction marked both DigiDollar and DigiAsset (BRWalletOutpointIsOneFamilyHeld 0 for every
//  input); 0 when any is, or when the wallet does not hold an input's funding transaction or its output (-1: it
//  cannot be judged, so it is refused), or when there is no wallet or no transaction. A DigiDollar output is spent
//  only by BRWalletCreateDigiDollarTransfer, and an output of a dual-family transaction by nothing (BRWallet.h,
//  ONE-FAMILY).
//
//  The rule is the bridge copy's name for name: tx_inputs_one_family_ok is BRWalletTxInputsOneFamilyOK, with the
//  same seam, so the bridge can include this header in its place.
//
//  MACRO CONVENTION: ONE_FAMILY_SIGNER_UNFIXED is tested by PRESENCE (#ifdef), as the bridge copy tests it and as
//  BRWallet.c tests its sibling ONE_FAMILY_UNFIXED, so a unit that includes both copies reads one arm from each.
//  Defined, it is the comparison arm: every input accepted. Never defined in a production build.
//
//  Host KATs: digibytewallet-android native/src/test/host/asset_sign_gate_core_kat/ (this header against
//  one_family_kat's cases) and asset_send_kat/ (BRWalletBuildAssetTransfer).
//  Header-only, static inline; no I/O. The wallet is asked once per input, under its own lock each time.
//

#ifndef BROneFamilyGate_h
#define BROneFamilyGate_h

#include "BRWallet.h"
#include "BRTransaction.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1 when every input of tx may be spent by a send that is not the DigiDollar builder's; 0 when any may not.
static inline int BRWalletTxInputsOneFamilyOK(BRWallet *wallet, const BRTransaction *tx)
{
    if (! wallet || ! tx) return 0;
#ifdef ONE_FAMILY_SIGNER_UNFIXED
    return 1;   // comparison arm: every input accepted
#else
    for (size_t i = 0; i < tx->inCount; i++) {
        if (BRWalletOutpointIsOneFamilyHeld(wallet, tx->inputs[i].txHash, tx->inputs[i].index) != 0) return 0;
    }
    return 1;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BROneFamilyGate_h
