//
//  BRDigiDollarSend.h
//
//  The checks between a DigiDollar send's confirmation and its signature. Until 2026-11 they lived in
//  Android's JNI bridge (native/src/main/jni/bridge/digidollar_send.h: dd_send_preview, dd_send_check).
//  Moved unchanged, so that both platforms confirm and sign a DigiDollar send by one rule. The build of
//  the transfer (BRWalletCreateDigiDollarTransfer), the credential prompt, the signature and the publish
//  stay where they are.
//
//  WHY TWO BUILDS. A DigiDollar transfer cannot be held across the credential prompt as bytes, the way a
//  DGB send is: the serializer leaves an input's amount out when it is zero, and DigiDollar inputs are
//  zero-value, so unsigned bytes do not parse back. So the platform builds the transfer from the wallet
//  twice. At review it builds it, reads what it pays (BRWalletDigiDollarSendPreview) and frees it: nothing
//  native outlives the prompt. After the prompt it builds it again and signs it only when the rebuilt
//  transfer is the approved send at the approved fee (BRWalletDigiDollarSendCheck); the wallet may have
//  changed while the prompt was up, and then the rebuilt transfer pays something else and is refused.
//  Android runs the check twice: on the rebuilt transfer before it is signed, and on the signed transfer
//  before it is handed on to be published.
//
//    BRWalletDigiDollarSendPreview  what the confirmation shows: the transfer's own fee -- its inputs
//                                   minus its outputs, looked up in the wallet's own transactions -- and
//                                   what comes back to the wallet (DigiDollar change, DGB change), and how
//                                   many inputs it spends. Returns 1 with *out set, or 0 (out untouched)
//                                   when there is no answer: wallet, tx or out is NULL; the transfer has
//                                   no input or no output; an input is not a transaction the wallet holds
//                                   (BRWalletFeeForTx answers UINT64_MAX); or the fee does not fit a
//                                   signed 64-bit value. Output 0 is the payment and is never counted as
//                                   change. Reads the wallet; changes nothing.
//
//    BRWalletDigiDollarSendCheck    only the approved send is signed: the transfer pays exactly the
//                                   approved fee; it is a DigiDollar TRANSFER of at least two outputs;
//                                   output 0 carries zero DGB to OP_1 <the approved 32-byte key> and is
//                                   bound by the OP_RETURN to exactly the approved cents; and every other
//                                   output is the DigiDollar OP_RETURN (exactly one) or pays an address of
//                                   this wallet. Refusals, in the order they are tested:
//                                     FEE_UNKNOWN   wallet, tx or key32 is NULL, or an input is not a
//                                                   transaction the wallet holds
//                                     FEE_CHANGED   the fee is not approvedFee
//                                     NOT_APPROVED  anything else above does not hold
//
//  LOCKING. Both functions call the wallet's own accessors (BRWalletFeeForTx, BRWalletContainsAddress),
//  each of which takes the wallet's lock: the caller must NOT hold it. tx is the caller's and must not
//  change during the call. A platform that can free its wallet while another thread reads it keeps its
//  own guard around the call (Android: WALLET_READ_GUARD).
//
//  Header-only, static inline; no I/O, no clock, no allocation.
//
//  Test seam (host KAT digidollar_send_core_kat in the Android repo): DIGIDOLLAR_SEND_UNFIXED, tested by
//  VALUE (#if). =1 is the comparison arm, the behaviour before the bridge header existed: the
//  confirmation showed the 0.1 DGB fee floor whatever the transfer paid, and the transfer was signed as
//  it was built, with nothing checked. Unset or =0 is what ships.
//

#ifndef BRDigiDollarSend_h
#define BRDigiDollarSend_h

#include "BRWallet.h"        // BRWallet, BRWalletFeeForTx, BRWalletContainsAddress
#include "BRTransaction.h"   // BRTransaction, BRTxOutput
#include "BRDigiDollar.h"    // BRDigiDollarTxType, BRDigiDollarOutputAmount, DD_TYPE_TRANSFER
#include "BRDigiDollarTransferLayout.h"   // BR_DIGIDOLLAR_MIN_FEE
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIGIDOLLAR_SEND_UNFIXED
#define DIGIDOLLAR_SEND_UNFIXED 0
#endif

// The 0.1 DGB a DigiDollar transfer pays at least is BR_DIGIDOLLAR_MIN_FEE (BRDigiDollarTransferLayout.h;
// the bridge header carried its own copy, DD_SEND_FEE_FLOOR_SATS): the figure the confirmation showed
// before these checks. Only the comparison arm reads it. The KAT holds it to what the builder charges.

typedef struct {
    uint64_t feeSats;         // the transfer's inputs minus its outputs, in satoshis
    uint64_t ddChangeCents;   // DigiDollar cents the transfer pays back to this wallet: its DigiDollar change
    uint64_t dgbChangeSats;   // DGB the transfer pays back to this wallet: its DGB change
    uint64_t inputCount;      // how many inputs the transfer spends (DigiDollar and DGB)
} BRDigiDollarSendPreview;

typedef enum {
    BR_DIGIDOLLAR_SEND_OK = 0,
    BR_DIGIDOLLAR_SEND_FEE_UNKNOWN = 1,   // an input is not a transaction the wallet holds: the fee cannot be told
    BR_DIGIDOLLAR_SEND_FEE_CHANGED = 2,   // the transfer does not pay exactly the approved fee
    BR_DIGIDOLLAR_SEND_NOT_APPROVED = 3   // its outputs are not the approved payment plus the OP_RETURN and change to this wallet
} BRDigiDollarSendVerdict;

#if ! DIGIDOLLAR_SEND_UNFIXED
// 1 when output i of tx pays an address of this wallet.
static inline int _BRDigiDollarSendPaysWallet(BRWallet *wallet, const BRTransaction *tx, size_t i)
{
    const BRTxOutput *o = &tx->outputs[i];
    return o->address[0] != '\0' && BRWalletContainsAddress(wallet, o->address);
}

// 1 when output i of tx is an OP_RETURN.
static inline int _BRDigiDollarSendIsOpReturn(const BRTransaction *tx, size_t i)
{
    const BRTxOutput *o = &tx->outputs[i];
    return o->amount == 0 && o->script && o->scriptLen > 0 && o->script[0] == 0x6a;
}
#endif

// What a built transfer pays and gives back: 1 with *out set, or 0 when there is no answer (the fee is
// unknown, or does not fit a signed 64-bit value). Reads the wallet; changes nothing.
static inline int BRWalletDigiDollarSendPreview(BRWallet *wallet, const BRTransaction *tx,
                                                BRDigiDollarSendPreview *out)
{
#if DIGIDOLLAR_SEND_UNFIXED
    if (! tx || ! out) return 0;
    (void)wallet;
    out->feeSats = BR_DIGIDOLLAR_MIN_FEE;   // the floor, whatever the transfer pays
    out->ddChangeCents = 0;
    out->dgbChangeSats = 0;
    out->inputCount = 0;
    return 1;
#else
    uint64_t fee, ddChange = 0, dgbChange = 0;

    if (! wallet || ! tx || ! out || tx->inCount == 0 || tx->outCount == 0) return 0;
    fee = BRWalletFeeForTx(wallet, tx);                  // UINT64_MAX: an input the wallet does not hold
    if (fee == UINT64_MAX || fee > (uint64_t)INT64_MAX) return 0;
    for (size_t i = 1; i < tx->outCount; i++) {          // output 0 is the payment
        if (! _BRDigiDollarSendPaysWallet(wallet, tx, i)) continue;
        int64_t cents = BRDigiDollarOutputAmount(tx, i);
        if (cents > 0) ddChange += (uint64_t)cents;
        else dgbChange += tx->outputs[i].amount;
    }
    out->feeSats = fee;
    out->ddChangeCents = ddChange;
    out->dgbChangeSats = dgbChange;
    out->inputCount = (uint64_t)tx->inCount;
    return 1;
#endif
}

// Whether a rebuilt transfer may be signed -- or, once signed, handed on to be published -- as the
// approved send: `cents` to the taproot output key `key32`, at `approvedFee`.
static inline BRDigiDollarSendVerdict BRWalletDigiDollarSendCheck(BRWallet *wallet, const BRTransaction *tx,
                                                                  const uint8_t key32[32], uint64_t cents,
                                                                  uint64_t approvedFee)
{
#if DIGIDOLLAR_SEND_UNFIXED
    (void)wallet; (void)tx; (void)key32; (void)cents; (void)approvedFee;
    return BR_DIGIDOLLAR_SEND_OK;
#else
    uint64_t fee;
    size_t opReturns = 0;
    const BRTxOutput *pay;

    if (! wallet || ! tx || ! key32) return BR_DIGIDOLLAR_SEND_FEE_UNKNOWN;
    fee = BRWalletFeeForTx(wallet, tx);
    if (fee == UINT64_MAX) return BR_DIGIDOLLAR_SEND_FEE_UNKNOWN;
    if (fee != approvedFee) return BR_DIGIDOLLAR_SEND_FEE_CHANGED;

    // A DigiDollar transfer whose output 0 is the approved payment: zero DGB, OP_1 <32-byte key>,
    // bound by the OP_RETURN to exactly the approved cents.
    if (BRDigiDollarTxType(tx) != DD_TYPE_TRANSFER || tx->outCount < 2) return BR_DIGIDOLLAR_SEND_NOT_APPROVED;
    pay = &tx->outputs[0];
    if (pay->amount != 0 || ! pay->script || pay->scriptLen != 34 || pay->script[0] != 0x51 ||
        pay->script[1] != 0x20 || memcmp(pay->script + 2, key32, 32) != 0) return BR_DIGIDOLLAR_SEND_NOT_APPROVED;
    if (BRDigiDollarOutputAmount(tx, 0) != (int64_t)cents) return BR_DIGIDOLLAR_SEND_NOT_APPROVED;

    // Everything else is the one OP_RETURN, or change to this wallet.
    for (size_t i = 1; i < tx->outCount; i++) {
        if (_BRDigiDollarSendIsOpReturn(tx, i)) opReturns++;
        else if (! _BRDigiDollarSendPaysWallet(wallet, tx, i)) return BR_DIGIDOLLAR_SEND_NOT_APPROVED;
    }
    return opReturns == 1 ? BR_DIGIDOLLAR_SEND_OK : BR_DIGIDOLLAR_SEND_NOT_APPROVED;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiDollarSend_h
