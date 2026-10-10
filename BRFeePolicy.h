//
//  BRFeePolicy.h
//
//  The fee rate a DGB send is built at, and the warning the send screen shows for a custom
//  fee. The rate decides what the transaction pays, so both platforms must compute it the same
//  way. Until 2026-10 this lived in Kotlin (SendViewModel.feeRatePerKb and .feeWarning).
//
//  The rule:
//    - by default a send is built at DEFAULT_FEE_PER_KB (100,000 sat/kB: DigiByte's minimum
//      relay fee, 100 sat/byte);
//    - a person may instead enter a TOTAL fee (DGB text, through BRAmountParseDGB). It becomes a
//      rate over the size of a typical send (BR_FEE_TYPICAL_TX_VSIZE, one P2WPKH input and two
//      outputs): rate = fee x 1000 / 141, rounded down. A fee <= 0, or text that is not an
//      amount, builds at the default rate;
//    - the warning for a custom fee: none <= 0 (or unreadable) is "fee required"; below
//      100 sat/byte across the typical size (14,100 sats) is "below minimum relay"; otherwise
//      none.
//  The rate is handed to BRWalletCreateTransactionAtFeePerKb for that one build; the wallet's
//  own rate is never changed (it is shared state other builds read).
//
//  Difference from the Kotlin: a fee whose rate would exceed INT64_MAX sat/kB (over about 92
//  million DGB) saturates there; Kotlin's Long multiplication wrapped.
//
//  Host KAT: digibytewallet-android native/src/test/host/fee_policy_kat/.
//  Header-only, static inline.
//

#ifndef BRFeePolicy_h
#define BRFeePolicy_h

#include "BRWallet.h"   // DEFAULT_FEE_PER_KB
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The vsize of a typical send: one P2WPKH input, two outputs.
#define BR_FEE_TYPICAL_TX_VSIZE 141
// The default fee for that typical send, in satoshis: 141 x 100 sat/byte. A literal for Swift.
#define BR_FEE_DEFAULT_ESTIMATE_SATS 14100
typedef char _BRFeeDefaultEstimateIsTypicalAtDefault[(BR_FEE_DEFAULT_ESTIMATE_SATS ==
    BR_FEE_TYPICAL_TX_VSIZE * DEFAULT_FEE_PER_KB / 1000) ? 1 : -1];

typedef enum {
    BRFeeWarningNone = 0,
    BRFeeWarningBelowRelay,     // "Below minimum relay fee: the transaction may not broadcast"
    BRFeeWarningRequired        // "Fee required"
} BRFeeWarning;

// The rate (sat/kB) to build at. custom: the person entered a total fee; feeSats: its value in
// satoshis (pass 0 when the text was not an amount).
static inline uint64_t BRFeeRateForSend(int custom, int64_t feeSats)
{
    uint64_t f, q, r, rate;

    if (! custom || feeSats <= 0) return DEFAULT_FEE_PER_KB;
    f = (uint64_t)feeSats;
#ifdef FEE_POLICY_RED
    // RED ARM SEAM (fee_policy_kat): the rate taken as the fee itself, per kB, no size.
    return f;
#endif
    q = f / BR_FEE_TYPICAL_TX_VSIZE;
    r = f % BR_FEE_TYPICAL_TX_VSIZE;
    if (q > (uint64_t)INT64_MAX / 1000) return (uint64_t)INT64_MAX;
    rate = q * 1000 + (r * 1000) / BR_FEE_TYPICAL_TX_VSIZE;    // floor(f x 1000 / 141), exactly
    return rate > (uint64_t)INT64_MAX ? (uint64_t)INT64_MAX : rate;
}

// The warning for the fee field. Only a custom fee is ever warned about.
static inline BRFeeWarning BRFeeWarningFor(int custom, int64_t feeSats)
{
    if (! custom) return BRFeeWarningNone;
    if (feeSats <= 0) return BRFeeWarningRequired;
#ifdef FEE_POLICY_RED
    return BRFeeWarningNone;   // RED: no relay check
#endif
    return feeSats < 100LL * BR_FEE_TYPICAL_TX_VSIZE ? BRFeeWarningBelowRelay : BRFeeWarningNone;
}

#ifdef __cplusplus
}
#endif

#endif // BRFeePolicy_h
