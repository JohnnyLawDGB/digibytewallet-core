//
//  BRFeePolicy.h
//
//  The fee rate a DGB send is built at, and what the send screen says about a custom fee. The
//  rate decides what the transaction pays, so both platforms must compute it the same way.
//
//  THE RULE (Android 4.1.0: core/send/FeeQuote.kt, TransactionBuilder.prepareTransaction):
//    - the fee field asks for one of three things (BRFeeRequestFor): the default rate; a custom
//      TOTAL in DGB (text, read by BRAmountParseDGB) that is a positive amount; or nothing. A custom
//      fee that is not a positive amount -- zero, empty, unreadable, negative -- quotes nothing:
//      review stops there, and the field's one message is "Fee required". It is never built at
//      another rate in its place;
//    - every send is built first at DEFAULT_FEE_PER_KB (100,000 sat/kB: DigiByte's minimum relay
//      fee, 100 sat/vB), and that transaction is quoted: its fee is its inputs minus its outputs,
//      and its size is its own vsize. A default-fee send is that transaction;
//    - a custom total becomes a rate over THAT transaction's vsize -- this send's own size, never a
//      typical one and never an earlier send's -- and the send is built again at the rate:
//      BRFeeRateForCustomTotal(total, vsize) = max(1, floor(total x 1000 / vsize)), saturating at
//      INT64_MAX. Never 0: the builder reads a rate of 0 as the wallet's own rate;
//    - the fee shown, approved and signed is the quote of the transaction built, never the total
//      typed. The builder pays at least 100 sat/vB whatever rate it is given, rounds a rate's fee up
//      to whole hundreds, and folds change too small to be an output into the fee, so a transaction
//      can pay more than the total typed. BRFeeQuoteRaised says when: the confirmation then says so
//      beside the fee it shows. There is no "below minimum relay" warning: the builder cannot produce
//      the transaction it would warn about.
//  A rate is handed to BRWalletCreateTransactionAtFeePerKb for that one build; the wallet's own rate
//  is never changed (it is shared state other builds read).
//
//  The quote itself (inputs minus outputs, looked up in the wallet's own transactions) is not here:
//  it needs a wallet and a transaction. This header is the arithmetic around it.
//
//  NO LONGER USED BY ANDROID 4.1.0, kept so iOS keeps compiling until it moves off them (do not
//  build new code on them): BRFeeRateForSend, BRFeeWarningFor and BR_FEE_DEFAULT_ESTIMATE_SATS (the
//  4.0.89 rule, below), with BR_FEE_TYPICAL_TX_VSIZE, which only they use.
//
//  Host KATs (digibytewallet-android native/src/test/host/): fee_policy_quote_kat (the 4.1.0 rule,
//  every FeeQuoteTest.kt case), fee_policy_kat (the 4.0.89 functions).
//  Header-only, static inline.
//

#ifndef BRFeePolicy_h
#define BRFeePolicy_h

#include "BRWallet.h"        // DEFAULT_FEE_PER_KB
#include "BRAmountParse.h"   // BRAmountParseDGB
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// MACRO CONVENTION: FEE_POLICY_QUOTE_UNFIXED is tested by VALUE (#if). =1 is fee_policy_quote_kat's
// comparison arm: the 4.0.89 rule (a custom total taken over a typical 141 vbytes, a custom fee that
// is not an amount built at the default rate, no "raised" verdict). Unset or =0 is what ships.
#ifndef FEE_POLICY_QUOTE_UNFIXED
#define FEE_POLICY_QUOTE_UNFIXED 0
#endif

// The vsize of a typical send: one P2WPKH input, two outputs. Used only by the 4.0.89 functions.
#define BR_FEE_TYPICAL_TX_VSIZE 141
// 4.0.89: the default fee for that typical send, in satoshis: 141 x 100 sat/byte. A literal for
// Swift. NOT USED BY 4.1.0: the form shows no figure before review, and a custom fee no longer
// starts from it; the fee shown is the quote of the transaction built.
#define BR_FEE_DEFAULT_ESTIMATE_SATS 14100
typedef char _BRFeeDefaultEstimateIsTypicalAtDefault[(BR_FEE_DEFAULT_ESTIMATE_SATS ==
    BR_FEE_TYPICAL_TX_VSIZE * DEFAULT_FEE_PER_KB / 1000) ? 1 : -1];

// What the fee field asks for. The zero value is the one that builds nothing.
typedef enum {
    BRFeeRequestNone = 0,       // a custom fee that is not a positive amount: quote nothing, and the
                                // field says "Fee required"
    BRFeeRequestDefault,        // DEFAULT_FEE_PER_KB
    BRFeeRequestCustomTotal     // a total, in satoshis, always > 0
} BRFeeRequest;

// The request for the fee field as it stands. custom: the person chose to enter a fee; text, len:
// the field (need not be NUL-terminated; ignored when ! custom). *totalSats (may be NULL) is set to
// the total for BRFeeRequestCustomTotal and to 0 otherwise.
static inline BRFeeRequest BRFeeRequestFor(int custom, const char *text, size_t len, int64_t *totalSats)
{
    int64_t sats = 0;

    if (totalSats) *totalSats = 0;
    if (! custom) return BRFeeRequestDefault;
    if (! text || ! BRAmountParseDGB(text, len, &sats) || sats <= 0) {
#if FEE_POLICY_QUOTE_UNFIXED
        return BRFeeRequestDefault;   // comparison arm: 4.0.89 built such a fee at the default rate
#else
        return BRFeeRequestNone;
#endif
    }
    if (totalSats) *totalSats = sats;
    return BRFeeRequestCustomTotal;
}

// floor(r x 1000 / v) for 0 <= r < v <= INT64_MAX, exactly, in 64 bits (no __int128: 32-bit
// targets have none). Horner over the bits of 1000, keeping quotient and remainder: the remainder
// stays below v < 2^63, so doubling it or adding r never overflows.
static inline uint64_t _BRFeeMulDiv1000(uint64_t r, uint64_t v)
{
    uint64_t q = 0, rem = 0;
    int bit;

    for (bit = 9; bit >= 0; bit--) {   // 1000 = 0b1111101000
        q <<= 1; rem <<= 1;
        if (rem >= v) { rem -= v; q++; }
        if ((1000u >> bit) & 1u) {
            rem += r;
            if (rem >= v) { rem -= v; q++; }
        }
    }
    return q;
}

// The 4.0.89 rule, kept as the comparison arm's answer. Defined below.
static inline uint64_t BRFeeRateForSend(int custom, int64_t feeSats);

// The rate, in sat/kB, at which a transaction of vsize vbytes pays totalSats:
// floor(totalSats x 1000 / vsize), computed exactly. 0 when vsize <= 0 or totalSats <= 0 (no rate:
// never pass that to the builder, which reads 0 as the wallet's own rate). A rate above INT64_MAX
// saturates there. Kotlin: FeeQuote.rateForTotal.
static inline uint64_t BRFeeRateForTotal(int64_t totalSats, int64_t vsize)
{
    uint64_t t, v, q, rate;

#if FEE_POLICY_QUOTE_UNFIXED
    (void)vsize;
    return BRFeeRateForSend(1, totalSats);   // comparison arm: over a typical 141 vbytes
#endif
    if (vsize <= 0 || totalSats <= 0) return 0;
    t = (uint64_t)totalSats;
    v = (uint64_t)vsize;
    q = t / v;
    if (q > (uint64_t)INT64_MAX / 1000) return (uint64_t)INT64_MAX;
    rate = q * 1000 + _BRFeeMulDiv1000(t % v, v);   // at most INT64_MAX - 807 + 999: no wrap
    return rate > (uint64_t)INT64_MAX ? (uint64_t)INT64_MAX : rate;
}

// The rate a send with a custom total is built at: totalSats over builtVsize, the vsize of THIS
// send as built at DEFAULT_FEE_PER_KB (its quote). At least 1 sat/kB -- the builder then pays its
// floor -- and never 0, which it would read as the wallet's own rate. Pass the total from
// BRFeeRequestFor (always > 0). Kotlin: TransactionBuilder.prepareTransaction,
// rateForTotal(total, atDefault.quote.vsize).coerceAtLeast(1).
static inline uint64_t BRFeeRateForCustomTotal(int64_t totalSats, int64_t builtVsize)
{
    uint64_t rate = BRFeeRateForTotal(totalSats, builtVsize);

#if FEE_POLICY_QUOTE_UNFIXED
    return rate;
#endif
    return rate < 1 ? 1 : rate;
}

// Whether the transaction pays more than the custom total typed: the confirmation then says the fee
// was raised from typedTotalSats, beside the fee it shows (feeSats, the quote of the transaction
// built), instead of showing the lower figure. Never for a default-fee send (custom 0), whatever
// typedTotalSats holds. Equal is not raised. Kotlin: FeeQuote.raised
// (requestedSats != null && feeSats > requestedSats).
static inline int BRFeeQuoteRaised(int custom, int64_t typedTotalSats, int64_t feeSats)
{
#if FEE_POLICY_QUOTE_UNFIXED
    (void)custom; (void)typedTotalSats; (void)feeSats;
    return 0;   // comparison arm: 4.0.89 showed the total typed as the fee
#endif
    return custom && feeSats > typedTotalSats;
}

// ---- the 4.0.89 rule: NOT USED BY ANDROID 4.1.0; kept until iOS moves off it ----------------

typedef enum {
    BRFeeWarningNone = 0,
    BRFeeWarningBelowRelay,     // "Below minimum relay fee: the transaction may not broadcast"
    BRFeeWarningRequired        // "Fee required"
} BRFeeWarning;

// NOT USED BY 4.1.0. The rate (sat/kB) to build at, over a typical 141-vbyte send. custom: the
// person entered a total fee; feeSats: its value in satoshis (pass 0 when the text was not an
// amount); a fee <= 0 builds at the default rate. 4.1.0 instead builds at DEFAULT_FEE_PER_KB first
// and takes the total over that transaction's own size (BRFeeRateForCustomTotal), and a fee that is
// not a positive amount quotes nothing (BRFeeRequestFor). A rate over INT64_MAX saturates.
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

// NOT USED BY 4.1.0. The warning for the fee field; only a custom fee is ever warned about.
// 4.1.0 shows no BRFeeWarningBelowRelay (the builder raises a low total to the floor, and the
// confirmation says so: BRFeeQuoteRaised); the field's one message, "Fee required", is
// BRFeeRequestFor(...) == BRFeeRequestNone.
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
