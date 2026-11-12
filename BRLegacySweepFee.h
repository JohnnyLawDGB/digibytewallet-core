//
//  BRLegacySweepFee.h
//
//  The fee rule of the Recover-funds sweep (BRLegacySweep.h), in one place. It depends on nothing but <stdint.h> and
//  <stddef.h> so the Android bridge's JNI-free backstop (bridge/sweep_fee_guard.h, used by jni_derive.c) can include
//  it too: the bridge and the core take every limit below from this file, and there is no second copy of any of them.
//
//  BRLegacySweepFeeCheck(totalIn, inputCount, feePerKb, &estSize, &fee), in this order (SWEEP-ABS-CEIL):
//    1. estSize = BR_LEGACY_SWEEP_BASE_BYTES (10) + inputCount * BR_LEGACY_SWEEP_INPUT_BYTES (160)
//       + BR_LEGACY_SWEEP_OUTPUT_BYTES (34), whatever the input types. estSize above SIZE_MAX, or
//       estSize * feePerKb above UINT64_MAX                                                    -> WRAPS (fee 0)
//    2. fee = estSize * feePerKb / 1000 (truncated), at least BR_LEGACY_SWEEP_MIN_FEE (1000). The floor cannot bind
//       inside the rate range (the smallest sweep at the smallest rate pays 20,400), and is kept so the rule never
//       pays less than DigiByte's minimum relay fee whatever the constants become.
//    3. feePerKb below BR_LEGACY_SWEEP_MIN_FEE_PER_KB (100,000: DigiByte's minimum relay rate, 100 sat/byte, which is
//       also DEFAULT_FEE_PER_KB, the rate every Android sweep asks for)                       -> RATE_TOO_LOW
//       feePerKb above BR_LEGACY_SWEEP_MAX_FEE_PER_KB (1,000,000: ten times that)             -> RATE_TOO_HIGH
//    4. fee above BR_LEGACY_SWEEP_FEE_CEILING (10,000,000 sats = 0.1 DGB: TX_MAX_SIZE, 100,000 bytes, at the
//       default rate; the default rate reaches it only at 625 inputs, an estimate over TX_MAX_SIZE)  -> ABOVE_CEILING
//    5. totalIn <= fee * BR_LEGACY_SWEEP_FEE_RATIO (20), i.e. the fee is 5% of the listed total or more, for ONE input
//       as for many. A legacy input's signature does not commit to its amount, so an amount listed below what the
//       coin holds still signs and the difference goes to the miner; a listed total that the estimated fee is a large
//       part of is how an under-report shows. The smallest single-input sweep that signs at the default rate lists
//       408,001 sats                                                                          -> RATIO
//    6. totalIn <= fee + BR_LEGACY_SWEEP_DUST (546)                                           -> DUST
//       (implied by 5 today; kept so the bound does not depend on the ratio's constant)
//    otherwise OK, and totalIn - fee is the one output (it does not wrap: 6 leaves fee < totalIn).
//  Nothing wraps: the product is checked before it is taken; fee is then at most (2^64 - 1) / 1000, so fee * 20 and
//  fee + 546 fit. estSize and fee (either may be NULL) receive what was computed, as far as the check got.
//
//  Comparison arms for the host KATs only (legacy_sweep_kat in the Android repo), tested by VALUE (#if); unset or
//  =0 is what ships. Each removes or bends one rule, on the unit compiled with it:
//    BR_LEGACY_SWEEP_RED_SIZE=1                 148 bytes per input instead of 160
//    BR_LEGACY_SWEEP_RED_RATIO=1                the 5% refusal is not applied
//    BR_LEGACY_SWEEP_RED_RATIO_STRICT=1         the 5% refusal applies only above the boundary (totalIn < fee * 20)
//    BR_LEGACY_SWEEP_RED_RATIO_SINGLE_EXEMPT=1  a lone input is exempt from the 5% refusal
//    BR_LEGACY_SWEEP_RED_RATE_FLOOR=1           no lower bound on feePerKb (no RATE_TOO_LOW)
//    BR_LEGACY_SWEEP_RED_FEE_CAP=1              no upper bound on feePerKb (no RATE_TOO_HIGH)
//    BR_LEGACY_SWEEP_RED_FEE_CEILING=1          no absolute ceiling on the fee (no ABOVE_CEILING)
//    BR_LEGACY_SWEEP_RED_FEE_OVERFLOW=1         no overflow check on estSize * feePerKb (no WRAPS; the product wraps)
//    BR_LEGACY_SWEEP_RED_ABS_CEIL=1             the whole SWEEP-ABS-CEIL guard removed: the rule as it was before it
//                                               (no lower rate bound, the upper one at MAX_FEE_PER_KB, no ceiling, a
//                                               lone input exempt from the 5% refusal; BRLegacySweep.h then also
//                                               accepts a zero amount)
//  Header-only, static inline; no I/O, no allocation.
//

#ifndef BRLegacySweepFee_h
#define BRLegacySweepFee_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BR_LEGACY_SWEEP_RED_SIZE
#define BR_LEGACY_SWEEP_RED_SIZE 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO
#define BR_LEGACY_SWEEP_RED_RATIO 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO_STRICT
#define BR_LEGACY_SWEEP_RED_RATIO_STRICT 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO_SINGLE_EXEMPT
#define BR_LEGACY_SWEEP_RED_RATIO_SINGLE_EXEMPT 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATE_FLOOR
#define BR_LEGACY_SWEEP_RED_RATE_FLOOR 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_FEE_CAP
#define BR_LEGACY_SWEEP_RED_FEE_CAP 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_FEE_CEILING
#define BR_LEGACY_SWEEP_RED_FEE_CEILING 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_FEE_OVERFLOW
#define BR_LEGACY_SWEEP_RED_FEE_OVERFLOW 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_ABS_CEIL
#define BR_LEGACY_SWEEP_RED_ABS_CEIL 0
#endif

#define BR_LEGACY_SWEEP_BASE_BYTES      10u
#if BR_LEGACY_SWEEP_RED_SIZE
#define BR_LEGACY_SWEEP_INPUT_BYTES     148u
#else
#define BR_LEGACY_SWEEP_INPUT_BYTES     160u   // an upper bound for a P2PKH (~148) or P2WPKH (~105) input
#endif
#define BR_LEGACY_SWEEP_OUTPUT_BYTES    34u
#define BR_LEGACY_SWEEP_MIN_FEE         1000u      // DigiByte's minimum relay fee
#define BR_LEGACY_SWEEP_FEE_RATIO       20u        // refused when totalIn <= fee * 20 (fee >= 5%)
#define BR_LEGACY_SWEEP_DUST            546u
#define BR_LEGACY_SWEEP_MIN_FEE_PER_KB  100000ull  // DigiByte's minimum relay rate (= DEFAULT_FEE_PER_KB)
#define BR_LEGACY_SWEEP_MAX_FEE_PER_KB  1000000ull // 10 x BR_LEGACY_SWEEP_MIN_FEE_PER_KB
#define BR_LEGACY_SWEEP_FEE_CEILING     10000000ull // TX_MAX_SIZE (100,000 bytes) at DEFAULT_FEE_PER_KB: 0.1 DGB
// The upper rate bound of the comparison arm BR_LEGACY_SWEEP_RED_ABS_CEIL: MAX_FEE_PER_KB (BRWallet.h), the bound
// before SWEEP-ABS-CEIL. BRLegacySweep.h asserts the two are equal.
#define BR_LEGACY_SWEEP_PRE_ABS_CEIL_MAX_FEE_PER_KB 5236126ull

// The floor never binds inside the rate range: the smallest sweep (one input) at the smallest rate pays more.
typedef char _BRLegacySweepFloorUnderRange[
    ((BR_LEGACY_SWEEP_BASE_BYTES + BR_LEGACY_SWEEP_INPUT_BYTES + BR_LEGACY_SWEEP_OUTPUT_BYTES) *
     BR_LEGACY_SWEEP_MIN_FEE_PER_KB / 1000 >= BR_LEGACY_SWEEP_MIN_FEE) ? 1 : -1];

typedef enum {
    BR_LEGACY_SWEEP_FEE_CHECK_OK = 0,
    BR_LEGACY_SWEEP_FEE_CHECK_WRAPS = 1,          // estSize, or estSize * feePerKb, does not fit
    BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_LOW = 2,   // feePerKb below BR_LEGACY_SWEEP_MIN_FEE_PER_KB
    BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_HIGH = 3,  // feePerKb above BR_LEGACY_SWEEP_MAX_FEE_PER_KB
    BR_LEGACY_SWEEP_FEE_CHECK_ABOVE_CEILING = 4,  // the fee is above BR_LEGACY_SWEEP_FEE_CEILING
    BR_LEGACY_SWEEP_FEE_CHECK_RATIO = 5,  // the fee is 5% of the listed total or more
    BR_LEGACY_SWEEP_FEE_CHECK_DUST = 6            // nothing above dust is left after the fee
} BRLegacySweepFeeVerdict;

static inline BRLegacySweepFeeVerdict BRLegacySweepFeeCheck(uint64_t totalIn, size_t inputCount, uint64_t feePerKb,
                                                            size_t *estSizeOut, uint64_t *feeOut)
{
    size_t estSize;
    uint64_t fee;

    if (estSizeOut) *estSizeOut = 0;
    if (feeOut) *feeOut = 0;
#if ! BR_LEGACY_SWEEP_RED_FEE_OVERFLOW
    if (inputCount >
        (SIZE_MAX - BR_LEGACY_SWEEP_BASE_BYTES - BR_LEGACY_SWEEP_OUTPUT_BYTES) / BR_LEGACY_SWEEP_INPUT_BYTES)
        return BR_LEGACY_SWEEP_FEE_CHECK_WRAPS;
#endif
    estSize = BR_LEGACY_SWEEP_BASE_BYTES + inputCount * BR_LEGACY_SWEEP_INPUT_BYTES + BR_LEGACY_SWEEP_OUTPUT_BYTES;
    if (estSizeOut) *estSizeOut = estSize;
#if ! BR_LEGACY_SWEEP_RED_FEE_OVERFLOW
    if (feePerKb != 0 && (uint64_t)estSize > UINT64_MAX / feePerKb) return BR_LEGACY_SWEEP_FEE_CHECK_WRAPS;
#endif
    fee = ((uint64_t)estSize * feePerKb) / 1000;
    if (fee < BR_LEGACY_SWEEP_MIN_FEE) fee = BR_LEGACY_SWEEP_MIN_FEE;
    if (feeOut) *feeOut = fee;

#if BR_LEGACY_SWEEP_RED_ABS_CEIL
    if (feePerKb > BR_LEGACY_SWEEP_PRE_ABS_CEIL_MAX_FEE_PER_KB) return BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_HIGH;
    if (inputCount > 1 && totalIn <= fee * BR_LEGACY_SWEEP_FEE_RATIO) return BR_LEGACY_SWEEP_FEE_CHECK_RATIO;
#else
#if ! BR_LEGACY_SWEEP_RED_RATE_FLOOR
    if (feePerKb < BR_LEGACY_SWEEP_MIN_FEE_PER_KB) return BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_LOW;
#endif
#if ! BR_LEGACY_SWEEP_RED_FEE_CAP
    if (feePerKb > BR_LEGACY_SWEEP_MAX_FEE_PER_KB) return BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_HIGH;
#endif
#if ! BR_LEGACY_SWEEP_RED_FEE_CEILING
    if (fee > BR_LEGACY_SWEEP_FEE_CEILING) return BR_LEGACY_SWEEP_FEE_CHECK_ABOVE_CEILING;
#endif
#if ! BR_LEGACY_SWEEP_RED_RATIO
#if BR_LEGACY_SWEEP_RED_RATIO_SINGLE_EXEMPT
    if (inputCount > 1 &&
#else
    if (
#endif
#if BR_LEGACY_SWEEP_RED_RATIO_STRICT
        totalIn < fee * BR_LEGACY_SWEEP_FEE_RATIO)
#else
        totalIn <= fee * BR_LEGACY_SWEEP_FEE_RATIO)
#endif
        return BR_LEGACY_SWEEP_FEE_CHECK_RATIO;
#endif
#endif
    if (totalIn <= fee + BR_LEGACY_SWEEP_DUST) return BR_LEGACY_SWEEP_FEE_CHECK_DUST;
    return BR_LEGACY_SWEEP_FEE_CHECK_OK;
}

#ifdef __cplusplus
}
#endif

#endif // BRLegacySweepFee_h
