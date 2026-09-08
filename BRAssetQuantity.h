//
//  BRAssetQuantity.h
//
//  How many DigiAsset token units land on ONE transaction output, computed
//  sovereignly from the decoded OP_RETURN header -- no network, no index.
//
//  This is the arithmetic behind the counting rule CLAUDE.md settled in
//  v4.0.39 after four releases spent inferring the bug from balance TOTALS:
//  a row counts if and only if the native wallet still holds that exact
//  output. That rule decides which outputs exist; this header decides how
//  many units are on one. Both must be identical on every platform, because
//  the same seed on two devices showing two balances is the failure the whole
//  shared-core architecture exists to prevent.
//
//  Four decisions live here, each with a direction that costs money:
//
//    BRAssetQuantityForOutput   what the explicit instructions assign.
//                               RANGE credits `amount` to EVERY output in
//                               0..outputIndex (RenzoDD/digiasset-core
//                               DigiByteTransaction.cpp:257-329,
//                               `startI = range ? 0 : output`). Dropping range
//                               entirely -- the shipped pre-fix shape -- makes
//                               every range receive read as 0. That is one of
//                               the two RED gates.
//
//    BRAssetImplicitChange      the units the instructions do NOT assign, which
//                               the protocol credits to the transaction's LAST
//                               output. bread-era wallets and digiasset-core
//                               rely on it: they emit one instruction for the
//                               recipient and let the remainder ride. Missing
//                               it under-counts in the UI and, in native, lets
//                               a plain-DGB spend destroy an asset.
//
//                               CONSUMPTION IS NOT CREDITING. A range
//                               instruction credits `amount` to each output in
//                               0..outputIndex but consumes (outputIndex + 1) *
//                               amount from the inputs (`totalAmount = range ?
//                               (output + 1) * amount : amount` in the
//                               reference); a burn consumes its units and
//                               credits nobody. Conflating the two is how a
//                               remainder gets invented.
//
//    BRAssetImplicitChangeVout  where that remainder lands: the last output,
//                               verbatim. When that output IS the OP_RETURN the
//                               reference credits it there anyway (an effective
//                               burn). Mirror the reference rather than
//                               "improving" it, or this wallet's view of the
//                               chain diverges from every other
//                               implementation's.
//
//    BRAssetOutpointMustBeExcluded
//                               the FAIL-CLOSED spending decision, and the only
//                               one here that is not about display. It is the
//                               rule BRWallet.h states in prose for
//                               BRWalletRegisterAssetOutpoint -- register the
//                               outpoint whenever the remainder is positive OR
//                               unknown -- expressed once, so a caller cannot
//                               get it subtly wrong. Deliberately NOT gated on
//                               the quantity being knowable: keeping an output
//                               out of a plain-DGB spend is cheap and
//                               reversible; spending an asset is not.
//
//  UNKNOWN is a first-class answer, not a zero. A percent instruction needs the
//  per-input asset balances (an index / provenance walk that does not exist at
//  this layer) and the reference implementation's percent path is itself buggy,
//  so percent is skipped for crediting -- an underestimate over a fake number --
//  and makes the remainder UNKNOWN. An unknown remainder credits NOTHING: the
//  balance under-states rather than invents.
//
//  UNSOUND is separate from UNKNOWN on purpose. UNKNOWN means "not computable
//  yet" and is an expected, routine condition; UNSOUND means the decoded
//  instructions cannot be trusted at all. Amounts arrive from an attacker-
//  chosen OP_RETURN through a fixed-precision decoder that multiplies a 42-bit
//  mantissa by up to 10^7, so an `amount` can already be any 64-bit value
//  including a negative one, and (outputIndex + 1) * amount over a 13-bit range
//  index multiplies that by up to 8192. Unguarded, the wrap turns `assigned`
//  negative and `inputUnits - assigned` becomes a FABRICATED credit -- units
//  the wallet displays and, worse, treats as an asset holding. Every add and
//  multiply here is overflow-checked and every negative input is rejected.
//  Dropping that guard is the second RED gate.
//
//  Ported from core/asset/AssetTxQuantity.kt (forOutput, forOutputTotal,
//  implicitChange, implicitChangeVout). The Kotlin mirror survives because its
//  suite runs on the host JVM (NativeBridge's static initializer throws
//  UnsatisfiedLinkError there), and AssetQuantityParityTest binds the mirror to
//  this C. KNOWN DIVERGENCE, deliberate: the mirror has no overflow guard, so
//  the parity test is expected to fail on the crafted-overflow vectors until
//  AssetTxQuantity.implicitChange gains the same checks. That fix is an Android
//  change to a file currently under audit and must land as its own PR.
//
//  Header-only static-inline, no BRWallet, no BRTransaction, no locking, no
//  I/O; testable standalone on the host
//  (native/src/test/host/asset_quantity_kat/). Its only include beyond libc is
//  BRAssetData.h, for the operation enum that has been in the core since 2019
//  -- deliberately NOT BRDigiAsset.h, whose DA_ASSET_DUST_AMOUNT is the asset
//  MARKER value in satoshis and has nothing to do with token units; conflating
//  the two is how a satoshi count gets read as a token count.
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

#ifndef BRAssetQuantity_h
#define BRAssetQuantity_h

#include <stdint.h>
#include <stddef.h>

#include "BRAssetData.h"   // BRAssetOperation: DA_UNDEFINED / DA_ISSUANCE / DA_TRANSFER / DA_BURN

#ifdef __cplusplus
extern "C" {
#endif

// The operation enum is BRAssetData.h's, unchanged and NOT restated here. It
// has been in the core since 2019 and a second copy would be a second source
// of truth for the one field every decision below switches on -- the same trap
// PeerPenaltyPersist.kt's HEADER_BYTES fell into.
//
// PARITY HAZARD, and it is not theoretical: these values are 1/2/3 with a
// DA_UNDEFINED at 0, while Kotlin's io.digibyte.core.model.AssetOperation is
// ISSUANCE/TRANSFER/BURN at 0/1/2. A parity test that maps the two by
// `.ordinal` silently reads every TRANSFER as an ISSUANCE. Map by NAME.
//
// DA_UNDEFINED is a real member rather than only an out-of-range cast, so the
// "I cannot say" answer below has a name a caller can actually pass.

// One decoded transfer instruction, as core/asset/DigiAssetDecoder.kt's
// TransferInstruction carries it.
//
// `skip` (advance the input pointer) is recorded so a caller can pass decoded
// rows through verbatim; none of the decisions here read it, because resolving
// which INPUT an instruction draws from needs the per-input balances that make
// percent unknowable in the first place.
//
// `isBurn` is the decoder's flag for the reserved non-range output index 31.
// It is kept as its own field rather than re-derived, so a future protocol
// version that moves the sentinel changes the decoder and not this table.
typedef struct {
    int     skip;
    int     range;
    int     percent;
    int     isBurn;
    int32_t outputIndex;
    int64_t amount;
} BRAssetTransferInstruction;

typedef enum {
    // The unit count written to *out is exact.
    BRAssetQuantityOK      = 0,
    // Not computable from what this layer can see: a percent instruction, or
    // input units that have not been resolved. *out is 0 and the caller MUST
    // credit nothing -- never treat this as a zero balance.
    BRAssetQuantityUnknown = 1,
    // The decoded instructions cannot be trusted: a negative amount, a negative
    // index, or arithmetic that would overflow. *out is 0. Distinct from
    // Unknown so a caller can log a malformed OP_RETURN rather than filing it
    // under the routine "not resolved yet".
    BRAssetQuantityUnsound = 2
} BRAssetQuantityStatus;

// --- overflow-checked arithmetic over non-negative units -------------------
// Written out rather than using __builtin_*_overflow: this header is compiled
// by whatever toolchain each platform brings, and a policy header that only
// works on clang/gcc is a policy header that gets reimplemented.

static inline int _BRAssetAddUnits(int64_t a, int64_t b, int64_t *out)
{
    if (a < 0 || b < 0) return 0;
    if (a > INT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static inline int _BRAssetMulUnits(int64_t a, int64_t b, int64_t *out)
{
    if (a < 0 || b < 0) return 0;
    if (a != 0 && b > INT64_MAX / a) return 0;
    *out = a * b;
    return 1;
}

// What the explicit instructions assign to `vout`.
//
//   ISSUANCE  totalQuantity lands on the first non-OP_RETURN output (the DA
//             convention -- the issuer's marker); every other output gets 0.
//             `firstNonOpReturnVout` < 0 means there is none, so nobody is
//             credited.
//   TRANSFER  every non-percent, non-burn instruction that targets `vout`,
//             summed. RANGE targets every output in 0..outputIndex.
//   BURN      0 to every output; the units are destroyed.
//
// Percent instructions are SKIPPED, not refused: callers of this function want
// the explicit floor, and a percentage resolved without the per-input balances
// would be a fabricated number. The remainder is where percent turns into
// UNKNOWN, which is the answer that actually protects the balance.
static inline BRAssetQuantityStatus
BRAssetQuantityForOutput(BRAssetOperation op, int64_t totalQuantity,
                         int32_t vout, int32_t firstNonOpReturnVout,
                         const BRAssetTransferInstruction *insts, size_t instCount,
                         int64_t *out)
{
    size_t i;
    int64_t sum = 0;

    if (! out) return BRAssetQuantityUnsound;
    *out = 0;
    if (vout < 0) return BRAssetQuantityUnsound;

    switch (op) {
        case DA_ISSUANCE:
            if (totalQuantity < 0) return BRAssetQuantityUnsound;
            if (firstNonOpReturnVout >= 0 && vout == firstNonOpReturnVout) *out = totalQuantity;
            return BRAssetQuantityOK;

        case DA_BURN:
            return BRAssetQuantityOK;

        case DA_TRANSFER:
            break;

        default:
            // DA_UNDEFINED, or an out-of-range value from a future protocol
            // version, a corrupted read or a bad cast -- a C enum is an int.
            // Kotlin's exhaustive `when` made this unreachable; here it must be
            // defined, and the safe answer is "I cannot say", never a credit.
            return BRAssetQuantityUnsound;
    }

    if (instCount > 0 && ! insts) return BRAssetQuantityUnsound;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];
        int matches;

        if (in->percent || in->isBurn) continue;
        if (in->amount < 0 || in->outputIndex < 0) return BRAssetQuantityUnsound;

#ifndef ASSET_QUANTITY_RANGE_DROPPED_UNFIXED
        matches = in->range ? (vout <= in->outputIndex) : (in->outputIndex == vout);
#else
        // RED-gate shape only: range instructions dropped entirely, which is
        // what shipped before the reference was re-read. Every range receive
        // then counts 0. Never defined in a production build.
        matches = in->range ? 0 : (in->outputIndex == vout);
#endif
        if (! matches) continue;
        if (! _BRAssetAddUnits(sum, in->amount, &sum)) return BRAssetQuantityUnsound;
    }

    *out = sum;
    return BRAssetQuantityOK;
}

// The units the instructions leave unassigned, which the protocol credits to
// the transaction's LAST output.
//
// ISSUANCE returns 0 rather than a remainder: the issued supply is credited by
// BRAssetQuantityForOutput's first-non-OP_RETURN convention, so computing a
// leftover here would double-count the issuer's marker. BURN goes through the
// loop like a transfer -- its instructions consume units, and whatever they do
// not consume still rides to the last output.
//
// Returns Unknown when `hasInputUnits` is false or any instruction is percent.
// Callers credit nothing on Unknown; see BRAssetOutpointMustBeExcluded for the
// separate, fail-closed SPENDING decision, which does not wait on the quantity
// being knowable.
static inline BRAssetQuantityStatus
BRAssetImplicitChange(BRAssetOperation op, int hasInputUnits, int64_t inputUnits,
                      const BRAssetTransferInstruction *insts, size_t instCount,
                      int64_t *out)
{
    size_t i;
    int64_t assigned = 0;

    if (! out) return BRAssetQuantityUnsound;
    *out = 0;

    if (op == DA_ISSUANCE) return BRAssetQuantityOK;
    // DA_UNDEFINED and every out-of-range value land here; see the default case
    // in BRAssetQuantityForOutput.
    if (op != DA_TRANSFER && op != DA_BURN) return BRAssetQuantityUnsound;
    if (! hasInputUnits) return BRAssetQuantityUnknown;
    if (inputUnits < 0) return BRAssetQuantityUnsound;
    if (instCount > 0 && ! insts) return BRAssetQuantityUnsound;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];
        int64_t consumed;

        if (in->percent) return BRAssetQuantityUnknown;
        if (in->amount < 0 || in->outputIndex < 0) return BRAssetQuantityUnsound;

#ifndef ASSET_QUANTITY_OVERFLOW_UNGUARDED
        if (in->range) {
            if (! _BRAssetMulUnits((int64_t)in->outputIndex + 1, in->amount, &consumed))
                return BRAssetQuantityUnsound;
        } else {
            consumed = in->amount;
        }
        if (! _BRAssetAddUnits(assigned, consumed, &assigned)) return BRAssetQuantityUnsound;
#else
        // RED-gate shape only: the same arithmetic without its overflow guard,
        // which is what the Kotlin mirror still does. Wrapping `assigned`
        // negative makes the remainder below a fabricated credit. Never defined
        // in a production build.
        consumed = in->range
            ? (int64_t)((uint64_t)((int64_t)in->outputIndex + 1) * (uint64_t)in->amount)
            : in->amount;
        assigned = (int64_t)((uint64_t)assigned + (uint64_t)consumed);
#endif
    }

    // Unsigned subtraction so the expression is DEFINED in both builds: in the
    // guarded one `assigned` is in [0, INT64_MAX] and `inputUnits > assigned`,
    // so this is bit-identical to the signed form; in the RED build `assigned`
    // may have wrapped negative, and signed overflow there would be undefined
    // behaviour rather than the fabricated credit the gate needs to observe.
    *out = inputUnits > assigned ? (int64_t)((uint64_t)inputUnits - (uint64_t)assigned) : 0;
    return BRAssetQuantityOK;
}

// The output index the implicit remainder lands on: the last one, verbatim.
// Returns a value no real vout can equal when outputCount is 0 or negative, so
// a failed read credits the remainder to nobody instead of to output 0.
static inline int32_t BRAssetImplicitChangeVout(int32_t outputCount)
{
    return outputCount - 1;
}

// The whole per-output quantity: what the instructions assign, plus the
// implicit remainder when this IS the last output. Detection and display both
// go through here so they cannot diverge.
//
// An UNKNOWN remainder contributes 0 and the result is still OK: the
// under-statement is deliberate and mirrors the Kotlin. A caller that needs to
// know the number is a floor rather than a total must ask
// BRAssetImplicitChange directly -- and one deciding whether the output is
// SPENDABLE must ask BRAssetOutpointMustBeExcluded, which fails the other way.
static inline BRAssetQuantityStatus
BRAssetQuantityForOutputTotal(BRAssetOperation op, int64_t totalQuantity,
                              int32_t vout, int32_t firstNonOpReturnVout,
                              int hasInputUnits, int64_t inputUnits, int32_t outputCount,
                              const BRAssetTransferInstruction *insts, size_t instCount,
                              int64_t *out)
{
    BRAssetQuantityStatus st;
    int64_t assigned = 0, change = 0;

    if (! out) return BRAssetQuantityUnsound;
    *out = 0;

    st = BRAssetQuantityForOutput(op, totalQuantity, vout, firstNonOpReturnVout,
                                  insts, instCount, &assigned);
    if (st != BRAssetQuantityOK) return st;

    if (vout != BRAssetImplicitChangeVout(outputCount)) {
        *out = assigned;
        return BRAssetQuantityOK;
    }

    st = BRAssetImplicitChange(op, hasInputUnits, inputUnits, insts, instCount, &change);
    if (st == BRAssetQuantityUnsound) return st;
    if (st == BRAssetQuantityUnknown) {
        *out = assigned;
        return BRAssetQuantityOK;
    }
    if (! _BRAssetAddUnits(assigned, change, out)) {
        *out = 0;
        return BRAssetQuantityUnsound;
    }
    return BRAssetQuantityOK;
}

// Must this outpoint be held OUT of the spendable plain-DGB set?
//
// The tx-local classifier cannot see implicit change -- there is no marker on
// the output saying it carries units -- so without this the wallet's own coin
// selection will spend an asset as if it were change. BRWallet.h states the
// rule in prose for BRWalletRegisterAssetOutpoint; this is that rule as code.
//
// FAIL-CLOSED, and the asymmetry is the whole point: excluded when the
// remainder is positive OR not computable. Wrongly excluding an output costs
// the user some spendable DGB until the next resolve; wrongly spending one
// destroys an asset permanently. Unknown therefore excludes, and an UNSOUND
// header -- a hostile or corrupt OP_RETURN -- excludes too rather than being
// waved through as "not an asset".
static inline int BRAssetOutpointMustBeExcluded(BRAssetOperation op,
                                                int32_t vout, int32_t outputCount,
                                                int hasInputUnits, int64_t inputUnits,
                                                const BRAssetTransferInstruction *insts,
                                                size_t instCount)
{
    BRAssetQuantityStatus st;
    int64_t change = 0;

    if (vout < 0 || vout != BRAssetImplicitChangeVout(outputCount)) return 0;
    st = BRAssetImplicitChange(op, hasInputUnits, inputUnits, insts, instCount, &change);
    if (st != BRAssetQuantityOK) return 1;
    return change > 0 ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetQuantity_h
