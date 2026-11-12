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

// ---- which outputs a transaction may put units on ------------------------------------------------
//
// Moved from Android's core/asset/AssetTxQuantity.kt: targetsOutput, the three private helpers it
// reads (destroys, mayVoid, issuanceMayCreditLastOutput), assignedUnits and consumptionUncountable.
// Each function below answers what its Kotlin answers, on every input. Nothing in the core calls
// them yet. Of the functions above they use only the overflow-checked arithmetic.
//
// How the Kotlin's arguments are written here:
//
//   header.operation      `op`. ISSUANCE, TRANSFER and BURN are DA_ISSUANCE, DA_TRANSFER and DA_BURN;
//                         every other value (DA_UNDEFINED, which BRAssetDecode.h gives a carrier it
//                         cannot classify, and anything out of range) is UNCLASSIFIABLE.
//   header.version        `version`.
//   header.hasRules       `hasRules` (BRAssetHeaderHasRules: opcode 3 or 4).
//   header.totalQuantity  `hasTotalQuantity` and `totalQuantity`; null is hasTotalQuantity == 0.
//   firstNonOpReturnVout  `hasFirstNonOpReturnVout` and `firstNonOpReturnVout`, the same way.
//   inputUnits            `hasInputUnits` and `inputUnits`, the same way.
//   transferInstructions  `insts` and `instCount`.
//
// One thing the Kotlin has no form of: instCount above zero with no array. That reads as
// instructions that cannot be read, and every function gives the answer it gives for those.
//
// Test seams (host KAT asset_quantity_targets_kat in the Android repo): ASSET_TARGETS_UNFIXED, tested
// by VALUE, a set of bits. 0, the default, is the code that ships; each bit turns one rule off so the
// suite can show that its cases see that rule. Never set in a build that ships.
//
//    1     ASSET_TARGETS_RED_RANGE_END_ONLY        a range instruction names only its end output.
//    2     ASSET_TARGETS_RED_DESTROY_ANY_OP        non-range output 31 destroys in every operation.
//    4     ASSET_TARGETS_RED_MISSING_OUTPUT_KEPT   an instruction to an output the transaction lacks does not void.
//    8     ASSET_TARGETS_RED_ZERO_AMOUNT_KEPT      an instruction of zero units does not void.
//    16    ASSET_TARGETS_RED_VOID_WITHOUT_UNITS    a void is counted when no units came in.
//    32    ASSET_TARGETS_RED_UNKNOWN_NOT_HELD      a remainder that is not known is not a target.
//    64    ASSET_TARGETS_RED_OVERDRAWN_NOTHING     instructions that assign more than came in leave nothing.
//    128   ASSET_TARGETS_RED_RANGE_WRAPS           what a range draws is multiplied without a check.
//    256   ASSET_TARGETS_RED_PERCENT_COUNTED       a percent instruction is counted as assigning nothing.
//    512   ASSET_TARGETS_RED_UNCLASSIFIABLE_OPEN   a carrier that is not classified targets no output.
//    1024  ASSET_TARGETS_RED_ISSUANCE_NO_REMAINDER an issuance's remainder is not counted.
//    2048  ASSET_TARGETS_RED_ISSUANCE_RULES_READ   an issuance with rules, or before version 3, is allocated.
//    4096  ASSET_TARGETS_RED_ISSUANCE_NO_VOID      an issuance's instruction to a missing output does not void.
//    8192  ASSET_TARGETS_RED_ISSUER_OUTPUT_OPEN    an issuance's first non-OP_RETURN output is not a target.

#ifndef ASSET_TARGETS_UNFIXED
#define ASSET_TARGETS_UNFIXED 0
#endif

#define ASSET_TARGETS_RED_RANGE_END_ONLY        1
#define ASSET_TARGETS_RED_DESTROY_ANY_OP        2
#define ASSET_TARGETS_RED_MISSING_OUTPUT_KEPT   4
#define ASSET_TARGETS_RED_ZERO_AMOUNT_KEPT      8
#define ASSET_TARGETS_RED_VOID_WITHOUT_UNITS    16
#define ASSET_TARGETS_RED_UNKNOWN_NOT_HELD      32
#define ASSET_TARGETS_RED_OVERDRAWN_NOTHING     64
#define ASSET_TARGETS_RED_RANGE_WRAPS           128
#define ASSET_TARGETS_RED_PERCENT_COUNTED       256
#define ASSET_TARGETS_RED_UNCLASSIFIABLE_OPEN   512
#define ASSET_TARGETS_RED_ISSUANCE_NO_REMAINDER 1024
#define ASSET_TARGETS_RED_ISSUANCE_RULES_READ   2048
#define ASSET_TARGETS_RED_ISSUANCE_NO_VOID      4096
#define ASSET_TARGETS_RED_ISSUER_OUTPUT_OPEN    8192

// 1 for the three operations a carrier is classified as, 0 for UNCLASSIFIABLE.
static inline int _BRAssetOperationIsClassified(BRAssetOperation op)
{
    return (op == DA_ISSUANCE || op == DA_TRANSFER || op == DA_BURN) ? 1 : 0;
}

// The index of a transaction's last output: outputCount - 1 as a 32-bit two's complement number, so
// the lowest count gives the highest index, as the Kotlin's Int does.
static inline int32_t _BRAssetLastVout(int32_t outputCount)
{
    return (outputCount == INT32_MIN) ? INT32_MAX : outputCount - 1;
}

// What one instruction draws from the inputs: its amount, and for a range its amount once for each
// output in 0..outputIndex. 0 when that does not fit a count. The caller has already refused a
// negative amount and a negative index.
static inline int _BRAssetInstructionDraw(const BRAssetTransferInstruction *in, int64_t *out)
{
    if (! in->range) {
        *out = in->amount;
        return 1;
    }

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_RANGE_WRAPS)
    *out = (int64_t)((uint64_t)((int64_t)in->outputIndex + 1) * (uint64_t)in->amount);
    return 1;
#else
    return _BRAssetMulUnits((int64_t)in->outputIndex + 1, in->amount, out);
#endif
}

// Kotlin: destroys. Does this instruction destroy its units instead of placing them? Only the
// non-range instruction to output 31 of a BURN does. The operation and the index decide it; the
// instruction's isBurn flag is not read. 0 for no instruction.
static inline int BRAssetDestroys(BRAssetOperation op, const BRAssetTransferInstruction *inst)
{
    if (! inst) return 0;
#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_DESTROY_ANY_OP)
    return (! inst->range && inst->outputIndex == 31) ? 1 : 0;
#else
    return (op == DA_BURN && ! inst->range && inst->outputIndex == 31) ? 1 : 0;
#endif
}

// Kotlin: mayVoid. Can the instructions of a transfer or burn be voided whatever the inputs carried
// beyond "something"? Yes when one of them names an output the transaction does not have (and does
// not destroy its units), or moves zero units. A voided transaction puts every unit on its last
// output. Percent instructions are read like the others.
static inline int BRAssetMayVoid(BRAssetOperation op, int32_t outputCount,
                                 const BRAssetTransferInstruction *insts, size_t instCount)
{
    size_t i;

    if (instCount > 0 && ! insts) return 1;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

#if !(ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_MISSING_OUTPUT_KEPT)
        if (! BRAssetDestroys(op, in) && in->outputIndex >= outputCount) return 1;
#endif
#if !(ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_ZERO_AMOUNT_KEPT)
        if (in->amount == 0) return 1;
#endif
    }

    return 0;
}

// Kotlin: assignedUnits. The units the instructions draw from the inputs, in *out, and 1; or 0 (the
// Kotlin's null, *out 0) when that is not a count: a carrier that is not classified, a percent
// instruction, a negative amount or index, or a sum that does not fit. A range draws its amount once
// for each output in 0..outputIndex. An issuance's instructions are summed like a transfer's.
static inline int BRAssetAssignedUnits(BRAssetOperation op, const BRAssetTransferInstruction *insts,
                                       size_t instCount, int64_t *out)
{
    size_t i;
    int64_t assigned = 0, drawn = 0;

    if (! out) return 0;
    *out = 0;
    if (! _BRAssetOperationIsClassified(op)) return 0;
    if (instCount > 0 && ! insts) return 0;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_PERCENT_COUNTED)
        if (in->percent) continue;
#else
        if (in->percent) return 0;
#endif
        if (in->amount < 0 || in->outputIndex < 0) return 0;
        if (! _BRAssetInstructionDraw(in, &drawn)) return 0;
        if (! _BRAssetAddUnits(assigned, drawn, &assigned)) return 0;
    }

    *out = assigned;
    return 1;
}

// Kotlin: consumptionUncountable. 1 when what the fixed and range instructions draw is not a count
// at all: a negative amount or index, or a sum that does not fit. Percent instructions are passed
// over, so this can be 0 where BRAssetAssignedUnits has no answer. 0 for a carrier that is not
// classified.
static inline int BRAssetConsumptionUncountable(BRAssetOperation op, const BRAssetTransferInstruction *insts,
                                                size_t instCount)
{
    size_t i;
    int64_t assigned = 0, drawn = 0;

    if (! _BRAssetOperationIsClassified(op)) return 0;
    if (instCount > 0 && ! insts) return 1;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

        if (in->percent) continue;
        if (in->amount < 0 || in->outputIndex < 0) return 1;
        if (! _BRAssetInstructionDraw(in, &drawn)) return 1;
        if (! _BRAssetAddUnits(assigned, drawn, &assigned)) return 1;
    }

    return 0;
}

// Kotlin: issuanceMayCreditLastOutput. Can an issuance leave units on its last output? It is what
// the Kotlin gets from AssetTransferAllocator.allocateIssuance: 1 when the allocation puts units on
// the last output or cannot be decided, 0 when it is decided and puts none there.
//
// An issuance hands out one supply of `totalQuantity` units. Its instructions draw from that supply
// in order; what they leave goes to the last output; and an instruction that cannot be carried out
// voids them all, which puts the whole supply on the last output. So:
//
//   - rules, a version before 3, no outputs, no total, a percent instruction, a negative amount or
//     index, a range whose draw does not fit a count: not decided, 1.
//   - a total of zero or less, or above 2^54 - 1: nothing is issued, 0.
//   - an instruction after the supply is used up or after one with `skip` set, one that draws more
//     than is left, one that draws units for an output the transaction does not have: void, 1.
//   - otherwise 1 when an instruction placed units on the last output or units are left over, else 0.
//
// An instruction of zero units places nothing and is not checked against the output count.
static inline int BRAssetIssuanceMayCreditLastOutput(int32_t version, int hasRules,
                                                     int hasTotalQuantity, int64_t totalQuantity,
                                                     int32_t outputCount,
                                                     const BRAssetTransferInstruction *insts, size_t instCount)
{
    size_t i;
    int64_t left, drawn = 0;
    int usedUp = 0, lastCredited = 0;

#if !(ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_ISSUANCE_RULES_READ)
    if (hasRules || version < 3) return 1;
#endif
    if (outputCount < 1) return 1;
    if (! hasTotalQuantity) return 1;
    if (totalQuantity <= 0 || totalQuantity > 18014398509481983LL) return 0;   // 2^54 - 1
    if (instCount > 0 && ! insts) return 1;

    for (i = 0; i < instCount; i++) {
        if (insts[i].percent) return 1;
    }

    left = totalQuantity;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

        if (in->outputIndex < 0 || in->amount < 0) return 1;
        if (! _BRAssetInstructionDraw(in, &drawn)) return 1;
        if (usedUp) return 1;

        if (drawn > 0) {
            if (drawn > left) return 1;
            left -= drawn;
            if (left == 0) usedUp = 1;
#if !(ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_ISSUANCE_NO_VOID)
            if (in->outputIndex >= outputCount) return 1;
#endif
            if (in->outputIndex == outputCount - 1) lastCredited = 1;
        }

        if (in->skip) usedUp = 1;
    }

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_ISSUANCE_NO_REMAINDER)
    return lastCredited;
#else
    return (lastCredited || left > 0) ? 1 : 0;
#endif
}

// Kotlin: targetsOutput. May this transaction put asset units on its output `vout`? 1 holds the
// output as one that may carry units; 0 says nothing in the transaction can put units there.
//
//   - A carrier that is not classified: every output, 1.
//   - An output an instruction names: 1, whatever came in. A range names every output up to its
//     index; a percent instruction names its output; an instruction that destroys its units
//     (BRAssetDestroys) names none. `vout` is compared as given, with no lower bound.
//   - An issuance's first non-OP_RETURN output: 1.
//   - The last output (outputCount - 1), when nothing above named it:
//       issuance          BRAssetIssuanceMayCreditLastOutput.
//       transfer, burn    1 when the instructions may be voided (BRAssetMayVoid) and the units that
//                         came in are unknown or are not zero. Otherwise the remainder decides: 1
//                         when it is unknown (the units that came in are unknown or negative, or
//                         BRAssetAssignedUnits has no answer), 1 when it is above zero. Instructions
//                         that assign more than came in leave all of it; otherwise what came in less
//                         what was assigned.
//   - Any other output: 0.
static inline int BRAssetTargetsOutput(BRAssetOperation op, int32_t version, int hasRules,
                                       int hasTotalQuantity, int64_t totalQuantity,
                                       int32_t vout, int hasFirstNonOpReturnVout, int32_t firstNonOpReturnVout,
                                       int hasInputUnits, int64_t inputUnits, int32_t outputCount,
                                       const BRAssetTransferInstruction *insts, size_t instCount)
{
    size_t i;
    int64_t assigned = 0, remainder;

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_UNCLASSIFIABLE_OPEN)
    if (! _BRAssetOperationIsClassified(op)) return 0;
#else
    if (! _BRAssetOperationIsClassified(op)) return 1;
#endif
    if (instCount > 0 && ! insts) return 1;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

        if (BRAssetDestroys(op, in)) continue;
#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_RANGE_END_ONLY)
        if (in->outputIndex == vout) return 1;
#else
        if (in->range ? (vout <= in->outputIndex) : (in->outputIndex == vout)) return 1;
#endif
    }

#if !(ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_ISSUER_OUTPUT_OPEN)
    if (op == DA_ISSUANCE && hasFirstNonOpReturnVout && vout == firstNonOpReturnVout) return 1;
#endif
    if (vout != _BRAssetLastVout(outputCount)) return 0;

    if (op == DA_ISSUANCE) {
        return BRAssetIssuanceMayCreditLastOutput(version, hasRules, hasTotalQuantity, totalQuantity,
                                                  outputCount, insts, instCount);
    }

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_VOID_WITHOUT_UNITS)
    if (BRAssetMayVoid(op, outputCount, insts, instCount)) return 1;
#else
    if (! (hasInputUnits && inputUnits == 0) && BRAssetMayVoid(op, outputCount, insts, instCount)) return 1;
#endif

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_UNKNOWN_NOT_HELD)
    if (! hasInputUnits || inputUnits < 0) return 0;
    if (! BRAssetAssignedUnits(op, insts, instCount, &assigned)) return 0;
#else
    if (! hasInputUnits || inputUnits < 0) return 1;
    if (! BRAssetAssignedUnits(op, insts, instCount, &assigned)) return 1;
#endif

#if (ASSET_TARGETS_UNFIXED & ASSET_TARGETS_RED_OVERDRAWN_NOTHING)
    remainder = (assigned > inputUnits) ? 0 : inputUnits - assigned;
#else
    remainder = (assigned > inputUnits) ? inputUnits : inputUnits - assigned;
#endif
    return (remainder > 0) ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetQuantity_h
