//
//  BRLegacySweep.h
//
//  The Recover-funds sweep: one transaction spending a derivation profile's coins, each signed with the key
//  derived from the recovery seed at the profile's prefix + (chain, index), into one output paying the
//  destination everything less the fee. Moved from the Android JNI bridge (jni_derive.c,
//  NativeBridge_buildAndSignLegacySweep). The fee rule is BRLegacySweepFee.h, the one copy the bridge's backstop
//  (bridge/sweep_fee_guard.h) also uses (SWEEP-ABS-CEIL). The core refuses everything the bridge refuses and signs
//  the same bytes wherever it signs; it refuses one thing more, an amount or total above MAX_MONEY (the bridge bounds
//  its sum at UINT64_MAX). A fee product that wraps is refused by both: the core names it FEE_OVERFLOW, the bridge
//  refuses the rate as out of range. A sweep that lists one outpoint twice is refused by both (CORE-SWEEP-DISTINCT:
//  the bridge by its tx_inputs_distinct, the core as DUPLICATE_INPUT). The bridge's
//  JNI handling (arrays, strings, the hex decoding of txids and scripts, logging), the signed-spend gate and the
//  serialization stay on the platform side.
//
//  BRLegacySweepBuildAndSign(&tx, seed, seedLen, hmacKey, prefixPath, prefixLen, inputs, inputCount,
//                            destAddress, feePerKb, &fee), in the bridge's order:
//    1. seed, hmacKey, inputs or destAddress NULL; prefixPath NULL with prefixLen > 0 -> BAD_ARGUMENT
//    2. inputCount 0                                                                     -> NO_INPUTS
//    3. seedLen 0 or above BR_LEGACY_SWEEP_SEED_MAX (64)                                 -> BAD_SEED
//    4. the key array, the transaction or the path buffer cannot be allocated            -> NO_MEMORY
//    5. per input, in order: a script NULL, empty, or longer than BR_LEGACY_SWEEP_SCRIPT_MAX (128, the bridge's
//       decode buffer)                                                                   -> BAD_INPUT (fee->input)
//       then an amount of 0, an amount above MAX_MONEY, or one that takes the running total of the amounts so far
//       above MAX_MONEY                                                                  -> BAD_AMOUNT (fee->input)
//       otherwise the key at prefixPath/chain/index is derived (BRBIP32PrivKeyArrayPath, HMAC key hmacKey) and
//       the input added (txHash, vout, amount, script; no signature or witness; TXIN_SEQUENCE). totalIn is the
//       sum of the amounts, at most MAX_MONEY.
//   5b. EVERY INPUT A DIFFERENT OUTPOINT (CORE-SWEEP-DISTINCT), asked of the inputs as assembled, once all of them
//       passed 5: two inputs with the same txHash and the same vout, whatever their amounts, scripts or key paths
//                                                                                        -> DUPLICATE_INPUT
//       (fee->input is the later input of the first such pair: the lowest j for which some i < j names the same
//       outpoint). Inputs that share a txHash and differ in vout are different outpoints. Nothing is signed: this
//       is before the destination is read and before the fee rule, as in the bridge.
//    6. BRAddressScriptPubKey(destAddress) into BR_LEGACY_SWEEP_DEST_SCRIPT_MAX (48) bytes is 0 -> BAD_DESTINATION
//    7. THE FEE: BRLegacySweepFeeCheck (BRLegacySweepFee.h), in its order. estSize = 10 + inputCount * 160 + 34;
//       estSize * feePerKb above UINT64_MAX (or estSize above SIZE_MAX)                  -> FEE_OVERFLOW
//       fee = estSize * feePerKb / 1000, at least 1000 (a floor the rate range never reaches).
//       feePerKb below BR_LEGACY_SWEEP_MIN_FEE_PER_KB (100,000)                          -> FEE_RATE_TOO_LOW
//       feePerKb above BR_LEGACY_SWEEP_MAX_FEE_PER_KB (1,000,000)                        -> FEE_RATE_TOO_HIGH
//       (the product is checked before the rate, so a rate that wraps is named as a wrap; either is refused)
//       fee above BR_LEGACY_SWEEP_FEE_CEILING (10,000,000)                               -> FEE_ABOVE_CEILING
//    8. totalIn <= fee * BR_LEGACY_SWEEP_FEE_RATIO (20), i.e. the fee is 5% of the inputs or more, for a lone input
//       as for many (SWEEP-ABS-CEIL: no single-input exemption)                          -> FEE_TOO_HIGH
//    9. totalIn <= fee + BR_LEGACY_SWEEP_DUST (546)                                      -> DUST
//   10. one output of totalIn - fee to the destination script; BRTransactionSign(tx, 0, keys, inputCount), which
//       signs P2PKH, P2WPKH, P2SH-P2WPKH and P2TR key-path inputs by their script; a failed sign, or a transaction
//       that is not then BRTransactionIsSigned (an input no derived key matches)       -> SIGN_FAILED
//   11. SIGNED: *txOut is the signed transaction; the caller frees it (BRTransactionFree).
//  On every refusal *txOut is NULL and nothing is left allocated: a refusal is a status, never a transaction with
//  a smaller output or a smaller (or zero) fee.
//  ARITHMETIC, uint64_t as the bridge computes it (the bridge casts its jlong amounts and feePerKb to uint64_t; a
//  platform passes what it would have passed the bridge). Nothing wraps. The two values that could wrap modulo 2^64
//  are refused before they do: the sum totalIn (each amount and the running total at most MAX_MONEY, so the sum is
//  at most MAX_MONEY: BAD_AMOUNT), and the product estSize * feePerKb (FEE_OVERFLOW). Then fee is at most
//  (2^64 - 1) / 1000 or the 1000 floor, so fee * 20 and fee + 546 fit; and the dust rule leaves fee < totalIn, so
//  the output totalIn - fee never wraps. (The bridge, jni_derive.c, bounds its sum at UINT64_MAX rather than
//  MAX_MONEY, so the core differs from it only on totals between the two.) A jlong amount that was negative reads as
//  above MAX_MONEY; the bridge refuses it as not positive.
//  FEE RATE (SWEEP-ABS-CEIL). The rate is within [100,000, 1,000,000] sat/kB: at least DigiByte's minimum relay rate
//  (a sweep below it never relays) and at most ten times it; the Android caller asks for DEFAULT_FEE_PER_KB
//  (100,000) on every sweep. With the absolute ceiling and the 5% rule applied to every sweep, a lone input pays at
//  most 204,000 satoshis (204 bytes at the top rate), and that only on a coin listed above 4,080,000.
//  fee (optional) reports what was computed for the platform's log: estSize, fee, totalIn and the output amount
//  as far as the call got (FEE_OVERFLOW leaves fee 0; FEE_RATE_TOO_LOW, FEE_RATE_TOO_HIGH and FEE_ABOVE_CEILING
//  report the fee the rate would have paid;
//  BAD_AMOUNT leaves totalIn the sum before the refused input; DUPLICATE_INPUT leaves totalIn the sum of every
//  listed amount, the repeat included), and the failing input for BAD_INPUT, BAD_AMOUNT and DUPLICATE_INPUT
//  (SIZE_MAX otherwise).
//
//  THE GATE. A platform MUST pass *txOut through BRSignedSpendGate (or its reservation) before serializing or
//  publishing it; a SIGNED result is not permission to broadcast. The bridge does so against its loaded wallet, or
//  the coin reservation alone, around its own wallet lock and clock. Nothing here claims or reads a reservation.
//  HEX. The caller decodes and validates the txid and script hex (the bridge did before: a txid of exactly 32 bytes,
//  a script of 1..128 bytes, even-length hex of 0-9a-fA-F only); this header takes bytes.
//
//  KEYS. seed is read, never written or copied. Every derived key is wiped (BRKeyClean) before the key array is
//  freed, on every path; the path buffer is wiped before it is freed. BRBIP32PrivKeyArrayPath wipes its own
//  intermediates (the HMAC output, chain code and secret).
//
//  INPUTS. txHash is the coin's txid in the parser's internal byte order (the bridge reverses the display hex it
//  is given; BRRawTxIdFromDisplayHex decodes the same 64 digits). The amount and script are the ones the coin was
//  proven at (BRRawTxBinding.h). BRLegacySweepInputFromProof(in, utxo, proof, parents, parentCount) fills txHash
//  and vout from the coin (utxo) and amount and script from its PROVEN proof, pointing into the caller's parent
//  bytes, which must outlive the call; so a proof is never paired with another outpoint. It refuses (0, in untouched)
//  a proof that is not PROVEN, a vout outside 0..UINT32_MAX, a parent index or script range outside parents[], and a
//  parent filed under a txid other than the coin's.
//  The caller's list is not trusted to name each coin once: a platform removes repeated rows before it builds the
//  list (BRRecoveryUtxo.h), and step 5b refuses a list that still names one twice. The comparison is quadratic in
//  inputCount, 36 bytes a pair, beside one BIP32 derivation per input.
//
//  NETWORK. BRAddressScriptPubKey follows BRNetworkIsTestnet() at the call.
//
//  Comparison arms for the host KAT only (legacy_sweep_kat in the Android repo), tested by VALUE (#if); unset or
//  =0 is what ships. The fee rule's arms are listed in BRLegacySweepFee.h (BR_LEGACY_SWEEP_RED_ABS_CEIL among them,
//  which here also lets a zero amount through); this header's own:
//    BR_LEGACY_SWEEP_RED_NO_WIPE=1       the derived keys are freed without being wiped
//    BR_LEGACY_SWEEP_RED_MAX_MONEY=1     no MAX_MONEY bound on an amount or the total (the sum wraps)
//    BR_LEGACY_SWEEP_RED_ZERO_AMOUNT=1   an amount of 0 is accepted
//    BR_LEGACY_SWEEP_RED_DUPLICATE_INPUT=1  two inputs naming one outpoint are not refused (5b)
//  Header-only, static inline; no I/O, no locking, no clock.
//

#ifndef BRLegacySweep_h
#define BRLegacySweep_h

#include "BRInt.h"
#include "BRKey.h"
#include "BRAddress.h"
#include "BRBIP32Sequence.h"
#include "BRCrypto.h"
#include "BRTransaction.h"   // MAX_MONEY
#include "BRWallet.h"        // DEFAULT_FEE_PER_KB, MAX_FEE_PER_KB
#include "BRRawTxBinding.h"
#include "BRLegacySweepFee.h" // the fee rule and its limits (SWEEP-ABS-CEIL)
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BR_LEGACY_SWEEP_RED_NO_WIPE
#define BR_LEGACY_SWEEP_RED_NO_WIPE 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_MAX_MONEY
#define BR_LEGACY_SWEEP_RED_MAX_MONEY 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_ZERO_AMOUNT
#define BR_LEGACY_SWEEP_RED_ZERO_AMOUNT 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_DUPLICATE_INPUT
#define BR_LEGACY_SWEEP_RED_DUPLICATE_INPUT 0
#endif

#define BR_LEGACY_SWEEP_SEED_MAX        64u    // a BIP39 seed; the bridge's SEED_BUFFER_MAX
#define BR_LEGACY_SWEEP_SCRIPT_MAX      128u   // the bridge's scriptBytes[128]
#define BR_LEGACY_SWEEP_DEST_SCRIPT_MAX 48u    // the bridge's destScript[48]
#define BR_LEGACY_SWEEP_MAX_MONEY       ((uint64_t)MAX_MONEY)        // 21e9 DGB in satoshis

// The rate the Android caller passes (DEFAULT_FEE_PER_KB) is the bottom of the range, DigiByte's minimum relay rate.
typedef char _BRLegacySweepDefaultRateIsFloor[(DEFAULT_FEE_PER_KB == BR_LEGACY_SWEEP_MIN_FEE_PER_KB) ? 1 : -1];
// The ceiling is TX_MAX_SIZE at the default rate.
typedef char _BRLegacySweepCeilingIsMaxSize[
    ((uint64_t)TX_MAX_SIZE * DEFAULT_FEE_PER_KB / 1000 == BR_LEGACY_SWEEP_FEE_CEILING) ? 1 : -1];
// The comparison arm BR_LEGACY_SWEEP_RED_ABS_CEIL restores the bound before SWEEP-ABS-CEIL, MAX_FEE_PER_KB.
typedef char _BRLegacySweepPreAbsCeilBound[
    ((uint64_t)MAX_FEE_PER_KB == BR_LEGACY_SWEEP_PRE_ABS_CEIL_MAX_FEE_PER_KB) ? 1 : -1];

typedef struct {
    UInt256 txHash;            // the coin's txid, internal byte order
    uint32_t vout;
    uint64_t amount;           // satoshis, as proven
    uint32_t chain;            // 0 receive, 1 change: the path element after the prefix
    uint32_t index;            // the last path element
    const uint8_t *script;     // the coin's scriptPubKey, as proven
    size_t scriptLen;
} BRLegacySweepInput;

typedef enum {
    BR_LEGACY_SWEEP_SIGNED = 0,
    BR_LEGACY_SWEEP_BAD_ARGUMENT = 1,     // a required pointer was NULL
    BR_LEGACY_SWEEP_NO_INPUTS = 2,
    BR_LEGACY_SWEEP_BAD_SEED = 3,         // seedLen 0 or above 64
    BR_LEGACY_SWEEP_NO_MEMORY = 4,
    BR_LEGACY_SWEEP_BAD_INPUT = 5,        // an input's script is NULL, empty or above 128 bytes
    BR_LEGACY_SWEEP_BAD_DESTINATION = 6,  // the destination has no script
    BR_LEGACY_SWEEP_FEE_TOO_HIGH = 7,     // the fee is 5% of the inputs or more
    BR_LEGACY_SWEEP_DUST_OUTPUT = 8,      // the inputs do not exceed the fee plus 546
    BR_LEGACY_SWEEP_SIGN_FAILED = 9,      // an input was not signed
    BR_LEGACY_SWEEP_BAD_AMOUNT = 10,      // an input's amount is 0, or it or the running total is above MAX_MONEY
    BR_LEGACY_SWEEP_FEE_RATE_TOO_HIGH = 11, // feePerKb is above BR_LEGACY_SWEEP_MAX_FEE_PER_KB
    BR_LEGACY_SWEEP_FEE_OVERFLOW = 12,    // estSize * feePerKb does not fit in 64 bits
    BR_LEGACY_SWEEP_FEE_RATE_TOO_LOW = 13, // feePerKb is below BR_LEGACY_SWEEP_MIN_FEE_PER_KB
    BR_LEGACY_SWEEP_FEE_ABOVE_CEILING = 14, // the fee is above BR_LEGACY_SWEEP_FEE_CEILING
    BR_LEGACY_SWEEP_DUPLICATE_INPUT = 15  // two inputs name one outpoint (the same txHash and vout)
} BRLegacySweepResult;

typedef struct {
    size_t estSize;
    uint64_t fee;
    uint64_t totalIn;
    uint64_t outAmount;
    size_t input;              // BAD_INPUT, BAD_AMOUNT, DUPLICATE_INPUT: the input refused; otherwise SIZE_MAX
} BRLegacySweepFee;

// Fills in's outpoint from utxo and its amount and script from utxo's PROVEN proof of parents[]
// (BRRawTxBindingCheck); 1 when it did. 0, and in untouched, otherwise (see INPUTS). chain and index stay the
// caller's.
static inline int BRLegacySweepInputFromProof(BRLegacySweepInput *in, const BRRawTxBindingUtxo *utxo,
                                              const BRRawTxProof *proof, const BRRawTxBindingParent parents[],
                                              size_t parentCount)
{
    if (! in || ! utxo || ! proof || ! parents || proof->state != BR_RAW_TX_PROOF_PROVEN) return 0;
    if (utxo->vout < 0 || utxo->vout > (int64_t)UINT32_MAX) return 0;
    if (proof->parent >= parentCount || ! parents[proof->parent].bytes) return 0;
    if (! UInt256Eq(parents[proof->parent].txid, utxo->txid)) return 0;
    if (proof->scriptOffset > parents[proof->parent].len ||
        proof->scriptLen > parents[proof->parent].len - proof->scriptOffset) return 0;
    in->txHash = utxo->txid;
    in->vout = (uint32_t)utxo->vout;
    in->amount = (uint64_t)proof->amount;
    in->script = parents[proof->parent].bytes + proof->scriptOffset;
    in->scriptLen = proof->scriptLen;
    return 1;
}

// The later input of the first pair of inputs[0, count) that names one outpoint (the same txHash and vout): the
// lowest j for which some i < j names inputs[j]'s outpoint. SIZE_MAX when every input names a different one.
static inline size_t _BRLegacySweepRepeatedInput(const BRLegacySweepInput inputs[], size_t count)
{
    size_t i, j;

    for (j = 1; j < count; j++) {
        for (i = 0; i < j; i++) {
            if (inputs[i].vout == inputs[j].vout && UInt256Eq(inputs[i].txHash, inputs[j].txHash)) return j;
        }
    }
    return SIZE_MAX;
}

static inline void _BRLegacySweepWipeKeys(BRKey *keys, size_t count)
{
#if BR_LEGACY_SWEEP_RED_NO_WIPE
    (void)keys; (void)count;
#else
    for (size_t i = 0; i < count; i++) BRKeyClean(&keys[i]);
#endif
}

static inline BRLegacySweepResult BRLegacySweepBuildAndSign(BRTransaction **txOut,
                                                            const uint8_t *seed, size_t seedLen,
                                                            const char *hmacKey,
                                                            const uint32_t *prefixPath, size_t prefixLen,
                                                            const BRLegacySweepInput inputs[], size_t inputCount,
                                                            const char *destAddress, uint64_t feePerKb,
                                                            BRLegacySweepFee *feeOut)
{
    BRLegacySweepFee f = { 0, 0, 0, 0, SIZE_MAX };
    BRLegacySweepResult r = BR_LEGACY_SWEEP_SIGNED;
    BRKey *keys = NULL;
    BRTransaction *tx = NULL;
    uint32_t *fullPath = NULL;
    uint8_t destScript[BR_LEGACY_SWEEP_DEST_SCRIPT_MAX];
    size_t destScriptLen, i;

    if (txOut) *txOut = NULL;
    if (! txOut || ! seed || ! hmacKey || ! inputs || ! destAddress || (! prefixPath && prefixLen > 0)) {
        r = BR_LEGACY_SWEEP_BAD_ARGUMENT;
        goto out;
    }
    if (inputCount == 0) { r = BR_LEGACY_SWEEP_NO_INPUTS; goto out; }
    if (seedLen == 0 || seedLen > BR_LEGACY_SWEEP_SEED_MAX) { r = BR_LEGACY_SWEEP_BAD_SEED; goto out; }

    keys = (BRKey *)calloc(inputCount, sizeof(BRKey));
    if (! keys) { r = BR_LEGACY_SWEEP_NO_MEMORY; goto out; }
    tx = BRTransactionNew();
    if (! tx) { r = BR_LEGACY_SWEEP_NO_MEMORY; goto out; }
    fullPath = (uint32_t *)malloc((prefixLen + 2) * sizeof(uint32_t));
    if (! fullPath) { r = BR_LEGACY_SWEEP_NO_MEMORY; goto out; }
    for (i = 0; i < prefixLen; i++) fullPath[i] = prefixPath[i];

    for (i = 0; i < inputCount; i++) {
        const BRLegacySweepInput *in = &inputs[i];

        if (! in->script || in->scriptLen == 0 || in->scriptLen > BR_LEGACY_SWEEP_SCRIPT_MAX) {
            f.input = i;
            r = BR_LEGACY_SWEEP_BAD_INPUT;
            goto out;
        }
#if ! BR_LEGACY_SWEEP_RED_ZERO_AMOUNT && ! BR_LEGACY_SWEEP_RED_ABS_CEIL
        if (in->amount == 0) {   // SWEEP-ABS-CEIL: every amount is positive
            f.input = i;
            r = BR_LEGACY_SWEEP_BAD_AMOUNT;
            goto out;
        }
#endif
#if ! BR_LEGACY_SWEEP_RED_MAX_MONEY
        // totalIn <= MAX_MONEY here, so MAX_MONEY - totalIn does not wrap, and neither does the sum below.
        if (in->amount > BR_LEGACY_SWEEP_MAX_MONEY || in->amount > BR_LEGACY_SWEEP_MAX_MONEY - f.totalIn) {
            f.input = i;
            r = BR_LEGACY_SWEEP_BAD_AMOUNT;
            goto out;
        }
#endif
        fullPath[prefixLen] = in->chain;
        fullPath[prefixLen + 1] = in->index;
        BRBIP32PrivKeyArrayPath(&keys[i], seed, seedLen, hmacKey, fullPath, prefixLen + 2);
        BRTransactionAddInput(tx, in->txHash, in->vout, in->amount, in->script, in->scriptLen,
                              NULL, 0, NULL, 0, TXIN_SEQUENCE);
        f.totalIn += in->amount;
    }
    mem_clean(fullPath, (prefixLen + 2) * sizeof(uint32_t));
    free(fullPath);
    fullPath = NULL;

#if ! BR_LEGACY_SWEEP_RED_DUPLICATE_INPUT
    // CORE-SWEEP-DISTINCT: every input names a different outpoint, or nothing is signed.
    i = _BRLegacySweepRepeatedInput(inputs, inputCount);
    if (i != SIZE_MAX) {
        f.input = i;
        r = BR_LEGACY_SWEEP_DUPLICATE_INPUT;
        goto out;
    }
#endif

    destScriptLen = BRAddressScriptPubKey(destScript, sizeof(destScript), destAddress);
    if (destScriptLen == 0) { r = BR_LEGACY_SWEEP_BAD_DESTINATION; goto out; }

    switch (BRLegacySweepFeeCheck(f.totalIn, inputCount, feePerKb, &f.estSize, &f.fee)) {
    case BR_LEGACY_SWEEP_FEE_CHECK_OK: break;
    case BR_LEGACY_SWEEP_FEE_CHECK_WRAPS: r = BR_LEGACY_SWEEP_FEE_OVERFLOW; goto out;
    case BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_LOW: r = BR_LEGACY_SWEEP_FEE_RATE_TOO_LOW; goto out;
    case BR_LEGACY_SWEEP_FEE_CHECK_RATE_TOO_HIGH: r = BR_LEGACY_SWEEP_FEE_RATE_TOO_HIGH; goto out;
    case BR_LEGACY_SWEEP_FEE_CHECK_ABOVE_CEILING: r = BR_LEGACY_SWEEP_FEE_ABOVE_CEILING; goto out;
    case BR_LEGACY_SWEEP_FEE_CHECK_RATIO: r = BR_LEGACY_SWEEP_FEE_TOO_HIGH; goto out;
    default: r = BR_LEGACY_SWEEP_DUST_OUTPUT; goto out;   // BR_LEGACY_SWEEP_FEE_CHECK_DUST
    }

    f.outAmount = f.totalIn - f.fee;
    BRTransactionAddOutput(tx, f.outAmount, destScript, destScriptLen);

    {
        int signOk = BRTransactionSign(tx, 0, keys, inputCount);

        _BRLegacySweepWipeKeys(keys, inputCount);
        free(keys);
        keys = NULL;
        if (! signOk || ! BRTransactionIsSigned(tx)) { r = BR_LEGACY_SWEEP_SIGN_FAILED; goto out; }
    }

    *txOut = tx;
    tx = NULL;

out:
    if (fullPath) {
        mem_clean(fullPath, (prefixLen + 2) * sizeof(uint32_t));
        free(fullPath);
    }
    if (keys) {
        _BRLegacySweepWipeKeys(keys, inputCount);
        free(keys);
    }
    if (tx) BRTransactionFree(tx);
    if (feeOut) *feeOut = f;
    return r;
}

#ifdef __cplusplus
}
#endif

#endif // BRLegacySweep_h
