//
//  BRLegacySweep.h
//
//  The Recover-funds sweep: one transaction spending a derivation profile's coins, each signed with the key
//  derived from the recovery seed at the profile's prefix + (chain, index), into one output paying the
//  destination everything less the fee. Moved from the Android JNI bridge (jni_derive.c,
//  NativeBridge_buildAndSignLegacySweep), unchanged: for the same inputs it signs the same bytes. The bridge's
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
//       otherwise the key at prefixPath/chain/index is derived (BRBIP32PrivKeyArrayPath, HMAC key hmacKey) and
//       the input added (txHash, vout, amount, script; no signature or witness; TXIN_SEQUENCE). totalIn is the
//       sum of the amounts.
//    6. BRAddressScriptPubKey(destAddress) into BR_LEGACY_SWEEP_DEST_SCRIPT_MAX (48) bytes is 0 -> BAD_DESTINATION
//    7. THE FEE. estSize = BR_LEGACY_SWEEP_BASE_BYTES (10) + inputCount * BR_LEGACY_SWEEP_INPUT_BYTES (160)
//       + BR_LEGACY_SWEEP_OUTPUT_BYTES (34), whatever the input types; fee = estSize * feePerKb / 1000, at
//       least BR_LEGACY_SWEEP_MIN_FEE (1000).
//    8. inputCount > 1 and totalIn <= fee * BR_LEGACY_SWEEP_FEE_RATIO (20), i.e. the fee is 5% of the inputs or
//       more                                                                             -> FEE_TOO_HIGH
//       (a lone input is exempt: a small coin can legitimately pay a large share in fee)
//    9. totalIn <= fee + BR_LEGACY_SWEEP_DUST (546)                                      -> DUST
//   10. one output of totalIn - fee to the destination script; BRTransactionSign(tx, 0, keys, inputCount), which
//       signs P2PKH, P2WPKH, P2SH-P2WPKH and P2TR key-path inputs by their script; a failed sign, or a transaction
//       that is not then BRTransactionIsSigned (an input no derived key matches)       -> SIGN_FAILED
//   11. SIGNED: *txOut is the signed transaction; the caller frees it (BRTransactionFree).
//  On every refusal *txOut is NULL and nothing is left allocated. ARITHMETIC: estSize is size_t; totalIn, fee,
//  fee * 20 and fee + 546 are uint64_t, all modulo their width, exactly as the bridge computes them (the bridge
//  casts its jlong amounts and feePerKb to uint64_t; a platform passes what it would have passed the bridge).
//  fee (optional) reports what was computed for the platform's log: estSize, fee, totalIn and the output amount
//  as far as the call got, and the failing input for BAD_INPUT (SIZE_MAX otherwise).
//
//  THE GATE. The bridge passes the signed transaction through its signed-spend gate (BRSpendGate.h's
//  BRSignedSpendGate against its loaded wallet, or the coin reservation alone) before serializing it; that stays
//  the platform's, around its own wallet lock and clock. Nothing here claims or reads a reservation.
//
//  KEYS. seed is read, never written or copied. Every derived key is wiped (BRKeyClean) before the key array is
//  freed, on every path; the path buffer is wiped before it is freed. BRBIP32PrivKeyArrayPath wipes its own
//  intermediates (the HMAC output, chain code and secret).
//
//  INPUTS. txHash is the coin's txid in the parser's internal byte order (the bridge reverses the display hex it
//  is given; BRRawTxIdFromDisplayHex decodes the same 64 digits). The amount and script are the ones the coin was
//  proven at (BRRawTxBinding.h): BRLegacySweepInputFromProof fills them from a PROVEN proof, pointing into the
//  caller's parent bytes, which must outlive the call.
//
//  NETWORK. BRAddressScriptPubKey follows BRNetworkIsTestnet() at the call.
//
//  Comparison arms for the host KAT only (legacy_sweep_kat in the Android repo), tested by VALUE (#if); unset or
//  =0 is what ships. Each is one fee rule or the key wipe changed:
//    BR_LEGACY_SWEEP_RED_SIZE=1          148 bytes per input instead of 160
//    BR_LEGACY_SWEEP_RED_FLOOR=1         no 1000-satoshi minimum fee
//    BR_LEGACY_SWEEP_RED_RATIO=1         the 5% refusal is not applied
//    BR_LEGACY_SWEEP_RED_RATIO_STRICT=1  the 5% refusal applies only above the boundary (totalIn < fee * 20)
//    BR_LEGACY_SWEEP_RED_RATIO_SINGLE=1  the 5% refusal applies to a lone input too
//    BR_LEGACY_SWEEP_RED_DUST=1          the dust refusal applies only below the boundary (totalIn < fee + 546)
//    BR_LEGACY_SWEEP_RED_NO_WIPE=1       the derived keys are freed without being wiped
//  Header-only, static inline; no I/O, no locking, no clock.
//

#ifndef BRLegacySweep_h
#define BRLegacySweep_h

#include "BRInt.h"
#include "BRKey.h"
#include "BRAddress.h"
#include "BRBIP32Sequence.h"
#include "BRCrypto.h"
#include "BRTransaction.h"
#include "BRRawTxBinding.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BR_LEGACY_SWEEP_RED_SIZE
#define BR_LEGACY_SWEEP_RED_SIZE 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_FLOOR
#define BR_LEGACY_SWEEP_RED_FLOOR 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO
#define BR_LEGACY_SWEEP_RED_RATIO 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO_STRICT
#define BR_LEGACY_SWEEP_RED_RATIO_STRICT 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_RATIO_SINGLE
#define BR_LEGACY_SWEEP_RED_RATIO_SINGLE 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_DUST
#define BR_LEGACY_SWEEP_RED_DUST 0
#endif
#ifndef BR_LEGACY_SWEEP_RED_NO_WIPE
#define BR_LEGACY_SWEEP_RED_NO_WIPE 0
#endif

#define BR_LEGACY_SWEEP_SEED_MAX        64u    // a BIP39 seed; the bridge's SEED_BUFFER_MAX
#define BR_LEGACY_SWEEP_SCRIPT_MAX      128u   // the bridge's scriptBytes[128]
#define BR_LEGACY_SWEEP_DEST_SCRIPT_MAX 48u    // the bridge's destScript[48]
#define BR_LEGACY_SWEEP_BASE_BYTES      10u
#if BR_LEGACY_SWEEP_RED_SIZE
#define BR_LEGACY_SWEEP_INPUT_BYTES     148u
#else
#define BR_LEGACY_SWEEP_INPUT_BYTES     160u   // an upper bound for a P2PKH (~148) or P2WPKH (~105) input
#endif
#define BR_LEGACY_SWEEP_OUTPUT_BYTES    34u
#define BR_LEGACY_SWEEP_MIN_FEE         1000u  // DigiByte's minimum relay fee
#define BR_LEGACY_SWEEP_FEE_RATIO       20u    // refused when totalIn <= fee * 20 (fee >= 5%), more than one input
#define BR_LEGACY_SWEEP_DUST            546u

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
    BR_LEGACY_SWEEP_FEE_TOO_HIGH = 7,     // more than one input and the fee is 5% of the inputs or more
    BR_LEGACY_SWEEP_DUST_OUTPUT = 8,      // the inputs do not exceed the fee plus 546
    BR_LEGACY_SWEEP_SIGN_FAILED = 9       // an input was not signed
} BRLegacySweepResult;

typedef struct {
    size_t estSize;
    uint64_t fee;
    uint64_t totalIn;
    uint64_t outAmount;
    size_t input;              // BAD_INPUT: the input refused; otherwise SIZE_MAX
} BRLegacySweepFee;

// Fills in's amount and script from a PROVEN proof of parents[] (BRRawTxBindingCheck); 1 when it did. 0, and in
// untouched, when proof is not PROVEN, or names a parent or a script range outside what was passed.
static inline int BRLegacySweepInputFromProof(BRLegacySweepInput *in, const BRRawTxProof *proof,
                                              const BRRawTxBindingParent parents[], size_t parentCount)
{
    if (! in || ! proof || ! parents || proof->state != BR_RAW_TX_PROOF_PROVEN) return 0;
    if (proof->parent >= parentCount || ! parents[proof->parent].bytes) return 0;
    if (proof->scriptOffset > parents[proof->parent].len ||
        proof->scriptLen > parents[proof->parent].len - proof->scriptOffset) return 0;
    in->amount = (uint64_t)proof->amount;
    in->script = parents[proof->parent].bytes + proof->scriptOffset;
    in->scriptLen = proof->scriptLen;
    return 1;
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

    destScriptLen = BRAddressScriptPubKey(destScript, sizeof(destScript), destAddress);
    if (destScriptLen == 0) { r = BR_LEGACY_SWEEP_BAD_DESTINATION; goto out; }

    f.estSize = BR_LEGACY_SWEEP_BASE_BYTES + inputCount * BR_LEGACY_SWEEP_INPUT_BYTES + BR_LEGACY_SWEEP_OUTPUT_BYTES;
    f.fee = ((uint64_t)f.estSize * feePerKb) / 1000;
#if ! BR_LEGACY_SWEEP_RED_FLOOR
    if (f.fee < BR_LEGACY_SWEEP_MIN_FEE) f.fee = BR_LEGACY_SWEEP_MIN_FEE;
#endif

#if ! BR_LEGACY_SWEEP_RED_RATIO
#if BR_LEGACY_SWEEP_RED_RATIO_SINGLE
    if (inputCount > 0 &&
#else
    if (inputCount > 1 &&
#endif
#if BR_LEGACY_SWEEP_RED_RATIO_STRICT
        f.totalIn < f.fee * BR_LEGACY_SWEEP_FEE_RATIO) {
#else
        f.totalIn <= f.fee * BR_LEGACY_SWEEP_FEE_RATIO) {
#endif
        r = BR_LEGACY_SWEEP_FEE_TOO_HIGH;
        goto out;
    }
#endif

#if BR_LEGACY_SWEEP_RED_DUST
    if (f.totalIn < f.fee + BR_LEGACY_SWEEP_DUST) {
#else
    if (f.totalIn <= f.fee + BR_LEGACY_SWEEP_DUST) {
#endif
        r = BR_LEGACY_SWEEP_DUST_OUTPUT;
        goto out;
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
