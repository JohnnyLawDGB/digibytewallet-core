//
//  BRAssetSend.c
//
//  See BRAssetSend.h. The transaction is the one the Android bridge assembled (jni_asset_send.c,
//  NativeBridge_buildAndSignAssetTransferTx) from the arrays AssetManager.sendAsset writes out of a plan;
//  the checks are the core's own.
//

#include "BRAssetSend.h"
#include "BRAssetAllocate.h"   // BRAssetAllocate, BRAssetInputStack, BRAssetOutputUnits
#include "BRAssetDecode.h"     // BRAssetDecodeInstructions, BRAssetPayloadReadsExactly
#include "BRAddress.h"         // BRAddressScriptPubKey
#include "BRSpendGate.h"       // BRSpendGuardInputsUnspent, BRSignedSpendGate

#include <stdlib.h>
#include <string.h>

#ifndef BR_ASSET_TRANSFER_UNFIXED
#define BR_ASSET_TRANSFER_UNFIXED 0
#endif

#define BR_ASSET_TRANSFER_RED_SHAPE          1
#define BR_ASSET_TRANSFER_RED_ASSET          2
#define BR_ASSET_TRANSFER_RED_BOUNDS         4
#define BR_ASSET_TRANSFER_RED_CARRIER        8
#define BR_ASSET_TRANSFER_RED_CARRIER_BYTES  16
#define BR_ASSET_TRANSFER_RED_UNITS          32
#define BR_ASSET_TRANSFER_RED_FEE            64
#define BR_ASSET_TRANSFER_RED_APPROVAL       128
#define BR_ASSET_TRANSFER_RED_CONFLICTED     256
#define BR_ASSET_TRANSFER_RED_UNKNOWN        512
#define BR_ASSET_TRANSFER_RED_RECORD         1024
#define BR_ASSET_TRANSFER_RED_HELD           2048
#define BR_ASSET_TRANSFER_RED_NOT_PLAIN      4096
#define BR_ASSET_TRANSFER_RED_PRESPENT       8192
#define BR_ASSET_TRANSFER_RED_GATE           16384
#define BR_ASSET_TRANSFER_RED_DUPLICATE      32768

#define _RED(bit) (BR_ASSET_TRANSFER_UNFIXED & (bit))

// One input as it is signed: its row, and the outpoint its txid names.
typedef struct {
    const BRAssetRow *row;
    int isAsset;
    UInt256 txHash;
} _BRAssetTransferInput;

static int _hexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// A txid as the bridge read it: exactly 64 hex digits, either case, in display order, reversed into the
// parser's order. 1 or 0.
static int _txidFromDisplayHex(const char *hex, UInt256 *out)
{
    size_t i;

    if (! hex || strlen(hex) != 64) return 0;
    for (i = 0; i < 32; i++) {
        int hi = _hexDigit(hex[2 * i]), lo = _hexDigit(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) return 0;
        out->u8[31 - i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int _sameBytes(const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen)
{
    return aLen == bLen && (aLen == 0 || (a && b && memcmp(a, b, aLen) == 0));
}

// THE PLAN'S SHAPE (check 4): the outputs a plan makes, in its order, at its sats; the carrier and the source
// script within the bridge's buffers; every asset input at the source script. The index lists and the output
// count (3 or 4) were bounded by the caller.
static int _planShapeOk(const BRAssetTransferPlan *plan, const BRAssetRow *assetRows)
{
    size_t i, n = plan->outputCount;

    if (plan->opReturnLen == 0 || plan->opReturnLen > sizeof(plan->opReturnScript)) return 0;
    if (! plan->sourceScript || plan->sourceScriptLen == 0 || plan->sourceScriptLen > BR_ASSET_TRANSFER_SCRIPT_MAX)
        return 0;
#if _RED(BR_ASSET_TRANSFER_RED_SHAPE)
    (void)i; (void)n; (void)assetRows;
    return 1;
#else
    if (plan->outputs[0].role != BR_ASSET_ROLE_RECIPIENT_MARKER || plan->outputs[0].sats != BR_ASSET_MARKER_SATS) return 0;
    if (plan->outputs[1].role != BR_ASSET_ROLE_ASSET_DATA || plan->outputs[1].sats != 0) return 0;
    if (n == 4 && (plan->outputs[2].role != BR_ASSET_ROLE_DGB_CHANGE ||
                   plan->outputs[2].sats <= BR_ASSET_CHANGE_DUST_SATS || plan->outputs[2].sats > (int64_t)MAX_MONEY))
        return 0;
    if (plan->outputs[n - 1].role != BR_ASSET_ROLE_ASSET_CHANGE_MARKER || plan->outputs[n - 1].sats != BR_ASSET_MARKER_SATS)
        return 0;
    for (i = 0; i < plan->assetInputCount; i++) {
        const BRAssetRow *r = &assetRows[plan->assetInputs[i]];

        if (! _sameBytes(r->script, r->script ? r->scriptLen : 0, plan->sourceScript, plan->sourceScriptLen)) return 0;
    }
    return 1;
#endif
}

// What the asset inputs hold (check 5): units of assetId, each above 0, `quantity` or more in all. *total is
// their exact sum.
static int _assetInputsOk(const BRAssetTransferPlan *plan, const BRAssetRow *assetRows, const char *assetId,
                          int64_t quantity, int64_t *total)
{
    size_t i;

    *total = 0;
    for (i = 0; i < plan->assetInputCount; i++) {
        const BRAssetRow *r = &assetRows[plan->assetInputs[i]];

#if ! _RED(BR_ASSET_TRANSFER_RED_ASSET)
        if (! r->assetId || strcmp(r->assetId, assetId) != 0 || r->assetQuantity <= 0) return 0;
#endif
        if (! _BRAssetAllocAddExact(*total, r->assetQuantity, total)) return 0;
    }
#if _RED(BR_ASSET_TRANSFER_RED_ASSET)
    (void)assetId;
    return quantity > 0 && *total >= 0;
#else
    return quantity > 0 && *total >= quantity;
#endif
}

// One input's own fields (check 6), as the bridge needed them to build it: a txid, a vout, a script that fits
// its buffer, and sats within MAX_MONEY.
static int _inputFieldsOk(const BRAssetRow *r, UInt256 *txHash)
{
    if (! _txidFromDisplayHex(r->txid, txHash)) return 0;
    if (! r->script || r->scriptLen == 0 || r->scriptLen > BR_ASSET_TRANSFER_SCRIPT_MAX) return 0;
#if _RED(BR_ASSET_TRANSFER_RED_BOUNDS)
    return 1;
#else
    return r->vout >= 0 && r->satoshis >= 0 && r->satoshis <= (int64_t)MAX_MONEY;
#endif
}

// THE CARRIER (check 10): a version-3 TRANSFER this reader classifies, read exactly. insts[0, *count) its list.
static int _carrierReads(const BRAssetTransferPlan *plan, BRAssetHeader *h, BRAssetTransferInstruction *insts,
                         size_t *count)
{
    *count = 0;
    if (BRAssetDecodeInstructions(plan->opReturnScript, plan->opReturnLen, h, insts, BR_ASSET_MAX_INSTRUCTIONS) !=
        BR_ASSET_SCRIPT_ASSET) return 0;
    *count = h->instructionCount;
    if (h->operation != DA_TRANSFER || h->version != 3 || BRAssetHeaderHasRules(h)) return 0;
    return BRAssetPayloadReadsExactly(plan->opReturnScript, plan->opReturnLen, h, insts, *count);
}

// WHERE THE UNITS LAND (check 11): exactly `quantity` of assetId on output 0, and the rest (when there is any)
// on the last output, nothing anywhere else, nothing voided. -1 when the working space cannot be allocated.
static int _unitsLandOk(const BRAssetHeader *h, const BRAssetTransferInstruction *insts, size_t instCount,
                        const _BRAssetTransferInput *inputs, size_t inCount, size_t assetInputCount,
                        int32_t outputCount, const char *assetId, int64_t quantity, int64_t change)
{
    BRAssetInputStack *stacks = calloc(inCount, sizeof(*stacks));
    BRAssetUnits *units = calloc(assetInputCount, sizeof(*units));
    int64_t *work = calloc(assetInputCount, sizeof(*work));
    size_t outCap = assetInputCount * (size_t)outputCount + instCount, i, found = 0;
    BRAssetOutputUnits *out = calloc(outCap, sizeof(*out));
    BRAssetAllocation a;
    int ok = 1;

    if (! stacks || ! units || ! work || ! out) { ok = -1; goto done; }
    for (i = 0; i < inCount; i++) {
        stacks[i].known = 1;
        if (i < assetInputCount) {
            units[i].assetId = assetId;
            units[i].count = inputs[i].row->assetQuantity;
            units[i].ruleFree = 1;   // the plan's choice asked the gate: its rule state is NONE
            stacks[i].units = &units[i];
            stacks[i].unitCount = 1;
        }
    }
    a = BRAssetAllocate(h, insts, instCount, 1, stacks, inCount, outputCount, work, assetInputCount, out, outCap);
    // Undecided, it answers no entry (count 0); decided, each entry is one output's units of one asset (summed),
    // so the landings below are each found once or the set is not the plan's.
    for (i = 0; ok && i < a.count; i++) {
        int mine = out[i].assetId != NULL && strcmp(out[i].assetId, assetId) == 0;

        if (mine && out[i].vout == 0 && out[i].count == quantity) found |= 1;
        else if (mine && out[i].vout == outputCount - 1 && change > 0 && out[i].count == change) found |= 2;
        else ok = 0;
    }
    if (a.status != BR_ASSET_ALLOCATION_ALLOCATED || a.instructionsVoided || a.count != (change > 0 ? 2u : 1u) ||
        found != (change > 0 ? 3u : 1u)) ok = 0;

done:
    free(out);
    free(work);
    free(units);
    free(stacks);
    return ok;
}

// THE PLAN'S INSTRUCTIONS (check 12): the carrier reads exactly as the list the plan's rule gives, and is that
// list's encoding byte for byte.
static int _carrierIsThePlans(const BRAssetTransferPlan *plan, const BRAssetRow *assetRows, int64_t quantity,
                              int64_t change, const BRAssetHeader *h)
{
    BRAssetTransferPlan expected;
    BRAssetHeader eh;
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];
    size_t count;

    memset(&expected, 0, sizeof(expected));
    if (! _BRAssetPlanInstructions(assetRows, plan->assetInputs, plan->assetInputCount, quantity, change, 0,
                                   (int32_t)plan->outputCount - 1, &expected)) return 0;
    if (BRAssetDecodeInstructions(expected.opReturnScript, expected.opReturnLen, &eh, insts, BR_ASSET_MAX_INSTRUCTIONS) !=
        BR_ASSET_SCRIPT_ASSET) return 0;
    count = eh.instructionCount;
    if (! BRAssetPayloadReadsExactly(plan->opReturnScript, plan->opReturnLen, h, insts, count)) return 0;
#if _RED(BR_ASSET_TRANSFER_RED_CARRIER_BYTES)
    return 1;
#else
    return _sameBytes(plan->opReturnScript, plan->opReturnLen, expected.opReturnScript, expected.opReturnLen);
#endif
}

static int _inHeld(const BRUTXO *held, size_t heldCount, UInt256 txHash, uint32_t n)
{
    size_t i;

    for (i = 0; i < heldCount; i++) {
        if (held[i].n == n && UInt256Eq(held[i].hash, txHash)) return 1;
    }
    return 0;
}

// Check 15 for one input; BR_ASSET_TRANSFER_SIGNED when it passes. plain[0, plainCount) the wallet's plain
// spendable coins.
static BRAssetTransferStatus _walletHoldsInput(BRWallet *wallet, const _BRAssetTransferInput *in,
                                               const BRUTXO *held, size_t heldCount,
                                               const BRUTXO *plain, size_t plainCount)
{
    uint32_t n = (uint32_t)in->row->vout;
    BRTransaction *funding;
    int state = BRWalletOutpointAssetState(wallet, in->txHash, n), ok;
    size_t i;

#if ! _RED(BR_ASSET_TRANSFER_RED_PRESPENT)
    if (state == 0) return BR_ASSET_TRANSFER_INPUT_SPENT;
#endif
#if ! _RED(BR_ASSET_TRANSFER_RED_CONFLICTED)
    if (state == -2) return BR_ASSET_TRANSFER_INPUT_CONFLICTED;
#endif
    funding = BRWalletCopyTransactionForHash(wallet, in->txHash);
#if _RED(BR_ASSET_TRANSFER_RED_UNKNOWN)
    if (! funding || n >= funding->outCount) {
        if (funding) BRTransactionFree(funding);
        funding = NULL;
    }
#else
    if (! funding || n >= funding->outCount) {
        if (funding) BRTransactionFree(funding);
        return BR_ASSET_TRANSFER_INPUT_UNKNOWN;
    }
#endif
    if (funding) {
        ok = funding->outputs[n].amount == (uint64_t)in->row->satoshis &&
             _sameBytes(funding->outputs[n].script, funding->outputs[n].scriptLen, in->row->script, in->row->scriptLen);
        BRTransactionFree(funding);
#if ! _RED(BR_ASSET_TRANSFER_RED_RECORD)
        if (! ok) return BR_ASSET_TRANSFER_INPUT_MISMATCH;
#else
        (void)ok;
#endif
    }
    if (in->isAsset) return BR_ASSET_TRANSFER_SIGNED;

#if ! _RED(BR_ASSET_TRANSFER_RED_HELD)
    if (_inHeld(held, heldCount, in->txHash, n)) return BR_ASSET_TRANSFER_INPUT_HELD;
#else
    (void)held; (void)heldCount;
#endif
#if ! _RED(BR_ASSET_TRANSFER_RED_NOT_PLAIN)
    for (i = 0; i < plainCount; i++) {
        if (plain[i].n == n && UInt256Eq(plain[i].hash, in->txHash)) break;
    }
    if (i == plainCount) return BR_ASSET_TRANSFER_FEE_COIN_NOT_PLAIN;
#else
    (void)i; (void)plain; (void)plainCount;
#endif
    return BR_ASSET_TRANSFER_SIGNED;
}

BRAssetTransferStatus BRWalletBuildAssetTransfer(BRTransaction **txOut, BRWallet *wallet,
                                                 const BRAssetSendOutcome *outcome,
                                                 const BRAssetRow *assetRows, size_t assetCount,
                                                 const BRAssetRow *dgbRows, size_t dgbCount,
                                                 const char *assetId, int64_t quantity,
                                                 const char *recipientAddress, int64_t approvedFeeSats,
                                                 const BRUTXO *held, size_t heldCount,
                                                 const void *seed, size_t seedLen, double now,
                                                 BRAssetTransferReport *report)
{
    BRAssetTransferReport rep = { SIZE_MAX, 0 };
    BRAssetTransferStatus r = BR_ASSET_TRANSFER_SIGNED;
    const BRAssetTransferPlan *plan;
    _BRAssetTransferInput *inputs = NULL;
    BRTransaction *tx = NULL;
    BRUTXO *plain = NULL;
    BRAssetHeader h;
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];
    uint8_t recipientScript[BR_ASSET_TRANSFER_SCRIPT_MAX];
    size_t recipientLen, inCount, instCount = 0, plainCount = 0, i, j;
    int64_t assetTotal = 0, change, totalIn = 0, totalOut = 0;

    if (txOut) *txOut = NULL;
    memset(&h, 0, sizeof(h));
    if (! txOut || ! wallet || ! outcome || ! assetId || ! recipientAddress || ! seed ||
        (assetCount > 0 && ! assetRows) || (dgbCount > 0 && ! dgbRows) || (heldCount > 0 && ! held)) {
        r = BR_ASSET_TRANSFER_BAD_ARGUMENT;
        goto out;
    }
    plan = &outcome->plan;
    if (outcome->kind != BR_ASSET_SEND_PLANNED || plan->status != BR_ASSET_PLAN_READY) {
        r = BR_ASSET_TRANSFER_NOT_PLANNED;
        goto out;
    }
    if (seedLen == 0 || seedLen > BR_ASSET_TRANSFER_SEED_MAX) { r = BR_ASSET_TRANSFER_BAD_SEED; goto out; }

    // 4. The index lists stay within their rows whatever the arm: past them is memory, not a check.
    if (plan->assetInputCount == 0 || ! plan->assetInputs || (plan->dgbInputCount > 0 && ! plan->dgbInputs) ||
        plan->outputCount < 3 || plan->outputCount > BR_ASSET_PLAN_MAX_OUTPUTS ||
        plan->dgbInputCount > SIZE_MAX / sizeof(*inputs) - plan->assetInputCount) {
        r = BR_ASSET_TRANSFER_PLAN_SHAPE;
        goto out;
    }
    for (i = 0; i < plan->assetInputCount; i++) {
        if (plan->assetInputs[i] >= assetCount) { r = BR_ASSET_TRANSFER_PLAN_SHAPE; goto out; }
    }
    for (i = 0; i < plan->dgbInputCount; i++) {
        if (plan->dgbInputs[i] >= dgbCount) { r = BR_ASSET_TRANSFER_PLAN_SHAPE; goto out; }
    }
    if (! _planShapeOk(plan, assetRows)) { r = BR_ASSET_TRANSFER_PLAN_SHAPE; goto out; }

    // 5.
    if (! _assetInputsOk(plan, assetRows, assetId, quantity, &assetTotal)) { r = BR_ASSET_TRANSFER_WRONG_ASSET; goto out; }
    change = assetTotal - quantity;

    // 6. In signing order: the asset inputs, then the fee inputs.
    inCount = plan->assetInputCount + plan->dgbInputCount;
    inputs = calloc(inCount, sizeof(*inputs));
    if (! inputs) { r = BR_ASSET_TRANSFER_NO_MEMORY; goto out; }
    for (i = 0; i < inCount; i++) {
        inputs[i].isAsset = i < plan->assetInputCount;
        inputs[i].row = inputs[i].isAsset ? &assetRows[plan->assetInputs[i]]
                                          : &dgbRows[plan->dgbInputs[i - plan->assetInputCount]];
        if (! _inputFieldsOk(inputs[i].row, &inputs[i].txHash)) {
            rep.input = i;
            r = BR_ASSET_TRANSFER_BAD_INPUT;
            goto out;
        }
#if ! _RED(BR_ASSET_TRANSFER_RED_BOUNDS)
        // totalIn <= MAX_MONEY here, so neither the difference nor the sum wraps.
        if (inputs[i].row->satoshis > (int64_t)MAX_MONEY - totalIn) {
            rep.input = i;
            r = BR_ASSET_TRANSFER_BAD_INPUT;
            goto out;
        }
#endif
        totalIn = (int64_t)((uint64_t)totalIn + (uint64_t)inputs[i].row->satoshis);
    }

    // 7.
#if ! _RED(BR_ASSET_TRANSFER_RED_DUPLICATE)
    for (i = 0; i < inCount; i++) {
        for (j = i + 1; j < inCount; j++) {
            if (inputs[i].row->vout == inputs[j].row->vout && UInt256Eq(inputs[i].txHash, inputs[j].txHash)) {
                r = BR_ASSET_TRANSFER_DUPLICATE_INPUT;
                goto out;
            }
        }
    }
#else
    (void)j;
#endif

    // 8.
    recipientLen = BRAddressScriptPubKey(recipientScript, sizeof(recipientScript), recipientAddress);
    if (recipientLen == 0) { r = BR_ASSET_TRANSFER_BAD_RECIPIENT; goto out; }

    // 9. The transaction, in the bridge's order.
    tx = BRTransactionNew();
    if (! tx) { r = BR_ASSET_TRANSFER_NO_MEMORY; goto out; }
    for (i = 0; i < inCount; i++) {
        const BRAssetRow *row = inputs[i].row;

        BRTransactionAddInput(tx, inputs[i].txHash, (uint32_t)row->vout, (uint64_t)row->satoshis, row->script,
                              row->scriptLen, NULL, 0, NULL, 0, TXIN_SEQUENCE);
    }
    for (i = 0; i < plan->outputCount; i++) {
        const BRAssetPlannedOutput *o = &plan->outputs[i];

        if (o->role == BR_ASSET_ROLE_RECIPIENT_MARKER)
            BRTransactionAddOutput(tx, (uint64_t)o->sats, recipientScript, recipientLen);
        else if (o->role == BR_ASSET_ROLE_ASSET_DATA)
            BRTransactionAddOutput(tx, (uint64_t)o->sats, plan->opReturnScript, plan->opReturnLen);
        else
            BRTransactionAddOutput(tx, (uint64_t)o->sats, plan->sourceScript, plan->sourceScriptLen);
        totalOut = (int64_t)((uint64_t)totalOut + (uint64_t)o->sats);
    }

    // 10, 11, 12.
#if ! _RED(BR_ASSET_TRANSFER_RED_CARRIER)
    if (! _carrierReads(plan, &h, insts, &instCount)) { r = BR_ASSET_TRANSFER_CARRIER_MISMATCH; goto out; }
#else
    if (BRAssetDecodeInstructions(plan->opReturnScript, plan->opReturnLen, &h, insts, BR_ASSET_MAX_INSTRUCTIONS) ==
        BR_ASSET_SCRIPT_ASSET) instCount = h.instructionCount;
#endif
#if ! _RED(BR_ASSET_TRANSFER_RED_UNITS)
    {
        int landed = _unitsLandOk(&h, insts, instCount, inputs, inCount, plan->assetInputCount,
                                  (int32_t)plan->outputCount, assetId, quantity, change);

        if (landed < 0) { r = BR_ASSET_TRANSFER_NO_MEMORY; goto out; }
        if (! landed) { r = BR_ASSET_TRANSFER_UNITS_MISPLACED; goto out; }
    }
#endif
#if ! _RED(BR_ASSET_TRANSFER_RED_CARRIER)
    if (! _carrierIsThePlans(plan, assetRows, quantity, change, &h)) { r = BR_ASSET_TRANSFER_CARRIER_MISMATCH; goto out; }
#endif

    // 13, 14. Every output's sats is at most MAX_MONEY (4) and there are at most four, so the sum fits.
    rep.paidFeeSats = (int64_t)((uint64_t)totalIn - (uint64_t)totalOut);
#if ! _RED(BR_ASSET_TRANSFER_RED_FEE)
    if (rep.paidFeeSats != plan->paidFeeSats) { r = BR_ASSET_TRANSFER_FEE_MISMATCH; goto out; }
#endif
#if ! _RED(BR_ASSET_TRANSFER_RED_APPROVAL)
    if (! BRAssetFeeWithinApproval(rep.paidFeeSats, approvedFeeSats)) { r = BR_ASSET_TRANSFER_FEE_NOT_APPROVED; goto out; }
#else
    (void)approvedFeeSats;
#endif

    // 15. The wallet's plain spendable coins, read once under its lock.
    if (plan->dgbInputCount > 0) {
        plainCount = BRWalletSelectableUTXOs(wallet, NULL, 0);
        plain = calloc(plainCount ? plainCount : 1, sizeof(*plain));
        if (! plain) { r = BR_ASSET_TRANSFER_NO_MEMORY; goto out; }
        plainCount = BRWalletSelectableUTXOs(wallet, plain, plainCount);
    }
    for (i = 0; i < inCount; i++) {
        r = _walletHoldsInput(wallet, &inputs[i], held, heldCount, plain, plainCount);
        if (r != BR_ASSET_TRANSFER_SIGNED) { rep.input = i; goto out; }
    }

    // 16, 17, 18: the DGB send's order (spent check, sign, claim, spent check again).
#if ! _RED(BR_ASSET_TRANSFER_RED_PRESPENT)
    if (! BRSpendGuardInputsUnspent(wallet, tx)) { r = BR_ASSET_TRANSFER_INPUT_SPENT; goto out; }
#endif
    if (! BRWalletSignTransaction(wallet, tx, 0, seed, seedLen) || ! BRTransactionIsSigned(tx)) {
        r = BR_ASSET_TRANSFER_SIGN_FAILED;
        goto out;
    }
#if ! _RED(BR_ASSET_TRANSFER_RED_GATE)
    if (! BRSignedSpendGate(wallet, tx, now)) { r = BR_ASSET_TRANSFER_GATE_REFUSED; goto out; }
#else
    (void)now;
#endif

    *txOut = tx;
    tx = NULL;

out:
    if (tx) BRTransactionFree(tx);
    free(plain);
    free(inputs);
    if (report) *report = rep;
    return r;
}
