//
//  BRAssetSend.h
//
//  The DigiAsset transfer builder and signer: one transaction from the plan BRAssetSendChoose made
//  (BRAssetSendPlan.h), signed with the wallet's own keys and passed through the spend gate
//  (BRSpendGate.h) before it may leave. Moved from the Android JNI bridge (jni_asset_send.c,
//  NativeBridge_buildAndSignAssetTransferTx), which assembles the same transaction from the arrays its
//  Kotlin caller (AssetManager.sendAsset) writes out of a plan: for every plan both sign, they sign the
//  same bytes. The bridge's JNI handling (arrays, strings, hex, logging) stays on the platform side, and
//  so does the serialization. The core does not take its caller's word for the plan: it re-checks what it
//  signs (THE CHECKS below), and each refusal is a status, never a transaction with something changed.
//
//  BRWalletBuildAssetTransfer(&tx, wallet, ruleState, outcome, assetRows, assetCount, dgbRows, dgbCount,
//                             assetId, quantity, recipientAddress, approvedFeeSats, held, heldCount, seed,
//                             seedLen, now, &report)
//
//  THE TRANSACTION, in the bridge's order, for a plan that passes every check:
//    inputs   plan.assetInputs (assetRows) in order, then plan.dgbInputs (dgbRows) in order; each its
//             row's outpoint (the txid's 64 display-order hex digits, either case, reversed into the
//             parser's order), satoshis and script, no signature or witness, TXIN_SEQUENCE.
//    outputs  plan.outputs in order: the recipient marker pays BRAddressScriptPubKey(recipientAddress);
//             the carrier pays plan.opReturnScript; the DGB change and the last marker pay
//             plan.sourceScript; each at its plan sats.
//    signing  BRSpendGuardInputsUnspent, BRWalletSignTransaction(wallet, tx, 0, seed, seedLen) with every
//             input signed (BRTransactionIsSigned), then BRSignedSpendGate(wallet, tx, now): the order
//             of the bridge's seed_sign_transaction, the signer every Android DGB send goes through
//             (spent check, sign, claim, spent check again). On SIGNED the claim is held for tx->txHash
//             until the publish releases it (BRWalletSend.h step 1b).
//
//  THE CHECKS, in this order; the first that fails is the status, *txOut is NULL, nothing is claimed
//  and nothing is left allocated:
//    1. txOut, wallet, outcome, assetId, recipientAddress or seed NULL; assetRows NULL with assetCount
//       above 0, dgbRows with dgbCount, held with heldCount                              -> BAD_ARGUMENT
//    2. ruleState does not allow a send (BRAssetRuleAllowsSend: only NONE; BOUND, UNKNOWN and any value
//       BRSweepRuleState does not define do not)                                         -> RULE_STATE
//       the outcome is not BR_ASSET_SEND_PLANNED, or its plan is not BR_ASSET_PLAN_READY  -> NOT_PLANNED
//       BRAssetSendOutcome is a plain struct: a caller can fill one in, keep a stale one, or keep one made
//       for another rule state, so a PLANNED kind and a READY status say nothing of where the plan came
//       from. Everything below is checked again here, and the rule state is asked again, as
//       BRAssetSendChoose asks it itself: ruleState is the asset's state read at this call (the same
//       BRAssetRuleStateForAsset reading the choice is given). A transfer that breaks an asset's rules
//       loses the whole input holding (BRAssetRuleGate.h), so a wrong NONE is the costly answer.
//    3. seedLen 0 or above BR_ASSET_TRANSFER_SEED_MAX (64)                                -> BAD_SEED
//    4. THE PLAN'S SHAPE: no asset input; an index list NULL where it has entries; an index outside
//       its rows; outputs other than [recipient marker, carrier, (DGB change), last marker]; a marker
//       of other than BR_ASSET_MARKER_SATS, a carrier of other than 0 sats, a DGB change at or below
//       BR_ASSET_CHANGE_DUST_SATS or above MAX_MONEY; a carrier of 0 bytes or more than
//       BR_ASSET_ENCODE_MAX_SCRIPT; a source script NULL, empty or above BR_ASSET_TRANSFER_SCRIPT_MAX;
//       an asset input whose script is not the source script                            -> PLAN_SHAPE
//    5. quantity not above 0; an asset input whose row is not of assetId (byte for byte) or holds no
//       units; the asset inputs' units, summed exactly, below quantity or past INT64_MAX -> WRONG_ASSET
//    6. per input, in signing order (report->input): a txid that is not 64 hex digits; a vout below 0;
//       a script NULL, empty or above BR_ASSET_TRANSFER_SCRIPT_MAX (256, the bridge's buffer); satoshis
//       below 0 or above MAX_MONEY, or a running total above MAX_MONEY                    -> BAD_INPUT
//    7. two inputs naming one outpoint (the bridge's tx_inputs_distinct)                  -> DUPLICATE_INPUT
//    8. BRAddressScriptPubKey(recipientAddress) into 256 bytes is 0 (an address with whitespace
//       around it is not an address)                                                     -> BAD_RECIPIENT
//    9. the transaction cannot be allocated                                              -> NO_MEMORY
//   10. THE CARRIER (BRAssetDecode.h): it is not a version-3 TRANSFER this reader classifies, or it does
//       not read exactly (BRAssetPayloadReadsExactly over the list it decodes to)       -> CARRIER_MISMATCH
//   11. WHERE THE UNITS LAND (BRAssetAllocate over the decoded list, the asset inputs each carrying its
//       row's units of assetId, rule-free only as BRAssetRuleAllowsSend(ruleState) says, and every fee
//       input nothing, and the transaction's output count): not
//       ALLOCATED, instructions voided, or anything but exactly `quantity` of assetId on output 0 and,
//       when the asset inputs hold more, exactly the rest on the LAST output (the implicit change; no
//       entry there when they hold exactly `quantity`)                                   -> UNITS_MISPLACED
//   12. THE PLAN'S INSTRUCTIONS: the carrier does not read exactly as the instructions the plan's rule
//       gives for these asset inputs, `quantity` and that change (BRAssetSendPlan.h, THE INSTRUCTIONS,
//       the change to the last output), or its bytes are not that list's encoding           -> CARRIER_MISMATCH
//   13. every input's sats less every output's is not plan.paidFeeSats; or the plan's own fee rule does
//       not hold of it: plan.estimatedFeeSats not above 0, or paidFeeSats not the estimate plus
//       0..BR_ASSET_CHANGE_DUST_SATS (BRAssetSendPlan.h, THE PLAN: change above the dust line is an output,
//       never fee)                                                                          -> FEE_MISMATCH
//   14. BRAssetFeeWithinApproval(paid, approvedFeeSats) is 0 (above what the person saw)   -> FEE_NOT_APPROVED
//   15. per input, in signing order (report->input), by the wallet (asset inputs and fee inputs alike): the outpoint is spent
//       (BRWalletOutpointAssetState 0)                                                    -> INPUT_SPENT
//       its funding transaction is held as invalid (-2: a send that was replaced)         -> INPUT_CONFLICTED
//       the wallet holds no funding transaction (-1), or none with that output index       -> INPUT_UNKNOWN
//       the output's amount or script is not the row's                                    -> INPUT_MISMATCH
//       a fee input in held[0, heldCount)                                                 -> INPUT_HELD
//       a fee input that is not one of the wallet's plain spendable coins
//       (BRWalletSelectableUTXOs), or that the planner's fee-coin rule does not admit
//       (BRAssetFeeCoinEligible against plan.sourceScript, the funding transaction's data output read
//       here: an output whose script starts with OP_RETURN, 0x6a)                         -> FEE_COIN_NOT_PLAIN
//   16. BRSpendGuardInputsUnspent is 0 (a send registered since 15)                       -> INPUT_SPENT
//   17. BRWalletSignTransaction fails, or an input is left unsigned                       -> SIGN_FAILED
//   18. BRSignedSpendGate refuses (a coin spent meanwhile, or claimed for another send)    -> GATE_REFUSED
//   19. SIGNED: *txOut is the signed transaction; the caller frees it (BRTransactionFree).
//
//  HELD. held[0, heldCount) is what a COMPLETE BRWalletHoldAssetOutputs (or BRAssetHoldOutputs over the
//  wallet's view) answered, run after the last transaction was added or removed and before this call
//  (BRAssetHold.h). An asset input may be held (an asset coin is); a fee input may not. Units of any
//  asset can sit on a held output, so a fee input there would burn them.
//
//  quantity, assetId, recipientAddress and approvedFeeSats are the approval the person confirmed: the
//  units sent, the asset, the address (already without surrounding whitespace) and the highest fee they
//  saw. A plan for anything else is refused (5, 8, 11, 14), so what is signed is what was approved. The
//  approval is the caller's to give as the figure the person saw: the higher the approval, the less it
//  limits, and check 13 does not limit the rate (the outcome does not carry the rate it was planned at).
//  A caller passes the fee the person was shown, never a placeholder.
//
//  KEYS. seed is read, never written or copied. The keys are derived and wiped inside
//  BRWalletSignTransaction (BRKeyClean, every path). Nothing here draws a random number or reads a
//  clock: `now` is the caller's, on the one monotonic clock every caller of BRCoinReservation.h uses.
//
//  ARITHMETIC. Satoshis are int64_t, as the rows hold them; every amount and the running sums are at most
//  MAX_MONEY (6, 4), so no sum wraps and every amount casts to the uint64_t the transaction holds as it
//  is. A vout below 0 or an amount out of that range is refused rather than cast.
//
//  report (optional), written on every path: the input refused, in signing order (checks 6 and 15;
//  SIZE_MAX otherwise), and the fee the transaction would pay (from check 13 on; 0 before).
//
//  NETWORK. BRAddressScriptPubKey follows BRNetworkIsTestnet() at the call.
//
//  Comparison arms for the host KAT only (asset_send_kat in the Android repo): BR_ASSET_TRANSFER_UNFIXED,
//  tested by VALUE as a set of bits, read in BRAssetSend.c; each arm sets one bit and fails only its own
//  cases. Unset or =0 is what ships.
//    1      BR_ASSET_TRANSFER_RED_SHAPE        the plan's outputs and source script are not checked (4).
//    2      BR_ASSET_TRANSFER_RED_ASSET        the asset inputs' asset and units are not checked (5).
//    4      BR_ASSET_TRANSFER_RED_BOUNDS       a negative vout and out-of-range sats are cast, unchecked (6).
//    8      BR_ASSET_TRANSFER_RED_CARRIER      the carrier is neither decoded nor compared (10, 12).
//    16     BR_ASSET_TRANSFER_RED_CARRIER_BYTES the carrier's bytes are not compared, only its reading (12).
//    32     BR_ASSET_TRANSFER_RED_UNITS        where the units land is not checked (11).
//    64     BR_ASSET_TRANSFER_RED_FEE          the fee paid is not compared with the plan's, nor held to the plan's fee rule (13).
//    128    BR_ASSET_TRANSFER_RED_APPROVAL     the fee is not held to the approval (14).
//    256    BR_ASSET_TRANSFER_RED_CONFLICTED   an input from a replaced send is signed (15).
//    512    BR_ASSET_TRANSFER_RED_UNKNOWN      an input the wallet holds no transaction for is signed (15).
//    1024   BR_ASSET_TRANSFER_RED_RECORD       an input's amount and script are not compared with the wallet's (15).
//    2048   BR_ASSET_TRANSFER_RED_HELD         a held fee input is signed (15).
//    4096   BR_ASSET_TRANSFER_RED_NOT_PLAIN    a fee input outside the plain spendable coins, or outside the planner's fee-coin rule, is signed (15).
//    8192   BR_ASSET_TRANSFER_RED_PRESPENT     a spent input is not refused before signing (15, 16).
//    16384  BR_ASSET_TRANSFER_RED_GATE         the signed transaction does not pass the spend gate (18).
//    32768  BR_ASSET_TRANSFER_RED_DUPLICATE    two inputs naming one outpoint are not refused (7).
//    65536  BR_ASSET_TRANSFER_RED_RULES        the rule state is not asked (2), and the allocator is told
//                                              the units are rule-free whatever it is (11).
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

#ifndef BRAssetSend_h
#define BRAssetSend_h

#include "BRAssetSendPlan.h"   // BRAssetSendOutcome, BRAssetTransferPlan, BRAssetRow; BRSweepRuleState
#include "BRTransaction.h"     // BRTransaction
#include "BRWallet.h"          // BRWallet, BRUTXO
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_ASSET_TRANSFER_SEED_MAX   64u    // a BIP39 seed: the bridge's g_seed
#define BR_ASSET_TRANSFER_SCRIPT_MAX 256u   // the bridge's script buffers, input and output

typedef enum {
    BR_ASSET_TRANSFER_SIGNED = 0,
    BR_ASSET_TRANSFER_BAD_ARGUMENT = 1,        // a required pointer was NULL
    BR_ASSET_TRANSFER_NOT_PLANNED = 2,         // not a PLANNED outcome with a READY plan
    BR_ASSET_TRANSFER_BAD_SEED = 3,            // seedLen 0 or above 64
    BR_ASSET_TRANSFER_NO_MEMORY = 4,
    BR_ASSET_TRANSFER_PLAN_SHAPE = 5,          // the plan's inputs, outputs or source script are not a plan's
    BR_ASSET_TRANSFER_WRONG_ASSET = 6,         // the asset inputs are not `quantity` or more units of assetId
    BR_ASSET_TRANSFER_BAD_INPUT = 7,           // an input's txid, vout, script or sats
    BR_ASSET_TRANSFER_DUPLICATE_INPUT = 8,     // two inputs name one outpoint
    BR_ASSET_TRANSFER_BAD_RECIPIENT = 9,       // the recipient is not an address
    BR_ASSET_TRANSFER_CARRIER_MISMATCH = 10,   // the carrier is not exactly the plan's instructions
    BR_ASSET_TRANSFER_UNITS_MISPLACED = 11,    // the units would not land on the recipient and the last output
    BR_ASSET_TRANSFER_FEE_MISMATCH = 12,       // the transaction pays another fee than the plan's
    BR_ASSET_TRANSFER_FEE_NOT_APPROVED = 13,   // the fee is above the approval
    BR_ASSET_TRANSFER_INPUT_SPENT = 14,        // an input the wallet holds as spent
    BR_ASSET_TRANSFER_INPUT_CONFLICTED = 15,   // an input of a send that was replaced
    BR_ASSET_TRANSFER_INPUT_UNKNOWN = 16,      // an input the wallet holds no transaction or output for
    BR_ASSET_TRANSFER_INPUT_MISMATCH = 17,     // an input whose amount or script is not the wallet's record
    BR_ASSET_TRANSFER_INPUT_HELD = 18,         // a fee input the hold holds
    BR_ASSET_TRANSFER_FEE_COIN_NOT_PLAIN = 19, // a fee input not among the wallet's plain spendable coins, or not
                                               // a fee coin by the planner's rule (BRAssetFeeCoinEligible)
    BR_ASSET_TRANSFER_SIGN_FAILED = 20,        // an input was not signed
    BR_ASSET_TRANSFER_GATE_REFUSED = 21,       // the spend gate refused the signed transaction
    BR_ASSET_TRANSFER_RULE_STATE = 22          // the asset's transfer-rule state does not allow a send
} BRAssetTransferStatus;

typedef struct {
    size_t input;              // BAD_INPUT and the wallet's checks: the input refused, in signing order; else SIZE_MAX
    int64_t paidFeeSats;       // from the fee check on: every input's sats less every output's; else 0
} BRAssetTransferReport;

// Builds and signs the transfer `outcome` plans (see THE TRANSACTION and THE CHECKS). assetRows and dgbRows are
// the rows the outcome's choice was given, and the `work` buffer that choice wrote must still hold the plan's
// index lists; the rows' txid, script and asset id strings stay the caller's.
BRAssetTransferStatus BRWalletBuildAssetTransfer(BRTransaction **txOut, BRWallet *wallet,
                                                 BRSweepRuleState ruleState, const BRAssetSendOutcome *outcome,
                                                 const BRAssetRow *assetRows, size_t assetCount,
                                                 const BRAssetRow *dgbRows, size_t dgbCount,
                                                 const char *assetId, int64_t quantity,
                                                 const char *recipientAddress, int64_t approvedFeeSats,
                                                 const BRUTXO *held, size_t heldCount,
                                                 const void *seed, size_t seedLen, double now,
                                                 BRAssetTransferReport *report);

#ifdef __cplusplus
}
#endif

#endif // BRAssetSend_h
