//
//  BRAssetSendPlan.h
//
//  What a DigiAsset send spends and what it pays, decided before anything is built: the coin selector,
//  the transfer planner, the size-aware fee, the check of each asset input against an indexer, the
//  choice among the wallet's coins and its outcomes, and the reading of a typed quantity. Until 2026-11
//  these rules were written only in Kotlin, in the Android repository (core/.../asset/send/
//  AssetCoinSelector.kt, AssetFeeEstimator.kt, AssetInputCheck.kt, AssetSendSelection.kt,
//  AssetTransferPlan.kt; core/.../model/AssetQuantity.kt; and in AssetManager.kt the rule check and
//  argument checks of planAssetTransfer). They move here unchanged: every input the Kotlin answers gets
//  the same answer here, and every input it refuses is refused here, for the same reason. THE ORDER in
//  which coins are taken is part of the rule: both apps must take the same coins for the same wallet.
//
//  THE RULES:
//    - THE GATE (BRAssetSendGate), before anything else: only an asset whose transfer-rule state is NONE
//      may be sent (BRAssetRuleAllowsSend, BRAssetRuleGate.h). BOUND is refused as RULE_BOUND, UNKNOWN
//      (and any value BRSweepRuleState does not define) as RULES_UNKNOWN. BRAssetSendChoose asks it again
//      first, so no plan is made for an asset the gate refuses. BRAssetSendChoose is the only public way
//      to a plan: the planner itself (_BRAssetPlan, _BRAssetPlanTransfer) asks no gate, carries a leading
//      underscore, and is called only behind the gate (the host KAT's source gate holds every public
//      function here that plans, or answers or writes a plan, to asking it first).
//    - AN OUTPOINT is a row's txid, ASCII letters' case ignored, and its vout (a NULL txid reads as
//      empty; C only). Scripts are bytes.
//    - THE FEE (BRAssetFeeEstimate): vsize = 12 + (assetInputs + dgbInputs + 1) * 150 + outputs * 34 + 9
//      + opReturnBytes, each count below zero read as zero (the + 1 is a margin for one more fee input);
//      fee = max(ceil(vsize * rate / 1000), ceil(vsize * 100,000 / 1000)), the rate in sat/kB read as 0
//      when negative. The floor is DigiByte's minimum relay fee (MIN_FEE_PER_KB, BRWallet.h). No fee
//      (0) when vsize * rate is past the int64 range (C only; Kotlin wraps).
//    - THE COIN SELECTOR (BRAssetCoinSelect). Refused when assetNeeded is not above 0 or a fee or marker
//      amount is below 0 (Kotlin: require). THE ORDER: the asset coins by asset quantity, largest first,
//      coins of equal quantity in the order given (a stable sort); taken while their sum, which stops at
//      the int64 range's ends, is below assetNeeded. Not enough: INSUFFICIENT_ASSET (assetNeeded, that
//      sum). The asset change is the sum less assetNeeded. The markers emitted are markerOutputSats, and
//      assetChangeMarkerSats too when the change is above 0. The plain DGB needed is fee + markers less
//      the sats of the asset coins taken, or 0. The fee coins are the plain coins whose outpoint is not
//      the outpoint of any asset coin given, each outpoint once (the first given), ordered by sats,
//      largest first, equal ones in the order given; taken, when DGB is needed, while their sum is below
//      it. Not enough: INSUFFICIENT_DGB (needed, that sum). The DGB change is every sat taken less the
//      fee and the markers.
//    - THE PLAN (_BRAssetPlanTransfer), from asset coins that must all pay one script (the source) and
//      fee coins already limited to eligible ones. Refused: no asset coin; coins at more than one script;
//      a quantity not above 0 (ARGUMENTS; Kotlin: the selector's require throws).
//      Two markers of BR_ASSET_MARKER_SATS are budgeted on every send. A first selection is made at the
//      fee of one asset input, one fee input, three outputs and an 80-byte carrier; its instructions are
//      built (THE INSTRUCTIONS, the change to output 3) and their script's length is the carrier length
//      from then on. Then, at most (fee coins + 2) times: the fee is estimated for the first selection's
//      asset inputs, the fee inputs last counted and three outputs; the coins are selected again at that
//      fee; when that takes no more fee inputs than were counted the loop ends, else the count is taken.
//      A refusal of either selection refuses the plan (NOT_ENOUGH_ASSET, NOT_ENOUGH_DGB). The outputs,
//      in the order signed: the recipient's marker (vout 0, which the instructions credit), the carrier
//      (0 sats), the DGB change to the source when it is above BR_ASSET_CHANGE_DUST_SATS, and LAST a
//      marker to the source, on every send: the protocol gives every unit the instructions do not assign
//      to the last output, so such units stay where they were. The instructions are built again with the
//      change to the last vout; a script of another length is refused. The fee paid (every input's sats
//      less every output's) must be the estimate plus 0..BR_ASSET_CHANGE_DUST_SATS, or it is refused
//      (FEE_MISMATCH).
//    - THE INSTRUCTIONS: refused when the asset inputs' quantities, summed exactly, are not the quantity
//      sent plus the change. Each input in order gives, while it has units, first to the recipient
//      (output 0) until the quantity is met, then to the change until it is met; after every input but
//      the last, the last instruction written so far gets the skip flag. They are encoded at version 3
//      (BRAssetEncode.h); a list that cannot be encoded is refused (INSTRUCTIONS).
//    - THE SOURCE GROUPS (BRAssetSourceGroups): the asset coins grouped by script, in the order each
//      script first appears, keeping the groups whose quantities (summed, stopping at the int64 range's
//      ends) reach the quantity, largest first, equal ones in that order. BRAssetLargestSingleSource is
//      the largest group's sum, 0 when there is no coin.
//    - A FEE COIN (BRAssetFeeCoinEligible) pays the fee of a send from a source when it pays the source
//      script itself, or the transaction that created it has no data output (NO; UNKNOWN is not eligible).
//    - AN ASSET INPUT (BRAssetInputJudge) is VERIFIED only when the indexer found it unspent with exactly
//      one entry, of the asset being sent, at the quantity the wallet recorded, which is above 0. No
//      answer is UNAVAILABLE; anything else (not unspent, another stack) is MISMATCH.
//    - THE CHOICE (BRAssetSendChoose), in this order: THE GATE; a quantity not above 0 (QUANTITY), a
//      negative fee rate (FEE_RATE), no asset coin (NO_ASSET_UTXOS), each NOT_PLANNED; no indexer
//      (UNVERIFIED); a NULL argument, or an answer whose entries are NULL while its entryCount is above
//      0, refused before anything is judged or marked (NOT_PLANNED, ARGUMENTS; C only: the Kotlin cannot
//      write such an answer); the asset coins' sum below the quantity (NOT_PLANNED, NOT_ENOUGH_ASSET).
//      Then up to (asset coins + 1) rounds, each over the asset coins not set aside and not left out of this send:
//      none of the source groups covers the quantity -> SPANS_ADDRESSES (the largest single source) when
//      they do together, UNCONFIRMED when they do not. Else the first group is planned with the fee coins
//      eligible for its script (a refusal is NOT_PLANNED; when it is NOT_ENOUGH_DGB and the eligibility
//      rule left a coin out, feeCoinRule says so). Each asset input of the plan, in its order, that is not
//      already confirmed (for this asset at this quantity) is judged: VERIFIED confirms it; MISMATCH sets
//      it aside for good when the indexer found it holding at least one entry, and otherwise leaves it out
//      of this send only (unconfirmed, or the indexer behind); UNAVAILABLE ends the choice, UNVERIFIED.
//      A round whose inputs are all confirmed is PLANNED. After the last round, UNCONFIRMED.
//    - A TYPED QUANTITY (BRAssetAmountParse), for an asset of 0..8 decimals: the text without surrounding
//      whitespace (Kotlin's isWhitespace, read from UTF-8); the separator rule of DGB amounts (no comma:
//      as is; with a dot, every comma is grouping and dropped; one comma and no dot, it is the point;
//      several and no dot, refused); at most BR_ASSET_AMOUNT_MAX_TEXT characters, not empty; ASCII digits
//      and one point only, at least one digit; no more decimals typed than the asset has (trailing zeros
//      count: "1.0" is not a quantity of an asset with none); the whole units at that divisibility,
//      within int64, above 0. Nothing is rounded. Unlike BRAmountParseDGB, a lone comma before exactly
//      three digits is the point here ("1,234" is 1234 units at three decimals): what the Kotlin reads.
//      BRAssetAmountFormat writes units as plain text (no grouping, exponent or trailing zero; "-" for a
//      negative count) that BRAssetAmountParse reads back as the same units.
//
//  SUMS. Asset quantities that decide (is there enough? which group is largest?) stop at the int64
//  range's ends, as Kotlin's AssetSums.add (BRAssetHoldings.h's); the total that becomes an
//  instruction's amount is exact (BRAssetAllocate.h's _BRAssetAllocAddExact), and a total past the range
//  refuses the plan. Satoshi sums are checked: where Kotlin's Long would wrap, the selector answers
//  OVERFLOW and a plan or choice is refused with BR_ASSET_PLAN_WHY_OVERFLOW (C only; no valid amount is
//  near the range: MAX_MONEY is far below it).
//
//  THE CHOICE IS A STEP FUNCTION. The Kotlin asks the indexer in the middle of a round. Here
//  BRAssetSendChoose answers LOOKUP (with the asset coin to ask about) when it needs an answer it was not
//  given; the platform asks, adds the answer to `answers` (keyed by the coin's txid as written and its
//  vout) and calls again with everything else the same. Each call starts from round 0, so given the same
//  answers it reaches the same point and goes on. One answer serves every row naming that txid and vout:
//  the Kotlin asks once a row, which differs only for two rows of one outpoint, and its table's primary
//  key (txid, vout) holds no such pair. What the Kotlin keeps for the life of the process (outputs
//  confirmed, and outputs set aside) the platform keeps and passes in (`verified`, `setAside`). After any
//  answer that is not LOOKUP (refusals included: `marks` is cleared first, whenever it has room) the
//  platform adds what `marks` says: a coin marked BR_ASSET_SEND_MARK_VERIFIED to `verified` (its txid,
//  vout, the asset sent, its quantity), one marked BR_ASSET_SEND_MARK_SET_ASIDE to `setAside`;
//  BR_ASSET_SEND_MARK_NOT_YET is left out of this send only and is not kept. After LOOKUP nothing is
//  kept yet.
//
//  Caller buffers. Every index answered is an index into the caller's arrays of rows. The selector and
//  the planner order the asset coins in `assetOrder` (room for every asset coin) and the fee coins in
//  `dgbOrder` (room for every plain coin); the choice takes `work` of BRAssetSendWorkLength(asset coins,
//  plain coins) entries and `marks` of one byte per asset coin. A buffer short of that is CAPACITY,
//  before anything is decided. The plan's index lists point into those buffers. No allocation, no
//  wallet, no network, no clock, no I/O. Header-only, static inline; its includes are libc,
//  BRAssetEncode.h (the encoder), BRAssetHoldings.h (BRAssetRow, which is the Kotlin's UtxoEntity, and
//  by way of BRAssetAllocate.h BRAssetUnits, BRAssetStackLookup and BRAssetFact), BRAssetRuleGate.h (the
//  gate) and BRDustPolicy.h (the dust lines the markers and the change line are held to), which this
//  header uses and does not redefine. Only a row's txid, vout, script, satoshis and asset quantity are read. It
//  reads no build-time policy macro. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_send_plan_kat in the Android repo): ASSET_SEND_PLAN_UNFIXED, tested by
//  VALUE as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is
//  what ships.
//    1        ASSET_SEND_PLAN_RED_INPUT_ORDER          coins are taken in the order given, not largest first.
//    2        ASSET_SEND_PLAN_RED_TIES_REVERSED        coins of equal size are taken last given first.
//    4        ASSET_SEND_PLAN_RED_POOLS_SHARED         a fee coin that is an asset coin, or given twice, is taken.
//    8        ASSET_SEND_PLAN_RED_TXID_CASE            outpoints are told apart by the case of their txid.
//    16       ASSET_SEND_PLAN_RED_CHANGE_MARKER_ALWAYS the asset-change marker is budgeted for an exact send too.
//    32       ASSET_SEND_PLAN_RED_NO_RELAY_FLOOR       the fee is not floored at the minimum relay fee.
//    64       ASSET_SEND_PLAN_RED_SUMS_WRAP            satoshi sums wrap.
//    128      ASSET_SEND_PLAN_RED_FEE_COIN_ANY         any plain coin pays the fee.
//    256      ASSET_SEND_PLAN_RED_PARENT_UNKNOWN_PAYS  a coin whose creating transaction is unread pays the fee.
//    512      ASSET_SEND_PLAN_RED_JUDGE_FRONT_ONLY     an input is judged by its stack's first entry only.
//    1024     ASSET_SEND_PLAN_RED_NO_ANSWER_GOES_ON    an input with no answer is left out and the send goes on.
//    2048     ASSET_SEND_PLAN_RED_NOT_YET_KEPT         an output the indexer has not seen is set aside for good.
//    4096     ASSET_SEND_PLAN_RED_RULES_UNKNOWN_SEND   an asset whose rules are UNKNOWN is sent.
//    8192     ASSET_SEND_PLAN_RED_APPROVAL_LOOSE       a fee above the approval is signed.
//    16384    ASSET_SEND_PLAN_RED_DUST_CHANGE          DGB change at or below the dust line is an output.
//    32768    ASSET_SEND_PLAN_RED_NO_SKIP              the last instruction drawing from an input does not skip.
//    65536    ASSET_SEND_PLAN_RED_ACROSS_ADDRESSES     a send draws from every address at once.
//    131072   ASSET_SEND_PLAN_RED_CHANGE_LAST          the DGB change is the last output.
//    262144   ASSET_SEND_PLAN_RED_PARSE_ROUNDS         decimals past the divisibility are dropped.
//    524288   ASSET_SEND_PLAN_RED_PARSE_ZERO           zero is a quantity.
//    1048576  ASSET_SEND_PLAN_RED_PARSE_COMMA_GROUPS   a lone comma is grouping.
//    2097152  ASSET_SEND_PLAN_RED_PARSE_UNBOUNDED      the text's length is not bounded.
//    4194304  ASSET_SEND_PLAN_RED_CONFIRMED_ASKED      an output confirmed earlier is asked again.
//    8388608  ASSET_SEND_PLAN_RED_NULL_ENTRIES_JUDGED  an answer with entries NULL and a count is judged, and
//                                                      its coin set aside.
//

#ifndef BRAssetSendPlan_h
#define BRAssetSendPlan_h

#include "BRAssetEncode.h"     // BRAssetEncodeTransferScript, BRAssetTransferInstruction
#include "BRAssetHoldings.h"   // BRAssetRow; BRAssetUnits, BRAssetStackLookup, BRAssetFact (BRAssetAllocate.h)
#include "BRAssetRuleGate.h"   // BRAssetRuleAllowsSend, BRSweepRuleState
#include "BRDustPolicy.h"      // BR_DUST_*_SATS
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_SEND_PLAN_UNFIXED
#define ASSET_SEND_PLAN_UNFIXED 0
#endif

#define ASSET_SEND_PLAN_RED_INPUT_ORDER           1
#define ASSET_SEND_PLAN_RED_TIES_REVERSED         2
#define ASSET_SEND_PLAN_RED_POOLS_SHARED          4
#define ASSET_SEND_PLAN_RED_TXID_CASE             8
#define ASSET_SEND_PLAN_RED_CHANGE_MARKER_ALWAYS  16
#define ASSET_SEND_PLAN_RED_NO_RELAY_FLOOR        32
#define ASSET_SEND_PLAN_RED_SUMS_WRAP             64
#define ASSET_SEND_PLAN_RED_FEE_COIN_ANY          128
#define ASSET_SEND_PLAN_RED_PARENT_UNKNOWN_PAYS   256
#define ASSET_SEND_PLAN_RED_JUDGE_FRONT_ONLY      512
#define ASSET_SEND_PLAN_RED_NO_ANSWER_GOES_ON     1024
#define ASSET_SEND_PLAN_RED_NOT_YET_KEPT          2048
#define ASSET_SEND_PLAN_RED_RULES_UNKNOWN_SEND    4096
#define ASSET_SEND_PLAN_RED_APPROVAL_LOOSE        8192
#define ASSET_SEND_PLAN_RED_DUST_CHANGE           16384
#define ASSET_SEND_PLAN_RED_NO_SKIP               32768
#define ASSET_SEND_PLAN_RED_ACROSS_ADDRESSES      65536
#define ASSET_SEND_PLAN_RED_CHANGE_LAST           131072
#define ASSET_SEND_PLAN_RED_PARSE_ROUNDS          262144
#define ASSET_SEND_PLAN_RED_PARSE_ZERO            524288
#define ASSET_SEND_PLAN_RED_PARSE_COMMA_GROUPS    1048576
#define ASSET_SEND_PLAN_RED_PARSE_UNBOUNDED       2097152
#define ASSET_SEND_PLAN_RED_CONFIRMED_ASKED       4194304
#define ASSET_SEND_PLAN_RED_NULL_ENTRIES_JUDGED   8388608

// Plain literals, so Swift imports them; the checks below hold them to the rules they come from.

// The sats of each marker output (Kotlin: DA_MARKER_SATS): above every standard script's dust line
// (DigiByte 9.26), so a marker to any recipient relays, and far below a payment.
#define BR_ASSET_MARKER_SATS 6000
// DGB change at or below this is left to the fee (Kotlin: DGB_CHANGE_DUST_THRESHOLD): the P2PKH dust
// line, the highest of the standard scripts', so a change output is never dust.
#define BR_ASSET_CHANGE_DUST_SATS 5460
// DigiByte's minimum relay fee, sat/kB (MIN_FEE_PER_KB, BRWallet.h): the fee's floor.
#define BR_ASSET_MIN_RELAY_FEE_PER_KB 100000
// The fee estimate's sizes, in vbytes.
#define BR_ASSET_FEE_INPUT_VBYTES 150
#define BR_ASSET_FEE_OUTPUT_VBYTES 34
#define BR_ASSET_FEE_OP_RETURN_OVERHEAD_VBYTES 9
#define BR_ASSET_FEE_TX_OVERHEAD_VBYTES 12
// The outputs a plan has at most: recipient marker, carrier, DGB change, last marker.
#define BR_ASSET_PLAN_MAX_OUTPUTS 4
// The most instructions a carrier of BR_ASSET_ENCODE_MAX_PAYLOAD bytes holds: 4 header bytes and at
// least 2 bytes an instruction.
#define BR_ASSET_PLAN_MAX_INSTRUCTIONS 38
// The most decimals an asset has, and the longest quantity text read.
#define BR_ASSET_MAX_DIVISIBILITY 8
#define BR_ASSET_AMOUNT_MAX_TEXT 32

typedef char _BRAssetSendMarkerClearsDust[(BR_ASSET_MARKER_SATS > BR_DUST_P2PKH_SATS &&
                                           BR_ASSET_MARKER_SATS > BR_DUST_P2SH_SATS &&
                                           BR_ASSET_MARKER_SATS > BR_DUST_P2WPKH_SATS &&
                                           BR_ASSET_MARKER_SATS > BR_DUST_P2WSH_SATS &&
                                           BR_ASSET_MARKER_SATS > BR_DUST_P2TR_SATS &&
                                           BR_ASSET_MARKER_SATS < 100000) ? 1 : -1];
typedef char _BRAssetSendChangeLineIsP2PKH[(BR_ASSET_CHANGE_DUST_SATS == BR_DUST_P2PKH_SATS) ? 1 : -1];
typedef char _BRAssetSendMaxInstructions[((BR_ASSET_ENCODE_MAX_PAYLOAD - 4) / 2 == BR_ASSET_PLAN_MAX_INSTRUCTIONS) ? 1 : -1];

// ---- the types -----------------------------------------------------------------------------------

// What the selector answers (Kotlin: AssetCoinSelector.Result). REFUSED is 0.
typedef enum {
    BR_ASSET_SELECT_REFUSED = 0,             // an argument the Kotlin's require() refuses, or a NULL
    BR_ASSET_SELECT_OK = 1,
    BR_ASSET_SELECT_INSUFFICIENT_ASSET = 2,
    BR_ASSET_SELECT_INSUFFICIENT_DGB = 3,
    BR_ASSET_SELECT_CAPACITY = 4,            // assetOrder or dgbOrder is short (C only)
    BR_ASSET_SELECT_OVERFLOW = 5             // a satoshi sum past the int64 range (C only; Kotlin wraps)
} BRAssetSelectStatus;

typedef struct {
    BRAssetSelectStatus status;
    int64_t required, available;     // INSUFFICIENT_*: what was needed, what the coins came to
    size_t assetInputCount;          // OK: assetOrder[0, assetInputCount) are the asset coins taken, in order
    size_t dgbInputCount;            // OK: dgbOrder[0, dgbInputCount) the fee coins taken, in order
    int64_t assetChangeQty;          // OK: units that return to the sender
    int64_t dgbChangeSats;           // OK: sats beyond the fee and the markers
} BRAssetSelection;

// One output of a plan (Kotlin: PlannedOutput.Role), in the order it is signed.
typedef enum {
    BR_ASSET_ROLE_RECIPIENT_MARKER = 0,      // vout 0, to the recipient: the output the instructions credit
    BR_ASSET_ROLE_ASSET_DATA = 1,            // vout 1, the carrier, 0 sats
    BR_ASSET_ROLE_DGB_CHANGE = 2,            // to the source, before the last output, only above the dust line
    BR_ASSET_ROLE_ASSET_CHANGE_MARKER = 3    // always last, to the source
} BRAssetOutputRole;

typedef struct {
    BRAssetOutputRole role;
    int64_t sats;
} BRAssetPlannedOutput;

// What the planner answers. REFUSED is 0.
typedef enum {
    BR_ASSET_PLAN_REFUSED = 0,
    BR_ASSET_PLAN_READY = 1,
    BR_ASSET_PLAN_CAPACITY = 2               // a caller buffer is short (C only)
} BRAssetPlanStatus;

// Why a plan is refused (the Kotlin's message, by its start).
typedef enum {
    BR_ASSET_PLAN_WHY_NONE = 0,
    BR_ASSET_PLAN_WHY_ARGUMENTS = 1,         // a NULL, or an argument the Kotlin's require() throws for (C only)
    BR_ASSET_PLAN_WHY_NO_ASSET_UTXOS = 2,    // "No UTXOs for this asset", "No UTXOs for asset ..."
    BR_ASSET_PLAN_WHY_MIXED_ADDRESSES = 3,   // "Asset inputs must come from one address"
    BR_ASSET_PLAN_WHY_NOT_ENOUGH_ASSET = 4,  // "Not enough asset: need <required>, have <available>"
    BR_ASSET_PLAN_WHY_NOT_ENOUGH_DGB = 5,    // "Not enough DGB for fee: need <required>, have <available>"
    BR_ASSET_PLAN_WHY_INSTRUCTIONS = 6,      // "Could not build transfer instructions"
    BR_ASSET_PLAN_WHY_RESIZED = 7,           // "Transfer instructions changed size"
    BR_ASSET_PLAN_WHY_FEE_MISMATCH = 8,      // "Fee does not match the transaction: pays <paid>, estimated <est>"
    BR_ASSET_PLAN_WHY_OVERFLOW = 9,          // a satoshi sum past the int64 range (C only; Kotlin wraps)
    BR_ASSET_PLAN_WHY_QUANTITY = 10,         // "Quantity must be positive"
    BR_ASSET_PLAN_WHY_FEE_RATE = 11          // "Fee rate must be non-negative"
} BRAssetPlanWhy;

// Everything an asset send signs (Kotlin: AssetTransferPlan), or why there is nothing to sign.
typedef struct {
    BRAssetPlanStatus status;
    BRAssetPlanWhy why;
    int64_t required, available;     // NOT_ENOUGH_*
    const size_t *assetInputs;       // indices into the asset rows: signed first, in this order (the
    size_t assetInputCount;          //   instructions are read against them)
    const size_t *dgbInputs;         // indices into the plain rows: signed after them
    size_t dgbInputCount;
    size_t outputCount;
    BRAssetPlannedOutput outputs[BR_ASSET_PLAN_MAX_OUTPUTS];
    uint8_t opReturnScript[BR_ASSET_ENCODE_MAX_SCRIPT];
    size_t opReturnLen;
    int64_t estimatedFeeSats;        // the fee the size estimate asked for (FEE_MISMATCH too)
    int64_t paidFeeSats;             // every input's sats less every output's (FEE_MISMATCH too)
    const uint8_t *sourceScript;     // the script every asset input pays (the first asset row's pointer);
    size_t sourceScriptLen;          //   the DGB change and the last output pay it too
} BRAssetTransferPlan;

// One output of an asset group, as the source groups see it.
typedef struct {
    size_t first;                    // the index of the group's first row; its rows are those paying its script
    size_t rowCount;
    int64_t total;                   // their quantities, summed, stopping at the int64 range's ends
} BRAssetSourceGroup;

// Kotlin's AssetInputCheck.Verdict. UNAVAILABLE is 0.
typedef enum {
    BR_ASSET_INPUT_UNAVAILABLE = 0,  // no answer: nothing is spent on a guess
    BR_ASSET_INPUT_MISMATCH = 1,     // the indexer answered, and the stack is anything else
    BR_ASSET_INPUT_VERIFIED = 2      // exactly the expected asset at the recorded quantity
} BRAssetInputVerdict;

// What the choice comes to (Kotlin: AssetSendSelection.Outcome, and planAssetTransfer's refusals).
// UNVERIFIED is 0: an outcome nobody filled sends nothing.
typedef enum {
    BR_ASSET_SEND_UNVERIFIED = 0,        // the asset's coins could not be confirmed now
    BR_ASSET_SEND_PLANNED = 1,           // `plan` is what to sign
    BR_ASSET_SEND_LOOKUP = 2,            // ask the indexer about asset row `lookupRow`, then call again
    BR_ASSET_SEND_UNCONFIRMED = 3,       // no coin confirmed to hold only this asset covers the amount
    BR_ASSET_SEND_SPANS_ADDRESSES = 4,   // it needs coins at more than one address; see largestSingleSource
    BR_ASSET_SEND_NOT_PLANNED = 5,       // plan.why says why (and plan.required / plan.available)
    BR_ASSET_SEND_RULE_BOUND = 6,        // the asset carries transfer rules
    BR_ASSET_SEND_RULES_UNKNOWN = 7,     // it is not known that the asset carries none
    BR_ASSET_SEND_CAPACITY = 8           // `work` or `marks` is short (C only)
} BRAssetSendKind;

typedef struct {
    BRAssetSendKind kind;
    size_t lookupRow;                    // LOOKUP
    int64_t largestSingleSource;         // SPANS_ADDRESSES
    int feeCoinRule;                     // NOT_PLANNED for NOT_ENOUGH_DGB: the eligibility rule left a coin out
    BRAssetTransferPlan plan;            // PLANNED: the plan; NOT_PLANNED: why
} BRAssetSendOutcome;

// What the platform keeps between choices: an output confirmed for an asset at a quantity, or (assetId
// NULL, quantity not read) an output set aside.
typedef struct {
    const char *txid;
    int32_t vout;
    const char *assetId;
    int64_t quantity;
} BRAssetSendKey;

// One answer of the indexer, for the coin whose txid (as written) and vout it names.
typedef struct {
    const char *txid;
    int32_t vout;
    BRAssetStackLookup lookup;
    const BRAssetUnits *entries;         // FOUND: the stack, front first; ruleFree is not read
    size_t entryCount;                   //   (entries NULL with entryCount above 0: the choice is ARGUMENTS)
} BRAssetSendLookup;

#define BR_ASSET_SEND_MARK_VERIFIED  1   // keep it in `verified`
#define BR_ASSET_SEND_MARK_SET_ASIDE 2   // keep it in `setAside`
#define BR_ASSET_SEND_MARK_NOT_YET   4   // left out of this send only

// ---- outpoints, scripts and sums -----------------------------------------------------------------

static inline const char *_BRAssetSendTxid(const char *txid)
{
    return txid ? txid : "";
}

// The same outpoint: the same vout, and txids equal with ASCII letters' case ignored.
static inline int _BRAssetSendSameOutpoint(const char *txidA, int32_t voutA, const char *txidB, int32_t voutB)
{
    if (voutA != voutB) return 0;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_TXID_CASE)
    return strcmp(_BRAssetSendTxid(txidA), _BRAssetSendTxid(txidB)) == 0;
#else
    return _BRAssetHoldSameIgnoringCase(_BRAssetSendTxid(txidA), _BRAssetSendTxid(txidB));
#endif
}

static inline int _BRAssetSendSameScript(const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen)
{
    if (! a) aLen = 0;
    if (! b) bLen = 0;
    return aLen == bLen && (aLen == 0 || memcmp(a, b, aLen) == 0);
}

// a + b and a - b over the whole int64 range; 0 when the result does not fit (Kotlin's Long wraps).
static inline int _BRAssetSendAdd(int64_t a, int64_t b, int64_t *out)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_SUMS_WRAP)
    *out = (int64_t)((uint64_t)a + (uint64_t)b);
    return 1;
#else
    return _BRAssetAllocAddExact(a, b, out);
#endif
}

static inline int _BRAssetSendSub(int64_t a, int64_t b, int64_t *out)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_SUMS_WRAP)
    *out = (int64_t)((uint64_t)a - (uint64_t)b);
    return 1;
#else
    if (b < 0 && a > INT64_MAX + b) return 0;
    if (b > 0 && a < INT64_MIN + b) return 0;
    *out = a - b;
    return 1;
#endif
}

// The i-th row of a set: set[i], or i when the set is every row.
static inline size_t _BRAssetSendAt(const size_t *set, size_t i)
{
    return set ? set[i] : i;
}

// Orders order[0, n) by key, largest first, equal keys in the order given (a stable insertion sort).
static inline void _BRAssetSendSortDescending(size_t *order, size_t n, const BRAssetRow *rows, int bySats)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_INPUT_ORDER)
    (void)order; (void)n; (void)rows; (void)bySats;
#else
    size_t i, j;

    for (i = 1; i < n; i++) {
        size_t key = order[i];
        int64_t k = bySats ? rows[key].satoshis : rows[key].assetQuantity;

        for (j = i; j > 0; j--) {
            int64_t p = bySats ? rows[order[j - 1]].satoshis : rows[order[j - 1]].assetQuantity;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_TIES_REVERSED)
            if (p > k) break;
#else
            if (p >= k) break;
#endif
            order[j] = order[j - 1];
        }
        order[j] = key;
    }
#endif
}

// ---- the fee (Kotlin: AssetFeeEstimator) --------------------------------------------------------

// The fee, in sats, of an asset transfer of this shape at feePerKb (see THE RULES). 1 and *fee; 0 when
// vsize * rate is past the int64 range (C only; Kotlin wraps).
static inline int BRAssetFeeEstimate(int32_t assetInputCount, int32_t dgbInputCount, int32_t outputCount,
                                     int32_t opReturnBytes, int64_t feePerKb, int64_t *fee)
{
    int64_t inputs = (assetInputCount > 0 ? assetInputCount : 0) + (int64_t)(dgbInputCount > 0 ? dgbInputCount : 0) + 1;
    int64_t vsize = BR_ASSET_FEE_TX_OVERHEAD_VBYTES + inputs * BR_ASSET_FEE_INPUT_VBYTES +
                    (int64_t)(outputCount > 0 ? outputCount : 0) * BR_ASSET_FEE_OUTPUT_VBYTES +
                    BR_ASSET_FEE_OP_RETURN_OVERHEAD_VBYTES + (opReturnBytes > 0 ? opReturnBytes : 0);
    int64_t rate = feePerKb > 0 ? feePerKb : 0, requested, floor;

    if (fee) *fee = 0;
    // vsize is at most about 2^40, so the floor's product fits; the rate's is checked.
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_SUMS_WRAP)
    requested = (int64_t)(((uint64_t)vsize * (uint64_t)rate + 999u) / 1000u);
#else
    if (rate > 0 && vsize > (INT64_MAX - 999) / rate) return 0;
    requested = (vsize * rate + 999) / 1000;
#endif
    floor = (vsize * BR_ASSET_MIN_RELAY_FEE_PER_KB + 999) / 1000;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_NO_RELAY_FLOOR)
    (void)floor;
    if (fee) *fee = requested;
#else
    if (fee) *fee = requested > floor ? requested : floor;
#endif
    return 1;
}

// ---- the coin selector (Kotlin: AssetCoinSelector) ----------------------------------------------

static inline BRAssetSelection _BRAssetSelectAnswer(BRAssetSelectStatus status)
{
    BRAssetSelection s;

    memset(&s, 0, sizeof(s));
    s.status = status;
    return s;
}

// The selector over the rows of two sets (NULL: every row). Indices into the row arrays go to
// assetOrder[0, assetCount) and dgbOrder[0, dgbCount), which the caller has checked are there.
static inline BRAssetSelection _BRAssetSelect(const BRAssetRow *assetRows, const size_t *assetSet, size_t assetCount,
                                              const BRAssetRow *dgbRows, const size_t *dgbSet, size_t dgbCount,
                                              int64_t assetNeeded, int64_t feeSats, int64_t markerOutputSats,
                                              int64_t assetChangeMarkerSats, size_t *assetOrder, size_t *dgbOrder)
{
    BRAssetSelection s = _BRAssetSelectAnswer(BR_ASSET_SELECT_OK);
    int64_t assetSum = 0, markers = markerOutputSats, assetSats = 0, needed = 0, dgbSum = 0, totalIn, change;
    size_t i, j, k = 0, fees = 0;

    for (i = 0; i < assetCount; i++) assetOrder[i] = _BRAssetSendAt(assetSet, i);
    _BRAssetSendSortDescending(assetOrder, assetCount, assetRows, 0);

    for (i = 0; i < assetCount; i++) {
        if (assetSum >= assetNeeded) break;
        k++;
        assetSum = _BRAssetHoldSaturatingAdd(assetSum, assetRows[assetOrder[i]].assetQuantity);
    }
    if (assetSum < assetNeeded) {
        s.status = BR_ASSET_SELECT_INSUFFICIENT_ASSET;
        s.required = assetNeeded;
        s.available = assetSum;
        return s;
    }

    // assetSum >= assetNeeded > 0, so the difference fits.
    s.assetChangeQty = assetSum - assetNeeded;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_CHANGE_MARKER_ALWAYS)
    if (! _BRAssetSendAdd(markers, assetChangeMarkerSats, &markers)) return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);
#else
    if (s.assetChangeQty > 0 && ! _BRAssetSendAdd(markers, assetChangeMarkerSats, &markers))
        return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);
#endif
    for (i = 0; i < k; i++) {
        if (! _BRAssetSendAdd(assetSats, assetRows[assetOrder[i]].satoshis, &assetSats))
            return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);
    }
    if (! _BRAssetSendAdd(feeSats, markers, &needed) || ! _BRAssetSendSub(needed, assetSats, &needed))
        return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);
    if (needed < 0) needed = 0;

    // The fee coins: no outpoint of an asset coin given, each outpoint once.
    for (j = 0; j < dgbCount; j++) {
        size_t r = _BRAssetSendAt(dgbSet, j), a;
        int skip = 0;

#if ! (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_POOLS_SHARED)
        for (a = 0; a < assetCount && ! skip; a++) {
            const BRAssetRow *ar = &assetRows[_BRAssetSendAt(assetSet, a)];

            skip = _BRAssetSendSameOutpoint(dgbRows[r].txid, dgbRows[r].vout, ar->txid, ar->vout);
        }
        for (a = 0; a < fees && ! skip; a++) {
            skip = _BRAssetSendSameOutpoint(dgbRows[r].txid, dgbRows[r].vout, dgbRows[dgbOrder[a]].txid,
                                             dgbRows[dgbOrder[a]].vout);
        }
#else
        (void)a;
#endif
        if (! skip) dgbOrder[fees++] = r;
    }
    _BRAssetSendSortDescending(dgbOrder, fees, dgbRows, 1);

    if (needed > 0) {
        for (j = 0; j < fees; j++) {
            if (dgbSum >= needed) break;
            s.dgbInputCount++;
            if (! _BRAssetSendAdd(dgbSum, dgbRows[dgbOrder[j]].satoshis, &dgbSum))
                return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);
        }
        if (dgbSum < needed) {
            s = _BRAssetSelectAnswer(BR_ASSET_SELECT_INSUFFICIENT_DGB);
            s.required = needed;
            s.available = dgbSum;
            return s;
        }
    }

    if (! _BRAssetSendAdd(assetSats, dgbSum, &totalIn) || ! _BRAssetSendSub(totalIn, feeSats, &change) ||
        ! _BRAssetSendSub(change, markers, &change)) return _BRAssetSelectAnswer(BR_ASSET_SELECT_OVERFLOW);

    s.assetInputCount = k;
    s.dgbChangeSats = change;
    return s;
}

// The asset coins and fee coins for one transfer (see THE COIN SELECTOR). assetOrder needs room for
// assetCount indices and dgbOrder for dgbCount; the answer's coins are their prefixes.
static inline BRAssetSelection BRAssetCoinSelect(const BRAssetRow *assetRows, size_t assetCount,
                                                 const BRAssetRow *dgbRows, size_t dgbCount, int64_t assetNeeded,
                                                 int64_t feeSats, int64_t markerOutputSats, int64_t assetChangeMarkerSats,
                                                 size_t *assetOrder, size_t assetOrderCap, size_t *dgbOrder,
                                                 size_t dgbOrderCap)
{
    if ((assetCount > 0 && ! assetRows) || (dgbCount > 0 && ! dgbRows)) return _BRAssetSelectAnswer(BR_ASSET_SELECT_REFUSED);
    if (assetNeeded <= 0 || feeSats < 0 || markerOutputSats < 0 || assetChangeMarkerSats < 0)
        return _BRAssetSelectAnswer(BR_ASSET_SELECT_REFUSED);
    if ((assetCount > 0 && (! assetOrder || assetOrderCap < assetCount)) ||
        (dgbCount > 0 && (! dgbOrder || dgbOrderCap < dgbCount))) return _BRAssetSelectAnswer(BR_ASSET_SELECT_CAPACITY);
    return _BRAssetSelect(assetRows, NULL, assetCount, dgbRows, NULL, dgbCount, assetNeeded, feeSats, markerOutputSats,
                          assetChangeMarkerSats, assetOrder, dgbOrder);
}

// No two of rows[0, count) name the same outpoint (Kotlin: AssetCoinSelector.outpointsDistinct). 1 or 0.
static inline int BRAssetOutpointsDistinct(const BRAssetRow *rows, size_t count)
{
    size_t i, j;

    if (count > 0 && ! rows) return 0;
    for (i = 0; i < count; i++) {
        for (j = 0; j < i; j++) {
            if (_BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, rows[j].txid, rows[j].vout)) return 0;
        }
    }
    return 1;
}

// ---- the planner (Kotlin: AssetTransferPlanner) -------------------------------------------------

// May a plan paying paidFeeSats be signed under an approval of approvedFeeSats? Never more than the
// person saw; an approval of zero or less approves nothing. 1 or 0.
static inline int BRAssetFeeWithinApproval(int64_t paidFeeSats, int64_t approvedFeeSats)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_APPROVAL_LOOSE)
    return approvedFeeSats > 0 && paidFeeSats >= 0;
#else
    return approvedFeeSats > 0 && paidFeeSats >= 0 && paidFeeSats <= approvedFeeSats;
#endif
}

// May a coin paying coinScript pay the fee of a send from sourceScript (see A FEE COIN)? parentHasData:
// whether the transaction that created the coin has a data output (UNKNOWN: it could not be read).
static inline int BRAssetFeeCoinEligible(const uint8_t *coinScript, size_t coinScriptLen, const uint8_t *sourceScript,
                                         size_t sourceScriptLen, BRAssetFact parentHasData)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_FEE_COIN_ANY)
    (void)coinScript; (void)coinScriptLen; (void)sourceScript; (void)sourceScriptLen; (void)parentHasData;
    return 1;
#elif (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_PARENT_UNKNOWN_PAYS)
    return _BRAssetSendSameScript(coinScript, coinScriptLen, sourceScript, sourceScriptLen) ||
           parentHasData != BR_ASSET_FACT_YES;
#else
    return _BRAssetSendSameScript(coinScript, coinScriptLen, sourceScript, sourceScriptLen) ||
           parentHasData == BR_ASSET_FACT_NO;
#endif
}

// THE INSTRUCTIONS for the asset coins assetOrder[0, n), encoded into plan->opReturnScript. 1, or 0
// (Kotlin: null).
static inline int _BRAssetPlanInstructions(const BRAssetRow *assetRows, const size_t *assetOrder, size_t n,
                                           int64_t quantity, int64_t change, int32_t recipientVout, int32_t changeVout,
                                           BRAssetTransferPlan *plan)
{
    BRAssetTransferInstruction insts[BR_ASSET_PLAN_MAX_INSTRUCTIONS];
    int64_t totalIn = 0, totalOut = 0, qty = quantity, left = change;
    size_t i, count = 0;

    plan->opReturnLen = 0;
    for (i = 0; i < n; i++) {
        if (! _BRAssetAllocAddExact(totalIn, assetRows[assetOrder[i]].assetQuantity, &totalIn)) return 0;
    }
    if (! _BRAssetAllocAddExact(totalOut, quantity, &totalOut) || ! _BRAssetAllocAddExact(totalOut, change, &totalOut)) return 0;
    if (totalIn != totalOut) return 0;

    for (i = 0; i < n; i++) {
        int64_t inputLeft = assetRows[assetOrder[i]].assetQuantity;

        if (inputLeft > 0 && qty > 0) {
            int64_t take = inputLeft < qty ? inputLeft : qty;

            // A list past BR_ASSET_PLAN_MAX_INSTRUCTIONS cannot be encoded (Kotlin: the encoder throws).
            if (count >= BR_ASSET_PLAN_MAX_INSTRUCTIONS) return 0;
            memset(&insts[count], 0, sizeof(insts[count]));
            insts[count].outputIndex = recipientVout;
            insts[count].amount = take;
            count++;
            qty -= take;
            inputLeft -= take;
        }

        if (inputLeft > 0 && left > 0 && changeVout >= 0) {
            int64_t take = inputLeft < left ? inputLeft : left;

            if (count >= BR_ASSET_PLAN_MAX_INSTRUCTIONS) return 0;
            memset(&insts[count], 0, sizeof(insts[count]));
            insts[count].outputIndex = changeVout;
            insts[count].amount = take;
            count++;
            left -= take;
            inputLeft -= take;
        }

#if ! (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_NO_SKIP)
        // The last instruction written so far skips, after every input but the last.
        if (i + 1 < n && count > 0) insts[count - 1].skip = 1;
#endif
    }

    return BRAssetEncodeTransferScript(3, insts, count, plan->opReturnScript, sizeof(plan->opReturnScript),
                                       &plan->opReturnLen, NULL) == BR_ASSET_ENCODE_OK;
}

static inline void _BRAssetPlanRefuse(BRAssetTransferPlan *plan, BRAssetPlanWhy why)
{
    BRAssetTransferPlan p;

    memset(&p, 0, sizeof(p));
    p.status = BR_ASSET_PLAN_REFUSED;
    p.why = why;
    *plan = p;
}

// A selection's refusal, as the plan's. 1 when it is OK.
static inline int _BRAssetPlanSelected(BRAssetSelection s, BRAssetTransferPlan *plan)
{
    switch (s.status) {
    case BR_ASSET_SELECT_OK: return 1;
    case BR_ASSET_SELECT_INSUFFICIENT_ASSET: _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_NOT_ENOUGH_ASSET); break;
    case BR_ASSET_SELECT_INSUFFICIENT_DGB: _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_NOT_ENOUGH_DGB); break;
    case BR_ASSET_SELECT_OVERFLOW: _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_OVERFLOW); break;
    case BR_ASSET_SELECT_CAPACITY:
        _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_NONE);
        plan->status = BR_ASSET_PLAN_CAPACITY;
        break;
    default: _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_ARGUMENTS); break;
    }
    plan->required = s.required;
    plan->available = s.available;
    return 0;
}

// The planner over the rows of two sets (NULL: every row); the caller has checked the buffers.
// INTERNAL: called only behind THE GATE (by BRAssetSendChoose, after BRAssetSendGate, and by
// _BRAssetPlanTransfer).
static inline void _BRAssetPlan(const BRAssetRow *assetRows, const size_t *assetSet, size_t assetCount,
                                const BRAssetRow *dgbRows, const size_t *dgbSet, size_t dgbCount, int64_t quantity,
                                int64_t feePerKb, size_t *assetOrder, size_t *dgbOrder, BRAssetTransferPlan *plan)
{
    const BRAssetRow *first;
    BRAssetSelection ok0, ok;
    int64_t bootstrapFee = 0, feeSats = 0, paid = 0, outSum = 0, beyond;
    size_t i, provisionalLen, iter, maxIterations, estimated;
    int32_t lastVout;
    int fits = 1;

    _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_NONE);
    if (assetCount == 0) { _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_NO_ASSET_UTXOS); return; }
    first = &assetRows[_BRAssetSendAt(assetSet, 0)];
    for (i = 0; i < assetCount; i++) {
        const BRAssetRow *r = &assetRows[_BRAssetSendAt(assetSet, i)];

        if (! _BRAssetSendSameScript(r->script, r->scriptLen, first->script, first->scriptLen)) {
            _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_MIXED_ADDRESSES);
            return;
        }
    }

    // Both markers are emitted on every send: the recipient's and the last output's.
    if (! BRAssetFeeEstimate(1, 1, 3, BR_ASSET_ENCODE_MAX_PAYLOAD, feePerKb, &bootstrapFee)) {
        _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_OVERFLOW);
        return;
    }
    if (quantity <= 0) { _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_ARGUMENTS); return; }   // Kotlin: require() throws
    ok0 = _BRAssetSelect(assetRows, assetSet, assetCount, dgbRows, dgbSet, dgbCount, quantity, bootstrapFee,
                         2 * BR_ASSET_MARKER_SATS, 0, assetOrder, dgbOrder);
    if (! _BRAssetPlanSelected(ok0, plan)) return;

    // The asset coins a selection takes do not depend on the fee, so every later selection takes
    // assetOrder[0, ok0.assetInputCount) again, in the same order.
    if (! _BRAssetPlanInstructions(assetRows, assetOrder, ok0.assetInputCount, quantity, ok0.assetChangeQty, 0, 3, plan)) {
        _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_INSTRUCTIONS);
        return;
    }
    provisionalLen = plan->opReturnLen;

    maxIterations = dgbCount + 2;
    estimated = ok0.dgbInputCount;
    feeSats = bootstrapFee;
    ok = ok0;
    for (iter = 0; iter < maxIterations; iter++) {
        if (! BRAssetFeeEstimate((int32_t)ok0.assetInputCount, (int32_t)estimated, 3, (int32_t)provisionalLen, feePerKb,
                                 &feeSats)) {
            _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_OVERFLOW);
            return;
        }
        ok = _BRAssetSelect(assetRows, assetSet, assetCount, dgbRows, dgbSet, dgbCount, quantity, feeSats,
                            2 * BR_ASSET_MARKER_SATS, 0, assetOrder, dgbOrder);
        if (! _BRAssetPlanSelected(ok, plan)) return;
        if (ok.dgbInputCount <= estimated) break;
        estimated = ok.dgbInputCount;
    }

    plan->outputCount = 0;
    plan->outputs[plan->outputCount].role = BR_ASSET_ROLE_RECIPIENT_MARKER;
    plan->outputs[plan->outputCount++].sats = BR_ASSET_MARKER_SATS;
    plan->outputs[plan->outputCount].role = BR_ASSET_ROLE_ASSET_DATA;
    plan->outputs[plan->outputCount++].sats = 0;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_CHANGE_LAST)
    plan->outputs[plan->outputCount].role = BR_ASSET_ROLE_ASSET_CHANGE_MARKER;
    plan->outputs[plan->outputCount++].sats = BR_ASSET_MARKER_SATS;
#endif
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_DUST_CHANGE)
    if (ok.dgbChangeSats > 0) {
#else
    if (ok.dgbChangeSats > BR_ASSET_CHANGE_DUST_SATS) {
#endif
        plan->outputs[plan->outputCount].role = BR_ASSET_ROLE_DGB_CHANGE;
        plan->outputs[plan->outputCount++].sats = ok.dgbChangeSats;
    }
#if ! (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_CHANGE_LAST)
    plan->outputs[plan->outputCount].role = BR_ASSET_ROLE_ASSET_CHANGE_MARKER;
    plan->outputs[plan->outputCount++].sats = BR_ASSET_MARKER_SATS;
#endif
    lastVout = (int32_t)plan->outputCount - 1;

    if (! _BRAssetPlanInstructions(assetRows, assetOrder, ok0.assetInputCount, quantity, ok0.assetChangeQty, 0, lastVout,
                                   plan)) {
        _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_INSTRUCTIONS);
        return;
    }
    if (plan->opReturnLen != provisionalLen) { _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_RESIZED); return; }

    plan->assetInputs = assetOrder;
    plan->assetInputCount = ok.assetInputCount;
    plan->dgbInputs = dgbOrder;
    plan->dgbInputCount = ok.dgbInputCount;
    plan->estimatedFeeSats = feeSats;
    plan->sourceScript = first->script;
    plan->sourceScriptLen = first->script ? first->scriptLen : 0;

    // Kotlin's order: every input's sats summed, every output's summed, then the difference.
    for (i = 0; i < ok.assetInputCount && fits; i++) fits = _BRAssetSendAdd(paid, assetRows[assetOrder[i]].satoshis, &paid);
    for (i = 0; i < ok.dgbInputCount && fits; i++) fits = _BRAssetSendAdd(paid, dgbRows[dgbOrder[i]].satoshis, &paid);
    for (i = 0; i < plan->outputCount && fits; i++) fits = _BRAssetSendAdd(outSum, plan->outputs[i].sats, &outSum);
    if (! fits || ! _BRAssetSendSub(paid, outSum, &paid)) { _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_OVERFLOW); return; }
    plan->paidFeeSats = paid;
    if (! _BRAssetSendSub(paid, feeSats, &beyond)) { _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_OVERFLOW); return; }
    // The selector leaves no negative change, so this holds of every plan it makes; Kotlin checks it, and
    // so does this.
    if (beyond < 0 || beyond > BR_ASSET_CHANGE_DUST_SATS) {
        _BRAssetPlanRefuse(plan, BR_ASSET_PLAN_WHY_FEE_MISMATCH);
        plan->paidFeeSats = paid;
        plan->estimatedFeeSats = feeSats;
        return;
    }
    plan->status = BR_ASSET_PLAN_READY;
    plan->why = BR_ASSET_PLAN_WHY_NONE;
}

// INTERNAL: called only behind THE GATE. It asks no transfer-rule gate, so it is not a send entry
// point: a send reaches a plan only through BRAssetSendChoose, which asks BRAssetSendGate first and
// then plans with _BRAssetPlan, the same planner. Outside the core only the host KAT and
// vectors/asset-send-plan/generate.c call this, to hold the planner to the Kotlin's (AssetTransferPlanner,
// which AssetManager.planAssetTransfer calls only after its rule check).
// Plan a send of `quantity` from assetRows (all paying one script) with the fee and markers paid from
// dgbRows (already limited to eligible coins) at feePerKb (see THE PLAN). assetOrder needs room for
// assetCount indices and dgbOrder for dgbCount; the plan's index lists point into them.
static inline BRAssetTransferPlan _BRAssetPlanTransfer(const BRAssetRow *assetRows, size_t assetCount,
                                                      const BRAssetRow *dgbRows, size_t dgbCount, int64_t quantity,
                                                      int64_t feePerKb, size_t *assetOrder, size_t assetOrderCap,
                                                      size_t *dgbOrder, size_t dgbOrderCap)
{
    BRAssetTransferPlan plan;

    _BRAssetPlanRefuse(&plan, BR_ASSET_PLAN_WHY_ARGUMENTS);
    if ((assetCount > 0 && ! assetRows) || (dgbCount > 0 && ! dgbRows)) return plan;
    if ((assetCount > 0 && (! assetOrder || assetOrderCap < assetCount)) ||
        (dgbCount > 0 && (! dgbOrder || dgbOrderCap < dgbCount))) {
        plan.status = BR_ASSET_PLAN_CAPACITY;
        plan.why = BR_ASSET_PLAN_WHY_NONE;
        return plan;
    }
    _BRAssetPlan(assetRows, NULL, assetCount, dgbRows, NULL, dgbCount, quantity, feePerKb, assetOrder, dgbOrder, &plan);
    return plan;
}

// No two of a plan's inputs (asset inputs, then fee inputs) name the same outpoint: the check the send
// makes on the exact list it signs. 1 or 0; 0 for a plan that is not READY.
static inline int BRAssetPlanInputsDistinct(const BRAssetTransferPlan *plan, const BRAssetRow *assetRows,
                                            const BRAssetRow *dgbRows)
{
    size_t n, i, j;

    if (! plan || plan->status != BR_ASSET_PLAN_READY) return 0;
    n = plan->assetInputCount + plan->dgbInputCount;
    for (i = 0; i < n; i++) {
        const BRAssetRow *a = (i < plan->assetInputCount) ? &assetRows[plan->assetInputs[i]]
                                                          : &dgbRows[plan->dgbInputs[i - plan->assetInputCount]];

        for (j = 0; j < i; j++) {
            const BRAssetRow *b = (j < plan->assetInputCount) ? &assetRows[plan->assetInputs[j]]
                                                              : &dgbRows[plan->dgbInputs[j - plan->assetInputCount]];

            if (_BRAssetSendSameOutpoint(a->txid, a->vout, b->txid, b->vout)) return 0;
        }
    }
    return 1;
}

// ---- the source groups ---------------------------------------------------------------------------

// Is row r looked at: no flags, or flags[r] has none of the `mask` bits?
static inline int _BRAssetSendKept(const uint8_t *flags, uint8_t mask, size_t r)
{
    return ! flags || ! (flags[r] & mask);
}

// Does row i belong to the group of row `first`'s script?
static inline int _BRAssetSendSameGroup(const BRAssetRow *rows, size_t i, size_t first)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_ACROSS_ADDRESSES)
    (void)rows; (void)i; (void)first;
    return 1;
#else
    return _BRAssetSendSameScript(rows[i].script, rows[i].scriptLen, rows[first].script, rows[first].scriptLen);
#endif
}

// The group of rows[first]'s script among the rows looked at: its row count and saturating total.
static inline void _BRAssetSendGroupOf(const BRAssetRow *rows, size_t count, const uint8_t *flags, uint8_t mask,
                                       size_t first, size_t *rowCount, int64_t *total)
{
    size_t i;

    *rowCount = 0;
    *total = 0;
    for (i = 0; i < count; i++) {
        if (! _BRAssetSendKept(flags, mask, i) || ! _BRAssetSendSameGroup(rows, i, first)) continue;
        (*rowCount)++;
        *total = _BRAssetHoldSaturatingAdd(*total, rows[i].assetQuantity);
    }
}

// Is row i the first of its group among the rows looked at?
static inline int _BRAssetSendGroupFirst(const BRAssetRow *rows, const uint8_t *flags, uint8_t mask, size_t i)
{
    size_t j;

    for (j = 0; j < i; j++) {
        if (_BRAssetSendKept(flags, mask, j) && _BRAssetSendSameGroup(rows, j, i)) return 0;
    }
    return 1;
}

// Among the rows looked at: the first group whose total covers `quantity`, of the largest such total
// (the first of the source groups): 1 and *group, or 0 when none covers it. *largest is the largest total
// of any group (0 when no row is looked at).
static inline int _BRAssetSendBestGroup(const BRAssetRow *rows, size_t count, const uint8_t *flags, uint8_t mask,
                                        int64_t quantity, BRAssetSourceGroup *group, int64_t *largest)
{
    size_t i;
    int found = 0, any = 0;

    *largest = 0;
    for (i = 0; i < count; i++) {
        size_t n;
        int64_t total;

        if (! _BRAssetSendKept(flags, mask, i) || ! _BRAssetSendGroupFirst(rows, flags, mask, i)) continue;
        _BRAssetSendGroupOf(rows, count, flags, mask, i, &n, &total);
        if (! any || total > *largest) *largest = total;
        any = 1;
        if (total >= quantity && (! found || total > group->total)) {
            group->first = i;
            group->rowCount = n;
            group->total = total;
            found = 1;
        }
    }
    return found;
}

// The source groups of rows[0, count) for `quantity` (see THE SOURCE GROUPS) into groups[0, *groupCount).
// 1, or 0 when an argument is NULL or `groups` has room for fewer than *groupCount (the number there are).
static inline int BRAssetSourceGroups(const BRAssetRow *rows, size_t count, int64_t quantity, BRAssetSourceGroup *groups,
                                      size_t cap, size_t *groupCount)
{
    size_t i, j, n = 0;

    if (groupCount) *groupCount = 0;
    if ((count > 0 && ! rows) || ! groupCount) return 0;
    for (i = 0; i < count; i++) {
        size_t rowCount;
        int64_t total;

        if (! _BRAssetSendGroupFirst(rows, NULL, 0, i)) continue;
        _BRAssetSendGroupOf(rows, count, NULL, 0, i, &rowCount, &total);
        if (total < quantity) continue;
        if (groups && n < cap) {
            // After every group whose total is at least as large: largest first, equal ones in order.
            for (j = n; j > 0 && groups[j - 1].total < total; j--) groups[j] = groups[j - 1];
            groups[j].first = i;
            groups[j].rowCount = rowCount;
            groups[j].total = total;
        }
        n++;
    }
    *groupCount = n;
    return groups ? n <= cap : n == 0;
}

// The most any one script's rows hold (Kotlin: largestSingleSource): 0 when there is no row.
static inline int64_t BRAssetLargestSingleSource(const BRAssetRow *rows, size_t count)
{
    BRAssetSourceGroup g;
    int64_t largest;

    if (count > 0 && ! rows) return 0;
    _BRAssetSendBestGroup(rows, count, NULL, 0, INT64_MAX, &g, &largest);
    return largest;
}

// Is rows[i] one of `group`'s (does it pay the group's script)?
static inline int BRAssetSourceGroupHas(const BRAssetRow *rows, const BRAssetSourceGroup *group, size_t i)
{
    if (! rows || ! group) return 0;
    return _BRAssetSendSameScript(rows[i].script, rows[i].scriptLen, rows[group->first].script, rows[group->first].scriptLen);
}

// ---- an asset input (Kotlin: AssetInputCheck) ---------------------------------------------------

// The verdict on an asset input the wallet recorded as recordedQuantity of expectedAssetId, from what
// the indexer said of it (see AN ASSET INPUT). entries[0, entryCount) is read only for FOUND.
static inline BRAssetInputVerdict BRAssetInputJudge(BRAssetStackLookup lookup, const BRAssetUnits *entries, size_t entryCount,
                                                    const char *expectedAssetId, int64_t recordedQuantity)
{
    if (lookup == BR_ASSET_STACK_NOT_UNSPENT) return BR_ASSET_INPUT_MISMATCH;
    if (lookup != BR_ASSET_STACK_FOUND) return BR_ASSET_INPUT_UNAVAILABLE;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_JUDGE_FRONT_ONLY)
    if (entryCount < 1 || ! entries) return BR_ASSET_INPUT_MISMATCH;
#else
    if (entryCount != 1 || ! entries) return BR_ASSET_INPUT_MISMATCH;
#endif
    if (recordedQuantity > 0 && entries[0].assetId && expectedAssetId && strcmp(entries[0].assetId, expectedAssetId) == 0 &&
        entries[0].count == recordedQuantity) return BR_ASSET_INPUT_VERIFIED;
    return BR_ASSET_INPUT_MISMATCH;
}

// ---- the choice (Kotlin: AssetSendSelection, planAssetTransfer) ---------------------------------

// The `work` entries BRAssetSendChoose needs for these many asset and plain coins. SIZE_MAX when the
// count does not fit a size_t.
static inline size_t BRAssetSendWorkLength(size_t assetCount, size_t dgbCount)
{
    if (dgbCount > SIZE_MAX / 4 || assetCount > SIZE_MAX / 4 - dgbCount) return SIZE_MAX;
    return 2 * assetCount + 2 * dgbCount;
}

// May the asset be sent (THE GATE)? 1; or 0 and *refusal RULE_BOUND or RULES_UNKNOWN.
static inline int BRAssetSendGate(BRSweepRuleState ruleState, BRAssetSendKind *refusal)
{
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_RULES_UNKNOWN_SEND)
    int allows = ruleState != BR_SWEEP_RULE_BOUND;
#else
    int allows = BRAssetRuleAllowsSend(ruleState);
#endif

    if (refusal) *refusal = BR_ASSET_SEND_RULES_UNKNOWN;
    if (allows) return 1;
    if (refusal && ruleState == BR_SWEEP_RULE_BOUND) *refusal = BR_ASSET_SEND_RULE_BOUND;
    return 0;
}

static inline BRAssetSendOutcome _BRAssetSendAnswer(BRAssetSendKind kind)
{
    BRAssetSendOutcome o;

    memset(&o, 0, sizeof(o));
    o.kind = kind;
    return o;
}

static inline BRAssetSendOutcome _BRAssetSendNotPlanned(BRAssetPlanWhy why)
{
    BRAssetSendOutcome o = _BRAssetSendAnswer(BR_ASSET_SEND_NOT_PLANNED);

    o.plan.status = BR_ASSET_PLAN_REFUSED;
    o.plan.why = why;
    return o;
}

// Is asset row i set aside: kept so by the platform, or marked so in this choice?
static inline int _BRAssetSendSetAside(const BRAssetRow *rows, size_t count, const uint8_t *marks,
                                       const BRAssetSendKey *setAside, size_t setAsideCount, size_t i)
{
    size_t j;

    for (j = 0; j < setAsideCount; j++) {
        if (_BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, setAside[j].txid, setAside[j].vout)) return 1;
    }
    for (j = 0; j < count; j++) {
        if ((marks[j] & BR_ASSET_SEND_MARK_SET_ASIDE) &&
            _BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, rows[j].txid, rows[j].vout)) return 1;
    }
    return 0;
}

// Is asset row i left out of this send (an outpoint marked NOT_YET in this choice)?
static inline int _BRAssetSendNotYet(const BRAssetRow *rows, size_t count, const uint8_t *marks, size_t i)
{
    size_t j;

    for (j = 0; j < count; j++) {
        if ((marks[j] & BR_ASSET_SEND_MARK_NOT_YET) &&
            _BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, rows[j].txid, rows[j].vout)) return 1;
    }
    return 0;
}

// Is asset row i confirmed for assetId at its quantity: kept so by the platform, or marked so here?
static inline int _BRAssetSendConfirmed(const BRAssetRow *rows, size_t count, const uint8_t *marks, const char *assetId,
                                        const BRAssetSendKey *verified, size_t verifiedCount, size_t i)
{
    size_t j;

#if ! (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_CONFIRMED_ASKED)
    for (j = 0; j < verifiedCount; j++) {
        if (_BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, verified[j].txid, verified[j].vout) &&
            verified[j].assetId && strcmp(verified[j].assetId, assetId) == 0 && verified[j].quantity == rows[i].assetQuantity)
            return 1;
    }
#else
    (void)verified; (void)verifiedCount;
#endif
    for (j = 0; j < count; j++) {
        if ((marks[j] & BR_ASSET_SEND_MARK_VERIFIED) && rows[j].assetQuantity == rows[i].assetQuantity &&
            _BRAssetSendSameOutpoint(rows[i].txid, rows[i].vout, rows[j].txid, rows[j].vout)) return 1;
    }
    return 0;
}

// Is any answer one whose entries are NULL while its entryCount is above 0 (C only)?
static inline int _BRAssetSendAnswersMalformed(const BRAssetSendLookup *answers, size_t answerCount)
{
    size_t j;

#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_NULL_ENTRIES_JUDGED)
    (void)answers; (void)answerCount; (void)j;
    return 0;
#else
    for (j = 0; j < answerCount; j++) {
        if (answers[j].entryCount > 0 && ! answers[j].entries) return 1;
    }
    return 0;
#endif
}

// The answer given for asset row i (its txid as written, and its vout), or NULL.
static inline const BRAssetSendLookup *_BRAssetSendAnswerFor(const BRAssetRow *row, const BRAssetSendLookup *answers,
                                                             size_t answerCount)
{
    size_t j;

    for (j = 0; j < answerCount; j++) {
        if (answers[j].vout == row->vout && strcmp(_BRAssetSendTxid(answers[j].txid), _BRAssetSendTxid(row->txid)) == 0)
            return &answers[j];
    }
    return NULL;
}

// What to send of `quantity` units of assetId (see THE CHOICE and THE CHOICE IS A STEP FUNCTION).
//   ruleState          the asset's transfer-rule state (BRAssetRuleStateForAsset)
//   hasStackSource     0 when there is no indexer to ask (Kotlin: a null source)
//   assetRows          the wallet's rows of this asset; dgbRows its plain coins, dgbParentHasData[j] whether
//                      the transaction that created dgbRows[j] has a data output
//   verified, setAside what the platform kept from earlier choices; answers: this choice's answers so far
//   marks              marksCap >= assetCount bytes, written: what to keep (see above)
//   work               BRAssetSendWorkLength(assetCount, dgbCount) entries; the plan's index lists point into it
static inline BRAssetSendOutcome BRAssetSendChoose(BRSweepRuleState ruleState, int hasStackSource, const char *assetId,
                                                   const BRAssetRow *assetRows, size_t assetCount,
                                                   const BRAssetRow *dgbRows, const BRAssetFact *dgbParentHasData,
                                                   size_t dgbCount, int64_t quantity, int64_t feePerKb,
                                                   const BRAssetSendKey *verified, size_t verifiedCount,
                                                   const BRAssetSendKey *setAside, size_t setAsideCount,
                                                   const BRAssetSendLookup *answers, size_t answerCount,
                                                   uint8_t *marks, size_t marksCap, size_t *work, size_t workCap)
{
    // Bit 0x80 of marks: not a candidate this round. Set at the start of a round, cleared before it plans.
    const uint8_t OUT = 0x80;
    BRAssetSendOutcome o;
    BRAssetSendKind refusal;
    size_t round, i, t, *members, *assetOrder, *feeSet, *dgbOrder;
    int64_t total = 0;

    if (marks && marksCap >= assetCount && assetCount > 0) memset(marks, 0, assetCount);   // nothing to keep yet
    if (! BRAssetSendGate(ruleState, &refusal)) return _BRAssetSendAnswer(refusal);
    if (quantity <= 0) return _BRAssetSendNotPlanned(BR_ASSET_PLAN_WHY_QUANTITY);
    if (feePerKb < 0) return _BRAssetSendNotPlanned(BR_ASSET_PLAN_WHY_FEE_RATE);
    if (assetCount == 0) return _BRAssetSendNotPlanned(BR_ASSET_PLAN_WHY_NO_ASSET_UTXOS);
    if (! hasStackSource) return _BRAssetSendAnswer(BR_ASSET_SEND_UNVERIFIED);
    if (! assetId || ! assetRows || (dgbCount > 0 && (! dgbRows || ! dgbParentHasData)) ||
        (verifiedCount > 0 && ! verified) || (setAsideCount > 0 && ! setAside) || (answerCount > 0 && ! answers) ||
        _BRAssetSendAnswersMalformed(answers, answerCount))
        return _BRAssetSendNotPlanned(BR_ASSET_PLAN_WHY_ARGUMENTS);   // marks were cleared above: nothing is kept
    if (! marks || marksCap < assetCount || ! work || workCap < BRAssetSendWorkLength(assetCount, dgbCount))
        return _BRAssetSendAnswer(BR_ASSET_SEND_CAPACITY);

    for (i = 0; i < assetCount; i++) total = _BRAssetHoldSaturatingAdd(total, assetRows[i].assetQuantity);
    if (total < quantity) {
        o = _BRAssetSendNotPlanned(BR_ASSET_PLAN_WHY_NOT_ENOUGH_ASSET);
        o.plan.required = quantity;
        o.plan.available = total;
        return o;
    }

    members = work;
    assetOrder = work + assetCount;
    feeSet = work + 2 * assetCount;
    dgbOrder = work + 2 * assetCount + dgbCount;

    // Each round plans and confirms, stops, or leaves at least one more coin out; the coins bound the rounds.
    for (round = 0; round <= assetCount; round++) {
        BRAssetSourceGroup group;
        int64_t largest = 0, candidates = 0;
        size_t k = 0, f = 0;
        int found, allConfirmed = 1;

        for (i = 0; i < assetCount; i++) {
            if (_BRAssetSendSetAside(assetRows, assetCount, marks, setAside, setAsideCount, i) ||
                _BRAssetSendNotYet(assetRows, assetCount, marks, i)) marks[i] |= OUT;
            else candidates = _BRAssetHoldSaturatingAdd(candidates, assetRows[i].assetQuantity);
        }
        memset(&group, 0, sizeof(group));
        found = _BRAssetSendBestGroup(assetRows, assetCount, marks, OUT, quantity, &group, &largest);
        if (found) {
            for (i = 0; i < assetCount; i++) {
                if (! (marks[i] & OUT) && _BRAssetSendSameGroup(assetRows, i, group.first)) members[k++] = i;
            }
        }
        for (i = 0; i < assetCount; i++) marks[i] &= (uint8_t)~OUT;

        if (! found) {
            if (candidates >= quantity) {
                o = _BRAssetSendAnswer(BR_ASSET_SEND_SPANS_ADDRESSES);
                o.largestSingleSource = largest;
                return o;
            }
            return _BRAssetSendAnswer(BR_ASSET_SEND_UNCONFIRMED);
        }

        for (i = 0; i < dgbCount; i++) {
            if (BRAssetFeeCoinEligible(dgbRows[i].script, dgbRows[i].scriptLen, assetRows[group.first].script,
                                       assetRows[group.first].scriptLen, dgbParentHasData[i])) feeSet[f++] = i;
        }

        o = _BRAssetSendAnswer(BR_ASSET_SEND_PLANNED);
        _BRAssetPlan(assetRows, members, k, dgbRows, feeSet, f, quantity, feePerKb, assetOrder, dgbOrder, &o.plan);
        if (o.plan.status == BR_ASSET_PLAN_CAPACITY) return _BRAssetSendAnswer(BR_ASSET_SEND_CAPACITY);
        if (o.plan.status != BR_ASSET_PLAN_READY) {
            o.kind = BR_ASSET_SEND_NOT_PLANNED;
            o.feeCoinRule = (o.plan.why == BR_ASSET_PLAN_WHY_NOT_ENOUGH_DGB && f < dgbCount);
            return o;
        }

        for (t = 0; t < o.plan.assetInputCount; t++) {
            size_t r = o.plan.assetInputs[t];
            const BRAssetSendLookup *a;
            BRAssetInputVerdict verdict;

            if (_BRAssetSendConfirmed(assetRows, assetCount, marks, assetId, verified, verifiedCount, r)) continue;
            a = _BRAssetSendAnswerFor(&assetRows[r], answers, answerCount);
            if (! a) {
                o = _BRAssetSendAnswer(BR_ASSET_SEND_LOOKUP);
                o.lookupRow = r;
                return o;
            }
            verdict = BRAssetInputJudge(a->lookup, a->entries, a->entryCount, assetId, assetRows[r].assetQuantity);
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_NO_ANSWER_GOES_ON)
            if (verdict == BR_ASSET_INPUT_UNAVAILABLE) verdict = BR_ASSET_INPUT_MISMATCH;
#endif
            if (verdict == BR_ASSET_INPUT_VERIFIED) marks[r] |= BR_ASSET_SEND_MARK_VERIFIED;
            else if (verdict == BR_ASSET_INPUT_MISMATCH) {
                // Kept for good only when the indexer positively reports other contents.
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_NOT_YET_KEPT)
                marks[r] |= BR_ASSET_SEND_MARK_SET_ASIDE;
#else
                if (a->lookup == BR_ASSET_STACK_FOUND && a->entryCount > 0) marks[r] |= BR_ASSET_SEND_MARK_SET_ASIDE;
                else marks[r] |= BR_ASSET_SEND_MARK_NOT_YET;
#endif
                allConfirmed = 0;
            }
            else return _BRAssetSendAnswer(BR_ASSET_SEND_UNVERIFIED);
        }
        if (allConfirmed) return o;
    }

    return _BRAssetSendAnswer(BR_ASSET_SEND_UNCONFIRMED);
}

// ---- a typed quantity (Kotlin: AssetQuantity) ---------------------------------------------------

// The code point starting at s[i] and its length in bytes, when s[i, end) starts with a well-formed
// UTF-8 sequence; 0 otherwise.
static inline size_t _BRAssetUtf8At(const unsigned char *s, size_t i, size_t end, uint32_t *cp)
{
    unsigned c = s[i];
    size_t n, k;
    uint32_t v;

    if (c < 0x80) { *cp = c; return 1; }
    if (c >= 0xc2 && c <= 0xdf) { n = 2; v = c & 0x1f; }
    else if (c >= 0xe0 && c <= 0xef) { n = 3; v = c & 0x0f; }
    else if (c >= 0xf0 && c <= 0xf4) { n = 4; v = c & 0x07; }
    else return 0;
    if (end - i < n) return 0;
    for (k = 1; k < n; k++) {
        if ((s[i + k] & 0xc0) != 0x80) return 0;
        v = (v << 6) | (s[i + k] & 0x3f);
    }
    if ((n == 3 && (v < 0x800 || (v >= 0xd800 && v <= 0xdfff))) || (n == 4 && (v < 0x10000 || v > 0x10ffff))) return 0;
    *cp = v;
    return n;
}

// Kotlin's Char.isWhitespace (Character.isWhitespace or isSpaceChar).
static inline int _BRAssetIsWhitespace(uint32_t c)
{
    return (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x20) || c == 0xa0 || c == 0x1680 ||
           (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000;
}

// The units of an asset with `divisibility` decimals that text[0, len) names (see A TYPED QUANTITY):
// 1 and *units, or 0 when it names no positive quantity of such an asset. text need not be NUL-terminated.
static inline int BRAssetAmountParse(const char *text, size_t len, int32_t divisibility, int64_t *units)
{
    const unsigned char *s = (const unsigned char *)text;
    size_t start = 0, end = len, i, commas = 0, normalLen, digits = 0, scale = 0, used = 0;
    int dot = 0, points = 0, mode;
    uint64_t v = 0;
    uint32_t cp;

    if (units) *units = 0;
    if (! text || ! units || divisibility < 0 || divisibility > BR_ASSET_MAX_DIVISIBILITY) return 0;

    for (;;) {   // leading whitespace
        size_t n;

        if (start >= end) break;
        n = _BRAssetUtf8At(s, start, end, &cp);
        if (n == 0 || ! _BRAssetIsWhitespace(cp)) break;
        start += n;
    }
    for (;;) {   // trailing whitespace: the last whole code point
        size_t back, n = 0;

        if (end <= start) break;
        for (back = 1; back <= 4 && back <= end - start; back++) {
            if (_BRAssetUtf8At(s, end - back, end, &cp) == back) { n = back; break; }
        }
        if (n == 0 || ! _BRAssetIsWhitespace(cp)) break;
        end -= n;
    }

    for (i = start; i < end; i++) {
        if (s[i] == ',') commas++;
        else if (s[i] == '.') dot = 1;
    }
    // The separators (DgbAmount.normalizeSeparators): 0 as is, 1 commas dropped, 2 the comma is the point.
    if (commas == 0) mode = 0;
    else if (dot) mode = 1;
    else if (commas == 1) mode = 2;
    else return 0;
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_PARSE_COMMA_GROUPS)
    if (mode == 2) mode = 1;
#endif
    normalLen = (end - start) - (mode == 1 ? commas : 0);
    if (normalLen == 0) return 0;
#if ! (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_PARSE_UNBOUNDED)
    if (normalLen > BR_ASSET_AMOUNT_MAX_TEXT) return 0;
#endif

    for (i = start; i < end; i++) {
        unsigned char c = s[i];

        if (c == ',') {
            if (mode == 1) continue;
            c = '.';
        }
        if (c == '.') {
            if (++points > 1) return 0;
            continue;
        }
        if (c < '0' || c > '9') return 0;   // Kotlin's filter takes any Unicode digit; its BigDecimal read does not
        digits++;
        if (points) {
            scale++;
            if ((int32_t)scale > divisibility) {
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_PARSE_ROUNDS)
                continue;
#else
                return 0;
#endif
            }
            used++;
        }
        if (v > (UINT64_C(0x7fffffffffffffff) - (uint64_t)(c - '0')) / 10) return 0;
        v = v * 10 + (uint64_t)(c - '0');
    }
    if (digits == 0) return 0;

    for (i = used; (int32_t)i < divisibility; i++) {
        if (v > UINT64_C(0x7fffffffffffffff) / 10) return 0;
        v *= 10;
    }
#if (ASSET_SEND_PLAN_UNFIXED & ASSET_SEND_PLAN_RED_PARSE_ZERO)
    *units = (int64_t)v;
    return 1;
#else
    if (v == 0) return 0;
    *units = (int64_t)v;
    return 1;
#endif
}

// `units` of an asset with `divisibility` decimals as plain text (Kotlin: AssetQuantity.format): no
// grouping, exponent or trailing zero, no locale; "-" before a negative count; a divisibility below 0
// read as 0. Into out[0, n) and terminated; returns n, or 0 when out has room for fewer than n + 1 bytes.
static inline size_t BRAssetAmountFormat(int64_t units, int32_t divisibility, char *out, size_t cap)
{
    char rev[20];
    size_t nd = 0, scale = divisibility > 0 ? (size_t)divisibility : 0, len, at = 0, i, low = 0;
    uint64_t mag = units < 0 ? (uint64_t)(-(units + 1)) + 1 : (uint64_t)units;
    int neg = units < 0;

    if (out && cap > 0) out[0] = '\0';
    if (units == 0) {
        if (! out || cap < 2) return 0;
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }

    do { rev[nd++] = (char)('0' + mag % 10); mag /= 10; } while (mag);   // least significant first
    while (scale > 0 && low < nd && rev[low] == '0') { low++; scale--; }   // trailing zeros of the fraction
    nd -= low;

    len = (size_t)neg + (scale == 0 ? nd : (nd > scale ? nd + 1 : 2 + scale));
    if (! out || cap < len + 1) return 0;

    if (neg) out[at++] = '-';
    if (scale == 0) {
        for (i = nd; i > 0; i--) out[at++] = rev[low + i - 1];
    }
    else if (nd > scale) {
        for (i = nd; i > 0; i--) {
            out[at++] = rev[low + i - 1];
            if (i - 1 == scale) out[at++] = '.';
        }
    }
    else {
        out[at++] = '0';
        out[at++] = '.';
        for (i = nd; i < scale; i++) out[at++] = '0';
        for (i = nd; i > 0; i--) out[at++] = rev[low + i - 1];
    }
    out[at] = '\0';
    return at;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetSendPlan_h
