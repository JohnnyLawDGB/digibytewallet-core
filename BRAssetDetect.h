//
//  BRAssetDetect.h
//
//  DigiAsset DETECTION: what the wallet writes about its own outputs of one transaction that carries a
//  DigiAsset payload. Until 2026-11 this lived only in Android's Kotlin (core/.../asset/AssetManager.kt:
//  processIncomingAssetTx up to its writes and the decisions after them, persistDetectedAssetOutput as it
//  calls it, walkFactsForCreditedAssets' choice of what to walk, the issuance walk's rename by
//  utxoDao.replaceAssetId, transferRuleState as transferOutputCredits asks it; AssetTxQuantity.kt:
//  forOutput, implicitChange, forOutputTotal). THE RULES below are its answers.
//
//  A STEP FUNCTION OVER DATA. The platform passes the transaction, the wallet's other transactions, the
//  scripts it owns, its stored rows (BRAssetRow, BRAssetHoldings.h), its remainder proofs and, when the
//  detection asks for them, what it knows of some assets' transfer rules. The core answers what to write.
//  It never calls out, fetches, stores or reads a clock; the platform schedules, fetches and stores.
//
//  THE RULES (BRAssetDetect):
//    - THE CARRIER is THE PASS's (BRAssetHoldCarrierOf, BRAssetHold.h): among the OP_RETURN outputs that
//      are DigiAsset carriers, the first one that cannot be classified, otherwise the last one. A
//      transaction with no outputs, or no carrier, is NOT_ASSET: nothing is written.
//    - THE PLACEHOLDER, the asset id the transaction's rows carry until the asset is named: a LOCKED
//      ISSUANCE is named at once by its first input (BRAssetIdForIssuance: that input's txid in display
//      order, lower case, and its index, which must be within INT32_MAX; the header's aggregation and
//      divisibility); anything else, and an issuance whose id is refused, is "unresolved:<txid>"
//      (BR_ASSET_UNRESOLVED_PREFIX, the txid in display order, lower case).
//    - WHAT THE INPUTS CARRIED (BRAssetHoldInputFacts, BRAssetHold.h): THE WALK in the decoder's
//      reading, the inputs it cannot read passed over, then the remainder proof. It feeds the claim, the
//      `targeted` answer and nothing else.
//    - THE OUTPUTS THAT GET A ROW: every output that is not OP_RETURN (a script whose first byte is 0x6a)
//      and whose script is one of `owned`; with no owned scripts (ownedCount 0: the platform could not
//      build the set) every output that is not OP_RETURN.
//    - A CARRIER THAT CANNOT BE CLASSIFIED (UNCLASSIFIABLE): nothing is written; every output that would
//      get a row is `targeted` (hold it), credited nothing, and not asked about.
//    - ALL SETTLED. When every output that gets a row already has a row whose credit is settled
//      (BRAssetCreditIsSettled), nothing is allocated again: every credit is UNKNOWN, which leaves those
//      rows as they are (BRAssetPersistDetectedOutput re-tags them NATIVE and nothing else).
//    - THE CREDIT of each output (BRAssetAllocate.h). An issuance: BRAssetAllocateIssuance under the
//      placeholder. A transfer or burn: BRAssetAllocate over the inputs' stacks (BRAssetBackedInputStack,
//      from each input's row and the funding transaction's facts); every input when all of them can be
//      read, otherwise one input that is not known. An asset on a stack counts as free of transfer rules
//      only when BRAssetRuleStateForAsset (BRAssetRuleGate.h) answers NONE from what the platform said of
//      it (BRAssetDetectRule: the store's issuance facts as BRAssetIssuanceFactsMatch takes them, and the
//      proxy's rules answer); an asset it has said nothing of is asked about (NEEDS_RULES) before anything
//      is allocated. A payload not read exactly (BRAssetPayloadReadsExactly) is not allocated, and asks
//      nothing. The output's credit is BRAssetCreditForOutput.
//    - THE CLAIM of each output (BRAssetClaimForOutputTotal): what the instructions assign it, plus, on
//      the last output, the remainder. It is the quantity an UNCHECKED row stores, which the hold reads.
//    - THE WRITE of each output is BRAssetPersistDetectedOutput (BRAssetHoldings.h) with the placeholder,
//      the claim and the credit: nothing for the change of our own unconfirmed send, a re-tag (and, for a
//      row not settled, a settlement or a raised claim) for a row the table holds, an insert otherwise.
//    - THE INDEXER is asked about an output (askIndexer) when its credit is UNKNOWN, the transaction is
//      not our own unconfirmed send, and the owned set is not empty (the indexer is told nothing about an
//      output that may be someone else's). Its answer is held to `bound` (BRAssetMaxDeliverable).
//    - THE ISSUANCE WALK is due (issuanceWalkDue) for an issuance when a write left a row unresolved and
//      the placeholder is an "unresolved:" id, or when the walk has not answered for this transaction in
//      this process (walkedInSession 0): the walk also brings the issuance's facts, which the rule gate reads.
//    - `targeted`: BRAssetTargetsOutput with what the inputs carried (Kotlin: protectTargetedOutputs).
//      The hold itself is BRAssetHold.h's pass, which is never weaker than this.
//
//  THE RENAME (BRAssetDetectRename; Kotlin: utxoDao.replaceAssetId after the issuance walk): every row
//  whose asset id is the placeholder, byte for byte, is renamed to the id the walk named, when that id
//  differs from it. Only an "unresolved:" placeholder is renamed, and only when the transaction's carrier
//  is its FIRST OP_RETURN output (carrierIsFirstOpReturn): the walk reads a transaction by its first
//  OP_RETURN (BRAssetProvenance.h, ONE HOP), and its answer names this transaction's asset only when that
//  is the carrier detection read it by. A derived id is never renamed.
//
//  THE FACTS WALK (BRAssetDetectFactsWalk; Kotlin: walkFactsForCreditedAssets), for a transfer or burn,
//  over the rows after the writes and the indexer's answers: the assets the transaction's own rows name
//  whose credit counts (BRAssetCreditCounts) with a quantity above zero, ids that are not empty and not a
//  placeholder, each once in row order. Nothing when the walk has answered for this transaction in this
//  process or no row names one; LATER within BR_ASSET_FACTS_WALK_RETRY_MS of the last attempt; otherwise
//  NOW, and the platform records the time, finds each asset's facts (BRAssetFactsForNamedAssetBegin) and,
//  when it found all of them, marks the transaction walked and forgets the time.
//
//  WHAT THE CALLER DOES, IN ORDER, for one transaction:
//    1. BRAssetDetectBounds, and buffers of those sizes (they may be kept from call to call).
//    2. BRAssetDetect. NEEDS_RULES: answer every id in asks[0, askCount) (an answer may say nothing is
//       known: issuance NULL, hasApiRules 0) and call again with all the answers. Any refusal: write
//       nothing. NOT_ASSET: nothing to do. UNCLASSIFIABLE: nothing to write.
//    3. DONE: for each output in outputs[0, outputCount), in order, apply `persist` (INSERT or UPDATE the
//       row at the output's outpoint; NOTHING writes nothing), then, when askIndexer is set, ask
//       BRAssetIndexerAskDecide about the row as it now is and, on NOW, the indexer, and settle the row by
//       BRAssetStackAnswerAccept(..., bound, placeholder).
//    4. When issuanceWalkDue: walk from the txid (BRAssetWalkBegin, not forced). On an answer: mark the
//       transaction walked for the process, apply BRAssetDetectRename to the rows, and store the facts.
//    5. For a transfer or burn: BRAssetDetectFactsWalk over the rows as they now are.
//  Detection is run again whenever the transaction is seen again (a sweep, a restart); every step above
//  is safe to repeat.
//
//  REFUSALS. The answer is DONE, NOT_ASSET, UNCLASSIFIABLE or NEEDS_RULES only when everything was read;
//  every refusal writes nothing and is not "nothing to write". ARGUMENTS: a NULL where a value is needed
//  (buffers included), or a test seam this build does not offer. UNREADABLE: the transaction or one of
//  the wallet's cannot be read (BRAssetHoldCarrierOf), or has an output whose value is past INT64_MAX (no
//  transaction the chain accepts has one, and a row stores the value as int64). ROWS: a row that is not
//  an asset row, whose txid is not 64 lower-case hex digits or whose vout is negative, or two rows for one
//  outpoint that differ in quantity, spent flag, credit or asset id. CAPACITY: a buffer smaller than
//  BRAssetDetectBounds says (`needs` then holds what suffices). The status 0 is a refusal, so an answer
//  nobody filled refuses.
//
//  POINTERS. The answer points into `out` (txid, placeholder), the view's rows (asset ids, an existing
//  row's script) and the transaction (scripts): keep them alive, and do not move `out`, while the answer
//  is read. No allocation, no network, no clock, no I/O. Header-only, static inline; its includes are libc
//  and the core headers whose types or functions it uses. BRAssetHold.h calls BRDigiAsset.c's classifier,
//  and BRAssetIdForIssuance needs BRCrypto.c and BRBase58.c, so a program that calls BRAssetDetect links
//  those. It reads no build-time policy macro. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_detect_kat in the Android repo): ASSET_DETECT_UNFIXED, tested by VALUE as a
//  set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is what ships.
//    1      ASSET_DETECT_RED_OWNERSHIP_IGNORED   an output that is not the wallet's own gets a row.
//    2      ASSET_DETECT_RED_OPRETURN_ROWS       an OP_RETURN output gets a row.
//    4      ASSET_DETECT_RED_EMPTY_OWNED_NONE    with no owned scripts no output gets a row.
//    8      ASSET_DETECT_RED_SETTLED_REALLOCATED a transaction whose rows are all settled is allocated again.
//    16     ASSET_DETECT_RED_INPUT_DROPPED       an input the allocation cannot read is passed over.
//    32     ASSET_DETECT_RED_PLACEHOLDER_ALWAYS  a locked issuance is not named by its first input.
//    64     ASSET_DETECT_RED_RULES_UNKNOWN_FREE  an asset whose rule state is UNKNOWN counts as rule-free.
//    128    ASSET_DETECT_RED_RULES_UNASKED_FREE  an asset nothing was said of counts as rule-free, unasked.
//    256    ASSET_DETECT_RED_ASK_UNOWNED         the indexer is asked with no owned set.
//    512    ASSET_DETECT_RED_ASK_OUTGOING        the indexer is asked about our own unconfirmed send.
//    1024   ASSET_DETECT_RED_RENAME_ANY          the rename takes any placeholder, whatever the carrier.
//    2048   ASSET_DETECT_RED_WALK_ONCE_DROPPED   the issuance walk is due only while a row is unresolved.
//    4096   ASSET_DETECT_RED_FACTS_UNCOUNTED     the facts walk names rows whose credit does not count.
//    8192   ASSET_DETECT_RED_CLAIM_EARLIER_RULE  the claim is BRAssetQuantityForOutputTotal's.
//    16384  ASSET_DETECT_RED_DUPLICATE_ROWS      two rows for one outpoint that differ in credit or id are read.
//    32768  ASSET_DETECT_RED_UNCLASSIFIABLE_ROWS a carrier that cannot be classified writes UNCHECKED rows.
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

#ifndef BRAssetDetect_h
#define BRAssetDetect_h

#include "BRAssetAllocate.h"     // BRAssetAllocate, BRAssetAllocateIssuance, BRAssetCreditForOutput, BRAssetMaxDeliverable
#include "BRAssetDecode.h"       // BRAssetHeader, BRAssetPayloadReadsExactly, BR_ASSET_MAX_INSTRUCTIONS
#include "BRAssetHold.h"         // BRAssetHoldCarrierOf, BRAssetHoldInputFacts, BRAssetHoldRow, BRAssetHoldWork
#include "BRAssetHoldings.h"     // BRAssetRow, BRAssetScript, BRAssetPersistDetectedOutput, BRAssetIdIsUnresolved
#include "BRAssetId.h"           // BRAssetIdForIssuance, BR_ASSET_ID_BUFFER
#include "BRAssetProvenance.h"   // BRAssetResolvedFacts, BRAssetIssuanceFactsMatch, BR_ASSET_TXID_BUFFER
#include "BRAssetQuantity.h"     // BRAssetTargetsOutput, BRAssetAssignedUnits, BRAssetQuantityForOutputTotal
#include "BRAssetRuleGate.h"     // BRAssetRuleStateForAsset
#include "BRInt.h"               // UInt256
#include "BRTransaction.h"       // BRTransaction
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_DETECT_UNFIXED
#define ASSET_DETECT_UNFIXED 0
#endif

#define ASSET_DETECT_RED_OWNERSHIP_IGNORED   1
#define ASSET_DETECT_RED_OPRETURN_ROWS       2
#define ASSET_DETECT_RED_EMPTY_OWNED_NONE    4
#define ASSET_DETECT_RED_SETTLED_REALLOCATED 8
#define ASSET_DETECT_RED_INPUT_DROPPED       16
#define ASSET_DETECT_RED_PLACEHOLDER_ALWAYS  32
#define ASSET_DETECT_RED_RULES_UNKNOWN_FREE  64
#define ASSET_DETECT_RED_RULES_UNASKED_FREE  128
#define ASSET_DETECT_RED_ASK_UNOWNED         256
#define ASSET_DETECT_RED_ASK_OUTGOING        512
#define ASSET_DETECT_RED_RENAME_ANY          1024
#define ASSET_DETECT_RED_WALK_ONCE_DROPPED   2048
#define ASSET_DETECT_RED_FACTS_UNCOUNTED     4096
#define ASSET_DETECT_RED_CLAIM_EARLIER_RULE  8192
#define ASSET_DETECT_RED_DUPLICATE_ROWS      16384
#define ASSET_DETECT_RED_UNCLASSIFIABLE_ROWS 32768

// "unresolved:" and a 64-character txid, and the NUL after it. It also holds a derived id.
#define BR_ASSET_PLACEHOLDER_BUFFER 76
typedef char _BRAssetDetectPlaceholderFits[(sizeof(BR_ASSET_UNRESOLVED_PREFIX) - 1 + BR_ASSET_TXID_LENGTH + 1 ==
                                            BR_ASSET_PLACEHOLDER_BUFFER && BR_ASSET_ID_BUFFER <= BR_ASSET_PLACEHOLDER_BUFFER) ? 1 : -1];

// How long after an attempt at the facts walk of one transaction the next may start: two minutes
// (Android: FACTS_WALK_RETRY_MS).
#define BR_ASSET_FACTS_WALK_RETRY_MS 120000LL

// ---- the claim (Android: AssetTxQuantity.forOutput, implicitChange, forOutputTotal) ---------------
//
// What an output's row claims while nothing backs it. `op` is the header's operation: DA_ISSUANCE,
// DA_TRANSFER and DA_BURN, and anything else is a carrier that is not classified. Kotlin's nullable
// arguments are has/value pairs (`has` 0: null, the value not read). The non-range instruction to output
// 31 destroys its units only in a BURN (BRAssetDestroys).

// What the instructions assign to `vout`: an issuance its whole amount (0 when it has none or a negative
// one) on the first output that is not OP_RETURN, nothing elsewhere; a transfer or burn the amounts of
// the instructions that name it (a range names 0..outputIndex), percent and destroying instructions left
// out; 0 when an amount or index is negative or the sum is past INT64_MAX; 0 for a carrier that is not
// classified. instCount above zero with no array is 0.
static inline int64_t BRAssetClaimForOutput(BRAssetOperation op, int hasTotalQuantity, int64_t totalQuantity,
                                            const BRAssetTransferInstruction *insts, size_t instCount,
                                            int32_t vout, int hasFirstNonOpReturnVout, int32_t firstNonOpReturnVout)
{
    int64_t sum = 0;
    size_t i;

    if (op == DA_ISSUANCE) {
        if (! hasFirstNonOpReturnVout || vout != firstNonOpReturnVout) return 0;
        return (hasTotalQuantity && totalQuantity > 0) ? totalQuantity : 0;
    }
    if (op != DA_TRANSFER && op != DA_BURN) return 0;
    if (instCount > 0 && ! insts) return 0;

    for (i = 0; i < instCount; i++) {
        const BRAssetTransferInstruction *in = &insts[i];

        if (in->percent || BRAssetDestroys(op, in)) continue;
        if (in->amount < 0 || in->outputIndex < 0) return 0;
        if (! (in->range ? (vout <= in->outputIndex) : (in->outputIndex == vout))) continue;
        if (! _BRAssetAddUnits(sum, in->amount, &sum)) return 0;
    }

    return sum;
}

// What the instructions leave for the last output, in *out, and 1; 0 (Kotlin: null, *out 0) when it is
// not known. An issuance leaves 0 (its amount is claimed on the issuer's output). A carrier that is not
// classified, units that came in unknown or negative, or instructions whose draw is not a count
// (BRAssetAssignedUnits): not known. Instructions that draw more than came in leave all of it.
static inline int BRAssetClaimRemainder(BRAssetOperation op, const BRAssetTransferInstruction *insts, size_t instCount,
                                        int hasInputUnits, int64_t inputUnits, int64_t *out)
{
    int64_t assigned = 0;

    if (! out) return 0;
    *out = 0;
    if (op == DA_ISSUANCE) return 1;
    if (op != DA_TRANSFER && op != DA_BURN) return 0;
    if (! hasInputUnits || inputUnits < 0) return 0;
    if (! BRAssetAssignedUnits(op, insts, instCount, &assigned)) return 0;
    *out = (assigned > inputUnits) ? inputUnits : inputUnits - assigned;
    return 1;
}

// The claim of `vout`: BRAssetClaimForOutput, plus BRAssetClaimRemainder when `vout` is the last output
// (outputCount - 1); a remainder not known adds nothing, and a sum past INT64_MAX is 0.
static inline int64_t BRAssetClaimForOutputTotal(BRAssetOperation op, int hasTotalQuantity, int64_t totalQuantity,
                                                 const BRAssetTransferInstruction *insts, size_t instCount,
                                                 int32_t vout, int hasFirstNonOpReturnVout, int32_t firstNonOpReturnVout,
                                                 int hasInputUnits, int64_t inputUnits, int32_t outputCount)
{
    int64_t explicitUnits, change = 0, total = 0;

#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_CLAIM_EARLIER_RULE)
    (void)hasTotalQuantity;
    (void)explicitUnits;
    (void)change;
    if (BRAssetQuantityForOutputTotal(op, totalQuantity, vout, hasFirstNonOpReturnVout ? firstNonOpReturnVout : -1,
                                      hasInputUnits, inputUnits, outputCount, insts, instCount, &total) != BRAssetQuantityOK) return 0;
    return total;
#else
    explicitUnits = BRAssetClaimForOutput(op, hasTotalQuantity, totalQuantity, insts, instCount, vout,
                                          hasFirstNonOpReturnVout, firstNonOpReturnVout);
    if (vout != _BRAssetLastVout(outputCount)) return explicitUnits;
    if (! BRAssetClaimRemainder(op, insts, instCount, hasInputUnits, inputUnits, &change)) return explicitUnits;
    return _BRAssetAddUnits(explicitUnits, change, &total) ? total : 0;
#endif
}

// ---- the rules answer ----------------------------------------------------------------------------

// What the platform knows of one asset's transfer rules, for an id the detection asked about.
typedef struct {
    const char *assetId;                     // the id asked about
    const BRAssetResolvedFacts *issuance;    // the store's issuance facts for it; NULL: none
    int hasApiRules;                         // the proxy answered (Android: rulesJsonFor is not null)
    int apiRules;                            // with a rules object of at least one member
} BRAssetDetectRule;

// Is the asset free of transfer rules, as far as the wallet can prove? Kotlin: transferRuleState(assetId)
// == NONE. Facts BRAssetIssuanceFactsMatch does not take for the id are none.
static inline int BRAssetDetectRuleFree(const BRAssetDetectRule *answer)
{
    const BRAssetResolvedFacts *f;
    BRSweepRuleState state;

    if (! answer || ! answer->assetId) return 0;
    f = BRAssetIssuanceFactsMatch(answer->issuance, answer->assetId) ? answer->issuance : NULL;
    state = BRAssetRuleStateForAsset(answer->assetId, f ? f->assetId : NULL, f ? f->hasIssuanceOpcode : 0,
                                     f ? f->issuanceOpcode : 0, f ? f->hasIssuanceLocked : 0, f ? f->issuanceLocked : 0,
                                     answer->hasApiRules, answer->apiRules);
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_RULES_UNKNOWN_FREE)
    return state != BR_SWEEP_RULE_BOUND;
#else
    return state == BR_SWEEP_RULE_NONE;
#endif
}

// ---- the types -----------------------------------------------------------------------------------

// What the detection reads.
typedef struct {
    const BRTransaction *tx;                 // the transaction to detect
    int64_t blockHeight;                     // what a new row is written with (0: not confirmed)
    int isOutgoingUnconfirmed;               // BRAssetTxIsOutgoingUnconfirmed of tx
    const BRTransaction *const *txs;         // every transaction the wallet holds (tx may be one of them)
    size_t txCount;
    const BRAssetScript *owned;              // the wallet's own scripts; ownedCount 0: the set could not be built
    size_t ownedCount;
    const BRAssetRow *rows;                  // the wallet's asset rows, spent ones included
    size_t rowCount;
    const UInt256 *proven;                   // txids whose last output is proven to carry no units
    size_t provenCount;
    const BRAssetDetectRule *rules;          // answers to the ids asked about so far
    size_t ruleCount;
    int walkedInSession;                     // the issuance walk has answered for tx in this process
} BRAssetDetectView;

// The sizes the caller's buffers need (BRAssetDetectBounds).
typedef struct {
    size_t work;                             // BRAssetHoldWork entries
    size_t holdRows;                         // BRAssetHoldRow entries
    size_t inputs;                           // entries of inputs, inputRows, slots, stacks, allocWork and asks
    size_t outputs;                          // entries of outputRows and outputs
    size_t delivered;                        // BRAssetOutputUnits entries
} BRAssetDetectNeeds;

// One output that gets a row, and what to do with it.
typedef struct {
    int32_t vout;
    int targeted;                            // BRAssetTargetsOutput: may carry units (Android holds it at once)
    int64_t claimed;                         // BRAssetClaimForOutputTotal
    BRAssetOutputCredit credit;              // what the wallet can say it holds
    BRAssetPersist persist;                  // the write (BRAssetPersistDetectedOutput)
    int askIndexer;                          // ask the indexer about it after the write
    BRAssetDeliverable bound;                // what an indexer's count for it is held to
} BRAssetDetectOutput;

// The caller's buffers, sized by BRAssetDetectBounds. A buffer of capacity 0 may be NULL.
typedef struct {
    BRAssetHoldWork *work;
    size_t workCap;
    BRAssetHoldRow *holdRows;                // the rows as BRAssetHold.h reads them, one per view row
    size_t holdRowCap;
    BRAssetInputFacts *inputs;               // inputCap entries each:
    size_t *inputRows;
    BRAssetUnits *slots;
    BRAssetInputStack *stacks;
    int64_t *allocWork;
    const char **asks;
    size_t inputCap;
    size_t *outputRows;                      // outputCap entries each:
    BRAssetDetectOutput *outputs;
    size_t outputCap;
    BRAssetOutputUnits *delivered;
    size_t deliveredCap;
} BRAssetDetectBuffers;

// BR_ASSET_DETECT_DONE or why not. 0 is a refusal.
typedef enum {
    BR_ASSET_DETECT_REFUSED = 0,             // nobody filled the answer
    BR_ASSET_DETECT_DONE = 1,                // outputs[0, outputCount): what to write, in order
    BR_ASSET_DETECT_NOT_ASSET = 2,           // no outputs, or no carrier: nothing to write
    BR_ASSET_DETECT_UNCLASSIFIABLE = 3,      // a carrier that cannot be classified: nothing to write; outputs say targeted
    BR_ASSET_DETECT_NEEDS_RULES = 4,         // answer asks[0, askCount) and call again
    BR_ASSET_DETECT_REFUSED_ARGUMENTS = 5,
    BR_ASSET_DETECT_REFUSED_UNREADABLE = 6,
    BR_ASSET_DETECT_REFUSED_ROWS = 7,
    BR_ASSET_DETECT_REFUSED_CAPACITY = 8     // `needs` says what suffices
} BRAssetDetectStatus;

// The answer. The caller owns it; the outputs and asks are in the caller's buffers.
typedef struct {
    BRAssetDetectStatus status;
    char txid[BR_ASSET_TXID_BUFFER];         // display order, lower case
    char placeholder[BR_ASSET_PLACEHOLDER_BUFFER];
    int placeholderDerived;                  // the placeholder is the id derived from the first input
    size_t carrierAt;                        // the carrier's output index
    int carrierIsFirstOpReturn;              // it is the transaction's first OP_RETURN output
    BRAssetHeader header;                    // the carrier's header
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];   // header.instructionCount of them
    int payloadExact;                        // BRAssetPayloadReadsExactly of the carrier
    int hasFirstNonOpReturn;
    int32_t firstNonOpReturn;
    int32_t txOutputCount;
    int hasInputUnits;                       // what the inputs carried, as the claim reads it
    int64_t inputUnits;
    int allSettled;                          // every output that gets a row has a settled row: nothing allocated
    int allocated;                           // `allocation` was made (and the credits read from it)
    BRAssetAllocation allocation;
    size_t outputCount;                      // DONE, UNCLASSIFIABLE: entries in buffers->outputs
    size_t askCount;                         // NEEDS_RULES: entries in buffers->asks
    int anyUnresolved;                       // DONE: a write left a row whose asset is not named
    int issuanceWalkDue;                     // DONE: walk from the txid now
    BRAssetDetectNeeds needs;                // CAPACITY: what suffices
} BRAssetDetection;

// ---- internals -----------------------------------------------------------------------------------

#define _BR_ASSET_DETECT_NONE ((size_t)-1)

static inline size_t _BRAssetDetectAddSat(size_t a, size_t b)
{
    return (b > SIZE_MAX - a) ? SIZE_MAX : a + b;
}

static inline int _BRAssetDetectIsOpReturn(const BRTxOutput *o)
{
    return (o->scriptLen > 0 && o->script[0] == 0x6a) ? 1 : 0;
}

// A txid of 64 lower-case hex digits, display order, as BRTransaction holds it: 1, or 0.
static inline int _BRAssetDetectTxidParse(const char *txid, UInt256 *h)
{
    size_t i;
    int hi, lo;

    if (! txid) return 0;
    for (i = 0; i < BR_ASSET_TXID_LENGTH; i++) {
        char c = txid[i];

        if (! ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    if (txid[BR_ASSET_TXID_LENGTH] != '\0') return 0;

    for (i = 0; i < 32; i++) {
        hi = (txid[2 * i] <= '9') ? txid[2 * i] - '0' : txid[2 * i] - 'a' + 10;
        lo = (txid[2 * i + 1] <= '9') ? txid[2 * i + 1] - '0' : txid[2 * i + 1] - 'a' + 10;
        h->u8[31 - i] = (uint8_t)(hi * 16 + lo);
    }

    return 1;
}

static inline int _BRAssetDetectSameId(const char *a, const char *b)
{
    if (! a || ! b) return a == b;
    return strcmp(a, b) == 0;
}

// Does output j of tx get a row (THE OUTPUTS THAT GET A ROW)?
static inline int _BRAssetDetectGetsRow(const BRAssetDetectView *v, size_t j)
{
    const BRTxOutput *o = &v->tx->outputs[j];

#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_OPRETURN_ROWS)
    if (_BRAssetDetectIsOpReturn(o)) return 0;
#endif
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_EMPTY_OWNED_NONE)
    if (v->ownedCount == 0) return 0;
#else
    if (v->ownedCount == 0) return 1;
#endif
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_OWNERSHIP_IGNORED)
    return 1;
#else
    return _BRAssetHoldOwns(v->owned, v->ownedCount, o->script, o->scriptLen);
#endif
}

// What `out` must hold for the carrier's allocation: the entries BRAssetAllocate(Issuance) says suffice.
static inline size_t _BRAssetDetectDelivered(const BRAssetHeader *h, const BRAssetTransferInstruction *insts,
                                             size_t inCount, size_t outCount)
{
    size_t i, n = (h->operation == DA_ISSUANCE) ? 1 : inCount, each;

    for (i = 0; i < h->instructionCount && i < BR_ASSET_MAX_INSTRUCTIONS; i++) {
        each = 1;
        if (insts[i].range && insts[i].outputIndex >= 0) {
            each = (size_t)insts[i].outputIndex + 1;
            if (each > outCount) each = outCount;
            if (each == 0) each = 1;
        }
        n = _BRAssetDetectAddSat(n, each);
    }

    return n;
}

static inline BRAssetDetectStatus _BRAssetDetectEnd(BRAssetDetection *out, BRAssetDetectStatus status)
{
    out->status = status;
    if (status != BR_ASSET_DETECT_DONE && status != BR_ASSET_DETECT_UNCLASSIFIABLE) out->outputCount = 0;
    if (status != BR_ASSET_DETECT_NEEDS_RULES) out->askCount = 0;
    return status;
}

// ---- the bounds ----------------------------------------------------------------------------------

// What the buffers need for `view`: 1 and *needs, or 0 (and *needs zero) when the view or its
// transaction cannot be read. work: the most of txCount, rowCount and provenCount; holdRows: rowCount;
// inputs: the transaction's inputs; outputs: its outputs; delivered: what its carrier's allocation can
// write (0 with no carrier).
static inline int BRAssetDetectBounds(const BRAssetDetectView *view, BRAssetDetectNeeds *needs)
{
    BRAssetHeader h;
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];
    BRAssetCarrierStatus c;

    if (! needs) return 0;
    memset(needs, 0, sizeof(*needs));
    if (! view || ! view->tx) return 0;
    c = BRAssetHoldCarrierOf(view->tx, NULL, &h, insts);
    if (c == BR_ASSET_CARRIER_UNREADABLE) return 0;

    needs->work = view->txCount;
    if (view->rowCount > needs->work) needs->work = view->rowCount;
    if (view->provenCount > needs->work) needs->work = view->provenCount;
    needs->holdRows = view->rowCount;
    needs->inputs = view->tx->inCount;
    needs->outputs = view->tx->outCount;
    needs->delivered = (c == BR_ASSET_CARRIER_FOUND) ? _BRAssetDetectDelivered(&h, insts, view->tx->inCount, view->tx->outCount) : 0;
    return 1;
}

// ---- the detection -------------------------------------------------------------------------------

// THE RULES over `view`, into `out`, with the caller's buffers (see WHAT THE CALLER DOES). Returns
// out->status.
static inline BRAssetDetectStatus BRAssetDetect(const BRAssetDetectView *view, const BRAssetDetectBuffers *buf,
                                                BRAssetDetection *out)
{
    const BRTransaction *tx;
    BRAssetHoldView hv;
    BRAssetHoldInputs facts;
    BRAssetDetectNeeds needs;
    BRAssetCarrierStatus carrier;
    size_t i, j, k, n, firstOpReturn = _BR_ASSET_DETECT_NONE, stackCount = 0;
    int anyUnreadableInput = 0, isIssuance;

    if (! out) return BR_ASSET_DETECT_REFUSED_ARGUMENTS;
    memset(out, 0, sizeof(*out));
    if (! view || ! buf || ! view->tx || (view->txCount > 0 && ! view->txs) || (view->ownedCount > 0 && ! view->owned) ||
        (view->rowCount > 0 && ! view->rows) || (view->provenCount > 0 && ! view->proven) ||
        (view->ruleCount > 0 && ! view->rules)) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ARGUMENTS);
    for (i = 0; i < view->ownedCount; i++) {
        if (view->owned[i].len > 0 && ! view->owned[i].bytes) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ARGUMENTS);
    }
    tx = view->tx;

    // the transaction and the wallet's, readable; the carrier
    carrier = BRAssetHoldCarrierOf(tx, &out->carrierAt, &out->header, out->insts);
    if (carrier == BR_ASSET_CARRIER_UNREADABLE) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_UNREADABLE);
    for (i = 0; i < view->txCount; i++) {
        if (! _BRAssetHoldTxReadable(view->txs[i])) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_UNREADABLE);
    }
    _BRAssetHopTxidHex(&tx->txHash, out->txid);
    out->txOutputCount = (int32_t)tx->outCount;
    if (tx->outCount == 0 || carrier != BR_ASSET_CARRIER_FOUND) {
        memset(&out->header, 0, sizeof(out->header));
        out->header.kind = BR_ASSET_SCRIPT_NOT_ASSET;
        out->carrierAt = 0;
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_NOT_ASSET);
    }
    for (j = 0; j < tx->outCount; j++) {
        if (tx->outputs[j].amount > (uint64_t)INT64_MAX) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_UNREADABLE);
    }

    // the buffers
    BRAssetDetectBounds(view, &needs);
    if ((buf->workCap > 0 && ! buf->work) || (buf->holdRowCap > 0 && ! buf->holdRows) ||
        (buf->inputCap > 0 && (! buf->inputs || ! buf->inputRows || ! buf->slots || ! buf->stacks || ! buf->allocWork ||
                               ! buf->asks)) ||
        (buf->outputCap > 0 && (! buf->outputRows || ! buf->outputs)) || (buf->deliveredCap > 0 && ! buf->delivered))
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ARGUMENTS);
    if (buf->workCap < needs.work || buf->holdRowCap < needs.holdRows || buf->inputCap < needs.inputs ||
        buf->outputCap < needs.outputs || buf->deliveredCap < needs.delivered) {
        out->needs = needs;
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_CAPACITY);
    }

    // the rows, as BRAssetHold.h reads them
    for (k = 0; k < view->rowCount; k++) {
        const BRAssetRow *r = &view->rows[k];

        if (! r->isAsset || r->vout < 0 || ! _BRAssetDetectTxidParse(r->txid, &buf->holdRows[k].txHash))
            return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ROWS);
        buf->holdRows[k].n = (uint32_t)r->vout;
        buf->holdRows[k].quantity = r->assetQuantity;
        buf->holdRows[k].spent = r->spent ? 1 : 0;
    }

    memset(&hv, 0, sizeof(hv));
    hv.txs = view->txs;
    hv.txCount = view->txCount;
    hv.rows = buf->holdRows;
    hv.rowCount = view->rowCount;
    hv.proven = view->proven;
    hv.provenCount = view->provenCount;
    facts = BRAssetHoldInputFacts(&hv, buf->work, buf->workCap, tx, buf->inputs, buf->inputRows, buf->inputCap,
                                  buf->outputRows, buf->outputCap);
    if (facts.status == BR_ASSET_HOLD_REFUSED_ROWS) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ROWS);
    if (facts.status == BR_ASSET_HOLD_REFUSED_UNREADABLE) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_UNREADABLE);
    if (facts.status == BR_ASSET_HOLD_REFUSED_CAPACITY) {
        out->needs = needs;
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_CAPACITY);
    }
    if (facts.status != BR_ASSET_HOLD_COMPLETE) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ARGUMENTS);

#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_DUPLICATE_ROWS)
    // rows for one outpoint must agree in what detection reads of them (work[].row: the rows in outpoint order)
    for (k = 1; k < view->rowCount; k++) {
        const BRAssetRow *a = &view->rows[buf->work[k - 1].row], *b = &view->rows[buf->work[k].row];

        if (a->vout == b->vout && UInt256Eq(buf->holdRows[buf->work[k - 1].row].txHash, buf->holdRows[buf->work[k].row].txHash) &&
            (a->credit != b->credit || ! _BRAssetDetectSameId(a->assetId, b->assetId)))
            return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ROWS);
    }
#endif
    out->hasInputUnits = facts.hasUnits;
    out->inputUnits = facts.units;

    // the layout and the placeholder
    for (j = 0; j < tx->outCount; j++) {
        if (_BRAssetDetectIsOpReturn(&tx->outputs[j])) {
            if (firstOpReturn == _BR_ASSET_DETECT_NONE) firstOpReturn = j;
        }
        else if (! out->hasFirstNonOpReturn) {
            out->hasFirstNonOpReturn = 1;
            out->firstNonOpReturn = (int32_t)j;
        }
    }
    out->carrierIsFirstOpReturn = (firstOpReturn == out->carrierAt) ? 1 : 0;
    isIssuance = (out->header.kind == BR_ASSET_SCRIPT_ASSET && out->header.operation == DA_ISSUANCE) ? 1 : 0;

#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_PLACEHOLDER_ALWAYS)
    if (isIssuance && out->header.locked && tx->inCount > 0 && tx->inputs[0].index <= (uint32_t)INT32_MAX) {
        char first[BR_ASSET_TXID_BUFFER];

        _BRAssetHopTxidHex(&tx->inputs[0].txHash, first);
        out->placeholderDerived = BRAssetIdForIssuance(first, (int32_t)tx->inputs[0].index, 1, out->header.aggregation,
                                                       out->header.divisibility, out->placeholder, sizeof(out->placeholder));
    }
#endif
    if (! out->placeholderDerived) {
        memcpy(out->placeholder, BR_ASSET_UNRESOLVED_PREFIX, sizeof(BR_ASSET_UNRESOLVED_PREFIX) - 1);
        memcpy(out->placeholder + sizeof(BR_ASSET_UNRESOLVED_PREFIX) - 1, out->txid, BR_ASSET_TXID_BUFFER);
    }

    // the outputs that get a row
    for (j = 0, n = 0; j < tx->outCount; j++) {
        BRAssetDetectOutput *o;

        if (! _BRAssetDetectGetsRow(view, j)) continue;
        o = &buf->outputs[n++];
        memset(o, 0, sizeof(*o));
        o->vout = (int32_t)j;
        o->credit.kind = BR_ASSET_OUTPUT_UNKNOWN;
        o->targeted = BRAssetTargetsOutput(out->header.operation, out->header.version, BRAssetHeaderHasRules(&out->header),
                                           out->header.hasTotalQuantity, out->header.totalQuantity, (int32_t)j,
                                           out->hasFirstNonOpReturn, out->firstNonOpReturn, out->hasInputUnits,
                                           out->inputUnits, out->txOutputCount, out->insts, out->header.instructionCount);
    }
    out->outputCount = n;

    if (out->header.kind != BR_ASSET_SCRIPT_ASSET) {   // a carrier that cannot be classified
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_UNCLASSIFIABLE_ROWS)
        for (i = 0; i < n; i++) {
            BRAssetDetectOutput *o = &buf->outputs[i];
            BRAssetDetectedOutput d;
            const BRTxOutput *txo = &tx->outputs[o->vout];

            memset(&d, 0, sizeof(d));
            d.txid = out->txid; d.vout = o->vout; d.script = txo->script; d.scriptLen = txo->scriptLen;
            d.satoshis = (int64_t)txo->amount; d.blockHeight = view->blockHeight; d.placeholderAssetId = out->placeholder;
            d.isOutgoingUnconfirmed = view->isOutgoingUnconfirmed; d.credit = &o->credit;
            o->persist = BRAssetPersistDetectedOutput(&d, buf->outputRows[o->vout] == _BR_ASSET_DETECT_NONE ? NULL :
                                                      &view->rows[buf->outputRows[o->vout]]);
        }
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_DONE);
#else
        return _BRAssetDetectEnd(out, BR_ASSET_DETECT_UNCLASSIFIABLE);
#endif
    }

    out->payloadExact = BRAssetPayloadReadsExactly(tx->outputs[out->carrierAt].script, tx->outputs[out->carrierAt].scriptLen,
                                                   &out->header, out->insts, out->header.instructionCount);

    // all settled
    out->allSettled = (n > 0) ? 1 : 0;
    for (i = 0; i < n && out->allSettled; i++) {
        size_t at = buf->outputRows[buf->outputs[i].vout];

        if (at == _BR_ASSET_DETECT_NONE || ! BRAssetCreditIsSettled(view->rows[at].credit)) out->allSettled = 0;
    }
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_SETTLED_REALLOCATED)
    out->allSettled = 0;
#endif

    // the allocation
    if (! out->allSettled && isIssuance) {
        out->allocation = BRAssetAllocateIssuance(&out->header, out->insts, out->header.instructionCount, out->placeholder,
                                                  out->txOutputCount, out->payloadExact, buf->delivered, buf->deliveredCap);
        out->allocated = 1;
    }
    else if (! out->allSettled && ! out->payloadExact) {
        out->allocation = BRAssetAllocate(&out->header, out->insts, out->header.instructionCount, 0, NULL, 0,
                                          out->txOutputCount, NULL, 0, NULL, 0);
        out->allocated = 1;
    }
    else if (! out->allSettled) {
        for (k = 0; k < tx->inCount; k++) {
            if (tx->inputs[k].index > (uint32_t)INT32_MAX) anyUnreadableInput = 1;
        }
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_INPUT_DROPPED)
        anyUnreadableInput = 0;
#endif
        if (anyUnreadableInput) {   // Kotlin: inputs == null, read as one input that is not known
            buf->stacks[0].known = 0;
            buf->stacks[0].units = NULL;
            buf->stacks[0].unitCount = 0;
            stackCount = 1;
        }
        else {
            for (k = 0; k < tx->inCount; k++) {
                BRAssetInputFacts f = buf->inputs[k];
                size_t at = buf->inputRows[k];

#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_INPUT_DROPPED)
                if (tx->inputs[k].index > (uint32_t)INT32_MAX) continue;
#endif
                if (at != _BR_ASSET_DETECT_NONE) {
                    f.credit = view->rows[at].credit;
                    f.assetId = view->rows[at].assetId;
                }
                buf->stacks[stackCount++] = BRAssetBackedInputStack(&f, &buf->slots[k]);
            }
        }

        // the rules: every asset on a known stack, each once, answered before anything is allocated
        for (k = 0; k < stackCount; k++) {
            const BRAssetInputStack *st = &buf->stacks[k];
            BRAssetUnits *e = (st->known && st->unitCount == 1) ? (BRAssetUnits *)st->units : NULL;
            const BRAssetDetectRule *answer = NULL;
            size_t m;

            if (! e) continue;
            for (m = 0; m < view->ruleCount && ! answer; m++) {
                if (_BRAssetDetectSameId(view->rules[m].assetId, e->assetId)) answer = &view->rules[m];
            }
            if (answer) {
                e->ruleFree = BRAssetDetectRuleFree(answer);
                continue;
            }
#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_RULES_UNASKED_FREE)
            e->ruleFree = 1;
#else
            for (m = 0; m < out->askCount && ! _BRAssetDetectSameId(buf->asks[m], e->assetId); m++) {}
            if (m == out->askCount) buf->asks[out->askCount++] = e->assetId;
#endif
        }
        if (out->askCount > 0) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_NEEDS_RULES);

        out->allocation = BRAssetAllocate(&out->header, out->insts, out->header.instructionCount, 1, buf->stacks, stackCount,
                                          out->txOutputCount, buf->allocWork, buf->inputCap, buf->delivered, buf->deliveredCap);
        out->allocated = 1;
    }
    if (out->allocated && out->allocation.status == BR_ASSET_ALLOCATION_INDETERMINATE) {
        if (out->allocation.why == BR_ASSET_WHY_ARGUMENTS) return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_ARGUMENTS);
        if (out->allocation.why == BR_ASSET_WHY_CAPACITY) {   // the bounds suffice; never read as an answer
            out->needs = needs;
            return _BRAssetDetectEnd(out, BR_ASSET_DETECT_REFUSED_CAPACITY);
        }
    }

    // each output: its claim, credit, write and question
    for (i = 0; i < n; i++) {
        BRAssetDetectOutput *o = &buf->outputs[i];
        const BRTxOutput *txo = &tx->outputs[o->vout];
        size_t at = buf->outputRows[o->vout];
        BRAssetDetectedOutput d;

        o->claimed = BRAssetClaimForOutputTotal(out->header.operation, out->header.hasTotalQuantity, out->header.totalQuantity,
                                                out->insts, out->header.instructionCount, o->vout, out->hasFirstNonOpReturn,
                                                out->firstNonOpReturn, out->hasInputUnits, out->inputUnits, out->txOutputCount);
        if (out->allocated) {
            o->credit = BRAssetCreditForOutput(out->allocation, buf->delivered, out->insts, out->header.instructionCount,
                                               o->vout, out->txOutputCount);
        }

        memset(&d, 0, sizeof(d));
        d.txid = out->txid;
        d.vout = o->vout;
        d.script = txo->script;
        d.scriptLen = txo->scriptLen;
        d.satoshis = (int64_t)txo->amount;
        d.blockHeight = view->blockHeight;
        d.placeholderAssetId = out->placeholder;
        d.claimedQuantity = o->claimed;
        d.isOutgoingUnconfirmed = view->isOutgoingUnconfirmed;
        d.credit = &o->credit;
        o->persist = BRAssetPersistDetectedOutput(&d, (at == _BR_ASSET_DETECT_NONE) ? NULL : &view->rows[at]);
        if (o->persist.action != BR_ASSET_PERSIST_NOTHING && o->persist.unresolved) out->anyUnresolved = 1;

        o->askIndexer = (o->credit.kind == BR_ASSET_OUTPUT_UNKNOWN) ? 1 : 0;
#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_ASK_OUTGOING)
        if (view->isOutgoingUnconfirmed) o->askIndexer = 0;
#endif
#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_ASK_UNOWNED)
        if (view->ownedCount == 0) o->askIndexer = 0;
#endif
        o->bound = BRAssetMaxDeliverable(&out->header, out->insts, out->header.instructionCount, o->vout, out->txOutputCount);
    }

#if (ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_WALK_ONCE_DROPPED)
    out->issuanceWalkDue = isIssuance && out->anyUnresolved && BRAssetIdIsUnresolved(out->placeholder);
#else
    out->issuanceWalkDue = isIssuance && ((out->anyUnresolved && BRAssetIdIsUnresolved(out->placeholder)) || ! view->walkedInSession);
#endif
    return _BRAssetDetectEnd(out, BR_ASSET_DETECT_DONE);
}

// ---- after the walks -----------------------------------------------------------------------------

// THE RENAME: which of rows[0, rowCount) to rename to answer->assetId, the issuance walk's answer for the
// transaction `detection` read. OK with their indices in renamed[0, *count) in row order (none when the
// rename does not apply); CAPACITY, and *count the number, when `renamed` cannot hold them; REFUSED for a
// NULL where a value is needed or facts whose id does not end in its buffer.
static inline BRAssetHoldingsStatus BRAssetDetectRename(const BRAssetDetection *detection, const BRAssetResolvedFacts *answer,
                                                        const BRAssetRow *rows, size_t rowCount, size_t *renamed, size_t cap,
                                                        size_t *count)
{
    size_t i, m = 0;

    if (! count) return BR_ASSET_HOLDINGS_REFUSED;
    *count = 0;
    if (! detection || ! answer || (rowCount > 0 && ! rows) || (cap > 0 && ! renamed) ||
        ! _BRAssetFactsWellFormed(answer)) return BR_ASSET_HOLDINGS_REFUSED;
    if (detection->status != BR_ASSET_DETECT_DONE || detection->header.kind != BR_ASSET_SCRIPT_ASSET ||
        detection->header.operation != DA_ISSUANCE || answer->assetId[0] == '\0' ||
        strcmp(answer->assetId, detection->placeholder) == 0) return BR_ASSET_HOLDINGS_OK;
#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_RENAME_ANY)
    if (! BRAssetIdIsUnresolved(detection->placeholder) || detection->placeholderDerived ||
        ! detection->carrierIsFirstOpReturn) return BR_ASSET_HOLDINGS_OK;
#endif

    for (i = 0; i < rowCount; i++) {
        if (rows[i].assetId && strcmp(rows[i].assetId, detection->placeholder) == 0) m++;
    }
    if (m > cap) {
        *count = m;
        return BR_ASSET_HOLDINGS_CAPACITY;
    }
    for (i = 0; i < rowCount; i++) {
        if (rows[i].assetId && strcmp(rows[i].assetId, detection->placeholder) == 0) renamed[(*count)++] = i;
    }

    return BR_ASSET_HOLDINGS_OK;
}

// What THE FACTS WALK says. REFUSED is 0.
typedef enum {
    BR_ASSET_FACTS_WALK_REFUSED = 0,         // a NULL where a value is needed, or `ids` too small (*count: how many)
    BR_ASSET_FACTS_WALK_NO = 1,              // nothing to walk
    BR_ASSET_FACTS_WALK_LATER = 2,           // the last attempt was less than BR_ASSET_FACTS_WALK_RETRY_MS ago
    BR_ASSET_FACTS_WALK_NOW = 3              // find the facts of ids[0, *count); record nowMs
} BRAssetFactsWalkDue;

// THE FACTS WALK for the transaction `detection` read, over rows[0, rowCount) as they are after the writes
// and the indexer's answers. walkedInSession: the walk has found every named asset's facts for this
// transaction in this process; hasLastAttempt and lastAttemptMs: when it last tried and did not.
static inline BRAssetFactsWalkDue BRAssetDetectFactsWalk(const BRAssetDetection *detection, const BRAssetRow *rows,
                                                         size_t rowCount, int walkedInSession, int hasLastAttempt,
                                                         int64_t lastAttemptMs, int64_t nowMs, const char **ids,
                                                         size_t cap, size_t *count)
{
    size_t i, m, n = 0;

    if (! count) return BR_ASSET_FACTS_WALK_REFUSED;
    *count = 0;
    if (! detection || (rowCount > 0 && ! rows) || (cap > 0 && ! ids)) return BR_ASSET_FACTS_WALK_REFUSED;
    if (detection->status != BR_ASSET_DETECT_DONE || detection->header.kind != BR_ASSET_SCRIPT_ASSET ||
        detection->header.operation == DA_ISSUANCE || walkedInSession) return BR_ASSET_FACTS_WALK_NO;

    for (i = 0; i < rowCount; i++) {
        const BRAssetRow *r = &rows[i];

        if (! r->isAsset || ! r->txid || strcmp(r->txid, detection->txid) != 0) continue;
#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_FACTS_UNCOUNTED)
        if (! BRAssetCreditCounts(r->credit)) continue;
#endif
        if (r->assetQuantity <= 0 || ! r->assetId || r->assetId[0] == '\0' || BRAssetIdIsUnresolved(r->assetId)) continue;
        for (m = 0; m < i; m++) {
            const BRAssetRow *q = &rows[m];

            if (q->isAsset && q->txid && strcmp(q->txid, detection->txid) == 0 &&
#if !(ASSET_DETECT_UNFIXED & ASSET_DETECT_RED_FACTS_UNCOUNTED)
                BRAssetCreditCounts(q->credit) &&
#endif
                q->assetQuantity > 0 && q->assetId && strcmp(q->assetId, r->assetId) == 0) break;
        }
        if (m < i) continue;
        if (n < cap) ids[n] = r->assetId;
        n++;
    }
    if (n == 0) return BR_ASSET_FACTS_WALK_NO;
    if (n > cap) {
        *count = n;
        return BR_ASSET_FACTS_WALK_REFUSED;
    }
    *count = n;
    if (hasLastAttempt) {
        // nowMs - lastAttemptMs as a Long does it: wrapping, then read as signed
        uint64_t since = (uint64_t)nowMs - (uint64_t)lastAttemptMs;

        if (since >= ((uint64_t)1 << 63) || since < (uint64_t)BR_ASSET_FACTS_WALK_RETRY_MS) return BR_ASSET_FACTS_WALK_LATER;
    }

    return BR_ASSET_FACTS_WALK_NOW;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetDetect_h
