//
//  BRAssetAllocate.h
//
//  Where the units of a DigiAsset transaction land, output by output, and what the wallet may believe
//  about one of its own outputs. Until 2026-11 this lived only in Android's Kotlin
//  (core/.../asset/AssetTransferAllocator.kt, AssetCredit.kt, and in AssetManager.kt the functions
//  resolveInputAssetUnits, backedInputStack, transferOutputCredits and issuanceOutputCredits). It moves
//  here unchanged: every input the Kotlin answers gets the same answer here, and every input it refuses
//  is refused here for the same reason.
//
//  THE RULES:
//    - THE INPUTS (BRAssetAllocate) are every input of the transaction, in order, each a stack of
//      (asset id, count) entries, or UNKNOWN. An entry whose count is zero or less is not counted, and
//      an input with no counted entry takes no place in the order units are drawn in.
//    - REFUSALS, in this order. A TRANSFER or BURN is not decided (INDETERMINATE) when: its payload was
//      not read exactly; the operation is an issuance, or none this reader classifies; there is no
//      output; there is no input; one input is UNKNOWN. When no input carries a counted entry the
//      transaction moves no asset (NOT_AN_ASSET_TRANSFER), whatever its instructions say. Then it is
//      not decided when an instruction is a percent instruction, or a counted entry's asset is not
//      known to be free of transfer rules.
//    - BEFORE VERSION 3, a transaction whose FIRST input carries no counted entry has its instructions
//      ignored: everything the inputs carry goes to the last output.
//    - THE INSTRUCTIONS, in order (_BRAssetAllocDistribute). An instruction with a negative output
//      index or amount is not decided. It consumes `amount`, or (outputIndex + 1) * amount when it is a
//      range, from the front of the current stack; the asset it moves is the one at the front when it
//      starts. An entry smaller than what is still to draw is used up and the draw goes on with the
//      next entry (of this stack, then of the next stack), but only for an AGGREGATABLE asset; for a
//      HYBRID asset the instruction is INVALID; for any other the transaction is not decided. A draw
//      that finds another asset at the front, or no entry at all, is INVALID. What was drawn is
//      delivered: `amount` to the output named, or to each of the outputs 0..outputIndex for a range;
//      an output index at or past the output count is INVALID; in a BURN the non-range output 31
//      delivers nothing (the units are destroyed). An amount of zero draws and delivers nothing, and
//      is INVALID only when no stack is left.
//    - SKIP. An instruction with the skip flag moves on to the next stack when it is done, unless the
//      current stack was just used up (the draw already moved on).
//    - INVALID. The first INVALID instruction voids them all: nothing any instruction delivered
//      stands, and everything the inputs carried goes to the last output (instructionsVoided).
//    - WHAT IS LEFT on the stacks when the instructions are done goes to the last output, entry by
//      entry. Units of one asset on one output are one sum; a sum past INT64_MAX is not decided.
//    - AN ISSUANCE (BRAssetAllocateIssuance) creates header->totalQuantity units of the id the wallet
//      names the new asset by, as ONE stack of one entry, and distributes it by the same instructions
//      (output 31 is an ordinary output; with one entry no draw goes on to a next one, so an
//      instruction that asks for more than is left is INVALID whatever the header's aggregation). It
//      is not decided when the header is not an issuance, its payload was not read exactly, there is
//      no output, or it carries no amount; an amount outside 1..BR_ASSET_MAX_ISSUANCE issues nothing
//      (NOT_AN_ASSET_TRANSFER); a percent instruction is not decided.
//    - AN ID'S AGGREGATION (BRAssetAggregationOfId), for a transfer: an id of at least 3 bytes whose
//      first is 'L' or 'U' says it in its second: 'a' aggregatable, 'h' hybrid, 'd' dispersed. Any
//      other id (a placeholder for an issuance not yet named) says nothing.
//    - ONE OUTPUT'S CREDIT (BRAssetCreditForOutput). NOT_AN_ASSET_TRANSFER: the output holds nothing.
//      ALLOCATED: nothing, the one entry delivered to it, or MIXED when it was delivered more than one
//      asset; the label is the one asset the transaction moved, when it moved exactly one. INDETERMINATE:
//      UNKNOWN for the last output and for an output an instruction names (a range names 0..outputIndex;
//      a percent instruction and a burn's output 31 name too); every other output holds nothing.
//    - THE MOST AN OUTPUT CAN BE DELIVERED (BRAssetMaxDeliverable): 0 when what the non-percent
//      instructions consume cannot be counted (a negative amount or index, or a total past INT64_MAX);
//      no bound for the last output; otherwise the sum of the amounts of the instructions that name it
//      (a burn's output 31 aside), no bound when one of them is a percent instruction, 0 when the sum
//      is past the int64 range.
//    - WHAT THE INPUTS CARRIED IN ALL (BRAssetResolveInputUnits), per input: a row with a positive
//      quantity carries it; a row storing zero carries nothing only when the transaction that created
//      the output directs no units to it (rowIsTargeted is NO), and is otherwise not a count; no row
//      carries nothing only when the funding transaction has no DigiAsset payload (fundingIsAssetTx is
//      NO). Anything else, or a total past INT64_MAX, is UNKNOWN. When rows storing zero are the whole
//      reason, the caller that asked is told which, and the total of the rest.
//    - ONE INPUT'S STACK (BRAssetBackedInputStack), as far as the wallet can vouch for it: a BACKED or
//      VERIFIED row carries its asset and quantity (nothing when the quantity is zero or less; UNKNOWN
//      when it has no asset id); an UNCHECKED row storing zero on an output its transaction does not
//      target carries nothing; no row carries nothing when the funding transaction has no data output;
//      anything else is UNKNOWN.
//    - WHAT AN INDEXER'S ANSWER SAYS (BRAssetCreditFromIndexer): the entries with a count above zero
//      decide. None: the output holds nothing. One asset: the sum of its entries. More than one: MIXED.
//      An output the indexer does not hold as unspent, an indexer that did not answer, and a sum past
//      INT64_MAX say nothing.
//
//  UNKNOWN and INDETERMINATE are answers, never zero: the platform holds such an output and credits
//  nothing for it. Every enum here has that answer at 0, so a struct nobody filled reads as it.
//
//  Asset ids are NUL-terminated byte strings the caller keeps alive, compared byte for byte. The ids in
//  the answers are the caller's own pointers.
//
//  No allocation. The working state of an allocation goes into the caller's `work` buffer (one int64_t
//  per entry of the input stacks) and its answer into the caller's `out` buffer; an allocation whose
//  deliveries, voided ones included, `out` cannot hold, or whose inputs `work` cannot hold, is
//  INDETERMINATE (BR_ASSET_WHY_CAPACITY), never shortened. No wallet, no network, no clock, no I/O.
//  Header-only, static inline; its includes are libc, BRAssetData.h (BRAssetOperation), BRAssetQuantity.h
//  (BRAssetTransferInstruction and the checked sums) and BRAssetDecode.h (BRAssetHeader,
//  BRAssetAggregation), which this header uses and does not redefine. It reads no build-time policy
//  macro. Nothing in the core calls it yet; BRDigiAsset.c and BRWallet.c are not changed by it.
//
//  SUMS. Counts are added and multiplied with BRAssetQuantity.h's _BRAssetAddUnits and _BRAssetMulUnits,
//  which refuse a negative operand as well as a result past INT64_MAX. Kotlin's Math.addExact and
//  Math.multiplyExact refuse only the latter; at every call here but one the operands are already known
//  not to be negative, so the answers are the same. The one is BRAssetMaxDeliverable's sum, which a
//  header of an unclassified operation reaches with amounts nobody checked: it is added over the whole
//  signed range (_BRAssetAllocAddExact), as Math.addExact does.
//
//  Test seams (host KAT asset_allocate_kat in the Android repo): ASSET_ALLOCATE_UNFIXED, tested by VALUE
//  as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is
//  what ships.
//    1      ASSET_ALLOCATE_RED_VOID_KEEPS          an invalid instruction leaves what earlier ones delivered.
//    2      ASSET_ALLOCATE_RED_NO_LEFTOVER         what the instructions leave is delivered to no output.
//    4      ASSET_ALLOCATE_RED_LEGACY_READS        before version 3 the instructions are always read.
//    8      ASSET_ALLOCATE_RED_BURN_ANY_OP         output 31 destroys in every operation.
//    16     ASSET_ALLOCATE_RED_ANY_DRAWS           every asset is drawn across entries.
//    32     ASSET_ALLOCATE_RED_SUMS_WRAP           a sum or product past INT64_MAX wraps.
//    64     ASSET_ALLOCATE_RED_UNKNOWN_INPUT_READ  an input whose contents are unknown is read as given.
//    128    ASSET_ALLOCATE_RED_INEXACT_READ        a payload not read exactly is allocated.
//    256    ASSET_ALLOCATE_RED_UNDECIDED_EMPTY     an undecided allocation credits every output nothing.
//    512    ASSET_ALLOCATE_RED_PERCENT_READ        a percent instruction is read as a count.
//    1024   ASSET_ALLOCATE_RED_RULES_IGNORED       an asset that may carry transfer rules is allocated.
//    2048   ASSET_ALLOCATE_RED_LAST_BOUNDED        the last output is bounded by the instructions that name it.
//    4096   ASSET_ALLOCATE_RED_ZERO_ROW_COUNTS     a row storing zero carries nothing, targeted or not.
//    8192   ASSET_ALLOCATE_RED_NO_ROW_EMPTY        an input without a row carries nothing.
//    16384  ASSET_ALLOCATE_RED_ISSUANCE_UNBOUNDED  an issuance of any amount is allocated.
//    32768  ASSET_ALLOCATE_RED_UNCHECKED_COUNTS    a row's quantity is believed whatever its credit state.
//    65536  ASSET_ALLOCATE_RED_SKIP_ALWAYS         a skip moves on even when the stack was just used up.
//    131072 ASSET_ALLOCATE_RED_EMPTY_INPUT_PLACED  an input with no counted entry keeps its place in the draw order.
//

#ifndef BRAssetAllocate_h
#define BRAssetAllocate_h

#include "BRAssetData.h"       // BRAssetOperation: DA_UNDEFINED / DA_ISSUANCE / DA_TRANSFER / DA_BURN
#include "BRAssetQuantity.h"   // BRAssetTransferInstruction, _BRAssetAddUnits, _BRAssetMulUnits
#include "BRAssetDecode.h"     // BRAssetHeader, BRAssetAggregation
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_ALLOCATE_UNFIXED
#define ASSET_ALLOCATE_UNFIXED 0
#endif

#define ASSET_ALLOCATE_RED_VOID_KEEPS          1
#define ASSET_ALLOCATE_RED_NO_LEFTOVER         2
#define ASSET_ALLOCATE_RED_LEGACY_READS        4
#define ASSET_ALLOCATE_RED_BURN_ANY_OP         8
#define ASSET_ALLOCATE_RED_ANY_DRAWS           16
#define ASSET_ALLOCATE_RED_SUMS_WRAP           32
#define ASSET_ALLOCATE_RED_UNKNOWN_INPUT_READ  64
#define ASSET_ALLOCATE_RED_INEXACT_READ        128
#define ASSET_ALLOCATE_RED_UNDECIDED_EMPTY     256
#define ASSET_ALLOCATE_RED_PERCENT_READ        512
#define ASSET_ALLOCATE_RED_RULES_IGNORED       1024
#define ASSET_ALLOCATE_RED_LAST_BOUNDED        2048
#define ASSET_ALLOCATE_RED_ZERO_ROW_COUNTS     4096
#define ASSET_ALLOCATE_RED_NO_ROW_EMPTY        8192
#define ASSET_ALLOCATE_RED_ISSUANCE_UNBOUNDED  16384
#define ASSET_ALLOCATE_RED_UNCHECKED_COUNTS    32768
#define ASSET_ALLOCATE_RED_SKIP_ALWAYS         65536
#define ASSET_ALLOCATE_RED_EMPTY_INPUT_PLACED  131072

// The most units an issuance can create: 2^54 - 1, the largest amount the 7-byte form carries. A plain
// literal, so Swift imports it; the check below holds it to the formula.
#define BR_ASSET_MAX_ISSUANCE 18014398509481983LL
typedef char _BRAssetAllocMaxIssuanceIsTheFormula[(((int64_t)1 << 54) - 1 == BR_ASSET_MAX_ISSUANCE) ? 1 : -1];

// In a BURN, the non-range output index that destroys the units an instruction draws.
#define BR_ASSET_BURN_OUTPUT 31

// ---- the types -----------------------------------------------------------------------------------

// An answer the wallet may or may not have (Kotlin: Boolean?). UNKNOWN is 0.
typedef enum {
    BR_ASSET_FACT_UNKNOWN = 0,
    BR_ASSET_FACT_NO = 1,
    BR_ASSET_FACT_YES = 2
} BRAssetFact;

// What backs the quantity a wallet row stores (Android: AssetCredit's UNCHECKED / BACKED / VERIFIED /
// MIXED). A value this header does not define counts for nothing.
typedef enum {
    BR_ASSET_CREDIT_UNCHECKED = 0,   // claimed by an indexer or a payload, not established
    BR_ASSET_CREDIT_BACKED = 1,      // follows from inputs the wallet vouches for
    BR_ASSET_CREDIT_VERIFIED = 2,    // established against the chain
    BR_ASSET_CREDIT_MIXED = 3        // the output holds more than one asset
} BRAssetCredit;

// Units of one asset (Android: AssetUnits, and the indexer's StackEntry).
typedef struct {
    const char *assetId;             // NUL-terminated; the caller keeps it alive
    int64_t count;
    int ruleFree;                    // BRAssetAllocate only: 1 when the asset is known to carry no transfer rules
} BRAssetUnits;

// What one input carried (Kotlin: List<AssetUnits>?).
typedef struct {
    int known;                       // 0: its contents are unknown (Kotlin: null); `units` is then not read
    const BRAssetUnits *units;       // its entries, front first
    size_t unitCount;
} BRAssetInputStack;

// Units delivered to one output.
typedef struct {
    int32_t vout;
    const char *assetId;             // one of the caller's pointers
    int64_t count;                   // above zero
} BRAssetOutputUnits;

// Android's AssetTransferAllocator.Result. INDETERMINATE is 0.
typedef enum {
    BR_ASSET_ALLOCATION_INDETERMINATE = 0,           // not decided: see BRAssetCreditForOutput
    BR_ASSET_ALLOCATION_NOT_AN_ASSET_TRANSFER = 1,   // the transaction moves no asset
    BR_ASSET_ALLOCATION_ALLOCATED = 2                // `out` holds what every output was delivered
} BRAssetAllocationStatus;

// Why an allocation is INDETERMINATE (the Kotlin's reason, by name).
typedef enum {
    BR_ASSET_WHY_NONE = 0,                    // it is decided, or nobody filled the struct
    BR_ASSET_WHY_ARGUMENTS = 1,               // a NULL where a value is needed (C only)
    BR_ASSET_WHY_CAPACITY = 2,                // `work` or `out` cannot hold it (C only)
    BR_ASSET_WHY_ISSUANCE = 3,                // "issuance"
    BR_ASSET_WHY_UNCLASSIFIABLE = 4,          // "unclassifiable carrier"
    BR_ASSET_WHY_NO_OUTPUTS = 5,              // "no outputs"
    BR_ASSET_WHY_NO_INPUTS = 6,               // "no inputs"
    BR_ASSET_WHY_INPUT_UNKNOWN = 7,           // "an input's contents are unknown"
    BR_ASSET_WHY_PERCENT = 8,                 // "percent instruction"
    BR_ASSET_WHY_RULES = 9,                   // "an input asset may carry transfer rules"
    BR_ASSET_WHY_NOT_ISSUANCE = 10,           // "not an issuance"
    BR_ASSET_WHY_PAYLOAD_NOT_EXACT = 11,      // "payload not read exactly"
    BR_ASSET_WHY_NO_ISSUED_AMOUNT = 12,       // "no issued amount"
    BR_ASSET_WHY_MALFORMED_INSTRUCTION = 13,  // "malformed instruction"
    BR_ASSET_WHY_NON_AGGREGABLE_DRAW = 14,    // "draw across entries of a non-aggregable asset"
    BR_ASSET_WHY_OVERFLOW = 15                // "overflow"
} BRAssetAllocationWhy;

typedef struct {
    BRAssetAllocationStatus status;
    BRAssetAllocationWhy why;        // BR_ASSET_WHY_NONE unless status is INDETERMINATE
    int instructionsVoided;          // ALLOCATED: an instruction was invalid, so none of them stands
    size_t count;                    // ALLOCATED: the entries written to `out`; 0 otherwise
} BRAssetAllocation;

// Android's OutputCredit. UNKNOWN is 0.
typedef enum {
    BR_ASSET_OUTPUT_UNKNOWN = 0,     // not established: hold the output, credit nothing
    BR_ASSET_OUTPUT_HOLDS = 1,       // it holds `count` of `assetId`, or no asset when hasUnits is 0
    BR_ASSET_OUTPUT_MIXED = 2        // it holds more than one asset
} BRAssetOutputCreditKind;

typedef struct {
    BRAssetOutputCreditKind kind;
    int hasUnits;                    // HOLDS: 1 when assetId and count say what it holds
    const char *assetId;
    int64_t count;
    const char *label;               // HOLDS: the asset to show the output under, or NULL
} BRAssetOutputCredit;

// What BRAssetMaxDeliverable answers. A struct nobody filled reads as "nothing can be delivered".
typedef struct {
    int unbounded;                   // 1: no bound (Kotlin: null); `max` is then 0
    int64_t max;
} BRAssetDeliverable;

// What the wallet knows about one input of a transaction. BRAssetResolveInputUnits reads hasRow,
// quantity, rowIsTargeted and fundingIsAssetTx; BRAssetBackedInputStack reads hasRow, credit, quantity,
// assetId, rowIsTargeted and fundingHasDataOutput.
typedef struct {
    int hasRow;                         // the wallet holds a row for the outpoint
    BRAssetCredit credit;               // the row's credit state
    int64_t quantity;                   // the row's stored quantity
    const char *assetId;                // the row's asset id; NULL or "" when it has none
    BRAssetFact rowIsTargeted;          // does the transaction that created the output direct units to it?
    BRAssetFact fundingIsAssetTx;       // does the funding transaction carry a DigiAsset payload?
    BRAssetFact fundingHasDataOutput;   // does the funding transaction have a data output?
} BRAssetInputFacts;

// What BRAssetResolveInputUnits answers. A struct nobody filled reads as UNKNOWN.
typedef struct {
    int known;                       // 1: `units` is what the inputs carried in all
    int64_t units;
    size_t zeroRowCount;             // not known, and rows storing zero are the whole reason: how many
    int64_t otherUnits;              // then: what the other inputs carried
} BRAssetInputUnits;

// What an indexer says about one output (Android: StackLookup). UNAVAILABLE is 0.
typedef enum {
    BR_ASSET_STACK_UNAVAILABLE = 0,  // it did not answer
    BR_ASSET_STACK_NOT_UNSPENT = 1,  // it does not hold the output as unspent
    BR_ASSET_STACK_FOUND = 2         // the output is unspent and carries exactly the entries given
} BRAssetStackLookup;

// ---- the credit states (Android: AssetCredit.counts, AssetCredit.isSettled) ----------------------

// Does a row in this state count toward a balance, and back a spend?
static inline int BRAssetCreditCounts(BRAssetCredit credit)
{
    return credit == BR_ASSET_CREDIT_BACKED || credit == BR_ASSET_CREDIT_VERIFIED;
}

// Is a row in this state decided, one way or the other?
static inline int BRAssetCreditIsSettled(BRAssetCredit credit)
{
    return credit == BR_ASSET_CREDIT_BACKED || credit == BR_ASSET_CREDIT_VERIFIED || credit == BR_ASSET_CREDIT_MIXED;
}

// ---- sums ----------------------------------------------------------------------------------------

// a + b and a * b for operands that are not negative (see SUMS). 0 when the result is not a count.
static inline int _BRAssetAllocAdd(int64_t a, int64_t b, int64_t *out)
{
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_SUMS_WRAP)
    *out = (int64_t)((uint64_t)a + (uint64_t)b);
    return 1;
#else
    return _BRAssetAddUnits(a, b, out);
#endif
}

static inline int _BRAssetAllocMul(int64_t a, int64_t b, int64_t *out)
{
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_SUMS_WRAP)
    *out = (int64_t)((uint64_t)a * (uint64_t)b);
    return 1;
#else
    return _BRAssetMulUnits(a, b, out);
#endif
}

// a + b over the whole int64 range (Math.addExact). 0 when it does not fit.
static inline int _BRAssetAllocAddExact(int64_t a, int64_t b, int64_t *out)
{
    if (b > 0 && a > INT64_MAX - b) return 0;
    if (b < 0 && a < INT64_MIN - b) return 0;
    *out = a + b;
    return 1;
}

// ---- an id's aggregation (Android: AssetTransferAllocator.aggregationOf) --------------------------

// What `assetId` says about its own aggregation: 1 and *aggregation, or 0 when it says nothing.
static inline int BRAssetAggregationOfId(const char *assetId, BRAssetAggregation *aggregation)
{
    BRAssetAggregation a;

    if (! assetId || strlen(assetId) < 3 || (assetId[0] != 'L' && assetId[0] != 'U')) return 0;
    if (assetId[1] == 'a') a = BR_ASSET_AGGREGATABLE;
    else if (assetId[1] == 'h') a = BR_ASSET_HYBRID;
    else if (assetId[1] == 'd') a = BR_ASSET_DISPERSED;
    else return 0;
    if (aggregation) *aggregation = a;
    return 1;
}

// ---- the distribution (Android: AssetTransferAllocator.distribute) -------------------------------

static inline BRAssetAllocation _BRAssetAllocUndecided(BRAssetAllocationWhy why)
{
    BRAssetAllocation r;

    r.status = BR_ASSET_ALLOCATION_INDETERMINATE;
    r.why = why;
    r.instructionsVoided = 0;
    r.count = 0;
    return r;
}

static inline BRAssetAllocation _BRAssetAllocNotAnAssetTransfer(void)
{
    BRAssetAllocation r = _BRAssetAllocUndecided(BR_ASSET_WHY_NONE);

    r.status = BR_ASSET_ALLOCATION_NOT_AN_ASSET_TRANSFER;
    return r;
}

// The stacks as they are drawn from. `left` is what remains of each entry, in input order; an entry
// that is not counted, or is used up, has 0.
typedef struct {
    const BRAssetInputStack *inputs;
    size_t inputCount;
    int64_t *left;
    size_t index;                    // the input units are drawn from; inputCount when none is left
    size_t base;                     // where that input's entries start in `left`
    int allowSkip;
    BRAssetOutputUnits *out;
    size_t outCap, outCount;
} _BRAssetAllocWork;

// Does this input carry a counted entry?
static inline int _BRAssetAllocCarries(const BRAssetInputStack *stack)
{
    size_t j;

    for (j = 0; j < stack->unitCount; j++) {
        if (stack->units[j].count > 0) return 1;
    }
    return 0;
}

// Every entry as its input carried it (Kotlin: freshStacks), and the draw back at the first input.
static inline void _BRAssetAllocFresh(_BRAssetAllocWork *w)
{
    size_t i, j, k = 0;

    for (i = 0; i < w->inputCount; i++) {
        for (j = 0; j < w->inputs[i].unitCount; j++) {
            w->left[k++] = (w->inputs[i].units[j].count > 0) ? w->inputs[i].units[j].count : 0;
        }
    }
    w->index = 0;
    w->base = 0;
}

// Inputs that carry nothing take no place in the order: settle on the next one that does.
static inline void _BRAssetAllocSettle(_BRAssetAllocWork *w)
{
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_EMPTY_INPUT_PLACED)
    while (w->index < w->inputCount && ! _BRAssetAllocCarries(&w->inputs[w->index])) {
        w->base += w->inputs[w->index].unitCount;
        w->index++;
    }
#endif
}

// On to the next stack (Kotlin: index++).
static inline void _BRAssetAllocNext(_BRAssetAllocWork *w)
{
    if (w->index >= w->inputCount) return;
    w->base += w->inputs[w->index].unitCount;
    w->index++;
    _BRAssetAllocSettle(w);
}

// The front entry of the current stack, as an index into its entries; unitCount when it has none left.
// The caller has checked that w->index names an input.
static inline size_t _BRAssetAllocFront(const _BRAssetAllocWork *w)
{
    size_t j, n = w->inputs[w->index].unitCount;

    for (j = 0; j < n; j++) {
        if (w->left[w->base + j] > 0) break;
    }
    return j;
}

// Is there an entry after the front one, in this stack or a later one?
static inline int _BRAssetAllocMore(const _BRAssetAllocWork *w, size_t front)
{
    size_t i, j;

    for (j = front + 1; j < w->inputs[w->index].unitCount; j++) {
        if (w->left[w->base + j] > 0) return 1;
    }
    for (i = w->index + 1; i < w->inputCount; i++) {
        if (_BRAssetAllocCarries(&w->inputs[i])) return 1;
    }
    return 0;
}

// `count` of `assetId` onto `vout` (Kotlin: add). The entries of one output stay together, outputs in
// the order they were first delivered to, and an output's assets in the order they first arrived.
static inline BRAssetAllocationWhy _BRAssetAllocDeliver(_BRAssetAllocWork *w, int32_t vout, const char *assetId,
                                                        int64_t count)
{
    size_t i, j, n = w->outCount;

    for (i = 0; i < n && w->out[i].vout != vout; i++) { }
    for (; i < n && w->out[i].vout == vout; i++) {
        if (strcmp(w->out[i].assetId, assetId) == 0) {
            if (! _BRAssetAllocAdd(w->out[i].count, count, &w->out[i].count)) return BR_ASSET_WHY_OVERFLOW;
            return BR_ASSET_WHY_NONE;
        }
    }
    if (n >= w->outCap) return BR_ASSET_WHY_CAPACITY;
    for (j = n; j > i; j--) w->out[j] = w->out[j - 1];
    w->out[i].vout = vout;
    w->out[i].assetId = assetId;
    w->out[i].count = count;
    w->outCount = n + 1;
    return BR_ASSET_WHY_NONE;
}

// One instruction, consuming `total`: 1 when it stands, 0 when it is INVALID, -1 (and *why) when the
// transaction is not decided.
static inline int _BRAssetAllocApply(_BRAssetAllocWork *w, const BRAssetTransferInstruction *inst, int64_t total,
                                     int32_t outputCount, int burnType, BRAssetAllocationWhy *why)
{
    const BRAssetInputStack *stack;
    const char *removed;
    BRAssetAggregation aggregation = BR_ASSET_DISPERSED;
    int64_t left = total, have;
    size_t front;
    int32_t vout;
    int said, destroyed;

    if (w->index >= w->inputCount) return 0;
    stack = &w->inputs[w->index];
    front = _BRAssetAllocFront(w);
    if (front >= stack->unitCount) return 0;
    removed = stack->units[front].assetId;

    while (left > 0) {
        if (w->index >= w->inputCount) return 0;
        stack = &w->inputs[w->index];
        front = _BRAssetAllocFront(w);
        if (front >= stack->unitCount) return 0;
        if (strcmp(stack->units[front].assetId, removed) != 0) return 0;
        w->allowSkip = 1;
        have = w->left[w->base + front];

        if (have < left) {
            if (! _BRAssetAllocMore(w, front)) return 0;
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_ANY_DRAWS)
            said = BRAssetAggregationOfId(stack->units[front].assetId, &aggregation);
            if (said && aggregation == BR_ASSET_HYBRID) return 0;
            if (! said || aggregation != BR_ASSET_AGGREGATABLE) {
                *why = BR_ASSET_WHY_NON_AGGREGABLE_DRAW;
                return -1;
            }
#endif
        }

        if (have <= left) {
            left -= have;
            w->left[w->base + front] = 0;

            if (_BRAssetAllocFront(w) >= stack->unitCount) {   // the stack is used up
                _BRAssetAllocNext(w);
                w->allowSkip = 0;
            }
        }
        else {
            w->left[w->base + front] = have - left;
            left = 0;
        }
    }

    if (total > 0) {
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_BURN_ANY_OP)
        destroyed = (! inst->range && inst->outputIndex == BR_ASSET_BURN_OUTPUT);
#else
        destroyed = (burnType && ! inst->range && inst->outputIndex == BR_ASSET_BURN_OUTPUT);
#endif
        if (! destroyed) {
            if (inst->outputIndex >= outputCount) return 0;

            for (vout = inst->range ? 0 : inst->outputIndex; vout <= inst->outputIndex; vout++) {
                *why = _BRAssetAllocDeliver(w, vout, removed, inst->amount);
                if (*why != BR_ASSET_WHY_NONE) return -1;
            }
        }
    }

    if (inst->skip) {
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_SKIP_ALWAYS)
        _BRAssetAllocNext(w);
#else
        if (w->allowSkip) _BRAssetAllocNext(w);
#endif
        w->allowSkip = 1;
    }
    return 1;
}

// The instructions over `inputs`, every one of them known, and then what they leave.
static inline BRAssetAllocation _BRAssetAllocDistribute(const BRAssetTransferInstruction *insts, size_t instCount,
                                                        const BRAssetInputStack *inputs, size_t inputCount,
                                                        int32_t outputCount, int burnType,
                                                        int legacyIgnoresInstructions,
                                                        int64_t *work, size_t workCap,
                                                        BRAssetOutputUnits *out, size_t outCap)
{
    BRAssetAllocation r;
    BRAssetAllocationWhy why = BR_ASSET_WHY_NONE;
    _BRAssetAllocWork w;
    int64_t total;
    size_t i, j, k, entries = 0;
    int valid, voided = 0;

    for (i = 0; i < inputCount; i++) {
        if (inputs[i].unitCount > workCap - entries) return _BRAssetAllocUndecided(BR_ASSET_WHY_CAPACITY);
        entries += inputs[i].unitCount;
    }
    w.inputs = inputs;
    w.inputCount = inputCount;
    w.left = work;
    w.allowSkip = 1;
    w.out = out;
    w.outCap = outCap;
    w.outCount = 0;
    _BRAssetAllocFresh(&w);
    _BRAssetAllocSettle(&w);

    if (! legacyIgnoresInstructions) {
        for (i = 0; i < instCount; i++) {
            if (insts[i].outputIndex < 0 || insts[i].amount < 0) {
                return _BRAssetAllocUndecided(BR_ASSET_WHY_MALFORMED_INSTRUCTION);
            }
            total = insts[i].amount;
            if (insts[i].range && ! _BRAssetAllocMul((int64_t)insts[i].outputIndex + 1, insts[i].amount, &total)) {
                return _BRAssetAllocUndecided(BR_ASSET_WHY_OVERFLOW);
            }
            valid = _BRAssetAllocApply(&w, &insts[i], total, outputCount, burnType, &why);
            if (valid < 0) return _BRAssetAllocUndecided(why);

            if (! valid) {
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_VOID_KEEPS)
                w.outCount = 0;
                _BRAssetAllocFresh(&w);
#endif
                voided = 1;
                break;
            }
        }
    }

#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_NO_LEFTOVER)
    k = 0;

    for (i = 0; i < inputCount; i++) {
        for (j = 0; j < inputs[i].unitCount; j++, k++) {
            if (work[k] <= 0) continue;
            why = _BRAssetAllocDeliver(&w, outputCount - 1, inputs[i].units[j].assetId, work[k]);
            if (why != BR_ASSET_WHY_NONE) return _BRAssetAllocUndecided(why);
        }
    }
#endif

    r.status = BR_ASSET_ALLOCATION_ALLOCATED;
    r.why = BR_ASSET_WHY_NONE;
    r.instructionsVoided = voided;
    r.count = w.outCount;
    return r;
}

// Does the list hold a percent instruction?
static inline int _BRAssetAllocAnyPercent(const BRAssetTransferInstruction *insts, size_t instCount)
{
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_PERCENT_READ)
    size_t i;

    for (i = 0; i < instCount; i++) {
        if (insts[i].percent) return 1;
    }
#endif
    return 0;
}

// ---- a transfer or a burn (Android: AssetTransferAllocator.allocate, transferOutputCredits) ------

// Where the units of a TRANSFER or BURN land (see THE RULES).
//
// `header` and insts[0, instCount) are what BRAssetDecodeInstructions read, and `payloadExact` what
// BRAssetPayloadReadsExactly said of them. Only header->operation and header->version are read: a
// header that is not BR_ASSET_SCRIPT_ASSET has DA_UNDEFINED and is not decided. inputs[0, inputCount)
// is every input of the transaction in order; when they could not all be read, pass ONE input that is
// not known. outputCount is the transaction's output count.
//
// `work` needs one int64_t per entry of the known inputs. `out` receives the answer: outputCount entries
// for each counted entry of the inputs always suffice, and so does one entry for each counted entry of
// the inputs plus, for each instruction, one (a range: outputIndex + 1, at most outputCount). Read `out`
// only when the status is BR_ASSET_ALLOCATION_ALLOCATED.
static inline BRAssetAllocation BRAssetAllocate(const BRAssetHeader *header,
                                                const BRAssetTransferInstruction *insts, size_t instCount,
                                                int payloadExact,
                                                const BRAssetInputStack *inputs, size_t inputCount,
                                                int32_t outputCount,
                                                int64_t *work, size_t workCap,
                                                BRAssetOutputUnits *out, size_t outCap)
{
    size_t i, j;
    int burnType, legacy, carried = 0;

    if (! header || (instCount > 0 && ! insts) || (inputCount > 0 && ! inputs)) {
        return _BRAssetAllocUndecided(BR_ASSET_WHY_ARGUMENTS);
    }
    for (i = 0; i < inputCount; i++) {
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_UNKNOWN_INPUT_READ)
        if (! inputs[i].known) continue;
#endif
        if (inputs[i].unitCount > 0 && ! inputs[i].units) return _BRAssetAllocUndecided(BR_ASSET_WHY_ARGUMENTS);

        for (j = 0; j < inputs[i].unitCount; j++) {
            if (! inputs[i].units[j].assetId) return _BRAssetAllocUndecided(BR_ASSET_WHY_ARGUMENTS);
        }
    }

#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_INEXACT_READ)
    if (! payloadExact) return _BRAssetAllocUndecided(BR_ASSET_WHY_PAYLOAD_NOT_EXACT);
#endif
    if (header->operation == DA_TRANSFER) burnType = 0;
    else if (header->operation == DA_BURN) burnType = 1;
    else if (header->operation == DA_ISSUANCE) return _BRAssetAllocUndecided(BR_ASSET_WHY_ISSUANCE);
    else return _BRAssetAllocUndecided(BR_ASSET_WHY_UNCLASSIFIABLE);

    if (outputCount < 1) return _BRAssetAllocUndecided(BR_ASSET_WHY_NO_OUTPUTS);
    if (inputCount == 0) return _BRAssetAllocUndecided(BR_ASSET_WHY_NO_INPUTS);

#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_UNKNOWN_INPUT_READ)
    for (i = 0; i < inputCount; i++) {
        if (! inputs[i].known) return _BRAssetAllocUndecided(BR_ASSET_WHY_INPUT_UNKNOWN);
    }
#endif
    for (i = 0; i < inputCount; i++) {
        if (_BRAssetAllocCarries(&inputs[i])) carried = 1;
    }
    if (! carried) return _BRAssetAllocNotAnAssetTransfer();
    if (_BRAssetAllocAnyPercent(insts, instCount)) return _BRAssetAllocUndecided(BR_ASSET_WHY_PERCENT);

#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_RULES_IGNORED)
    for (i = 0; i < inputCount; i++) {
        for (j = 0; j < inputs[i].unitCount; j++) {
            if (inputs[i].units[j].count > 0 && ! inputs[i].units[j].ruleFree) {
                return _BRAssetAllocUndecided(BR_ASSET_WHY_RULES);
            }
        }
    }
#endif

#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_LEGACY_READS)
    legacy = 0;
#else
    legacy = (header->version < 3 && ! _BRAssetAllocCarries(&inputs[0]));
#endif
    return _BRAssetAllocDistribute(insts, instCount, inputs, inputCount, outputCount, burnType, legacy,
                                   work, work ? workCap : 0, out, out ? outCap : 0);
}

// ---- an issuance (Android: AssetTransferAllocator.allocateIssuance, issuanceOutputCredits) -------

// Where the units an ISSUANCE creates land (see THE RULES). `assetId` is the id the wallet names the
// new asset by (BRAssetIdForIssuance, or the platform's placeholder for an issuance it cannot name);
// the answer's entries carry that pointer. header->operation, hasTotalQuantity and totalQuantity are
// read. One entry of `out` for each instruction (a range: outputIndex + 1, at most
// outputCount) and one more always suffice, and so do outputCount entries.
static inline BRAssetAllocation BRAssetAllocateIssuance(const BRAssetHeader *header,
                                                        const BRAssetTransferInstruction *insts, size_t instCount,
                                                        const char *assetId, int32_t outputCount, int payloadExact,
                                                        BRAssetOutputUnits *out, size_t outCap)
{
    BRAssetUnits issued;
    BRAssetInputStack stack;
    int64_t work[1];

    if (! header || (instCount > 0 && ! insts) || ! assetId) return _BRAssetAllocUndecided(BR_ASSET_WHY_ARGUMENTS);
    if (header->operation != DA_ISSUANCE) return _BRAssetAllocUndecided(BR_ASSET_WHY_NOT_ISSUANCE);
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_INEXACT_READ)
    if (! payloadExact) return _BRAssetAllocUndecided(BR_ASSET_WHY_PAYLOAD_NOT_EXACT);
#endif
    if (outputCount < 1) return _BRAssetAllocUndecided(BR_ASSET_WHY_NO_OUTPUTS);
    if (! header->hasTotalQuantity) return _BRAssetAllocUndecided(BR_ASSET_WHY_NO_ISSUED_AMOUNT);
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_ISSUANCE_UNBOUNDED)
    if (header->totalQuantity <= 0 || header->totalQuantity > BR_ASSET_MAX_ISSUANCE) {
        return _BRAssetAllocNotAnAssetTransfer();
    }
#endif
    if (_BRAssetAllocAnyPercent(insts, instCount)) return _BRAssetAllocUndecided(BR_ASSET_WHY_PERCENT);
    issued.assetId = assetId;
    issued.count = header->totalQuantity;
    issued.ruleFree = 0;
    stack.known = 1;
    stack.units = &issued;
    stack.unitCount = 1;
    return _BRAssetAllocDistribute(insts, instCount, &stack, 1, outputCount, 0, 0, work, 1, out, out ? outCap : 0);
}

// ---- one output's credit (Android: AssetCreditRules.forOutput) -----------------------------------

static inline BRAssetOutputCredit _BRAssetAllocCredit(BRAssetOutputCreditKind kind)
{
    BRAssetOutputCredit c;

    c.kind = kind;
    c.hasUnits = 0;
    c.assetId = NULL;
    c.count = 0;
    c.label = NULL;
    return c;
}

// Does an instruction name `vout`? A range names every output up to its index.
static inline int _BRAssetAllocNames(const BRAssetTransferInstruction *inst, int32_t vout)
{
    return inst->range ? (vout <= inst->outputIndex) : (inst->outputIndex == vout);
}

// Is `vout` the transaction's last output (Kotlin: vout == outputCount - 1, in 32-bit arithmetic)?
static inline int _BRAssetAllocIsLast(int32_t vout, int32_t outputCount)
{
    return (uint32_t)vout == (uint32_t)outputCount - 1u;
}

// What `vout` holds under `allocation` (see THE RULES). `outputs` is the buffer the allocation was
// written to, insts[0, instCount) the instructions it was made from, outputCount the transaction's
// output count. `vout` is taken as given: an index the transaction does not have holds nothing under a
// decided allocation.
static inline BRAssetOutputCredit BRAssetCreditForOutput(BRAssetAllocation allocation,
                                                         const BRAssetOutputUnits *outputs,
                                                         const BRAssetTransferInstruction *insts, size_t instCount,
                                                         int32_t vout, int32_t outputCount)
{
    BRAssetOutputCredit c = _BRAssetAllocCredit(BR_ASSET_OUTPUT_HOLDS);
    const BRAssetOutputUnits *held = NULL;
    const char *moved = NULL;
    size_t i, heldCount = 0;
    int single = 1;

    if (allocation.status == BR_ASSET_ALLOCATION_NOT_AN_ASSET_TRANSFER) return c;

    if (allocation.status == BR_ASSET_ALLOCATION_ALLOCATED) {
        if (allocation.count > 0 && ! outputs) return _BRAssetAllocCredit(BR_ASSET_OUTPUT_UNKNOWN);

        for (i = 0; i < allocation.count; i++) {
            if (! moved) moved = outputs[i].assetId;
            else if (strcmp(outputs[i].assetId, moved) != 0) single = 0;

            if (outputs[i].vout == vout) {
                if (heldCount == 0) held = &outputs[i];
                heldCount++;
            }
        }
        if (heldCount == 0) {
            c.label = single ? moved : NULL;
            return c;
        }
        if (heldCount > 1) return _BRAssetAllocCredit(BR_ASSET_OUTPUT_MIXED);
        c.hasUnits = 1;
        c.assetId = held->assetId;
        c.count = held->count;
        c.label = held->assetId;
        return c;
    }

    if (instCount > 0 && ! insts) return _BRAssetAllocCredit(BR_ASSET_OUTPUT_UNKNOWN);
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_UNDECIDED_EMPTY)
    if (_BRAssetAllocIsLast(vout, outputCount)) return _BRAssetAllocCredit(BR_ASSET_OUTPUT_UNKNOWN);

    for (i = 0; i < instCount; i++) {
        if (_BRAssetAllocNames(&insts[i], vout)) return _BRAssetAllocCredit(BR_ASSET_OUTPUT_UNKNOWN);
    }
#endif
    return c;
}

// ---- the most an output can be delivered (Android: AssetCreditRules.maxDeliverable) --------------

// Can what the non-percent instructions consume not be counted (Android:
// AssetTxQuantity.consumptionUncountable)? A header of an operation this reader does not classify is
// never asked.
static inline int _BRAssetAllocUncountable(const BRAssetHeader *header, const BRAssetTransferInstruction *insts,
                                           size_t instCount)
{
    int64_t assigned = 0, consumed;
    size_t i;

    if (header->operation != DA_ISSUANCE && header->operation != DA_TRANSFER && header->operation != DA_BURN) return 0;

    for (i = 0; i < instCount; i++) {
        if (insts[i].percent) continue;
        if (insts[i].amount < 0 || insts[i].outputIndex < 0) return 1;
        consumed = insts[i].amount;
        if (insts[i].range &&
            ! _BRAssetAllocMul((int64_t)insts[i].outputIndex + 1, insts[i].amount, &consumed)) return 1;
        if (! _BRAssetAllocAdd(assigned, consumed, &assigned)) return 1;
    }
    return 0;
}

// The most units the transaction's instructions can deliver to `vout` (see THE RULES): a bound an
// indexer's count for the output is held to. Only header->operation is read.
static inline BRAssetDeliverable BRAssetMaxDeliverable(const BRAssetHeader *header,
                                                       const BRAssetTransferInstruction *insts, size_t instCount,
                                                       int32_t vout, int32_t outputCount)
{
    BRAssetDeliverable d = { 0, 0 };
    int64_t max = 0;
    size_t i;

    if (! header || (instCount > 0 && ! insts)) return d;
    if (_BRAssetAllocUncountable(header, insts, instCount)) return d;
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_LAST_BOUNDED)
    if (_BRAssetAllocIsLast(vout, outputCount)) {
        d.unbounded = 1;
        return d;
    }
#endif

    for (i = 0; i < instCount; i++) {
        if (! _BRAssetAllocNames(&insts[i], vout)) continue;
        if (header->operation == DA_BURN && ! insts[i].range && insts[i].outputIndex == BR_ASSET_BURN_OUTPUT) continue;

        if (insts[i].percent) {
            d.unbounded = 1;
            return d;
        }
        if (! _BRAssetAllocAddExact(max, insts[i].amount, &max)) return d;
    }
    d.max = max;
    return d;
}

// ---- what the inputs carried in all (Android: resolveInputAssetUnits) ----------------------------

// The total units inputs[0, inputCount) carried (see THE RULES); hasRow, quantity, rowIsTargeted and
// fundingIsAssetTx are read, each only where the rule needs it, and no input after the one that makes
// the answer UNKNOWN.
//
// `zeroRows` is NULL when nobody asks why (Kotlin: unresolved = null). Otherwise it has room for
// zeroRowCap indices (inputCount always suffice), and when the answer is UNKNOWN only because of rows
// storing zero, the indices of those inputs are written to it in order, zeroRowCount says how many, and
// otherUnits is the total of the other inputs. More such rows than zeroRowCap is UNKNOWN with no row
// reported, never a shortened list.
static inline BRAssetInputUnits BRAssetResolveInputUnits(const BRAssetInputFacts *inputs, size_t inputCount,
                                                         size_t *zeroRows, size_t zeroRowCap)
{
    BRAssetInputUnits r = { 0, 0, 0, 0 };
    int64_t total = 0;
    size_t i, n = 0;

    if (inputCount > 0 && ! inputs) return r;

    for (i = 0; i < inputCount; i++) {
        if (inputs[i].hasRow && inputs[i].quantity > 0) {
            if (! _BRAssetAllocAdd(total, inputs[i].quantity, &total)) return r;
            continue;
        }
        if (inputs[i].hasRow) {
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_ZERO_ROW_COUNTS)
            if (inputs[i].rowIsTargeted == BR_ASSET_FACT_NO) continue;
            if (! zeroRows || n >= zeroRowCap) return r;
            zeroRows[n++] = i;
#endif
            continue;
        }
#if ! (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_NO_ROW_EMPTY)
        if (inputs[i].fundingIsAssetTx != BR_ASSET_FACT_NO) return r;
#endif
    }

    if (n == 0) {
        r.known = 1;
        r.units = total;
        return r;
    }
    r.zeroRowCount = n;
    r.otherUnits = total;
    return r;
}

// ---- one input's stack (Android: backedInputStack) -----------------------------------------------

// What one input of a transfer carried, as far as the wallet can vouch for it (see THE RULES): a stack
// that is not known, an empty one, or one entry written to `*slot` (its ruleFree is 0: the caller says
// whether the asset is known to carry no transfer rules). The stack points at `slot`, and the entry's
// id is input->assetId.
static inline BRAssetInputStack BRAssetBackedInputStack(const BRAssetInputFacts *input, BRAssetUnits *slot)
{
    BRAssetInputStack unknown = { 0, NULL, 0 }, nothing = { 1, NULL, 0 }, one = { 1, NULL, 1 };

    if (! input) return unknown;

    if (input->hasRow) {
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_UNCHECKED_COUNTS)
        if (input->quantity != 0 || BRAssetCreditCounts(input->credit)) {
#else
        if (BRAssetCreditCounts(input->credit)) {
#endif
            if (input->quantity <= 0) return nothing;
            if (! input->assetId || input->assetId[0] == '\0' || ! slot) return unknown;
            slot->assetId = input->assetId;
            slot->count = input->quantity;
            slot->ruleFree = 0;
            one.units = slot;
            return one;
        }
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_ZERO_ROW_COUNTS)
        if (input->credit == BR_ASSET_CREDIT_UNCHECKED && input->quantity == 0) return nothing;
#else
        if (input->credit == BR_ASSET_CREDIT_UNCHECKED && input->quantity == 0 &&
            input->rowIsTargeted == BR_ASSET_FACT_NO) return nothing;
#endif
        return unknown;
    }
#if (ASSET_ALLOCATE_UNFIXED & ASSET_ALLOCATE_RED_NO_ROW_EMPTY)
    return nothing;
#else
    return (input->fundingHasDataOutput == BR_ASSET_FACT_NO) ? nothing : unknown;
#endif
}

// ---- what an indexer's answer says (Android: AssetCreditRules.fromIndexer) -----------------------

// The credit an indexer's answer for one output gives it (see THE RULES): 1 and *credit, or 0 when the
// answer says nothing (Kotlin: null; *credit is then BR_ASSET_OUTPUT_UNKNOWN). entries[0, entryCount)
// is read only for BR_ASSET_STACK_FOUND.
static inline int BRAssetCreditFromIndexer(BRAssetStackLookup lookup, const BRAssetUnits *entries, size_t entryCount,
                                           BRAssetOutputCredit *credit)
{
    const char *first = NULL;
    int64_t sum = 0;
    size_t i;

    if (! credit) return 0;
    *credit = _BRAssetAllocCredit(BR_ASSET_OUTPUT_UNKNOWN);
    if (lookup != BR_ASSET_STACK_FOUND || (entryCount > 0 && ! entries)) return 0;

    for (i = 0; i < entryCount; i++) {
        if (entries[i].count <= 0) continue;
        if (! entries[i].assetId) return 0;
        if (! first) first = entries[i].assetId;

        if (strcmp(entries[i].assetId, first) != 0) {
            credit->kind = BR_ASSET_OUTPUT_MIXED;
            return 1;
        }
    }

    for (i = 0; i < entryCount; i++) {
        if (entries[i].count > 0 && ! _BRAssetAllocAdd(sum, entries[i].count, &sum)) return 0;
    }
    credit->kind = BR_ASSET_OUTPUT_HOLDS;

    if (first) {
        credit->hasUnits = 1;
        credit->assetId = first;
        credit->count = sum;
        credit->label = first;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetAllocate_h
