//
//  BRScanPartition.h
//
//  How a reconcile scan ("Scan for missing funds") reports what the node returned: each output is put
//  through the wallet's OWN partition -- the one its balance is built from (BROutpointClassify.h) -- and
//  listed in exactly one class. The headline SPENDABLE figure is therefore the wallet's spendable
//  balance by construction, wherever the node agrees with the wallet; walletOnly and NOT_IN_WALLET are
//  where they disagree. Only NOT_IN_WALLET is missing funds. Until 2026-11 this lived only in Android's
//  Kotlin (core/.../reconcile/ScanPartition.kt: ScanClass, WalletOutpointCode, ClassTotal, HeldKind,
//  heldKindOf, partitionScan, ScanPartition.matchesWallet / move, walletOnlyOf). It moves here unchanged.
//  The distinct-outpoint and distinct-address lists of the same file are BRReconcilePlan.h's.
//
//  THE RULES:
//    - CLASS OF A ROW (BRScanClassForCode), from its BROutpointCode:
//        SPENDABLE -> SPENDABLE; DIGIDOLLAR -> DIGIDOLLAR; IMMATURE -> IMMATURE;
//        SPENT, PENDING -> PENDING;
//        HELD -> by why it is held: ASSET -> HELD_ASSET, UNKNOWN_REMAINDER -> HELD_UNKNOWN,
//                PROVEN_ZERO -> PROVEN_PLAIN (a held kind this header does not know -> HELD_ASSET);
//        every other code (NOT_CREDITED, NOT_HELD, CONFLICTED, UNREADABLE, unknown) -> NOT_IN_WALLET.
//    - WHY A HELD ROW IS HELD (BRScanHeldKindOf), from what the hold rule reads (Android:
//      HeldOutputFacts). No facts -> ASSET. A stored quantity above zero -> ASSET. Otherwise the
//      platform's two answers to "does the transaction's asset data credit this output?" (Android:
//      AssetTxQuantity.targetsOutput), asked once with the inputs' units known to be 0 (namedAnyway)
//      and once with them unknown (namedIfUnknown): named anyway, or not named even when unknown ->
//      ASSET. Left: the output's only claim to units is the last-output remainder, so it is
//      PROVEN_ZERO when the hold rule now answers that it would not hold it (heldByRuleNow == 0), and
//      UNKNOWN_REMAINDER otherwise (it would, or there is no answer).
//    - THE PARTITION (BRScanPartitionMake). Rows in order; each lands in its class's member list, in
//      row order. No partition (0) when there are no codes, when there is not exactly one code per
//      row, or when the wallet-only answer is missing. Each class's total is its member count and the
//      sum of its members' amounts (a sum wraps as a 64-bit two's-complement integer, as Kotlin's Long
//      does). The held kinds are the platform's, one per row, read only for HELD rows (Android computes
//      them asynchronously, so they come in as data); a HELD row with no held kind, or one this header
//      does not know, is no partition.
//    - MATCHES THE WALLET (BRScanPartitionMatchesWallet): no NOT_IN_WALLET row, no wallet-only
//      output, and the SPENDABLE sum equal to the wallet's spendable balance.
//    - MOVE (BRScanPartitionMove): the same partition with the members of `from` whose outpoint is
//      among `moved` taken out of `from` and appended to `to`, in their order in `from`. Nothing to
//      move, or nothing of `from` among it, is the partition unchanged. Totals are recomputed. As in
//      Kotlin, `to` is built from its list BEFORE the move, so moving a class onto itself appends the
//      moving members a second time.
//    - WALLET ONLY (BRScanWalletOnlyOf): BRWalletSpendableNotListed's [count, sat] answer, read
//      strictly: missing, shorter than 2, or a negative count or sum is no answer; a count above
//      INT32_MAX is read as INT32_MAX (Kotlin's Int).
//    Outpoints compare as BRUTXO bytes (hash, then index); a platform that keeps txids as hex parses
//    them first, so two spellings of one txid are one outpoint.
//
//  Allocation: the member lists (malloc; BRScanPartitionFree releases them, and is safe on a partition
//  a failed call zeroed). No wallet, no locking, no I/O. Header-only, static inline. Move takes
//  O((members + moved) log moved).
//
//  Test seams (host KAT scan_partition_kat in the Android repo, ScanPartitionTest case for case):
//  SCAN_PARTITION_UNFIXED, tested by VALUE as a set of bits; each comparison arm sets one bit and fails
//  only its own cases. Unset or =0 is what ships.
//    1   SCAN_PARTITION_RED_PENDING_MISSING      SPENT and PENDING rows read as NOT_IN_WALLET.
//    2   SCAN_PARTITION_RED_WALLET_ONLY_IGNORED  the match ignores the wallet-only outputs.
//    4   SCAN_PARTITION_RED_HELD_KIND_IGNORED    every HELD row reads as HELD_ASSET.
//    8   SCAN_PARTITION_RED_MOVE_KEEPS_SOURCE    a move leaves the moved members in `from` too.
//    16  SCAN_PARTITION_RED_WALLET_ONLY_LAX      a negative wallet-only answer is read.
//    32  SCAN_PARTITION_RED_NO_ANSWER_PROVEN     no hold-rule answer reads as PROVEN_ZERO.
//

#ifndef BRScanPartition_h
#define BRScanPartition_h

#include "BRWallet.h"            // BRUTXO
#include "BROutpointClassify.h"  // BROutpointCode
#include "BRInt.h"               // UInt256
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCAN_PARTITION_UNFIXED
#define SCAN_PARTITION_UNFIXED 0
#endif

#define SCAN_PARTITION_RED_PENDING_MISSING      1
#define SCAN_PARTITION_RED_WALLET_ONLY_IGNORED  2
#define SCAN_PARTITION_RED_HELD_KIND_IGNORED    4
#define SCAN_PARTITION_RED_MOVE_KEEPS_SOURCE    8
#define SCAN_PARTITION_RED_WALLET_ONLY_LAX      16
#define SCAN_PARTITION_RED_NO_ANSWER_PROVEN     32

// Android's ScanClass, in its order.
typedef enum {
    BR_SCAN_SPENDABLE = 0,      // in the wallet's spendable set: what its DGB balance sums
    BR_SCAN_HELD_ASSET = 1,     // held out of the spendable set because it carries DigiAsset units
    BR_SCAN_HELD_UNKNOWN = 2,   // held out because the last output's remainder is not known
    BR_SCAN_PROVEN_PLAIN = 3,   // held out until now, proven to carry no units
    BR_SCAN_DIGIDOLLAR = 4,     // a DigiDollar token output
    BR_SCAN_IMMATURE = 5,       // a coin-generation output that has not matured
    BR_SCAN_PENDING = 6,        // in a transaction the wallet holds as pending, or spent by one
    BR_SCAN_NOT_IN_WALLET = 7   // the wallet does not credit it: the only missing-funds class
} BRScanClass;

#define BR_SCAN_CLASS_COUNT 8

// Android's HeldKind, in its order.
typedef enum {
    BR_SCAN_HELD_KIND_ASSET = 0,
    BR_SCAN_HELD_KIND_UNKNOWN_REMAINDER = 1,
    BR_SCAN_HELD_KIND_PROVEN_ZERO = 2
} BRScanHeldKind;

// Android's ClassTotal.
typedef struct {
    int64_t count;
    int64_t sat;
} BRScanClassTotal;

// One row the node returned: its outpoint (wallet byte order) and its amount.
typedef struct {
    BRUTXO outpoint;
    int64_t amountSat;
} BRScanRow;

// What the hold rule reads of a held output (Android: HeldOutputFacts, with targetsOutput's two answers).
typedef struct {
    int hasRowQuantity;     // 0: no stored quantity (Kotlin null)
    int64_t rowQuantity;
    int namedAnyway;        // targetsOutput(header, vout, firstNonOpReturnVout, inputUnits = 0, outputCount)
    int namedIfUnknown;     // targetsOutput(header, vout, firstNonOpReturnVout, inputUnits = null, outputCount)
    int heldByRuleNow;      // 1 yes, 0 no, any other value: no answer (Kotlin null)
} BRScanHeldFacts;

typedef struct {
    BRScanClassTotal totals[BR_SCAN_CLASS_COUNT];
    size_t *members[BR_SCAN_CLASS_COUNT];       // row indices, per class
    size_t memberCount[BR_SCAN_CLASS_COUNT];
    BRScanClassTotal walletOnly;                // the wallet's spendable outputs the node did not report
    int64_t walletSpendableSat;                 // the wallet's spendable balance at the time of the scan
} BRScanPartition;

static inline BRScanClass BRScanClassForCode(int32_t code, BRScanHeldKind heldKind)
{
    switch (code) {
    case BR_OUTPOINT_SPENDABLE: return BR_SCAN_SPENDABLE;
    case BR_OUTPOINT_DIGIDOLLAR: return BR_SCAN_DIGIDOLLAR;
    case BR_OUTPOINT_IMMATURE: return BR_SCAN_IMMATURE;
    case BR_OUTPOINT_SPENT:
    case BR_OUTPOINT_PENDING:
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_PENDING_MISSING
        return BR_SCAN_NOT_IN_WALLET;
#else
        return BR_SCAN_PENDING;
#endif
    case BR_OUTPOINT_HELD:
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_HELD_KIND_IGNORED
        (void)heldKind;
        return BR_SCAN_HELD_ASSET;
#else
        switch (heldKind) {
        case BR_SCAN_HELD_KIND_UNKNOWN_REMAINDER: return BR_SCAN_HELD_UNKNOWN;
        case BR_SCAN_HELD_KIND_PROVEN_ZERO: return BR_SCAN_PROVEN_PLAIN;
        case BR_SCAN_HELD_KIND_ASSET:
        default: return BR_SCAN_HELD_ASSET;
        }
#endif
    default: return BR_SCAN_NOT_IN_WALLET;
    }
}

// Why a held output is held. facts NULL: what the hold rule reads could not be read (Kotlin null).
static inline BRScanHeldKind BRScanHeldKindOf(const BRScanHeldFacts *facts)
{
    if (! facts) return BR_SCAN_HELD_KIND_ASSET;
    if ((facts->hasRowQuantity ? facts->rowQuantity : 0) > 0) return BR_SCAN_HELD_KIND_ASSET;
    if (facts->namedAnyway || ! facts->namedIfUnknown) return BR_SCAN_HELD_KIND_ASSET;
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_NO_ANSWER_PROVEN
    return (facts->heldByRuleNow != 1) ? BR_SCAN_HELD_KIND_PROVEN_ZERO : BR_SCAN_HELD_KIND_UNKNOWN_REMAINDER;
#else
    return (facts->heldByRuleNow == 0) ? BR_SCAN_HELD_KIND_PROVEN_ZERO : BR_SCAN_HELD_KIND_UNKNOWN_REMAINDER;
#endif
}

// BRWalletSpendableNotListed's answer as [count, sat]. Returns 1 and sets *out, or 0 (no answer).
static inline int BRScanWalletOnlyOf(const int64_t *answer, size_t answerLen, BRScanClassTotal *out)
{
    if (! out) return 0;
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_WALLET_ONLY_LAX
    if (! answer || answerLen < 2) return 0;
#else
    if (! answer || answerLen < 2 || answer[0] < 0 || answer[1] < 0) return 0;
#endif
    out->count = answer[0] > INT32_MAX ? INT32_MAX : answer[0];
    out->sat = answer[1];
    return 1;
}

static inline void BRScanPartitionFree(BRScanPartition *p)
{
    if (! p) return;
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        free(p->members[c]);
        p->members[c] = NULL;
        p->memberCount[c] = 0;
    }
}

static inline BRScanClassTotal BRScanPartitionTotal(const BRScanPartition *p, BRScanClass c)
{
    BRScanClassTotal none = { 0, 0 };
    return (p && (unsigned)c < BR_SCAN_CLASS_COUNT) ? p->totals[c] : none;
}

// The headline: the node's outputs that the wallet counts as spendable.
static inline int64_t BRScanPartitionSpendableSat(const BRScanPartition *p)
{
    return BRScanPartitionTotal(p, BR_SCAN_SPENDABLE).sat;
}

// True only when the two views agree output for output.
static inline int BRScanPartitionMatchesWallet(const BRScanPartition *p)
{
    if (! p) return 0;
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_WALLET_ONLY_IGNORED
    return BRScanPartitionTotal(p, BR_SCAN_NOT_IN_WALLET).count == 0 &&
        BRScanPartitionSpendableSat(p) == p->walletSpendableSat;
#else
    return BRScanPartitionTotal(p, BR_SCAN_NOT_IN_WALLET).count == 0 && p->walletOnly.count == 0 &&
        BRScanPartitionSpendableSat(p) == p->walletSpendableSat;
#endif
}

// Each class's total from its members' rows (Kotlin's fold: a Long sum, wrapping).
static inline void _BRScanTotals(BRScanPartition *p, const BRScanRow rows[])
{
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        uint64_t sat = 0;
        for (size_t i = 0; i < p->memberCount[c]; i++) sat += (uint64_t)rows[p->members[c][i]].amountSat;
        p->totals[c].count = (int64_t)p->memberCount[c];
        p->totals[c].sat = (int64_t)sat;
    }
}

// Allocates every class's list for counts[c] members; 0 (and p's lists freed and zeroed) on failure.
static inline int _BRScanAllocMembers(BRScanPartition *p, const size_t counts[])
{
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        p->members[c] = (size_t *)malloc((counts[c] ? counts[c] : 1) * sizeof(size_t));
        p->memberCount[c] = 0;
        if (! p->members[c]) { BRScanPartitionFree(p); return 0; }
    }
    return 1;
}

// Partition the node's rows (already distinct: BRReconcileDistinctOutpoints) by the wallet's classes.
// codes: one BROutpointCode per row (BRWalletClassifyOutpoints); heldKinds: one BRScanHeldKind per row,
// read only for HELD rows; walletOnly: BRScanWalletOnlyOf's answer. Returns 1 and fills *out (free it
// with BRScanPartitionFree), or 0 with *out zeroed: no partition.
static inline int BRScanPartitionMake(const BRScanRow rows[], size_t rowCount, const int32_t codes[], size_t codeCount,
                                      const int32_t heldKinds[], const BRScanClassTotal *walletOnly,
                                      int64_t walletSpendableSat, BRScanPartition *out)
{
    if (! out) return 0;
    memset(out, 0, sizeof(*out));
    if (! codes || codeCount != rowCount || ! walletOnly) return 0;
    if (rowCount > 0 && ! rows) return 0;
    if (rowCount > SIZE_MAX / sizeof(size_t)) return 0;

    size_t counts[BR_SCAN_CLASS_COUNT] = { 0 };
    for (size_t i = 0; i < rowCount; i++) {
        BRScanHeldKind kind = BR_SCAN_HELD_KIND_ASSET;
        if (codes[i] == BR_OUTPOINT_HELD) {
            if (! heldKinds) return 0;
            if (heldKinds[i] != BR_SCAN_HELD_KIND_ASSET && heldKinds[i] != BR_SCAN_HELD_KIND_UNKNOWN_REMAINDER &&
                heldKinds[i] != BR_SCAN_HELD_KIND_PROVEN_ZERO) return 0;
            kind = (BRScanHeldKind)heldKinds[i];
        }
        counts[BRScanClassForCode(codes[i], kind)]++;
    }
    if (! _BRScanAllocMembers(out, counts)) return 0;
    for (size_t i = 0; i < rowCount; i++) {
        BRScanHeldKind kind = (codes[i] == BR_OUTPOINT_HELD) ? (BRScanHeldKind)heldKinds[i] : BR_SCAN_HELD_KIND_ASSET;
        BRScanClass c = BRScanClassForCode(codes[i], kind);
        out->members[c][out->memberCount[c]++] = i;
    }
    _BRScanTotals(out, rows);
    out->walletOnly = *walletOnly;
    out->walletSpendableSat = walletSpendableSat;
    return 1;
}

static inline int _BRScanOutpointCompare(const void *a, const void *b)
{
    const BRUTXO *x = (const BRUTXO *)a, *y = (const BRUTXO *)b;
    int r = memcmp(x->hash.u8, y->hash.u8, sizeof(x->hash.u8));
    if (r) return r;
    return (x->n < y->n) ? -1 : (x->n > y->n) ? 1 : 0;
}

// A deep copy of p into *out; 0 (and *out zeroed) on failure.
static inline int _BRScanPartitionCopy(const BRScanPartition *p, BRScanPartition *out)
{
    memset(out, 0, sizeof(*out));
    if (! _BRScanAllocMembers(out, p->memberCount)) return 0;
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        if (p->memberCount[c]) memcpy(out->members[c], p->members[c], p->memberCount[c] * sizeof(size_t));
        out->memberCount[c] = p->memberCount[c];
        out->totals[c] = p->totals[c];
    }
    out->walletOnly = p->walletOnly;
    out->walletSpendableSat = p->walletSpendableSat;
    return 1;
}

// The same partition with the members of `from` whose outpoint is among moved[0..movedCount) put in `to`.
// rows: the rows p was made from. Returns 1 and fills *out (a new partition; p is unchanged), or 0 with
// *out zeroed (an argument out of range or an allocation failure).
static inline int BRScanPartitionMove(const BRScanPartition *p, const BRScanRow rows[], size_t rowCount,
                                      const BRUTXO moved[], size_t movedCount, BRScanClass from, BRScanClass to,
                                      BRScanPartition *out)
{
    if (! out) return 0;
    memset(out, 0, sizeof(*out));
    if (! p || (unsigned)from >= BR_SCAN_CLASS_COUNT || (unsigned)to >= BR_SCAN_CLASS_COUNT) return 0;
    if (movedCount > 0 && ! moved) return 0;
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        for (size_t i = 0; i < p->memberCount[c]; i++) if (! rows || p->members[c][i] >= rowCount) return 0;
    }
    if (movedCount == 0) return _BRScanPartitionCopy(p, out);
    if (movedCount > SIZE_MAX / sizeof(BRUTXO)) return 0;

    BRUTXO *keys = (BRUTXO *)malloc(movedCount * sizeof(BRUTXO));
    if (! keys) return 0;
    memcpy(keys, moved, movedCount * sizeof(BRUTXO));
    qsort(keys, movedCount, sizeof(BRUTXO), _BRScanOutpointCompare);

    const size_t nFrom = p->memberCount[from], nTo = p->memberCount[to];
    size_t nLeaving = 0;
    for (size_t i = 0; i < nFrom; i++) {
        if (bsearch(&rows[p->members[from][i]].outpoint, keys, movedCount, sizeof(BRUTXO), _BRScanOutpointCompare))
            nLeaving++;
    }
    if (nLeaving == 0) { free(keys); return _BRScanPartitionCopy(p, out); }
    if (nTo > SIZE_MAX / sizeof(size_t) - nLeaving) { free(keys); return 0; }

    size_t counts[BR_SCAN_CLASS_COUNT];
    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) counts[c] = p->memberCount[c];
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_MOVE_KEEPS_SOURCE
    counts[from] = nFrom;
#else
    counts[from] = nFrom - nLeaving;
#endif
    counts[to] = nTo + nLeaving;   // built from `to` before the move, as Kotlin does (also when from == to)
    if (! _BRScanAllocMembers(out, counts)) { free(keys); return 0; }

    for (size_t c = 0; c < BR_SCAN_CLASS_COUNT; c++) {
        if (c == (size_t)from || c == (size_t)to) continue;
        if (p->memberCount[c]) memcpy(out->members[c], p->members[c], p->memberCount[c] * sizeof(size_t));
        out->memberCount[c] = p->memberCount[c];
    }
    size_t *staying = out->members[from];
    size_t nStaying = 0;
    size_t *toList = out->members[to];
    size_t nToList = 0;
    if (from != to) {
        for (size_t i = 0; i < nFrom; i++) {
            size_t r = p->members[from][i];
            int leaves = bsearch(&rows[r].outpoint, keys, movedCount, sizeof(BRUTXO), _BRScanOutpointCompare) != NULL;
#if SCAN_PARTITION_UNFIXED & SCAN_PARTITION_RED_MOVE_KEEPS_SOURCE
            staying[nStaying++] = r;
#else
            if (! leaves) staying[nStaying++] = r;
#endif
            (void)leaves;
        }
        out->memberCount[from] = nStaying;
    }
    for (size_t i = 0; i < nTo; i++) toList[nToList++] = p->members[to][i];
    for (size_t i = 0; i < nFrom; i++) {
        size_t r = p->members[from][i];
        if (bsearch(&rows[r].outpoint, keys, movedCount, sizeof(BRUTXO), _BRScanOutpointCompare)) toList[nToList++] = r;
    }
    out->memberCount[to] = nToList;
    free(keys);

    _BRScanTotals(out, rows);
    out->walletOnly = p->walletOnly;
    out->walletSpendableSat = p->walletSpendableSat;
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BRScanPartition_h
