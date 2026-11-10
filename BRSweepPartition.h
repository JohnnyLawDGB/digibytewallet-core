//
//  BRSweepPartition.h
//
//  Which of a recovered seed's unspent outputs a Recover-funds sweep may spend as plain DGB, and the
//  bookkeeping around the DigiAsset moves that run before it. Until 2026-11 these rules lived only in
//  Android's Kotlin (core/.../recovery/SweepPartition.kt; ForeignUtxoAssetClassifier.kt's verdicts;
//  RecoverySequence.kt sweepExclusions and assetsLeftBehind). They decide which inputs a sweep signs, and
//  a DigiAsset output spent as plain DGB -- without the DigiAsset output structure -- is destroyed, not
//  moved. Both platforms take them from here. The raw-transaction fetch, the transfer-rule lookup, the
//  move itself and the signing stay each platform's own. BRRecoveryUtxo.h decides which rows of a lookup
//  are coins (one per outpoint); this header decides what may happen to each coin.
//
//  THE RULES:
//    - THE VERDICT for one outpoint (BRSweepClassifyRawTx, BRSweepVerdictOf). The platform fetches the
//      raw transaction that created the outpoint. No bytes (the fetch failed, threw, or returned an empty
//      body) is ABSENT. Bytes the core's parser (BRTransactionParseSigned, the network format) cannot
//      read are UNREADABLE. Otherwise the transaction is ASSET when the core's DigiAsset reader
//      (BRTXContainsAsset) finds a DigiAsset carrier on ANY of its outputs -- including a tagged carrier
//      it cannot classify, which BRDigiAsset.c holds as an asset -- and PLAIN otherwise.
//        ABSENT, UNREADABLE (or any class this header does not know) -> UNKNOWN: not classified.
//        PLAIN  -> classified, no asset.
//        ASSET  -> classified, carries an asset, with a transfer-rule state.
//      The question is asked of the TRANSACTION, not the output: every output of an asset transaction,
//      plain change included, carries the ASSET verdict. Over-holding costs a later move; under-holding
//      destroys an asset.
//      RULE STATE (BRSweepRuleStateRead). Only an ASSET verdict has one; the platform asks for it only
//      then. A lookup that failed or threw, was not wired, or answered a value this header does not know
//      reads as UNKNOWN. UNKNOWN and BOUND both mean "do not move this asset": only NONE may move.
//      For a non-asset verdict ruleState is set to UNKNOWN and means nothing.
//    - ONE FETCH PER TRANSACTION (BRSweepTxidGroups). Several outpoints of one transaction share one
//      fetch and one verdict: each row is mapped to the first row that names its txid (the row the
//      platform fetches for), and every row of the group takes that row's verdict. A row whose verdict
//      was never computed is UNKNOWN (BRSweepVerdictUnknown) -- the platform never leaves one unset.
//    - THE SPLIT (BRSweepBucketOf, BRSweepPartitionSplit). Each outpoint lands in exactly one bucket, and
//      "could we tell?" is asked BEFORE "is it an asset?":
//        not classified -> UNCLASSIFIED (held back: an unswept asset can be moved later, a burned one
//                          cannot, so "we could not check" never resolves to "go ahead");
//        carries asset  -> ASSET (moved by the asset path, or left alone);
//        otherwise      -> SWEEPABLE.
//      A NULL verdict is UNCLASSIFIED. Input order is kept. The quoted total (sweepableSat) is the signed
//      sum of the SWEEPABLE rows' amounts only, so no one is quoted coins the sweep will not move; a sum
//      that does not fit an int64 is reported (OVERFLOW), never wrapped.
//    - HOLD EVERYTHING (BRSweepFoundAssetOrUnknown). Whether any row is ASSET or UNCLASSIFIED. For a
//      platform that cannot yet move DigiAssets: as of 2026-11-10 the iOS wallet sweeps NOTHING from a
//      seed for which this holds over every row of every profile the recovery would sweep -- a held coin
//      beside a swept one leaves the user a wallet half-emptied with no way to move what is left from
//      that device. Android, which moves assets first, does not use it; its rule is the split above.
//      NULL verdicts with a nonzero count hold.
//    - SWEEP EXCLUSIONS (BRSweepExclusions). Assets move first; the sweep is the complement of the moves.
//      For every move record, its asset outpoint AND every input its plan named are withheld from the
//      sweep -- whether or not the move broadcast. A broadcast move spent them (sweeping one would
//      double-spend an outpoint an unconfirmed transaction already claimed). A failed move spent nothing,
//      and its plan's inputs must stay for the retry. A move with no plan withholds only its own asset
//      outpoint. The answer is a SET: sorted (txid bytes, then vout) and distinct, so membership is a
//      binary search (BRSweepOutpointIn).
//    - LEFT BEHIND (BRSweepAssetsLeftBehind). The asset-bearing outpoints the result screen may call
//      "left behind": those with no move that arrived. A move that failed, and an outpoint the move phase
//      never reported at all, are both left behind (over-reporting sends someone to check a wallet that
//      does hold something; under-reporting calls it empty when it is not). The answer is indices into
//      the asset-bearing list, in its order, duplicates kept.
//
//  OUTPOINTS. Rows are BRRecoveryUtxo (BRRecoveryUtxo.h); an outpoint elsewhere is BRSweepOutpoint. TXIDS
//  are the 32 bytes in the order the caller chooses -- the same order for every row -- and compare as
//  bytes, so a platform that keeps txids as hex (Android's "txid:vout" strings) decodes them first.
//  COST. Server-controlled counts are never looped over quadratically: grouping by txid, the exclusion
//  set and the arrived set are each an in-place heapsort (O(n log n), no allocation, no recursion), and
//  each membership test is a binary search. Buffers are the caller's.
//  Header-only, static inline. No locking, no clock, no I/O. Allocation only inside the core's
//  transaction parser (BRSweepClassifyRawTx frees what it parsed before returning).
//
//  Test seams (host KAT sweep_partition_kat in the Android repo): SWEEP_PARTITION_UNFIXED, tested by VALUE
//  as a set of bits, one per way the rules go wrong; each comparison arm sets one bit and fails only its own
//  cases. Unset or =0 is what ships.
//    1   SWEEP_PARTITION_RED_UNKNOWN_SWEPT     an outpoint that could not be classified read as plain.
//    2   SWEEP_PARTITION_RED_ASSET_SWEPT       an asset-bearing outpoint put in the sweep.
//    4   SWEEP_PARTITION_RED_UNREAD_PLAIN      a raw transaction absent or unreadable read as plain.
//    8   SWEEP_PARTITION_RED_FAILED_MOVE_FREES a failed move's plan inputs released to the sweep.
//    16  SWEEP_PARTITION_RED_LEFT_BEHIND_ALL   every asset-bearing outpoint called left behind.
//    32  SWEEP_PARTITION_RED_RULE_FAIL_OPEN    a failed or missing rule lookup read as NONE.
//    64  SWEEP_PARTITION_RED_UNKNOWN_NOT_HELD  the hold-everything predicate counts assets only.
//    128 SWEEP_PARTITION_RED_TOTAL_ALL         the quoted total counts held coins too.
//
//  Vectors: vectors/sweep-partition/ (generate.c writes vectors.txt from this header).
//

#ifndef BRSweepPartition_h
#define BRSweepPartition_h

#include "BRRecoveryUtxo.h"
#include "BRTransaction.h"
#include "BRDigiAsset.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SWEEP_PARTITION_UNFIXED
#define SWEEP_PARTITION_UNFIXED 0
#endif

#define SWEEP_PARTITION_RED_UNKNOWN_SWEPT      1
#define SWEEP_PARTITION_RED_ASSET_SWEPT        2
#define SWEEP_PARTITION_RED_UNREAD_PLAIN       4
#define SWEEP_PARTITION_RED_FAILED_MOVE_FREES  8
#define SWEEP_PARTITION_RED_LEFT_BEHIND_ALL    16
#define SWEEP_PARTITION_RED_RULE_FAIL_OPEN     32
#define SWEEP_PARTITION_RED_UNKNOWN_NOT_HELD   64
#define SWEEP_PARTITION_RED_TOTAL_ALL          128

// ---- the verdict -------------------------------------------------------------------------------

// What the core read in the raw transaction that created an outpoint.
typedef enum {
    BR_SWEEP_RAW_TX_ABSENT = 0,      // no bytes: the fetch failed, threw or returned an empty body
    BR_SWEEP_RAW_TX_UNREADABLE = 1,  // bytes the core's parser cannot read
    BR_SWEEP_RAW_TX_PLAIN = 2,       // a transaction with no DigiAsset carrier
    BR_SWEEP_RAW_TX_ASSET = 3        // a transaction with a DigiAsset carrier on some output
} BRSweepRawTxClass;

// Android's TransferRuleState, in its order.
typedef enum {
    BR_SWEEP_RULE_NONE = 0,     // no transfer rules: the only state that may move
    BR_SWEEP_RULE_BOUND = 1,    // rule-bound: a plain transfer destroys it
    BR_SWEEP_RULE_UNKNOWN = 2   // could not be proven either way
} BRSweepRuleState;

typedef struct {
    int classified;              // nonzero: the asset question was answered for this outpoint
    int carriesAsset;            // nonzero: it carries a DigiAsset (read only when classified)
    BRSweepRuleState ruleState;  // read only when carriesAsset; UNKNOWN otherwise
} BRSweepAssetVerdict;

// Classifies raw[0..len) with the core's parser and DigiAsset reader (see THE VERDICT).
static inline BRSweepRawTxClass BRSweepClassifyRawTx(const uint8_t *raw, size_t len)
{
    BRTransaction *tx;
    BRSweepRawTxClass c;

    if (!raw || len == 0) {
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_UNREAD_PLAIN
        return BR_SWEEP_RAW_TX_PLAIN;   // RED ARM SEAM (sweep_partition_kat)
#else
        return BR_SWEEP_RAW_TX_ABSENT;
#endif
    }
    tx = BRTransactionParseSigned(raw, len);
    if (!tx) {
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_UNREAD_PLAIN
        return BR_SWEEP_RAW_TX_PLAIN;   // RED ARM SEAM (sweep_partition_kat)
#else
        return BR_SWEEP_RAW_TX_UNREADABLE;
#endif
    }
    c = BRTXContainsAsset(tx) ? BR_SWEEP_RAW_TX_ASSET : BR_SWEEP_RAW_TX_PLAIN;
    BRTransactionFree(tx);
    return c;
}

// The rule state an ASSET verdict carries: state when the lookup answered (resolved nonzero) with a value
// this header knows, UNKNOWN otherwise.
static inline BRSweepRuleState BRSweepRuleStateRead(int resolved, int state)
{
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_RULE_FAIL_OPEN
    // RED ARM SEAM (sweep_partition_kat): a failed or missing lookup read as NONE.
    if (!resolved) return BR_SWEEP_RULE_NONE;
#else
    if (!resolved) return BR_SWEEP_RULE_UNKNOWN;
#endif
    switch (state) {
    case BR_SWEEP_RULE_NONE: return BR_SWEEP_RULE_NONE;
    case BR_SWEEP_RULE_BOUND: return BR_SWEEP_RULE_BOUND;
    default: return BR_SWEEP_RULE_UNKNOWN;
    }
}

// The verdict that holds an outpoint back: not classified.
static inline BRSweepAssetVerdict BRSweepVerdictUnknown(void)
{
    BRSweepAssetVerdict v;
    v.classified = 0;
    v.carriesAsset = 0;
    v.ruleState = BR_SWEEP_RULE_UNKNOWN;
    return v;
}

// The verdict for an outpoint whose parent transaction classified as c. ruleResolved and ruleState are the
// transfer-rule lookup's answer (BRSweepRuleStateRead); read only when c is ASSET.
static inline BRSweepAssetVerdict BRSweepVerdictOf(BRSweepRawTxClass c, int ruleResolved, int ruleState)
{
    BRSweepAssetVerdict v = BRSweepVerdictUnknown();

    switch (c) {
    case BR_SWEEP_RAW_TX_PLAIN:
        v.classified = 1;
        break;
    case BR_SWEEP_RAW_TX_ASSET:
        v.classified = 1;
        v.carriesAsset = 1;
        v.ruleState = BRSweepRuleStateRead(ruleResolved, ruleState);
        break;
    default:   // ABSENT, UNREADABLE, or a value this header does not know
        break;
    }
    return v;
}

// ---- one fetch per transaction -----------------------------------------------------------------

// Work pairs {row, row} by the row's txid, then by row index.
static inline int _BRSweepTxidCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRRecoveryUtxo *u = (const BRRecoveryUtxo *)ctx;
    int c = memcmp(u[a[0]].txid, u[b[0]].txid, sizeof(u[a[0]].txid));
    if (c) return c;
    return _BRRecoveryUtxoIndexCompare(a[0], b[0]);
}

// groupOf[i] = the first row of utxos[0..count) whose txid is utxos[i]'s (groupOf[i] == i for the row the
// platform fetches for). work[] holds BRRecoveryUtxoWorkCapacity(count) indices, else BUFFER_TOO_SMALL.
// groupOf may be NULL only when count is 0; past count it is not written.
static inline BRRecoveryUtxoStatus BRSweepTxidGroups(const BRRecoveryUtxo utxos[], size_t count, size_t work[],
                                                     size_t workCapacity, size_t groupOf[])
{
    size_t need = BRRecoveryUtxoWorkCapacity(count), i, first = 0;

    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!utxos || !work || !groupOf) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    if (need == 0 || workCapacity < need) return BR_RECOVERY_UTXO_BUFFER_TOO_SMALL;
    for (i = 0; i < count; i++) { work[2 * i] = i; work[2 * i + 1] = i; }
    _BRRecoveryUtxoHeapSort(work, count, _BRSweepTxidCompare, utxos);
    // Each group is now in row order, so its first pair is the row that first named the txid.
    for (i = 0; i < count; i++) {
        if (i == 0 || memcmp(utxos[work[2 * i]].txid, utxos[work[2 * first]].txid, sizeof(utxos[0].txid)) != 0) {
            first = i;
        }
        groupOf[work[2 * i]] = work[2 * first];
    }
    return BR_RECOVERY_UTXO_OK;
}

// ---- the split ---------------------------------------------------------------------------------

typedef enum {
    BR_SWEEP_BUCKET_SWEEPABLE = 0,     // safe to spend as plain DGB
    BR_SWEEP_BUCKET_ASSET = 1,         // carries a DigiAsset: moved by the asset path, or left alone
    BR_SWEEP_BUCKET_UNCLASSIFIED = 2   // could not be classified: held back
} BRSweepBucket;

typedef struct {
    size_t sweepable;      // rows in each bucket
    size_t assetBearing;
    size_t unclassified;
    int64_t sweepableSat;  // the signed sum of the SWEEPABLE rows' amounts
} BRSweepPartitionSummary;

// The bucket of one outpoint (see THE SPLIT). NULL is UNCLASSIFIED.
static inline BRSweepBucket BRSweepBucketOf(const BRSweepAssetVerdict *v)
{
    if (!v) return BR_SWEEP_BUCKET_UNCLASSIFIED;
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_ASSET_SWEPT
    // RED ARM SEAM (sweep_partition_kat): an asset-bearing outpoint put in the sweep.
    if (!v->classified) return BR_SWEEP_BUCKET_UNCLASSIFIED;
    return BR_SWEEP_BUCKET_SWEEPABLE;
#elif SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_UNKNOWN_SWEPT
    // RED ARM SEAM (sweep_partition_kat): "is it an asset" asked without "could we tell".
    return v->carriesAsset ? BR_SWEEP_BUCKET_ASSET : BR_SWEEP_BUCKET_SWEEPABLE;
#else
    // Order matters: "could we tell?" BEFORE "is it an asset?". Reversed, an unanswerable outpoint would
    // be read as a confident no and swept.
    if (!v->classified) return BR_SWEEP_BUCKET_UNCLASSIFIED;
    if (v->carriesAsset) return BR_SWEEP_BUCKET_ASSET;
    return BR_SWEEP_BUCKET_SWEEPABLE;
#endif
}

// Splits utxos[0..count) by verdicts[0..count) (one per row; NULL: none computed, every row UNCLASSIFIED).
// buckets[i] (when buckets is not NULL) is row i's bucket, in row order. *summary counts each bucket and
// totals the sweepable rows; it is all zero unless OK. On OVERFLOW the buckets are still written.
static inline BRRecoveryUtxoStatus BRSweepPartitionSplit(const BRRecoveryUtxo utxos[],
                                                         const BRSweepAssetVerdict verdicts[], size_t count,
                                                         BRSweepBucket buckets[], BRSweepPartitionSummary *summary)
{
    BRSweepPartitionSummary s;
    int overflow = 0;
    size_t i;

    if (!summary) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    memset(summary, 0, sizeof(*summary));
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!utxos) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    memset(&s, 0, sizeof(s));
    for (i = 0; i < count; i++) {
        BRSweepBucket b = BRSweepBucketOf(verdicts ? &verdicts[i] : NULL);
        int counted = (b == BR_SWEEP_BUCKET_SWEEPABLE);
        int64_t a = utxos[i].amount;
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_TOTAL_ALL
        counted = 1;   // RED ARM SEAM (sweep_partition_kat): held coins quoted too
#endif
        if (buckets) buckets[i] = b;
        if (b == BR_SWEEP_BUCKET_SWEEPABLE) s.sweepable++;
        else if (b == BR_SWEEP_BUCKET_ASSET) s.assetBearing++;
        else s.unclassified++;
        if (counted && !overflow) {
            if ((a > 0 && s.sweepableSat > INT64_MAX - a) || (a < 0 && s.sweepableSat < INT64_MIN - a)) overflow = 1;
            else s.sweepableSat += a;
        }
    }
    if (overflow) return BR_RECOVERY_UTXO_OVERFLOW;
    *summary = s;
    return BR_RECOVERY_UTXO_OK;
}

// Whether any of verdicts[0..count) is ASSET or UNCLASSIFIED (see HOLD EVERYTHING). NULL with a nonzero
// count holds; no rows do not.
static inline int BRSweepFoundAssetOrUnknown(const BRSweepAssetVerdict verdicts[], size_t count)
{
    size_t i;

    if (count == 0) return 0;
    if (!verdicts) return 1;
    for (i = 0; i < count; i++) {
        BRSweepBucket b = BRSweepBucketOf(&verdicts[i]);
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_UNKNOWN_NOT_HELD
        if (b == BR_SWEEP_BUCKET_ASSET) return 1;   // RED ARM SEAM (sweep_partition_kat)
#else
        if (b != BR_SWEEP_BUCKET_SWEEPABLE) return 1;
#endif
    }
    return 0;
}

// ---- outpoint sets -----------------------------------------------------------------------------

typedef struct {
    uint8_t txid[32];   // as bytes (see OUTPOINTS)
    uint32_t vout;
} BRSweepOutpoint;

static inline int BRSweepOutpointCompare(const BRSweepOutpoint *a, const BRSweepOutpoint *b)
{
    int c = memcmp(a->txid, b->txid, sizeof(a->txid));
    if (c) return c;
    return (a->vout < b->vout) ? -1 : (a->vout > b->vout) ? 1 : 0;
}

static inline void _BRSweepOutpointSwap(BRSweepOutpoint *a, BRSweepOutpoint *b)
{
    BRSweepOutpoint t = *a;
    *a = *b;
    *b = t;
}

static inline void _BRSweepOutpointSiftDown(BRSweepOutpoint *base, size_t root, size_t n)
{
    for (;;) {
        size_t child = 2 * root + 1, top = root;
        if (child >= n || child < root) return;   // child < root: 2 * root + 1 overflowed
        if (BRSweepOutpointCompare(&base[top], &base[child]) < 0) top = child;
        if (child + 1 < n && BRSweepOutpointCompare(&base[top], &base[child + 1]) < 0) top = child + 1;
        if (top == root) return;
        _BRSweepOutpointSwap(&base[root], &base[top]);
        root = top;
    }
}

// Sorts set[0..n) ascending and drops repeats, in place: O(n log n), no allocation, no recursion. Returns
// the distinct count.
static inline size_t _BRSweepOutpointSortDistinct(BRSweepOutpoint *set, size_t n)
{
    size_t i, end, m;

    if (!set || n == 0) return 0;
    for (i = n / 2; i > 0; i--) _BRSweepOutpointSiftDown(set, i - 1, n);
    for (end = n - 1; end > 0; end--) {
        _BRSweepOutpointSwap(&set[0], &set[end]);
        _BRSweepOutpointSiftDown(set, 0, end);
    }
    for (i = 1, m = 1; i < n; i++) {
        if (BRSweepOutpointCompare(&set[m - 1], &set[i]) != 0) set[m++] = set[i];
    }
    return m;
}

// Whether op is in set[0..n), sorted ascending and distinct (as BRSweepExclusions writes it): a binary
// search. NULL set or op: not in it.
static inline int BRSweepOutpointIn(const BRSweepOutpoint set[], size_t n, const BRSweepOutpoint *op)
{
    size_t lo = 0, hi = n;

    if (!set || !op) return 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = BRSweepOutpointCompare(&set[mid], op);
        if (c == 0) return 1;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return 0;
}

// ---- sweep exclusions --------------------------------------------------------------------------

// What one asset's move did, in outpoints (Android's RecoverySequence.MoveRecord).
typedef struct {
    BRSweepOutpoint outpoint;            // the asset-bearing outpoint this move was for
    const BRSweepOutpoint *spentInputs;  // every outpoint its plan spends; may be NULL when spentCount is 0
    size_t spentCount;                   // 0 when no plan was built
    int broadcast;                       // nonzero once the signed move reached relay
} BRSweepMoveRecord;

// Whether record r withholds its plan's inputs (not only its asset outpoint).
static inline int _BRSweepWithholdsPlan(const BRSweepMoveRecord *r)
{
#if SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_FAILED_MOVE_FREES
    return r->broadcast != 0;   // RED ARM SEAM (sweep_partition_kat): a failed move's inputs released
#else
    (void)r;
    return 1;
#endif
}

// The capacity BRSweepExclusions needs for moved[0..count): the sum over records of spentCount + 1.
// OVERFLOW when it does not fit a size_t; *need is then 0.
static inline BRRecoveryUtxoStatus BRSweepExclusionsCapacity(const BRSweepMoveRecord moved[], size_t count,
                                                             size_t *need)
{
    size_t total = 0, i;

    if (!need) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *need = 0;
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!moved) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    for (i = 0; i < count; i++) {
        size_t k = moved[i].spentCount;
        if (k == SIZE_MAX || total > SIZE_MAX - (k + 1)) return BR_RECOVERY_UTXO_OVERFLOW;
        total += k + 1;
    }
    *need = total;
    return BR_RECOVERY_UTXO_OK;
}

// The outpoints the sweep must not touch (see SWEEP EXCLUSIONS), sorted ascending and distinct, into
// out[0..capacity). capacity must be at least BRSweepExclusionsCapacity, else BUFFER_TOO_SMALL; *outCount
// is the number written (0 unless OK). A record with spentCount > 0 and NULL spentInputs is NULL_ARGUMENT.
static inline BRRecoveryUtxoStatus BRSweepExclusions(const BRSweepMoveRecord moved[], size_t count,
                                                     BRSweepOutpoint out[], size_t capacity, size_t *outCount)
{
    size_t need = 0, n = 0, i, j;
    BRRecoveryUtxoStatus status;

    if (!outCount) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *outCount = 0;
    status = BRSweepExclusionsCapacity(moved, count, &need);
    if (status != BR_RECOVERY_UTXO_OK) return status;
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!out) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    if (capacity < need) return BR_RECOVERY_UTXO_BUFFER_TOO_SMALL;
    for (i = 0; i < count; i++) {
        if (moved[i].spentCount > 0 && !moved[i].spentInputs) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    }
    for (i = 0; i < count; i++) {
        // The asset outpoint itself is always excluded: spent if the move went through, and never
        // sweepable as plain DGB if it did not.
        out[n++] = moved[i].outpoint;
        if (!_BRSweepWithholdsPlan(&moved[i])) continue;
        for (j = 0; j < moved[i].spentCount; j++) out[n++] = moved[i].spentInputs[j];
    }
    *outCount = _BRSweepOutpointSortDistinct(out, n);
    return BR_RECOVERY_UTXO_OK;
}

// ---- left behind -------------------------------------------------------------------------------

// One asset's move, as the result screen reads it (Android's ForeignAssetTransferService.Move).
typedef struct {
    BRSweepOutpoint outpoint;  // the asset-bearing outpoint the move was for
    int moved;                 // nonzero: the move's transaction was broadcast (it has a txid)
} BRSweepMoveOutcome;

// The indices into assetBearing[0..count) that are left behind (see LEFT BEHIND), in order, into
// out[0..capacity); *outCount is the number written (0 unless OK; BUFFER_TOO_SMALL when they do not fit,
// capacity >= count always does). work[] holds moveCount outpoints, else BUFFER_TOO_SMALL.
static inline BRRecoveryUtxoStatus BRSweepAssetsLeftBehind(const BRSweepOutpoint assetBearing[], size_t count,
                                                           const BRSweepMoveOutcome moves[], size_t moveCount,
                                                           BRSweepOutpoint work[], size_t workCapacity,
                                                           size_t out[], size_t capacity, size_t *outCount)
{
    size_t arrived = 0, n = 0, i;

    if (!outCount) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *outCount = 0;
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!assetBearing || !out || (moveCount > 0 && (!moves || !work))) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    if (workCapacity < moveCount) return BR_RECOVERY_UTXO_BUFFER_TOO_SMALL;
#if !(SWEEP_PARTITION_UNFIXED & SWEEP_PARTITION_RED_LEFT_BEHIND_ALL)
    for (i = 0; i < moveCount; i++) {
        if (moves[i].moved) work[arrived++] = moves[i].outpoint;
    }
    arrived = _BRSweepOutpointSortDistinct(work, arrived);
#endif
    // RED ARM SEAM (sweep_partition_kat, SWEEP_PARTITION_RED_LEFT_BEHIND_ALL): nothing counts as arrived,
    // so every asset excluded from the sweep reads as left behind.
    for (i = 0; i < count; i++) {
        if (BRSweepOutpointIn(work, arrived, &assetBearing[i])) continue;
        if (n >= capacity) return BR_RECOVERY_UTXO_BUFFER_TOO_SMALL;
        out[n++] = i;
    }
    *outCount = n;
    return BR_RECOVERY_UTXO_OK;
}

#ifdef __cplusplus
}
#endif

#endif // BRSweepPartition_h
