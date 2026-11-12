//
//  BRReconcilePlan.h
//
//  The planning rules of a node reconcile: which transactions an address-history pass imports, when
//  that pass may say it covered the wallet's addresses, which wallet transactions are still pending,
//  and the address and outpoint lists sent to and read from the node. Until 2026-11 these lived only
//  in Android's Kotlin (ChainReconciliationService.kt: planHistoryImport, importPlannedHistory /
//  HistoryImportOutcome, knownTxidsForHistoryPlan, pendingTxids; ScanPartition.kt: distinctAddresses,
//  distinctOutpoints). The reconcile itself -- the node requests, the fetches, the registrations -- is
//  each platform's own (it is I/O, and asynchronous); this header owns the rules that executor follows,
//  so both platforms plan the same import from the same answers and agree on when a pass covered.
//
//  THE RULES:
//    - KNOWN SET. The transactions the wallet already holds, every one of them, read from the wallet
//      itself in one lock hold (BRReconcileKnownTxHashes, over BRWalletTransactionHashes). Never a
//      truncated list: a known set that leaves out the wallet's older transactions lets them into the
//      plan, the wallet then refuses each as a duplicate, and every refusal counts against coverage
//      (below), so a wallet with a long history could never be covered. A buffer too small to hold
//      them all is reported (BR_RECONCILE_INCOMPLETE), never read as the whole set.
//    - PLAN. From the node's history entries, in the order the node gave them (one list per address,
//      concatenated): drop each entry whose txid the wallet holds, and each with no txid (all zero);
//      keep one entry per txid, carrying the HIGHEST height any entry gave it; list the kept txids in
//      the order each was first seen (BRReconcilePlanHistoryImport). The height is the one registered
//      with the transaction. The plan checks no height range: whether a height is one the wallet can
//      check belongs to the registration (the wallet does not keep a server's height it cannot check),
//      and a registration refused for it is unrecovered (COVERAGE).
//    - IMPORT STEP. Each planned transaction is fetched, decoded, checked to BE the transaction asked
//      for (its own id equals the planned txid), and only then registered, in that order; the first
//      step that fails is the outcome (BRReconcileImportStepFor). Bytes that are not the transaction
//      asked for are never registered (BRReconcileImportMayRegister).
//    - COVERAGE. A pass covered the wallet's addresses iff the list of distinct addresses asked was not
//      empty, the node answered for every one of them, and every planned transaction was registered: no
//      step failed for any of them, and as many were registered as were planned (an empty plan is
//      covered only when the node answered for every address). A history request that failed, in whole
//      or in part, is never read as an empty plan: the pass records the addresses asked and answered
//      (BRReconcileImportBegin) and is not covered. A REFUSED registration is not recovered: with the
//      known set complete, the wallet's duplicate refusal cannot be reached here, so a refusal means
//      the transaction did not land (unparseable, unsigned, not the wallet's, or a height the wallet
//      cannot check). Coverage is all-or-nothing (BRReconcileImportCovered). Only a covered pass may
//      report that history the compact-filter scan gave up on has been recovered.
//    - PENDING. A wallet transaction is pending iff its blockHeight is TX_UNCONFIRMED
//      (BRReconcileIsPending); BRReconcilePendingTxHashes lists every such transaction the wallet
//      holds, in the wallet's oldest-first order.
//    - DISTINCT ADDRESSES. The address list sent to the node: each address trimmed of whitespace,
//      empty ones dropped, each address once, first-seen order (BRReconcileDistinctAddresses). Trimmed
//      bytes: ASCII TAB, LF, VT, FF, CR, the four separators 0x1C-0x1F, and SPACE (what Kotlin's trim()
//      removes from an ASCII string).
//    - DISTINCT OUTPOINTS. The node's unspent rows with each outpoint (txid, output index) once, the
//      first row kept, before anything is counted or summed (BRReconcileDistinctOutpoints).
//    The plan and both distinct lists take O(n log n) in their input (the node chooses how many
//    history entries and unspent rows it returns).
//
//  BUFFERS. Every output is a buffer the caller owns; nothing here allocates except the transaction
//  copies BRReconcilePendingTxHashes takes from the wallet and frees before it returns. A function
//  that cannot fit its answer says so (BR_RECONCILE_BUFFER_TOO_SMALL / BR_RECONCILE_INCOMPLETE) and
//  reports a count of 0. Sizes: a plan or a distinct list is given a buffer for its whole input (the
//  buffer is also the working space), so planCap / keepCap / outCap >= the input count always
//  suffices; BRReconcileCapacity and BRReconcileArrayBytes size a buffer with overflow checked. No
//  I/O, no clock, no network. The wallet readers take the wallet's lock, which is not recursive: the
//  caller must NOT hold it.
//
//  TXIDS are UInt256 in the wallet's byte order (UInt256.u8); a txid string displays it reversed.
//  They compare as bytes, so a platform that keeps txids as hex compares them case-insensitively.
//
//  Shared vectors: vectors/reconcile-plan/ (this header's answers on a fixed corpus, for each
//  platform's mirror). Host KAT (digibytewallet-android native/src/test/host/): reconcile_plan_kat,
//  AddressHistoryPlanTest and HistoryImportCoverageTest case for case.
//  Header-only, static inline.
//

#ifndef BRReconcilePlan_h
#define BRReconcilePlan_h

#include "BRWallet.h"        // BRWallet, BRUTXO, BRWalletTransactionHashes, BRWalletCopyTransactionForHash
#include "BRTransaction.h"   // BRTransaction, TX_UNCONFIRMED, BRTransactionFree
#include "BRInt.h"           // UInt256, UInt256Eq, UInt256IsZero
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// MACRO CONVENTION: RECONCILE_PLAN_UNFIXED is tested by VALUE (#if). =1 is the host KAT's comparison
// arm, three ways a reconcile plan goes wrong: the known set truncated to the wallet's 100 newest
// transactions (what Android's getTransactionDetails() carries), a repeated txid planned at its LOWEST
// height, and a refused registration read as recovered. Unset or =0 is what ships.
#ifndef RECONCILE_PLAN_UNFIXED
#define RECONCILE_PLAN_UNFIXED 0
#endif

// The height of a pending transaction. A literal for Swift; it is TX_UNCONFIRMED (INT32_MAX).
#define BR_RECONCILE_PENDING_HEIGHT 2147483647u
typedef char BRReconcileCheckPendingHeight[(BR_RECONCILE_PENDING_HEIGHT == (uint32_t)TX_UNCONFIRMED) ? 1 : -1];

// The comparison arm's truncated known set: the wallet's newest this many. Never used by what ships.
#define BR_RECONCILE_TRUNCATED_KNOWN 100u

typedef enum {
    BR_RECONCILE_OK = 0,
    BR_RECONCILE_NULL_ARGUMENT = 1,     // a required pointer was NULL (or NULL with a nonzero count)
    BR_RECONCILE_BUFFER_TOO_SMALL = 2,  // the answer does not fit the caller's buffer
    BR_RECONCILE_KNOWN_UNSORTED = 3,    // the known set is not in BRReconcileSortTxHashes order
    BR_RECONCILE_INCOMPLETE = 4,        // a wallet read: the buffer may not hold every transaction
    BR_RECONCILE_NO_MEMORY = 5          // a wallet read: a transaction copy could not be allocated
} BRReconcileStatus;

// ---- sizes -------------------------------------------------------------------------------------

// A buffer size for a wallet read that reported `count`: count + 1 (a read is complete only when it
// leaves room to spare). 0 when count + 1 would overflow.
static inline size_t BRReconcileCapacity(size_t count)
{
    return (count == SIZE_MAX) ? 0 : count + 1;
}

// count * elemSize, or 0 when it would overflow (or either is 0).
static inline size_t BRReconcileArrayBytes(size_t count, size_t elemSize)
{
    if (count == 0 || elemSize == 0 || count > SIZE_MAX / elemSize) return 0;
    return count * elemSize;
}

// ---- txids -------------------------------------------------------------------------------------

// The order the known set is kept in: the 32 bytes compared as unsigned bytes. -1, 0 or 1.
static inline int BRReconcileTxHashCompare(UInt256 a, UInt256 b)
{
    int c = memcmp(a.u8, b.u8, sizeof(a.u8));
    return (c < 0) ? -1 : (c > 0) ? 1 : 0;
}

static inline int _BRReconcileTxHashQsort(const void *a, const void *b)
{
    return BRReconcileTxHashCompare(*(const UInt256 *)a, *(const UInt256 *)b);
}

// Sorts hashes in place into the known set's order. NULL-safe.
static inline void BRReconcileSortTxHashes(UInt256 hashes[], size_t count)
{
    if (hashes && count > 1) qsort(hashes, count, sizeof(*hashes), _BRReconcileTxHashQsort);
}

// 1 when hashes[0..count) is in the known set's order (repeats allowed); an empty set is. 0 for NULL
// with a nonzero count.
static inline int BRReconcileTxHashesSorted(const UInt256 hashes[], size_t count)
{
    if (count == 0) return 1;
    if (! hashes) return 0;
    for (size_t i = 1; i < count; i++) {
        if (BRReconcileTxHashCompare(hashes[i - 1], hashes[i]) > 0) return 0;
    }
    return 1;
}

// 1 when the sorted known set holds txHash. NULL-safe (NULL holds nothing).
static inline int BRReconcileKnownContains(const UInt256 known[], size_t count, UInt256 txHash)
{
    size_t lo = 0, hi = count;

    if (! known) return 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = BRReconcileTxHashCompare(known[mid], txHash);
        if (c == 0) return 1;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return 0;
}

// ---- reading the wallet ------------------------------------------------------------------------

// Every registered transaction's hash, oldest first, in one lock hold. OK only when the copy left room
// to spare (fewer than cap written): a copy that fills the buffer may have stopped short.
static inline BRReconcileStatus _BRReconcileCopyTxHashes(BRWallet *wallet, UInt256 hashes[], size_t cap, size_t *count)
{
    size_t n;

    if (count) *count = 0;
    if (! wallet || ! count) return BR_RECONCILE_NULL_ARGUMENT;
    if (! hashes || cap == 0) {
        *count = BRWalletTransactionHashes(wallet, NULL, 0);
        return BR_RECONCILE_INCOMPLETE;
    }
    n = BRWalletTransactionHashes(wallet, hashes, cap);
    if (n >= cap) {
        // Full: the wallet may hold more. Report how many it holds now, so the caller can size again.
        *count = BRWalletTransactionHashes(wallet, NULL, 0);
        return BR_RECONCILE_INCOMPLETE;
    }
    *count = n;
    return BR_RECONCILE_OK;
}

// The KNOWN SET: every transaction the wallet holds, written to hashes[0..*count) in the known set's
// order (sorted), taken in one lock hold.
//   OK               the set is complete (*count < cap).
//   INCOMPLETE       hashes NULL or cap 0 (a sizing call), or the copy filled the buffer: *count is how
//                    many the wallet holds now; nothing written is the set. Call again with
//                    BRReconcileCapacity(*count) entries.
//   NULL_ARGUMENT    wallet or count NULL; *count (when count is not NULL) is 0.
// The caller must not hold the wallet's lock.
static inline BRReconcileStatus BRReconcileKnownTxHashes(BRWallet *wallet, UInt256 hashes[], size_t cap, size_t *count)
{
    BRReconcileStatus s = _BRReconcileCopyTxHashes(wallet, hashes, cap, count);

    if (s != BR_RECONCILE_OK) return s;
#if RECONCILE_PLAN_UNFIXED
    // comparison arm: the 100 newest only (BRWalletTransactions order is oldest first)
    if (*count > BR_RECONCILE_TRUNCATED_KNOWN) {
        memmove(hashes, hashes + (*count - BR_RECONCILE_TRUNCATED_KNOWN), BR_RECONCILE_TRUNCATED_KNOWN * sizeof(*hashes));
        *count = BR_RECONCILE_TRUNCATED_KNOWN;
    }
#endif
    BRReconcileSortTxHashes(hashes, *count);
    return BR_RECONCILE_OK;
}

// PENDING: 1 iff blockHeight is TX_UNCONFIRMED.
static inline int BRReconcileIsPending(uint32_t blockHeight)
{
    return blockHeight == BR_RECONCILE_PENDING_HEIGHT;
}

// Every pending transaction the wallet holds, written to hashes[0..*count) in the wallet's oldest-first
// order. The hashes are taken in one lock hold, then each transaction is read (a copy, freed at once);
// one removed in between is not listed. Statuses as BRReconcileKnownTxHashes (for INCOMPLETE, *count is
// how many transactions the wallet holds, pending or not: size the buffer for all of them), and
//   NO_MEMORY        a transaction the wallet still holds could not be copied; *count is 0.
// The caller must not hold the wallet's lock.
static inline BRReconcileStatus BRReconcilePendingTxHashes(BRWallet *wallet, UInt256 hashes[], size_t cap, size_t *count)
{
    BRReconcileStatus s = _BRReconcileCopyTxHashes(wallet, hashes, cap, count);
    size_t i, n, k = 0;

    if (s != BR_RECONCILE_OK) return s;
    n = *count;
    for (i = 0; i < n; i++) {
        BRTransaction *tx = BRWalletCopyTransactionForHash(wallet, hashes[i]);
        if (! tx) {
            // Removed since the hashes were read, or the copy failed: only the first is not pending.
            // Defensive: BRTransactionCopy's BRTransactionNew asserts on allocation failure, so with
            // assertions on a failed copy never returns here.
            if (BRWalletTransactionForHash(wallet, hashes[i]) != NULL) { *count = 0; return BR_RECONCILE_NO_MEMORY; }
            continue;
        }
        if (BRReconcileIsPending(tx->blockHeight)) hashes[k++] = hashes[i];
        BRTransactionFree(tx);
    }
    *count = k;
    return BR_RECONCILE_OK;
}

// ---- the plan ----------------------------------------------------------------------------------

// One entry of the node's address history: a txid and the height the node gave it (signed, as the
// node's JSON number is read).
typedef struct {
    UInt256 txHash;
    int64_t height;
} BRReconcileHistoryTx;

// One planned import: the txid, the height to register it at, and the index in the history of the
// entry that first named it (the plan's order).
typedef struct {
    UInt256 txHash;
    int64_t height;
    size_t firstIndex;
} BRReconcilePlanTx;

static inline int _BRReconcilePlanByHashQsort(const void *a, const void *b)
{
    const BRReconcilePlanTx *x = (const BRReconcilePlanTx *)a, *y = (const BRReconcilePlanTx *)b;
    int c = BRReconcileTxHashCompare(x->txHash, y->txHash);
    if (c) return c;
    return (x->firstIndex < y->firstIndex) ? -1 : (x->firstIndex > y->firstIndex) ? 1 : 0;
}

static inline int _BRReconcilePlanByIndexQsort(const void *a, const void *b)
{
    const BRReconcilePlanTx *x = (const BRReconcilePlanTx *)a, *y = (const BRReconcilePlanTx *)b;
    return (x->firstIndex < y->firstIndex) ? -1 : (x->firstIndex > y->firstIndex) ? 1 : 0;
}

// The PLAN: from history[0..historyCount) (the node's entries, every address's list concatenated in
// the order received) and the known set known[0..knownCount) (sorted, as BRReconcileKnownTxHashes
// writes it), writes plan[0..*planCount): each txid the wallet does not hold, once, at the highest
// height given it, in first-seen order. Entries with an all-zero txid are dropped.
//   OK               *planCount entries written (0 for an empty history).
//   BUFFER_TOO_SMALL more entries survive the known set than planCap holds; *planCount 0. planCap >=
//                    historyCount always suffices.
//   KNOWN_UNSORTED   known is not sorted; *planCount 0.
//   NULL_ARGUMENT    planCount NULL, or history / known / plan NULL with a nonzero count; *planCount 0.
// plan[] is also the working space: its contents past *planCount, and on any failure, are unspecified.
static inline BRReconcileStatus BRReconcilePlanHistoryImport(const BRReconcileHistoryTx history[], size_t historyCount,
                                                             const UInt256 known[], size_t knownCount,
                                                             BRReconcilePlanTx plan[], size_t planCap,
                                                             size_t *planCount)
{
    size_t i, n = 0, m = 0;

    if (! planCount) return BR_RECONCILE_NULL_ARGUMENT;
    *planCount = 0;
    if ((historyCount && ! history) || (knownCount && ! known) || (planCap && ! plan)) return BR_RECONCILE_NULL_ARGUMENT;
    if (! BRReconcileTxHashesSorted(known, knownCount)) return BR_RECONCILE_KNOWN_UNSORTED;

    for (i = 0; i < historyCount; i++) {
        if (UInt256IsZero(history[i].txHash)) continue;
        if (BRReconcileKnownContains(known, knownCount, history[i].txHash)) continue;
        if (n >= planCap) return BR_RECONCILE_BUFFER_TOO_SMALL;
        plan[n].txHash = history[i].txHash;
        plan[n].height = history[i].height;
        plan[n].firstIndex = i;
        n++;
    }
    if (n == 0) return BR_RECONCILE_OK;

    // Group by txid (each group in history order, the indices being distinct), fold each group into its
    // first entry, then restore first-seen order.
    qsort(plan, n, sizeof(*plan), _BRReconcilePlanByHashQsort);
    for (i = 0; i < n; i++) {
        if (m > 0 && UInt256Eq(plan[m - 1].txHash, plan[i].txHash)) {
#if RECONCILE_PLAN_UNFIXED
            if (plan[i].height < plan[m - 1].height) plan[m - 1].height = plan[i].height;   // comparison arm: lowest
#else
            if (plan[i].height > plan[m - 1].height) plan[m - 1].height = plan[i].height;
#endif
        }
        else plan[m++] = plan[i];
    }
    qsort(plan, m, sizeof(*plan), _BRReconcilePlanByIndexQsort);
    *planCount = m;
    return BR_RECONCILE_OK;
}

// ---- the import and its coverage ---------------------------------------------------------------

// What became of one planned transaction: registered, or the first step that failed.
typedef enum {
    BR_RECONCILE_STEP_REGISTERED = 0,
    BR_RECONCILE_STEP_NOT_FETCHED = 1,   // the node gave no transaction
    BR_RECONCILE_STEP_NOT_DECODED = 2,   // what it gave did not decode to bytes
    BR_RECONCILE_STEP_NOT_THE_TX = 3,    // the bytes' own id is not the planned txid: never registered
    BR_RECONCILE_STEP_REFUSED = 4        // the wallet refused the registration
} BRReconcileImportStep;

// 1 when a planned transaction may be put to the wallet: fetched, decoded, and its bytes are the
// transaction asked for.
static inline int BRReconcileImportMayRegister(int fetched, int decoded, int isTheTx)
{
    return fetched && decoded && isTheTx;
}

// The IMPORT STEP outcome, the first failure in the steps' order. `registered` is read only when the
// transaction may be registered.
static inline BRReconcileImportStep BRReconcileImportStepFor(int fetched, int decoded, int isTheTx, int registered)
{
    if (! fetched) return BR_RECONCILE_STEP_NOT_FETCHED;
    if (! decoded) return BR_RECONCILE_STEP_NOT_DECODED;
    if (! isTheTx) return BR_RECONCILE_STEP_NOT_THE_TX;
    return registered ? BR_RECONCILE_STEP_REGISTERED : BR_RECONCILE_STEP_REFUSED;
}

// 1 when the step recovered the transaction: REGISTERED only. Any other value, known or not, is not.
static inline int BRReconcileImportStepRecovered(BRReconcileImportStep step)
{
    switch (step) {
        case BR_RECONCILE_STEP_REGISTERED: return 1;
#if RECONCILE_PLAN_UNFIXED
        case BR_RECONCILE_STEP_REFUSED: return 1;   // comparison arm: a refusal read as recovered
#endif
        default: return 0;
    }
}

// The tally of one address-history pass.
typedef struct {
    size_t addressesAsked;     // distinct addresses the history was asked for
    size_t addressesAnswered;  // of those, how many the node's answer covers
    size_t planned;            // entries in the plan
    size_t imported;           // steps that recovered their transaction
    size_t unrecovered;        // steps that did not
} BRReconcileImportOutcome;

// Starts a pass: the history was asked for addressesAsked distinct addresses (BRReconcileDistinctAddresses),
// the node's answer covers addressesAnswered of them (all of them when every request succeeded; a failed
// request answers for none of its addresses), and the plan made from that answer has `planned` entries.
// A pass whose history request failed is begun with what it answered (0 when it failed outright, plan
// 0), never skipped: it is then not covered, where an empty plan alone would be. NULL-safe.
static inline void BRReconcileImportBegin(BRReconcileImportOutcome *outcome, size_t addressesAsked,
                                          size_t addressesAnswered, size_t planned)
{
    if (! outcome) return;
    outcome->addressesAsked = addressesAsked;
    outcome->addressesAnswered = addressesAnswered;
    outcome->planned = planned;
    outcome->imported = 0;
    outcome->unrecovered = 0;
}

// Records one planned transaction's step. NULL-safe; the counts saturate at SIZE_MAX.
static inline void BRReconcileImportRecord(BRReconcileImportOutcome *outcome, BRReconcileImportStep step)
{
    size_t *c;

    if (! outcome) return;
    c = BRReconcileImportStepRecovered(step) ? &outcome->imported : &outcome->unrecovered;
    if (*c < SIZE_MAX) (*c)++;
}

// COVERAGE: 1 iff some addresses were asked, the node answered for every one, nothing was unrecovered
// and every planned transaction was registered. NULL: 0.
static inline int BRReconcileImportCovered(const BRReconcileImportOutcome *outcome)
{
    return outcome && outcome->addressesAsked > 0 && outcome->addressesAnswered == outcome->addressesAsked &&
           outcome->unrecovered == 0 && outcome->imported == outcome->planned;
}

// ---- distinct lists ----------------------------------------------------------------------------

// An in-place heapsort with a context: O(n log n), no allocation (qsort takes no context). The comparisons
// used here are total orders (each ends on a distinct index), so the result does not depend on the sort
// being stable.
typedef int (*_BRReconcileCompareFn)(const void *a, const void *b, const void *ctx);

static inline void _BRReconcileSwap(unsigned char *a, unsigned char *b, size_t size)
{
    for (size_t i = 0; i < size; i++) { unsigned char t = a[i]; a[i] = b[i]; b[i] = t; }
}

static inline void _BRReconcileSiftDown(unsigned char *base, size_t root, size_t n, size_t size,
                                        _BRReconcileCompareFn cmp, const void *ctx)
{
    for (;;) {
        size_t child = 2 * root + 1, top = root;
        if (child >= n || child < root) return;   // child < root: 2 * root + 1 overflowed
        if (cmp(base + top * size, base + child * size, ctx) < 0) top = child;
        if (child + 1 < n && cmp(base + top * size, base + (child + 1) * size, ctx) < 0) top = child + 1;
        if (top == root) return;
        _BRReconcileSwap(base + root * size, base + top * size, size);
        root = top;
    }
}

static inline void _BRReconcileHeapSort(void *base, size_t n, size_t size, _BRReconcileCompareFn cmp, const void *ctx)
{
    unsigned char *b = (unsigned char *)base;

    if (! base || n < 2) return;
    for (size_t i = n / 2; i > 0; i--) _BRReconcileSiftDown(b, i - 1, n, size, cmp, ctx);
    for (size_t end = n - 1; end > 0; end--) {
        _BRReconcileSwap(b, b + end * size, size);
        _BRReconcileSiftDown(b, 0, end, size, cmp, ctx);
    }
}

static inline int _BRReconcileIndexCompare(size_t a, size_t b)
{
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

// Outpoint row indices by (txid, output index, row index).
static inline int _BRReconcileOutpointCompare(const void *a, const void *b, const void *ctx)
{
    const BRUTXO *u = (const BRUTXO *)ctx;
    size_t i = *(const size_t *)a, j = *(const size_t *)b;
    int c = BRReconcileTxHashCompare(u[i].hash, u[j].hash);
    if (c) return c;
    if (u[i].n != u[j].n) return (u[i].n < u[j].n) ? -1 : 1;
    return _BRReconcileIndexCompare(i, j);
}

static inline int _BRReconcileSizeCompare(const void *a, const void *b, const void *ctx)
{
    (void)ctx;
    return _BRReconcileIndexCompare(*(const size_t *)a, *(const size_t *)b);
}

// The DISTINCT OUTPOINTS: writes to keep[0..*keptCount) the index in utxos of each outpoint's first
// row, in order. keep[] is also the working space: keepCap must be at least count.
//   OK / BUFFER_TOO_SMALL (keepCap < count; *keptCount 0) / NULL_ARGUMENT.
static inline BRReconcileStatus BRReconcileDistinctOutpoints(const BRUTXO utxos[], size_t count,
                                                             size_t keep[], size_t keepCap, size_t *keptCount)
{
    size_t i, n = 0;

    if (! keptCount) return BR_RECONCILE_NULL_ARGUMENT;
    *keptCount = 0;
    if ((count && ! utxos) || (keepCap && ! keep)) return BR_RECONCILE_NULL_ARGUMENT;
    if (count == 0) return BR_RECONCILE_OK;
    if (keepCap < count) return BR_RECONCILE_BUFFER_TOO_SMALL;
    for (i = 0; i < count; i++) keep[i] = i;
    _BRReconcileHeapSort(keep, count, sizeof(*keep), _BRReconcileOutpointCompare, utxos);
    for (i = 0; i < count; i++) {   // the first of each group is its first row
        if (n > 0 && BRUTXOEq(&utxos[keep[n - 1]], &utxos[keep[i]])) continue;
        keep[n++] = keep[i];
    }
    _BRReconcileHeapSort(keep, n, sizeof(*keep), _BRReconcileSizeCompare, NULL);
    *keptCount = n;
    return BR_RECONCILE_OK;
}

// One kept address: addrs[index] + offset, length bytes (the address trimmed).
typedef struct {
    size_t index;
    size_t offset;
    size_t length;
} BRReconcileAddressSpan;

static inline int _BRReconcileIsTrimmed(unsigned char c)
{
    return c == 0x20 || (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x1F);
}

// The trimmed part of s: *offset and *length. NULL s: 0, 0. NULL-safe.
static inline void BRReconcileAddressTrim(const char *s, size_t *offset, size_t *length)
{
    size_t a = 0, b;

    if (offset) *offset = 0;
    if (length) *length = 0;
    if (! s) return;
    b = strlen(s);
    while (a < b && _BRReconcileIsTrimmed((unsigned char)s[a])) a++;
    while (b > a && _BRReconcileIsTrimmed((unsigned char)s[b - 1])) b--;
    if (offset) *offset = a;
    if (length) *length = b - a;
}

// Address spans by (trimmed bytes, then length: a prefix first), then index.
static inline int _BRReconcileSpanBytesCompare(const BRReconcileAddressSpan *x, const BRReconcileAddressSpan *y,
                                               const char *const *addrs)
{
    size_t len = (x->length < y->length) ? x->length : y->length;
    int c = memcmp(addrs[x->index] + x->offset, addrs[y->index] + y->offset, len);
    if (c) return (c < 0) ? -1 : 1;
    return _BRReconcileIndexCompare(x->length, y->length);
}

static inline int _BRReconcileSpanCompare(const void *a, const void *b, const void *ctx)
{
    const BRReconcileAddressSpan *x = (const BRReconcileAddressSpan *)a, *y = (const BRReconcileAddressSpan *)b;
    int c = _BRReconcileSpanBytesCompare(x, y, (const char *const *)ctx);
    return c ? c : _BRReconcileIndexCompare(x->index, y->index);
}

static inline int _BRReconcileSpanIndexCompare(const void *a, const void *b, const void *ctx)
{
    (void)ctx;
    return _BRReconcileIndexCompare(((const BRReconcileAddressSpan *)a)->index, ((const BRReconcileAddressSpan *)b)->index);
}

// The DISTINCT ADDRESSES: from addrs[0..count) (NUL-terminated strings; a NULL entry is skipped), writes
// out[0..*outCount): each trimmed, non-empty address once, first-seen order. out[] is also the working
// space: it must hold every non-empty entry (outCap >= count always suffices).
//   OK / BUFFER_TOO_SMALL (*outCount 0) / NULL_ARGUMENT.
static inline BRReconcileStatus BRReconcileDistinctAddresses(const char *const addrs[], size_t count,
                                                             BRReconcileAddressSpan out[], size_t outCap,
                                                             size_t *outCount)
{
    size_t i, n = 0, m = 0, off, len;

    if (! outCount) return BR_RECONCILE_NULL_ARGUMENT;
    *outCount = 0;
    if ((count && ! addrs) || (outCap && ! out)) return BR_RECONCILE_NULL_ARGUMENT;
    for (i = 0; i < count; i++) {
        if (! addrs[i]) continue;
        BRReconcileAddressTrim(addrs[i], &off, &len);
        if (len == 0) continue;
        if (n >= outCap) return BR_RECONCILE_BUFFER_TOO_SMALL;
        out[n].index = i;
        out[n].offset = off;
        out[n].length = len;
        n++;
    }
    _BRReconcileHeapSort(out, n, sizeof(*out), _BRReconcileSpanCompare, addrs);
    for (i = 0; i < n; i++) {   // the first of each group is its first occurrence
        if (m > 0 && _BRReconcileSpanBytesCompare(&out[m - 1], &out[i], addrs) == 0) continue;
        out[m++] = out[i];
    }
    _BRReconcileHeapSort(out, m, sizeof(*out), _BRReconcileSpanIndexCompare, NULL);
    *outCount = m;
    return BR_RECONCILE_OK;
}

#ifdef __cplusplus
}
#endif

#endif // BRReconcilePlan_h
