//
//  BRRecoveryUtxo.h
//
//  The rules that decide which unspent outputs a Recover-funds scan counts and sweeps, from the rows a
//  UTXO lookup returned for one derivation profile. Until 2026-11 these lived only in Android's Kotlin
//  (core/.../recovery/UtxoDedup.kt; the per-profile filter in RecoveryScanService.classifyDerived; the
//  non-positive-amount refusal in LegacySweepService.admit). They change the balance a scan quotes and
//  the inputs a sweep signs, so both platforms take them from here. The lookup itself, the JSON parse
//  and the signing stay each platform's own; vectors/reconcile-response/ binds the parsers that produce
//  the rows this header reads.
//
//  THE RULES, in the order a scan applies them:
//    - ONE COIN PER OUTPOINT (BRRecoveryUtxoDedup). The lookup has been observed returning the same
//      outpoint twice for a real address, once at a block height and once at height 0. Counted twice,
//      the scan quotes coins that do not exist, and a sweep spending one outpoint twice is invalid by
//      consensus, so the whole sweep is rejected. One entry is kept per (txid, vout):
//        * it stands where the outpoint was FIRST seen, so nothing else in the list moves;
//        * the copy kept is the first CONFIRMED copy (blockHeight > 0) if there is one, otherwise the
//          first copy. A height of 0 -- or below 0, which no block has -- means "not in a block"; keeping
//          it over a confirmed copy would describe a settled coin as pending, which can gate spending it.
//          Two confirmed copies that disagree keep the first.
//      Distinct from the reconcile's distinct-outpoint rule for node rows (keep the first row): this one
//      prefers the confirmed copy.
//    - A COIN FOR ITS PROFILE (BRRecoveryUtxoIsCoinForFormat). On a P2TR (BIP86, m/86'/20'/0') profile
//      an output carrying zero satoshis is a DigiDollar token output, which the DigiDollar path recovers;
//      as a plain coin it would make the sweep refuse the whole profile. On that profile only outputs of
//      a positive amount are coins. Every other profile keeps every row: a zero or negative amount there
//      is the lookup's error, and the next rule refuses the profile rather than hiding it.
//      Applied AFTER the one-coin rule, as Android does: a confirmed zero-value copy and an unconfirmed
//      positive copy of one P2TR outpoint leave nothing.
//      BRRecoveryUtxoSelect applies both rules in that order.
//    - TOTAL (BRRecoveryUtxoTotal). A profile's quoted balance is the sum of its selected rows' amounts,
//      signed; a sum that does not fit an int64 is reported, never wrapped.
//    - SWEEP ADMISSION (BRRecoverySweepAdmit). A profile may be swept only when its lookup was answered,
//      and then only when every selected row has a positive amount. One non-positive row refuses the
//      whole profile (a legacy P2PKH signature does not commit to the amount it spends, so an amount
//      that is not the chain's is never handed to the signer); the first such row is reported. An
//      unanswered lookup is reported before any row is read. The remaining admission step -- each
//      parent transaction must state the amount the lookup reported (Android's RawTxBinding) -- is the
//      platform's, after this one.
//
//  ADDRESS FORMATS are Android's DerivationProfile.addressFormat codes: 0 P2PKH, 1 P2WPKH, 2
//  P2SH-P2WPKH, 3 P2TR. NOT BRWalletAddressForScriptType's scriptType (where 2 is P2TR). A code this
//  header does not know is not P2TR: every row is kept, and admission refuses any non-positive one.
//
//  ROWS. A BRRecoveryUtxo carries only what the rules read; the caller keeps the rest of its row (address,
//  script) beside it and maps back by index. Outputs are INDICES into the caller's array, in a buffer the
//  caller owns, which is also the working space: it holds 2 * count indices
//  (BRRecoveryUtxoWorkCapacity), and the answer is never more than count of them. A buffer too small is
//  reported (BR_RECOVERY_UTXO_BUFFER_TOO_SMALL) with a count of 0. TXIDS are the 32 bytes in the order
//  the caller chooses -- the same order for every row -- and compare as bytes, so a platform that keeps
//  txids as hex decodes them first (vectors/reconcile-response/ gives lookup txids lowercase).
//  COST. The server decides how many rows there are, so nothing here is quadratic: the one-coin rule
//  sorts row indices by (txid, vout, row index) with an in-place heapsort (O(n log n), no allocation,
//  no recursion), folds each outpoint's group by the rule above in row order, and sorts the kept rows
//  back into first-seen order. Every comparison ends on a distinct row index, so the answer does not
//  depend on the sort, and it is the same answer Kotlin's sequential LinkedHashMap fold gives.
//  No allocation, no I/O, no clock, libc only. Header-only, static inline.
//
//  Host KAT (digibytewallet-android native/src/test/host/): recovery_utxo_kat -- DuplicateUtxoTest,
//  RecoveryScanClassifyTest's taproot case and AmountProvenanceGateTest's amount cases, case for case.
//

#ifndef BRRecoveryUtxo_h
#define BRRecoveryUtxo_h

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// MACRO CONVENTION: RECOVERY_UTXO_UNFIXED is tested by VALUE (#if). =1 is the host KAT's comparison arm,
// three ways the rules go wrong: the UNCONFIRMED copy of a repeated outpoint kept over the confirmed one,
// zero-value (and negative) P2TR rows kept as coins, and a zero amount admitted to a sweep. Unset or =0
// is what ships.
#ifndef RECOVERY_UTXO_UNFIXED
#define RECOVERY_UTXO_UNFIXED 0
#endif

// Android's DerivationProfile.addressFormat codes.
#define BR_RECOVERY_FORMAT_P2PKH       0
#define BR_RECOVERY_FORMAT_P2WPKH      1
#define BR_RECOVERY_FORMAT_P2SH_P2WPKH 2
#define BR_RECOVERY_FORMAT_P2TR        3

typedef struct {
    uint8_t txid[32];     // the outpoint's transaction, as bytes (see ROWS above)
    uint32_t vout;        // the outpoint's output index
    int64_t amount;       // satoshis, as the lookup reported them: may be zero or negative
    int64_t blockHeight;  // as the lookup reported it: > 0 in a block, <= 0 not
} BRRecoveryUtxo;

typedef enum {
    BR_RECOVERY_UTXO_OK = 0,
    BR_RECOVERY_UTXO_NULL_ARGUMENT = 1,     // a required pointer was NULL (or NULL with a nonzero count)
    BR_RECOVERY_UTXO_BUFFER_TOO_SMALL = 2,  // the answer does not fit the caller's buffer
    BR_RECOVERY_UTXO_OVERFLOW = 3,          // a total does not fit an int64
    BR_RECOVERY_UTXO_BAD_INDEX = 4          // an index names no row of the array
} BRRecoveryUtxoStatus;

typedef enum {
    BR_RECOVERY_SWEEP_ADMIT = 0,                // the profile may go on to the parent check
    BR_RECOVERY_SWEEP_REFUSE_UNREACHABLE = 1,   // the lookup was not answered
    BR_RECOVERY_SWEEP_REFUSE_NON_POSITIVE = 2,  // a row's amount is zero or negative
    BR_RECOVERY_SWEEP_REFUSE_BAD_ARGUMENT = 3   // NULL rows with a nonzero count, or a bad index
} BRRecoverySweepAdmission;

// ---- one coin per outpoint ---------------------------------------------------------------------

// Whether a row at this height is in a block.
static inline int BRRecoveryUtxoIsConfirmed(int64_t blockHeight)
{
    return blockHeight > 0;
}

// Whether two rows name the same outpoint.
static inline int BRRecoveryUtxoSameOutpoint(const BRRecoveryUtxo *a, const BRRecoveryUtxo *b)
{
    return a->vout == b->vout && memcmp(a->txid, b->txid, sizeof(a->txid)) == 0;
}

// Whether a later copy of an outpoint replaces the copy kept so far: only a confirmed copy replaces an
// unconfirmed one.
static inline int BRRecoveryUtxoReplaces(int64_t keptHeight, int64_t laterHeight)
{
#if RECOVERY_UTXO_UNFIXED
    return BRRecoveryUtxoIsConfirmed(keptHeight) && !BRRecoveryUtxoIsConfirmed(laterHeight);
#else
    return !BRRecoveryUtxoIsConfirmed(keptHeight) && BRRecoveryUtxoIsConfirmed(laterHeight);
#endif
}

// The working space the one-coin rule needs for count rows: 2 * count indices. 0 when that would overflow.
static inline size_t BRRecoveryUtxoWorkCapacity(size_t count)
{
    return (count > SIZE_MAX / 2) ? 0 : 2 * count;
}

// An in-place heapsort of n work pairs (2 * n size_t) with a context: O(n log n), no allocation, no
// recursion. Used only with total orders, so stability does not matter.
typedef int (*_BRRecoveryUtxoCompareFn)(const size_t *a, const size_t *b, const void *ctx);

static inline void _BRRecoveryUtxoSwap(size_t *a, size_t *b)
{
    size_t t0 = a[0], t1 = a[1];
    a[0] = b[0]; a[1] = b[1];
    b[0] = t0; b[1] = t1;
}

static inline void _BRRecoveryUtxoSiftDown(size_t *base, size_t root, size_t n, _BRRecoveryUtxoCompareFn cmp,
                                           const void *ctx)
{
    for (;;) {
        size_t child = 2 * root + 1, top = root;
        if (child >= n || child < root) return;   // child < root: 2 * root + 1 overflowed
        if (cmp(base + 2 * top, base + 2 * child, ctx) < 0) top = child;
        if (child + 1 < n && cmp(base + 2 * top, base + 2 * (child + 1), ctx) < 0) top = child + 1;
        if (top == root) return;
        _BRRecoveryUtxoSwap(base + 2 * root, base + 2 * top);
        root = top;
    }
}

static inline void _BRRecoveryUtxoHeapSort(size_t *pairs, size_t n, _BRRecoveryUtxoCompareFn cmp, const void *ctx)
{
    size_t i, end;

    if (!pairs || n < 2) return;
    for (i = n / 2; i > 0; i--) _BRRecoveryUtxoSiftDown(pairs, i - 1, n, cmp, ctx);
    for (end = n - 1; end > 0; end--) {
        _BRRecoveryUtxoSwap(pairs, pairs + 2 * end);
        _BRRecoveryUtxoSiftDown(pairs, 0, end, cmp, ctx);
    }
}

static inline int _BRRecoveryUtxoIndexCompare(size_t a, size_t b)
{
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

// Work pairs {row, first} (the row an outpoint's group keeps, and the row that first named it), by the
// row's (txid, vout), then by row index.
static inline int _BRRecoveryUtxoOutpointCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRRecoveryUtxo *u = (const BRRecoveryUtxo *)ctx;
    size_t i = a[0], j = b[0];
    int c = memcmp(u[i].txid, u[j].txid, sizeof(u[i].txid));
    if (c) return c;
    if (u[i].vout != u[j].vout) return (u[i].vout < u[j].vout) ? -1 : 1;
    return _BRRecoveryUtxoIndexCompare(i, j);
}

// Work pairs by the row that first named the outpoint.
static inline int _BRRecoveryUtxoFirstCompare(const size_t *a, const size_t *b, const void *ctx)
{
    (void)ctx;
    return _BRRecoveryUtxoIndexCompare(a[1], b[1]);
}

// One index per outpoint into utxos[0..count), in the order each outpoint was first seen, each naming
// the copy the rule keeps. kept[] is also the working space: capacity must be at least
// BRRecoveryUtxoWorkCapacity(count), else BUFFER_TOO_SMALL. *keptCount is the number written to
// kept[] (0 unless OK); kept[] past it is unspecified. kept may be NULL only when count is 0.
static inline BRRecoveryUtxoStatus BRRecoveryUtxoDedup(const BRRecoveryUtxo utxos[], size_t count,
                                                       size_t kept[], size_t capacity, size_t *keptCount)
{
    size_t need = BRRecoveryUtxoWorkCapacity(count), n = 0, i;

    if (!keptCount) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *keptCount = 0;
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!utxos || !kept) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    if (need == 0 || capacity < need) return BR_RECOVERY_UTXO_BUFFER_TOO_SMALL;

    // kept[2i] = the row a group keeps, kept[2i + 1] = the row that first named it.
    for (i = 0; i < count; i++) { kept[2 * i] = i; kept[2 * i + 1] = i; }
    _BRRecoveryUtxoHeapSort(kept, count, _BRRecoveryUtxoOutpointCompare, utxos);
    // Each group is now in row order, so its first pair is the row that first named it; fold the rest
    // into it in that order.
    for (i = 0; i < count; i++) {
        size_t row = kept[2 * i];
        if (n > 0 && BRRecoveryUtxoSameOutpoint(&utxos[kept[2 * (n - 1)]], &utxos[row])) {
            if (BRRecoveryUtxoReplaces(utxos[kept[2 * (n - 1)]].blockHeight, utxos[row].blockHeight)) {
                kept[2 * (n - 1)] = row;
            }
        } else {
            kept[2 * n] = row;
            kept[2 * n + 1] = kept[2 * i + 1];
            n++;
        }
    }
    _BRRecoveryUtxoHeapSort(kept, n, _BRRecoveryUtxoFirstCompare, NULL);
    for (i = 0; i < n; i++) kept[i] = kept[2 * i];
    *keptCount = n;
    return BR_RECOVERY_UTXO_OK;
}

// ---- a coin for its profile --------------------------------------------------------------------

// Whether a row of this amount is a coin on a profile of this address format.
static inline int BRRecoveryUtxoIsCoinForFormat(int addressFormat, int64_t amount)
{
#if RECOVERY_UTXO_UNFIXED
    (void)addressFormat; (void)amount;
    return 1;
#else
    return addressFormat != BR_RECOVERY_FORMAT_P2TR || amount > 0;
#endif
}

// The one-coin rule, then the coin-for-its-profile rule: the indices of the rows a profile counts and
// sweeps, in the one-coin rule's order. Same buffer contract as BRRecoveryUtxoDedup (2 * count).
static inline BRRecoveryUtxoStatus BRRecoveryUtxoSelect(int addressFormat, const BRRecoveryUtxo utxos[],
                                                        size_t count, size_t kept[], size_t capacity,
                                                        size_t *keptCount)
{
    size_t n = 0, m = 0, i;
    BRRecoveryUtxoStatus status;

    if (!keptCount) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *keptCount = 0;
    status = BRRecoveryUtxoDedup(utxos, count, kept, capacity, &n);
    if (status != BR_RECOVERY_UTXO_OK) return status;
    for (i = 0; i < n; i++) {
        if (BRRecoveryUtxoIsCoinForFormat(addressFormat, utxos[kept[i]].amount)) kept[m++] = kept[i];
    }
    *keptCount = m;
    return BR_RECOVERY_UTXO_OK;
}

// ---- total -------------------------------------------------------------------------------------

// The signed sum of the amounts of utxos[indices[0..count)] (indices NULL: utxos[0..count)). *total is
// 0 unless OK.
static inline BRRecoveryUtxoStatus BRRecoveryUtxoTotal(const BRRecoveryUtxo utxos[], size_t rowCount,
                                                       const size_t indices[], size_t count,
                                                       int64_t *total)
{
    int64_t sum = 0, a;
    size_t i, k;

    if (!total) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    *total = 0;
    if (count == 0) return BR_RECOVERY_UTXO_OK;
    if (!utxos) return BR_RECOVERY_UTXO_NULL_ARGUMENT;
    for (i = 0; i < count; i++) {
        k = indices ? indices[i] : i;
        if (k >= rowCount) return BR_RECOVERY_UTXO_BAD_INDEX;
        a = utxos[k].amount;
        if ((a > 0 && sum > INT64_MAX - a) || (a < 0 && sum < INT64_MIN - a)) return BR_RECOVERY_UTXO_OVERFLOW;
        sum += a;
    }
    *total = sum;
    return BR_RECOVERY_UTXO_OK;
}

// ---- sweep admission ---------------------------------------------------------------------------

// Whether a row of this amount may be handed to the signer.
static inline int BRRecoveryUtxoAmountIsSweepable(int64_t amount)
{
#if RECOVERY_UTXO_UNFIXED
    return amount >= 0;
#else
    return amount > 0;
#endif
}

// Whether a profile whose selected rows are utxos[indices[0..count)] (indices NULL: utxos[0..count))
// may be swept. backendReachable is nonzero when the lookup was answered. On
// BR_RECOVERY_SWEEP_REFUSE_NON_POSITIVE, *offending (when not NULL) is the index into utxos of the first
// such row in the order given; otherwise it is (size_t)-1.
static inline BRRecoverySweepAdmission BRRecoverySweepAdmit(int backendReachable,
                                                            const BRRecoveryUtxo utxos[], size_t rowCount,
                                                            const size_t indices[], size_t count,
                                                            size_t *offending)
{
    size_t i, k;

    if (offending) *offending = (size_t)-1;
    if (!backendReachable) return BR_RECOVERY_SWEEP_REFUSE_UNREACHABLE;
    if (count == 0) return BR_RECOVERY_SWEEP_ADMIT;
    if (!utxos) return BR_RECOVERY_SWEEP_REFUSE_BAD_ARGUMENT;
    for (i = 0; i < count; i++) {
        k = indices ? indices[i] : i;
        if (k >= rowCount) return BR_RECOVERY_SWEEP_REFUSE_BAD_ARGUMENT;
    }
    for (i = 0; i < count; i++) {
        k = indices ? indices[i] : i;
        if (!BRRecoveryUtxoAmountIsSweepable(utxos[k].amount)) {
            if (offending) *offending = k;
            return BR_RECOVERY_SWEEP_REFUSE_NON_POSITIVE;
        }
    }
    return BR_RECOVERY_SWEEP_ADMIT;
}

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryUtxo_h
