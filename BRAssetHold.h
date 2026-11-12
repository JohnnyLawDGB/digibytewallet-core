//
//  BRAssetHold.h
//
//  Which of the wallet's outputs must be HELD -- kept out of every plain DGB spend -- because they may
//  carry DigiAsset units. A pass over every transaction the wallet holds, run before any spend is built
//  from the plain-coin set. Until 2026-11 this lived only in Android's Kotlin (core/.../asset/
//  AssetManager.kt: holdAssetOutputsBeforeSpendImpl, the TargetingWalk behind outputIsTargeted,
//  resolveInputAssetUnits as those call it, replayAssetOutpointExclusions with resolveRowTargetsImpl and
//  replayAnswerForAbsentTransaction, provenInputUnits). It moves here with the same answers and the same
//  refusals, and one deliberate difference, THE UNION below.
//
//  THE RULES:
//    - TWO READERS. The decoder (BRAssetDecode.h, with BRAssetTargetsOutput in BRAssetQuantity.h) says
//      which outputs a carrier may put units on, implicit change and unclassifiable carriers included.
//      The core's classifier (BRTxOutputIsAsset and BRContainsAsset in BRDigiAsset.c, the test behind
//      the wallet's assetUtxos) says which outputs an instruction names, and fails closed on a carrier it
//      cannot classify. Each answers YES, NO or UNKNOWN (BRAssetFact).
//    - THE UNION (BRAssetHoldCombine). YES when either reader says YES; NO only when both say NO;
//      otherwise UNKNOWN. Never weaker than either reader. The pass is read twice. The DECODER'S
//      READING is the Kotlin's, exactly: every fact the walk reads is the decoder's. The OTHER READING
//      puts the questions the Kotlin puts to its decoder alone -- does this funding transaction carry a
//      payload, may this funding output carry units -- to both readers, and reads the union; and it reads
//      a funding transaction only by the carrier the pass reads that transaction by. In both,
//      each output's verdict is the decoder's united with the classifier's, and an output either
//      reading holds is held. (Two readings, not one: a remainder proof turns an unknown total into a
//      known one, so a reading with more unknowns can hold less; the decoder's reading keeps the pass
//      never weaker than the Kotlin.) Everywhere else the move is exact.
//    - THE PASS (BRAssetHoldOutputs), in the wallet's order, each transaction once:
//        * its carrier: among its OP_RETURN outputs (a script whose first byte is 0x6a) that are DigiAsset
//          carriers, the first one that cannot be classified, otherwise the last one (BRDigiAsset.c's
//          choice). None: the decoder says NO for every output.
//        * what its inputs carried, input by input: a row with a positive quantity carries it; a row
//          storing zero or less carries nothing only when its funding output is NOT targeted (the walk
//          below); no row carries nothing only when the funding transaction carries no payload (the
//          decoder reads its FIRST OP_RETURN; in the other reading the classifier reads any output too).
//          A no-row input whose funding transaction may carry a payload, a sum past INT64_MAX, or an
//          input whose outpoint index is past INT32_MAX makes the total unknown; so does a stored-zero
//          row that may be targeted, though the inputs after it are still read. Unknown, and the
//          transaction's remainder proven zero: what its instructions assign (BRAssetAssignedUnits).
//        * every output that is not OP_RETURN and is the wallet's own (owned == NULL: every output):
//          decoder BRAssetTargetsOutput(carrier, vout, first non-OP_RETURN output, input units, output
//          count); classifier BRTxOutputIsAsset. YES held, NO not held, UNKNOWN refuses.
//    - THE WALK (does a funding output's transaction direct units to it?), for a row storing zero: the
//      payload decides every output but one. Not targeted even with an unknown remainder: NO. Targeted with a
//      remainder of zero: YES. Otherwise the remainder of the funding transaction decides, and its input
//      total is resolved the same way, one transaction further back, as far back as the run goes (each
//      transaction once, on an explicit stack held in the caller's work buffer, so a long run of sends costs
//      no call depth). The walk reads the funding transaction's FIRST OP_RETURN as its carrier; in the other
//      reading only when that is also the carrier THE PASS reads it by. A transaction the wallet does not
//      hold, one with no carrier there (in the other reading: one whose carrier is another output), and one
//      whose inputs cannot all be read (an index past INT32_MAX) have no answer. A total taken before
//      everything under it was resolved (a cycle) has no answer, and that walk records nothing for later
//      walks; every other total a walk resolves is recorded for the rest of the phase, and the pass records
//      each carrier transaction's own total as it goes. In the other reading each answer the walk gives,
//      for the output asked about and for every stored-zero input it reads on the way, is united with the
//      classifier's verdict for that output. The steps are the Kotlin's in both.
//    - THE REPLAY (Kotlin: replayAssetOutpointExclusions), after the pass, over the rows not spent, with
//      its own record of totals: a row with a positive quantity is held; any other is held when its
//      output is targeted -- the pass's rule, except that an input it cannot read is passed over -- or
//      when that has no answer (a transaction with no output or no carrier). A row whose transaction the
//      wallet does not hold is not held: nothing can spend it, and an outpoint held ahead of its
//      transaction is never released. The classifier is asked too, and the union decides. Each reading
//      replays with its own record of totals.
//    - REFUSALS. The answer is BR_ASSET_HOLD_COMPLETE only when every transaction was read. A NULL where
//      a value is needed, or a test seam in a build that does not offer them (TEST SEAMS below), is
//      ARGUMENTS; two rows for one outpoint that differ in quantity or spent flag are ROWS (rows that are
//      the same are read as one, by the first of them in the view); a transaction that cannot be read (a
//      NULL transaction, outputs, inputs or script where the counts say there are some, or more than
//      INT32_MAX outputs) is UNREADABLE; a work buffer smaller than the view's count of transactions, rows or proofs, whichever
//      is most, or a held list the buffer cannot hold, is CAPACITY. A refusal reports heldCount 0, and what
//      `held` then holds is unspecified. The caller must refuse the spend on any status but COMPLETE, never
//      read a refusal as "nothing held". The status 0 is a refusal, so a result nobody filled refuses.
//      CAPACITY says what suffices: workNeeded and heldNeeded (every output of every transaction, plus
//      every row), as BRAssetHoldBounds gives them.
//
//  How the Kotlin's arguments are written here: a transaction is the BRTransaction the wallet holds; a
//  txid is its txHash as the struct holds it (BRWallet's order, not the display order); a row is
//  BRAssetHoldRow (its txid, index, stored quantity and spent flag; one answer per outpoint, as the
//  Kotlin's table has one row per outpoint); the proof store is the list of txids whose remainder is
//  proven zero; the owned-script set is the owned callback. The classifier half is BRDigiAsset.c's.
//  The view's classifier field is a test seam (TEST SEAMS below): a build without ASSET_HOLD_TEST_SEAMS
//  refuses a view that names one, so a production caller leaves it NULL, as BRWalletHoldAssetOutputs
//  does. A pass here reads one snapshot, so the Kotlin's re-listing until the set settles and its caches
//  are not needed: they change what is read, not what is answered. Its plain-transaction set is kept for
//  the one pass (it answers "no payload" for a transaction read earlier in the pass that has no outputs);
//  across passes it is not.
//
//  BRWalletHoldAssetOutputs runs the pass over the wallet's own transactions under its lock, owned
//  meaning "an address of the wallet's", and on COMPLETE holds every outpoint in the list
//  (BRWalletRegisterAssetOutpoint's list, one balance rebuild for all of them); newlyHeld counts those
//  not held before. On a refusal it holds nothing new. What it holds covers the transactions it read, and
//  registrations do not survive a restart: run it after the wallet loads, after transactions are added or
//  removed, and immediately before building any spend from the plain-coin set; refuse the spend when it
//  answers anything but COMPLETE. (Nothing in the core enforces that order yet.)
//
//  No allocation, no network, no clock, no I/O in the pass: the caller's `work` buffer (BRAssetHoldBounds)
//  holds the walk's state, its stack and the sorted indexes of transactions, rows and proofs, and the
//  caller's `held` buffer the answer, never shortened. Every lookup (a transaction, a row, a proof, a
//  held outpoint) is a binary search over a sorted index, never a scan. The pass is static inline; it
//  calls BRDigiAsset.c's classifier. Its includes are libc and the core headers whose types or functions
//  it uses. It reads no build-time policy macro.
//
//  TEST SEAMS (host KAT asset_hold_kat in the Android repo). ASSET_HOLD_TEST_SEAMS, tested by VALUE:
//  unset or =0 is what ships, and then BRAssetHoldOutputs refuses (ARGUMENTS) a view whose classifier is
//  not NULL, and _BRAssetHoldOutputsReading refuses any choice of readings but both. =1 (the host KAT's
//  test builds only) honours the view's classifier (abstract verdicts no script has to give) and lets
//  _BRAssetHoldOutputsReading make one reading alone. No build makes no reading. The view's layout is
//  the same either way.
//  ASSET_HOLD_UNFIXED, tested by VALUE as a set of bits; each comparison arm sets one bit and fails only
//  its own cases. Unset or =0 is what ships.
//    1     ASSET_HOLD_RED_DECODER_DROPPED     a verdict is the classifier's alone.
//    2     ASSET_HOLD_RED_CLASSIFIER_DROPPED  a verdict is the decoder's alone.
//    4     ASSET_HOLD_RED_UNKNOWN_FREE        a verdict neither reader can give is "carries nothing".
//    8     ASSET_HOLD_RED_WALK_STOPS          a funding transaction's remainder is never walked back.
//    16    ASSET_HOLD_RED_REPLAY_SKIPPED      the rows are not replayed.
//    32    ASSET_HOLD_RED_ABSENT_HELD         a row whose transaction the wallet does not hold is held.
//    64    ASSET_HOLD_RED_OWNERSHIP_IGNORED   an output that is not the wallet's own is held like one that is.
//    128   ASSET_HOLD_RED_PROOF_IGNORED       a remainder proof is not read.
//    256   ASSET_HOLD_RED_FIRST_CARRIER       a transaction's carrier is its first carrier output.
//    512   ASSET_HOLD_RED_INPUT_DROPPED       an input the pass cannot read is passed over.
//    1024  ASSET_HOLD_RED_SETTLED_UNGATED     a walk records totals taken before everything under them was resolved.
//    2048  ASSET_HOLD_RED_CAPACITY_SHORTENS   a held list the buffer cannot hold is shortened.
//    4096  ASSET_HOLD_RED_REFUSAL_EMPTY       a pass that cannot complete answers "complete, nothing held".
//    8192  ASSET_HOLD_RED_FACTS_DECODER_ONLY  only the decoder's reading is made.
//    16384 ASSET_HOLD_RED_SHAPE_FIRST_ONLY    the other reading too reads a funding transaction by its first OP_RETURN.
//    32768 ASSET_HOLD_RED_DUPLICATE_ROWS      two rows for one outpoint that differ are read, one of them winning.
//    65536 ASSET_HOLD_RED_SEAMS_OPEN          a build without ASSET_HOLD_TEST_SEAMS honours the test seams.
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

#ifndef BRAssetHold_h
#define BRAssetHold_h

#include "BRAssetAllocate.h"   // BRAssetFact, BRAssetInputFacts, BRAssetResolveInputUnits
#include "BRAssetData.h"       // BRAssetOperation
#include "BRAssetDecode.h"     // BRAssetHeader, BRAssetDecodeInstructions, BR_ASSET_MAX_INSTRUCTIONS
#include "BRAssetQuantity.h"   // BRAssetTargetsOutput, BRAssetAssignedUnits, _BRAssetAddUnits
#include "BRDigiAsset.h"       // BRTxOutputIsAsset, BRContainsAsset
#include "BRInt.h"             // UInt256, UInt256Eq
#include "BRTransaction.h"     // BRTransaction, BRTxOutput
#include "BRWallet.h"          // BRWallet, BRUTXO
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_HOLD_UNFIXED
#define ASSET_HOLD_UNFIXED 0
#endif

#ifndef ASSET_HOLD_TEST_SEAMS
#define ASSET_HOLD_TEST_SEAMS 0
#endif

#define ASSET_HOLD_RED_DECODER_DROPPED     1
#define ASSET_HOLD_RED_CLASSIFIER_DROPPED  2
#define ASSET_HOLD_RED_UNKNOWN_FREE        4
#define ASSET_HOLD_RED_WALK_STOPS          8
#define ASSET_HOLD_RED_REPLAY_SKIPPED      16
#define ASSET_HOLD_RED_ABSENT_HELD         32
#define ASSET_HOLD_RED_OWNERSHIP_IGNORED   64
#define ASSET_HOLD_RED_PROOF_IGNORED       128
#define ASSET_HOLD_RED_FIRST_CARRIER       256
#define ASSET_HOLD_RED_INPUT_DROPPED       512
#define ASSET_HOLD_RED_SETTLED_UNGATED     1024
#define ASSET_HOLD_RED_CAPACITY_SHORTENS   2048
#define ASSET_HOLD_RED_REFUSAL_EMPTY       4096
#define ASSET_HOLD_RED_FACTS_DECODER_ONLY  8192
#define ASSET_HOLD_RED_SHAPE_FIRST_ONLY    16384
#define ASSET_HOLD_RED_DUPLICATE_ROWS      32768
#define ASSET_HOLD_RED_SEAMS_OPEN          65536

// ---- the types -----------------------------------------------------------------------------------

// One wallet row (Android: UtxoEntity), the fields the hold reads. The caller gives the current row of
// each outpoint, once, from a store keyed by outpoint: a txid kept as hex is put in one canonical form
// (lower case) before it is parsed, so that two spellings of one txid cannot be two rows. Only asset
// rows (Android: is_asset, as getAssetUtxoAt and getAllAssetUtxosNow read them), never a row for a plain
// coin: a stored-zero row is read differently from no row. Two rows for one outpoint that differ refuse
// the pass (ROWS); the same row twice is read once.
typedef struct {
    UInt256 txHash;                  // the transaction that created the output, as BRTransaction holds it
    uint32_t n;                      // the output's index
    int64_t quantity;                // the units the row stores
    int spent;                       // 1: the replay passes over it
} BRAssetHoldRow;

// Is tx->outputs[vout] the wallet's own? `info` is the view's.
typedef int (*BRAssetHoldOwnedFn)(void *info, const BRTransaction *tx, size_t vout);

// The classifier half, when it is not the core's (a test puts verdicts here that no script it has to
// write gives). Each answers 1 or 0. NULL in the view, or a NULL function: BRDigiAsset.c's. A TEST SEAM,
// honoured only when ASSET_HOLD_TEST_SEAMS is 1: another classifier can make the union weaker, so a
// build without the seams refuses a view that names one (ARGUMENTS).
typedef struct {
    int (*outputIsAsset)(void *info, const BRTransaction *tx, size_t vout);   // BRTxOutputIsAsset
    int (*containsAsset)(void *info, const BRTransaction *tx);                // BRContainsAsset over its outputs
    void *info;
} BRAssetHoldClassifier;

// What the pass reads.
typedef struct {
    const BRTransaction *const *txs; // every transaction the wallet holds, in the wallet's order
    size_t txCount;
    BRAssetHoldOwnedFn owned;        // NULL: every output is the wallet's own (Kotlin: an empty owned set)
    void *info;
    const BRAssetHoldRow *rows;      // the wallet's rows, spent ones included; one answer per outpoint
    size_t rowCount;
    const UInt256 *proven;           // txids whose last output is proven to carry no units
    size_t provenCount;
    const BRAssetHoldClassifier *classifier;   // NULL: the core's. A test seam: not NULL refuses unless ASSET_HOLD_TEST_SEAMS
} BRAssetHoldView;

// One entry of the caller's work buffer: as many as the view has transactions, rows or proofs, whichever
// is most (BRAssetHoldBounds). The fields are the pass's own.
typedef struct {
    size_t sorted;                   // the transactions by txid
    size_t row, proof;               // the rows by outpoint, the proofs by txid
    size_t stackTx, stackNext;       // the walk's stack
    size_t link;                     // the totals one walk resolved
    uint32_t epoch;                  // the walk the fields below belong to
    int state;                       // 1 on the walk's way, 2 total resolved
    int known;
    int64_t units;
    int settled, settledKnown;       // the phase's record of totals
    int64_t settledUnits;
} BRAssetHoldWork;

// BR_ASSET_HOLD_COMPLETE or why not. 0 is a refusal.
typedef enum {
    BR_ASSET_HOLD_REFUSED = 0,              // nobody filled the result
    BR_ASSET_HOLD_COMPLETE = 1,             // every transaction was read; `held` is the answer
    BR_ASSET_HOLD_REFUSED_ARGUMENTS = 2,    // a NULL where a value is needed, or a test seam this build does not offer
    BR_ASSET_HOLD_REFUSED_UNREADABLE = 3,   // a transaction that cannot be read, or a verdict neither reader can give
    BR_ASSET_HOLD_REFUSED_CAPACITY = 4,     // `work` or `held` too small: see workNeeded and heldNeeded
    BR_ASSET_HOLD_REFUSED_ROWS = 5          // two rows for one outpoint that differ in quantity or spent flag
} BRAssetHoldStatus;

typedef struct {
    BRAssetHoldStatus status;
    size_t heldCount;                // COMPLETE: the outpoints written to `held`; 0 otherwise, and `held` unspecified
    size_t newlyHeld;                // BRWalletHoldAssetOutputs, COMPLETE: those the wallet did not hold before
    size_t workNeeded;               // CAPACITY: work entries that suffice
    size_t heldNeeded;               // CAPACITY: held entries that suffice
} BRAssetHoldResult;

// ---- the union -----------------------------------------------------------------------------------

// (internal) A fact this header does not define reads as UNKNOWN.
static inline BRAssetFact _BRAssetHoldFact(BRAssetFact f)
{
    return (f == BR_ASSET_FACT_NO || f == BR_ASSET_FACT_YES) ? f : BR_ASSET_FACT_UNKNOWN;
}

// The decoder's and the classifier's verdicts for one output, as one (THE UNION): YES when either says
// YES, NO only when both say NO, UNKNOWN otherwise.
static inline BRAssetFact BRAssetHoldCombine(BRAssetFact decoder, BRAssetFact classifier)
{
    decoder = _BRAssetHoldFact(decoder);
    classifier = _BRAssetHoldFact(classifier);
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_DECODER_DROPPED)
    decoder = classifier;
#endif
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_CLASSIFIER_DROPPED)
    classifier = decoder;
#endif
    if (decoder == BR_ASSET_FACT_YES || classifier == BR_ASSET_FACT_YES) return BR_ASSET_FACT_YES;
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_UNKNOWN_FREE)
    return BR_ASSET_FACT_NO;
#else
    if (decoder == BR_ASSET_FACT_NO && classifier == BR_ASSET_FACT_NO) return BR_ASSET_FACT_NO;
    return BR_ASSET_FACT_UNKNOWN;
#endif
}

// ---- the pass's pieces (internal) ----------------------------------------------------------------

#define _BR_ASSET_HOLD_NONE ((size_t)-1)

typedef struct { int has; int64_t v; } _BRAssetHoldUnits;   // Long?

// One transaction's carrier, decoded, and what BRAssetTargetsOutput reads beside it.
typedef struct {
    BRAssetHeader h;
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];
    int hasFirst;
    int32_t first;                   // the first output that is not OP_RETURN
    int32_t outputCount;
} _BRAssetHoldTx;

typedef struct {
    const BRAssetHoldView *v;
    BRAssetHoldWork *w;
    size_t heldSorted;               // held[0, heldSorted) is sorted and holds each outpoint once
    uint32_t epoch;                  // the current walk
    int every;                       // no total of this walk was taken before everything under it
    size_t resolved;                 // the totals this walk resolved, linked through w[].link
    int classifierInFacts;           // the walk's facts are the union (1) or the decoder's alone (0)
    size_t current;                  // the pass: the transaction it is reading; the replay: _BR_ASSET_HOLD_NONE
} _BRAssetHoldState;

static inline _BRAssetHoldUnits _BRAssetHoldSome(int64_t v)
{
    _BRAssetHoldUnits u;

    u.has = 1;
    u.v = v;
    return u;
}

static inline _BRAssetHoldUnits _BRAssetHoldNone(void)
{
    _BRAssetHoldUnits u;

    u.has = 0;
    u.v = 0;
    return u;
}

static inline int _BRAssetHoldIsOpReturn(const BRTxOutput *o)
{
    return (o->scriptLen > 0 && o->script[0] == 0x6a) ? 1 : 0;
}

// The three indexes the work buffer sorts: the transactions by txid, the rows by outpoint, the proofs by
// txid; each then by place in the view.
enum { _BR_ASSET_HOLD_BY_TX, _BR_ASSET_HOLD_BY_ROW, _BR_ASSET_HOLD_BY_PROOF };

static inline size_t *_BRAssetHoldIndex(BRAssetHoldWork *w, int by, size_t k)
{
    return (by == _BR_ASSET_HOLD_BY_TX) ? &w[k].sorted : (by == _BR_ASSET_HOLD_BY_ROW) ? &w[k].row : &w[k].proof;
}

// The outpoint (h, n) against (h2, n2): negative, 0 or positive.
static inline int _BRAssetHoldOutpointCmp(UInt256 h, uint32_t n, UInt256 h2, uint32_t n2)
{
    int c = memcmp(h.u8, h2.u8, sizeof(UInt256));

    return (c != 0) ? c : (n < n2) ? -1 : (n > n2) ? 1 : 0;
}

static inline int _BRAssetHoldBefore(const BRAssetHoldView *v, int by, size_t i, size_t j)
{
    int c;

    if (by == _BR_ASSET_HOLD_BY_TX) c = memcmp(v->txs[i]->txHash.u8, v->txs[j]->txHash.u8, sizeof(UInt256));
    else if (by == _BR_ASSET_HOLD_BY_ROW)
        c = _BRAssetHoldOutpointCmp(v->rows[i].txHash, v->rows[i].n, v->rows[j].txHash, v->rows[j].n);
    else c = memcmp(v->proven[i].u8, v->proven[j].u8, sizeof(UInt256));
    return (c < 0 || (c == 0 && i < j)) ? 1 : 0;
}

static inline void _BRAssetHoldSiftDown(const BRAssetHoldView *v, BRAssetHoldWork *w, int by, size_t root, size_t end)
{
    while (2 * root + 1 < end) {
        size_t child = 2 * root + 1, top = root, t;

        if (_BRAssetHoldBefore(v, by, *_BRAssetHoldIndex(w, by, top), *_BRAssetHoldIndex(w, by, child))) top = child;
        if (child + 1 < end && _BRAssetHoldBefore(v, by, *_BRAssetHoldIndex(w, by, top), *_BRAssetHoldIndex(w, by, child + 1)))
            top = child + 1;
        if (top == root) return;
        t = *_BRAssetHoldIndex(w, by, root);
        *_BRAssetHoldIndex(w, by, root) = *_BRAssetHoldIndex(w, by, top);
        *_BRAssetHoldIndex(w, by, top) = t;
        root = top;
    }
}

// Heap sort of one index: no allocation, whatever the count.
static inline void _BRAssetHoldSort(const BRAssetHoldView *v, BRAssetHoldWork *w, int by, size_t n)
{
    size_t i, t;

    for (i = 0; i < n; i++) *_BRAssetHoldIndex(w, by, i) = i;
    if (n < 2) return;
    for (i = n / 2; i-- > 0;) _BRAssetHoldSiftDown(v, w, by, i, n);

    for (i = n - 1; i > 0; i--) {
        t = *_BRAssetHoldIndex(w, by, 0);
        *_BRAssetHoldIndex(w, by, 0) = *_BRAssetHoldIndex(w, by, i);
        *_BRAssetHoldIndex(w, by, i) = t;
        _BRAssetHoldSiftDown(v, w, by, 0, i);
    }
}

// The wallet's transaction with this txid (the first, when it holds two), or _BR_ASSET_HOLD_NONE.
static inline size_t _BRAssetHoldFind(const _BRAssetHoldState *s, UInt256 txHash)
{
    size_t lo = 0, hi = s->v->txCount, mid;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;
        if (memcmp(s->v->txs[s->w[mid].sorted]->txHash.u8, txHash.u8, sizeof(UInt256)) < 0) lo = mid + 1;
        else hi = mid;
    }

    if (lo < s->v->txCount && UInt256Eq(s->v->txs[s->w[lo].sorted]->txHash, txHash)) return s->w[lo].sorted;
    return _BR_ASSET_HOLD_NONE;
}

static inline const BRTransaction *_BRAssetHoldTxAt(const _BRAssetHoldState *s, size_t i)
{
    return (i == _BR_ASSET_HOLD_NONE) ? NULL : s->v->txs[i];
}

// Where the rows for (txHash, n) start in the sorted rows (their count when there are none).
static inline size_t _BRAssetHoldRowLowerBound(const _BRAssetHoldState *s, UInt256 txHash, uint32_t n)
{
    size_t lo = 0, hi = s->v->rowCount, mid;
    const BRAssetHoldRow *r;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;
        r = &s->v->rows[s->w[mid].row];
        if (_BRAssetHoldOutpointCmp(r->txHash, r->n, txHash, n) < 0) lo = mid + 1;
        else hi = mid;
    }

    return lo;
}

// The stored quantity of the row for (txHash, n), in *q, and 1; 0 when there is no row. (Rows for one
// outpoint that differ were refused before the pass: any of them is the answer.)
static inline int _BRAssetHoldRowOf(const _BRAssetHoldState *s, UInt256 txHash, uint32_t n, int64_t *q)
{
    size_t lo = _BRAssetHoldRowLowerBound(s, txHash, n);
    const BRAssetHoldRow *r;

    if (lo >= s->v->rowCount) return 0;
    r = &s->v->rows[s->w[lo].row];
    if (r->n != n || ! UInt256Eq(r->txHash, txHash)) return 0;
    *q = r->quantity;
    return 1;
}

// Do two rows for one outpoint differ in quantity or spent flag? (The rows are sorted.)
static inline int _BRAssetHoldRowsDisagree(const BRAssetHoldView *v, const BRAssetHoldWork *w)
{
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_DUPLICATE_ROWS)
    (void)v;
    (void)w;
    return 0;
#else
    size_t k;

    for (k = 1; k < v->rowCount; k++) {
        const BRAssetHoldRow *a = &v->rows[w[k - 1].row], *b = &v->rows[w[k].row];

        if (_BRAssetHoldOutpointCmp(a->txHash, a->n, b->txHash, b->n) == 0 &&
            (a->quantity != b->quantity || (a->spent != 0) != (b->spent != 0))) return 1;
    }

    return 0;
#endif
}

static inline int _BRAssetHoldIsProven(const _BRAssetHoldState *s, UInt256 txHash)
{
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_PROOF_IGNORED)
    (void)s;
    (void)txHash;
    return 0;
#else
    size_t lo = 0, hi = s->v->provenCount, mid;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;
        if (memcmp(s->v->proven[s->w[mid].proof].u8, txHash.u8, sizeof(UInt256)) < 0) lo = mid + 1;
        else hi = mid;
    }

    return (lo < s->v->provenCount && UInt256Eq(s->v->proven[s->w[lo].proof], txHash)) ? 1 : 0;
#endif
}

// Decodes script `o` into t->h and t->insts. BR_ASSET_MAX_INSTRUCTIONS entries hold every list.
static inline BRAssetScriptKind _BRAssetHoldDecode(const BRTxOutput *o, _BRAssetHoldTx *t)
{
    return BRAssetDecodeInstructions(o->script, o->scriptLen, &t->h, t->insts, BR_ASSET_MAX_INSTRUCTIONS);
}

static inline void _BRAssetHoldLayout(const BRTransaction *tx, _BRAssetHoldTx *t)
{
    size_t j;

    t->hasFirst = 0;
    t->first = 0;
    t->outputCount = (int32_t)tx->outCount;

    for (j = 0; j < tx->outCount; j++) {
        if (! _BRAssetHoldIsOpReturn(&tx->outputs[j])) {
            t->hasFirst = 1;
            t->first = (int32_t)j;
            break;
        }
    }
}

// Kotlin: assetCarrier. The carrier of a transaction (see THE PASS) in *t, its output index in *at
// (when `at` is not NULL), and 1; 0 when none.
static inline int _BRAssetHoldCarrier(const BRTransaction *tx, _BRAssetHoldTx *t, size_t *at)
{
    size_t j, last = _BR_ASSET_HOLD_NONE;
    BRAssetScriptKind kind;

    _BRAssetHoldLayout(tx, t);

    for (j = 0; j < tx->outCount; j++) {
        if (! _BRAssetHoldIsOpReturn(&tx->outputs[j])) continue;
        kind = _BRAssetHoldDecode(&tx->outputs[j], t);
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_FIRST_CARRIER)
        if (kind != BR_ASSET_SCRIPT_NOT_ASSET) {
#else
        if (kind == BR_ASSET_SCRIPT_UNCLASSIFIABLE) {
#endif
            if (at) *at = j;
            return 1;
        }
        if (kind == BR_ASSET_SCRIPT_ASSET) last = j;
    }

    if (last == _BR_ASSET_HOLD_NONE) return 0;
    _BRAssetHoldDecode(&tx->outputs[last], t);
    if (at) *at = last;
    return 1;
}

// Kotlin: assetTxShape. A funding transaction as the walk reads it: its FIRST OP_RETURN, when that is a
// carrier, in *t, and 1; 0 (no answer) otherwise. In the other reading the first OP_RETURN must also be
// the carrier THE PASS reads the transaction by; a transaction whose carrier is another has no answer.
static inline int _BRAssetHoldShape(const _BRAssetHoldState *s, const BRTransaction *tx, _BRAssetHoldTx *t)
{
    size_t j, first = _BR_ASSET_HOLD_NONE, at = _BR_ASSET_HOLD_NONE;

    if (! tx || tx->outCount == 0) return 0;

    for (j = 0; j < tx->outCount && first == _BR_ASSET_HOLD_NONE; j++) {
        if (_BRAssetHoldIsOpReturn(&tx->outputs[j])) first = j;
    }

    if (first == _BR_ASSET_HOLD_NONE) return 0;
#if !(ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_SHAPE_FIRST_ONLY)
    if (s->classifierInFacts) return (_BRAssetHoldCarrier(tx, t, &at) && at == first) ? 1 : 0;
#endif
    (void)s;
    (void)at;
    _BRAssetHoldLayout(tx, t);
    return (_BRAssetHoldDecode(&tx->outputs[first], t) != BR_ASSET_SCRIPT_NOT_ASSET) ? 1 : 0;
}

static inline int _BRAssetHoldTargets(const _BRAssetHoldTx *t, int32_t vout, _BRAssetHoldUnits units)
{
    return BRAssetTargetsOutput(t->h.operation, t->h.version, BRAssetHeaderHasRules(&t->h), t->h.hasTotalQuantity,
                                t->h.totalQuantity, vout, t->hasFirst, t->first, units.has, units.v, t->outputCount,
                                t->insts, t->h.instructionCount);
}

// Kotlin: provenInputUnits. What the instructions assign, when the transaction's remainder is proven zero.
static inline _BRAssetHoldUnits _BRAssetHoldProvenUnits(const _BRAssetHoldState *s, const BRTransaction *tx,
                                                        const _BRAssetHoldTx *t)
{
    int64_t assigned = 0;

    if (_BRAssetHoldIsProven(s, tx->txHash) &&
        BRAssetAssignedUnits(t->h.operation, t->insts, t->h.instructionCount, &assigned)) return _BRAssetHoldSome(assigned);
    return _BRAssetHoldNone();
}

// The classifier's verdict for output `vout` of `tx`: UNKNOWN for a transaction the wallet does not
// hold, NO for an output it does not have (as BRTxOutputIsAsset answers for an output not its own).
static inline BRAssetFact _BRAssetHoldClassifier(const _BRAssetHoldState *s, const BRTransaction *tx, size_t vout)
{
    const BRAssetHoldClassifier *c = s->v->classifier;
    int is;

    if (! tx) return BR_ASSET_FACT_UNKNOWN;
    if (vout >= tx->outCount) return BR_ASSET_FACT_NO;
    is = (c && c->outputIsAsset) ? c->outputIsAsset(c->info, tx, vout) : BRTxOutputIsAsset(tx, &tx->outputs[vout]);
    return is ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
}

// Does the classifier find a carrier among tx's outputs? UNKNOWN for a transaction the wallet does not hold.
static inline BRAssetFact _BRAssetHoldClassifierContains(const _BRAssetHoldState *s, const BRTransaction *tx)
{
    const BRAssetHoldClassifier *c = s->v->classifier;
    int is;

    if (! tx) return BR_ASSET_FACT_UNKNOWN;
    is = (c && c->containsAsset) ? c->containsAsset(c->info, tx) : BRContainsAsset(tx->outputs, tx->outCount);
    return is ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
}

// A fact of the walk: the decoder's alone in the decoder's reading, the union in the other.
static inline BRAssetFact _BRAssetHoldFactOf(const _BRAssetHoldState *s, BRAssetFact decoder, BRAssetFact classifier)
{
    return s->classifierInFacts ? BRAssetHoldCombine(decoder, classifier) : _BRAssetHoldFact(decoder);
}

// Kotlin: isAssetTx (hasAssetPayload over the FIRST OP_RETURN), with the classifier (any carrier).
// The pass answers NO for a transaction it has already read and found to carry no carrier (Kotlin: the
// pass's plainTxs); that differs from hasAssetPayload only for a transaction with no outputs.
static inline BRAssetFact _BRAssetHoldIsAssetTx(const _BRAssetHoldState *s, UInt256 txHash)
{
    size_t i = _BRAssetHoldFind(s, txHash), j;
    const BRTransaction *tx = _BRAssetHoldTxAt(s, i);
    BRAssetFact decoder = BR_ASSET_FACT_UNKNOWN;

    if (tx && tx->outCount == 0 && s->current != _BR_ASSET_HOLD_NONE && i < s->current) decoder = BR_ASSET_FACT_NO;
    if (tx && tx->outCount > 0) {
        decoder = BR_ASSET_FACT_NO;

        for (j = 0; j < tx->outCount; j++) {
            if (! _BRAssetHoldIsOpReturn(&tx->outputs[j])) continue;
            if (BRAssetDecodeHeader(tx->outputs[j].script, tx->outputs[j].scriptLen, NULL) != BR_ASSET_SCRIPT_NOT_ASSET)
                decoder = BR_ASSET_FACT_YES;
            break;
        }
    }

    return _BRAssetHoldFactOf(s, decoder, _BRAssetHoldClassifierContains(s, tx));
}

// Kotlin: TargetingWalk.fromPayload. 1 or 0 when the payload decides, -1 when only the remainder does.
// The decoder's alone: every answer the walk gives is united with the classifier where it is used.
static inline int _BRAssetHoldFromPayload(const _BRAssetHoldTx *t, int32_t vout)
{
    if (! _BRAssetHoldTargets(t, vout, _BRAssetHoldNone())) return 0;
    if (_BRAssetHoldTargets(t, vout, _BRAssetHoldSome(0))) return 1;
    return -1;
}

static inline void _BRAssetHoldTouch(_BRAssetHoldState *s, size_t i)
{
    if (s->w[i].epoch != s->epoch) {
        s->w[i].epoch = s->epoch;
        s->w[i].state = 0;
        s->w[i].known = 0;
        s->w[i].units = 0;
    }
}

static inline int _BRAssetHoldInWalk(const _BRAssetHoldState *s, size_t i, int state)
{
    return (s->w[i].epoch == s->epoch && s->w[i].state == state) ? 1 : 0;
}

static inline int _BRAssetHoldTotalResolved(const _BRAssetHoldState *s, size_t i)
{
    return (_BRAssetHoldInWalk(s, i, 2) || s->w[i].settled) ? 1 : 0;
}

static inline _BRAssetHoldUnits _BRAssetHoldTotalOf(const _BRAssetHoldState *s, size_t i)
{
    _BRAssetHoldUnits u = _BRAssetHoldNone();

    if (_BRAssetHoldInWalk(s, i, 2)) {
        u.has = s->w[i].known;
        u.v = s->w[i].units;
    }
    else if (s->w[i].settled) {
        u.has = s->w[i].settledKnown;
        u.v = s->w[i].settledUnits;
    }

    return u;
}

// Are all of tx's inputs readable as the Kotlin reads them (an index it can hold in an Int)?
static inline int _BRAssetHoldInputsReadable(const BRTransaction *tx)
{
    size_t k;

    for (k = 0; k < tx->inCount; k++) {
        if (tx->inputs[k].index > (uint32_t)INT32_MAX) return 0;
    }

    return 1;
}

// Kotlin: TargetingWalk.answerFromTotals, united with the classifier: from the payload and the totals
// already resolved, never walking further.
static inline BRAssetFact _BRAssetHoldAnswerFromTotals(_BRAssetHoldState *s, UInt256 txHash, uint32_t vout)
{
    size_t i = _BRAssetHoldFind(s, txHash);
    const BRTransaction *tx = _BRAssetHoldTxAt(s, i);
    BRAssetFact decoder = BR_ASSET_FACT_UNKNOWN;
    _BRAssetHoldTx t;
    int p;

    if (_BRAssetHoldShape(s, tx, &t)) {
        p = _BRAssetHoldFromPayload(&t, (int32_t)vout);
        if (p >= 0) decoder = p ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
        else if (! _BRAssetHoldTotalResolved(s, i)) s->every = 0;
        else decoder = _BRAssetHoldTargets(&t, (int32_t)vout, _BRAssetHoldTotalOf(s, i)) ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
    }

    return _BRAssetHoldFactOf(s, decoder, _BRAssetHoldClassifier(s, tx, vout));
}

// Kotlin: TargetingWalk.inputTotalOf. Transaction i's input total from the totals already resolved.
static inline _BRAssetHoldUnits _BRAssetHoldWalkTotal(_BRAssetHoldState *s, size_t i)
{
    const BRTransaction *tx = s->v->txs[i];
    _BRAssetHoldTx t;
    int64_t total = 0, q = 0;
    size_t k;

    if (! _BRAssetHoldShape(s, tx, &t)) return _BRAssetHoldNone();
    if (! _BRAssetHoldInputsReadable(tx)) return _BRAssetHoldNone();

    for (k = 0; k < tx->inCount; k++) {
        const BRTxInput *in = &tx->inputs[k];
        BRAssetInputFacts fact;
        BRAssetInputUnits r;

        memset(&fact, 0, sizeof(fact));
        if (_BRAssetHoldRowOf(s, in->txHash, in->index, &q)) {
            fact.hasRow = 1;
            fact.quantity = q;
            if (q <= 0) fact.rowIsTargeted = _BRAssetHoldAnswerFromTotals(s, in->txHash, in->index);
        }
        else fact.fundingIsAssetTx = _BRAssetHoldIsAssetTx(s, in->txHash);

        r = BRAssetResolveInputUnits(&fact, 1, NULL, 0);
        if (! r.known || ! _BRAssetAddUnits(total, r.units, &total)) return _BRAssetHoldProvenUnits(s, tx, &t);
    }

    return _BRAssetHoldSome(total);
}

// The walk's next step from transaction i: does it rest on a funding transaction whose total must be
// resolved first? Its index, or _BR_ASSET_HOLD_NONE when no input of i is left that does.
static inline size_t _BRAssetHoldNextBelow(_BRAssetHoldState *s, size_t depth)
{
    const BRTransaction *tx = s->v->txs[s->w[depth].stackTx];
    _BRAssetHoldTx t;
    int64_t q = 0;

    while (s->w[depth].stackNext < tx->inCount) {
        const BRTxInput *in = &tx->inputs[s->w[depth].stackNext++];
        size_t f;

        if (! _BRAssetHoldRowOf(s, in->txHash, in->index, &q) || q > 0) continue;
        f = _BRAssetHoldFind(s, in->txHash);
        if (! _BRAssetHoldShape(s, _BRAssetHoldTxAt(s, f), &t)) continue;
        if (_BRAssetHoldFromPayload(&t, (int32_t)in->index) >= 0) continue;
        return f;
    }

    return _BR_ASSET_HOLD_NONE;
}

static inline void _BRAssetHoldPush(_BRAssetHoldState *s, size_t *depth, size_t i)
{
    _BRAssetHoldTx t;

    _BRAssetHoldTouch(s, i);
    s->w[i].state = 1;
    s->w[*depth].stackTx = i;
    s->w[*depth].stackNext = 0;
    // Kotlin: restsOn is empty for a transaction with no carrier there or inputs it cannot read.
    if (! _BRAssetHoldShape(s, s->v->txs[i], &t) || ! _BRAssetHoldInputsReadable(s->v->txs[i]))
        s->w[*depth].stackNext = s->v->txs[i]->inCount;
    (*depth)++;
}

// Kotlin: TargetingWalk.resolveTotals. The input total of `root` and of every transaction under it,
// deepest first, each once.
static inline void _BRAssetHoldResolveTotals(_BRAssetHoldState *s, size_t root)
{
    size_t depth = 0, below, i;
    _BRAssetHoldUnits u;

    if (_BRAssetHoldTotalResolved(s, root)) return;
    _BRAssetHoldPush(s, &depth, root);

    while (depth > 0) {
        below = _BRAssetHoldNextBelow(s, depth - 1);

        if (below != _BR_ASSET_HOLD_NONE) {
            if (_BRAssetHoldTotalResolved(s, below)) continue;
            if (_BRAssetHoldInWalk(s, below, 1)) {   // already on the way: this walk records nothing
                s->every = 0;
                continue;
            }
            _BRAssetHoldPush(s, &depth, below);   // each transaction is on the way at most once: depth <= txCount
            continue;
        }

        i = s->w[--depth].stackTx;
        u = _BRAssetHoldWalkTotal(s, i);
        s->w[i].state = 2;
        s->w[i].known = u.has;
        s->w[i].units = u.v;
        s->w[i].link = s->resolved;
        s->resolved = i;
    }
}

// Kotlin: outputIsTargeted (TargetingWalk.answer), united with the classifier, for output `vout` of
// funding transaction txHash, with the phase's record of totals.
static inline BRAssetFact _BRAssetHoldWalk(_BRAssetHoldState *s, UInt256 txHash, uint32_t vout)
{
    size_t i = _BRAssetHoldFind(s, txHash), k;
    const BRTransaction *tx = _BRAssetHoldTxAt(s, i);
    BRAssetFact answer;
    _BRAssetHoldTx t;
    int p;

    if (! _BRAssetHoldShape(s, tx, &t)) return _BRAssetHoldFactOf(s, BR_ASSET_FACT_UNKNOWN, _BRAssetHoldClassifier(s, tx, vout));
    p = _BRAssetHoldFromPayload(&t, (int32_t)vout);
    if (p >= 0) return _BRAssetHoldFactOf(s, p ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO, _BRAssetHoldClassifier(s, tx, vout));
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_WALK_STOPS)
    return _BRAssetHoldFactOf(s, BR_ASSET_FACT_UNKNOWN, _BRAssetHoldClassifier(s, tx, vout));
#endif

    if (++s->epoch == 0) {   // 2^32 walks in one pass: start the stamps again
        for (k = 0; k < s->v->txCount; k++) s->w[k].epoch = 0;
        s->epoch = 1;
    }
    s->every = 1;
    s->resolved = _BR_ASSET_HOLD_NONE;

    _BRAssetHoldResolveTotals(s, i);
    answer = _BRAssetHoldAnswerFromTotals(s, txHash, vout);

#if !(ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_SETTLED_UNGATED)
    if (s->every)
#endif
    {
        for (k = s->resolved; k != _BR_ASSET_HOLD_NONE; k = s->w[k].link) {
            s->w[k].settled = 1;
            s->w[k].settledKnown = s->w[k].known;
            s->w[k].settledUnits = s->w[k].units;
        }
    }

    return answer;
}

// Kotlin: resolveInputAssetUnits with `unresolved` given, as the pass and the replay call it: what tx's
// inputs carried, or none. `dropUnreadable`: an input whose index is past INT32_MAX is passed over (the
// replay) instead of making the total unknown (the pass).
static inline _BRAssetHoldUnits _BRAssetHoldInputUnits(_BRAssetHoldState *s, const BRTransaction *tx, int dropUnreadable)
{
    int64_t total = 0, q = 0;
    size_t k, zeroRow;
    int zeroRows = 0;

#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_INPUT_DROPPED)
    dropUnreadable = 1;
#endif
    if (! dropUnreadable && ! _BRAssetHoldInputsReadable(tx)) return _BRAssetHoldNone();

    for (k = 0; k < tx->inCount; k++) {
        const BRTxInput *in = &tx->inputs[k];
        BRAssetInputFacts fact;
        BRAssetInputUnits r;

        if (in->index > (uint32_t)INT32_MAX) continue;   // reached only when dropUnreadable
        memset(&fact, 0, sizeof(fact));
        if (_BRAssetHoldRowOf(s, in->txHash, in->index, &q)) {
            fact.hasRow = 1;
            fact.quantity = q;
            if (q <= 0) fact.rowIsTargeted = _BRAssetHoldWalk(s, in->txHash, in->index);
        }
        else fact.fundingIsAssetTx = _BRAssetHoldIsAssetTx(s, in->txHash);

        r = BRAssetResolveInputUnits(&fact, 1, &zeroRow, 1);
        if (r.zeroRowCount > 0) {   // a stored-zero row that may be targeted: unknown, and the rest is read
            zeroRows = 1;
            continue;
        }
        if (! r.known || ! _BRAssetAddUnits(total, r.units, &total)) return _BRAssetHoldNone();
    }

    return zeroRows ? _BRAssetHoldNone() : _BRAssetHoldSome(total);
}

// Adds an outpoint to `held` unless held[0, s->heldSorted) has it. 0 when it does not fit. (Within one
// phase, the pass or the replay, each outpoint is offered once -- the pass reads each transaction once, and
// the replay reads only the first row of each outpoint -- so what was added since the last
// _BRAssetHoldSettle need not be searched, and a held buffer of the answer's size is enough.)
static inline int _BRAssetHoldAdd(const _BRAssetHoldState *s, BRUTXO *held, size_t heldCap, size_t *count, UInt256 txHash,
                                  uint32_t n)
{
    size_t lo = 0, hi = s->heldSorted, mid;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;
        if (_BRAssetHoldOutpointCmp(held[mid].hash, held[mid].n, txHash, n) < 0) lo = mid + 1;
        else hi = mid;
    }

    if (lo < s->heldSorted && held[lo].n == n && UInt256Eq(held[lo].hash, txHash)) return 1;
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_CAPACITY_SHORTENS)
    if (*count >= heldCap) return 1;
#else
    if (*count >= heldCap) return 0;
#endif
    held[*count].hash = txHash;
    held[*count].n = n;
    (*count)++;
    return 1;
}

static inline void _BRAssetHoldHeldSiftDown(BRUTXO *held, size_t root, size_t end)
{
    while (2 * root + 1 < end) {
        size_t child = 2 * root + 1, top = root;
        BRUTXO t;

        if (_BRAssetHoldOutpointCmp(held[top].hash, held[top].n, held[child].hash, held[child].n) < 0) top = child;
        if (child + 1 < end && _BRAssetHoldOutpointCmp(held[top].hash, held[top].n, held[child + 1].hash, held[child + 1].n) < 0)
            top = child + 1;
        if (top == root) return;
        t = held[root];
        held[root] = held[top];
        held[top] = t;
        root = top;
    }
}

// The end of a phase: held[0, *count) sorted, each outpoint once, and all of it searched from now on.
static inline void _BRAssetHoldSettle(_BRAssetHoldState *s, BRUTXO *held, size_t *count)
{
    size_t i, n = *count, k;
    BRUTXO t;

    for (i = n / 2; i-- > 0;) _BRAssetHoldHeldSiftDown(held, i, n);

    for (i = n; i-- > 1;) {
        t = held[0];
        held[0] = held[i];
        held[i] = t;
        _BRAssetHoldHeldSiftDown(held, 0, i);
    }

    for (i = 0, k = 0; i < n; i++) {
        if (k > 0 && _BRAssetHoldOutpointCmp(held[k - 1].hash, held[k - 1].n, held[i].hash, held[i].n) == 0) continue;
        held[k++] = held[i];
    }

    *count = k;
    s->heldSorted = k;
}

// Kotlin: resolveRowTargetsImpl and replayAnswerForAbsentTransaction, with `?: true`: the decoder's
// verdict for a row storing zero or less.
static inline BRAssetFact _BRAssetHoldReplayAnswer(_BRAssetHoldState *s, const BRAssetHoldRow *row)
{
    const BRTransaction *tx = _BRAssetHoldTxAt(s, _BRAssetHoldFind(s, row->txHash));
    _BRAssetHoldUnits units;
    _BRAssetHoldTx t;

#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_ABSENT_HELD)
    if (! tx) return BR_ASSET_FACT_YES;
#else
    if (! tx) return BR_ASSET_FACT_NO;   // the wallet is loaded and holds no such transaction
#endif
    if (tx->outCount == 0 || ! _BRAssetHoldCarrier(tx, &t, NULL) || row->n > (uint32_t)INT32_MAX) return BR_ASSET_FACT_YES;
    units = _BRAssetHoldInputUnits(s, tx, 1);
    if (! units.has) units = _BRAssetHoldProvenUnits(s, tx, &t);
    return _BRAssetHoldTargets(&t, (int32_t)row->n, units) ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
}

// (internal) A refusal: heldCount 0, whatever `held` was given.
static inline BRAssetHoldResult _BRAssetHoldRefuse(BRAssetHoldStatus status)
{
    BRAssetHoldResult r;

    memset(&r, 0, sizeof(r));
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_REFUSAL_EMPTY)
    if (status != BR_ASSET_HOLD_REFUSED_ARGUMENTS) status = BR_ASSET_HOLD_COMPLETE;
#endif
    r.status = status;
    return r;
}

// ---- the pass ------------------------------------------------------------------------------------

// What suffices for `view`: as many work entries as it has transactions, rows or proofs, whichever is most;
// and every output of every transaction plus every row in `held` (saturating at SIZE_MAX). 0 and both 0
// when the view cannot be read.
static inline int BRAssetHoldBounds(const BRAssetHoldView *view, size_t *workNeeded, size_t *heldNeeded)
{
    size_t i, n;

    if (workNeeded) *workNeeded = 0;
    if (heldNeeded) *heldNeeded = 0;
    if (! view || (view->txCount > 0 && ! view->txs)) return 0;
    n = view->rowCount;

    for (i = 0; i < view->txCount; i++) {
        if (! view->txs[i]) return 0;
        n = (view->txs[i]->outCount > SIZE_MAX - n) ? SIZE_MAX : n + view->txs[i]->outCount;
    }

    if (workNeeded) {
        *workNeeded = view->txCount;
        if (view->rowCount > *workNeeded) *workNeeded = view->rowCount;
        if (view->provenCount > *workNeeded) *workNeeded = view->provenCount;
    }
    if (heldNeeded) *heldNeeded = n;
    return 1;
}

// (internal) THE PASS and THE REPLAY once, reading the walk's facts with the classifier or without it
// (s->classifierInFacts): the outpoints to hold added to held[0, *count). COMPLETE or a refusal's status.
static inline BRAssetHoldStatus _BRAssetHoldRead(_BRAssetHoldState *s, BRUTXO *held, size_t heldCap, size_t *count)
{
    const BRAssetHoldView *view = s->v;
    BRAssetHoldWork *work = s->w;
    _BRAssetHoldTx t;
    size_t i, j, k;

    for (i = 0; i < view->txCount; i++) {
        work[i].epoch = 0;
        work[i].state = 0;
        work[i].settled = 0;
        work[i].link = _BR_ASSET_HOLD_NONE;
    }
    s->epoch = 0;

    // THE PASS
    for (i = 0; i < view->txCount; i++) {
        const BRTransaction *tx = view->txs[i];
        _BRAssetHoldUnits units = _BRAssetHoldNone();
        int carrier;

        if (_BRAssetHoldFind(s, tx->txHash) != i) continue;   // listed twice: read once
        s->current = i;
        carrier = _BRAssetHoldCarrier(tx, &t, NULL);

        if (carrier) {
            units = _BRAssetHoldInputUnits(s, tx, 0);
            if (! units.has) units = _BRAssetHoldProvenUnits(s, tx, &t);
            work[i].settled = 1;
            work[i].settledKnown = units.has;
            work[i].settledUnits = units.v;
        }

        for (j = 0; j < tx->outCount; j++) {
            BRAssetFact decoder = BR_ASSET_FACT_NO, verdict;

            if (_BRAssetHoldIsOpReturn(&tx->outputs[j])) continue;
#if !(ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_OWNERSHIP_IGNORED)
            if (view->owned && ! view->owned(view->info, tx, j)) continue;
#endif
            if (carrier) decoder = _BRAssetHoldTargets(&t, (int32_t)j, units) ? BR_ASSET_FACT_YES : BR_ASSET_FACT_NO;
            verdict = BRAssetHoldCombine(decoder, _BRAssetHoldClassifier(s, tx, j));
            if (verdict == BR_ASSET_FACT_UNKNOWN) return BR_ASSET_HOLD_REFUSED_UNREADABLE;
            if (verdict == BR_ASSET_FACT_NO) continue;
            if (! _BRAssetHoldAdd(s, held, heldCap, count, tx->txHash, (uint32_t)j)) return BR_ASSET_HOLD_REFUSED_CAPACITY;
        }
    }

    _BRAssetHoldSettle(s, held, count);

    // THE REPLAY, with its own record of totals
    for (i = 0; i < view->txCount; i++) work[i].settled = 0;
    s->current = _BR_ASSET_HOLD_NONE;

#if !(ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_REPLAY_SKIPPED)
    for (k = 0; k < view->rowCount; k++) {
        const BRAssetHoldRow *row = &view->rows[k];
        const BRTransaction *tx = _BRAssetHoldTxAt(s, _BRAssetHoldFind(s, row->txHash));
        BRAssetFact decoder, verdict;

        // a row listed twice is read once, at its first place in the view (the first in sorted order), so
        // the rows are still read in the view's order
        if (s->w[_BRAssetHoldRowLowerBound(s, row->txHash, row->n)].row != k) continue;
        if (row->spent) continue;
        decoder = (row->quantity > 0) ? BR_ASSET_FACT_YES : _BRAssetHoldReplayAnswer(s, row);
        // The classifier holds nothing of a transaction the wallet does not hold.
        verdict = BRAssetHoldCombine(decoder, tx ? _BRAssetHoldClassifier(s, tx, row->n) : BR_ASSET_FACT_NO);
        if (verdict == BR_ASSET_FACT_UNKNOWN) return BR_ASSET_HOLD_REFUSED_UNREADABLE;
        if (verdict == BR_ASSET_FACT_NO) continue;
        if (! _BRAssetHoldAdd(s, held, heldCap, count, row->txHash, row->n)) return BR_ASSET_HOLD_REFUSED_CAPACITY;
    }

    _BRAssetHoldSettle(s, held, count);
#else
    (void)k;
#endif

    return BR_ASSET_HOLD_COMPLETE;
}

// (internal) BRAssetHoldOutputs with a choice of readings: bit 1 the decoder's, bit 2 the other; 3 both.
// A choice of neither, or of bits beyond these, refuses. One reading alone is a test seam (TEST SEAMS):
// the host KAT reads each alone, and a build without ASSET_HOLD_TEST_SEAMS refuses anything but 3.
static inline BRAssetHoldResult _BRAssetHoldOutputsReading(const BRAssetHoldView *view, BRAssetHoldWork *work,
                                                           size_t workCap, BRUTXO *held, size_t heldCap, int readings)
{
    BRAssetHoldResult r;
    BRAssetHoldStatus status = BR_ASSET_HOLD_COMPLETE;
    _BRAssetHoldState s;
    size_t i, j, count = 0, workNeeded = 0;

    memset(&r, 0, sizeof(r));
    if (! view || (view->txCount > 0 && ! view->txs) || (view->rowCount > 0 && ! view->rows) ||
        (view->provenCount > 0 && ! view->proven) || (heldCap > 0 && ! held) || (workCap > 0 && ! work) ||
        (readings & 3) == 0 || (readings & ~3) != 0)
        return _BRAssetHoldRefuse(BR_ASSET_HOLD_REFUSED_ARGUMENTS);
#if !ASSET_HOLD_TEST_SEAMS && !(ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_SEAMS_OPEN)
    // what ships: the core's classifier and both readings, always
    if (view->classifier != NULL || readings != 3) return _BRAssetHoldRefuse(BR_ASSET_HOLD_REFUSED_ARGUMENTS);
#endif

    for (i = 0; i < view->txCount; i++) {   // every transaction must be readable before any is read
        const BRTransaction *tx = view->txs[i];

        if (! tx || (tx->outCount > 0 && ! tx->outputs) || (tx->inCount > 0 && ! tx->inputs) ||
            tx->outCount > (size_t)INT32_MAX) return _BRAssetHoldRefuse(BR_ASSET_HOLD_REFUSED_UNREADABLE);
        for (j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].scriptLen > 0 && ! tx->outputs[j].script)
                return _BRAssetHoldRefuse(BR_ASSET_HOLD_REFUSED_UNREADABLE);
        }
    }

    BRAssetHoldBounds(view, &workNeeded, NULL);
    if (workCap < workNeeded) status = BR_ASSET_HOLD_REFUSED_CAPACITY;
    else {
        s.v = view;
        s.w = work;
        s.heldSorted = 0;
        s.epoch = 0;
        s.every = 1;
        s.resolved = _BR_ASSET_HOLD_NONE;
        s.current = _BR_ASSET_HOLD_NONE;
        _BRAssetHoldSort(view, work, _BR_ASSET_HOLD_BY_TX, view->txCount);
        _BRAssetHoldSort(view, work, _BR_ASSET_HOLD_BY_ROW, view->rowCount);
        _BRAssetHoldSort(view, work, _BR_ASSET_HOLD_BY_PROOF, view->provenCount);
        if (_BRAssetHoldRowsDisagree(view, work)) return _BRAssetHoldRefuse(BR_ASSET_HOLD_REFUSED_ROWS);

        // the decoder's reading (the Kotlin's), then the one whose facts the classifier informs
        s.classifierInFacts = 0;
        if (readings & 1) status = _BRAssetHoldRead(&s, held, heldCap, &count);
        s.classifierInFacts = 1;
        if ((readings & 2) && status == BR_ASSET_HOLD_COMPLETE) status = _BRAssetHoldRead(&s, held, heldCap, &count);
    }

    if (status != BR_ASSET_HOLD_COMPLETE) {
        r = _BRAssetHoldRefuse(status);
        if (status == BR_ASSET_HOLD_REFUSED_CAPACITY) BRAssetHoldBounds(view, &r.workNeeded, &r.heldNeeded);
        return r;
    }

    r.status = BR_ASSET_HOLD_COMPLETE;
    r.heldCount = count;
    return r;
}

// THE PASS and THE REPLAY over `view` (see THE RULES), the decoder's reading and the classifier-informed
// one: every outpoint to hold, written to held[0, heldCount) once each, in outpoint order. `work` has room
// for workCap entries.
static inline BRAssetHoldResult BRAssetHoldOutputs(const BRAssetHoldView *view, BRAssetHoldWork *work, size_t workCap,
                                                   BRUTXO *held, size_t heldCap)
{
#if (ASSET_HOLD_UNFIXED & ASSET_HOLD_RED_FACTS_DECODER_ONLY)
    return _BRAssetHoldOutputsReading(view, work, workCap, held, heldCap, 1);
#else
    return _BRAssetHoldOutputsReading(view, work, workCap, held, heldCap, 3);
#endif
}

// ---- the wallet ----------------------------------------------------------------------------------

// THE PASS and THE REPLAY over the wallet's own transactions, under its lock, with `rows` and `proven`
// as the view's; on COMPLETE every outpoint in held[0, heldCount) is held out of the plain-coin set
// (one balance rebuild), and newlyHeld counts those it was not holding. Defined in BRWallet.c.
BRAssetHoldResult BRWalletHoldAssetOutputs(BRWallet *wallet, const BRAssetHoldRow *rows, size_t rowCount,
                                           const UInt256 *proven, size_t provenCount,
                                           BRAssetHoldWork *work, size_t workCap, BRUTXO *held, size_t heldCap);

#ifdef __cplusplus
}
#endif

#endif // BRAssetHold_h
