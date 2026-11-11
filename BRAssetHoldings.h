//
//  BRAssetHoldings.h
//
//  What the wallet holds of each DigiAsset, and how its record of one asset output (a "row") is kept
//  true: the row itself and its stored form, which rows count toward a balance, the balance, the
//  reconcile of a row's spent flag against the native wallet, the prunes that delete rows of
//  transactions the wallet no longer has, the write made when an asset output is detected, and the
//  acceptance of a DigiAsset indexer's answer for one output. Until 2026-11 this lived only in
//  Android's Kotlin (core/.../asset/AssetManager.kt: isHeldForDisplay, computeHeldAssetBalancesImpl,
//  decideAssetSpent, reconcileAssetRowsLocallyImpl, clearDeadAssetSend, pruneRemovedNativeAssetRowsImpl,
//  pruneDeadBroadcastRowsImpl, persistDetectedAssetOutput, settledRow, settleFromIndexer and
//  isOutgoingUnconfirmedRow; AssetSums.add; AssetMaintenanceGate.kt; and the reply rules of
//  network/DigiScopeAssetParsing.kt). It moves here unchanged: every input the Kotlin answers gets the
//  same answer here, and every input it refuses is refused here.
//
//  THE RULES:
//    - A ROW (BRAssetRow) is one output: its outpoint, script, value, confirming height (0: never
//      confirmed), whether it is an asset row, its asset id (or none), its stored quantity, its spent
//      flag, where it came from (BRAssetSource) and what backs its quantity (BRAssetCredit). Every
//      function below sees only the rows marked as asset rows; any other row is not there.
//    - NATIVE STATE is BRWalletOutpointAssetState's answer for the row's outpoint: SPENT 0, HELD 1,
//      UNDETECTED -1 (the wallet has no record of the funding transaction), CONFLICTED -2 (the funding
//      transaction is known and invalid), or PROBE_ERROR -99 (the platform could not ask). Any other
//      value is an answer of none of these.
//    - HELD (BRAssetHeldForDisplay): the row's script is not empty and is one of the wallet's own, and
//      the native state is HELD. Nothing else is held, whatever the row's provenance: a CONFLICTED
//      output never exists on chain, and an outpoint the wallet has no record of may be a phantom.
//    - A ROW COUNTS (BRAssetRowCounts) when it is an asset row, not flagged spent, names an asset, its
//      credit counts (BACKED or VERIFIED: BRAssetCreditCounts) and it is held.
//    - THE BALANCE (BRAssetHeldBalances), per asset id, over the rows that count: the quantities
//      summed, a sum past the int64 range stopping at its end (INT64_MAX, or INT64_MIN for negative
//      quantities) and never wrapping; and the number of those rows whose quantity is above zero. An
//      asset whose counted rows sum to zero is still listed, at zero: the platform shows only a
//      quantity above zero. An empty owned set is NO_OWNERSHIP, not an empty balance: the wallet could
//      not say which scripts are its own.
//    - THE SPENT FLAG (BRAssetRowSpentDecide): SPENT sets it, HELD clears it, every other state leaves
//      it as it is (a mid-sync wallet never hides a holding, and nothing spent a CONFLICTED output).
//    - THE RECONCILE (BRAssetReconcileRows): when the prune is allowed and the owned set is not empty,
//      every row whose script is not empty and not the wallet's own is deleted; then every other row's
//      spent flag is set by BRAssetRowSpentDecide. BRAssetClearDeadSend deletes the rows of one dead
//      send at the outputs whose script is the wallet's own.
//    - THE PRUNES. A NATIVE row whose transaction the wallet positively no longer holds is deleted on
//      the BR_ASSET_ABSENCE_PASSES-th pass in a row that finds it absent (BRAssetPruneRemovedNativeRows);
//      "absent" there is a lookup that found nothing or failed. A row of any provenance that never
//      confirmed (height 0 or less) and whose transaction the wallet holds no outputs of is deleted the
//      same way (BRAssetPruneDeadBroadcastRows); there a failed lookup is not absence. A row whose txid
//      is not 64 bytes is never looked up, counted or deleted. A pass that finds the transaction present
//      forgets the count. The counts are kept per outpoint and per prune in one caller-held table
//      (BRAssetAbsenceTable); a native pass ends by dropping every count but those of the NATIVE rows
//      it looked at. The prunes and the ownership half of the
//      reconcile run only while BRAssetPruneGateOpen is open: synced this session, a peer, progress at
//      1, a loaded wallet, and a known scan frontier within BR_CF_BEHIND_THRESHOLD of a known tip.
//    - A DETECTED OUTPUT (BRAssetPersistDetectedOutput). Nothing is written for the change of our own
//      unconfirmed send (BRAssetTxIsOutgoingUnconfirmed). A row the table already holds is re-tagged
//      NATIVE; when its credit is not settled (BRAssetCreditIsSettled) a decided credit settles it
//      (BRAssetSettledRowOf, BACKED) and an undecided one raises its quantity to a strictly larger
//      claim, never lowers it. Otherwise a NATIVE row is inserted, settled when the credit is decided
//      and UNCHECKED at the claimed quantity when it is not. The answer says whether the row's asset is
//      still unresolved (no id, or a placeholder starting "unresolved:").
//    - A SETTLED ROW (BRAssetSettledRowOf): holds units -> their asset and count; holds nothing -> the
//      label (or the placeholder) at zero; mixed -> the placeholder at zero, MIXED; unknown -> nothing.
//    - THE INDEXER. A row is asked about only while it is an unspent asset row whose credit is not
//      settled, and at most once every BR_ASSET_RECEIPT_RECHECK_MS (BRAssetIndexerAskDecide; the
//      platform keys the time by the txid in lower case and the vout, and forgets it when a row settles).
//      Its reply (BRAssetStackAnswerRead) is an answer only when it carries no error, names the txid
//      asked (ASCII case ignored) and the vout asked, and carries an array of entries each of which is
//      an object with an asset id that is neither empty nor "null" and a whole count of zero or more;
//      anything else is no answer, never an empty stack. A not-found reply is "not unspent" only when its
//      body is an object whose "unspent" is the boolean false (BRAssetStackNotFoundRead). An answer is
//      believed (BRAssetStackAnswerAccept) when BRAssetCreditFromIndexer reads it and the count it gives
//      the output is within BRAssetMaxDeliverable's bound; it then settles the row VERIFIED.
//
//  Answers that are not decided are never zero units: every enum here that has one keeps it at 0, so a
//  struct nobody filled reads as it (no answer, keep the row, refused).
//
//  Scripts are bytes compared byte for byte; ids and txids are NUL-terminated byte strings compared
//  byte for byte, the caller's own pointers kept in the answers.
//
//  THE STORED FORM (BRAssetRowEncode / BRAssetRowDecode), BR_ASSET_ROW_WIRE_VERSION 1, little-endian:
//      0  version (1)               1  flags: 1 asset row, 2 spent, 4 has an asset id; no other bit
//      2  source (0 BACKEND, 1 NATIVE)                  3  credit (0..3, BRAssetCredit)
//      4  vout, int32               8  satoshis, int64   16 blockHeight, int64   24 assetQuantity, int64
//     32  txid length T (0..255), T bytes, 0           then asset id length I (0..255; 0 without an id),
//         I bytes, 0                                   then script length S (uint16), S bytes
//  BR_ASSET_ROW_WIRE_FIXED + T + I + S bytes in all, exactly: a decode refuses any other length, a
//  missing terminator, a zero byte inside an id, an unknown version, flag, source or credit. A decoded
//  row points into the bytes it was read from. No allocation.
//
//  Caller buffers: a balance that `out` cannot hold, a stack answer with more entries than `out` holds,
//  a prune whose counts the table cannot hold, and a row the buffer cannot hold are refused with
//  BR_ASSET_HOLDINGS_CAPACITY, before anything is written. No allocation, no wallet, no network, no
//  clock (the platform passes the times), no I/O. Header-only, static inline; its includes are libc,
//  BRAssetAllocate.h (BRAssetCredit, BRAssetUnits, BRAssetOutputCredit, BRAssetStackLookup,
//  BRAssetDeliverable, BRAssetCreditFromIndexer and the credit states, which this header uses and does
//  not redefine) and BRSyncFrontier.h (BR_CF_BEHIND_THRESHOLD). Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_holdings_kat in the Android repo): ASSET_HOLDINGS_UNFIXED, tested by VALUE
//  as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is what
//  ships.
//    1        ASSET_HOLDINGS_RED_BACKEND_RESCUES      a BACKEND row the wallet has no record of is held.
//    2        ASSET_HOLDINGS_RED_CONFLICTED_HELD      a CONFLICTED outpoint is held.
//    4        ASSET_HOLDINGS_RED_OWNERSHIP_IGNORED    a script the wallet does not own is held.
//    8        ASSET_HOLDINGS_RED_UNBACKED_COUNTS      a row counts whatever its credit.
//    16       ASSET_HOLDINGS_RED_SPENT_COUNTS         a row flagged spent counts.
//    32       ASSET_HOLDINGS_RED_SUMS_WRAP            a balance past the int64 range wraps.
//    64       ASSET_HOLDINGS_RED_EMPTY_ROWS_COUNTED   a counted row of quantity zero adds to the row count.
//    128      ASSET_HOLDINGS_RED_NO_OWNERSHIP_EMPTY   an empty owned set answers an empty balance.
//    256      ASSET_HOLDINGS_RED_CONFLICTED_SPENT     CONFLICTED sets the spent flag.
//    512      ASSET_HOLDINGS_RED_NO_DEBOUNCE          a prune deletes on the first absent pass.
//    1024     ASSET_HOLDINGS_RED_TXID_DEBOUNCE        a prune counts per txid, not per outpoint.
//    2048     ASSET_HOLDINGS_RED_DEAD_PRUNES_CONFIRMED the dead-broadcast prune takes confirmed rows.
//    4096     ASSET_HOLDINGS_RED_PRUNE_ANY_SOURCE     the native prune takes rows of any provenance.
//    8192     ASSET_HOLDINGS_RED_SCRIPTLESS_PRUNED    the reconcile deletes a row with no script.
//    16384    ASSET_HOLDINGS_RED_STACK_UNBOUNDED      an indexer count past the bound is believed.
//    32768    ASSET_HOLDINGS_RED_STACK_ANY_OUTPUT     a reply naming another outpoint is read.
//    65536    ASSET_HOLDINGS_RED_BAD_ENTRY_SKIPPED    a malformed entry is skipped, not the reply refused.
//    131072   ASSET_HOLDINGS_RED_SETTLED_REWRITTEN    re-detection rewrites a settled row.
//    262144   ASSET_HOLDINGS_RED_OUTGOING_PERSISTED   our own unconfirmed send's change is written.
//    524288   ASSET_HOLDINGS_RED_ASKED_EVERY_TIME     the indexer is asked again at once.
//    1048576  ASSET_HOLDINGS_RED_WIRE_TRAILING        a stored row with bytes after it is read.
//    2097152  ASSET_HOLDINGS_RED_GATE_IGNORES_SCAN    the prune gate opens whatever the scan frontier.
//    4194304  ASSET_HOLDINGS_RED_QUANTITY_LOWERED     re-detection lowers an unsettled quantity.
//

#ifndef BRAssetHoldings_h
#define BRAssetHoldings_h

#include "BRAssetAllocate.h"   // BRAssetCredit, BRAssetUnits, BRAssetOutputCredit, BRAssetStackLookup, BRAssetDeliverable
#include "BRSyncFrontier.h"    // BR_CF_BEHIND_THRESHOLD
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_HOLDINGS_UNFIXED
#define ASSET_HOLDINGS_UNFIXED 0
#endif

#define ASSET_HOLDINGS_RED_BACKEND_RESCUES       1
#define ASSET_HOLDINGS_RED_CONFLICTED_HELD       2
#define ASSET_HOLDINGS_RED_OWNERSHIP_IGNORED     4
#define ASSET_HOLDINGS_RED_UNBACKED_COUNTS       8
#define ASSET_HOLDINGS_RED_SPENT_COUNTS          16
#define ASSET_HOLDINGS_RED_SUMS_WRAP             32
#define ASSET_HOLDINGS_RED_EMPTY_ROWS_COUNTED    64
#define ASSET_HOLDINGS_RED_NO_OWNERSHIP_EMPTY    128
#define ASSET_HOLDINGS_RED_CONFLICTED_SPENT      256
#define ASSET_HOLDINGS_RED_NO_DEBOUNCE           512
#define ASSET_HOLDINGS_RED_TXID_DEBOUNCE         1024
#define ASSET_HOLDINGS_RED_DEAD_PRUNES_CONFIRMED 2048
#define ASSET_HOLDINGS_RED_PRUNE_ANY_SOURCE      4096
#define ASSET_HOLDINGS_RED_SCRIPTLESS_PRUNED     8192
#define ASSET_HOLDINGS_RED_STACK_UNBOUNDED       16384
#define ASSET_HOLDINGS_RED_STACK_ANY_OUTPUT      32768
#define ASSET_HOLDINGS_RED_BAD_ENTRY_SKIPPED     65536
#define ASSET_HOLDINGS_RED_SETTLED_REWRITTEN     131072
#define ASSET_HOLDINGS_RED_OUTGOING_PERSISTED    262144
#define ASSET_HOLDINGS_RED_ASKED_EVERY_TIME      524288
#define ASSET_HOLDINGS_RED_WIRE_TRAILING         1048576
#define ASSET_HOLDINGS_RED_GATE_IGNORES_SCAN     2097152
#define ASSET_HOLDINGS_RED_QUANTITY_LOWERED      4194304

// BRWalletOutpointAssetState's answers, and the platform's own for a probe that failed.
#define BR_ASSET_STATE_SPENT         0
#define BR_ASSET_STATE_HELD          1
#define BR_ASSET_STATE_UNDETECTED    (-1)
#define BR_ASSET_STATE_CONFLICTED    (-2)
#define BR_ASSET_STATE_PROBE_ERROR   (-99)

// Consecutive passes that must find a row's transaction absent before a prune deletes the row.
#define BR_ASSET_ABSENCE_PASSES      2
// How long after asking the indexer about an output it may be asked again: one minute.
#define BR_ASSET_RECEIPT_RECHECK_MS  60000LL
// A transaction height at or past this is unconfirmed (TX_UNCONFIRMED, INT32_MAX). A plain literal.
#define BR_ASSET_TX_UNCONFIRMED      2147483647LL
// The prefix of an asset id given to an issuance the wallet has not named yet.
#define BR_ASSET_UNRESOLVED_PREFIX   "unresolved:"

#define BR_ASSET_ROW_WIRE_VERSION    1
#define BR_ASSET_ROW_WIRE_FIXED      38
#define BR_ASSET_ROW_WIRE_MAX        66083   // FIXED + 255 + 255 + 65535
#define BR_ASSET_TXID_LENGTH         64

typedef char _BRAssetHoldWireMaxIsTheSum[(BR_ASSET_ROW_WIRE_FIXED + 255 + 255 + 65535 == BR_ASSET_ROW_WIRE_MAX) ? 1 : -1];
typedef char _BRAssetHoldUnconfirmedIsInt32Max[(BR_ASSET_TX_UNCONFIRMED == INT32_MAX) ? 1 : -1];

// ---- the types -----------------------------------------------------------------------------------

// What every function here answers about itself. REFUSED is 0.
typedef enum {
    BR_ASSET_HOLDINGS_REFUSED = 0,       // a NULL where a value is needed, or bytes that are not a row
    BR_ASSET_HOLDINGS_OK = 1,
    BR_ASSET_HOLDINGS_CAPACITY = 2,      // a caller buffer cannot hold the answer; nothing was written
    BR_ASSET_HOLDINGS_NO_OWNERSHIP = 3   // BRAssetHeldBalances: the owned set is empty (Kotlin: null)
} BRAssetHoldingsStatus;

// Where a row came from (Android: AssetSource). Only NATIVE is told apart; BACKEND is the default.
typedef enum {
    BR_ASSET_SOURCE_BACKEND = 0,   // surfaced by a reconcile with an indexer
    BR_ASSET_SOURCE_NATIVE = 1     // detected from a transaction the native wallet held
} BRAssetSource;

// One script, as bytes.
typedef struct {
    const uint8_t *bytes;
    size_t len;
} BRAssetScript;

// One output the wallet keeps a record of (Android: UtxoEntity).
typedef struct {
    const char *txid;              // NUL-terminated; the caller keeps it alive
    int32_t vout;
    const uint8_t *script;         // scriptPubKey; scriptLen bytes
    size_t scriptLen;
    int64_t satoshis;
    int64_t blockHeight;           // the confirming height; 0 never confirmed
    int isAsset;                   // 0: not an asset row, which no function here sees
    const char *assetId;           // NULL: none
    int64_t assetQuantity;
    int spent;
    BRAssetSource source;
    BRAssetCredit credit;
} BRAssetRow;

// One asset's balance.
typedef struct {
    const char *assetId;           // the first counted row's pointer
    int64_t quantity;
    size_t utxoCount;              // counted rows whose quantity is above zero
} BRAssetHeldBalance;

// What to do with one row. KEEP is 0.
typedef enum {
    BR_ASSET_ROW_KEEP = 0,
    BR_ASSET_ROW_DELETE = 1,
    BR_ASSET_ROW_MARK_SPENT = 2,
    BR_ASSET_ROW_MARK_UNSPENT = 3
} BRAssetRowChange;

// One output of a transaction, for BRAssetClearDeadSend.
typedef struct {
    int32_t vout;
    const uint8_t *script;
    size_t scriptLen;
} BRAssetTxOutput;

// What the platform found when it asked the native wallet for a row's transaction outputs. FAILED is 0.
typedef enum {
    BR_ASSET_TX_LOOKUP_FAILED = 0,   // the call failed
    BR_ASSET_TX_NOT_HELD = 1,        // no such transaction (Kotlin: null)
    BR_ASSET_TX_NO_OUTPUTS = 2,      // an empty list
    BR_ASSET_TX_HELD = 3             // its outputs
} BRAssetTxLookup;

typedef enum {
    BR_ASSET_ABSENCE_NATIVE = 0,     // BRAssetPruneRemovedNativeRows
    BR_ASSET_ABSENCE_DEAD = 1        // BRAssetPruneDeadBroadcastRows
} BRAssetAbsenceKind;

// One outpoint's count of passes in a row that found its transaction absent.
typedef struct {
    BRAssetAbsenceKind kind;
    char txid[BR_ASSET_TXID_LENGTH + 1];
    int32_t vout;
    int32_t passes;
} BRAssetAbsence;

// The prunes' counts, kept by the caller from pass to pass (Kotlin: nativeAbsenceCounts). Process
// lifetime; an empty table is where a process starts.
typedef struct {
    BRAssetAbsence *entries;
    size_t count;
    size_t capacity;
} BRAssetAbsenceTable;

// The row values a decided credit settles to (Kotlin: SettledRow).
typedef struct {
    const char *assetId;
    int64_t quantity;
    BRAssetCredit credit;
} BRAssetSettledRow;

// An output the wallet detected as one of its own in an asset transaction.
typedef struct {
    const char *txid;
    int32_t vout;
    const uint8_t *script;
    size_t scriptLen;
    int64_t satoshis;
    int64_t blockHeight;
    const char *placeholderAssetId;     // the asset id the transaction is known by until it is named
    int64_t claimedQuantity;            // what its instructions claim for the output
    int isOutgoingUnconfirmed;          // BRAssetTxIsOutgoingUnconfirmed of its transaction
    const BRAssetOutputCredit *credit;  // what the wallet can say it holds; NULL is UNKNOWN
} BRAssetDetectedOutput;

typedef enum {
    BR_ASSET_PERSIST_NOTHING = 0,
    BR_ASSET_PERSIST_INSERT = 1,        // write `row` as a new row
    BR_ASSET_PERSIST_UPDATE = 2         // write `row` over the row the table holds
} BRAssetPersistAction;

typedef struct {
    BRAssetPersistAction action;
    BRAssetRow row;                     // INSERT / UPDATE: the row to write
    int unresolved;                     // its asset is not named yet (no id, or a placeholder)
} BRAssetPersist;

// When to ask the indexer about a row. NO is 0.
typedef enum {
    BR_ASSET_ASK_NO = 0,                // the row does not wait for an answer
    BR_ASSET_ASK_LATER = 1,             // asked less than BR_ASSET_RECEIPT_RECHECK_MS ago
    BR_ASSET_ASK_NOW = 2                // ask; the platform records the time
} BRAssetIndexerAsk;

// One entry of the indexer's reply, as the platform's JSON reader found it.
typedef struct {
    int isObject;                       // the entry is a JSON object
    const char *assetId;                // its "assetId" as text; NULL or "" when absent
    int countIsWhole;                   // its "count" is a JSON integer that fits int64
    int64_t count;
} BRAssetStackAnswerEntry;

// The indexer's reply for one output (GET /digiassets/txout/:txid/:vout), as the platform's JSON reader
// found it.
typedef struct {
    int hasError;                       // it has an "error" member
    const char *txid;                   // its "txid" as text; NULL or "" when absent
    int hasVout;                        // it has a "vout" member
    int32_t vout;                       // that member as an int (-1 when it is not a number)
    int hasAssets;                      // its "assets" is an array
    const BRAssetStackAnswerEntry *entries;
    size_t entryCount;
} BRAssetStackAnswer;

// What became of an indexer answer. NO_ANSWER is 0.
typedef enum {
    BR_ASSET_ACCEPT_NO_ANSWER = 0,      // it says nothing about the output: the row stays as it is
    BR_ASSET_ACCEPT_NOT_BELIEVED = 1,   // more than the transaction can deliver there: the row stays
    BR_ASSET_ACCEPT_SETTLED = 2         // write `row` to the row
} BRAssetAcceptVerdict;

typedef struct {
    BRAssetAcceptVerdict verdict;
    BRAssetOutputCredit credit;         // what the answer says the output holds
    BRAssetSettledRow row;              // SETTLED: the values the row settles to
    int labelsHistory;                  // SETTLED: the transaction is listed under row.assetId
} BRAssetStackAcceptance;

// ---- small rules ---------------------------------------------------------------------------------

// Is `assetId` a placeholder (or no id at all)? Kotlin: assetId == null || startsWith("unresolved:").
static inline int BRAssetIdIsUnresolved(const char *assetId)
{
    return ! assetId || strncmp(assetId, BR_ASSET_UNRESOLVED_PREFIX, sizeof(BR_ASSET_UNRESOLVED_PREFIX) - 1) == 0;
}

// Is a transaction the wallet lists our own send (it spent something of ours) that has not confirmed?
// Kotlin: isOutgoingUnconfirmedRow.
static inline int BRAssetTxIsOutgoingUnconfirmed(int64_t sent, int64_t blockHeight)
{
    return sent > 0 && blockHeight >= BR_ASSET_TX_UNCONFIRMED;
}

// The spent flag a native state sets: 1 with *spent written, or 0 to leave the flag as it is.
// Kotlin: decideAssetSpent.
static inline int BRAssetRowSpentDecide(int nativeState, int *spent)
{
    int value;

    if (nativeState == BR_ASSET_STATE_SPENT) value = 1;
    else if (nativeState == BR_ASSET_STATE_HELD) value = 0;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_CONFLICTED_SPENT)
    else if (nativeState == BR_ASSET_STATE_CONFLICTED) value = 1;
#endif
    else return 0;

    if (spent) *spent = value;
    return 1;
}

// May the prunes, and the ownership half of the reconcile, run? Kotlin: assetPruneGateOpen.
static inline int BRAssetPruneGateOpen(int syncedThisSession, int32_t peerCount, float progress, int walletLoaded,
                                       int64_t scanFrontier, int64_t headerTip)
{
    if (! syncedThisSession || peerCount <= 0 || ! (progress >= 1.0f) || ! walletLoaded) return 0;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_GATE_IGNORES_SCAN)
    (void)scanFrontier;
    return headerTip > 0;
#else
    // Both are above zero, so the difference fits.
    return scanFrontier > 0 && headerTip > 0 && headerTip - scanFrontier <= BR_CF_BEHIND_THRESHOLD;
#endif
}

// a + b, stopping at the end of the int64 range. Kotlin: AssetSums.add.
static inline int64_t _BRAssetHoldSaturatingAdd(int64_t a, int64_t b)
{
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_SUMS_WRAP)
    return (int64_t)((uint64_t)a + (uint64_t)b);
#else
    if (b > 0 && a > INT64_MAX - b) return INT64_MAX;
    if (b < 0 && a < INT64_MIN - b) return INT64_MIN;
    return a + b;
#endif
}

// Is the script one of `owned`?
static inline int _BRAssetHoldOwns(const BRAssetScript *owned, size_t ownedCount, const uint8_t *script, size_t scriptLen)
{
    size_t i;

    if (! owned) return 0;
    for (i = 0; i < ownedCount; i++) {
        if (owned[i].len != scriptLen) continue;
        if (scriptLen == 0 || (owned[i].bytes && memcmp(owned[i].bytes, script, scriptLen) == 0)) return 1;
    }
    return 0;
}

// ---- holding and counting -------------------------------------------------------------------------

// Does the wallet hold this output? Kotlin: isHeldForDisplay (its everConfirmed is not read there).
static inline int BRAssetHeldForDisplay(const uint8_t *script, size_t scriptLen, const BRAssetScript *owned,
                                        size_t ownedCount, BRAssetSource source, int nativeState)
{
    if (scriptLen == 0 || ! script) return 0;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_OWNERSHIP_IGNORED)
    (void)owned;
    (void)ownedCount;
#else
    if (! _BRAssetHoldOwns(owned, ownedCount, script, scriptLen)) return 0;
#endif

    if (nativeState == BR_ASSET_STATE_HELD) return 1;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_CONFLICTED_HELD)
    if (nativeState == BR_ASSET_STATE_CONFLICTED) return 1;
#endif
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_BACKEND_RESCUES)
    if (source == BR_ASSET_SOURCE_BACKEND &&
        (nativeState == BR_ASSET_STATE_UNDETECTED || nativeState == BR_ASSET_STATE_PROBE_ERROR)) return 1;
#else
    (void)source;
#endif
    return 0;
}

// Does this row count toward its asset's balance?
static inline int BRAssetRowCounts(const BRAssetRow *row, const BRAssetScript *owned, size_t ownedCount, int nativeState)
{
    if (! row || ! row->isAsset || ! row->assetId) return 0;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_SPENT_COUNTS)
    if (row->spent) return 0;
#endif
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_UNBACKED_COUNTS)
    if (! BRAssetCreditCounts(row->credit)) return 0;
#endif
    return BRAssetHeldForDisplay(row->script, row->scriptLen, owned, ownedCount, row->source, nativeState);
}

// The balance of every asset the rows hold. nativeStates[i] is row i's native state, one per row; only
// an unspent asset row that names an asset depends on it. OK with *count balances in out[0, *count), in the order
// their assets first count; NO_OWNERSHIP when ownedCount is 0; CAPACITY when more assets count than
// `cap` holds. Kotlin: computeHeldAssetBalancesImpl.
static inline BRAssetHoldingsStatus BRAssetHeldBalances(const BRAssetRow *rows, size_t rowCount, const int *nativeStates,
                                                        const BRAssetScript *owned, size_t ownedCount,
                                                        BRAssetHeldBalance *out, size_t cap, size_t *count)
{
    size_t i, j, n = 0;

    if (! count) return BR_ASSET_HOLDINGS_REFUSED;
    *count = 0;
    if (ownedCount > 0 && ! owned) return BR_ASSET_HOLDINGS_REFUSED;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_NO_OWNERSHIP_EMPTY)
    if (ownedCount == 0) return BR_ASSET_HOLDINGS_OK;
#else
    if (ownedCount == 0) return BR_ASSET_HOLDINGS_NO_OWNERSHIP;
#endif
    if (rowCount > 0 && (! rows || ! nativeStates)) return BR_ASSET_HOLDINGS_REFUSED;
    if (cap > 0 && ! out) return BR_ASSET_HOLDINGS_REFUSED;

    // First how many assets count, so that a balance `out` cannot hold writes nothing.
    for (i = 0; i < rowCount; i++) {
        if (! rows[i].isAsset || ! rows[i].assetId || ! BRAssetRowCounts(&rows[i], owned, ownedCount, nativeStates[i])) continue;
        for (j = 0; j < i; j++) {
            if (rows[j].isAsset && rows[j].assetId && strcmp(rows[j].assetId, rows[i].assetId) == 0 &&
                BRAssetRowCounts(&rows[j], owned, ownedCount, nativeStates[j])) break;
        }
        if (j == i) n++;
    }
    if (n > cap) return BR_ASSET_HOLDINGS_CAPACITY;

    n = 0;
    for (i = 0; i < rowCount; i++) {
        if (! rows[i].isAsset || ! rows[i].assetId || ! BRAssetRowCounts(&rows[i], owned, ownedCount, nativeStates[i])) continue;
        for (j = 0; j < n && strcmp(out[j].assetId, rows[i].assetId) != 0; j++) {}
        if (j == n) {
            out[n].assetId = rows[i].assetId;
            out[n].quantity = 0;
            out[n].utxoCount = 0;
            n++;
        }
        out[j].quantity = _BRAssetHoldSaturatingAdd(out[j].quantity, rows[i].assetQuantity);
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_EMPTY_ROWS_COUNTED)
        if (rows[i].assetQuantity >= 0) out[j].utxoCount++;
#else
        if (rows[i].assetQuantity > 0) out[j].utxoCount++;
#endif
    }
    *count = n;
    return BR_ASSET_HOLDINGS_OK;
}

// ---- reconcile and prunes -------------------------------------------------------------------------

// Mark every asset row at (txid, vout) not yet marked for deletion; how many were marked. The table's
// delete is by outpoint, among asset rows.
static inline size_t _BRAssetHoldDelete(const BRAssetRow *rows, size_t rowCount, const char *txid, int32_t vout,
                                        BRAssetRowChange *changes)
{
    size_t i, n = 0;

    for (i = 0; i < rowCount; i++) {
        if (! rows[i].isAsset || ! rows[i].txid || rows[i].vout != vout || changes[i] == BR_ASSET_ROW_DELETE) continue;
        if (strcmp(rows[i].txid, txid) != 0) continue;
        changes[i] = BR_ASSET_ROW_DELETE;
        n++;
    }
    return n;
}

// Delete row i's outpoint: every asset row at it (only row i itself when it has no txid).
static inline size_t _BRAssetHoldDeleteAt(const BRAssetRow *rows, size_t rowCount, size_t i, BRAssetRowChange *changes)
{
    if (rows[i].txid) return _BRAssetHoldDelete(rows, rowCount, rows[i].txid, rows[i].vout, changes);
    changes[i] = BR_ASSET_ROW_DELETE;
    return 1;
}

// What the reconcile does to each row: changes[i] for row i (KEEP, DELETE, MARK_SPENT, MARK_UNSPENT),
// *pruned the rows deleted. nativeStates[i] is read only for an asset row not deleted. With pruneUnowned
// 0 (the gate is shut) nothing is deleted. Kotlin: reconcileAssetRowsLocallyImpl, and with pruneUnowned
// 0 reconcileAssetSpentFromNative.
static inline BRAssetHoldingsStatus BRAssetReconcileRows(const BRAssetRow *rows, size_t rowCount, const BRAssetScript *owned,
                                                         size_t ownedCount, int pruneUnowned, const int *nativeStates,
                                                         BRAssetRowChange *changes, size_t *pruned)
{
    size_t i;
    int spent;

    if (! pruned) return BR_ASSET_HOLDINGS_REFUSED;
    *pruned = 0;
    if (rowCount > 0 && (! rows || ! nativeStates || ! changes)) return BR_ASSET_HOLDINGS_REFUSED;
    if (ownedCount > 0 && ! owned) return BR_ASSET_HOLDINGS_REFUSED;
    for (i = 0; i < rowCount; i++) changes[i] = BR_ASSET_ROW_KEEP;

    if (pruneUnowned && ownedCount > 0) {
        for (i = 0; i < rowCount; i++) {
            if (! rows[i].isAsset || changes[i] == BR_ASSET_ROW_DELETE) continue;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_SCRIPTLESS_PRUNED)
            if (rows[i].scriptLen == 0) continue;
#endif
            if (rows[i].scriptLen > 0 && ! rows[i].script) continue;
            if (_BRAssetHoldOwns(owned, ownedCount, rows[i].script, rows[i].scriptLen)) continue;
            *pruned += _BRAssetHoldDeleteAt(rows, rowCount, i, changes);
        }
    }

    for (i = 0; i < rowCount; i++) {
        if (! rows[i].isAsset || changes[i] == BR_ASSET_ROW_DELETE) continue;
        if (! BRAssetRowSpentDecide(nativeStates[i], &spent)) continue;
        if ((rows[i].spent != 0) != spent) changes[i] = spent ? BR_ASSET_ROW_MARK_SPENT : BR_ASSET_ROW_MARK_UNSPENT;
    }
    return BR_ASSET_HOLDINGS_OK;
}

// The rows of a dead send `txid` to delete, from the transaction's outputs read before it was removed:
// each asset row at an output whose script is not empty and is the wallet's own. changes[i] is DELETE or
// KEEP; *removed how many. Kotlin: clearDeadAssetSend.
static inline BRAssetHoldingsStatus BRAssetClearDeadSend(const BRAssetRow *rows, size_t rowCount, const char *txid,
                                                         const BRAssetTxOutput *outputs, size_t outputCount,
                                                         const BRAssetScript *owned, size_t ownedCount,
                                                         BRAssetRowChange *changes, size_t *removed)
{
    size_t i;

    if (! removed) return BR_ASSET_HOLDINGS_REFUSED;
    *removed = 0;
    if (! txid || (rowCount > 0 && (! rows || ! changes)) || (outputCount > 0 && ! outputs) ||
        (ownedCount > 0 && ! owned)) return BR_ASSET_HOLDINGS_REFUSED;
    for (i = 0; i < rowCount; i++) changes[i] = BR_ASSET_ROW_KEEP;

    for (i = 0; i < outputCount; i++) {
        if (outputs[i].scriptLen == 0 || ! outputs[i].script) continue;
        if (! _BRAssetHoldOwns(owned, ownedCount, outputs[i].script, outputs[i].scriptLen)) continue;
        *removed += _BRAssetHoldDelete(rows, rowCount, txid, outputs[i].vout, changes);
    }
    return BR_ASSET_HOLDINGS_OK;
}

static inline int _BRAssetHoldTxidWellFormed(const char *txid)
{
    return txid && strlen(txid) == BR_ASSET_TXID_LENGTH;
}

static inline int _BRAssetHoldAbsenceIs(const BRAssetAbsence *e, BRAssetAbsenceKind kind, const char *txid, int32_t vout)
{
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_TXID_DEBOUNCE)
    (void)vout;
    return e->kind == kind && memcmp(e->txid, txid, BR_ASSET_TXID_LENGTH) == 0;
#else
    return e->kind == kind && e->vout == vout && memcmp(e->txid, txid, BR_ASSET_TXID_LENGTH) == 0;
#endif
}

// The entry of (kind, txid, vout), or table->count.
static inline size_t _BRAssetHoldAbsenceFind(const BRAssetAbsenceTable *table, BRAssetAbsenceKind kind, const char *txid,
                                             int32_t vout)
{
    size_t i;

    for (i = 0; i < table->count; i++) if (_BRAssetHoldAbsenceIs(&table->entries[i], kind, txid, vout)) break;
    return i;
}

static inline void _BRAssetHoldAbsenceRemove(BRAssetAbsenceTable *table, size_t at)
{
    if (at >= table->count) return;
    table->entries[at] = table->entries[table->count - 1];
    table->count--;
}

// Is row i one this prune looks at? (A row whose txid is not 64 bytes is not.)
static inline int _BRAssetHoldPrunes(const BRAssetRow *row, BRAssetAbsenceKind kind)
{
    if (! row->isAsset || ! _BRAssetHoldTxidWellFormed(row->txid)) return 0;
    if (kind == BR_ASSET_ABSENCE_NATIVE) {
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_PRUNE_ANY_SOURCE)
        return 1;
#else
        return row->source == BR_ASSET_SOURCE_NATIVE;
#endif
    }
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_DEAD_PRUNES_CONFIRMED)
    return 1;
#else
    return row->blockHeight <= 0;
#endif
}

// Is the row's transaction absent, as this prune reads the lookup?
static inline int _BRAssetHoldGone(BRAssetAbsenceKind kind, BRAssetTxLookup lookup)
{
    if (kind == BR_ASSET_ABSENCE_NATIVE) return lookup == BR_ASSET_TX_NOT_HELD || lookup == BR_ASSET_TX_LOOKUP_FAILED;
    return lookup == BR_ASSET_TX_NOT_HELD || lookup == BR_ASSET_TX_NO_OUTPUTS;
}

static inline BRAssetHoldingsStatus _BRAssetHoldPrune(BRAssetAbsenceKind kind, const BRAssetRow *rows, size_t rowCount,
                                                      const BRAssetTxLookup *lookups, BRAssetAbsenceTable *table,
                                                      BRAssetRowChange *changes, size_t *removed)
{
    size_t i, j, at, need = 0;

    if (! removed) return BR_ASSET_HOLDINGS_REFUSED;
    *removed = 0;
    if (! table || (table->count > 0 && ! table->entries) || table->count > table->capacity) return BR_ASSET_HOLDINGS_REFUSED;
    if (rowCount > 0 && (! rows || ! lookups || ! changes)) return BR_ASSET_HOLDINGS_REFUSED;

    // Room for every count this pass may add: one per row looked at, found absent, and not yet counted.
    for (i = 0; i < rowCount; i++) {
        if (! _BRAssetHoldPrunes(&rows[i], kind) || ! _BRAssetHoldGone(kind, lookups[i])) continue;
        if (_BRAssetHoldAbsenceFind(table, kind, rows[i].txid, rows[i].vout) == table->count) need++;
    }
    if (need > table->capacity - table->count) return BR_ASSET_HOLDINGS_CAPACITY;
    if (need > 0 && ! table->entries) return BR_ASSET_HOLDINGS_REFUSED;

    for (i = 0; i < rowCount; i++) changes[i] = BR_ASSET_ROW_KEEP;
    for (i = 0; i < rowCount; i++) {
        if (! _BRAssetHoldPrunes(&rows[i], kind)) continue;
        at = _BRAssetHoldAbsenceFind(table, kind, rows[i].txid, rows[i].vout);
        if (! _BRAssetHoldGone(kind, lookups[i])) {
            _BRAssetHoldAbsenceRemove(table, at);
            continue;
        }
        if (at == table->count) {
            table->entries[at].kind = kind;
            memcpy(table->entries[at].txid, rows[i].txid, BR_ASSET_TXID_LENGTH);
            table->entries[at].txid[BR_ASSET_TXID_LENGTH] = '\0';
            table->entries[at].vout = rows[i].vout;
            table->entries[at].passes = 0;
            table->count++;
        }
        table->entries[at].passes++;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_NO_DEBOUNCE)
        if (table->entries[at].passes < BR_ASSET_ABSENCE_PASSES) continue;
#endif
        *removed += _BRAssetHoldDeleteAt(rows, rowCount, i, changes);
        _BRAssetHoldAbsenceRemove(table, at);
    }

    if (kind == BR_ASSET_ABSENCE_NATIVE) {
        // Keep only the counts of the NATIVE rows this pass looked at.
        for (j = table->count; j > 0; j--) {
            for (i = 0; i < rowCount; i++) {
                if (_BRAssetHoldPrunes(&rows[i], kind) &&
                    _BRAssetHoldAbsenceIs(&table->entries[j - 1], kind, rows[i].txid, rows[i].vout)) break;
            }
            if (i == rowCount) _BRAssetHoldAbsenceRemove(table, j - 1);
        }
    }
    return BR_ASSET_HOLDINGS_OK;
}

// One pass of the prune of NATIVE rows whose transaction the native wallet no longer holds. lookups[i]
// is what the platform found for row i's transaction; it is read only for a NATIVE asset row with a txid
// of 64 bytes. changes[i] is DELETE or KEEP; *removed how many; `table` carries the counts to the next
// pass. Run it only while BRAssetPruneGateOpen. Kotlin: pruneRemovedNativeAssetRowsImpl.
static inline BRAssetHoldingsStatus BRAssetPruneRemovedNativeRows(const BRAssetRow *rows, size_t rowCount,
                                                                  const BRAssetTxLookup *lookups, BRAssetAbsenceTable *table,
                                                                  BRAssetRowChange *changes, size_t *removed)
{
    return _BRAssetHoldPrune(BR_ASSET_ABSENCE_NATIVE, rows, rowCount, lookups, table, changes, removed);
}

// One pass of the prune of rows of a broadcast that never confirmed and that the wallet has dropped,
// whatever their provenance. As BRAssetPruneRemovedNativeRows otherwise; lookups[i] is read only for an
// asset row with a txid of 64 bytes and a height of 0 or less. Kotlin: pruneDeadBroadcastRowsImpl.
static inline BRAssetHoldingsStatus BRAssetPruneDeadBroadcastRows(const BRAssetRow *rows, size_t rowCount,
                                                                  const BRAssetTxLookup *lookups, BRAssetAbsenceTable *table,
                                                                  BRAssetRowChange *changes, size_t *removed)
{
    return _BRAssetHoldPrune(BR_ASSET_ABSENCE_DEAD, rows, rowCount, lookups, table, changes, removed);
}

// ---- detection and the indexer --------------------------------------------------------------------

// The row values `credit` settles to, with `source` as the credit of a decided holding: 1 with *out
// written, or 0 for an UNKNOWN credit (or a NULL). Kotlin: settledRow.
static inline int BRAssetSettledRowOf(const BRAssetOutputCredit *credit, const char *placeholderAssetId,
                                      BRAssetCredit source, BRAssetSettledRow *out)
{
    if (! credit || ! out) return 0;
    if (credit->kind == BR_ASSET_OUTPUT_HOLDS) {
        if (credit->hasUnits) {
            out->assetId = credit->assetId;
            out->quantity = credit->count;
        }
        else {
            out->assetId = credit->label ? credit->label : placeholderAssetId;
            out->quantity = 0;
        }
        out->credit = source;
        return 1;
    }
    if (credit->kind == BR_ASSET_OUTPUT_MIXED) {
        out->assetId = placeholderAssetId;
        out->quantity = 0;
        out->credit = BR_ASSET_CREDIT_MIXED;
        return 1;
    }
    return 0;
}

// The write for a detected output. `existing` is the row the table holds at its outpoint, or NULL
// (a row that is not an asset row is none). Kotlin: persistDetectedAssetOutput.
static inline BRAssetPersist BRAssetPersistDetectedOutput(const BRAssetDetectedOutput *output, const BRAssetRow *existing)
{
    BRAssetPersist r;
    BRAssetSettledRow settled;
    int decided;

    memset(&r, 0, sizeof(r));
    if (! output || ! output->txid || ! output->placeholderAssetId) return r;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_OUTGOING_PERSISTED)
    if (output->isOutgoingUnconfirmed) return r;
#endif
    decided = BRAssetSettledRowOf(output->credit, output->placeholderAssetId, BR_ASSET_CREDIT_BACKED, &settled);

    if (existing && existing->isAsset) {
        r.action = BR_ASSET_PERSIST_UPDATE;
        r.row = *existing;
        r.row.source = BR_ASSET_SOURCE_NATIVE;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_SETTLED_REWRITTEN)
        if (1) {
#else
        if (! BRAssetCreditIsSettled(existing->credit)) {
#endif
            if (decided) {
                r.row.assetId = settled.assetId;
                r.row.assetQuantity = settled.quantity;
                r.row.credit = settled.credit;
            }
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_QUANTITY_LOWERED)
            else r.row.assetQuantity = output->claimedQuantity;
#else
            else if (output->claimedQuantity > existing->assetQuantity) r.row.assetQuantity = output->claimedQuantity;
#endif
        }
        r.unresolved = BRAssetIdIsUnresolved(r.row.assetId);
        return r;
    }

    r.action = BR_ASSET_PERSIST_INSERT;
    r.row.txid = output->txid;
    r.row.vout = output->vout;
    r.row.script = output->script;
    r.row.scriptLen = output->scriptLen;
    r.row.satoshis = output->satoshis;
    r.row.blockHeight = output->blockHeight;
    r.row.isAsset = 1;
    r.row.assetId = decided ? settled.assetId : output->placeholderAssetId;
    r.row.assetQuantity = decided ? settled.quantity : output->claimedQuantity;
    r.row.spent = 0;
    r.row.source = BR_ASSET_SOURCE_NATIVE;
    r.row.credit = decided ? settled.credit : BR_ASSET_CREDIT_UNCHECKED;
    r.unresolved = BRAssetIdIsUnresolved(r.row.assetId);
    return r;
}

// Whether to ask the indexer about `row` (the asset row at the outpoint, or NULL) now. hasLastAsked and
// lastAskedMs: when it was last asked and has not settled since. Kotlin: settleFromIndexer, up to the
// lookup.
static inline BRAssetIndexerAsk BRAssetIndexerAskDecide(const BRAssetRow *row, int hasLastAsked, int64_t lastAskedMs,
                                                        int64_t nowMs)
{
    if (! row || ! row->isAsset || row->spent || BRAssetCreditIsSettled(row->credit)) return BR_ASSET_ASK_NO;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_ASKED_EVERY_TIME)
    (void)hasLastAsked;
    (void)lastAskedMs;
    (void)nowMs;
#else
    if (hasLastAsked) {
        uint64_t since;

        // nowMs - lastAskedMs as a Long does it: wrapping, then read as signed.
        since = (uint64_t)nowMs - (uint64_t)lastAskedMs;
        if (since >= ((uint64_t)1 << 63) || since < (uint64_t)BR_ASSET_RECEIPT_RECHECK_MS) return BR_ASSET_ASK_LATER;
    }
#endif
    return BR_ASSET_ASK_NOW;
}

static inline int _BRAssetHoldAsciiLower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

// a and b equal with ASCII letters' case ignored.
static inline int _BRAssetHoldSameIgnoringCase(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        if (_BRAssetHoldAsciiLower((unsigned char)*a) != _BRAssetHoldAsciiLower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

// Is this entry one an answer may carry?
static inline int _BRAssetHoldEntryWellFormed(const BRAssetStackAnswerEntry *e)
{
    return e->isObject && e->assetId && e->assetId[0] && strcmp(e->assetId, "null") != 0 && e->countIsWhole && e->count >= 0;
}

// The indexer's reply for output (askedTxid, askedVout): OK with *lookup FOUND and the stack in out[0,
// *count), front first, or *lookup UNAVAILABLE (no answer) and *count 0; CAPACITY when a FOUND stack has
// more entries than `cap`. The ids are the answer's pointers. Kotlin: DigiScopeAssetParsing.txOutStack.
static inline BRAssetHoldingsStatus BRAssetStackAnswerRead(const BRAssetStackAnswer *answer, const char *askedTxid,
                                                           int32_t askedVout, BRAssetUnits *out, size_t cap, size_t *count,
                                                           BRAssetStackLookup *lookup)
{
    size_t i, n = 0;

    if (! count || ! lookup) return BR_ASSET_HOLDINGS_REFUSED;
    *count = 0;
    *lookup = BR_ASSET_STACK_UNAVAILABLE;
    if (! answer || ! askedTxid || (answer->entryCount > 0 && ! answer->entries) || (cap > 0 && ! out)) {
        return BR_ASSET_HOLDINGS_REFUSED;
    }

    if (answer->hasError) return BR_ASSET_HOLDINGS_OK;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_STACK_ANY_OUTPUT)
    if (! _BRAssetHoldSameIgnoringCase(answer->txid ? answer->txid : "", askedTxid)) return BR_ASSET_HOLDINGS_OK;
    if (! answer->hasVout || answer->vout != askedVout) return BR_ASSET_HOLDINGS_OK;
#else
    (void)askedVout;
#endif
    if (! answer->hasAssets) return BR_ASSET_HOLDINGS_OK;

    for (i = 0; i < answer->entryCount; i++) {
        if (_BRAssetHoldEntryWellFormed(&answer->entries[i])) n++;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_BAD_ENTRY_SKIPPED)
        else return BR_ASSET_HOLDINGS_OK;
#endif
    }
    if (n > cap) return BR_ASSET_HOLDINGS_CAPACITY;

    n = 0;
    for (i = 0; i < answer->entryCount; i++) {
        if (! _BRAssetHoldEntryWellFormed(&answer->entries[i])) continue;
        out[n].assetId = answer->entries[i].assetId;
        out[n].count = answer->entries[i].count;
        out[n].ruleFree = 0;
        n++;
    }
    *count = n;
    *lookup = BR_ASSET_STACK_FOUND;
    return BR_ASSET_HOLDINGS_OK;
}

// The indexer's not-found reply: NOT_UNSPENT only when its body parsed as a JSON object whose "unspent"
// is the boolean false; UNAVAILABLE otherwise (a blank body, another page). Kotlin: DigiScopeAssetParsing.notFound.
static inline BRAssetStackLookup BRAssetStackNotFoundRead(int bodyIsObject, int unspentIsFalse)
{
    return (bodyIsObject && unspentIsFalse) ? BR_ASSET_STACK_NOT_UNSPENT : BR_ASSET_STACK_UNAVAILABLE;
}

// What an indexer's answer for an output settles, given the most the transaction's instructions can
// deliver there (BRAssetMaxDeliverable). Kotlin: settleFromIndexer, after the lookup.
static inline BRAssetStackAcceptance BRAssetStackAnswerAccept(BRAssetStackLookup lookup, const BRAssetUnits *entries,
                                                              size_t entryCount, BRAssetDeliverable bound,
                                                              const char *placeholderAssetId)
{
    BRAssetStackAcceptance r;
    int64_t reported;

    memset(&r, 0, sizeof(r));
    if (! placeholderAssetId) return r;
    if (! BRAssetCreditFromIndexer(lookup, entries, entryCount, &r.credit)) return r;

    reported = (r.credit.kind == BR_ASSET_OUTPUT_HOLDS && r.credit.hasUnits) ? r.credit.count : 0;
#if !(ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_STACK_UNBOUNDED)
    if (! bound.unbounded && reported > bound.max) {
        r.verdict = BR_ASSET_ACCEPT_NOT_BELIEVED;
        return r;
    }
#else
    (void)bound;
    (void)reported;
#endif
    if (! BRAssetSettledRowOf(&r.credit, placeholderAssetId, BR_ASSET_CREDIT_VERIFIED, &r.row)) return r;
    r.verdict = BR_ASSET_ACCEPT_SETTLED;
    r.labelsHistory = BRAssetCreditCounts(r.row.credit) && r.row.quantity > 0 && ! BRAssetIdIsUnresolved(r.row.assetId);
    return r;
}

// ---- the stored form ------------------------------------------------------------------------------

static inline void _BRAssetHoldPutLE(uint8_t *p, uint64_t v, int bytes)
{
    int i;

    for (i = 0; i < bytes; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static inline uint64_t _BRAssetHoldGetLE(const uint8_t *p, int bytes)
{
    uint64_t v = 0;
    int i;

    for (i = bytes - 1; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

// Two's complement bits to int64, with no implementation-defined conversion.
static inline int64_t _BRAssetHoldSigned64(uint64_t u)
{
    return (u >> 63) ? -(int64_t)(~u) - 1 : (int64_t)u;
}

static inline int32_t _BRAssetHoldSigned32(uint32_t u)
{
    return (u >> 31) ? -(int32_t)(~u) - 1 : (int32_t)u;
}

// The bytes BRAssetRowEncode writes for `row`, or 0 when the row cannot be stored: no txid, a txid or
// asset id longer than 255 bytes, a script longer than 65535 bytes or with no bytes, or a source or
// credit this header does not define.
static inline size_t BRAssetRowWireLength(const BRAssetRow *row)
{
    size_t t, a;

    if (! row || ! row->txid || (row->scriptLen > 0 && ! row->script)) return 0;
    if ((unsigned)row->source > BR_ASSET_SOURCE_NATIVE || (unsigned)row->credit > BR_ASSET_CREDIT_MIXED) return 0;
    t = strlen(row->txid);
    a = row->assetId ? strlen(row->assetId) : 0;
    if (t > 255 || a > 255 || row->scriptLen > 65535) return 0;
    return BR_ASSET_ROW_WIRE_FIXED + t + a + row->scriptLen;
}

// `row` in its stored form, into buf[0, cap): OK with *written bytes, REFUSED when it cannot be stored
// (BRAssetRowWireLength), CAPACITY when it does not fit.
static inline BRAssetHoldingsStatus BRAssetRowEncode(const BRAssetRow *row, uint8_t *buf, size_t cap, size_t *written)
{
    size_t len, t, a, at;

    if (! written) return BR_ASSET_HOLDINGS_REFUSED;
    *written = 0;
    len = BRAssetRowWireLength(row);
    if (len == 0) return BR_ASSET_HOLDINGS_REFUSED;
    if (len > cap) return BR_ASSET_HOLDINGS_CAPACITY;
    if (! buf) return BR_ASSET_HOLDINGS_REFUSED;

    t = strlen(row->txid);
    a = row->assetId ? strlen(row->assetId) : 0;
    buf[0] = BR_ASSET_ROW_WIRE_VERSION;
    buf[1] = (uint8_t)((row->isAsset ? 1 : 0) | (row->spent ? 2 : 0) | (row->assetId ? 4 : 0));
    buf[2] = (uint8_t)row->source;
    buf[3] = (uint8_t)row->credit;
    _BRAssetHoldPutLE(buf + 4, (uint32_t)row->vout, 4);
    _BRAssetHoldPutLE(buf + 8, (uint64_t)row->satoshis, 8);
    _BRAssetHoldPutLE(buf + 16, (uint64_t)row->blockHeight, 8);
    _BRAssetHoldPutLE(buf + 24, (uint64_t)row->assetQuantity, 8);
    at = 32;
    buf[at++] = (uint8_t)t;
    memcpy(buf + at, row->txid, t);
    at += t;
    buf[at++] = 0;
    buf[at++] = (uint8_t)a;
    if (a > 0) memcpy(buf + at, row->assetId, a);
    at += a;
    buf[at++] = 0;
    _BRAssetHoldPutLE(buf + at, (uint64_t)row->scriptLen, 2);
    at += 2;
    if (row->scriptLen > 0) memcpy(buf + at, row->script, row->scriptLen);
    at += row->scriptLen;
    *written = at;
    return BR_ASSET_HOLDINGS_OK;
}

// A stored row from buf[0, len), which must be exactly one: OK with *row pointing into `buf`, or
// REFUSED (and *row zeroed).
static inline BRAssetHoldingsStatus BRAssetRowDecode(const uint8_t *buf, size_t len, BRAssetRow *row)
{
    size_t t, a, s, at;

    if (! row) return BR_ASSET_HOLDINGS_REFUSED;
    memset(row, 0, sizeof(*row));
    if (! buf || len < BR_ASSET_ROW_WIRE_FIXED) return BR_ASSET_HOLDINGS_REFUSED;
    if (buf[0] != BR_ASSET_ROW_WIRE_VERSION || (buf[1] & ~7u) != 0 || buf[2] > BR_ASSET_SOURCE_NATIVE ||
        buf[3] > BR_ASSET_CREDIT_MIXED) return BR_ASSET_HOLDINGS_REFUSED;

    at = 32;
    t = buf[at++];
    if (len < BR_ASSET_ROW_WIRE_FIXED + t) return BR_ASSET_HOLDINGS_REFUSED;
    if (memchr(buf + at, 0, t) || buf[at + t] != 0) return BR_ASSET_HOLDINGS_REFUSED;
    at += t + 1;
    a = buf[at++];
    if (len < BR_ASSET_ROW_WIRE_FIXED + t + a) return BR_ASSET_HOLDINGS_REFUSED;
    if ((a > 0 && ! (buf[1] & 4)) || memchr(buf + at, 0, a) || buf[at + a] != 0) return BR_ASSET_HOLDINGS_REFUSED;
    at += a + 1;
    s = (size_t)_BRAssetHoldGetLE(buf + at, 2);
    at += 2;
#if (ASSET_HOLDINGS_UNFIXED & ASSET_HOLDINGS_RED_WIRE_TRAILING)
    if (len < at + s) return BR_ASSET_HOLDINGS_REFUSED;
#else
    if (len != at + s) return BR_ASSET_HOLDINGS_REFUSED;
#endif

    row->isAsset = (buf[1] & 1) != 0;
    row->spent = (buf[1] & 2) != 0;
    row->source = (BRAssetSource)buf[2];
    row->credit = (BRAssetCredit)buf[3];
    row->vout = _BRAssetHoldSigned32((uint32_t)_BRAssetHoldGetLE(buf + 4, 4));
    row->satoshis = _BRAssetHoldSigned64(_BRAssetHoldGetLE(buf + 8, 8));
    row->blockHeight = _BRAssetHoldSigned64(_BRAssetHoldGetLE(buf + 16, 8));
    row->assetQuantity = _BRAssetHoldSigned64(_BRAssetHoldGetLE(buf + 24, 8));
    row->txid = (const char *)(buf + 33);
    row->assetId = (buf[1] & 4) ? (const char *)(buf + 33 + t + 2) : NULL;
    row->scriptLen = s;
    row->script = s > 0 ? buf + at : NULL;
    return BR_ASSET_HOLDINGS_OK;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetHoldings_h
