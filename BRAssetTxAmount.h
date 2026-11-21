//
//  BRAssetTxAmount.h
//
//  What one DigiAsset transaction moved, for its row in the activity list and its details: the units and
//  the asset they resolve to. Until 2026-11 this lived only in Android's Kotlin (v4.1.4,
//  core/.../asset/AssetManager.kt: assetTokenCountForTx 2886-2922, receivedBackedUnits 2925-2928 and the
//  count and id halves of assetAmountForTx 2936-2950; core/.../db/dao/UtxoDao.kt: getResolvedAssetIdForTx
//  62-63 and getAssetUtxosForTxNow 116-117; AssetSums.kt add 14-18; AssetTxQuantity.kt forOutput 34-56).
//  It moves here unchanged: every input the Kotlin answers gets the same answer here.
//
//  THE RULES (BRAssetTxActivityAmount):
//    - THE DIRECTION is the platform's: a send when the transaction's row amount is below zero (Android's
//      WalletViewModel.kt:926, `tx.amount < 0`; the row amount is BRTxRows.h's).
//    - THE ROWS OF THE TRANSACTION are the rows given that are asset rows and whose txid is `txid`, byte
//      for byte (Kotlin: `WHERE is_asset = 1 AND txid = :txid`), spent or not, owned or not, in the order
//      given.
//    - A RECEIVE: the stored quantities of the transaction's rows whose credit counts (BACKED or VERIFIED,
//      BRAssetCreditCounts), summed with the sum stopping at the end of the int64 range (INT64_MAX, or
//      INT64_MIN for negative quantities) and never wrapping (Kotlin: AssetSums.saturating). Never what
//      the instructions claim: the sender writes the instructions, and a received output is counted only
//      once its rows are backed or verified. The transaction is not read.
//    - A SEND: the transaction is the wallet's copy of `txid` (NULL: the wallet has none). Its carrier is
//      the one carrier rule's, read by the core's decoder (BRAssetHoldCarrierOf, BRAssetHold.h: Kotlin's
//      assetCarrierOfLines). For every output that is not OP_RETURN (a script whose first byte is 0x6a)
//      and is not the wallet's own, what the instructions assign it (BRAssetClaimForOutput, BRAssetDetect.h:
//      Kotlin's AssetTxQuantity.forOutput, overflow-checked: an amount or index below zero, or a sum past
//      INT64_MAX, assigns 0; percent and destroying instructions are left out; an issuance assigns its whole
//      amount to the first output that is not OP_RETURN), summed with the same stopping sum. An output is
//      the wallet's own when the owned set is not empty and holds its script; with an empty owned set
//      (Kotlin: buildOwnedScriptHexes failed) no output is. No transaction, no outputs, a transaction the
//      reader cannot read, no carrier, or a carrier that is undecided or not classified: no amount.
//    - THE AMOUNT is that total when it is above zero; otherwise there is none (Kotlin: null, and the row
//      shows its DGB).
//    - THE ASSET (Kotlin: getResolvedAssetIdForTx, `asset_id NOT LIKE 'unresolved:%' AND asset_credit IN
//      ('BACKED', 'VERIFIED') LIMIT 1`): the asset id of the first of the transaction's rows that names one
//      that is not a placeholder (one starting "unresolved:", ASCII case ignored, as SQLite's LIKE ignores
//      it) and whose credit counts; NULL when none does. The same for a receive and a send (a send's are
//      the rows of its own change). SQLite's LIMIT 1 without ORDER BY takes the table's order, which for
//      Android's table is the order the rows were written: the platform passes its rows in the order it
//      stored them.
//
//  Display only: the answer is an amount on a screen, never a balance, a spend or the held set. The
//  platform words it (the asset's symbol or name from its metadata, the quantity at the core's
//  divisibility); this header chooses no words.
//
//  Answers that are not decided are never an amount: REFUSED is 0, so a struct nobody filled reads as
//  no amount. REFUSED: a NULL txid, rows NULL with a count above zero, or (a send) a transaction whose
//  hash is not `txid`. The answer's assetId is a pointer into the caller's rows. No allocation, no
//  wallet, no network, no clock, no I/O. Header-only, static inline; its includes are libc and the core
//  headers whose types or functions it uses. A program that calls it links BRDigiAsset.c (the one
//  carrier rule) and what BRAssetHold.h links. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_tx_amount_kat in the Android repo): ASSET_TX_AMOUNT_UNFIXED, tested by
//  VALUE as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is
//  what ships.
//    1     ASSET_TX_AMOUNT_RED_UNBACKED_COUNTS     a receive counts a row whatever its credit.
//    2     ASSET_TX_AMOUNT_RED_SPENT_SKIPPED       a receive leaves rows flagged spent out.
//    4     ASSET_TX_AMOUNT_RED_SUMS_WRAP           a sum past the int64 range wraps.
//    8     ASSET_TX_AMOUNT_RED_OWNED_SENT          a send counts the wallet's own outputs too.
//    16    ASSET_TX_AMOUNT_RED_EMPTY_OWNED_NOTHING a send with an empty owned set counts nothing.
//    32    ASSET_TX_AMOUNT_RED_DATA_OUTPUT_SENT    a send counts an OP_RETURN output.
//    64    ASSET_TX_AMOUNT_RED_PLACEHOLDER_NAMED   a placeholder is the transaction's asset.
//    128   ASSET_TX_AMOUNT_RED_UNCOUNTED_NAMED     a row whose credit does not count names the asset.
//    256   ASSET_TX_AMOUNT_RED_BURN_DROPPED        a send reads the earlier quantity rule (a burn delivers nothing).
//    512   ASSET_TX_AMOUNT_RED_PLACEHOLDER_CASE    a placeholder is told by its case ("UNRESOLVED:" names the asset).
//    1024  ASSET_TX_AMOUNT_RED_RECEIVE_CLAIMED     a receive counts what the instructions assign the wallet's outputs.
//    2048  ASSET_TX_AMOUNT_RED_ANY_TXID            a row of another transaction counts and names.
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

#ifndef BRAssetTxAmount_h
#define BRAssetTxAmount_h

#include "BRAssetAllocate.h"   // BRAssetCreditCounts
#include "BRAssetDecode.h"     // BRAssetHeader, BR_ASSET_MAX_INSTRUCTIONS, BR_ASSET_SCRIPT_ASSET
#include "BRAssetDetect.h"     // BRAssetClaimForOutput (Kotlin: AssetTxQuantity.forOutput)
#include "BRAssetHold.h"       // BRAssetHoldCarrierOf (the one carrier rule, the decoder's reading)
#include "BRAssetHoldings.h"   // BRAssetRow, BRAssetScript, BR_ASSET_UNRESOLVED_PREFIX, BR_ASSET_TXID_LENGTH
#include "BRAssetQuantity.h"   // BRAssetTransferInstruction, BRAssetQuantityForOutput (the comparison arm's)
#include "BRTransaction.h"     // BRTransaction, BRTxOutput (read only)
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_TX_AMOUNT_UNFIXED
#define ASSET_TX_AMOUNT_UNFIXED 0
#endif

#define ASSET_TX_AMOUNT_RED_UNBACKED_COUNTS     1
#define ASSET_TX_AMOUNT_RED_SPENT_SKIPPED       2
#define ASSET_TX_AMOUNT_RED_SUMS_WRAP           4
#define ASSET_TX_AMOUNT_RED_OWNED_SENT          8
#define ASSET_TX_AMOUNT_RED_EMPTY_OWNED_NOTHING 16
#define ASSET_TX_AMOUNT_RED_DATA_OUTPUT_SENT    32
#define ASSET_TX_AMOUNT_RED_PLACEHOLDER_NAMED   64
#define ASSET_TX_AMOUNT_RED_UNCOUNTED_NAMED     128
#define ASSET_TX_AMOUNT_RED_BURN_DROPPED        256
#define ASSET_TX_AMOUNT_RED_PLACEHOLDER_CASE    512
#define ASSET_TX_AMOUNT_RED_RECEIVE_CLAIMED     1024
#define ASSET_TX_AMOUNT_RED_ANY_TXID            2048

// What BRAssetTxActivityAmount answers. REFUSED is 0.
typedef enum {
    BR_ASSET_TX_AMOUNT_REFUSED = 0,   // a NULL where a value is needed, or a send's transaction that is not txid's
    BR_ASSET_TX_AMOUNT_NONE = 1,      // no amount: the row shows its DGB (Kotlin: null)
    BR_ASSET_TX_AMOUNT_OK = 2         // units above zero
} BRAssetTxAmountStatus;

// One transaction's asset amount.
typedef struct {
    BRAssetTxAmountStatus status;
    int64_t units;                    // OK: above zero; otherwise 0
    const char *assetId;              // OK: THE ASSET, a row's own pointer, or NULL when none resolves; otherwise NULL
} BRAssetTxAmount;

// a + b, stopping at the end of the int64 range. Kotlin: AssetSums.add.
static inline int64_t _BRAssetTxAmountAdd(int64_t a, int64_t b)
{
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_SUMS_WRAP)
    return (int64_t)((uint64_t)a + (uint64_t)b);
#else
    if (b > 0 && a > INT64_MAX - b) return INT64_MAX;
    if (b < 0 && a < INT64_MIN - b) return INT64_MIN;
    return a + b;
#endif
}

// Is the row one of the transaction's? Kotlin: `is_asset = 1 AND txid = :txid`.
static inline int _BRAssetTxAmountRowOf(const BRAssetRow *row, const char *txid)
{
    if (! row->isAsset) return 0;
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_ANY_TXID)
    (void)txid;
    return 1;
#else
    return row->txid != NULL && strcmp(row->txid, txid) == 0;
#endif
}

// Is the id a placeholder? Kotlin's SQL: `asset_id NOT LIKE 'unresolved:%'`, which ignores ASCII case.
static inline int _BRAssetTxAmountIsPlaceholder(const char *assetId)
{
    static const char prefix[] = BR_ASSET_UNRESOLVED_PREFIX;
    size_t i;

#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_PLACEHOLDER_NAMED)
    (void)prefix;
    (void)i;
    (void)assetId;
    return 0;
#else
    for (i = 0; i + 1 < sizeof(prefix); i++) {
        int c = (unsigned char)assetId[i];

#if !(ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_PLACEHOLDER_CASE)
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
#endif
        if (c != prefix[i]) return 0;   // a shorter id ends at its NUL, which is no prefix character
    }
    return 1;
#endif
}

// THE ASSET: the first of the transaction's rows naming an id that is not a placeholder and whose credit
// counts; NULL when none does. Kotlin: UtxoDao.getResolvedAssetIdForTx.
static inline const char *_BRAssetTxAmountAssetOf(const char *txid, const BRAssetRow *rows, size_t rowCount)
{
    size_t i;

    for (i = 0; i < rowCount; i++) {
        const BRAssetRow *r = &rows[i];

        if (! _BRAssetTxAmountRowOf(r, txid) || ! r->assetId) continue;
        if (_BRAssetTxAmountIsPlaceholder(r->assetId)) continue;
#if !(ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_UNCOUNTED_NAMED)
        if (! BRAssetCreditCounts(r->credit)) continue;
#endif
        return r->assetId;
    }
    return NULL;
}

// Is the script one of `owned`? An empty owned set owns nothing.
static inline int _BRAssetTxAmountOwns(const BRAssetScript *owned, size_t ownedCount, const BRTxOutput *o)
{
    size_t i;

    if (! owned) return 0;
    for (i = 0; i < ownedCount; i++) {
        if (owned[i].len != o->scriptLen) continue;
        if (o->scriptLen == 0 || (owned[i].bytes && memcmp(owned[i].bytes, o->script, o->scriptLen) == 0)) return 1;
    }
    return 0;
}

// Is the output OP_RETURN, as the Kotlin tells one: a script that is not empty and starts 0x6a?
static inline int _BRAssetTxAmountIsData(const BRTxOutput *o)
{
    return o->scriptLen > 0 && o->script != NULL && o->script[0] == 0x6a;
}

// What the instructions assign `vout`. Kotlin: AssetTxQuantity.forOutput.
static inline int64_t _BRAssetTxAmountAssigned(const BRAssetHeader *h, const BRAssetTransferInstruction *insts,
                                               size_t instCount, int32_t vout, int hasFirst, int32_t first)
{
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_BURN_DROPPED)
    int64_t out = 0;

    if (BRAssetQuantityForOutput(h->operation, h->totalQuantity, vout, hasFirst ? first : -1, insts, instCount, &out) !=
        BRAssetQuantityOK) return 0;
    return out;
#else
    return BRAssetClaimForOutput(h->operation, h->hasTotalQuantity, h->totalQuantity, insts, instCount, vout, hasFirst, first);
#endif
}

// The units a send moved: what the carrier assigns the outputs the wallet does not own (`receive` 0), or,
// in the comparison arm only, the ones it owns (`receive` 1). Kotlin: assetTokenCountForTx's send half.
static inline int64_t _BRAssetTxAmountCarried(const BRTransaction *tx, const BRAssetScript *owned, size_t ownedCount,
                                              int receive)
{
    BRAssetHeader h;
    BRAssetTransferInstruction insts[BR_ASSET_MAX_INSTRUCTIONS];
    size_t j, at = 0, n;
    int32_t first = 0;
    int hasFirst = 0;
    int64_t total = 0;

    if (! tx || tx->outCount == 0) return 0;
    memset(&h, 0, sizeof(h));
    if (BRAssetHoldCarrierOf(tx, &at, &h, insts) != BR_ASSET_CARRIER_FOUND) return 0;
    if (h.kind != BR_ASSET_SCRIPT_ASSET) return 0;   // undecided, or not classified: nothing is assigned
    n = (h.instructionCount < BR_ASSET_MAX_INSTRUCTIONS) ? h.instructionCount : BR_ASSET_MAX_INSTRUCTIONS;

    for (j = 0; j < tx->outCount; j++) {
        if (! _BRAssetTxAmountIsData(&tx->outputs[j])) {
            hasFirst = 1;
            first = (int32_t)j;
            break;
        }
    }
    for (j = 0; j < tx->outCount; j++) {
        const BRTxOutput *o = &tx->outputs[j];
        int isOwned, wanted;

#if !(ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_DATA_OUTPUT_SENT)
        if (_BRAssetTxAmountIsData(o)) continue;
#endif
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_EMPTY_OWNED_NOTHING)
        if (ownedCount == 0) return 0;
#endif
        isOwned = ownedCount > 0 && _BRAssetTxAmountOwns(owned, ownedCount, o);
        wanted = receive ? isOwned : ! isOwned;
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_OWNED_SENT)
        if (! receive) wanted = 1;
#endif
        if (wanted) total = _BRAssetTxAmountAdd(total, _BRAssetTxAmountAssigned(&h, insts, n, (int32_t)j, hasFirst, first));
    }
    return total;
}

// What transaction `txid` moved, for its activity row and details (THE RULES above). Kotlin:
// AssetManager.assetTokenCountForTx and the count and id of assetAmountForTx.
//
//   txid        the transaction's id as the rows store it (display order, NUL-terminated)
//   isSend      the row amount is below zero
//   rows        the wallet's stored rows (any of them; only the transaction's are read), rowCount of them
//   tx          a send's transaction: the wallet's copy of txid, NULL when it has none; a receive's is not read
//   owned       the wallet's own scripts, ownedCount of them (0: the platform could not say)
static inline BRAssetTxAmount BRAssetTxActivityAmount(const char *txid, int isSend, const BRAssetRow *rows, size_t rowCount,
                                                      const BRTransaction *tx, const BRAssetScript *owned, size_t ownedCount)
{
    BRAssetTxAmount out;
    int64_t total = 0;
    size_t i;

    memset(&out, 0, sizeof(out));
    if (! txid || (rowCount > 0 && ! rows)) return out;

    if (isSend) {
        if (tx && ! _BRAssetHoldTxidIs(txid, tx)) return out;
        total = _BRAssetTxAmountCarried(tx, owned, ownedCount, 0);
    } else {
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_RECEIVE_CLAIMED)
        (void)i;
        total = (tx && _BRAssetHoldTxidIs(txid, tx)) ? _BRAssetTxAmountCarried(tx, owned, ownedCount, 1) : 0;
#else
        (void)tx;
        for (i = 0; i < rowCount; i++) {
            const BRAssetRow *r = &rows[i];

            if (! _BRAssetTxAmountRowOf(r, txid)) continue;
#if !(ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_UNBACKED_COUNTS)
            if (! BRAssetCreditCounts(r->credit)) continue;
#endif
#if (ASSET_TX_AMOUNT_UNFIXED & ASSET_TX_AMOUNT_RED_SPENT_SKIPPED)
            if (r->spent) continue;
#endif
            total = _BRAssetTxAmountAdd(total, r->assetQuantity);
        }
#endif
    }

    if (total <= 0) {
        out.status = BR_ASSET_TX_AMOUNT_NONE;
        return out;
    }
    out.status = BR_ASSET_TX_AMOUNT_OK;
    out.units = total;
    out.assetId = _BRAssetTxAmountAssetOf(txid, rows, rowCount);
    return out;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetTxAmount_h
