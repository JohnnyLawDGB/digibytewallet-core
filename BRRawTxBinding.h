//
//  BRRawTxBinding.h
//
//  The id of raw transaction bytes, and the amount and script a recovery sweep may sign for a coin, read
//  from its parent transaction's bytes. Until 2026-11 these lived on the Android side: the id in the JNI
//  bridge (bridge/asset_tx_checks.h raw_tx_id, behind NativeBridge.rawTransactionId -- used by recovery,
//  by the reconcile's "the bytes are the transaction requested" check and by the asset send's parent
//  binding), the rest in Kotlin (core/.../recovery/RawTxBinding.kt, the parent step of
//  LegacySweepService.admit, and RawTxBinding.feePaid). Moved unchanged, so every platform signs the same
//  values. The lookup, the JSON and hex decoding, the signing and the broadcast stay each platform's own.
//
//  THE ID (BRRawTxId). Reported only when the bytes are exactly one complete signed transaction: the
//  parser reads them (BRTransactionParseSigned), the transaction is signed (the parser computes an id),
//  and serializing what it read gives back the same bytes, no more and no fewer. The id is the one the
//  parser computes over the serialization WITHOUT witness data -- the id every txid on the network refers
//  to. For a transaction with no witness it is the double SHA-256 of the bytes; for one with a witness it
//  is not. Bytes the parser refuses, an unsigned transaction, trailing bytes, a truncation and a
//  non-canonical encoding (a varint longer than it needs, say) get no id.
//
//  THE BINDING (BRRawTxBindingCheck). A legacy P2PKH signature does not commit to the amount it spends,
//  so the amount handed to the signer has to come from the transaction that created the output, read
//  from bytes whose own id is the outpoint's txid -- computed from the bytes, never taken from the key
//  they were filed under. Each coin, in the order given, gets one answer:
//    PROVEN      its parent was supplied, the bytes are that transaction (BRRawTxId equals the coin's
//                txid), it has the output, the reported amount is the one it states and the reported
//                script (when one was reported) is the one it states. The proof carries the PARENT's
//                amount and script (a range of the caller's parent bytes); only these reach a signer.
//    UNPROVEN    no parent was filed under the coin's txid, its bytes are absent or get no id, or one of
//                its outputs states an amount above INT64_MAX (Android's reader takes amounts as a signed
//                64-bit integer and could not read that parent). The coin stays where it is and is
//                reported; the rest of the profile is unaffected.
//    CONTRADICTED the bytes are another transaction (their id is not the txid), the transaction has no
//                such output, or it states a different amount or a different script. The FIRST such coin
//                ends the check: nothing in the profile is signed (every proof is REFUSED) and the
//                verdict names the coin and why.
//  Every coin is checked, whatever its script. Each parent is read at most once. A coin's parent is the
//  FIRST entry of parents[] filed under its txid. Unproven coins are reported once per outpoint: the first
//  coin of each unproven outpoint has `listed` set, in coin order (Android's held-back list).
//
//  ADMISSION (BRRawTxBindingAdmit): the whole pre-sign gate of a profile sweep, in Android's order.
//  Unanswered lookup -> REFUSE_UNREACHABLE; then the first coin whose amount is not sweepable
//  (BRRecoveryUtxoAmountIsSweepable: zero or negative) -> REFUSE_NON_POSITIVE, before any parent is read,
//  so a zero amount is refused even when its parent states zero; then the binding: CONTRADICTED ->
//  REFUSE_CONTRADICTED, otherwise ADMIT with the proofs.
//
//  THE FEE (BRRawTxBindingFeePaid). What a signed transaction pays, read back from it rather than
//  estimated: the amounts of the outpoints it spends, less what it pays out. Answered only when the bytes
//  parse as a signed transaction, spend exactly the outpoints in spent[] (as many inputs as spent[] has
//  entries, and the same set of outpoints: so none twice), have at least one output, every spent amount
//  is positive, and both sums fit an int64 with the fee not negative. Android's reader also answered
//  nothing for an input index above INT32_MAX or an output amount above INT64_MAX; so does this.
//
//  TXIDS are UInt256 in the parser's internal byte order (BRTransaction.txHash); a platform holding the
//  display-order hex a lookup gives decodes it first (BRRawTxIdFromDisplayHex: exactly 64 ASCII hex
//  digits, either case). A REPORTED SCRIPT is the lookup's hex text, compared with the parent's script
//  as ASCII hex ignoring case, exactly as Android compares it; NULL means none was reported (a
//  zero-length non-NULL text is a reported empty script). Parent BYTES are the caller's, decoded from the
//  lookup's hex: NULL (or length 0) for an entry whose hex did not decode.
//  COST. The server decides how many coins, parents, inputs and outputs there are, so nothing here is
//  quadratic: parents, unproven outpoints and a fee's outpoints are sorted (BRRecoveryUtxo.h's in-place
//  heapsort, O(n log n)), each parent is parsed once, and its outputs' script offsets are computed once.
//  Allocation: the working space of a check or a fee is allocated here (and the parser allocates), all of
//  it freed before return; a failed allocation is BR_RAW_TX_BINDING_NO_MEMORY, never a verdict.
//  Header-only, static inline; no I/O, no clock, no locking.
//
//  Host KAT (digibytewallet-android native/src/test/host/): raw_tx_binding_kat -- the bridge's raw_tx_id
//  compiled beside BRRawTxId and compared on fixed, fuzzed and hostile bytes; RawTxBindingTest,
//  AmountProvenanceGateTest's parent cases and SweepSignsProvenInputsSourceGateTest's intent, case for
//  case; and a model of the Kotlin rules compared with this header on fuzzed profiles.
//

#ifndef BRRawTxBinding_h
#define BRRawTxBinding_h

#include "BRInt.h"
#include "BRAddress.h"        // BRVarIntSize
#include "BRTransaction.h"
#include "BRRecoveryUtxo.h"   // BRRecoveryUtxoAmountIsSweepable, the in-place heapsort
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// MACRO CONVENTION: both seams are tested by VALUE (#if). =1 is the host KAT's comparison arm; unset or =0
// is what ships.
//   RAW_TX_ID_UNFIXED=1       an id is reported for whatever the parser read: trailing bytes, a truncation
//                             the parser tolerates and non-canonical encodings are not refused.
//   RAW_TX_BINDING_UNFIXED=1  three ways the binding goes wrong: a parent whose computed id is not the
//                             coin's txid is read as if it were; a coin with no readable parent is proven
//                             at the amount the server reported; and the fee is answered for a transaction
//                             that does not spend exactly the given outpoints.
#ifndef RAW_TX_ID_UNFIXED
#define RAW_TX_ID_UNFIXED 0
#endif
#ifndef RAW_TX_BINDING_UNFIXED
#define RAW_TX_BINDING_UNFIXED 0
#endif

// ---- the id ------------------------------------------------------------------------------------

// The parsed transaction and its id when buf[0..len) is exactly one complete signed transaction (see THE
// ID); NULL otherwise. The caller frees what is returned.
static inline BRTransaction *_BRRawTxParseExact(const uint8_t *buf, size_t len)
{
    BRTransaction *tx;
    int ok;

    if (!buf || len == 0) return NULL;
    tx = BRTransactionParseSigned(buf, len);
    if (!tx) return NULL;
    ok = !UInt256IsZero(tx->txHash);
#if !RAW_TX_ID_UNFIXED
    if (ok) {
        size_t n = BRTransactionSerialize(tx, NULL, 0);
        ok = (n == len);
        if (ok) {
            uint8_t *again = (uint8_t *)malloc(n);
            ok = again != NULL
                && BRTransactionSerialize(tx, again, n) == n
                && memcmp(again, buf, n) == 0;
            free(again);
        }
    }
#endif
    if (!ok) {
        BRTransactionFree(tx);
        return NULL;
    }
    return tx;
}

// The id of the transaction serialized in buf[0..len), in internal byte order, written to *txHashOut.
// Returns 1 when an id is reported, 0 otherwise (*txHashOut is then not written).
static inline int BRRawTxId(const uint8_t *buf, size_t len, UInt256 *txHashOut)
{
    BRTransaction *tx;

    if (!buf || len == 0 || !txHashOut) return 0;
    tx = _BRRawTxParseExact(buf, len);
    if (!tx) return 0;
    *txHashOut = tx->txHash;
    BRTransactionFree(tx);
    return 1;
}

static inline int _BRRawTxHexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// A display-order txid (exactly 64 ASCII hex digits, either case) as a UInt256 in internal byte order.
// Returns 1 and writes *out, or 0 (nothing written) for anything else.
static inline int BRRawTxIdFromDisplayHex(const char *hex, size_t len, UInt256 *out)
{
    UInt256 u;
    size_t i;

    if (!hex || !out || len != 64) return 0;
    for (i = 0; i < 32; i++) {
        int hi = _BRRawTxHexDigit(hex[2 * i]), lo = _BRRawTxHexDigit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        u.u8[31 - i] = (uint8_t)((hi << 4) | lo);
    }
    *out = u;
    return 1;
}

// ---- the binding -------------------------------------------------------------------------------

typedef struct {
    UInt256 txid;              // the outpoint's transaction, internal byte order
    int64_t vout;              // the outpoint's output index as reported (any value; only 0..outputs-1 exist)
    int64_t amount;            // satoshis as reported
    const char *scriptHex;     // the reported scriptPubKey as hex text; NULL = none reported
    size_t scriptHexLen;
} BRRawTxBindingUtxo;

typedef struct {
    UInt256 txid;              // the txid the lookup filed these bytes under
    const uint8_t *bytes;      // the bytes, decoded from the lookup's hex; NULL = it did not decode
    size_t len;
} BRRawTxBindingParent;

typedef enum {
    BR_RAW_TX_PROOF_NONE = 0,       // not written (a check that did not complete)
    BR_RAW_TX_PROOF_PROVEN = 1,     // amount and script below are the parent's
    BR_RAW_TX_PROOF_UNPROVEN = 2,   // no readable parent: hold this coin back and report it
    BR_RAW_TX_PROOF_REFUSED = 3     // the profile was contradicted: sign nothing
} BRRawTxProofState;

typedef struct {
    BRRawTxProofState state;
    int64_t amount;            // PROVEN: the amount the parent states; otherwise 0
    size_t parent;             // PROVEN: the index into parents[] that proved it; otherwise SIZE_MAX
    size_t scriptOffset;       // PROVEN: the parent's script is parents[parent].bytes[scriptOffset..+scriptLen)
    size_t scriptLen;          //         (SIZE_MAX and 0 otherwise)
    int listed;                // UNPROVEN: 1 for the first coin of its outpoint, the one the report lists
} BRRawTxProof;

typedef enum {
    BR_RAW_TX_BINDING_CHECKED = 0,       // nothing disagreed: proofs[] holds PROVEN / UNPROVEN
    BR_RAW_TX_BINDING_CONTRADICTED = 1,  // a parent disagrees: every proof is REFUSED
    BR_RAW_TX_BINDING_BAD_ARGUMENT = 2,  // a required pointer was NULL (or NULL with a nonzero count)
    BR_RAW_TX_BINDING_NO_MEMORY = 3      // the working space could not be allocated; no answer
} BRRawTxBindingOutcome;

typedef enum {
    BR_RAW_TX_CONTRADICTION_NONE = 0,
    BR_RAW_TX_CONTRADICTION_OTHER_TX = 1,        // the bytes are the transaction otherTxid
    BR_RAW_TX_CONTRADICTION_NO_SUCH_OUTPUT = 2,  // the parent has no output vout
    BR_RAW_TX_CONTRADICTION_AMOUNT = 3,          // the parent states parentAmount
    BR_RAW_TX_CONTRADICTION_SCRIPT = 4           // the parent states another script
} BRRawTxContradiction;

typedef struct {
    BRRawTxBindingOutcome outcome;
    size_t utxo;                    // CONTRADICTED: the coin (index into utxos[]); otherwise SIZE_MAX
    BRRawTxContradiction reason;
    UInt256 otherTxid;              // OTHER_TX: the id computed from the bytes supplied
    int64_t parentAmount;           // AMOUNT: what the parent states
    size_t provenCount;             // CHECKED: coins PROVEN
    size_t unprovenListed;          // CHECKED: unproven outpoints (coins with `listed` set)
} BRRawTxBindingVerdict;

enum { _BR_RAW_TX_PARENT_UNREAD = 0, _BR_RAW_TX_PARENT_UNREADABLE, _BR_RAW_TX_PARENT_OTHER, _BR_RAW_TX_PARENT_READ };

typedef struct {
    int state;
    UInt256 id;                // OTHER: the computed id
    BRTransaction *tx;         // READ: the parsed parent
    size_t *scriptOffset;      // READ: each output's script offset in the parent's bytes
} _BRRawTxParentState;

static inline int _BRRawTxUInt256Compare(const UInt256 *a, const UInt256 *b)
{
    return memcmp(a->u8, b->u8, sizeof(a->u8));
}

// Work pairs {parent, parent} by (filed txid, index).
static inline int _BRRawTxParentCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRRawTxBindingParent *p = (const BRRawTxBindingParent *)ctx;
    int c = _BRRawTxUInt256Compare(&p[a[0]].txid, &p[b[0]].txid);
    return c ? c : _BRRecoveryUtxoIndexCompare(a[0], b[0]);
}

// Work pairs {coin, coin} by (txid, vout, index).
static inline int _BRRawTxUtxoCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRRawTxBindingUtxo *u = (const BRRawTxBindingUtxo *)ctx;
    int c = _BRRawTxUInt256Compare(&u[a[0]].txid, &u[b[0]].txid);
    if (c) return c;
    if (u[a[0]].vout != u[b[0]].vout) return (u[a[0]].vout < u[b[0]].vout) ? -1 : 1;
    return _BRRecoveryUtxoIndexCompare(a[0], b[0]);
}

// The first parent (lowest index) filed under txid, from the sorted pairs; SIZE_MAX when none.
static inline size_t _BRRawTxFindParent(const BRRawTxBindingParent *parents, const size_t *sorted, size_t count,
                                        const UInt256 *txid)
{
    size_t lo = 0, hi = count;

    while (lo < hi) {   // the first pair whose txid is not below txid
        size_t mid = lo + (hi - lo) / 2;
        if (_BRRawTxUInt256Compare(&parents[sorted[2 * mid]].txid, txid) < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo < count && _BRRawTxUInt256Compare(&parents[sorted[2 * lo]].txid, txid) == 0) return sorted[2 * lo];
    return SIZE_MAX;
}

// Where each output's script lies in bytes[0..len), which are exactly the serialization of tx (the id
// rule). Computed from the layout BRTransactionSerialize writes, and checked against the bytes. Returns 1
// and fills off[0..outCount), or 0 when the layout does not match the bytes (not reached for bytes that
// passed the id rule).
static inline int _BRRawTxScriptOffsets(const BRTransaction *tx, const uint8_t *bytes, size_t len, size_t *off)
{
    size_t pos = sizeof(uint32_t), i;
    int witness = 0;

    for (i = 0; i < tx->inCount; i++) if (tx->inputs[i].witLen > 0) witness = 1;
    if (witness) pos += 2;
    pos += BRVarIntSize(tx->inCount);
    for (i = 0; i < tx->inCount; i++) {
        const BRTxInput *in = &tx->inputs[i];
        size_t sl = in->signature ? in->sigLen : in->scriptLen;
        pos += sizeof(UInt256) + sizeof(uint32_t) + BRVarIntSize(sl) + sl;
        if (!in->signature && in->amount != 0) pos += sizeof(uint64_t);
        pos += sizeof(uint32_t);
        if (pos > len) return 0;
    }
    pos += BRVarIntSize(tx->outCount);
    for (i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];
        if (pos > len || len - pos < sizeof(uint64_t)) return 0;
        if (UInt64GetLE(&bytes[pos]) != o->amount) return 0;
        pos += sizeof(uint64_t) + BRVarIntSize(o->scriptLen);
        if (pos > len || len - pos < o->scriptLen) return 0;
        if (o->scriptLen > 0 && memcmp(&bytes[pos], o->script, o->scriptLen) != 0) return 0;
        off[i] = pos;
        pos += o->scriptLen;
    }
    return 1;
}

static inline void _BRRawTxReadParent(const BRRawTxBindingParent *parent, _BRRawTxParentState *st)
{
    BRTransaction *tx;
    size_t i;

    st->state = _BR_RAW_TX_PARENT_UNREADABLE;
    tx = _BRRawTxParseExact(parent->bytes, parent->len);
    if (!tx) return;
    if (!UInt256Eq(tx->txHash, parent->txid)) {
        st->id = tx->txHash;
#if !RAW_TX_BINDING_UNFIXED
        st->state = _BR_RAW_TX_PARENT_OTHER;
        BRTransactionFree(tx);
        return;
#endif
    }
    for (i = 0; i < tx->outCount; i++) {
        if (tx->outputs[i].amount > (uint64_t)INT64_MAX) { BRTransactionFree(tx); return; }
    }
    st->scriptOffset = (size_t *)malloc((tx->outCount ? tx->outCount : 1) * sizeof(size_t));
    if (!st->scriptOffset || !_BRRawTxScriptOffsets(tx, parent->bytes, parent->len, st->scriptOffset)) {
        free(st->scriptOffset);
        st->scriptOffset = NULL;
        BRTransactionFree(tx);
        return;
    }
    st->tx = tx;
    st->state = _BR_RAW_TX_PARENT_READ;
}

// Whether the reported script text is the script's hex, ignoring ASCII case.
static inline int _BRRawTxScriptHexEquals(const char *hex, size_t hexLen, const uint8_t *script, size_t scriptLen)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (scriptLen > SIZE_MAX / 2 || hexLen != 2 * scriptLen) return 0;
    for (i = 0; i < hexLen; i++) {
        char c = hex[i];
        uint8_t b = script[i / 2];
        char want = digits[(i % 2 == 0) ? (b >> 4) : (b & 0x0f)];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != want) return 0;
    }
    return 1;
}

static inline void _BRRawTxProofClear(BRRawTxProof *p, BRRawTxProofState state)
{
    p->state = state;
    p->amount = 0;
    p->parent = SIZE_MAX;
    p->scriptOffset = SIZE_MAX;
    p->scriptLen = 0;
    p->listed = 0;
}

// Checks every coin of utxos[0..count) against parents[0..parentCount) (see THE BINDING). proofs[] has
// count entries, written for every coin unless the outcome is BAD_ARGUMENT or NO_MEMORY (then every
// proof is NONE where proofs is not NULL). *verdict (required) describes the outcome.
static inline BRRawTxBindingOutcome BRRawTxBindingCheck(const BRRawTxBindingUtxo utxos[], size_t count,
                                                        const BRRawTxBindingParent parents[], size_t parentCount,
                                                        BRRawTxProof proofs[], BRRawTxBindingVerdict *verdict)
{
    size_t *sorted = NULL, *order = NULL, i, n;
    _BRRawTxParentState *states = NULL;
    BRRawTxBindingOutcome outcome = BR_RAW_TX_BINDING_CHECKED;

    if (!verdict) return BR_RAW_TX_BINDING_BAD_ARGUMENT;
    memset(verdict, 0, sizeof(*verdict));
    verdict->utxo = SIZE_MAX;
    if (proofs) for (i = 0; i < count; i++) _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_NONE);
    if (count > 0 && (!utxos || !proofs)) return verdict->outcome = BR_RAW_TX_BINDING_BAD_ARGUMENT;
    if (parentCount > 0 && !parents) return verdict->outcome = BR_RAW_TX_BINDING_BAD_ARGUMENT;
    for (i = 0; i < count; i++) {
        if (utxos[i].scriptHex == NULL && utxos[i].scriptHexLen != 0) return verdict->outcome = BR_RAW_TX_BINDING_BAD_ARGUMENT;
    }
    if (count == 0) return verdict->outcome = BR_RAW_TX_BINDING_CHECKED;

    if (parentCount > SIZE_MAX / (2 * sizeof(size_t)) || count > SIZE_MAX / (2 * sizeof(size_t))) {
        return verdict->outcome = BR_RAW_TX_BINDING_NO_MEMORY;
    }
    sorted = (size_t *)malloc((parentCount ? 2 * parentCount : 1) * sizeof(size_t));
    states = (_BRRawTxParentState *)calloc(parentCount ? parentCount : 1, sizeof(_BRRawTxParentState));
    order = (size_t *)malloc(2 * count * sizeof(size_t));
    if (!sorted || !states || !order) {
        free(sorted); free(states); free(order);
        return verdict->outcome = BR_RAW_TX_BINDING_NO_MEMORY;
    }
    for (i = 0; i < parentCount; i++) sorted[2 * i] = sorted[2 * i + 1] = i;
    _BRRecoveryUtxoHeapSort(sorted, parentCount, _BRRawTxParentCompare, parents);

    for (i = 0; i < count && outcome == BR_RAW_TX_BINDING_CHECKED; i++) {
        const BRRawTxBindingUtxo *u = &utxos[i];
        size_t k = _BRRawTxFindParent(parents, sorted, parentCount, &u->txid);
        _BRRawTxParentState *st = (k == SIZE_MAX) ? NULL : &states[k];
        const BRTxOutput *out;

        if (st && st->state == _BR_RAW_TX_PARENT_UNREAD) _BRRawTxReadParent(&parents[k], st);
        if (!st || st->state == _BR_RAW_TX_PARENT_UNREADABLE) {
#if RAW_TX_BINDING_UNFIXED
            _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_PROVEN);
            proofs[i].amount = u->amount;
#else
            _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_UNPROVEN);
#endif
            continue;
        }
        if (st->state == _BR_RAW_TX_PARENT_OTHER) {
            outcome = BR_RAW_TX_BINDING_CONTRADICTED;
            verdict->utxo = i;
            verdict->reason = BR_RAW_TX_CONTRADICTION_OTHER_TX;
            verdict->otherTxid = st->id;
            break;
        }
        if (u->vout < 0 || (uint64_t)u->vout >= (uint64_t)st->tx->outCount) {
            outcome = BR_RAW_TX_BINDING_CONTRADICTED;
            verdict->utxo = i;
            verdict->reason = BR_RAW_TX_CONTRADICTION_NO_SUCH_OUTPUT;
            break;
        }
        out = &st->tx->outputs[(size_t)u->vout];
        if ((int64_t)out->amount != u->amount) {
            outcome = BR_RAW_TX_BINDING_CONTRADICTED;
            verdict->utxo = i;
            verdict->reason = BR_RAW_TX_CONTRADICTION_AMOUNT;
            verdict->parentAmount = (int64_t)out->amount;
            break;
        }
        if (u->scriptHex && !_BRRawTxScriptHexEquals(u->scriptHex, u->scriptHexLen, out->script, out->scriptLen)) {
            outcome = BR_RAW_TX_BINDING_CONTRADICTED;
            verdict->utxo = i;
            verdict->reason = BR_RAW_TX_CONTRADICTION_SCRIPT;
            break;
        }
        _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_PROVEN);
        proofs[i].amount = (int64_t)out->amount;
        proofs[i].parent = k;
        proofs[i].scriptOffset = st->scriptOffset[(size_t)u->vout];
        proofs[i].scriptLen = out->scriptLen;
    }

    if (outcome == BR_RAW_TX_BINDING_CONTRADICTED) {
        for (i = 0; i < count; i++) _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_REFUSED);
    } else {
        // The first coin of each unproven outpoint is the one listed.
        for (i = 0, n = 0; i < count; i++) {
            if (proofs[i].state == BR_RAW_TX_PROOF_PROVEN) verdict->provenCount++;
            else if (proofs[i].state == BR_RAW_TX_PROOF_UNPROVEN) { order[2 * n] = order[2 * n + 1] = i; n++; }
        }
        _BRRecoveryUtxoHeapSort(order, n, _BRRawTxUtxoCompare, utxos);
        for (i = 0; i < n; i++) {
            const BRRawTxBindingUtxo *a = &utxos[order[2 * i]], *b = i ? &utxos[order[2 * (i - 1)]] : NULL;
            if (!b || !UInt256Eq(a->txid, b->txid) || a->vout != b->vout) {
                proofs[order[2 * i]].listed = 1;
                verdict->unprovenListed++;
            }
        }
    }

    for (i = 0; i < parentCount; i++) {
        if (states[i].tx) BRTransactionFree(states[i].tx);
        free(states[i].scriptOffset);
    }
    free(sorted); free(states); free(order);
    return verdict->outcome = outcome;
}

// ---- admission ---------------------------------------------------------------------------------

typedef enum {
    BR_RAW_TX_ADMIT = 0,                      // proofs[] says which coins may be signed, at which values
    BR_RAW_TX_REFUSE_UNREACHABLE = 1,         // the lookup was not answered
    BR_RAW_TX_REFUSE_NON_POSITIVE = 2,        // verdict->utxo reports a zero or negative amount
    BR_RAW_TX_REFUSE_CONTRADICTED = 3,        // a parent disagrees (verdict says which coin and why)
    BR_RAW_TX_REFUSE_BAD_ARGUMENT = 4,
    BR_RAW_TX_REFUSE_NO_MEMORY = 5
} BRRawTxAdmission;

// Whether anything on a profile whose coins are utxos[0..count) may be signed (see ADMISSION).
// backendReachable is nonzero when the lookup was answered. proofs[] and *verdict as BRRawTxBindingCheck;
// on a refusal before the binding every proof is REFUSED.
static inline BRRawTxAdmission BRRawTxBindingAdmit(int backendReachable, const BRRawTxBindingUtxo utxos[], size_t count,
                                                   const BRRawTxBindingParent parents[], size_t parentCount,
                                                   BRRawTxProof proofs[], BRRawTxBindingVerdict *verdict)
{
    size_t i;

    if (!verdict) return BR_RAW_TX_REFUSE_BAD_ARGUMENT;
    memset(verdict, 0, sizeof(*verdict));
    verdict->utxo = SIZE_MAX;
    if (count > 0 && (!utxos || !proofs)) {
        verdict->outcome = BR_RAW_TX_BINDING_BAD_ARGUMENT;
        return BR_RAW_TX_REFUSE_BAD_ARGUMENT;
    }
    for (i = 0; i < count; i++) _BRRawTxProofClear(&proofs[i], BR_RAW_TX_PROOF_REFUSED);
    if (!backendReachable) return BR_RAW_TX_REFUSE_UNREACHABLE;
    for (i = 0; i < count; i++) {
        if (!BRRecoveryUtxoAmountIsSweepable(utxos[i].amount)) {
            verdict->utxo = i;
            return BR_RAW_TX_REFUSE_NON_POSITIVE;
        }
    }
    switch (BRRawTxBindingCheck(utxos, count, parents, parentCount, proofs, verdict)) {
    case BR_RAW_TX_BINDING_CHECKED: return BR_RAW_TX_ADMIT;
    case BR_RAW_TX_BINDING_CONTRADICTED: return BR_RAW_TX_REFUSE_CONTRADICTED;
    case BR_RAW_TX_BINDING_NO_MEMORY: return BR_RAW_TX_REFUSE_NO_MEMORY;
    default: return BR_RAW_TX_REFUSE_BAD_ARGUMENT;
    }
}

// ---- the fee -----------------------------------------------------------------------------------

typedef struct {
    UInt256 txid;              // internal byte order
    int64_t vout;
    int64_t amount;            // satoshis, as the proof gave them
} BRRawTxBindingSpent;

typedef struct {
    const BRTransaction *tx;
    const BRRawTxBindingSpent *spent;
} _BRRawTxFeeCtx;

// Work pairs {input, input} by (txHash, index).
static inline int _BRRawTxInputCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRTxInput *in = ((const _BRRawTxFeeCtx *)ctx)->tx->inputs;
    int c = _BRRawTxUInt256Compare(&in[a[0]].txHash, &in[b[0]].txHash);
    if (c) return c;
    if (in[a[0]].index != in[b[0]].index) return (in[a[0]].index < in[b[0]].index) ? -1 : 1;
    return _BRRecoveryUtxoIndexCompare(a[0], b[0]);
}

// Work pairs {spent, spent} by (txid, vout).
static inline int _BRRawTxSpentCompare(const size_t *a, const size_t *b, const void *ctx)
{
    const BRRawTxBindingSpent *s = ((const _BRRawTxFeeCtx *)ctx)->spent;
    int c = _BRRawTxUInt256Compare(&s[a[0]].txid, &s[b[0]].txid);
    if (c) return c;
    if (s[a[0]].vout != s[b[0]].vout) return (s[a[0]].vout < s[b[0]].vout) ? -1 : 1;
    return _BRRecoveryUtxoIndexCompare(a[0], b[0]);
}

// Whether the sorted inputs and the sorted spent outpoints are the same SET of outpoints.
static inline int _BRRawTxSameOutpointSet(const BRTransaction *tx, const size_t *ins, size_t inCount,
                                          const BRRawTxBindingSpent *spent, const size_t *sp, size_t spCount)
{
    size_t i = 0, j = 0;

    while (i < inCount && j < spCount) {
        const BRTxInput *in = &tx->inputs[ins[2 * i]];
        const BRRawTxBindingSpent *s = &spent[sp[2 * j]];
        if (!UInt256Eq(in->txHash, s->txid) || (int64_t)in->index != s->vout) return 0;
        // step past every copy of this outpoint on both sides
        while (i < inCount && UInt256Eq(tx->inputs[ins[2 * i]].txHash, s->txid)
               && (int64_t)tx->inputs[ins[2 * i]].index == s->vout) i++;
        while (j < spCount && UInt256Eq(spent[sp[2 * j]].txid, s->txid) && spent[sp[2 * j]].vout == s->vout) j++;
    }
    return i == inCount && j == spCount;
}

// The fee the signed transaction in buf[0..len) pays, at the amounts spent[0..count) gives for the
// outpoints it spends (see THE FEE). Returns 1 and writes *fee, or 0 (*fee = 0) when no fee is answered.
// A failed allocation is also 0.
static inline int BRRawTxBindingFeePaid(const uint8_t *buf, size_t len, const BRRawTxBindingSpent spent[], size_t count,
                                        int64_t *fee)
{
    BRTransaction *tx;
    size_t *ins = NULL, *sp = NULL, i;
    int64_t totalIn = 0, totalOut = 0;
    int ok = 0;
    _BRRawTxFeeCtx ctx;

    if (!fee) return 0;
    *fee = 0;
    if (!buf || len == 0 || (count > 0 && !spent)) return 0;
    tx = BRTransactionParseSigned(buf, len);
    if (!tx) return 0;

    for (i = 0; i < tx->inCount; i++) if (tx->inputs[i].index > (uint32_t)INT32_MAX) goto done;
    for (i = 0; i < tx->outCount; i++) if (tx->outputs[i].amount > (uint64_t)INT64_MAX) goto done;
#if !RAW_TX_BINDING_UNFIXED
    if (tx->inCount != count) goto done;
    if (count > SIZE_MAX / (2 * sizeof(size_t))) goto done;
    ins = (size_t *)malloc((count ? 2 * count : 1) * sizeof(size_t));
    sp = (size_t *)malloc((count ? 2 * count : 1) * sizeof(size_t));
    if (!ins || !sp) goto done;
    for (i = 0; i < count; i++) { ins[2 * i] = ins[2 * i + 1] = i; sp[2 * i] = sp[2 * i + 1] = i; }
    ctx.tx = tx;
    ctx.spent = spent;
    _BRRecoveryUtxoHeapSort(ins, count, _BRRawTxInputCompare, &ctx);
    _BRRecoveryUtxoHeapSort(sp, count, _BRRawTxSpentCompare, &ctx);
    if (!_BRRawTxSameOutpointSet(tx, ins, count, spent, sp, count)) goto done;
#else
    (void)ctx; (void)_BRRawTxSameOutpointSet; (void)_BRRawTxInputCompare; (void)_BRRawTxSpentCompare;
#endif
    if (tx->outCount == 0) goto done;
    for (i = 0; i < count; i++) if (spent[i].amount <= 0) goto done;
    for (i = 0; i < count; i++) {
        if (totalIn > INT64_MAX - spent[i].amount) goto done;
        totalIn += spent[i].amount;
    }
    for (i = 0; i < tx->outCount; i++) {
        int64_t a = (int64_t)tx->outputs[i].amount;
        if (totalOut > INT64_MAX - a) goto done;
        totalOut += a;
    }
    if (totalIn - totalOut < 0) goto done;
    *fee = totalIn - totalOut;
    ok = 1;

done:
    free(ins);
    free(sp);
    BRTransactionFree(tx);
    return ok;
}

#ifdef __cplusplus
}
#endif

#endif // BRRawTxBinding_h
