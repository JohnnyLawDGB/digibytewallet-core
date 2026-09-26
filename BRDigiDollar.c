//
//  BRDigiDollar.c
//
//  DigiDollar (DD) SHOW decoder implementation. See BRDigiDollar.h for the
//  public API contract and docs/superpowers/specs/2026-07-04-digidollar-wire-format.md
//  for the pinned wire format.
//
//  Task 1 (.superpowers/sdd/task-1-brief.md) implemented the tx-version
//  classifier, BRDigiDollarTxType. Task 2 (.superpowers/sdd/task-2-brief.md)
//  implements BRDigiDollarDecodeAmounts (OP_RETURN "DD" push-walker + minimal
//  CScriptNum amount decode). Task 3 (.superpowers/sdd/task-3-brief.md)
//  implements BRDigiDollarOutputAmount (positional DD-output-ordinal binding
//  of decoded amounts to a specific vout; fails closed on any ambiguity).
//

#include "BRDigiDollar.h"
#include "BRAddress.h" // OP_RETURN
#include "BRBase58.h"

int BRDigiDollarTxType(const BRTransaction *tx)
{
    if (! tx) return 0;
    if ((tx->version & 0xFFFFu) != DD_VERSION_MARKER) return 0;
    int type = (int)((tx->version >> 24) & 0xFFu);
    if (type == DD_TYPE_MINT || type == DD_TYPE_TRANSFER || type == DD_TYPE_REDEEM) return type;
    return 0;
}

// Minimal-encoded signed little-endian CScriptNum decode (Satoshi rules), <= 8 bytes.
// Returns 1 and sets *out on success; returns 0 on non-minimal encoding or len > 8.
// Empty (len==0) decodes to 0 with success (caller decides whether to skip).
static int _ddReadScriptNum(const uint8_t *data, size_t len, int64_t *out)
{
    if (len > 8) return 0;
    if (len == 0) { *out = 0; return 1; }
    // minimal-encoding check: top byte can't be 0x00 unless it sets the sign bit of the next
    if ((data[len - 1] & 0x7f) == 0) {
        if (len == 1 || (data[len - 2] & 0x80) == 0) return 0; // non-minimal
    }
    // accumulate in uint64_t to avoid signed-shift/overflow UB on an 8-byte,
    // high-bit-set push (real DD amounts are <= 4 bytes, but fail closed safely)
    uint64_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= (uint64_t)data[i] << (8 * i);
    if (data[len - 1] & 0x80) { // negative
        uint64_t mask = (uint64_t)1 << (8 * len - 1);
        acc &= ~mask;
        *out = -(int64_t)acc;
    } else {
        *out = (int64_t)acc;
    }
    return 1;
}

// Advance a script-push cursor. On entry *pos indexes an opcode in script[0..scriptLen).
// On success sets *dataOff/*dataLen for the pushed bytes, advances *pos past the opcode,
// returns 1. Returns 0 at end-of-script or on a push that does not fit.
//
// Understands all four standard push encodings — direct pushes 0x01..0x4b, OP_PUSHDATA1
// (0x4c), OP_PUSHDATA2 (0x4d) and OP_PUSHDATA4 (0x4e) — so a transfer another wallet built
// with any of them decodes the same. An empty push (OP_0/0x00) yields dataLen 0, and so does
// any opcode that is not a push (OP_1NEGATE, OP_1..OP_16, OP_NOP, ...): the reference reader's
// GetOp presents those with no data and its loop passes over them, and both readers here do the
// same, so they agree with the reference about every byte sequence that reaches the list.
//
// In every case the declared length is compared against the bytes that remain after the opcode
// and its length header: `avail` is computed only once the header itself is known to fit, and
// the test is `l > avail`. A push that does not fit fails closed.
static int _ddNextPush(const uint8_t *script, size_t scriptLen, size_t *pos,
                       size_t *dataOff, size_t *dataLen)
{
    if (*pos >= scriptLen) return 0;
    uint8_t op = script[*pos];
    if (op == 0x00) { *dataOff = *pos + 1; *dataLen = 0; *pos += 1; return 1; } // OP_0 / empty
    if (op >= 0x01 && op <= 0x4b) {                  // direct push: the opcode is the length
        size_t l = op, avail = scriptLen - (*pos + 1);
        if (l > avail) return 0;
        *dataOff = *pos + 1; *dataLen = l; *pos += 1 + l; return 1;
    }
    if (op == 0x4c) {                                // OP_PUSHDATA1: one length byte
        if (*pos + 2 > scriptLen) return 0;         // room for opcode + length byte
        size_t l = script[*pos + 1], avail = scriptLen - (*pos + 2);
        if (l > avail) return 0;
        *dataOff = *pos + 2; *dataLen = l; *pos += 2 + l; return 1;
    }
    if (op == 0x4d) {                                // OP_PUSHDATA2: two length bytes, little-endian
        if (*pos + 3 > scriptLen) return 0;         // room for opcode + 2 length bytes
        size_t l = (size_t)script[*pos + 1] | ((size_t)script[*pos + 2] << 8);
        size_t avail = scriptLen - (*pos + 3);
        if (l > avail) return 0;
        *dataOff = *pos + 3; *dataLen = l; *pos += 3 + l; return 1;
    }
    if (op == 0x4e) {                                // OP_PUSHDATA4: four length bytes, little-endian
        if (*pos + 5 > scriptLen) return 0;         // room for opcode + 4 length bytes
        size_t l = (size_t)script[*pos + 1] | ((size_t)script[*pos + 2] << 8) |
                   ((size_t)script[*pos + 3] << 16) | ((size_t)script[*pos + 4] << 24);
        size_t avail = scriptLen - (*pos + 5);
        if (l > avail) return 0;
        *dataOff = *pos + 5; *dataLen = l; *pos += 5 + l; return 1;
    }
#ifdef DD_PUSH_LIST_OPCODE_UNFIXED
    return 0; // any other opcode ends the list
#else
    // invariant: any other opcode carries no data and is passed over, as the reference does.
    *dataOff = *pos + 1; *dataLen = 0; *pos += 1; return 1;
#endif
}

// The type push, read as the reference reads it: a script number of at most 4 bytes (CScriptNum's
// default width; a longer push is refused before it is decoded) and compared at full width against
// the type the version carries. Returns 1 when the push matches `type`.
static int _ddTypePushMatches(const uint8_t *data, size_t len, int type)
{
    int64_t tt;
#ifdef DD_TYPE_WIDTH_UNFIXED
    return _ddReadScriptNum(data, len, &tt) && (int)tt == type;
#else
    return len <= 4 && _ddReadScriptNum(data, len, &tt) && tt == (int64_t)type;
#endif
}

// Find the first output that is an OP_RETURN whose FIRST push is the 2 bytes "DD" (44 44).
// Returns the output index, or -1.
static long _ddFindDDOpReturn(const BRTransaction *tx)
{
    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];
        if (o->scriptLen < 4 || ! o->script || o->script[0] != OP_RETURN) continue;
        size_t pos = 1, off = 0, len = 0;
        if (! _ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) continue;
        if (len == 2 && o->script[off] == 0x44 && o->script[off + 1] == 0x44) return (long)i;
    }
    return -1;
}

int BRDigiDollarDecodeAmounts(const BRTransaction *tx, int64_t *amounts, size_t maxAmounts)
{
    int type = BRDigiDollarTxType(tx);
    if (type == 0) return -1;
    long ri = _ddFindDDOpReturn(tx);
    if (ri < 0) return -1;
    const BRTxOutput *o = &tx->outputs[ri];

    size_t pos = 1, off = 0, len = 0;
    // push 0: "DD" (already validated by _ddFindDDOpReturn)
    if (! _ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) return -1;
    // push 1: txType
    if (! _ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) return -1;
    if (! _ddTypePushMatches(o->script + off, len, type)) return -1;

    int count = 0;
    while (_ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) {
        if (len == 0) continue;               // empty push consumes no slot (spec §3.2)
        int64_t v;
        if (! _ddReadScriptNum(o->script + off, len, &v)) return -1; // non-minimal -> fail closed
        if (v <= 0) return -1;                 // amounts must be positive
        if ((size_t)count >= maxAmounts) return -1;
        amounts[count++] = v;
        if (type != DD_TYPE_TRANSFER) break;   // MINT/REDEEM: first push only
    }
    if (count == 0) return -1;
    return count;
}

// Returns the DD cent amount at DD-output ordinal `ordinal` (0-based) by walking the "DD"
// OP_RETURN's amount pushes. It needs no buffer, so it places no cap on how many outputs a
// transfer may carry.
//
// It accepts exactly the lists BRDigiDollarDecodeAmounts accepts, so the two public readers
// always agree about a transaction: the WHOLE list is validated, not only the part up to
// `ordinal`. The value at `ordinal` is remembered and the walk continues to the end of the
// list; any amount anywhere in it that is not minimal and positive refuses the list as a
// whole (fail closed), and then no output of that transaction binds to an amount.
//
// Returns 1 and sets *out on success; 0 if `tx` is not a DD tx, the list is refused, or the
// ordinal is past the end of the list.
static int _ddAmountAtOrdinal(const BRTransaction *tx, size_t ordinal, int64_t *out)
{
    int type = BRDigiDollarTxType(tx);
    if (type == 0) return 0;
    long ri = _ddFindDDOpReturn(tx);
    if (ri < 0) return 0;
    const BRTxOutput *o = &tx->outputs[ri];

    size_t pos = 1, off = 0, len = 0;
    if (! _ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) return 0; // push 0: "DD"
    if (! _ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) return 0; // push 1: txType
    if (! _ddTypePushMatches(o->script + off, len, type)) return 0;

    size_t k = 0;
    int found = 0;
    int64_t atOrdinal = 0;
    while (_ddNextPush(o->script, o->scriptLen, &pos, &off, &len)) {
        if (len == 0) continue;                    // empty push consumes no slot (spec §3.2)
        int64_t v;
        if (! _ddReadScriptNum(o->script + off, len, &v)) return 0; // non-minimal -> fail closed
        if (v <= 0) return 0;                      // amounts must be positive
        if (k == ordinal) { atOrdinal = v; found = 1; } // remember it; keep validating the rest
        k++;
        if (type != DD_TYPE_TRANSFER) break;       // MINT/REDEEM: first push only
    }
    if (! found) return 0;                          // ordinal past the amount list
    *out = atOrdinal;                               // set only once the whole list has been accepted
    return 1;
}

int64_t BRDigiDollarOutputAmount(const BRTransaction *tx, size_t voutIndex)
{
    if (! tx || voutIndex >= tx->outCount) return -1;
    if (BRDigiDollarTxType(tx) == 0 || _ddFindDDOpReturn(tx) < 0) return -1;

    size_t k = 0;
    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];
        if (o->scriptLen >= 1 && o->script && o->script[0] == OP_RETURN) continue; // skip metadata
        if (o->amount != 0) continue;                                              // skip DGB/collateral
        // A DD token output is Core's canonical zero-value P2TR: OP_1 (0x51) followed by a
        // 32-byte push (0x20). Requiring the second byte too keeps a 34-byte OP_1 script that
        // is not that exact form from binding to an amount slot.
        if (o->scriptLen == 34 && o->script && o->script[0] == 0x51 && o->script[1] == 0x20) {
            if (i == voutIndex) {
                int64_t amt;
                return _ddAmountAtOrdinal(tx, k, &amt) ? amt : -1;                 // walk to this ordinal
            }
            k++;                                                                   // advance for every DD output
        } else if (i == voutIndex) {
            return -1;                                                             // target isn't a DD output
        }
    }
    return -1;
}

// Minimal signed little-endian CScriptNum encode of a non-negative value; writes to out (<=9 bytes),
// returns the byte length (0 if v==0). Inverse of _ddReadScriptNum. Positive-only (DD amounts > 0).
size_t BRDigiDollarWriteScriptNum(int64_t v, uint8_t out[9])
{
    if (v <= 0) return 0;
    uint64_t a = (uint64_t)v;
    size_t len = 0;
    while (a) { out[len++] = (uint8_t)(a & 0xff); a >>= 8; }
    if (out[len - 1] & 0x80) out[len++] = 0x00; // sign byte so it reads back positive
    return len;
}

// Decodes a DigiDollar address ("TD…" testnet / "DD…" mainnet, Base58Check) into its 32-byte
// taproot output key. Returns 1 on success, 0 on any failure (fail closed).
int BRDigiDollarAddressDecode(uint8_t key32[32], const char *addr, int isTestnet)
{
    if (! addr || ! key32) return 0;
    uint8_t data[64];
    size_t len = BRBase58CheckDecode(data, sizeof(data), addr); // verifies 4-byte double-SHA256 checksum
    if (len != 34) return 0;                                     // 2-byte version + 32-byte key
    uint8_t v0 = isTestnet ? 0xb1 : 0x52, v1 = isTestnet ? 0x29 : 0x85; // "TD" / "DD"
    if (data[0] != v0 || data[1] != v1) return 0;
    memcpy(key32, data + 2, 32);
    return 1;
}

// Encodes a 32-byte taproot output key as a DigiDollar receive address ("TD…" testnet / "DD…"
// mainnet, Base58Check). Exact inverse of BRDigiDollarAddressDecode: prepends the 2-byte network
// version and appends the 4-byte double-SHA256 checksum via BRBase58CheckEncode. Returns the string
// length written (excl. NUL), or 0 on failure.
size_t BRDigiDollarAddressEncode(char *addr, size_t addrLen, const uint8_t key32[32], int isTestnet)
{
    if (! addr || ! key32) return 0;
    uint8_t data[34];
    data[0] = isTestnet ? 0xb1 : 0x52; // "T"/"D" version high byte
    data[1] = isTestnet ? 0x29 : 0x85; // "D" version low byte
    memcpy(data + 2, key32, 32);
    size_t n = BRBase58CheckEncode(addr, addrLen, data, 34);
    return (n > 1) ? n - 1 : 0; // BRBase58CheckEncode returns length incl. NUL
}
