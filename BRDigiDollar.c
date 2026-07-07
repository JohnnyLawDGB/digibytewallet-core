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
// On success sets *dataOff/*dataLen for the pushed bytes, advances *pos past the push,
// returns 1. Returns 0 at end-of-script or on a non-push / OP_PUSHDATA it can't read.
// Handles direct pushes 0x01..0x4b and OP_PUSHDATA1 (0x4c). An empty push (OP_0/0x00)
// yields dataLen 0. (DD metadata never uses larger pushdata; reject them = fail closed.)
static int _ddNextPush(const uint8_t *script, size_t scriptLen, size_t *pos,
                       size_t *dataOff, size_t *dataLen)
{
    if (*pos >= scriptLen) return 0;
    uint8_t op = script[*pos];
    if (op == 0x00) { *dataOff = *pos + 1; *dataLen = 0; *pos += 1; return 1; } // OP_0 / empty
    if (op >= 0x01 && op <= 0x4b) {
        size_t l = op;
        if (*pos + 1 + l > scriptLen) return 0;
        *dataOff = *pos + 1; *dataLen = l; *pos += 1 + l; return 1;
    }
    if (op == 0x4c) { // OP_PUSHDATA1
        if (*pos + 2 > scriptLen) return 0;
        size_t l = script[*pos + 1];
        if (*pos + 2 + l > scriptLen) return 0;
        *dataOff = *pos + 2; *dataLen = l; *pos += 2 + l; return 1;
    }
    return 0; // any other opcode (incl OP_N numeric) is not a DD metadata push
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
    int64_t tt;
    if (! _ddReadScriptNum(o->script + off, len, &tt) || (int)tt != type) return -1;

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

int64_t BRDigiDollarOutputAmount(const BRTransaction *tx, size_t voutIndex)
{
    if (! tx || voutIndex >= tx->outCount) return -1;
    int64_t amounts[64];
    int n = BRDigiDollarDecodeAmounts(tx, amounts, 64);
    if (n < 0) return -1;

    size_t k = 0;
    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *o = &tx->outputs[i];
        if (o->scriptLen >= 1 && o->script && o->script[0] == OP_RETURN) continue; // skip metadata
        if (o->amount != 0) continue;                                              // skip DGB/collateral
        if (o->scriptLen == 34 && o->script && o->script[0] == 0x51) {             // a DD (zero-value P2TR) output
            if (i == voutIndex) {
                if (k < (size_t)n) return amounts[k];
                return -1;                                                         // ordinal past amount list
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
