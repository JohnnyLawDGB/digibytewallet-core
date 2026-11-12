//
//  BRAssetEncode.h
//
//  The DigiAssets carrier encoder: the OP_RETURN script of an asset TRANSFER, from its instructions.
//  Until 2026-11 these rules were written only in Kotlin, in the Android repository
//  (core/.../asset/DigiAssetEncoder.kt and BitWriter.kt). They move here unchanged: every list the
//  Kotlin encodes is encoded to the same bytes here, and every list it refuses is refused here.
//
//  THE RULES:
//    - AN INSTRUCTION (BRAssetTransferInstructionValid) is written only when its fields fit them: an
//      output index of 0..31 (0..8191 for a range), and an amount of 0..100 when it is a percent, of zero
//      or more otherwise. isBurn must be 0: this encoder writes TRANSFER payloads, in which output 31 is
//      an ordinary output, and the decoder reads isBurn only in a BURN (C only: Kotlin's instruction has
//      no such field).
//    - THE PAYLOAD (BRAssetEncodeTransferPayload): the tag "DA" (0x44 0x41), the version (2 or 3), the
//      opcode 0x15, then each instruction in order, packed most significant bit first: 1 bit skip, 1 bit
//      range, 1 bit percent, the output index in 5 bits (13 for a range), then the amount: 8 bits for a
//      percent, FIXED PRECISION otherwise. Every instruction is a whole number of bytes, so nothing is
//      padded. Refused, in this order: an instruction that is not valid; a version other than 2 or 3;
//      no instruction; an amount FIXED PRECISION cannot carry.
//    - FIXED PRECISION (BRAssetBitsWriteFixedPrecision), the form BRAssetDecode.h reads: 0..31 in one
//      byte (header 000, 5-bit mantissa). Above 31 every trailing decimal zero is taken into the
//      exponent (value = m * 10^e, m not divisible by 10), and the first form that holds both m and e is
//      written: 2, 3 or 4 bytes (header 001, 010, 011; a 9-, 17- or 25-bit mantissa and a 4-bit
//      exponent), 5 or 6 bytes (100, 101; 34 or 42 bits and a 3-bit exponent). Otherwise the 7-byte form
//      (header 11, the value itself in 54 bits), which holds 0..2^54 - 1; a larger value, or a negative
//      one, is refused. The zeros are always taken whole, so a value whose exponent would not fit is
//      written in the 7-byte form even where a smaller exponent would fit a shorter one (10^16 takes 7
//      bytes, not 2 as 10 * 10^15 would): what is written is what the Kotlin writes.
//    - THE SCRIPT (BRAssetEncodeTransferScript): OP_RETURN (0x6a) and the payload as one push, a direct
//      push (its length byte) up to 75 bytes and OP_PUSHDATA1 (0x4c, then its length byte) from 76. A
//      payload over BR_ASSET_ENCODE_MAX_PAYLOAD (80) bytes is refused. BRAssetEncodeSimpleTransfer is the
//      script of one instruction moving `quantity` to one output.
//    - THE INVERSE. On every script this encoder writes, BRAssetDecodeInstructions answers
//      BR_ASSET_SCRIPT_ASSET with a TRANSFER header of that version and exactly the given list, field for
//      field, and BRAssetPayloadReadsExactly answers 1.
//
//  THE BIT WRITER (BRAssetBitWriter, Kotlin: BitWriter) writes into the caller's buffer, which need not
//  be zeroed. A write that does not fit writes nothing and is refused (Kotlin grows its buffer).
//
//  Statuses: REFUSED (0) when the Kotlin throws, with the reason; CAPACITY when the caller's buffer
//  cannot hold an answer that would otherwise be written, before anything is written: grow it and call
//  again. BR_ASSET_ENCODE_MAX_SCRIPT bytes hold any script this encoder writes.
//
//  No allocation, no wallet, no network, no clock, no I/O. Header-only, static inline; its includes are
//  libc and BRAssetDecode.h (BRAssetTransferInstruction by way of BRAssetQuantity.h, and BRAssetPow10),
//  which this header uses and does not redefine. It reads no build-time policy macro. Nothing in the core
//  calls it yet.
//
//  Test seams (host KAT asset_send_plan_kat in the Android repo): ASSET_ENCODE_UNFIXED, tested by VALUE
//  as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is what
//  ships.
//    1   ASSET_ENCODE_RED_SINGLE_PUSH       a payload of 76..80 bytes is framed with a direct push.
//    2   ASSET_ENCODE_RED_NO_LENGTH_CAP     a payload over 80 bytes is written.
//    4   ASSET_ENCODE_RED_AMOUNT_TRUNCATES  an amount past 2^54 - 1 is written as its low 54 bits.
//    8   ASSET_ENCODE_RED_NO_EXPONENT       trailing zeros are not taken into the exponent.
//    16  ASSET_ENCODE_RED_RANGE_NARROW      a range instruction's output index is written in 5 bits.
//    32  ASSET_ENCODE_RED_FIELDS_UNCHECKED  an instruction whose fields do not fit them is written, masked.
//

#ifndef BRAssetEncode_h
#define BRAssetEncode_h

#include "BRAssetDecode.h"     // BRAssetTransferInstruction (BRAssetQuantity.h), BRAssetPow10
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_ENCODE_UNFIXED
#define ASSET_ENCODE_UNFIXED 0
#endif

#define ASSET_ENCODE_RED_SINGLE_PUSH       1
#define ASSET_ENCODE_RED_NO_LENGTH_CAP     2
#define ASSET_ENCODE_RED_AMOUNT_TRUNCATES  4
#define ASSET_ENCODE_RED_NO_EXPONENT       8
#define ASSET_ENCODE_RED_RANGE_NARROW      16
#define ASSET_ENCODE_RED_FIELDS_UNCHECKED  32

// The TRANSFER opcode of a DigiAsset payload.
#define BR_ASSET_OPCODE_TRANSFER 0x15
// The longest payload a transfer script carries (DigiByte's standard OP_RETURN data), in bytes.
#define BR_ASSET_ENCODE_MAX_PAYLOAD 80
// The longest payload a direct push frames; a longer one is framed with OP_PUSHDATA1.
#define BR_ASSET_ENCODE_MAX_DIRECT_PUSH 75
// The longest script this encoder writes: OP_RETURN, OP_PUSHDATA1, a length byte and 80 bytes.
#define BR_ASSET_ENCODE_MAX_SCRIPT 83
// The largest amount FIXED PRECISION carries: 2^54 - 1, the 7-byte form's 54 bits. A plain literal, so
// Swift imports it; the check below holds it to the formula.
#define BR_ASSET_FIXED_PRECISION_MAX 18014398509481983LL
// The longest instruction range index, and the longest plain one.
#define BR_ASSET_MAX_RANGE_OUTPUT 8191
#define BR_ASSET_MAX_OUTPUT 31

typedef char _BRAssetEncodeMaxIsTheFormula[(((int64_t)1 << 54) - 1 == BR_ASSET_FIXED_PRECISION_MAX) ? 1 : -1];
typedef char _BRAssetEncodeMaxScriptIsTheSum[(3 + BR_ASSET_ENCODE_MAX_PAYLOAD == BR_ASSET_ENCODE_MAX_SCRIPT &&
                                              BR_ASSET_ENCODE_MAX_DIRECT_PUSH < 0x4c) ? 1 : -1];

// What an encode answers. REFUSED is 0.
typedef enum {
    BR_ASSET_ENCODE_REFUSED = 0,     // the Kotlin throws; see BRAssetEncodeWhy
    BR_ASSET_ENCODE_OK = 1,
    BR_ASSET_ENCODE_CAPACITY = 2     // the caller's buffer cannot hold it; nothing was written
} BRAssetEncodeStatus;

// Why an encode is refused (the Kotlin's IllegalArgumentException, by its message).
typedef enum {
    BR_ASSET_ENCODE_WHY_NONE = 0,          // it was not refused
    BR_ASSET_ENCODE_WHY_ARGUMENTS = 1,     // a NULL where a value is needed (C only)
    BR_ASSET_ENCODE_WHY_INSTRUCTION = 2,   // "outputIndex must be non-negative", "... max 31", "... max 8191",
                                           // "percent amount must be 0..100", "amount must be non-negative"
    BR_ASSET_ENCODE_WHY_VERSION = 3,       // "version must be 2 or 3"
    BR_ASSET_ENCODE_WHY_EMPTY = 4,         // "at least one transfer instruction required"
    BR_ASSET_ENCODE_WHY_AMOUNT = 5,        // "value too large for SFFC"
    BR_ASSET_ENCODE_WHY_TOO_LONG = 6       // "OP_RETURN payload ...b exceeds max 80 b"
} BRAssetEncodeWhy;

// ---- the bit writer (Kotlin: BitWriter) ---------------------------------------------------------

typedef struct {
    uint8_t *buf;                    // the caller's; cap bytes
    size_t cap;
    size_t bitPos;                   // bits written so far
} BRAssetBitWriter;

static inline BRAssetBitWriter BRAssetBitWriterMake(uint8_t *buf, size_t cap)
{
    BRAssetBitWriter w;

    w.buf = buf;
    w.cap = buf ? cap : 0;
    w.bitPos = 0;
    return w;
}

// The bytes written so far, the last one padded with zero bits (Kotlin: toByteArray().size).
static inline size_t BRAssetBitWriterLength(const BRAssetBitWriter *w)
{
    return w ? (w->bitPos + 7) / 8 : 0;
}

// Is there room for `bits` more bits?
static inline int _BRAssetBitsRoom(const BRAssetBitWriter *w, size_t bits)
{
    return w && w->buf && w->bitPos <= w->cap * 8 && bits <= w->cap * 8 - w->bitPos;
}

// Writes the low `count` bits (1..64) of `value`, most significant first. 1, or 0 and nothing written
// when `count` is out of range or the buffer has no room (Kotlin throws for the first, grows for the second).
static inline int BRAssetBitsWrite(BRAssetBitWriter *w, uint64_t value, int count)
{
    int remaining = count;

    if (count < 1 || count > 64 || ! _BRAssetBitsRoom(w, (size_t)count)) return 0;

    while (remaining > 0) {
        size_t byteIndex = w->bitPos / 8;
        int offset = (int)(w->bitPos % 8);
        int available = 8 - offset;
        int take = (remaining < available) ? remaining : available;
        int shift = remaining - take;
        unsigned chunk = (unsigned)((value >> shift) & ((1u << take) - 1u));

        if (offset == 0) w->buf[byteIndex] = 0;   // a byte is zero until it is written
        w->buf[byteIndex] = (uint8_t)(w->buf[byteIndex] | (chunk << (available - take)));
        w->bitPos += (size_t)take;
        remaining -= take;
    }

    return 1;
}

static inline int BRAssetBitsWriteByte(BRAssetBitWriter *w, uint8_t b)
{
    return BRAssetBitsWrite(w, b, 8);
}

// Every byte of bytes[0, len); 0 and nothing written when they do not all fit.
static inline int BRAssetBitsWriteBytes(BRAssetBitWriter *w, const uint8_t *bytes, size_t len)
{
    size_t i;

    if (len > 0 && ! bytes) return 0;
    if (len > SIZE_MAX / 8 || ! _BRAssetBitsRoom(w, len * 8)) return 0;
    for (i = 0; i < len; i++) BRAssetBitsWriteByte(w, bytes[i]);
    return 1;
}

// The FIXED PRECISION form of `value` (see THE RULES): 1 and its header, mantissa bits, exponent bits,
// mantissa and exponent; 0 when it has none (negative, or past BR_ASSET_FIXED_PRECISION_MAX).
static inline int _BRAssetFixedPrecisionForm(int64_t value, unsigned *header, int *headerBits, int *manBits,
                                             int *expBits, uint64_t *mantissa, uint64_t *exponent)
{
    static const struct { unsigned header; int manBits, expBits; } forms[5] = {
        { 1, 9, 4 }, { 2, 17, 4 }, { 3, 25, 4 }, { 4, 34, 3 }, { 5, 42, 3 }
    };
    int64_t m = value;
    int e = 0, i;

    if (value < 0) return 0;

    if (value <= 31) {
        *header = 0; *headerBits = 3; *manBits = 5; *expBits = 0; *mantissa = (uint64_t)value; *exponent = 0;
        return 1;
    }

#if ! (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_NO_EXPONENT)
    while (m % 10 == 0) { m /= 10; e++; }
#endif

    for (i = 0; i < 5; i++) {
        if ((uint64_t)m <= (((uint64_t)1 << forms[i].manBits) - 1) && e <= (1 << forms[i].expBits) - 1) {
            *header = forms[i].header; *headerBits = 3; *manBits = forms[i].manBits; *expBits = forms[i].expBits;
            *mantissa = (uint64_t)m; *exponent = (uint64_t)e;
            return 1;
        }
    }

    // The 7-byte form: header 11 and the value itself, m * 10^e, which is `value`.
#if ! (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_AMOUNT_TRUNCATES)
    if (value > BR_ASSET_FIXED_PRECISION_MAX) return 0;
#endif
    *header = 3; *headerBits = 2; *manBits = 54; *expBits = 0;
    *mantissa = (uint64_t)value & (uint64_t)BR_ASSET_FIXED_PRECISION_MAX; *exponent = 0;
    return 1;
}

// The bytes `value` takes in FIXED PRECISION, 1..7; 0 when it cannot be written.
static inline size_t BRAssetFixedPrecisionLength(int64_t value)
{
    unsigned header; int hb, mb, eb; uint64_t m, e;

    if (! _BRAssetFixedPrecisionForm(value, &header, &hb, &mb, &eb, &m, &e)) return 0;
    return (size_t)(hb + mb + eb) / 8;
}

// Writes `value` in FIXED PRECISION (Kotlin: writeFixedPrecision). 1, or 0 and nothing written when it
// has no such form or does not fit.
static inline int BRAssetBitsWriteFixedPrecision(BRAssetBitWriter *w, int64_t value)
{
    unsigned header; int hb, mb, eb; uint64_t m, e;

    if (! _BRAssetFixedPrecisionForm(value, &header, &hb, &mb, &eb, &m, &e)) return 0;
    if (! _BRAssetBitsRoom(w, (size_t)(hb + mb + eb))) return 0;
    BRAssetBitsWrite(w, header, hb);
    BRAssetBitsWrite(w, m, mb);
    if (eb > 0) BRAssetBitsWrite(w, e, eb);
    return 1;
}

// ---- the encoder (Kotlin: DigiAssetEncoder) -----------------------------------------------------

// May this instruction be written (Kotlin: TransferInstruction's init, and isBurn 0)? 1 or 0.
static inline int BRAssetTransferInstructionValid(const BRAssetTransferInstruction *inst)
{
    if (! inst || inst->isBurn) return 0;
#if (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_FIELDS_UNCHECKED)
    return 1;
#else
    if (inst->outputIndex < 0) return 0;
    if (inst->outputIndex > (inst->range ? BR_ASSET_MAX_RANGE_OUTPUT : BR_ASSET_MAX_OUTPUT)) return 0;
    if (inst->percent) return inst->amount >= 0 && inst->amount <= 100;
    return inst->amount >= 0;
#endif
}

// The bits of the output index field.
static inline int _BRAssetEncodeIndexBits(const BRAssetTransferInstruction *inst)
{
#if (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_RANGE_NARROW)
    (void)inst;
    return 5;
#else
    return inst->range ? 13 : 5;
#endif
}

// The bytes one valid instruction takes, or 0 when its amount cannot be written.
static inline size_t _BRAssetEncodeInstructionLength(const BRAssetTransferInstruction *inst)
{
    size_t amount = inst->percent ? 1 : BRAssetFixedPrecisionLength(inst->amount);

    return amount ? (size_t)(3 + _BRAssetEncodeIndexBits(inst)) / 8 + amount : 0;
}

// The payload's length, or 0 and *why when it is refused.
static inline size_t _BRAssetEncodePayloadLength(int32_t version, const BRAssetTransferInstruction *insts, size_t count,
                                                 BRAssetEncodeWhy *why)
{
    size_t i, len = 4;

    *why = BR_ASSET_ENCODE_WHY_NONE;
    if (count > 0 && ! insts) { *why = BR_ASSET_ENCODE_WHY_ARGUMENTS; return 0; }
    for (i = 0; i < count; i++) {
        if (! BRAssetTransferInstructionValid(&insts[i])) { *why = BR_ASSET_ENCODE_WHY_INSTRUCTION; return 0; }
    }
    if (version != 2 && version != 3) { *why = BR_ASSET_ENCODE_WHY_VERSION; return 0; }
    if (count == 0) { *why = BR_ASSET_ENCODE_WHY_EMPTY; return 0; }

    for (i = 0; i < count; i++) {
        size_t n = _BRAssetEncodeInstructionLength(&insts[i]);

        if (n == 0) { *why = BR_ASSET_ENCODE_WHY_AMOUNT; return 0; }
        if (len > SIZE_MAX - n) { *why = BR_ASSET_ENCODE_WHY_TOO_LONG; return 0; }
        len += n;
    }

    return len;
}

// Writes the payload, whose length the caller computed, at out[0, len).
static inline void _BRAssetEncodeWritePayload(int32_t version, const BRAssetTransferInstruction *insts, size_t count,
                                              uint8_t *out, size_t len)
{
    BRAssetBitWriter w = BRAssetBitWriterMake(out, len);
    size_t i;

    BRAssetBitsWriteByte(&w, 0x44);
    BRAssetBitsWriteByte(&w, 0x41);
    BRAssetBitsWriteByte(&w, (uint8_t)version);
    BRAssetBitsWriteByte(&w, BR_ASSET_OPCODE_TRANSFER);

    for (i = 0; i < count; i++) {
        const BRAssetTransferInstruction *inst = &insts[i];

        BRAssetBitsWrite(&w, inst->skip ? 1 : 0, 1);
        BRAssetBitsWrite(&w, inst->range ? 1 : 0, 1);
        BRAssetBitsWrite(&w, inst->percent ? 1 : 0, 1);
        BRAssetBitsWrite(&w, (uint64_t)(uint32_t)inst->outputIndex, _BRAssetEncodeIndexBits(inst));
        if (inst->percent) BRAssetBitsWrite(&w, (uint64_t)inst->amount, 8);
        else BRAssetBitsWriteFixedPrecision(&w, inst->amount);
    }
}

static inline BRAssetEncodeStatus _BRAssetEncodeRefused(BRAssetEncodeWhy *why, BRAssetEncodeWhy reason)
{
    if (why) *why = reason;
    return BR_ASSET_ENCODE_REFUSED;
}

// The payload alone, [tag | version | opcode | instructions], into out[0, *written) (Kotlin:
// encodeTransferPayload). No length cap here: the script carries the cap. `written` and `why` may be NULL.
static inline BRAssetEncodeStatus BRAssetEncodeTransferPayload(int32_t version, const BRAssetTransferInstruction *insts,
                                                               size_t count, uint8_t *out, size_t cap, size_t *written,
                                                               BRAssetEncodeWhy *why)
{
    BRAssetEncodeWhy reason;
    size_t len;

    if (written) *written = 0;
    if (why) *why = BR_ASSET_ENCODE_WHY_NONE;
    len = _BRAssetEncodePayloadLength(version, insts, count, &reason);
    if (len == 0) return _BRAssetEncodeRefused(why, reason);
    if (! out || cap < len) return BR_ASSET_ENCODE_CAPACITY;
    _BRAssetEncodeWritePayload(version, insts, count, out, len);
    if (written) *written = len;
    return BR_ASSET_ENCODE_OK;
}

// The OP_RETURN script of a transfer into out[0, *written) (Kotlin: encodeTransferScript); see THE
// RULES. BR_ASSET_ENCODE_MAX_SCRIPT bytes always suffice. `written` and `why` may be NULL.
static inline BRAssetEncodeStatus BRAssetEncodeTransferScript(int32_t version, const BRAssetTransferInstruction *insts,
                                                              size_t count, uint8_t *out, size_t cap, size_t *written,
                                                              BRAssetEncodeWhy *why)
{
    BRAssetEncodeWhy reason;
    size_t len, head;

    if (written) *written = 0;
    if (why) *why = BR_ASSET_ENCODE_WHY_NONE;
    len = _BRAssetEncodePayloadLength(version, insts, count, &reason);
    if (len == 0) return _BRAssetEncodeRefused(why, reason);
#if ! (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_NO_LENGTH_CAP)
    if (len > BR_ASSET_ENCODE_MAX_PAYLOAD) return _BRAssetEncodeRefused(why, BR_ASSET_ENCODE_WHY_TOO_LONG);
#else
    if (len > 255) return _BRAssetEncodeRefused(why, BR_ASSET_ENCODE_WHY_TOO_LONG);
#endif

#if (ASSET_ENCODE_UNFIXED & ASSET_ENCODE_RED_SINGLE_PUSH)
    head = (len <= BR_ASSET_ENCODE_MAX_PAYLOAD) ? 2 : 3;
#else
    head = (len <= BR_ASSET_ENCODE_MAX_DIRECT_PUSH) ? 2 : 3;
#endif
    if (! out || cap < head + len) return BR_ASSET_ENCODE_CAPACITY;

    out[0] = 0x6a;   // OP_RETURN
    if (head == 2) out[1] = (uint8_t)len;
    else {
        out[1] = 0x4c;   // OP_PUSHDATA1
        out[2] = (uint8_t)len;
    }
    _BRAssetEncodeWritePayload(version, insts, count, out + head, len);
    if (written) *written = head + len;
    return BR_ASSET_ENCODE_OK;
}

// The script of one instruction moving `quantity` (not a percent, not a range, no skip) to output
// `recipientOutputIndex` (Kotlin: encodeSimpleTransfer).
static inline BRAssetEncodeStatus BRAssetEncodeSimpleTransfer(int32_t version, int32_t recipientOutputIndex,
                                                              int64_t quantity, uint8_t *out, size_t cap,
                                                              size_t *written, BRAssetEncodeWhy *why)
{
    BRAssetTransferInstruction inst;

    memset(&inst, 0, sizeof(inst));
    inst.outputIndex = recipientOutputIndex;
    inst.amount = quantity;
    return BRAssetEncodeTransferScript(version, &inst, 1, out, cap, written, why);
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetEncode_h
