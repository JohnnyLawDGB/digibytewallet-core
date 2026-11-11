//
//  BRAssetDecode.h
//
//  The DigiAssets carrier decoder: what an OP_RETURN script says about asset units. Until 2026-11 this
//  lived only in Android's Kotlin (core/.../asset/DigiAssetDecoder.kt, BitReader.kt and
//  AssetPayloadCheck.kt). It moves here unchanged: every script the Kotlin decoder decodes decodes to
//  the same fields here, and every script it refuses is refused here the same way.
//
//  THE RULES:
//    - THE CARRIER (BRAssetDecodeCarrier). A script is a DigiAsset carrier when it is OP_RETURN (0x6a)
//      followed by one push whose first two bytes are the tag "DA" (0x44 0x41). The push is a direct
//      push (a length byte up to 75), OP_PUSHDATA1 (0x4c, one length byte), OP_PUSHDATA2 (0x4d, two
//      length bytes, little-endian) or OP_PUSHDATA4 (0x4e, four). Anything else, a push of fewer than
//      two bytes, a script that ends before the tag, or another tag, is NOT a carrier.
//    - FAIL CLOSED. A tagged carrier this reader cannot classify is UNCLASSIFIABLE, never "not an
//      asset": the platform holds every output of that transaction it owns and credits none. That is
//      a carrier framed with OP_PUSHDATA2 or OP_PUSHDATA4 (no DigiAsset encoder frames a payload that
//      way), a push shorter than the four header bytes or running past the script, and a payload that
//      does not decode (below).
//    - THE HEADER (BRAssetDecodeHeader), from the payload's first byte: tag (2 bytes), version
//      (1 byte; 0 does not decode), opcode (1 byte): 1..5 an ISSUANCE, 0x15 a TRANSFER, 0x25 a BURN;
//      any other does not decode. Then
//        version < 3 and opcode < 3: 20 bytes (a SHA1 the reader steps over), which must be there;
//        opcode 1, 3 or 4: the 32-byte SHA256 of the metadata, which must be there;
//        an ISSUANCE: the amount issued (FIXED PRECISION, below), which must read; then the flags,
//          which are the payload's LAST byte wherever the reading stands: divisibility = its top 3
//          bits, locked = bit 0x10, aggregation = bits 0x0c (0 aggregatable, 1 hybrid, 2 dispersed;
//          3 does not decode). In version 1 with a divisibility above 0 the amount is divided by
//          10^divisibility (integer division).
//      Opcodes 3 and 4 carry a rules block this reader does not parse (BRAssetHeaderHasRules).
//    - THE INSTRUCTIONS (BRAssetDecodeInstructions), read from where the header stopped until no bits
//      are left (an issuance: until only its 8 flag bits are left). Each is 1 bit skip, 1 bit range,
//      1 bit percent, an output index of 5 bits (13 bits when range is set), and an amount: 8 bits
//      when percent is set, FIXED PRECISION otherwise. isBurn is set only in a BURN, for the
//      non-range output index 31; in a transfer or an issuance index 31 names a real output.
//        A TRANSFER or a BURN is read strictly: a stream that ends inside an instruction, or an
//          amount that does not read, is a payload that does not decode.
//        An ISSUANCE is read as far as it makes sense (its stream may follow a rules block): fewer
//          than 8 bits before the flags, or an amount that does not read, ends the list and keeps what
//          was read; a percent byte the payload does not have empties the list. An instruction may
//          read into the flags byte. The issuance still decodes either way.
//    - FIXED PRECISION (BRAssetBitsReadFixedPrecision): a 3-bit header h, length = h + 1 bytes.
//      Length 1: a 5-bit mantissa. Lengths 2..4: a (length*8 - 7)-bit mantissa and a 4-bit exponent.
//      Lengths 5 and 6: a (length*8 - 6)-bit mantissa and a 3-bit exponent. h = 6 and h = 7 are both
//      the 7-byte form: its header is two bits, so the third bit read is the top bit of a 54-bit
//      mantissa, with no exponent. The value is mantissa * 10^exponent, and one past INT64_MAX is NOT
//      READ: it is not a count, and wrapping it would credit a number the chain never carried.
//    - READ EXACTLY (BRAssetPayloadReadsExactly). The decoder is lenient where detection must be; the
//      protocol is not. This re-reads a script strictly and answers 1 only when: the script is
//      OP_RETURN and ONE push (direct of 1..75 bytes, or OP_PUSHDATA1) that is the whole script; the
//      tag, the version and the opcode are the header's; it is not an issuance with rules or before
//      version 3; an issuance's amount is the header's; every instruction reads, the reading ends
//      exactly on the issuance's flags (or on the last bit), and the instructions are the given list
//      field for field. Anything else is 0, and the platform then decides nothing from the list.
//    - THE METADATA CID (BRAssetMetadataCid): CIDv1 of the raw codec over the header's SHA256: the
//      bytes 01 55 12 20 and the 32 hash bytes, RFC 4648 base32 in lower case without padding, after
//      the letter 'b' (59 characters). A header without a hash, or with a hash of 32 zero bytes, has
//      no CID.
//
//  A decoded header is what Kotlin's DecodedAssetHeader holds. A header that is not BR_ASSET_SCRIPT_ASSET
//  has every other field zero: no version, no opcode, DA_UNDEFINED, no hash, no quantity, no instruction
//  (Kotlin: DecodedAssetHeader.unclassifiable(), or null).
//
//  No allocation: the instruction list goes into the caller's buffer, and BR_ASSET_MAX_INSTRUCTIONS
//  entries hold any list a script this reader classifies can carry. A list the buffer cannot hold is
//  answered UNCLASSIFIABLE, never shortened. No wallet, no network, no clock, no I/O. Header-only,
//  static inline; its includes are libc, BRAssetData.h (BRAssetOperation) and BRAssetQuantity.h
//  (BRAssetTransferInstruction), which this header uses and does not redefine. It reads no build-time
//  policy macro. BRDigiAsset.c is not changed by this header and does not call it.
//
//  Test seams (host KAT asset_decode_kat in the Android repo): ASSET_DECODE_UNFIXED, tested by VALUE
//  as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is
//  what ships.
//    1    ASSET_DECODE_RED_AMOUNT_WRAPS         an amount past INT64_MAX is read, wrapped.
//    2    ASSET_DECODE_RED_FAIL_OPEN            a tagged carrier that cannot be classified is not an asset.
//    4    ASSET_DECODE_RED_PUSHDATA_READ        an OP_PUSHDATA2/4 carrier is read like any other.
//    8    ASSET_DECODE_RED_LENIENT_TRANSFER     a transfer's or burn's stream is read as an issuance's.
//    16   ASSET_DECODE_RED_BURN_ANY_OP          output 31 is a burn in every operation.
//    32   ASSET_DECODE_RED_EXACT_END_UNCHECKED  the re-read does not ask where the reading ended.
//    64   ASSET_DECODE_RED_EXACT_PUSH_LOOSE     the re-read accepts bytes after the push.
//    128  ASSET_DECODE_RED_AMOUNT_BYTE_ALIGNED  an amount is read from the next byte boundary.
//    256  ASSET_DECODE_RED_ZERO_HASH_CID        a hash of 32 zero bytes gets a CID.
//    512  ASSET_DECODE_RED_EXACT_RULES_READ     the re-read answers for an issuance with rules or before v3.
//

#ifndef BRAssetDecode_h
#define BRAssetDecode_h

#include "BRAssetData.h"       // BRAssetOperation: DA_UNDEFINED / DA_ISSUANCE / DA_TRANSFER / DA_BURN
#include "BRAssetQuantity.h"   // BRAssetTransferInstruction
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_DECODE_UNFIXED
#define ASSET_DECODE_UNFIXED 0
#endif

#define ASSET_DECODE_RED_AMOUNT_WRAPS         1
#define ASSET_DECODE_RED_FAIL_OPEN            2
#define ASSET_DECODE_RED_PUSHDATA_READ        4
#define ASSET_DECODE_RED_LENIENT_TRANSFER     8
#define ASSET_DECODE_RED_BURN_ANY_OP          16
#define ASSET_DECODE_RED_EXACT_END_UNCHECKED  32
#define ASSET_DECODE_RED_EXACT_PUSH_LOOSE     64
#define ASSET_DECODE_RED_AMOUNT_BYTE_ALIGNED  128
#define ASSET_DECODE_RED_ZERO_HASH_CID        256
#define ASSET_DECODE_RED_EXACT_RULES_READ     512

// The most instructions a classified script can carry: the longest payload is OP_PUSHDATA1's 255
// bytes, 4 of them the header, and an instruction is at least 2 bytes. A plain literal, so Swift
// imports it; the check below holds it to the formula.
#define BR_ASSET_MAX_INSTRUCTIONS 125
typedef char _BRAssetDecodeMaxInstructionsIsTheFormula[((255 - 4) / 2 == BR_ASSET_MAX_INSTRUCTIONS) ? 1 : -1];

// A metadata CID is 59 characters: 'b' and the base32 of 36 bytes. With its terminator, 60.
#define BR_ASSET_CID_LENGTH 59
#define BR_ASSET_CID_BUFFER 60
typedef char _BRAssetDecodeCidLengthIsTheFormula[(1 + (36 * 8 + 4) / 5 == BR_ASSET_CID_LENGTH &&
                                                  BR_ASSET_CID_LENGTH + 1 == BR_ASSET_CID_BUFFER) ? 1 : -1];

// What a script is. UNCLASSIFIABLE is 0, so a header nobody filled reads as the answer that holds
// everything; a value this header does not define is to be treated the same way.
typedef enum {
    BR_ASSET_SCRIPT_UNCLASSIFIABLE = 0,   // tagged "DA" and not readable: hold every owned output, credit none
    BR_ASSET_SCRIPT_NOT_ASSET = 1,        // not a DigiAsset carrier (Kotlin: null)
    BR_ASSET_SCRIPT_ASSET = 2             // a carrier this reader classifies
} BRAssetScriptKind;

// Android's Aggregation, in its order.
typedef enum {
    BR_ASSET_AGGREGATABLE = 0,
    BR_ASSET_HYBRID = 1,
    BR_ASSET_DISPERSED = 2
} BRAssetAggregation;

// Android's DecodedAssetHeader. Every field but `kind` is zero unless kind is BR_ASSET_SCRIPT_ASSET.
typedef struct {
    BRAssetScriptKind kind;
    int32_t version;                 // 1..255
    int32_t opcode;                  // 1..5, 0x15 or 0x25
    BRAssetOperation operation;      // DA_ISSUANCE / DA_TRANSFER / DA_BURN; DA_UNDEFINED when not an asset
    int hasMetadataHash;             // opcodes 1, 3 and 4
    uint8_t metadataHash[32];
    int hasTotalQuantity;            // an issuance
    int64_t totalQuantity;
    int32_t divisibility;            // 0..7
    int locked;
    BRAssetAggregation aggregation;
    size_t instructionCount;         // how many instructions the decoder reads, whether or not a list was asked for
} BRAssetHeader;

// ---- the bit reader (Android: BitReader) ---------------------------------------------------------

// Bits of `data`, most significant bit of each byte first. The caller keeps `data` alive.
typedef struct {
    const uint8_t *data;
    size_t totalBits;
    size_t position;                 // bits read so far, never above totalBits
} BRAssetBitReader;

static inline BRAssetBitReader BRAssetBitReaderMake(const uint8_t *data, size_t len)
{
    BRAssetBitReader r;

    r.data = data;
    r.totalBits = (data && len <= SIZE_MAX / 8) ? len * 8 : 0;   // a length whose bit count does not fit: no bits
    r.position = 0;
    return r;
}

static inline size_t BRAssetBitsRemaining(const BRAssetBitReader *r)
{
    return (r && r->position <= r->totalBits) ? r->totalBits - r->position : 0;
}

// The next `count` bits (1..64) as an unsigned number. 0, and nothing read, when `count` is out of
// range or fewer bits are left (Kotlin throws).
static inline int BRAssetBitsRead(BRAssetBitReader *r, int count, uint64_t *out)
{
    uint64_t result = 0;
    int remaining = count;

    if (! r || count < 1 || count > 64 || BRAssetBitsRemaining(r) < (size_t)count) return 0;

    while (remaining > 0) {
        size_t byteIndex = r->position / 8;
        int available = 8 - (int)(r->position % 8);
        int take = (remaining < available) ? remaining : available;
        unsigned bits = ((unsigned)r->data[byteIndex] >> (available - take)) & ((1u << take) - 1u);

        result = (result << take) | bits;
        r->position += (size_t)take;
        remaining -= take;
    }

    if (out) *out = result;
    return 1;
}

// Steps over `count` bits. 0, and nothing skipped, when fewer are left.
static inline int BRAssetBitsSkip(BRAssetBitReader *r, size_t count)
{
    if (! r || BRAssetBitsRemaining(r) < count) return 0;
    r->position += count;
    return 1;
}

// The next `count` bytes into `out`. 0 when the reader runs out; the bytes before that were read.
static inline int BRAssetBitsReadBytes(BRAssetBitReader *r, uint8_t *out, size_t count)
{
    size_t i;
    uint64_t v = 0;

    if (count > 0 && ! out) return 0;

    for (i = 0; i < count; i++) {
        if (! BRAssetBitsRead(r, 8, &v)) return 0;
        out[i] = (uint8_t)v;
    }

    return 1;
}

// 10^exponent for 0..18, every power of ten an int64_t holds. 0 for any other exponent.
static inline int BRAssetPow10(int exponent, int64_t *out)
{
    static const int64_t table[19] = {
        1LL, 10LL, 100LL, 1000LL, 10000LL, 100000LL, 1000000LL, 10000000LL, 100000000LL, 1000000000LL,
        10000000000LL, 100000000000LL, 1000000000000LL, 10000000000000LL, 100000000000000LL,
        1000000000000000LL, 10000000000000000LL, 100000000000000000LL, 1000000000000000000LL
    };

    if (exponent < 0 || exponent > 18) return 0;
    if (out) *out = table[exponent];
    return 1;
}

// One FIXED PRECISION amount (see THE RULES). 0 when the reader runs out inside it or its value is
// past INT64_MAX; the reader then stands where the reading stopped.
static inline int BRAssetBitsReadFixedPrecision(BRAssetBitReader *r, int64_t *out)
{
    uint64_t head = 0, mantissa = 0, exponent = 0;
    int64_t pow = 1;
    int length;

    if (! r) return 0;
#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_AMOUNT_BYTE_ALIGNED)
    r->position = (r->position + 7) / 8 * 8;
#endif
    if (! BRAssetBitsRead(r, 3, &head)) return 0;
    length = (int)head + 1;

    if (length >= 7) {   // the 7-byte form: the third header bit is the mantissa's top bit
        r->position -= 1;
        length = 7;
    }

    if (length == 1) {
        if (! BRAssetBitsRead(r, 5, &mantissa)) return 0;
    }
    else if (length < 5) {
        if (! BRAssetBitsRead(r, length * 8 - 7, &mantissa) || ! BRAssetBitsRead(r, 4, &exponent)) return 0;
    }
    else if (length < 7) {
        if (! BRAssetBitsRead(r, length * 8 - 6, &mantissa) || ! BRAssetBitsRead(r, 3, &exponent)) return 0;
    }
    else {
        if (! BRAssetBitsRead(r, 54, &mantissa)) return 0;
    }

    if (! BRAssetPow10((int)exponent, &pow)) return 0;   // an exponent field is at most 15
#if !(ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_AMOUNT_WRAPS)
    // mantissa * pow fits exactly when mantissa is no more than INT64_MAX / pow, rounded down.
    if (mantissa > (uint64_t)INT64_MAX / (uint64_t)pow) return 0;
#endif
    if (out) *out = (int64_t)(mantissa * (uint64_t)pow);
    return 1;
}

// ---- the decoder (Android: DigiAssetDecoder) -----------------------------------------------------

// The answer for a tagged carrier this reader cannot classify.
static inline BRAssetScriptKind _BRAssetDecodeUnclassifiable(void)
{
#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_FAIL_OPEN)
    return BR_ASSET_SCRIPT_NOT_ASSET;
#else
    return BR_ASSET_SCRIPT_UNCLASSIFIABLE;
#endif
}

// Is `script` a DigiAsset carrier, and where is its payload? BR_ASSET_SCRIPT_ASSET: tagged, and the
// payload (from the tag on, at least 4 bytes) is script[*payloadOff, *payloadOff + *payloadLen).
// BR_ASSET_SCRIPT_UNCLASSIFIABLE: tagged, and not readable. BR_ASSET_SCRIPT_NOT_ASSET otherwise.
// Android's containsAsset is "the answer is not BR_ASSET_SCRIPT_NOT_ASSET". Either out pointer may be
// NULL; both are 0 unless the answer is BR_ASSET_SCRIPT_ASSET.
static inline BRAssetScriptKind BRAssetDecodeCarrier(const uint8_t *script, size_t scriptLen,
                                                     size_t *payloadOff, size_t *payloadLen)
{
    uint64_t pushLen;
    size_t dataOff;
    uint8_t push;

    if (payloadOff) *payloadOff = 0;
    if (payloadLen) *payloadLen = 0;
    if (! script || scriptLen < 2 || script[0] != 0x6a) return BR_ASSET_SCRIPT_NOT_ASSET;
    push = script[1];

    if (push <= 75) {            // a direct push
        pushLen = push;
        dataOff = 2;
    }
    else if (push == 0x4c) {     // OP_PUSHDATA1
        if (scriptLen < 3) return BR_ASSET_SCRIPT_NOT_ASSET;
        pushLen = script[2];
        dataOff = 3;
    }
    else if (push == 0x4d) {     // OP_PUSHDATA2
        if (scriptLen < 4) return BR_ASSET_SCRIPT_NOT_ASSET;
        pushLen = (uint64_t)script[2] | ((uint64_t)script[3] << 8);
        dataOff = 4;
    }
    else if (push == 0x4e) {     // OP_PUSHDATA4
        if (scriptLen < 6) return BR_ASSET_SCRIPT_NOT_ASSET;
        pushLen = (uint64_t)script[2] | ((uint64_t)script[3] << 8) | ((uint64_t)script[4] << 16) |
                  ((uint64_t)script[5] << 24);
        dataOff = 6;
    }
    else return BR_ASSET_SCRIPT_NOT_ASSET;

    // The tag: the first two bytes of the push, where the script has them.
    if (pushLen < 2 || scriptLen < dataOff + 2) return BR_ASSET_SCRIPT_NOT_ASSET;
    if (script[dataOff] != 0x44 || script[dataOff + 1] != 0x41) return BR_ASSET_SCRIPT_NOT_ASSET;

    // Tagged. From here on, what cannot be classified is unclassifiable, never "not an asset".
#if !(ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_PUSHDATA_READ)
    if (push == 0x4d || push == 0x4e) return _BRAssetDecodeUnclassifiable();
#endif
    // scriptLen - dataOff is at least 2 here, so the comparison cannot wrap.
    if (pushLen < 4 || pushLen > (uint64_t)(scriptLen - dataOff)) return _BRAssetDecodeUnclassifiable();

    if (payloadOff) *payloadOff = dataOff;
    if (payloadLen) *payloadLen = (size_t)pushLen;
    return BR_ASSET_SCRIPT_ASSET;
}

// Android's DecodedAssetHeader.hasRules: opcodes 3 (rewritable rules) and 4 (immutable rules).
static inline int BRAssetHeaderHasRules(const BRAssetHeader *header)
{
    return (header && (header->opcode == 3 || header->opcode == 4)) ? 1 : 0;
}

// (internal) Android's parseHeader and parseTransferInstructions over one payload. 1 and the header
// filled when the payload decodes; 0 when it does not (the header is then not to be read). Up to
// `instCap` instructions are written to `insts`; header->instructionCount is how many were read.
static inline int _BRAssetDecodePayload(const uint8_t *payload, size_t payloadLen, BRAssetHeader *header,
                                        BRAssetTransferInstruction *insts, size_t instCap)
{
    BRAssetBitReader r = BRAssetBitReaderMake(payload, payloadLen);
    uint64_t v = 0;
    int version, opcode, issuance, lenient;
    size_t footer, count = 0;
    BRAssetOperation operation;

    if (! payload || payloadLen < 4) return 0;
    if (! BRAssetBitsSkip(&r, 16) || ! BRAssetBitsRead(&r, 8, &v)) return 0;   // the tag, then the version
    version = (int)v;
    if (version == 0) return 0;
    if (! BRAssetBitsRead(&r, 8, &v)) return 0;
    opcode = (int)v;

    if (opcode >= 1 && opcode <= 5) operation = DA_ISSUANCE;
    else if (opcode == 0x15) operation = DA_TRANSFER;
    else if (opcode == 0x25) operation = DA_BURN;
    else return 0;

    issuance = (operation == DA_ISSUANCE);

    if (version < 3 && opcode < 3) {   // 20 bytes of SHA1, stepped over
        if (BRAssetBitsRemaining(&r) < 160 || ! BRAssetBitsSkip(&r, 160)) return 0;
    }

    if (opcode == 1 || opcode == 3 || opcode == 4) {   // the SHA256 of the metadata
        if (BRAssetBitsRemaining(&r) < 256 || ! BRAssetBitsReadBytes(&r, header->metadataHash, 32)) return 0;
        header->hasMetadataHash = 1;
    }

    if (issuance) {
        int64_t quantity = 0, scale = 1;
        unsigned flags, aggregation;

        if (! BRAssetBitsReadFixedPrecision(&r, &quantity)) return 0;
        flags = payload[payloadLen - 1];   // the last byte, wherever the reading stands
        header->divisibility = (int32_t)(flags >> 5);
        header->locked = (flags & 0x10) ? 1 : 0;
        aggregation = (flags & 0x0c) >> 2;

        if (aggregation == 0) header->aggregation = BR_ASSET_AGGREGATABLE;
        else if (aggregation == 1) header->aggregation = BR_ASSET_HYBRID;
        else if (aggregation == 2) header->aggregation = BR_ASSET_DISPERSED;
        else return 0;

        if (version == 1 && header->divisibility > 0) {   // version 1 wrote the amount scaled
            if (! BRAssetPow10((int)header->divisibility, &scale)) return 0;
            quantity /= scale;
        }

        header->hasTotalQuantity = 1;
        header->totalQuantity = quantity;
    }

    footer = issuance ? 8 : 0;
    lenient = issuance;
#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_LENIENT_TRANSFER)
    lenient = 1;
#endif

    while (BRAssetBitsRemaining(&r) > footer) {
        uint64_t skip = 0, range = 0, percent = 0, output = 0, amount = 0;
        int64_t fixed = 0;
        int burn;

        if (BRAssetBitsRemaining(&r) < 8 + footer) {   // no room for the smallest instruction
            if (lenient) break;
            return 0;
        }

        if (! BRAssetBitsRead(&r, 1, &skip) || ! BRAssetBitsRead(&r, 1, &range) ||
            ! BRAssetBitsRead(&r, 1, &percent) || ! BRAssetBitsRead(&r, range ? 13 : 5, &output) ||
            (percent && ! BRAssetBitsRead(&r, 8, &amount))) {
            if (! lenient) return 0;
            count = 0;   // an issuance whose index or percent byte is not there: no instruction at all
            break;
        }

        if (! percent) {
            if (! BRAssetBitsReadFixedPrecision(&r, &fixed)) {
                if (lenient) break;   // an issuance keeps what it read before this one
                return 0;
            }

            amount = (uint64_t)fixed;
        }

#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_BURN_ANY_OP)
        burn = (! range && output == 31);
#else
        burn = (! range && output == 31 && operation == DA_BURN);
#endif

        if (insts && count < instCap) {
            insts[count].skip = (int)skip;
            insts[count].range = (int)range;
            insts[count].percent = (int)percent;
            insts[count].isBurn = burn;
            insts[count].outputIndex = (int32_t)output;
            insts[count].amount = (int64_t)amount;
        }

        count++;
    }

    header->version = (int32_t)version;
    header->opcode = (int32_t)opcode;
    header->operation = operation;
    header->instructionCount = count;
    return 1;
}

// (internal) Android's decode. `wantList`: the instructions go to insts[0, instCap), and a list that
// does not fit is unclassifiable.
static inline BRAssetScriptKind _BRAssetDecode(const uint8_t *script, size_t scriptLen, BRAssetHeader *header,
                                               BRAssetTransferInstruction *insts, size_t instCap, int wantList)
{
    BRAssetHeader h;
    size_t off = 0, len = 0;
    BRAssetScriptKind kind = BRAssetDecodeCarrier(script, scriptLen, &off, &len);

    memset(&h, 0, sizeof(h));
    if (! wantList || ! insts) instCap = 0;

    if (kind == BR_ASSET_SCRIPT_ASSET) {
        if (! _BRAssetDecodePayload(script + off, len, &h, (wantList ? insts : NULL), instCap) ||
            (wantList && h.instructionCount > instCap)) {
            memset(&h, 0, sizeof(h));
            kind = _BRAssetDecodeUnclassifiable();
        }
    }
    else if (kind != BR_ASSET_SCRIPT_NOT_ASSET) kind = _BRAssetDecodeUnclassifiable();

    h.kind = kind;
    if (header) *header = h;
    return kind;
}

// What `script` says (Android: DigiAssetDecoder.decode). BR_ASSET_SCRIPT_ASSET and the header's
// fields; BR_ASSET_SCRIPT_UNCLASSIFIABLE (Kotlin: operation UNCLASSIFIABLE) or
// BR_ASSET_SCRIPT_NOT_ASSET (Kotlin: null), with every other field zero. header->instructionCount is
// the length of the list BRAssetDecodeInstructions writes. `header` may be NULL.
static inline BRAssetScriptKind BRAssetDecodeHeader(const uint8_t *script, size_t scriptLen, BRAssetHeader *header)
{
    return _BRAssetDecode(script, scriptLen, header, NULL, 0, 0);
}

// The same answer, with the instructions written to insts[0, header->instructionCount). A list longer
// than `instCap` (or any list at all with no buffer) is answered BR_ASSET_SCRIPT_UNCLASSIFIABLE, never
// shortened; BR_ASSET_MAX_INSTRUCTIONS entries always suffice. Read `insts` only when the answer is
// BR_ASSET_SCRIPT_ASSET.
static inline BRAssetScriptKind BRAssetDecodeInstructions(const uint8_t *script, size_t scriptLen,
                                                          BRAssetHeader *header,
                                                          BRAssetTransferInstruction *insts, size_t instCap)
{
    return _BRAssetDecode(script, scriptLen, header, insts, instCap, 1);
}

// ---- the strict re-read (Android: AssetPayloadCheck.readsExactly) --------------------------------

// Was `script` read EXACTLY as `header` and insts[0, instCount) say (see THE RULES)? 1 or 0. The
// header is taken as given: its version, opcode, operation and quantity are compared with the
// script's, so a header that is not this script's is answered 0 by the comparison.
static inline int BRAssetPayloadReadsExactly(const uint8_t *script, size_t scriptLen, const BRAssetHeader *header,
                                             const BRAssetTransferInstruction *insts, size_t instCount)
{
    BRAssetBitReader r;
    const uint8_t *payload;
    size_t payloadLen, footer, n = 0;
    uint64_t v = 0;
    int version, opcode, issuance;
    unsigned push;

    if (! script || ! header || (instCount > 0 && ! insts)) return 0;
    if (scriptLen < 2 || script[0] != 0x6a) return 0;
    push = script[1];

    // The single push after OP_RETURN, which must be the whole script.
    if (push >= 1 && push <= 75) {
#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_EXACT_PUSH_LOOSE)
        if (scriptLen < 2 + (size_t)push) return 0;
#else
        if (scriptLen != 2 + (size_t)push) return 0;
#endif
        payload = script + 2;
        payloadLen = push;
    }
    else if (push == 0x4c) {
        if (scriptLen < 3) return 0;
#if (ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_EXACT_PUSH_LOOSE)
        if (scriptLen < 3 + (size_t)script[2]) return 0;
#else
        if (scriptLen != 3 + (size_t)script[2]) return 0;
#endif
        payload = script + 3;
        payloadLen = script[2];
    }
    else return 0;

    r = BRAssetBitReaderMake(payload, payloadLen);
    if (! BRAssetBitsRead(&r, 16, &v) || v != 0x4441) return 0;
    if (! BRAssetBitsRead(&r, 8, &v)) return 0;
    version = (int)v;
    if (! BRAssetBitsRead(&r, 8, &v)) return 0;
    opcode = (int)v;
    if ((int32_t)version != header->version || (int32_t)opcode != header->opcode) return 0;

    issuance = (header->operation == DA_ISSUANCE);
#if !(ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_EXACT_RULES_READ)
    // A rules block is not parsed here, and the decoder rescales an amount before version 3.
    if (issuance && (BRAssetHeaderHasRules(header) || version < 3)) return 0;
#endif
    if (version < 3 && opcode < 3 && ! BRAssetBitsSkip(&r, 160)) return 0;
    if ((opcode == 1 || opcode == 3 || opcode == 4) && ! BRAssetBitsSkip(&r, 256)) return 0;

    if (issuance) {
        int64_t quantity = 0;

        if (! BRAssetBitsReadFixedPrecision(&r, &quantity)) return 0;
        if (! header->hasTotalQuantity || quantity != header->totalQuantity) return 0;
    }

    footer = issuance ? 8 : 0;

    while (BRAssetBitsRemaining(&r) > footer) {
        uint64_t skip = 0, range = 0, percent = 0, output = 0, amount = 0;
        int64_t fixed = 0;
        int burn;

        if (! BRAssetBitsRead(&r, 1, &skip) || ! BRAssetBitsRead(&r, 1, &range) ||
            ! BRAssetBitsRead(&r, 1, &percent) || ! BRAssetBitsRead(&r, range ? 13 : 5, &output)) return 0;

        if (percent) {
            if (! BRAssetBitsRead(&r, 8, &amount)) return 0;
        }
        else {
            if (! BRAssetBitsReadFixedPrecision(&r, &fixed)) return 0;
            amount = (uint64_t)fixed;
        }

        // Output 31 is the destroy marker only in a BURN, as the decoder reads it.
        burn = (! range && output == 31 && header->operation == DA_BURN);

        // The lists differ as soon as one more is read than was given, or one field differs.
        if (n >= instCount) return 0;
        if ((insts[n].skip != 0) != (skip != 0) || (insts[n].range != 0) != (range != 0) ||
            (insts[n].percent != 0) != (percent != 0) || (insts[n].isBurn != 0) != (burn != 0) ||
            insts[n].outputIndex != (int32_t)output || insts[n].amount != (int64_t)amount) return 0;
        n++;
    }

#if !(ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_EXACT_END_UNCHECKED)
    if (BRAssetBitsRemaining(&r) != footer) return 0;
#endif
    return (n == instCount) ? 1 : 0;
}

// ---- the metadata CID (Android: DecodedAssetHeader.metadataCid) ----------------------------------

// The header's metadata CID as text in `out`, terminated; returns its length, BR_ASSET_CID_LENGTH.
// 0 and an empty string when the header has no hash, the hash is 32 zero bytes, or `outCap` is under
// BR_ASSET_CID_BUFFER.
static inline size_t BRAssetMetadataCid(const BRAssetHeader *header, char *out, size_t outCap)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";   // RFC 4648, lower case
    uint8_t cid[36];
    unsigned buffer = 0;
    int bitsLeft = 0, nonZero = 0;
    size_t i, n = 0;

    if (out && outCap > 0) out[0] = '\0';
    if (! header || ! header->hasMetadataHash || ! out || outCap < BR_ASSET_CID_BUFFER) return 0;
    for (i = 0; i < 32; i++) if (header->metadataHash[i] != 0) nonZero = 1;
#if !(ASSET_DECODE_UNFIXED & ASSET_DECODE_RED_ZERO_HASH_CID)
    if (! nonZero) return 0;
#endif
    (void)nonZero;

    cid[0] = 0x01;   // CID version 1
    cid[1] = 0x55;   // the raw codec
    cid[2] = 0x12;   // sha2-256
    cid[3] = 0x20;   // 32 bytes
    memcpy(&cid[4], header->metadataHash, 32);

    out[n++] = 'b';   // multibase: base32, lower case

    for (i = 0; i < sizeof(cid); i++) {
        buffer = ((buffer & 0x0fu) << 8) | cid[i];   // at most 4 bits are carried from one byte to the next
        bitsLeft += 8;

        while (bitsLeft >= 5) {
            bitsLeft -= 5;
            out[n++] = alphabet[(buffer >> bitsLeft) & 0x1fu];
        }
    }

    if (bitsLeft > 0) out[n++] = alphabet[(buffer << (5 - bitsLeft)) & 0x1fu];
    out[n] = '\0';
    return n;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetDecode_h
