//
//  BRDigiAsset.c
//  DigiByte
//
//  Created by Yoshi Jaeger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#include "BRDigiAsset.h"
#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRArray.h"
#ifdef ASSET_SCRIPT_BOUNDS_UNFIXED
#include <assert.h>   /* used only by the UNFIXED arm the bounds KAT builds */
#endif
#include <string.h>

uint8_t BRTXContainsAsset(BRTransaction *tx)
{
    return BRContainsAsset(tx->outputs, tx->outCount);
}

uint8_t BRContainsAsset(const BRTxOutput *outputs, size_t outCount)
{
    for (int p = 0; p < outCount; p++)
        if (BROutpointIsAsset(&outputs[p])) return 1;
    return 0;
}

/* (internal)
 * Tests the protocol tag of an asset.
 * Returns 1 if the test was successful, otherwise it returns zero.
 */
uint8_t BRTestProtocolTag(const uint8_t* ptr, const char* check) {
    if (ptr == NULL || check == NULL) return 0;
    return (*ptr == check[0] && *(ptr + 1) == check[1]);
}

/* (internal) What _BRAssetPayloadSpan found in one output. */
#define DA_CARRIER_NONE          0  /* not a DigiAsset carrier */
#define DA_CARRIER_FOUND         1  /* a carrier this reader can classify; its span is reported */
#define DA_CARRIER_UNCLASSIFIED  2  /* tagged "DA", but framed or sized so this reader cannot classify it */

/* (internal)
 * The answer for every output of a transaction whose DigiAsset carrier this reader cannot
 * classify: 1, held as an asset output. FAIL CLOSED -- which outputs the protocol credits cannot
 * be read from such a carrier, and a held output can be released later, while an asset spent as
 * plain DGB is gone. The Kotlin DigiAssetDecoder reports the same carriers as UNCLASSIFIABLE and
 * its hold rule makes the same call.
 */
#ifdef ASSET_CARRIER_FAILCLOSED_UNFIXED
/* UNFIXED arm, built only by the unclassifiable-carrier KAT: the earlier answer, "no asset". */
#define DA_UNCLASSIFIED_ANSWER 0
#else
#define DA_UNCLASSIFIED_ANSWER 1
#endif

/* (internal)
 * Locate the DigiAsset payload inside an OP_RETURN output.
 *
 * A DigiAsset payload is framed by a script push: a direct single-byte push for payloads up
 * to 75 bytes, and OP_PUSHDATA1 (0x4c) for 76 bytes and above -- the framing every payload of
 * 76 bytes or more needs, and the framing the wallet's own encoder emits at that size. Both are
 * recognised here, so a standard PUSHDATA1 carrier is seen as the asset it is and the output
 * its instruction names is held as an asset output.
 *
 * A push that begins with the "DA" tag is a carrier whether or not this reader can classify it.
 * OP_PUSHDATA2/4 (little-endian 2- and 4-byte lengths, as script reads them) are read only far
 * enough to see the tag: no DigiAsset encoder frames a payload that way, and which outputs the
 * protocol would credit for one is not something this reader can decide. Such a carrier, and a
 * tagged push too short for the header or running past the script, is DA_CARRIER_UNCLASSIFIED.
 *
 * Returns DA_CARRIER_FOUND and reports, each bounded by the bytes the output actually owns:
 *   *hdrOff     offset of the version byte (the first byte after the "DA" tag), so the reader
 *               starts at the real header for either framing instead of a fixed guess.
 *   *payloadEnd one past the last byte the push DECLARES, so every later read is bounded by the
 *               declared payload and not by whatever trails it in the script.
 * Returns DA_CARRIER_UNCLASSIFIED for a tagged carrier it cannot classify (nothing reported),
 * and DA_CARRIER_NONE when the output is not a DigiAsset carrier at all.
 */
static int _BRAssetPayloadSpan(const BRTxOutput *output, size_t *hdrOff, const uint8_t **payloadEnd)
{
    const uint8_t *s;
    size_t n;
    uint8_t p;

    if (!output || !output->script) return DA_CARRIER_NONE;
    s = output->script;
    n = output->scriptLen;
    if (n < 2 || s[0] != OP_RETURN) return DA_CARRIER_NONE;

    p = s[1];
    if (p == 0) return DA_CARRIER_NONE;
#ifdef ASSET_SCRIPT_FRAMING_UNFIXED
    /* UNFIXED arm, built only by the framing KAT: the earlier shape of this lookup -- one length
     * byte of any value, the header at a fixed offset, and the whole script as the read bound. */
    if (n <= 6 || (size_t)p + 2 > n) return DA_CARRIER_NONE;
    if (!BRTestProtocolTag(s + 2, "DA")) return DA_CARRIER_NONE;
    if (hdrOff)     *hdrOff = 4;
    if (payloadEnd) *payloadEnd = s + n;
    return DA_CARRIER_FOUND;
#else
    uint64_t pushLen;
    size_t dataOff;

    if (p <= 75) {                 /* direct single-byte push */
        pushLen = p;
        dataOff = 2;
    } else if (p == OP_PUSHDATA1) { /* the length is in the next byte */
        if (n < 3) return DA_CARRIER_NONE;
        pushLen = s[2];
        dataOff = 3;
    } else if (p == OP_PUSHDATA2) { /* a 2-byte little-endian length */
        if (n < 4) return DA_CARRIER_NONE;
        pushLen = (uint64_t)s[2] | ((uint64_t)s[3] << 8);
        dataOff = 4;
    } else if (p == OP_PUSHDATA4) { /* a 4-byte little-endian length */
        if (n < 6) return DA_CARRIER_NONE;
        pushLen = (uint64_t)s[2] | ((uint64_t)s[3] << 8) | ((uint64_t)s[4] << 16) | ((uint64_t)s[5] << 24);
        dataOff = 6;
    } else {
        return DA_CARRIER_NONE;    /* not a push */
    }

    /* The tag: the first two bytes of the push, where the script has them. */
    if (pushLen < 2 || dataOff + 2 > n) return DA_CARRIER_NONE;
    if (!BRTestProtocolTag(s + dataOff, "DA")) return DA_CARRIER_NONE;

    /* Tagged. From here on, anything this reader cannot classify is unclassified, never "no
     * carrier". */
#ifndef ASSET_CARRIER_FAILCLOSED_UNFIXED
    if (p == OP_PUSHDATA2 || p == OP_PUSHDATA4) return DA_CARRIER_UNCLASSIFIED;
    /* The declared payload must fit inside the bytes the output owns, with room for the tag,
     * the version and the opcode. */
    if (pushLen < 4) return DA_CARRIER_UNCLASSIFIED;
    if (dataOff + pushLen > n) return DA_CARRIER_UNCLASSIFIED;
#else
    /* UNFIXED arm, built only by the unclassifiable-carrier KAT: the earlier shape -- none of
     * these is a carrier. */
    if (p == OP_PUSHDATA2 || p == OP_PUSHDATA4) return DA_CARRIER_NONE;
    if (pushLen < 4) return DA_CARRIER_NONE;
    if (dataOff + pushLen > n) return DA_CARRIER_NONE;
#endif

    if (hdrOff)     *hdrOff = dataOff + 2;
    if (payloadEnd) *payloadEnd = s + dataOff + (size_t)pushLen;
    return DA_CARRIER_FOUND;
#endif
}

/*
 * Returns zero if an output is no DigiAsset carrier; otherwise nonzero: the length of the
 * carrier's declared payload (from the "DA" tag on, always >= 4), or DA_UNCLASSIFIED_ANSWER for
 * a tagged carrier this reader cannot classify -- still a carrier, fail closed.
 */
uint8_t BROutpointIsAsset(const BRTxOutput* output)
{
    size_t hdrOff;
    const uint8_t *payloadEnd;

    switch (_BRAssetPayloadSpan(output, &hdrOff, &payloadEnd)) {
        case DA_CARRIER_FOUND:
            /* at most 255 (PUSHDATA1), so the length fits the return type. */
            return (uint8_t)(payloadEnd - (output->script + hdrOff - 2));
        case DA_CARRIER_UNCLASSIFIED:
            return DA_UNCLASSIFIED_ANSWER;
        default:
            return 0;
    }
}

typedef struct {
    uint8_t exponent;
    uint8_t byteSize;
    uint8_t mantis;
    uint8_t skipBits;
} sffcEntry;

const sffcEntry sffcTable[] = {
    { 0, 1, 5, 3 },
    { 4, 2, 9, 3 },
    { 4, 3, 17, 3 },
    { 4, 4, 25, 3 },
    { 3, 5, 34, 3 },
    { 3, 6, 42, 3 },
    { 0, 7, 54, 2 },
};

/* (internal)
 * Width in bytes of the compact amount field that starts at `ptr`, or 0 when the field runs
 * past `end` -- an amount the payload ends inside, which does not decode. A nonzero result
 * never exceeds the bytes that remain, so advancing by it keeps the cursor inside the payload.
 *
 * The field's 3-bit header selects one of the seven rows of sffcTable. Header values 0..5 are
 * the 1..6-byte forms. Values 6 and 7 are BOTH the 7-byte form: that form's header is two bits
 * wide (row 6 skips two bits, not three), so its third bit is the top bit of the 54-bit
 * mantissa. The reference decoder and the Kotlin BitReader read it the same way.
 *
 * Requires ptr < end.
 */
#ifndef ASSET_SCRIPT_BOUNDS_UNFIXED
static size_t _BRAssetAmountSpan(const uint8_t *ptr, const uint8_t *end)
{
    uint8_t row = (uint8_t)((*ptr & 0xe0) >> 5);
    size_t width, left = (size_t)(end - ptr);

    if (row == 7) row = 6;
    width = sffcTable[row].byteSize;
    return (width > left) ? 0 : width;
}
#endif

/*
 * Returns 1 if an asset was sent to the output -- or, fail closed, if the transaction carries a
 * DigiAsset carrier this reader cannot classify (DA_UNCLASSIFIED_ANSWER): then every output of
 * the transaction is held, whichever one is asked about.
 *
 * Unclassifiable: a tagged carrier _BRAssetPayloadSpan cannot frame; a version of 0 or an opcode
 * other than the issuance opcodes 0x01-0x05, transfer 0x15 and burn 0x25; metadata, an issuance
 * amount or an issuance flags byte the payload is too short to hold or that is invalid
 * (aggregation 3); and a transfer or burn instruction the payload ends inside. Those are the
 * payloads the Kotlin DigiAssetDecoder reports as UNCLASSIFIABLE. An issuance's instruction
 * stream follows a rules block neither reader parses (opcodes 3 and 4), so it is read only as far
 * as it goes.
 */
uint8_t BRTxOutputIsAsset(const BRTransaction* transaction, const BRTxOutput* output) {
    size_t idx = (size_t)-1;

    BRTxOutput* or_output = NULL;
    size_t hdrOff = 0;
    const uint8_t *payloadEnd = NULL;
    int unclassified = 0;

    uint8_t* ptr;
    uint8_t type;
    uint8_t version;
    int issuance;

    // 1) find `output`'s index in the transaction
    // 2) find the asset OP_RETURN and the span it declares
    for (size_t i = 0; i < transaction->outCount; ++i) {
        size_t ho;
        const uint8_t *pe;

        if (&transaction->outputs[i] == output)
            idx = i;

        switch (_BRAssetPayloadSpan(&transaction->outputs[i], &ho, &pe)) {
            case DA_CARRIER_FOUND:
                or_output = &transaction->outputs[i];
                hdrOff = ho;
                payloadEnd = pe;
                break;
            case DA_CARRIER_UNCLASSIFIED:
                unclassified = 1;
                break;
            default:
                break;
        }
    }

    if (idx == (size_t)-1) return 0;
    if (unclassified) return DA_UNCLASSIFIED_ANSWER;
    if (or_output == NULL) return 0;

    /* Every read below is bounded by the DECLARED payload, not the whole script. */
    const uint8_t *end = payloadEnd;

    ptr = or_output->script + hdrOff; /* first byte after the "DA" tag, for either framing */
    if ((size_t)(end - ptr) < 2) return DA_UNCLASSIFIED_ANSWER; /* no room for version + type */
    version = *ptr;
    ptr++;

    type = *ptr;
    ptr++;

    issuance = (type >= DA_TYPE_SHA1_META_SHA256 && type <= DA_TYPE_SHA1_NO_META_LOCKED);
    if (version == 0 || (!issuance && type != 0x15 && type != 0x25)) return DA_UNCLASSIFIED_ANSWER;

    {
        // Metadata: v1/v2 issuance opcodes 1 and 2 carry a 20-byte SHA1 torrent hash, and opcodes
        // 1, 3 and 4 the 32-byte SHA256 of the metadata (DigiAsset_Core DigiAsset.cpp
        // processIssuance; the Kotlin DigiAssetDecoder reads the same). The skip is bounded by the
        // bytes that remain, so a short script cannot advance the cursor past the payload.
        size_t meta = 0;
        if (version < 3 && type < 3) meta += 20 /* SHA1 Torrent Hash */;
        if (type == 1 || type == 3 || type == 4) meta += 32 /* SHA256 of metadata */;
#ifndef ASSET_SCRIPT_BOUNDS_UNFIXED
        if ((size_t)(end - ptr) < meta) return DA_UNCLASSIFIED_ANSWER;
#endif
        ptr += meta;
    }

    if (issuance) {
        // Issuance: step over the amount field. Only its width matters here, and an amount the
        // payload ends inside does not decode (see _BRAssetAmountSpan).
#ifdef ASSET_SCRIPT_BOUNDS_UNFIXED
        /* UNFIXED arm, built only by the bounds KAT: the earlier shape of this step. */
        uint8_t flagsLen = (*ptr & 0xe0) >> 5;
        if (flagsLen & 0x0F == 0x07) flagsLen = 6;
        assert(flagsLen <= 6 && "sffc out of range");
        sffcEntry* data = &sffcTable[flagsLen];
        ptr += data->byteSize;
#else
        size_t width;
        if (ptr >= end) return DA_UNCLASSIFIED_ANSWER;
        width = _BRAssetAmountSpan(ptr, end);
        if (width == 0) return DA_UNCLASSIFIED_ANSWER;
        ptr += width;
        // The issuance flags are the payload's last byte; aggregation 3 is not a valid type.
        if (((end[-1] & 0x0C) >> 2) == 3) return DA_UNCLASSIFIED_ANSWER;
#endif
    }

    {
        // Parse the transfer instructions, bounded by the declared payload. A transfer or burn
        // instruction the payload ends inside does not decode; an issuance's stream is read only
        // as far as it goes (see above).
        uint16_t outputIdx;
        uint8_t skip = 0, range = 0, percent = 0;
        uint8_t burn = 0;
        int truncated = 0;

        while (ptr < end) {
            uint8_t flags = *ptr++;

            skip = !!(flags & (1 << 7));
            range = !!(flags & (1 << 6));
            percent = !!(flags & (1 << 5));
            outputIdx = flags & 0x1F;   // low 5 bits
            (void)skip;

            if (range) {
                uint8_t outputIdx2;
                if (ptr >= end) { truncated = 1; break; }
                outputIdx2 = *ptr++;
                // output index is 13 bits
#ifdef ASSET_RANGE_TARGETS_UNFIXED
                outputIdx = outputIdx | (outputIdx2 << 8);
#else
                // the 5 flag bits are the HIGH bits, the next byte is the low 8
                outputIdx = (uint16_t)((outputIdx << 8) | outputIdx2);
#endif
            }

            if (percent) {
                if (ptr >= end) { truncated = 1; break; }
                ptr++; // percentage byte
            } else {
#ifdef ASSET_SCRIPT_BOUNDS_UNFIXED
                /* UNFIXED arm, built only by the bounds KAT: the earlier shape of this step. */
                uint8_t flagsLen = (*ptr & 0xe0) >> 5;
                if (flagsLen & 0x0F == 0x07) flagsLen = 6;
                assert(flagsLen <= 6 && "sffc out of range");
                sffcEntry* data = &sffcTable[flagsLen];
                ptr += data->byteSize;
#else
                size_t width;
                if (ptr >= end) { truncated = 1; break; }   /* a flags byte with no amount after it */
                width = _BRAssetAmountSpan(ptr, end);
                if (width == 0) { truncated = 1; break; }   /* an amount the payload ends inside */
                ptr += width;
#endif
            }

            burn = (outputIdx == 31 && range == 0);

            // An instruction targets output `idx` when it names it; a RANGE names every
            // output from 0 up to and including its endpoint.
            if (!burn) {
#ifdef ASSET_RANGE_TARGETS_UNFIXED
                if (outputIdx == idx) return 1;
#else
                if (range) { if (idx <= (size_t)outputIdx) return 1; }
                else       { if ((size_t)outputIdx == idx) return 1; }
#endif
            }
        }

        if (truncated && !issuance) return DA_UNCLASSIFIED_ANSWER;
    }

    return 0;
}
