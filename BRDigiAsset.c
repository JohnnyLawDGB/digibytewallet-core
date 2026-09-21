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

/* (internal)
 * Locate the DigiAsset payload inside an OP_RETURN output.
 *
 * A DigiAsset payload is framed by a script push: a direct single-byte push for payloads up
 * to 75 bytes, and OP_PUSHDATA1 (0x4c) for 76 bytes and above -- the framing every payload of
 * 76 bytes or more needs, and the framing the wallet's own encoder emits at that size. Both are
 * recognised here, so a standard PUSHDATA1 carrier is seen as the asset it is and the output
 * its instruction names is held as an asset output.
 *
 * On success returns 1 and reports, each bounded by the bytes the output actually owns:
 *   *hdrOff     offset of the version byte (the first byte after the "DA" tag), so the reader
 *               starts at the real header for either framing instead of a fixed guess.
 *   *payloadEnd one past the last byte the push DECLARES, so every later read is bounded by the
 *               declared payload and not by whatever trails it in the script.
 * Returns 0 when the output is not a DigiAsset OP_RETURN this reader can represent.
 */
static int _BRAssetPayloadSpan(const BRTxOutput *output, size_t *hdrOff, const uint8_t **payloadEnd)
{
    const uint8_t *s;
    size_t n;
    uint8_t p;

    if (!output || !output->script) return 0;
    s = output->script;
    n = output->scriptLen;
    if (n < 2 || s[0] != OP_RETURN) return 0;

    p = s[1];
    if (p == 0) return 0;
#ifdef ASSET_SCRIPT_FRAMING_UNFIXED
    /* UNFIXED arm, built only by the framing KAT: the earlier shape of this lookup -- one length
     * byte of any value, the header at a fixed offset, and the whole script as the read bound. */
    if (n <= 6 || (size_t)p + 2 > n) return 0;
    if (!BRTestProtocolTag(s + 2, "DA")) return 0;
    if (hdrOff)     *hdrOff = 4;
    if (payloadEnd) *payloadEnd = s + n;
    return 1;
#else
    size_t pushLen, dataOff;

    if (p <= 75) {                 /* direct single-byte push */
        pushLen = p;
        dataOff = 2;
    } else if (p == 0x4c) {        /* OP_PUSHDATA1: the length is in the next byte */
        if (n < 3) return 0;
        pushLen = s[2];
        dataOff = 3;
    } else {
        return 0;                  /* OP_PUSHDATA2/4 do not frame a DigiAsset payload */
    }

    /* The declared payload must fit inside the bytes the output owns, with room for the tag,
     * the version and the opcode. */
    if (pushLen < 4) return 0;
    if (dataOff + pushLen > n) return 0;
    if (!BRTestProtocolTag(s + dataOff, "DA")) return 0;

    if (hdrOff)     *hdrOff = dataOff + 2;
    if (payloadEnd) *payloadEnd = s + dataOff + pushLen;
    return 1;
#endif
}

/*
 * Returns zero if an outpoint is no asset, otherwise
 * returns the length of the asset's declared payload
 */
uint8_t BROutpointIsAsset(const BRTxOutput* output)
{
    size_t hdrOff;
    const uint8_t *payloadEnd;

    if (!_BRAssetPayloadSpan(output, &hdrOff, &payloadEnd)) return 0;
    /* declared payload length from the "DA" tag onward; always >= 4, so nonzero. */
    return (uint8_t)(payloadEnd - (output->script + hdrOff - 2));
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
 * Width in bytes of the compact amount field that starts at `ptr`, never more than the bytes
 * that remain before `end`, so advancing by the result keeps the cursor inside the payload.
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
    return (width > left) ? left : width;
}
#endif

/*
 * Returns 1 if an asset was sent to the output
 */
uint8_t BRTxOutputIsAsset(const BRTransaction* transaction, const BRTxOutput* output) {
    size_t idx = (size_t)-1;

    BRTxOutput* or_output = NULL;
    size_t hdrOff = 0;
    const uint8_t *payloadEnd = NULL;

    uint8_t* ptr;
    uint8_t type;
    uint8_t version;

    // 1) find `output`'s index in the transaction
    // 2) find the asset OP_RETURN and the span it declares
    for (size_t i = 0; i < transaction->outCount; ++i) {
        size_t ho;
        const uint8_t *pe;

        if (&transaction->outputs[i] == output)
            idx = i;

        if (_BRAssetPayloadSpan(&transaction->outputs[i], &ho, &pe)) {
            or_output = &transaction->outputs[i];
            hdrOff = ho;
            payloadEnd = pe;
        }
    }

    if (idx == (size_t)-1) return 0;
    if (or_output == NULL) return 0;

    /* Every read below is bounded by the DECLARED payload, not the whole script. */
    const uint8_t *end = payloadEnd;

    ptr = or_output->script + hdrOff; /* first byte after the "DA" tag, for either framing */
    if ((size_t)(end - ptr) < 2) return 0; /* no room for version + type */
    version = *ptr;
    ptr++;
    (void)version;

    type = *ptr;
    ptr++;

    if ((type & 0x0F) < 5) {
        // Has metadata: a 20-byte hash and a 32-byte hash. The skip is bounded by the bytes
        // that remain, so a short script cannot advance the cursor past the payload.
#ifndef ASSET_SCRIPT_BOUNDS_UNFIXED
        if ((size_t)(end - ptr) < 52) return 0;
#endif
        ptr += 20 /* SHA1 Torrent Hash */;
        ptr += 32 /* SHA256 of metadata */;
    }

    if (!DA_IS_BURN(type) && !DA_IS_TRANSFER(type)) {
        // Issuance: step over the amount field. Only its width matters here, and the step is
        // bounded by the bytes that remain (see _BRAssetAmountSpan).
#ifdef ASSET_SCRIPT_BOUNDS_UNFIXED
        /* UNFIXED arm, built only by the bounds KAT: the earlier shape of this step. */
        uint8_t flagsLen = (*ptr & 0xe0) >> 5;
        if (flagsLen & 0x0F == 0x07) flagsLen = 6;
        assert(flagsLen <= 6 && "sffc out of range");
        sffcEntry* data = &sffcTable[flagsLen];
        ptr += data->byteSize;
#else
        if (ptr >= end) return 0;
        ptr += _BRAssetAmountSpan(ptr, end);
#endif
    }

    {
        // Parse the transfer instructions, bounded by the declared payload.
        uint16_t outputIdx;
        uint8_t skip = 0, range = 0, percent = 0;
        uint8_t burn = 0;

        while (ptr < end) {
            uint8_t flags = *ptr++;

            skip = !!(flags & (1 << 7));
            range = !!(flags & (1 << 6));
            percent = !!(flags & (1 << 5));
            outputIdx = flags & 0x1F;   // low 5 bits
            (void)skip;

            if (range) {
                uint8_t outputIdx2;
                if (ptr >= end) break;
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
                if (ptr >= end) break;
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
                if (ptr >= end) break;   /* a flags byte with no amount after it */
                ptr += _BRAssetAmountSpan(ptr, end);
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
    }

    return 0;
}


