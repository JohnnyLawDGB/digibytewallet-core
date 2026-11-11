//
//  BRAssetId.h
//
//  The id of the asset a DigiAsset issuance creates, derived from the issuance transaction's first
//  input. Until 2026-11 this lived only in the Android bridge (native/src/main/jni/bridge/jni_asset.c,
//  deriveIssuanceAssetId). It moves here unchanged: every input the bridge names gets the same id here,
//  and every input it refuses is refused here.
//
//  THE RULES:
//    - THE ID of a LOCKED issuance is base58check(prefix || hash160 || 0x00 || divisibility), where
//      hash160 = RIPEMD160(SHA256(text)) and text is the ASCII "<txid>:<vout>" of the issuance's first
//      input: the 64 characters of its txid as given, a colon, and its output index in decimal.
//    - THE PREFIX says the aggregation: aggregatable 0x20 0xce (the id starts "La"), hybrid 0x21 0x02
//      ("Lh"), dispersed 0x20 0xe4 ("Ld"). The id is always 38 characters.
//    - REFUSED (0, and no id): no txid; an output index below zero; an aggregation that is none of the
//      three; a divisibility outside 0..7; a txid that is not exactly 64 bytes long; an UNLOCKED
//      issuance.
//    - THE TXID is used as it is given. Its characters are not checked and its case is not changed, so
//      the caller passes it exactly as the issuer hashed it: lower-case hex, in display order.
//
//  LIMIT: the id of an UNLOCKED issuance cannot be derived here. It is computed from the script of the
//  output the first input spends, which this function is not given; the Android bridge refuses it in
//  the same way, and the caller names such an asset by other means.
//
//  No allocation of its own, no wallet, no network, no clock, no I/O. Header-only, static inline; its
//  includes are libc, BRAssetDecode.h (BRAssetAggregation), BRCrypto.h (BRSHA256, BRRMD160) and
//  BRBase58.h (BRBase58CheckEncode), so a program that calls it links BRCrypto.c and BRBase58.c. It
//  reads no build-time policy macro. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_allocate_kat in the Android repo): ASSET_ID_UNFIXED, tested by VALUE as a
//  set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is what
//  ships.
//    1   ASSET_ID_RED_UNLOCKED_DERIVED   an unlocked issuance is given the locked id.
//    2   ASSET_ID_RED_SHORT_TXID         a txid shorter than 64 bytes is hashed as given.
//    4   ASSET_ID_RED_DIVISIBILITY_ZERO  the divisibility is left out of the id.
//    8   ASSET_ID_RED_ONE_PREFIX         every aggregation gets the aggregatable prefix.
//    16  ASSET_ID_RED_VOUT_ZERO          the output index is always written as 0.
//

#ifndef BRAssetId_h
#define BRAssetId_h

#include "BRAssetDecode.h"   // BRAssetAggregation
#include "BRBase58.h"        // BRBase58CheckEncode
#include "BRCrypto.h"        // BRSHA256, BRRMD160
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_ID_UNFIXED
#define ASSET_ID_UNFIXED 0
#endif

#define ASSET_ID_RED_UNLOCKED_DERIVED   1
#define ASSET_ID_RED_SHORT_TXID         2
#define ASSET_ID_RED_DIVISIBILITY_ZERO  4
#define ASSET_ID_RED_ONE_PREFIX         8
#define ASSET_ID_RED_VOUT_ZERO          16

// An id's length in characters, and the bytes that hold it with the NUL after it.
#define BR_ASSET_ID_LENGTH 38
#define BR_ASSET_ID_BUFFER 39

// The id of the asset a LOCKED issuance creates (see THE RULES): 1, and the NUL-terminated id in
// assetId[0, assetIdCap), or 0 when it is refused or assetIdCap is too small (BR_ASSET_ID_BUFFER always
// suffices). On 0 `assetId` holds an empty string when it has room for one.
//
// firstInputTxidHex and firstInputVout name the output the issuance's FIRST input spends; `locked`,
// `aggregation` and `divisibility` are what BRAssetDecodeHeader read from the issuance.
static inline int BRAssetIdForIssuance(const char *firstInputTxidHex, int32_t firstInputVout, int locked,
                                       BRAssetAggregation aggregation, int32_t divisibility,
                                       char *assetId, size_t assetIdCap)
{
    char text[64 + 1 + 10], digits[10];
    uint8_t sha[32], payload[24];
    uint32_t v;
    size_t i, len = 0, n = 0, need;

    if (assetId && assetIdCap > 0) assetId[0] = '\0';
    if (! firstInputTxidHex || ! assetId) return 0;
    if (firstInputVout < 0) return 0;
    if (divisibility < 0 || divisibility > 7) return 0;
#if ! (ASSET_ID_UNFIXED & ASSET_ID_RED_UNLOCKED_DERIVED)
    if (! locked) return 0;
#endif

    if (aggregation == BR_ASSET_AGGREGATABLE) {
        payload[0] = 0x20;
        payload[1] = 0xce;
    }
    else if (aggregation == BR_ASSET_HYBRID) {
        payload[0] = 0x21;
        payload[1] = 0x02;
    }
    else if (aggregation == BR_ASSET_DISPERSED) {
        payload[0] = 0x20;
        payload[1] = 0xe4;
    }
    else return 0;
#if (ASSET_ID_UNFIXED & ASSET_ID_RED_ONE_PREFIX)
    payload[0] = 0x20;
    payload[1] = 0xce;
#endif

    while (len <= 64 && firstInputTxidHex[len] != '\0') len++;
#if (ASSET_ID_UNFIXED & ASSET_ID_RED_SHORT_TXID)
    if (len > 64) return 0;
#else
    if (len != 64) return 0;
#endif

    for (i = 0; i < len; i++) text[i] = firstInputTxidHex[i];
    text[len++] = ':';
#if (ASSET_ID_UNFIXED & ASSET_ID_RED_VOUT_ZERO)
    v = 0;
#else
    v = (uint32_t)firstInputVout;
#endif

    do {
        digits[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0);

    while (n > 0) text[len++] = digits[--n];
    BRSHA256(sha, text, len);
    BRRMD160(&payload[2], sha, sizeof(sha));
    payload[22] = 0x00;
#if (ASSET_ID_UNFIXED & ASSET_ID_RED_DIVISIBILITY_ZERO)
    payload[23] = 0x00;
#else
    payload[23] = (uint8_t)divisibility;
#endif
    need = BRBase58CheckEncode(NULL, 0, payload, sizeof(payload));
    if (need == 0 || need > 64 || need > assetIdCap) return 0;
    return BRBase58CheckEncode(assetId, assetIdCap, payload, sizeof(payload)) == need;
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetId_h
