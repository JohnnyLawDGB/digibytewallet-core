//
//  BRPaymentUri.h
//
//  The `digibyte:` payment URI (BIP21 plus two asset parameters): the wallet's entry point for
//  QR codes and deep links, and so ENTIRELY UNTRUSTED INPUT. What it parses decides the
//  address and the amount a send screen is filled with, so both platforms must parse it the
//  same way. Until 2026-10 the rule lived in Kotlin (core/model/DigiByteUri.kt); its tests are
//  carried over case for case in the host KAT.
//
//  The rule:
//    - surrounding whitespace is trimmed; empty input is rejected;
//    - input containing "://" that does not start with "digibyte:" is rejected (digiid://,
//      https://, ...);
//    - input without the "digibyte:" prefix is a bare address, returned whole;
//    - otherwise the address is the text before the first '?', trimmed, and must not be empty.
//      It is NOT percent-decoded;
//    - the query after the first '?' is split on '&'; each key and value is percent-decoded
//      ('+' is a space). The FIRST occurrence of a key wins: a repeated key is how a second
//      value is smuggled past a display that shows only the first;
//    - amount: DGB text through BRAmountParseDGB (exact; no floating point). An amount that is
//      not one is DROPPED (hasAmount 0), never rounded and never a rejection;
//    - assetId and assetAmount (the asset's RAW units, never scaled like DGB) come together or
//      not at all. Either one alone, an assetAmount that is not an integer, or one <= 0 REJECTS
//      the whole URI: a malformed asset request must never degrade into a plain DGB payment
//      prompt to an address the requester chose. Parsing proves nothing about ownership.
//    - label and message are returned decoded (they are display text, not instructions).
//
//  Deliberate differences from the Kotlin it replaces (Android adopts these with the header):
//    - input is bounded at BR_PAYMENT_URI_MAX bytes and must not contain a NUL byte;
//    - trimming and "blank" are ASCII whitespace only, and integers are ASCII digits only
//      (Kotlin also accepted Unicode spaces and digits, e.g. an Arabic-Indic asset quantity);
//    - a percent escape is '%' and exactly two hex digits; Kotlin's toIntOrNull(16) also
//      accepted a sign ("%-1" decoded to byte 0xFF);
//    - decoding works on bytes, so UTF-8 outside the BMP survives; Kotlin re-encoded a
//      surrogate pair one half at a time, turning an emoji into "??".
//  The scheme is matched case-sensitively, as before; BIP21 allows "DIGIBYTE:" and accepting it
//  is a separate decision.
//
//  Host KAT: digibytewallet-android native/src/test/host/payment_uri_kat/.
//  Header-only, static inline; no allocation, no locale.
//

#ifndef BRPaymentUri_h
#define BRPaymentUri_h

#include "BRAmountParse.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// The longest input parsed, in bytes. A QR code holds at most 2,953 bytes.
#define BR_PAYMENT_URI_MAX 4096
// The buffer the caller lends BRPaymentUriParse for the text fields: four fields, each up to
// BR_PAYMENT_URI_MAX bytes plus a NUL. (Text is not embedded in the struct: Swift's C importer
// drops fixed arrays this large, and a JNI caller copies out of one buffer anyway.)
#define BR_PAYMENT_URI_BUF_SIZE 16388   // 4 * (BR_PAYMENT_URI_MAX + 1): a literal, so Swift sees it
typedef char _BRPaymentUriBufSizeIsFourFields[(BR_PAYMENT_URI_BUF_SIZE == 4 * (BR_PAYMENT_URI_MAX + 1)) ? 1 : -1];

// Every text field points into the caller's buffer, is NUL-terminated, and is valid (empty when
// absent) for as long as that buffer is. Decoded fields may contain NUL bytes: use the length.
typedef struct {
    const char *address; size_t addressLen;   // as written, never decoded
    int hasAmount;
    int64_t amount;                           // satoshis
    int hasLabel;
    const char *label; size_t labelLen;       // decoded
    int hasMessage;
    const char *message; size_t messageLen;   // decoded
    int hasAsset;
    const char *assetId; size_t assetIdLen;   // decoded
    int64_t assetAmount;                      // the asset's raw units, > 0
} BRPaymentUri;

static inline int _BRUriIsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static inline int _BRUriHex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Percent-decodes s[0..len) into out (capacity BR_PAYMENT_URI_MAX + 1); returns the length.
static inline size_t _BRUriDecode(const char *s, size_t len, char *out)
{
    size_t i = 0, n = 0;

    while (i < len && n < BR_PAYMENT_URI_MAX) {
        int hi, lo;

        if (s[i] == '+') { out[n++] = ' '; i++; }
        else if (s[i] == '%' && i + 2 < len && (hi = _BRUriHex(s[i + 1])) >= 0 && (lo = _BRUriHex(s[i + 2])) >= 0) {
            out[n++] = (char)(hi << 4 | lo); i += 3;
        }
        else out[n++] = s[i++];      // a '%' without two hex digits after it is itself
    }
    out[n] = '\0';
    return n;
}

static inline int _BRUriBlank(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) if (! _BRUriIsSpace(s[i])) return 0;
    return 1;
}

// Kotlin's String.toLongOrNull in ASCII: an optional sign, then one or more digits, in range.
static inline int _BRUriParseInt64(const char *s, size_t len, int64_t *out)
{
    size_t i = 0;
    int negative = 0;
    uint64_t v = 0, limit;

    if (len == 0) return 0;
    if (s[0] == '+' || s[0] == '-') { negative = (s[0] == '-'); i = 1; if (len == 1) return 0; }
    limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    for (; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        if (v > (limit - (uint64_t)(s[i] - '0')) / 10) return 0;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    *out = negative ? (int64_t)(0 - v) : (int64_t)v;
    return 1;
}

// Parses text[0..len) into *uri, with the text fields in buf (bufLen >= BR_PAYMENT_URI_BUF_SIZE).
// Returns 1 for a request, 0 when the input is rejected or buf is too small.
static inline int BRPaymentUriParse(const char *text, size_t len, BRPaymentUri *uri, char *buf, size_t bufLen)
{
    static const char scheme[] = "digibyte:";
    const size_t schemeLen = sizeof(scheme) - 1;
    size_t start = 0, end = len, i, q, a0, a1;
    int seenAmount = 0, seenLabel = 0, seenMessage = 0, seenAssetId = 0, seenAssetAmount = 0;
    char key[BR_PAYMENT_URI_MAX + 1], amountText[BR_PAYMENT_URI_MAX + 1], assetAmountText[BR_PAYMENT_URI_MAX + 1];
    size_t keyLen, amountLen = 0, assetAmountLen = 0;
    char *fAddress, *fLabel, *fMessage, *fAssetId;   // writable views of the caller's buffer

    if (! uri) return 0;
    memset(uri, 0, sizeof(*uri));
    if (! buf || bufLen < BR_PAYMENT_URI_BUF_SIZE) return 0;
    fAddress = buf;
    fLabel = fAddress + (BR_PAYMENT_URI_MAX + 1);
    fMessage = fLabel + (BR_PAYMENT_URI_MAX + 1);
    fAssetId = fMessage + (BR_PAYMENT_URI_MAX + 1);
    fAddress[0] = fLabel[0] = fMessage[0] = fAssetId[0] = '\0';
    uri->address = fAddress; uri->label = fLabel; uri->message = fMessage; uri->assetId = fAssetId;
    if (! text || len > BR_PAYMENT_URI_MAX || memchr(text, '\0', len)) return 0;

    while (start < end && _BRUriIsSpace(text[start])) start++;
    while (end > start && _BRUriIsSpace(text[end - 1])) end--;
    if (start == end) return 0;
    text += start; len = end - start;

    int hasScheme = (len >= schemeLen && memcmp(text, scheme, schemeLen) == 0);
    for (i = 0; ! hasScheme && i + 3 <= len; i++) {
        if (text[i] == ':' && text[i + 1] == '/' && text[i + 2] == '/') return 0;   // a foreign scheme
    }
    if (! hasScheme) {                                     // a bare address
        memcpy(fAddress, text, len);
        fAddress[len] = '\0';
        uri->addressLen = len;
        return 1;
    }

    text += schemeLen; len -= schemeLen;
    for (q = 0; q < len && text[q] != '?'; q++);
    a0 = 0; a1 = q;
    while (a0 < a1 && _BRUriIsSpace(text[a0])) a0++;
    while (a1 > a0 && _BRUriIsSpace(text[a1 - 1])) a1--;
    if (a0 == a1) return 0;
    memcpy(fAddress, text + a0, a1 - a0);
    fAddress[a1 - a0] = '\0';
    uri->addressLen = a1 - a0;

    for (i = q + 1; i <= len && q < len; ) {
        size_t p = i, eq, pairEnd;
        while (p < len && text[p] != '&') p++;
        pairEnd = p;
        if (pairEnd > i) {
            for (eq = i; eq < pairEnd && text[eq] != '='; eq++);
            keyLen = _BRUriDecode(text + i, eq - i, key);
            const char *val = (eq < pairEnd) ? text + eq + 1 : text + pairEnd;
            size_t valLen = (eq < pairEnd) ? pairEnd - eq - 1 : 0;

            if (! _BRUriBlank(key, keyLen)) {
#ifdef PAYMENT_URI_UNFIXED
                // RED ARM SEAM (payment_uri_kat): the LAST occurrence of a key wins.
#define _BR_URI_TAKE(seen) 1
#else
#define _BR_URI_TAKE(seen) (! (seen))
#endif
                if (keyLen == 6 && memcmp(key, "amount", 6) == 0 && _BR_URI_TAKE(seenAmount)) {
                    seenAmount = 1; amountLen = _BRUriDecode(val, valLen, amountText);
                }
                else if (keyLen == 5 && memcmp(key, "label", 5) == 0 && _BR_URI_TAKE(seenLabel)) {
                    seenLabel = 1; uri->hasLabel = 1; uri->labelLen = _BRUriDecode(val, valLen, fLabel);
                }
                else if (keyLen == 7 && memcmp(key, "message", 7) == 0 && _BR_URI_TAKE(seenMessage)) {
                    seenMessage = 1; uri->hasMessage = 1; uri->messageLen = _BRUriDecode(val, valLen, fMessage);
                }
                else if (keyLen == 7 && memcmp(key, "assetId", 7) == 0 && _BR_URI_TAKE(seenAssetId)) {
                    seenAssetId = 1; uri->assetIdLen = _BRUriDecode(val, valLen, fAssetId);
                }
                else if (keyLen == 11 && memcmp(key, "assetAmount", 11) == 0 && _BR_URI_TAKE(seenAssetAmount)) {
                    seenAssetAmount = 1; assetAmountLen = _BRUriDecode(val, valLen, assetAmountText);
                }
            }
        }
        i = pairEnd + 1;
    }
#undef _BR_URI_TAKE

    {
        int haveId = seenAssetId && ! _BRUriBlank(uri->assetId, uri->assetIdLen);
        int haveQty = 0;
        int64_t qty = 0;

        if (seenAssetAmount) {
            if (! _BRUriParseInt64(assetAmountText, assetAmountLen, &qty)) {
#ifndef PAYMENT_URI_UNFIXED
                return 0;           // a quantity that is not one never reads as "no quantity"
#endif
            }
            else haveQty = 1;
        }
#ifdef PAYMENT_URI_UNFIXED
        // RED ARM SEAM: fail open. A half or malformed asset request degrades to a plain one.
        if (! (haveId && haveQty && qty > 0)) { haveId = haveQty = 0; uri->assetIdLen = 0; fAssetId[0] = '\0'; }
#else
        if (haveId != haveQty) return 0;
        if (haveQty && qty <= 0) return 0;
#endif
        if (haveId) { uri->hasAsset = 1; uri->assetAmount = qty; }
        else { uri->assetIdLen = 0; fAssetId[0] = '\0'; }
    }

    if (seenAmount && memchr(amountText, '\0', amountLen) == NULL)
        uri->hasAmount = BRAmountParseDGB(amountText, amountLen, &uri->amount);
    if (! uri->hasAmount) uri->amount = 0;
    return 1;
}

// Appends s percent-encoded (unreserved A-Z a-z 0-9 - _ . ~ kept, every other byte %XX).
static inline size_t _BRUriEncode(const char *s, size_t len, char *out, size_t at, size_t outLen)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        int keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '-' || c == '_' || c == '.' || c == '~';
        if (keep) { if (at + 1 >= outLen) return 0; out[at++] = (char)c; }
        else { if (at + 3 >= outLen) return 0; out[at++] = '%'; out[at++] = hex[c >> 4]; out[at++] = hex[c & 15]; }
    }
    return at;
}

static inline size_t _BRUriAppend(const char *s, char *out, size_t at, size_t outLen)
{
    size_t n = strlen(s);
    if (at + n >= outLen) return 0;
    memcpy(out + at, s, n);
    return at + n;
}

// Writes a payment request: "digibyte:<address>[?amount=<DGB>][&label=<encoded>]". amount is
// written only when hasAmount, as plain exact DGB text (BRAmountFormatDGB). label may be NULL.
// Returns the length written (excluding the NUL), or 0 if out is too small.
static inline size_t BRPaymentUriEncode(char *out, size_t outLen, const char *address,
                                        int hasAmount, int64_t sats, const char *label)
{
    size_t at = 0;
    char amount[32];
    int first = 1;

    if (! out || ! address) return 0;
    if (! (at = _BRUriAppend("digibyte:", out, at, outLen))) return 0;
    if (! (at = _BRUriAppend(address, out, at, outLen))) return 0;
    if (hasAmount) {
        if (! BRAmountFormatDGB(sats, amount, sizeof(amount))) return 0;
        if (! (at = _BRUriAppend("?amount=", out, at, outLen))) return 0;
        if (! (at = _BRUriAppend(amount, out, at, outLen))) return 0;
        first = 0;
    }
    if (label) {
        if (! (at = _BRUriAppend(first ? "?label=" : "&label=", out, at, outLen))) return 0;
        if (! (at = _BRUriEncode(label, strlen(label), out, at, outLen))) return 0;
    }
    out[at] = '\0';
    return at;
}

// Writes an asset transfer request: "digibyte:<address>?assetId=<encoded>&assetAmount=<n>
// [&label=<encoded>]". Separate from BRPaymentUriEncode so an asset request is never produced
// by accident, and the quantity never passes through the DGB decimal conversion. Returns 0
// (nothing written) for a quantity <= 0 or when out is too small.
static inline size_t BRPaymentUriEncodeAsset(char *out, size_t outLen, const char *address,
                                             const char *assetId, int64_t assetAmount, const char *label)
{
    size_t at = 0, n = 0;
    char qty[24], tmp[24];
    uint64_t v;

    if (! out || ! address || ! assetId || assetAmount <= 0) return 0;
    v = (uint64_t)assetAmount;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (size_t k = 0; k < n; k++) qty[k] = tmp[n - 1 - k];
    qty[n] = '\0';
    if (! (at = _BRUriAppend("digibyte:", out, at, outLen))) return 0;
    if (! (at = _BRUriAppend(address, out, at, outLen))) return 0;
    if (! (at = _BRUriAppend("?assetId=", out, at, outLen))) return 0;
    if (! (at = _BRUriEncode(assetId, strlen(assetId), out, at, outLen))) return 0;
    if (! (at = _BRUriAppend("&assetAmount=", out, at, outLen))) return 0;
    if (! (at = _BRUriAppend(qty, out, at, outLen))) return 0;
    if (label) {
        if (! (at = _BRUriAppend("&label=", out, at, outLen))) return 0;
        if (! (at = _BRUriEncode(label, strlen(label), out, at, outLen))) return 0;
    }
    out[at] = '\0';
    return at;
}

#ifdef __cplusplus
}
#endif

#endif // BRPaymentUri_h
