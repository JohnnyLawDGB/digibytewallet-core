//
//  BRAmountParse.h
//
//  DGB text <-> satoshis, EXACTLY. The amount a user types or a QR carries becomes the amount
//  on the wire, so both platforms must read the same text as the same number of satoshis.
//  Until 2026-10 the rule lived only in Kotlin (core/model/DgbAmount.kt); this is its C
//  source of truth, and the host KAT carries DgbAmountTest.kt's cases with its values.
//
//  Why exact: converting through a double read "0.29" as 28,999,999 sats, and one dust-coded
//  deposit (N.0000CCCC) in fifteen landed a satoshi low (reported 2026-09-07).
//
//  The rules (Android's):
//   - surrounding whitespace is ignored;
//   - a dot is the decimal point, and commas around it are grouping ("1,234.5");
//   - a LONE comma with no dot is the decimal point ("0,29": seven of the app's languages,
//     and the platform decimal keyboard, write it that way); several commas with no dot are
//     ambiguous and refused;
//   - EXCEPT that a lone comma (no dot) followed by EXACTLY three digits is ambiguous and
//     refused: "1,000" is one thousand to an English reader and one to a German one, and
//     "25,500" and "0,123" are read either way too. "Exactly three digits" is the run of ASCII
//     digits that starts right after the comma, in the text with its surrounding whitespace
//     already dropped: it is three long and the next character is not a digit, whatever that
//     character is (the end of the text, an exponent, anything else) and whatever comes before
//     the comma. So "1,000", " 1,000 ", "1,000e2", "1,000E-2", ",123" and "0,000" are refused;
//     "1,5", "0,29", "12,3456", "1,0000", "1,00e2" and "1," keep the comma as the point, and
//     "1,000.50" and "1,234,567.8" keep commas around a dot as grouping;
//   - the number follows java.math.BigDecimal's grammar: an optional sign, digits with an
//     optional point ("5", "5.", ".5"), an optional exponent ("1e2" is 100 DGB);
//   - more than eight decimals is refused, never rounded; trailing zeros do not count;
//   - a negative amount is refused; zero (including "-0") is 0, and the caller decides what
//     it means;
//   - the magnitude is bounded BEFORE any scaling, so "1e50000000" costs nothing.
//
//  Only ASCII whitespace and ASCII digits. Kotlin's trim() also takes Unicode spaces (the
//  no-break space, U+2000..U+200A, U+3000, ...); those are refused here. Non-ASCII decimal digits
//  (Arabic-Indic, Persian, Devanagari, full width) are refused here too, as they were by Kotlin's
//  String.toBigDecimalOrNull (it screens the text for ASCII digits before java.math.BigDecimal,
//  which alone would take them). The platforms map every Unicode decimal digit (category Nd) to
//  its ASCII digit BEFORE calling, exactly as they do for dollar text (BRUsdCentsParse): iOS
//  FiatText.asciiDigits, Android UsdCents.asciiDigits. The Arabic decimal and thousands
//  separators (U+066B, U+066C) are not mapped, so "\u0665\u066B\u0665" is no amount anywhere.
//
//  Host KAT: digibytewallet-android native/src/test/host/amount_parse_kat/.
//  Header-only, static inline; no allocation, no locale, no floating point.
//

#ifndef BRAmountParse_h
#define BRAmountParse_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_SATS_PER_DGB 100000000LL
#define BR_DGB_DECIMALS 8

static inline int _BRAmountIsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// Parses DGB text into *sats. Returns 1 on success, 0 when the text is not an amount.
// text need not be NUL-terminated; len is its length in bytes.
static inline int BRAmountParseDGB(const char *text, size_t len, int64_t *sats)
{
    size_t start = 0, end = len, commas = 0, dots = 0, i, nd = 0;
    int negative = 0, sawDigit = 0, sawPoint = 0, inExponent = 0, expNegative = 0, expDigits = 0, signAllowed = 1;
    char digits[24];              // significant digits; a valid amount never has more than 19
    int64_t pendingZeros = 0;     // zeros after the last nonzero digit, not yet known to be significant
    int64_t fracDigits = 0, exponent = 0;

    if (! text || ! sats) return 0;
    while (start < end && _BRAmountIsSpace(text[start])) start++;
    while (end > start && _BRAmountIsSpace(text[end - 1])) end--;
    if (start == end) return 0;

    for (i = start; i < end; i++) {
        if (text[i] == ',') commas++;
        else if (text[i] == '.') dots++;
    }

    // BigDecimal grammar: [+-] (digits [. digits*] | . digits) [(e|E) [+-] digits], read after
    // the one separator rule: commas are grouping around a point, a lone comma IS the point,
    // and several commas with no point, or a lone comma before exactly three digits, are
    // ambiguous.
    for (i = start; i < end; i++) {
        char c = text[i];

        if (c == ',') {
            if (dots > 0) continue;
            if (commas != 1) return 0;
            {
                size_t j = i + 1;
                while (j < end && text[j] >= '0' && text[j] <= '9') j++;
#ifndef AMOUNT_PARSE_COMMA_THOUSANDS_UNFIXED
                if (j - (i + 1) == 3) return 0;   // "1,000": a thousand or one? Refused.
#endif
            }
            c = '.';
        }
        if (inExponent) {
            if ((c == '+' || c == '-') && signAllowed) { expNegative = (c == '-'); signAllowed = 0; continue; }
            if (c < '0' || c > '9') return 0;
            signAllowed = 0;
            expDigits++;
            exponent = exponent * 10 + (c - '0');
            if (exponent > 2147483648LL) return 0;   // beyond an int exponent: BigDecimal refuses
            continue;
        }
        if ((c == '+' || c == '-') && signAllowed) { negative = (c == '-'); signAllowed = 0; continue; }
        signAllowed = 0;
        if (c >= '0' && c <= '9') {
            sawDigit = 1;
            if (sawPoint) fracDigits++;
            if (c == '0') {
                if (nd > 0) pendingZeros++;                // maybe trailing, maybe interior
            } else {
                while (pendingZeros > 0) {                  // they were interior: significant
                    if (nd >= sizeof(digits)) return 0;     // > 19 significant digits: never valid
                    digits[nd++] = '0';
                    pendingZeros--;
                }
                if (nd >= sizeof(digits)) return 0;
                digits[nd++] = c;
            }
        } else if (c == '.') {
            if (sawPoint) return 0;
            sawPoint = 1;
        } else if ((c == 'e' || c == 'E') && sawDigit) {
            inExponent = 1;
            signAllowed = 1;
        } else return 0;
    }
    if (! sawDigit) return 0;
    if (inExponent) {
        if (! expDigits) return 0;
        if (expNegative) exponent = -exponent;
        if (exponent > 2147483647LL || exponent < -2147483648LL) return 0;
    }
    // BigDecimal's scale (fraction digits minus exponent) must fit an int as well.
    if (fracDigits - exponent > 2147483647LL || fracDigits - exponent < -2147483648LL) return 0;

    if (nd == 0) { *sats = 0; return 1; }    // zero, "-0" included
    if (negative) return 0;

    // value = digits x 10^(pendingZeros + exponent - fracDigits); trailing zeros are not decimals.
    int64_t shift = pendingZeros + exponent - fracDigits + BR_DGB_DECIMALS;   // into satoshis
    if (shift < 0) return 0;                  // more than eight decimals: refused, not rounded
    if ((int64_t)nd + shift > 19) return 0;   // cannot fit a signed 64-bit count of satoshis

#ifdef AMOUNT_PARSE_VIA_DOUBLE_UNFIXED
    // RED-gate shape only: the old `(text.toDouble() * 1e8).toLong()`, on the same digits.
    // Never defined in a production build.
    {
        double v = 0;
        for (size_t k = 0; k < nd; k++) v = v * 10 + (digits[k] - '0');
        for (int64_t k = 0; k < shift - BR_DGB_DECIMALS; k++) v *= 10;
        for (int64_t k = shift; k < BR_DGB_DECIMALS; k++) v /= 10;
        *sats = (int64_t)(v * 1e8);
        return 1;
    }
#endif
    {
        uint64_t v = 0;
        for (size_t k = 0; k < nd; k++) {
            uint64_t d = (uint64_t)(digits[k] - '0');
            if (v > (UINT64_C(0x7fffffffffffffff) - d) / 10) return 0;
            v = v * 10 + d;
        }
        for (int64_t k = 0; k < shift; k++) {
            if (v > UINT64_C(0x7fffffffffffffff) / 10) return 0;
            v *= 10;
        }
        *sats = (int64_t)v;
        return 1;
    }
}

// Writes sats as plain decimal DGB text (no exponent, no grouping, no trailing zeros) into
// out. Returns the length written (excluding the NUL), or 0 if out is too small or sats < 0.
static inline size_t BRAmountFormatDGB(int64_t sats, char *out, size_t outLen)
{
    char tmp[32];
    size_t n = 0, len = 0;
    uint64_t whole, frac;
    int fd;

    if (! out || sats < 0) return 0;
    whole = (uint64_t)sats / BR_SATS_PER_DGB;
    frac = (uint64_t)sats % BR_SATS_PER_DGB;
    do { tmp[n++] = (char)('0' + whole % 10); whole /= 10; } while (whole);
    if (outLen < n + 1) return 0;
    while (n) out[len++] = tmp[--n];
    if (frac) {
        char f[BR_DGB_DECIMALS];
        for (fd = BR_DGB_DECIMALS - 1; fd >= 0; fd--) { f[fd] = (char)('0' + frac % 10); frac /= 10; }
        fd = BR_DGB_DECIMALS;
        while (fd > 0 && f[fd - 1] == '0') fd--;
        if (outLen < len + 1 + (size_t)fd + 1) return 0;
        out[len++] = '.';
        for (int k = 0; k < fd; k++) out[len++] = f[k];
    }
    out[len] = '\0';
    return len;
}

#ifdef __cplusplus
}
#endif

#endif // BRAmountParse_h
