//
//  BRFiatAmount.h
//
//  Dollar text <-> cents, and cents <-> satoshis at a market rate, EXACTLY. The C source of
//  truth for Android's core/model/UsdCents.kt, which keeps a Kotlin mirror tied to this header
//  by a parity test (docs/ios-port/push-down-recipe.md in digibytewallet-android). The host KAT
//  carries UsdCentsTest.kt's cases with its values.
//
//  What is exact, and what is not:
//   - Amounts are integers on both sides: cents (int64) and satoshis (int64). Nothing here
//     holds an amount in binary floating point.
//   - The RATE arrives as a double (a price feed's JSON number). BRFiatRateFromDouble is the
//     ONE floating-point step in this header: it turns the double into the decimal Kotlin's
//     BigDecimal.valueOf(double) reads from it (the shortest decimal that reads back as the same
//     double), and from then on the rate is digits x 10^exp, an exact decimal.
//   - Conversions multiply and divide that decimal exactly in a fixed-width integer bignum
//     (32-bit limbs, 64-bit intermediates: no __int128, because Android ships armeabi-v7a), and
//     round once, HALF_EVEN, as Kotlin's setScale/divide(..., HALF_EVEN) does.
//   - Every magnitude is bounded BEFORE it is scaled, so an absurd rate (1e308, 5e-324) costs
//     a comparison, never a loop over hundreds of powers of ten.
//
//  The dollar text rules (Android's UsdCents.parse):
//   - surrounding ASCII whitespace is ignored;
//   - separators are read by the DGB amount rule (BRAmountParse.h): a dot is the decimal point
//     and commas around it are grouping; a LONE comma with no dot is the decimal point; several
//     commas with no dot are ambiguous and refused;
//   - after that only digits and one point: no sign, no exponent, no "NaN";
//   - at most two decimals may be TYPED ("1.0000" is refused, like "1.005"); never rounded;
//   - at most 32 characters once grouping commas are dropped, checked before anything is built.
//
//  Where this deliberately differs from Kotlin:
//   - only ASCII whitespace and ASCII digits, as in BRAmountParse.h. Kotlin's trim() and
//     isDigit() also accept Unicode spaces (NBSP, U+001C..U+001F) and non-ASCII decimal digits;
//     those are refused here, and a platform that wants them maps them to ASCII first.
//   - the rate's decimal is the one JDK 19+ Double.toString specifies (shortest that reads back,
//     closest to the double among those, at least two digits). Older runtimes (JDK 17's
//     FloatingDecimal, which the JVM unit tests run on) sometimes print a longer decimal, and for
//     a rare double that decimal is a different value. A rate a price feed sends (a handful of
//     significant digits) is printed identically by both; a parity test should use such rates.
//   - BRFiatCentsForSats / BRFiatSatsForCents refuse a negative amount; Kotlin never passes one
//     (its amounts come from parsers that refuse negatives).
//
//  No I/O, no allocation, no setlocale. snprintf/strtod are used only inside
//  BRFiatRateFromDouble and are made independent of the C locale's decimal point: the digits are
//  read from "%.*e" output skipping whatever radix character the locale prints, and the
//  round-trip check feeds strtod a string with no radix character at all ("612e-5").
//
//  Host KAT: digibytewallet-android native/src/test/host/fiat_amount_kat/.
//  Header-only, static inline.
//

#ifndef BRFiatAmount_h
#define BRFiatAmount_h

#include "BRAmountParse.h"
#include <float.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_USD_DECIMALS 2
#define BR_USD_CENTS_MAX_TEXT 32      // longer than any text that fits an int64 of cents
#define BR_FIAT_TEXT_BUFSIZE 32       // fits every string the functions below write, NUL included

// A positive exact decimal rate: digits x 10^exp, digits > 0 with no trailing zeros. For a price
// in dollars per DGB, from BRFiatRateFromDouble.
typedef struct {
    uint64_t digits;
    int32_t exp;
} BRFiatRate;

// ---- exact integer arithmetic ----------------------------------------------------------------

#define _BR_FIAT_LIMBS 12             // 384 bits: the bounds below never need more than 2^258

typedef struct { uint32_t w[_BR_FIAT_LIMBS]; } _BRFiatBig;

static inline void _BRFiatBigSet(_BRFiatBig *b, uint64_t v)
{
    for (int i = 0; i < _BR_FIAT_LIMBS; i++) b->w[i] = 0;
    b->w[0] = (uint32_t)v;
    b->w[1] = (uint32_t)(v >> 32);
}

// b *= m; returns 0 if the product does not fit.
static inline int _BRFiatBigMulSmall(_BRFiatBig *b, uint32_t m)
{
    uint64_t carry = 0;
    for (int i = 0; i < _BR_FIAT_LIMBS; i++) {
        uint64_t t = (uint64_t)b->w[i] * m + carry;
        b->w[i] = (uint32_t)t;
        carry = t >> 32;
    }
    return carry == 0;
}

// b *= m (64-bit); returns 0 if the product does not fit.
static inline int _BRFiatBigMul64(_BRFiatBig *b, uint64_t m)
{
    _BRFiatBig hi = *b;
    uint64_t carry = 0;
    if (! _BRFiatBigMulSmall(b, (uint32_t)m)) return 0;
    if (! _BRFiatBigMulSmall(&hi, (uint32_t)(m >> 32))) return 0;
    if (hi.w[_BR_FIAT_LIMBS - 1] != 0) return 0;               // shifting it a limb would overflow
    for (int i = 1; i < _BR_FIAT_LIMBS; i++) {                  // b += hi << 32
        uint64_t t = (uint64_t)b->w[i] + hi.w[i - 1] + carry;
        b->w[i] = (uint32_t)t;
        carry = t >> 32;
    }
    return carry == 0;
}

static inline int _BRFiatBigMulPow10(_BRFiatBig *b, int64_t n)
{
    for (int64_t i = 0; i < n; i++) if (! _BRFiatBigMulSmall(b, 10)) return 0;
    return 1;
}

static inline int _BRFiatBigCmp(const _BRFiatBig *a, const _BRFiatBig *b)
{
    for (int i = _BR_FIAT_LIMBS - 1; i >= 0; i--) {
        if (a->w[i] != b->w[i]) return a->w[i] < b->w[i] ? -1 : 1;
    }
    return 0;
}

static inline void _BRFiatBigSub(_BRFiatBig *a, const _BRFiatBig *b)   // a -= b, a >= b
{
    uint64_t borrow = 0;
    for (int i = 0; i < _BR_FIAT_LIMBS; i++) {
        uint64_t t = (uint64_t)a->w[i] - b->w[i] - borrow;
        a->w[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
}

static inline void _BRFiatBigShl1(_BRFiatBig *a, int bit)   // a = 2a + bit; callers keep a < 2^383
{
    for (int i = _BR_FIAT_LIMBS - 1; i > 0; i--) a->w[i] = (a->w[i] << 1) | (a->w[i - 1] >> 31);
    a->w[0] = (a->w[0] << 1) | (uint32_t)(bit & 1);
}

static inline int _BRFiatBigBits(const _BRFiatBig *a)
{
    for (int i = _BR_FIAT_LIMBS - 1; i >= 0; i--) {
        if (a->w[i]) {
            int n = 32;
            while (! (a->w[i] >> (n - 1))) n--;
            return i * 32 + n;
        }
    }
    return 0;
}

// *out = HALF_EVEN(n / d) for d > 0. Returns 0 when the rounded quotient exceeds INT64_MAX.
static inline int _BRFiatDivHalfEven(const _BRFiatBig *n, const _BRFiatBig *d, int64_t *out)
{
    _BRFiatBig rem;
    uint64_t q = 0;
    int cmp;

    _BRFiatBigSet(&rem, 0);
    for (int i = _BRFiatBigBits(n) - 1; i >= 0; i--) {          // restoring binary long division
        int bit = (int)((n->w[i / 32] >> (i % 32)) & 1), qbit = 0;
        _BRFiatBigShl1(&rem, bit);
        if (_BRFiatBigCmp(&rem, d) >= 0) { _BRFiatBigSub(&rem, d); qbit = 1; }
        if (q > (UINT64_C(0x7fffffffffffffff) - (uint64_t)qbit) / 2) return 0;   // q only grows
        q = 2 * q + (uint64_t)qbit;
    }
    _BRFiatBigShl1(&rem, 0);                                    // compare 2 x remainder with d
    cmp = _BRFiatBigCmp(&rem, d);
    if (cmp > 0 || (cmp == 0 && (q & 1))) {
        if (q == UINT64_C(0x7fffffffffffffff)) return 0;
        q++;
    }
    *out = (int64_t)q;
    return 1;
}

// *out = HALF_EVEN(a x b x 10^p / c), with a, b, c > 0. Returns 0 when it exceeds INT64_MAX.
static inline int _BRFiatScaledRatio(uint64_t a, uint64_t b, uint64_t c, int64_t p, int64_t *out)
{
    _BRFiatBig n, d;

    _BRFiatBigSet(&n, a);
    if (! _BRFiatBigMul64(&n, b)) return 0;                     // a x b < 2^128
    _BRFiatBigSet(&d, c);
    if (p >= 0) {
        // a x b >= 1 and c < 2^64, so 10^40 / 2^64 > 5 x 10^20 already exceeds INT64_MAX.
        if (p >= 40) return 0;
        if (! _BRFiatBigMulPow10(&n, p)) return 0;              // < 2^128 x 10^39 < 2^258
    } else {
        // a x b < 2^128 < 10^39 and c >= 1, so dividing by 10^40 or more leaves < 0.1: zero.
        if (p <= -40) { *out = 0; return 1; }
        if (! _BRFiatBigMulPow10(&d, -p)) return 0;             // < 2^64 x 10^39 < 2^194
    }
    return _BRFiatDivHalfEven(&n, &d, out);
}

// ---- the rate: the one floating-point step ---------------------------------------------------

// Whether digits x 10^exp reads back as exactly x. The string carries no radix character, so the
// C locale's decimal point cannot change how strtod reads it.
static inline int _BRFiatReadsBackAs(uint64_t digits, int exp, double x)
{
    char buf[48], *end = NULL;
    snprintf(buf, sizeof(buf), "%llue%d", (unsigned long long)digits, exp);
    return strtod(buf, &end) == x && end && *end == '\0';
}

// x correctly rounded to n significant digits, as digits x 10^exp. "%.*e" prints one digit, the
// locale's radix character (which may be several bytes, or a comma), n - 1 digits, then e+XX.
static inline int _BRFiatRoundTo(double x, int n, uint64_t *digits, int *exp)
{
    char buf[64];
    const char *s = buf;
    uint64_t v = 0;
    int got = 0, e = 0, eNeg = 0;

    if (snprintf(buf, sizeof(buf), "%.*e", n - 1, x) <= 0) return 0;
    for (; *s && *s != 'e' && *s != 'E'; s++) {
        if (*s >= '0' && *s <= '9') { v = v * 10 + (uint64_t)(*s - '0'); got++; }
        // anything else is the radix character, whatever the locale made it
    }
    if (got != n || (*s != 'e' && *s != 'E')) return 0;
    s++;
    if (*s == '+' || *s == '-') eNeg = (*s++ == '-');
    if (*s < '0' || *s > '9') return 0;
    for (; *s >= '0' && *s <= '9'; s++) { e = e * 10 + (*s - '0'); if (e > 100000) return 0; }
    if (*s) return 0;
    *digits = v;
    *exp = (eNeg ? -e : e) - (n - 1);
    return 1;
}

// The exact decimal for a price, or 0 when the price is not usable (NaN, infinite, zero,
// negative). The decimal is the one JDK 19+ Double.toString, and so BigDecimal.valueOf(double),
// reads from the double: the fewest significant digits (1..17) that read back as that double;
// among those the closest to it; and when that is one digit, the closest two-digit decimal
// instead (so the smallest subnormal is 4.9e-324, not 5e-324).
//
// THE ONLY FLOATING-POINT CODE IN THIS HEADER. At each length the correctly rounded value is
// tried, then the next decimal up: the double's rounding interval is wider above than below only
// when it is a power of two, and that is the one case where the nearest decimal can fall outside
// it while the one above lies inside (2^-24 is 5.960464477539063e-08, not ...062).
static inline int BRFiatRateFromDouble(double price, BRFiatRate *rate)
{
    uint64_t digits = 0;
    int exp = 0, n, found = 0;

    if (! rate) return 0;
    if (! (price > 0) || price > DBL_MAX) return 0;    // NaN fails the first test, infinity the second

    for (n = 1; n <= 17 && ! found; n++) {
        if (! _BRFiatRoundTo(price, n, &digits, &exp)) return 0;
        if (_BRFiatReadsBackAs(digits, exp, price)) found = n;
        else if (_BRFiatReadsBackAs(digits + 1, exp, price)) { digits++; found = n; }
    }
    if (! found) return 0;                              // 17 digits always read back; never reached
    if (found == 1) {                                   // Double.toString prints at least two digits
        uint64_t d2;
        int e2;
        if (_BRFiatRoundTo(price, 2, &d2, &e2) && _BRFiatReadsBackAs(d2, e2, price)) { digits = d2; exp = e2; }
    }
    while (digits % 10 == 0) { digits /= 10; exp++; }
    rate->digits = digits;
    rate->exp = (int32_t)exp;
    return 1;
}

#ifdef FIAT_VIA_DOUBLE_UNFIXED
// RED-gate shape only: the rate back as the double it came from. Never in a production build.
static inline double _BRFiatRateAsDouble(BRFiatRate rate)
{
    char buf[48];
    snprintf(buf, sizeof(buf), "%llue%d", (unsigned long long)rate.digits, (int)rate.exp);
    return strtod(buf, NULL);
}
#endif

// ---- conversions -----------------------------------------------------------------------------

// Cents that sats buy at rate (dollars per DGB): HALF_EVEN(sats / 10^8 x rate x 100). Returns 1
// and sets *cents, or 0 when sats is negative, the rate is not positive, or the result does not
// fit an int64.
static inline int BRFiatCentsForSats(int64_t sats, BRFiatRate rate, int64_t *cents)
{
    if (! cents || sats < 0 || rate.digits == 0) return 0;
    if (sats == 0) { *cents = 0; return 1; }
#ifdef FIAT_VIA_DOUBLE_UNFIXED
    // RED-gate shape only: the naive double conversion, rounded half up.
    *cents = (int64_t)((double)sats / 1e8 * _BRFiatRateAsDouble(rate) * 100 + 0.5);
    return 1;
#endif
    return _BRFiatScaledRatio((uint64_t)sats, rate.digits, 1, (int64_t)rate.exp - 6, cents);
}

// Satoshis that cents buy at rate (dollars per DGB): HALF_EVEN(cents / 100 / rate x 10^8).
// Returns 1 and sets *sats, or 0 when cents is negative, the rate is not positive, or the result
// does not fit an int64.
static inline int BRFiatSatsForCents(int64_t cents, BRFiatRate rate, int64_t *sats)
{
    if (! sats || cents < 0 || rate.digits == 0) return 0;
    if (cents == 0) { *sats = 0; return 1; }
#ifdef FIAT_VIA_DOUBLE_UNFIXED
    // RED-gate shape only: the naive double conversion, rounded half up.
    *sats = (int64_t)((double)cents / 100 / _BRFiatRateAsDouble(rate) * 1e8 + 0.5);
    return 1;
#endif
    return _BRFiatScaledRatio((uint64_t)cents, 1, rate.digits, 6 - (int64_t)rate.exp, sats);
}

// ---- dollar text ------------------------------------------------------------------------------

// Parses dollar text into *cents. Returns 1 on success, 0 when the text is not a whole number of
// cents. text need not be NUL-terminated; len is its length in bytes. Zero is 0.
static inline int BRUsdCentsParse(const char *text, size_t len, int64_t *cents)
{
    size_t start = 0, end = len, commas = 0, dots = 0, i;
    int sawDigit = 0, sawPoint = 0, decimals = 0;
    uint64_t v = 0;

    if (! text || ! cents) return 0;
    while (start < end && _BRAmountIsSpace(text[start])) start++;
    while (end > start && _BRAmountIsSpace(text[end - 1])) end--;

    for (i = start; i < end; i++) {
        if (text[i] == ',') commas++;
        else if (text[i] == '.') dots++;
    }
    if (commas > 1 && dots == 0) return 0;                       // ambiguous
    // The length Kotlin bounds is the text after grouping commas are dropped.
    if (end - start - (dots > 0 ? commas : 0) == 0) return 0;
    if (end - start - (dots > 0 ? commas : 0) > BR_USD_CENTS_MAX_TEXT) return 0;

    for (i = start; i < end; i++) {
        char c = text[i];
        if (c == ',') {
            if (dots > 0) continue;                              // grouping
            c = '.';                                             // the lone comma is the point
        }
        if (c == '.') {
            if (sawPoint) return 0;
            sawPoint = 1;
        } else if (c >= '0' && c <= '9') {
            sawDigit = 1;
            if (sawPoint && ++decimals > BR_USD_DECIMALS) return 0;   // typed, so never rounded
            if (v > (UINT64_C(0x7fffffffffffffff) - (uint64_t)(c - '0')) / 10) return 0;
            v = v * 10 + (uint64_t)(c - '0');
        } else return 0;                                         // no sign, exponent, letters
    }
    if (! sawDigit) return 0;
    for (; decimals < BR_USD_DECIMALS; decimals++) {
        if (v > UINT64_C(0x7fffffffffffffff) / 10) return 0;
        v *= 10;
    }
    *cents = (int64_t)v;
    return 1;
}

// Writes cents as plain dollar text with exactly two decimals (no grouping, no exponent, no
// locale; "-0.05" for -5) into out. Returns the length written (excluding the NUL), or 0 when out
// is too small.
static inline size_t BRUsdCentsFormat(int64_t cents, char *out, size_t outLen)
{
    char tmp[24];
    size_t n = 0, len = 0;
    uint64_t mag = cents < 0 ? (uint64_t)0 - (uint64_t)cents : (uint64_t)cents;

    if (! out) return 0;
    tmp[n++] = (char)('0' + mag % 10); mag /= 10;
    tmp[n++] = (char)('0' + mag % 10); mag /= 10;
    tmp[n++] = '.';
    do { tmp[n++] = (char)('0' + mag % 10); mag /= 10; } while (mag);
    if (cents < 0) tmp[n++] = '-';
    if (outLen < n + 1) return 0;
    while (n) out[len++] = tmp[--n];
    out[len] = '\0';
    return len;
}

// ---- the send screen's two amount fields ------------------------------------------------------

// The dollars line shown beside typed DGB text (UsdCents.previewForDgb): the DGB text read by
// BRAmountParseDGB, the parser the send uses, converted at priceUsd and formatted. Writes "" and
// returns 0 when the text is not an amount, the price is not usable, the result does not fit, or
// out is too small; otherwise returns the length written.
static inline size_t BRFiatPreviewForDgb(const char *dgbText, size_t len, double priceUsd,
                                         char *out, size_t outLen)
{
    int64_t sats, cents;
    BRFiatRate rate;
    size_t n = 0;

    if (! out || outLen == 0) return 0;
    if (BRAmountParseDGB(dgbText, len, &sats) && BRFiatRateFromDouble(priceUsd, &rate) &&
        BRFiatCentsForSats(sats, rate, &cents)) n = BRUsdCentsFormat(cents, out, outLen);
    if (n == 0) out[0] = '\0';
    return n;
}

// The DGB amount typed dollar text buys, as amount-field text (UsdCents.dgbTextFor): plain
// decimals, never grouped, so it parses back to itself. Writes "" and returns 0 when the text is
// not a whole number of cents, the price is not usable, the result does not fit, or out is too
// small; otherwise returns the length written.
static inline size_t BRFiatDgbTextFor(const char *usdText, size_t len, double priceUsd,
                                      char *out, size_t outLen)
{
    int64_t cents, sats;
    BRFiatRate rate;
    size_t n = 0;

    if (! out || outLen == 0) return 0;
    if (BRUsdCentsParse(usdText, len, &cents) && BRFiatRateFromDouble(priceUsd, &rate) &&
        BRFiatSatsForCents(cents, rate, &sats)) n = BRAmountFormatDGB(sats, out, outLen);
    if (n == 0) out[0] = '\0';
    return n;
}

#ifdef __cplusplus
}
#endif

#endif // BRFiatAmount_h
