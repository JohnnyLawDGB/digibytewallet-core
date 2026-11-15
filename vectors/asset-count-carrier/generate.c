// Vectors for BRAssetHoldings.h's count-side carrier answer (BRAssetRowCarrierOf): the header's own answers on
// a fixed corpus of real transactions, so a platform that keeps a count rule of its own (Android's
// AssetManager.carrierCreditRefusal, which its host-JVM tests run; or a Swift reading of it) can be held to the
// core without loading it. These are the header written down, not independent answers; the host KAT
// asset_holdings_kat holds the header to the Kotlin tests' own expectations and checks this file is current.
//
// THE RULE these hold (DA-014-REF, the count side): a row counts only when its funding transaction's carrier,
// read by the one carrier rule (BRTxAssetCarrier; Kotlin: DigiAssetCarrierRule.verdict), is DA_TX_CARRIER, the
// transaction carries no DigiDollar marking, the row's output is one of its outputs and not OP_RETURN, and the
// carrier's instructions can deliver there (BRAssetTargetsOutput, the units that came in unknown).
//
// The corpus, in the order it is written:
//   1. count-rule: AssetCarrierCountRuleTest's funding transactions, value for value (its output lines' amounts
//      and scripts; one input, or the test's own input count). The generator checks each answer the Kotlin test
//      states and writes nothing when one differs;
//   2. one-family and edges: a carrier beside a DigiDollar OP_RETURN in either form DigiByte Core's
//      FindDDOpReturn accepts (OP_RETURN OP_DIGIDOLLAR, or a first push "DD"), each written so that it is not
//      nulldata and the carrier stays the only nulldata output; a plain transaction; a row at the carrier itself;
//   3. da-carrier: every case of vectors/da-carrier/vectors.txt (its first argument), built as a transaction
//      with that case's input count and amounts. The generator checks that a case the file calls NONE answers
//      none at every output, one it calls UNDECIDED answers undecided at every output, and one it calls
//      CARRIER:<i> answers data-output at <i>.
//
// Each transaction is version 1, so the nVersion DigiDollar marker never applies here: these are the answers a
// reading of the scripts alone (the Kotlin's) gives too.
//
// THE FILE. Text, one transaction a line, fields separated by one space. A line that starts with '#' is a
// comment.
//
//   count <name> <tx> <answer for vout 0> ... <answer for vout n-1> <answer for vout n>
//     <tx>       the transaction's bytes, lower-case hex, as BRTransactionParseSigned reads them; the row's
//                txid is that transaction's hash;
//     <answer>   credits | unreadable | none | undecided | digidollar | no-such-output | data-output |
//                not-targeted   (BR_ASSET_ROW_CARRIER_*; Kotlin: null and the carrier:<reason> strings)
//   One answer for each output and one more for the vout one past the last.
//
// Build (it calls BRDigiAsset.c's carrier rule, BRDigiDollar.c's marking and the parser): with the core's
// objects, as asset_holdings_kat's run.sh does, then
//   ./gen vectors/da-carrier/vectors.txt > vectors/asset-count-carrier/vectors.txt
// It exits 1, writing nothing, when a check fails, a case does not fit its buffers or the da-carrier file
// cannot be read.
//

#include "BRAssetHoldings.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TXCAP 8192
#define OMAX 8
#define SMAX 300
#define OUTCAP (1 << 20)

static char OUT[OUTCAP];
static size_t OUTN = 0;
static int BAD = 0;

static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// strtok_r is POSIX, not C99, and a -std=c99 build on glibc does not declare it: a C99 one.
static char *_tok(char *s, const char *delim, char **save)
{
    char *end;

    if (! s) s = *save;
    s += strspn(s, delim);
    if (*s == '\0') { *save = s; return NULL; }
    end = s + strcspn(s, delim);
    if (*end != '\0') *end++ = '\0';
    *save = end;
    return s;
}

static void emit(const char *fmt, ...)
{
    va_list ap;
    int k;

    va_start(ap, fmt);
    k = vsnprintf(OUT + OUTN, OUTCAP - OUTN, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= OUTCAP - OUTN) { fprintf(stderr, "output buffer full\n"); BAD = 1; return; }
    OUTN += (size_t)k;
}

static void fail(const char *name, const char *why)
{
    fprintf(stderr, "%s: %s\n", name, why);
    BAD = 1;
}

typedef struct { uint8_t b[TXCAP]; size_t n; int bad; } Buf;

static void put8(Buf *o, uint8_t v) { if (o->n < TXCAP) o->b[o->n++] = v; else o->bad = 1; }
static void putLE32(Buf *o, uint32_t v) { int i; for (i = 0; i < 4; i++) put8(o, (uint8_t)(v >> (8 * i))); }

static int hexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// hex -> bytes; (size_t)-1 when it is not whole hex or does not fit
static size_t hx(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0, len = strlen(hex);

    if (len % 2) return (size_t)-1;
    for (; *hex; hex += 2) {
        int hi = hexDigit(hex[0]), lo = hexDigit(hex[1]);
        if (hi < 0 || lo < 0 || n >= cap) return (size_t)-1;
        out[n++] = (uint8_t)(hi * 16 + lo);
    }
    return n;
}

typedef struct { uint64_t amount; uint8_t script[SMAX]; size_t len; } TOut;

static const char *const PREVS[4] = { "1010101010101010101010101010101010101010101010101010101010101010",
                                      "2020202020202020202020202020202020202020202020202020202020202020",
                                      "3030303030303030303030303030303030303030303030303030303030303030",
                                      "4040404040404040404040404040404040404040404040404040404040404040" };

// A version-1 transaction: inputs spending PREVS[k]:k with empty scriptSigs, the outputs, lock time 0.
static void txBuild(Buf *o, size_t nIn, const TOut *outs, size_t nOut)
{
    size_t i, j;

    memset(o, 0, sizeof(*o));
    putLE32(o, 1);
    put8(o, (uint8_t)nIn);
    for (i = 0; i < nIn; i++) {
        uint8_t h[32];
        if (hx(PREVS[i], h, sizeof(h)) != 32) { o->bad = 1; return; }
        for (j = 0; j < 32; j++) put8(o, h[31 - j]);   // display order -> internal
        putLE32(o, (uint32_t)i);
        put8(o, 0x00);
        putLE32(o, 0xffffffffu);
    }
    put8(o, (uint8_t)nOut);
    for (i = 0; i < nOut; i++) {
        for (j = 0; j < 8; j++) put8(o, (uint8_t)(outs[i].amount >> (8 * j)));
        if (outs[i].len < 0xfd) put8(o, (uint8_t)outs[i].len);
        else { put8(o, 0xfd); put8(o, (uint8_t)outs[i].len); put8(o, (uint8_t)(outs[i].len >> 8)); }
        for (j = 0; j < outs[i].len; j++) put8(o, outs[i].script[j]);
    }
    putLE32(o, 0);
}

static int outOf(TOut *t, const char *scriptHex, uint64_t amount)
{
    size_t n = hx(scriptHex, t->script, sizeof(t->script));

    if (n == (size_t)-1) return 0;
    t->len = n;
    t->amount = amount;
    return 1;
}

static const char *answerName(BRAssetRowCarrier a)
{
    switch (a) {
    case BR_ASSET_ROW_CARRIER_UNREADABLE: return "unreadable";
    case BR_ASSET_ROW_CARRIER_CREDITS: return "credits";
    case BR_ASSET_ROW_CARRIER_NONE: return "none";
    case BR_ASSET_ROW_CARRIER_UNDECIDED: return "undecided";
    case BR_ASSET_ROW_CARRIER_DIGIDOLLAR: return "digidollar";
    case BR_ASSET_ROW_CARRIER_NO_SUCH_OUTPUT: return "no-such-output";
    case BR_ASSET_ROW_CARRIER_DATA_OUTPUT: return "data-output";
    case BR_ASSET_ROW_CARRIER_NOT_TARGETED: return "not-targeted";
    case BR_ASSET_ROW_CARRIER_NOT_FUNDING: return "not-funding";
    }
    return "?";
}

// The header's answer for every vout of the built transaction (and one past the last) into answers[], and the
// line for them. Returns the number of answers, 0 on a build failure.
static size_t countLine(const char *name, const Buf *b, BRAssetRowCarrier *answers)
{
    static const char digits[] = "0123456789abcdef";
    BRTransaction *tx;
    BRAssetRow row;
    char txid[BR_ASSET_TXID_LENGTH + 1];
    size_t i, n;

    if (b->bad) { fail(name, "the transaction does not fit its buffer"); return 0; }
    tx = BRTransactionParseSigned(b->b, b->n);
    if (! tx) { fail(name, "the built transaction does not parse"); return 0; }
    for (i = 0; i < 32; i++) {
        txid[2 * i] = digits[tx->txHash.u8[31 - i] >> 4];
        txid[2 * i + 1] = digits[tx->txHash.u8[31 - i] & 0x0f];
    }
    txid[BR_ASSET_TXID_LENGTH] = '\0';
    memset(&row, 0, sizeof(row));
    row.txid = txid;
    row.isAsset = 1;
    n = tx->outCount + 1;
    for (i = 0; i < n; i++) {
        row.vout = (int32_t)i;
        answers[i] = BRAssetRowCarrierOf(&row, tx);
    }
    BRTransactionFree(tx);

    emit("count %s ", name);
    for (i = 0; i < b->n; i++) emit("%02x", b->b[i]);
    for (i = 0; i < n; i++) emit(" %s", answerName(answers[i]));
    emit("\n");
    return n;
}

// ---- 1. AssetCarrierCountRuleTest ---------------------------------------------------------------

#define OURS            "0014" "1111111111111111111111111111111111111111"
#define TRANSFER_TEN    "6a0644410115000a"          // transfer, 10 units to output 0
#define PLAIN           "6a04deadbeef"
#define ISSUANCE_TEN    "6a06444103050a10"          // issuance of 10, no instructions
#define ISSUANCE_ALL_0  "6a0844410305" "0a" "000a" "10"   // v3 issuance of 10, all to output 0
#define RANGE_TO_TWO    "6a07444101154002" "0a"     // transfer, one range instruction: 10 over outputs 0..2
#define TWO_INSTR       "6a08444101150005" "0205"   // transfer: 5 to output 0, 5 to output 2

typedef struct { uint64_t amount; const char *script; } Line;

// One test's funding transaction from its output lines, with `inputs` inputs; want[v] is the answer the test
// states for vout v, or -1 where it states none.
static void ruleCase(const char *name, const Line *lines, size_t n, size_t inputs, const int *want)
{
    TOut outs[OMAX];
    BRAssetRowCarrier got[OMAX + 1];
    Buf b;
    size_t i, k;

    for (i = 0; i < n; i++) if (! outOf(&outs[i], lines[i].script, lines[i].amount)) { fail(name, "bad script"); return; }
    txBuild(&b, inputs, outs, n);
    k = countLine(name, &b, got);
    for (i = 0; i < k && i <= n; i++) {
        if (want[i] >= 0 && (int)got[i] != want[i]) fail(name, "the Kotlin test states another answer");
    }
}

#define CR BR_ASSET_ROW_CARRIER_CREDITS
#define UD BR_ASSET_ROW_CARRIER_UNDECIDED
#define NT BR_ASSET_ROW_CARRIER_NOT_TARGETED
#define DO BR_ASSET_ROW_CARRIER_DATA_OUTPUT
#define NS BR_ASSET_ROW_CARRIER_NO_SUCH_OUTPUT
#define DD BR_ASSET_ROW_CARRIER_DIGIDOLLAR
#define NO BR_ASSET_ROW_CARRIER_NONE

static void countRuleCases(void)
{
    static const Line phantom[] = { { 700, OURS }, { 0, TRANSFER_TEN }, { 0, PLAIN } };
    static const Line genuine[] = { { 700, OURS }, { 0, TRANSFER_TEN } };
    static const Line remainder[] = { { 700, OURS }, { 0, TRANSFER_TEN }, { 700, OURS } };
    static const Line notTargeted[] = { { 700, OURS }, { 700, OURS }, { 0, TRANSFER_TEN }, { 700, OURS } };
    static const Line issuanceMarker[] = { { 0, ISSUANCE_TEN }, { 700, OURS }, { 700, OURS } };
    static const Line issuanceAllToZero[] = { { 700, OURS }, { 0, ISSUANCE_ALL_0 }, { 700, OURS }, { 700, OURS } };
    static const Line range[] = { { 700, OURS }, { 700, OURS }, { 700, OURS }, { 700, OURS }, { 0, RANGE_TO_TWO }, { 700, OURS } };
    static const Line twoInstr[] = { { 700, OURS }, { 700, OURS }, { 700, OURS }, { 0, TWO_INSTR }, { 700, OURS } };
    static const Line encryptedKey[] = { { 650, OURS }, { 0, TRANSFER_TEN }, { 700, OURS } };
    static const int wPhantom[] = { UD, UD, UD, UD };
    static const int wGenuine[] = { CR, DO, NS };
    static const int wRemainder[] = { CR, DO, CR, NS };
    static const int wNotTargeted[] = { CR, NT, DO, CR, NS };
    static const int wIssuanceMarker[] = { DO, CR, -1, NS };
    static const int wIssuanceAllToZero[] = { CR, DO, NT, -1, NS };
    static const int wRange[] = { CR, CR, CR, NT, DO, CR, NS };
    static const int wTwoInstr[] = { CR, NT, CR, DO, CR, NS };
    static const int wEncryptedKey[] = { UD, UD, UD, UD };
    static const int wTwoInputs[] = { CR, DO, -1, NS };

    emit("# 1. AssetCarrierCountRuleTest\n");
    ruleCase("count_rule_undecided_funding", phantom, 3, 1, wPhantom);
    ruleCase("count_rule_genuine", genuine, 2, 1, wGenuine);
    ruleCase("count_rule_remainder_last_output", remainder, 3, 1, wRemainder);
    ruleCase("count_rule_not_targeted", notTargeted, 4, 1, wNotTargeted);
    ruleCase("count_rule_issuance_marker", issuanceMarker, 3, 1, wIssuanceMarker);
    ruleCase("count_rule_issuance_all_to_zero", issuanceAllToZero, 4, 1, wIssuanceAllToZero);
    ruleCase("count_rule_range_transfer", range, 6, 1, wRange);
    ruleCase("count_rule_two_instructions", twoInstr, 5, 1, wTwoInstr);
    ruleCase("count_rule_encrypted_key_shape", encryptedKey, 3, 1, wEncryptedKey);
    ruleCase("count_rule_encrypted_key_two_inputs", encryptedKey, 3, 2, wTwoInputs);
}

// ---- 2. one-family and edges --------------------------------------------------------------------

static void edgeCases(void)
{
    static const Line ddOpcode[] = { { 700, OURS }, { 0, TRANSFER_TEN }, { 0, "6abb" } };
    static const Line ddPush[] = { { 700, OURS }, { 0, TRANSFER_TEN }, { 0, "6a02444476" } };
    static const Line ddFirst[] = { { 0, "6abb" }, { 700, OURS }, { 0, TRANSFER_TEN } };
    static const Line plain[] = { { 700, OURS }, { 0, PLAIN } };
    static const Line issuanceAtCarrier[] = { { 0, ISSUANCE_TEN }, { 700, OURS } };
    static const int wDd[] = { DD, DD, DD, DD };
    static const int wPlain[] = { NO, NO, NO };
    static const int wIssuanceAtCarrier[] = { DO, CR, NS };

    emit("# 2. one-family and edges\n");
    ruleCase("one_family_op_digidollar", ddOpcode, 3, 1, wDd);
    ruleCase("one_family_dd_push", ddPush, 3, 1, wDd);
    ruleCase("one_family_op_digidollar_first", ddFirst, 3, 1, wDd);
    ruleCase("edge_plain_transaction", plain, 2, 1, wPlain);
    ruleCase("edge_issuance_at_carrier", issuanceAtCarrier, 2, 1, wIssuanceAtCarrier);
}

// ---- 3. vectors/da-carrier ------------------------------------------------------------------------

static void daCarrierCases(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[4096];
    int cases = 0;

    if (! f) { fail(path, "cannot be read"); return; }
    emit("# 3. vectors/da-carrier, each case built with its input count and amounts\n");
    while (fgets(line, sizeof(line), f)) {
        char *tok, *save = NULL, name[128], expected[32], full[160];
        TOut outs[OMAX];
        uint64_t amts[OMAX];
        BRAssetRowCarrier got[OMAX + 1];
        size_t nOut = 0, nAmt = 0, nIn = 2, i, k;
        int hasAmt = 0;
        Buf b;

        if (strncmp(line, "v ", 2) != 0) continue;
        line[strcspn(line, "\r\n")] = '\0';
        tok = _tok(line + 2, " ", &save);
        if (! tok || strlen(tok) >= sizeof(name)) { fail(path, "a case without a name"); break; }
        strcpy(name, tok);
        tok = _tok(NULL, " ", &save);
        if (! tok || strlen(tok) >= sizeof(expected)) { fail(name, "no expected verdict"); break; }
        strcpy(expected, tok);
        while ((tok = _tok(NULL, " ", &save))) {
            if (strncmp(tok, "in=", 3) == 0) { nIn = (size_t)strtoul(tok + 3, NULL, 10); continue; }
            if (strncmp(tok, "amt=", 4) == 0) {
                char *a = tok + 4, *s2 = NULL, *x;
                hasAmt = 1;
                for (x = _tok(a, ",", &s2); x && nAmt < OMAX; x = _tok(NULL, ",", &s2)) amts[nAmt++] = strtoull(x, NULL, 10);
                continue;
            }
            if (nOut >= OMAX || ! outOf(&outs[nOut], tok, 700)) { fail(name, "an output that does not fit"); goto done; }
            nOut++;
        }
        if (nIn < 1 || nIn > 4) { fail(name, "an input count this generator does not build"); goto done; }
        if (hasAmt) {
            if (nAmt != nOut) { fail(name, "amounts and outputs differ in number"); goto done; }
            for (i = 0; i < nOut; i++) outs[i].amount = amts[i];
        }
        txBuild(&b, nIn, outs, nOut);
        snprintf(full, sizeof(full), "da_carrier_%s", name);
        k = countLine(full, &b, got);
        cases++;
        if (strcmp(expected, "NONE") == 0 || strcmp(expected, "UNDECIDED") == 0) {
            BRAssetRowCarrier want = (expected[0] == 'N') ? NO : UD;
            for (i = 0; i < k; i++) if (got[i] != want) fail(full, "every output of a NONE or UNDECIDED case answers it");
        } else if (strncmp(expected, "CARRIER:", 8) == 0) {
            size_t idx = (size_t)strtoul(expected + 8, NULL, 10);
            if (idx >= k || got[idx] != DO) fail(full, "a CARRIER case's carrier output answers data-output");
        } else fail(full, "an expected verdict this generator does not read");
    }
done:
    fclose(f);
    if (! BAD && cases < 40) fail(path, "fewer da-carrier cases than the file holds");
}

int main(int argc, char **argv)
{
    const char *daCarrier = argc > 1 ? argv[1] : "vectors/da-carrier/vectors.txt";

    emit("# BRAssetHoldings.h count-side carrier vectors (BRAssetRowCarrierOf): the header's answers on real\n");
    emit("# transactions, written down. Generated by vectors/asset-count-carrier/generate.c, which describes each\n");
    emit("# field; do not edit (asset_holdings_kat checks it). The row's txid is the transaction's hash.\n");
    emit("# count <name> <tx hex> <answer for vout 0> ... <answer for vout n>   (n = the output count)\n");
    countRuleCases();
    edgeCases();
    daCarrierCases(daCarrier);
    if (BAD) return 1;
    fwrite(OUT, 1, OUTN, stdout);
    return 0;
}
