// Vectors for BRAssetProvenance.h's hop (BRAssetHopClassify): the header's own answers on a fixed corpus of
// real transactions, so a platform that keeps a hop of its own (Android's AssetManager.classifyProvenanceHopFrom,
// which its host-JVM tests run; or a Swift reading of it) can be held to the core without loading it. These are
// the header written down, not independent answers; the host KAT asset_provenance_rules_kat holds the header to
// the Kotlin tests' own expectations and to a line-for-line model of the Kotlin, and checks this file is current.
//
// THE RULE these hold (DA-014-REF): a hop reads a transaction's carrier by the one carrier rule, BRTxAssetCarrier
// (Kotlin: DigiAssetCarrierRule.verdict), never the first OP_RETURN. Only a DA_TX_CARRIER answer is decoded; a
// transaction the rule calls NONE or UNDECIDED is a dead end, so nothing is named or recorded from it.
//
// The corpus, in the order it is written:
//   1. carrier-rule: AssetProvenanceCarrierRuleTest's hops, value for value: the received transaction spends
//      a…a:0 and carries the test's output scripts (each output 0 sat). The generator checks each against the
//      Kotlin test's own expectation and writes nothing when one differs;
//   2. the shapes in which the first-OP_RETURN reading and the one rule disagree in the other direction: an
//      OP_RETURN that is not nulldata (6aff, 6a76) before the carrier is no carrier, so the carrier after it
//      decides;
//   3. da-carrier: every case of vectors/da-carrier/vectors.txt (its first argument), built as a transaction
//      with that case's input count and amounts. The generator checks that every case the file does not call
//      CARRIER is a dead end, and that every CARRIER whose carrier decodes as a transfer walks to the first
//      input's transaction.
//
// THE FILE. Text, one hop a line, fields separated by one space. A line that starts with '#' is a comment.
//
//   hop <name> <tx> <answer>
//     <tx>       the transaction's bytes, lower-case hex, as BRTransactionParseSigned reads them;
//     <answer>   dead-end
//                transfer <parentTxid>                      display order, lower case
//                issuance <assetId> <totalSupply> <divisibility> <cid or -> <opcode> <locked>
//
// No bytes (UNAVAILABLE) and bytes that do not parse (DEAD END) need no transaction and are not written.
//
// Build (it calls BRDigiAsset.c's carrier rule, the parser and BRAssetIdForIssuance): with the core's objects,
// as asset_provenance_rules_kat's run.sh does, then
//   ./gen vectors/da-carrier/vectors.txt > vectors/asset-provenance-hop/vectors.txt
// It exits 1, writing nothing, when a check fails, a case does not fit its buffers or the da-carrier file
// cannot be read.
//

#include "BRAssetProvenance.h"
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
#include <stdarg.h>

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

// A version-1 transaction: inputs spending prev[k] (display-order hex) : vout[k] with empty scriptSigs, the
// outputs, lock time `lock`.
static void txBuild(Buf *o, const char *const *prev, const uint32_t *vout, size_t nIn, const TOut *outs, size_t nOut,
                    uint32_t lock)
{
    size_t i, j;

    memset(o, 0, sizeof(*o));
    putLE32(o, 1);
    put8(o, (uint8_t)nIn);
    for (i = 0; i < nIn; i++) {
        uint8_t h[32];
        if (hx(prev[i], h, sizeof(h)) != 32) { o->bad = 1; return; }
        for (j = 0; j < 32; j++) put8(o, h[31 - j]);   // display order -> internal
        putLE32(o, vout[i]);
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
    putLE32(o, lock);
}

static int outOf(TOut *t, const char *scriptHex, uint64_t amount)
{
    size_t n = hx(scriptHex, t->script, sizeof(t->script));

    if (n == (size_t)-1) return 0;
    t->len = n;
    t->amount = amount;
    return 1;
}

// The header's hop on the built bytes, and the line for it. Returns the hop (kind DEAD_END on a build failure).
static BRAssetHop hopLine(const char *name, const Buf *b)
{
    BRTransaction *tx;
    BRAssetHop h;
    size_t i;

    memset(&h, 0, sizeof(h));
    h.kind = BR_ASSET_HOP_DEAD_END;
    if (b->bad) { fail(name, "the transaction does not fit its buffer"); return h; }
    tx = BRTransactionParseSigned(b->b, b->n);
    if (! tx) { fail(name, "the built transaction does not parse"); return h; }
    h = BRAssetHopClassify(1, tx);
    BRTransactionFree(tx);

    emit("hop %s ", name);
    for (i = 0; i < b->n; i++) emit("%02x", b->b[i]);
    switch (h.kind) {
    case BR_ASSET_HOP_DEAD_END: emit(" dead-end\n"); break;
    case BR_ASSET_HOP_TRANSFER: emit(" transfer %s\n", h.parentTxid); break;
    case BR_ASSET_HOP_ISSUANCE:
        emit(" issuance %s %lld %d %s %d %d\n", h.facts.assetId, (long long)h.facts.totalSupply, (int)h.facts.divisibility,
             h.facts.hasMetadataCid ? h.facts.metadataCid : "-", (int)h.facts.issuanceOpcode, h.facts.issuanceLocked);
        break;
    default: fail(name, "a parsed transaction's hop is UNAVAILABLE"); break;
    }
    return h;
}

// ---- 1. AssetProvenanceCarrierRuleTest ------------------------------------------------------------

#define ISSUANCE_TEN       "6a06444103050a10"   // locked issuance, 10 units, divisibility 0
#define ISSUANCE_TWENTY_D1 "6a06444103051430"   // locked issuance, 20 units, divisibility 1
#define TRANSFER           "6a0644410115000a"   // transfer, 10 units to output 0
#define PLAIN              "6a04deadbeef"
#define PAYEE             "0014" "1111111111111111111111111111111111111111"
#define PARENT_A           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

typedef enum { WANT_DEAD_END, WANT_TRANSFER_A, WANT_ISSUANCE_START } Want;

static void startCase(const char *name, const char *const *scripts, size_t n, Want want)
{
    const char *prev[1] = { PARENT_A };
    uint32_t vout[1] = { 0 };
    TOut outs[OMAX];
    Buf b;
    BRAssetHop h;
    size_t i;
    char id[BR_ASSET_ID_BUFFER];

    for (i = 0; i < n; i++) if (! outOf(&outs[i], scripts[i], 0)) { fail(name, "bad script"); return; }
    txBuild(&b, prev, vout, 1, outs, n, 1);   // the Kotlin test's tag 1 is the lock time
    h = hopLine(name, &b);
    switch (want) {
    case WANT_DEAD_END:
        if (h.kind != BR_ASSET_HOP_DEAD_END) fail(name, "the Kotlin test wants DeadEnd");
        break;
    case WANT_TRANSFER_A:
        if (h.kind != BR_ASSET_HOP_TRANSFER || strcmp(h.parentTxid, PARENT_A) != 0) fail(name, "the Kotlin test wants Transfer(a…a)");
        break;
    case WANT_ISSUANCE_START:
        // the Kotlin test's id is "derived from start's first input" (a…a:0), divisibility 0
        if (! BRAssetIdForIssuance(PARENT_A, 0, 1, BR_ASSET_AGGREGATABLE, 0, id, sizeof(id)) ||
            h.kind != BR_ASSET_HOP_ISSUANCE || strcmp(h.facts.assetId, id) != 0 || h.facts.totalSupply != 10 ||
            h.facts.divisibility != 0)
            fail(name, "the Kotlin test wants Issuance of start's own id, 10 units, divisibility 0");
        break;
    }
}

static void carrierRuleCases(void)
{
    static const char *earlierTransfer[] = { TRANSFER, ISSUANCE_TWENTY_D1, PAYEE };
    static const char *twoIssuances[] = { ISSUANCE_TEN, ISSUANCE_TWENTY_D1, PAYEE };
    static const char *plainFirst[] = { PLAIN, ISSUANCE_TEN, PAYEE };
    static const char *plainAfter[] = { ISSUANCE_TEN, PLAIN, PAYEE };
    static const char *single[] = { ISSUANCE_TEN, PAYEE };
    static const char *transfer[] = { TRANSFER, PAYEE };

    emit("# 1. AssetProvenanceCarrierRuleTest\n");
    startCase("carrier_rule_transfer_before_issuance", earlierTransfer, 3, WANT_DEAD_END);
    startCase("carrier_rule_two_issuance_carriers", twoIssuances, 3, WANT_DEAD_END);
    startCase("carrier_rule_plain_before_carrier", plainFirst, 3, WANT_DEAD_END);
    startCase("carrier_rule_plain_after_carrier", plainAfter, 3, WANT_DEAD_END);
    startCase("carrier_rule_no_outputs", NULL, 0, WANT_DEAD_END);
    startCase("carrier_rule_single_issuance", single, 2, WANT_ISSUANCE_START);
    startCase("carrier_rule_single_transfer", transfer, 2, WANT_TRANSFER_A);
}

// ---- 2. an OP_RETURN that is not nulldata before the carrier ---------------------------------------

static void nonNullDataCases(void)
{
    static const char *ffFirst[] = { "6aff", TRANSFER, PAYEE };
    static const char *nonPushFirst[] = { "6a76", ISSUANCE_TEN, PAYEE };
    static const char *truncatedFirst[] = { "6a05aabb", TRANSFER };

    emit("# 2. an OP_RETURN that is not nulldata is no carrier: the carrier after it decides\n");
    startCase("non_nulldata_6aff_before_transfer", ffFirst, 3, WANT_TRANSFER_A);
    startCase("non_nulldata_6a76_before_issuance", nonPushFirst, 3, WANT_ISSUANCE_START);
    startCase("truncated_push_before_transfer", truncatedFirst, 2, WANT_TRANSFER_A);
}

// ---- 3. vectors/da-carrier ------------------------------------------------------------------------

static void daCarrierCases(const char *path)
{
    static const char *prevs[4] = { "1010101010101010101010101010101010101010101010101010101010101010",
                                    "2020202020202020202020202020202020202020202020202020202020202020",
                                    "3030303030303030303030303030303030303030303030303030303030303030",
                                    "4040404040404040404040404040404040404040404040404040404040404040" };
    static const uint32_t vouts[4] = { 0, 1, 2, 3 };
    FILE *f = fopen(path, "r");
    char line[4096];
    int cases = 0;

    if (! f) { fail(path, "cannot be read"); return; }
    emit("# 3. vectors/da-carrier, each case built with its input count and amounts\n");
    while (fgets(line, sizeof(line), f)) {
        char *tok, *save = NULL, name[128], expected[32], full[160];
        TOut outs[OMAX];
        uint64_t amts[OMAX];
        size_t nOut = 0, nAmt = 0, nIn = 2, i;
        int hasAmt = 0;
        Buf b;
        BRAssetHop h;

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
        txBuild(&b, prevs, vouts, nIn, outs, nOut, 0);
        snprintf(full, sizeof(full), "da_carrier_%s", name);
        h = hopLine(full, &b);
        cases++;
        if (strncmp(expected, "CARRIER:", 8) != 0) {
            if (h.kind != BR_ASSET_HOP_DEAD_END) fail(full, "a transaction the one rule does not call CARRIER must be a dead end");
        } else {
            size_t idx = (size_t)strtoul(expected + 8, NULL, 10);
            BRAssetHeader header;
            if (idx < nOut && BRAssetDecodeHeader(outs[idx].script, outs[idx].len, &header) == BR_ASSET_SCRIPT_ASSET &&
                header.operation == DA_TRANSFER &&
                (h.kind != BR_ASSET_HOP_TRANSFER || strcmp(h.parentTxid, prevs[0]) != 0))
                fail(full, "a CARRIER transfer must walk to the first input's transaction");
        }
    }
done:
    fclose(f);
    if (! BAD && cases < 40) fail(path, "fewer da-carrier cases than the file holds");
}

int main(int argc, char **argv)
{
    const char *daCarrier = argc > 1 ? argv[1] : "vectors/da-carrier/vectors.txt";

    emit("# BRAssetProvenance.h hop vectors (BRAssetHopClassify): the header's answers on real transactions, written\n");
    emit("# down. Generated by vectors/asset-provenance-hop/generate.c, which describes each field; do not edit\n");
    emit("# (asset_provenance_rules_kat checks it). The hop reads the carrier by the one carrier rule (BRTxAssetCarrier):\n");
    emit("# only DA_TX_CARRIER is decoded, anything else is a dead end.\n");
    emit("# hop <name> <tx hex> dead-end | transfer <parentTxid> | issuance <assetId> <supply> <div> <cid|-> <opcode> <locked>\n");
    carrierRuleCases();
    nonNullDataCases();
    daCarrierCases(daCarrier);
    if (BAD) return 1;
    fwrite(OUT, 1, OUTN, stdout);
    return 0;
}
