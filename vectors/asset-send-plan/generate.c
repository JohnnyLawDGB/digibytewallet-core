// Vectors for BRAssetEncode.h and BRAssetSendPlan.h: the headers' own answers on a fixed corpus, so a
// platform that keeps an encoder, a selector or a planner of its own (the Kotlin DigiAssetEncoder.kt and
// asset/send/*.kt, AssetQuantity.kt, which its host-JVM tests run; or a Swift reading of them) can be held
// to the core without loading it. These are the headers written down, not independent answers; the host
// KAT asset_send_plan_kat holds the headers to the Kotlin tests' own expectations and to a line-for-line
// model of the Kotlin, and checks this file is current.
//
// The corpus, in the order it is written:
//   1. HAND: the instruction lists, coins, plans, stacks, groups and texts of the Kotlin tests;
//   2. seeded sets of instruction lists, fee shapes, selections, plans, verdicts, source groups,
//      choices (each a world of up to three calls in a row, sharing what is kept between them),
//      quantity texts and formatted quantities.
// A line that an earlier line already states is not written again, so no line occurs twice.
//
// THE FILE. Text, one vector a line, fields separated by one space, every number in decimal. A line
// that starts with '#' is a comment. Short names stand for the corpus's asset ids: A for the asset
// sent, O for another.
//
//   encode <version> <instructions> <answer>
//     BRAssetEncodeTransferScript. <instructions>: `-` for none, else per instruction
//     <flags>:<output>:<amount> joined by ','; <flags> three characters s r p for skip, range and percent,
//     each - when 0. <answer>: the script in hex, or `refused <why>` (BRAssetEncodeWhy in lower case,
//     BR_ASSET_ENCODE_WHY_ dropped).
//
//   fee <assetInputs> <dgbInputs> <outputs> <opReturnBytes> <feePerKb> <answer>
//     BRAssetFeeEstimate: the fee, or `overflow`.
//
//   <rows> (in select, plan, groups and choose): `-` for none, else per row
//     <txid>:<vout>:<script>:<sats>:<quantity> joined by '/'; <script> hex, `.` when empty. In choose a
//     plain row has a sixth field, whether the transaction that created it has a data output: y, n or u.
//
//   select <assetRows> <dgbRows> <assetNeeded> <feeSats> <markerOutputSats> <assetChangeMarkerSats> <answer>
//     BRAssetCoinSelect. <answer>: `ok <asset> <dgb> <assetChangeQty> <dgbChangeSats>`, the coins taken as
//     indices of the rows given, in the order taken, joined by ',' (`-` for none);
//     `insufficient-asset <required> <available>`; `insufficient-dgb <required> <available>`; `refused`;
//     `overflow`.
//
//   plan <assetRows> <dgbRows> <quantity> <feePerKb> <answer>
//     _BRAssetPlanTransfer. <answer>: `ready <asset> <dgb> <outputs> <opReturn> <estimatedFee> <paidFee>`,
//     the inputs as in select, the outputs <role>:<sats> joined by ',' (role r recipient marker, d data,
//     c DGB change, m last marker), the carrier in hex; or `refused <why>` (BRAssetPlanWhy in lower case,
//     BR_ASSET_PLAN_WHY_ dropped, '_' as '-'), followed by <required> <available> for not-enough-asset
//     and not-enough-dgb and by <paid> <estimated> for fee-mismatch.
//
//   judge <lookup> <entries> <recordedQuantity> <answer>
//     BRAssetInputJudge for the asset A. <lookup>: found, not-unspent or unavailable. <entries>: `-`, or
//     <id>:<count> joined by ','. <answer>: verified, mismatch or unavailable.
//
//   groups <rows> <quantity> <answer> <largest>
//     BRAssetSourceGroups and BRAssetLargestSingleSource. <answer>: `-`, or per group, largest first,
//     <first>:<rowCount>:<total> joined by ','.
//
//   choose <world> <call> <rule> <indexer> <assetRows> <dgbRows> <stacks> <quantity> <feePerKb> <answer> <asks>
//     One call of BRAssetSendChoose through its step protocol, for the asset A: every LOOKUP answered
//     from <stacks>, and what `marks` says kept after the call, for the calls after it in the same
//     <world>. <rule>: none, bound or unknown. <indexer>: 1, or 0 for none. <stacks>: per asset row, in
//     order and joined by '/', what the indexer says of it: `?` no answer, `x` not unspent, `-` found and
//     empty, or found with <id>:<count> joined by ','. <answer>: `planned <asset> <dgb> <estimatedFee>
//     <paidFee>`; `unverified`; `unconfirmed`; `spans <largestSingleSource>`; `not-planned <why>` with
//     the plan's numbers as above, then `fee-coin-rule` when it says so; `rule-bound`; `rules-unknown`.
//     <asks>: the asset rows asked about, in order, joined by ',' (`-` for none).
//
//   parse <text> <divisibility> <answer>
//     BRAssetAmountParse. <text> in hex (`-` when empty); <answer> the units, or `null`.
//
//   format <units> <divisibility> <answer>
//     BRAssetAmountFormat with room enough: the text.
//
// The numbers drawn from the seeded stream are drawn one a statement: the order of two calls inside one
// expression is not fixed by C, and the file must be the same whatever compiler writes it.
//
// Build: cc -std=c99 -I <core> vectors/asset-send-plan/generate.c -o gen && ./gen > vectors/asset-send-plan/vectors.txt
// It exits 1, writing nothing it has not checked, when an answer does not fit its buffer.
//

#include "BRAssetSendPlan.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof((a)[0]))
#define MAXR 48
#define LINE 16384

static const char *ASSET = "A";
static const char *OTHER = "O";

// ---- writing lines, each once -------------------------------------------------------------------

static uint64_t SEEN[1 << 16];
static size_t SEEN_N;

static uint64_t fnv(const char *s)
{
    uint64_t h = 1469598103934665603ULL;

    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h ? h : 1;
}

static void emit(const char *line)
{
    uint64_t h = fnv(line);
    size_t i = (size_t)(h & (N(SEEN) - 1));

    while (SEEN[i]) {
        if (SEEN[i] == h) return;   // written already (a 64-bit hash of the line)
        i = (i + 1) & (N(SEEN) - 1);
    }
    if (SEEN_N + 1 >= N(SEEN) / 2) { fprintf(stderr, "too many vectors\n"); exit(1); }
    SEEN[i] = h;
    SEEN_N++;
    printf("%s\n", line);
}

typedef struct { char s[LINE]; size_t n; } Buf;

static void put(Buf *b, const char *fmt, ...)
{
    va_list ap;
    int k;

    va_start(ap, fmt);
    k = vsnprintf(b->s + b->n, sizeof(b->s) - b->n, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= sizeof(b->s) - b->n) { fprintf(stderr, "a vector does not fit its buffer\n"); exit(1); }
    b->n += (size_t)k;
}

static void putHex(Buf *b, const uint8_t *p, size_t n)
{
    size_t i;

    if (n == 0) { put(b, "."); return; }
    for (i = 0; i < n; i++) put(b, "%02x", p[i]);
}

static void putIdx(Buf *b, const size_t *idx, size_t n)
{
    size_t i;

    if (n == 0) { put(b, "-"); return; }
    for (i = 0; i < n; i++) put(b, "%s%zu", i ? "," : "", idx[i]);
}

static const char *lower(const char *s)
{
    static char b[64];
    size_t i;

    for (i = 0; s[i] && i + 1 < sizeof(b); i++) b[i] = (s[i] == '_') ? '-' : (char)((s[i] >= 'A' && s[i] <= 'Z') ? s[i] + 32 : s[i]);
    b[i] = '\0';
    return b;
}

// ---- rows ------------------------------------------------------------------------------------

static const uint8_t SX[2] = { 1, 1 }, SY[2] = { 2, 2 }, S3[3] = { 3, 3, 3 }, S5[5] = { 0, 0x14, 1, 2, 3 }, SE[5] = { 0, 0x14, 9, 9, 9 };
static const uint8_t NONE[1] = { 0 };

static BRAssetRow row(const char *txid, int32_t vout, const uint8_t *script, size_t len, int64_t sats, int64_t qty)
{
    BRAssetRow r;

    memset(&r, 0, sizeof(r));
    r.txid = txid;
    r.vout = vout;
    r.script = script ? script : NONE;
    r.scriptLen = script ? len : 0;
    r.satoshis = sats;
    r.isAsset = qty != 0;
    r.assetQuantity = qty;
    return r;
}

static void putRows(Buf *b, const BRAssetRow *r, size_t n, const BRAssetFact *parents)
{
    size_t i;

    if (n == 0) { put(b, "-"); return; }
    for (i = 0; i < n; i++) {
        put(b, "%s%s:%d:", i ? "/" : "", r[i].txid, (int)r[i].vout);
        putHex(b, r[i].script, r[i].scriptLen);
        put(b, ":%lld:%lld", (long long)r[i].satoshis, (long long)r[i].assetQuantity);
        if (parents) put(b, ":%c", parents[i] == BR_ASSET_FACT_YES ? 'y' : parents[i] == BR_ASSET_FACT_NO ? 'n' : 'u');
    }
}

// ---- the answers -------------------------------------------------------------------------------

static const char *encodeWhy(BRAssetEncodeWhy w)
{
    switch (w) {
    case BR_ASSET_ENCODE_WHY_ARGUMENTS: return "arguments";
    case BR_ASSET_ENCODE_WHY_INSTRUCTION: return "instruction";
    case BR_ASSET_ENCODE_WHY_VERSION: return "version";
    case BR_ASSET_ENCODE_WHY_EMPTY: return "empty";
    case BR_ASSET_ENCODE_WHY_AMOUNT: return "amount";
    case BR_ASSET_ENCODE_WHY_TOO_LONG: return "too-long";
    default: return "none";
    }
}

static const char *planWhy(BRAssetPlanWhy w)
{
    static const char *const names[] = { "NONE", "ARGUMENTS", "NO_ASSET_UTXOS", "MIXED_ADDRESSES", "NOT_ENOUGH_ASSET", "NOT_ENOUGH_DGB",
                                         "INSTRUCTIONS", "RESIZED", "FEE_MISMATCH", "OVERFLOW", "QUANTITY", "FEE_RATE" };

    return (unsigned)w < N(names) ? lower(names[w]) : "unknown";
}

static void encodeLine(int32_t version, const BRAssetTransferInstruction *l, size_t n)
{
    static Buf b;
    uint8_t s[BR_ASSET_ENCODE_MAX_SCRIPT];
    size_t len = 0, i;
    BRAssetEncodeWhy why = BR_ASSET_ENCODE_WHY_NONE;
    BRAssetEncodeStatus st;

    b.n = 0;
    put(&b, "encode %d ", (int)version);
    if (n == 0) put(&b, "-");
    for (i = 0; i < n; i++) {
        put(&b, "%s%c%c%c:%d:%lld", i ? "," : "", l[i].skip ? 's' : '-', l[i].range ? 'r' : '-', l[i].percent ? 'p' : '-',
            (int)l[i].outputIndex, (long long)l[i].amount);
    }
    st = BRAssetEncodeTransferScript(version, l, n, s, sizeof(s), &len, &why);
    if (st == BR_ASSET_ENCODE_OK) { put(&b, " "); putHex(&b, s, len); }
    else if (st == BR_ASSET_ENCODE_REFUSED) put(&b, " refused %s", encodeWhy(why));
    else { fprintf(stderr, "an encode did not fit %d bytes\n", BR_ASSET_ENCODE_MAX_SCRIPT); exit(1); }
    emit(b.s);
}

static void feeLine(int32_t a, int32_t d, int32_t o, int32_t op, int64_t rate)
{
    static Buf b;
    int64_t fee = 0;

    b.n = 0;
    put(&b, "fee %d %d %d %d %lld ", (int)a, (int)d, (int)o, (int)op, (long long)rate);
    if (BRAssetFeeEstimate(a, d, o, op, rate, &fee)) put(&b, "%lld", (long long)fee);
    else put(&b, "overflow");
    emit(b.s);
}

static size_t AO[MAXR], DO_[MAXR];

static void selectLine(const BRAssetRow *a, size_t na, const BRAssetRow *d, size_t nd, int64_t need, int64_t fee, int64_t marker,
                       int64_t changeMarker)
{
    static Buf b;
    BRAssetSelection s;

    b.n = 0;
    put(&b, "select ");
    putRows(&b, a, na, NULL);
    put(&b, " ");
    putRows(&b, d, nd, NULL);
    put(&b, " %lld %lld %lld %lld ", (long long)need, (long long)fee, (long long)marker, (long long)changeMarker);
    s = BRAssetCoinSelect(a, na, d, nd, need, fee, marker, changeMarker, AO, N(AO), DO_, N(DO_));
    switch (s.status) {
    case BR_ASSET_SELECT_OK:
        put(&b, "ok ");
        putIdx(&b, AO, s.assetInputCount);
        put(&b, " ");
        putIdx(&b, DO_, s.dgbInputCount);
        put(&b, " %lld %lld", (long long)s.assetChangeQty, (long long)s.dgbChangeSats);
        break;
    case BR_ASSET_SELECT_INSUFFICIENT_ASSET: put(&b, "insufficient-asset %lld %lld", (long long)s.required, (long long)s.available); break;
    case BR_ASSET_SELECT_INSUFFICIENT_DGB: put(&b, "insufficient-dgb %lld %lld", (long long)s.required, (long long)s.available); break;
    case BR_ASSET_SELECT_REFUSED: put(&b, "refused"); break;
    case BR_ASSET_SELECT_OVERFLOW: put(&b, "overflow"); break;
    default: fprintf(stderr, "a selection did not fit its buffers\n"); exit(1);
    }
    emit(b.s);
}

static void putPlanRefusal(Buf *b, const BRAssetTransferPlan *p)
{
    put(b, "%s", planWhy(p->why));
    if (p->why == BR_ASSET_PLAN_WHY_NOT_ENOUGH_ASSET || p->why == BR_ASSET_PLAN_WHY_NOT_ENOUGH_DGB)
        put(b, " %lld %lld", (long long)p->required, (long long)p->available);
    if (p->why == BR_ASSET_PLAN_WHY_FEE_MISMATCH) put(b, " %lld %lld", (long long)p->paidFeeSats, (long long)p->estimatedFeeSats);
}

static void planLine(const BRAssetRow *a, size_t na, const BRAssetRow *d, size_t nd, int64_t qty, int64_t rate)
{
    static Buf b;
    static const char roles[] = { 'r', 'd', 'c', 'm' };
    BRAssetTransferPlan p;
    size_t i;

    b.n = 0;
    put(&b, "plan ");
    putRows(&b, a, na, NULL);
    put(&b, " ");
    putRows(&b, d, nd, NULL);
    put(&b, " %lld %lld ", (long long)qty, (long long)rate);
    p = _BRAssetPlanTransfer(a, na, d, nd, qty, rate, AO, N(AO), DO_, N(DO_));
    if (p.status == BR_ASSET_PLAN_READY) {
        put(&b, "ready ");
        putIdx(&b, p.assetInputs, p.assetInputCount);
        put(&b, " ");
        putIdx(&b, p.dgbInputs, p.dgbInputCount);
        put(&b, " ");
        for (i = 0; i < p.outputCount; i++) put(&b, "%s%c:%lld", i ? "," : "", roles[p.outputs[i].role & 3], (long long)p.outputs[i].sats);
        put(&b, " ");
        putHex(&b, p.opReturnScript, p.opReturnLen);
        put(&b, " %lld %lld", (long long)p.estimatedFeeSats, (long long)p.paidFeeSats);
    }
    else if (p.status == BR_ASSET_PLAN_REFUSED) { put(&b, "refused "); putPlanRefusal(&b, &p); }
    else { fprintf(stderr, "a plan did not fit its buffers\n"); exit(1); }
    emit(b.s);
}

static const char *lookupName(BRAssetStackLookup l)
{
    return l == BR_ASSET_STACK_FOUND ? "found" : l == BR_ASSET_STACK_NOT_UNSPENT ? "not-unspent" : "unavailable";
}

static void judgeLine(BRAssetStackLookup lookup, const BRAssetUnits *e, size_t n, int64_t q)
{
    static Buf b;
    BRAssetInputVerdict v;
    size_t i;

    b.n = 0;
    put(&b, "judge %s ", lookupName(lookup));
    if (n == 0 || lookup != BR_ASSET_STACK_FOUND) put(&b, "-");
    for (i = 0; lookup == BR_ASSET_STACK_FOUND && i < n; i++) put(&b, "%s%s:%lld", i ? "," : "", e[i].assetId, (long long)e[i].count);
    v = BRAssetInputJudge(lookup, e, lookup == BR_ASSET_STACK_FOUND ? n : 0, ASSET, q);
    put(&b, " %lld %s", (long long)q, v == BR_ASSET_INPUT_VERIFIED ? "verified" : v == BR_ASSET_INPUT_MISMATCH ? "mismatch" : "unavailable");
    emit(b.s);
}

static void groupsLine(const BRAssetRow *r, size_t n, int64_t qty)
{
    static Buf b;
    BRAssetSourceGroup g[MAXR];
    size_t count = 0, i;

    b.n = 0;
    put(&b, "groups ");
    putRows(&b, r, n, NULL);
    put(&b, " %lld ", (long long)qty);
    if (! BRAssetSourceGroups(r, n, qty, g, N(g), &count)) { fprintf(stderr, "groups did not fit\n"); exit(1); }
    if (count == 0) put(&b, "-");
    for (i = 0; i < count; i++) put(&b, "%s%zu:%zu:%lld", i ? "," : "", g[i].first, g[i].rowCount, (long long)g[i].total);
    put(&b, " %lld", (long long)BRAssetLargestSingleSource(r, n));
    emit(b.s);
}

// c as UTF-8 into out (room for 4 bytes): its length.
static size_t utf8Of(uint32_t c, char *out)
{
    if (c < 0x80) { out[0] = (char)c; return 1; }
    if (c < 0x800) { out[0] = (char)(0xc0 | (c >> 6)); out[1] = (char)(0x80 | (c & 0x3f)); return 2; }
    out[0] = (char)(0xe0 | (c >> 12)); out[1] = (char)(0x80 | ((c >> 6) & 0x3f)); out[2] = (char)(0x80 | (c & 0x3f));
    return 3;
}

static void parseLine(const char *t, size_t len, int32_t div)
{
    static Buf b;
    int64_t u = 0;

    b.n = 0;
    put(&b, "parse ");
    if (len == 0) put(&b, "-");
    else putHex(&b, (const uint8_t *)t, len);
    put(&b, " %d ", (int)div);
    if (BRAssetAmountParse(t, len, div, &u)) put(&b, "%lld", (long long)u);
    else put(&b, "null");
    emit(b.s);
}

static void formatLine(int64_t u, int32_t div)
{
    static Buf b;
    char t[128];

    if (! BRAssetAmountFormat(u, div, t, sizeof(t))) { fprintf(stderr, "a format did not fit\n"); exit(1); }
    b.n = 0;
    put(&b, "format %lld %d %s", (long long)u, (int)div, t);
    emit(b.s);
}

// ---- the choice, through its step protocol -------------------------------------------------------

typedef struct {
    BRAssetStackLookup lookup;
    BRAssetUnits e[3];
    size_t n;
} Stack;

typedef struct {
    BRAssetSendKey verified[256];
    size_t nv;
    BRAssetSendKey aside[256];
    size_t na;
} Kept;

static void putStacks(Buf *b, const Stack *s, size_t n)
{
    size_t i, k;

    if (n == 0) { put(b, "-"); return; }
    for (i = 0; i < n; i++) {
        put(b, "%s", i ? "/" : "");
        if (s[i].lookup == BR_ASSET_STACK_UNAVAILABLE) put(b, "?");
        else if (s[i].lookup == BR_ASSET_STACK_NOT_UNSPENT) put(b, "x");
        else if (s[i].n == 0) put(b, "-");
        else for (k = 0; k < s[i].n; k++) put(b, "%s%s:%lld", k ? "," : "", s[i].e[k].assetId, (long long)s[i].e[k].count);
    }
}

static void chooseLine(int world, int call, Kept *kept, BRSweepRuleState rule, int indexer, const BRAssetRow *a, size_t na,
                       const BRAssetRow *d, const BRAssetFact *parents, size_t nd, const Stack *stacks, int64_t qty, int64_t rate)
{
    static Buf b;
    static BRAssetSendLookup answers[256];
    size_t work[4 * MAXR], asks[256], nAsks = 0, nAnswers = 0, i;
    uint8_t marks[MAXR];
    BRAssetSendOutcome o;

    for (;;) {
        o = BRAssetSendChoose(rule, indexer, ASSET, a, na, d, parents, nd, qty, rate, kept->verified, kept->nv, kept->aside, kept->na,
                              answers, nAnswers, marks, sizeof(marks), work, N(work));
        if (o.kind != BR_ASSET_SEND_LOOKUP) break;
        if (nAnswers >= N(answers) || o.lookupRow >= na) { fprintf(stderr, "too many lookups\n"); exit(1); }
        asks[nAsks++] = o.lookupRow;
        answers[nAnswers].txid = a[o.lookupRow].txid;
        answers[nAnswers].vout = a[o.lookupRow].vout;
        answers[nAnswers].lookup = stacks[o.lookupRow].lookup;
        answers[nAnswers].entries = stacks[o.lookupRow].e;
        answers[nAnswers].entryCount = stacks[o.lookupRow].n;
        nAnswers++;
    }
    if (o.kind == BR_ASSET_SEND_CAPACITY) { fprintf(stderr, "a choice did not fit its buffers\n"); exit(1); }
    for (i = 0; i < na; i++) {
        if ((marks[i] & BR_ASSET_SEND_MARK_VERIFIED) && kept->nv < N(kept->verified)) {
            BRAssetSendKey k = { a[i].txid, a[i].vout, ASSET, a[i].assetQuantity };
            kept->verified[kept->nv++] = k;
        }
        if ((marks[i] & BR_ASSET_SEND_MARK_SET_ASIDE) && kept->na < N(kept->aside)) {
            BRAssetSendKey k = { a[i].txid, a[i].vout, NULL, 0 };
            kept->aside[kept->na++] = k;
        }
    }

    b.n = 0;
    put(&b, "choose %d %d %s %d ", world, call, rule == BR_SWEEP_RULE_NONE ? "none" : rule == BR_SWEEP_RULE_BOUND ? "bound" : "unknown", indexer);
    putRows(&b, a, na, NULL);
    put(&b, " ");
    putRows(&b, d, nd, parents);
    put(&b, " ");
    putStacks(&b, stacks, na);
    put(&b, " %lld %lld ", (long long)qty, (long long)rate);
    switch (o.kind) {
    case BR_ASSET_SEND_PLANNED:
        put(&b, "planned ");
        putIdx(&b, o.plan.assetInputs, o.plan.assetInputCount);
        put(&b, " ");
        putIdx(&b, o.plan.dgbInputs, o.plan.dgbInputCount);
        put(&b, " %lld %lld", (long long)o.plan.estimatedFeeSats, (long long)o.plan.paidFeeSats);
        break;
    case BR_ASSET_SEND_UNVERIFIED: put(&b, "unverified"); break;
    case BR_ASSET_SEND_UNCONFIRMED: put(&b, "unconfirmed"); break;
    case BR_ASSET_SEND_SPANS_ADDRESSES: put(&b, "spans %lld", (long long)o.largestSingleSource); break;
    case BR_ASSET_SEND_NOT_PLANNED:
        put(&b, "not-planned ");
        putPlanRefusal(&b, &o.plan);
        if (o.feeCoinRule) put(&b, " fee-coin-rule");
        break;
    case BR_ASSET_SEND_RULE_BOUND: put(&b, "rule-bound"); break;
    default: put(&b, "rules-unknown"); break;
    }
    put(&b, " ");
    putIdx(&b, asks, nAsks);
    emit(b.s);
}

// ---- the seeded stream ---------------------------------------------------------------------------

static uint64_t RNG = 0x5eed2026111115ULL;

static uint32_t rnd(void)   // xorshift64: the same stream on every machine
{
    RNG ^= RNG << 13; RNG ^= RNG >> 7; RNG ^= RNG << 17;
    return (uint32_t)(RNG >> 24);
}

static uint32_t below(uint32_t n) { return rnd() % n; }

static const char *const TXIDS[] = { "aa", "AA", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk" };

static void rndScript(BRAssetRow *r, int mostlyOne)
{
    uint32_t k = below(10);

    if (mostlyOne && k > 0) k = 0;
    else k = below(4);
    if (k == 0) { r->script = SX; r->scriptLen = 2; }
    else if (k == 1) { r->script = SY; r->scriptLen = 2; }
    else if (k == 2) { r->script = S3; r->scriptLen = 3; }
    else { r->script = NONE; r->scriptLen = 0; }
}

static BRAssetRow rndAsset(int mostlyOne)
{
    uint32_t t = below(N(TXIDS)), v = below(3), s = below(10), q = below(12);
    BRAssetRow r = row(TXIDS[t], (int32_t)v, SX, 2, 6000, 1);

    rndScript(&r, mostlyOne);
    if (s == 0) r.satoshis = (int64_t)below(20000);
    else if (s == 1) r.satoshis = 200000 + (int64_t)below(100000);
    if (q == 0) r.assetQuantity = 0;
    else if (q == 1) r.assetQuantity = -1;
    else if (q == 2) r.assetQuantity = 4996000000000000000LL;
    else if (q == 3) r.assetQuantity = 1000 * (int64_t)(1 + below(9));
    else r.assetQuantity = 1 + (int64_t)below(20);
    return r;
}

static BRAssetRow rndDgb(void)
{
    uint32_t t = below(N(TXIDS)), v = below(3), s = below(6);
    BRAssetRow r = row(TXIDS[t], (int32_t)v, SX, 2, 0, 0);

    rndScript(&r, 0);
    if (s == 0) r.satoshis = 1000000;
    else if (s == 1) r.satoshis = -(int64_t)below(1000);
    else r.satoshis = (int64_t)below(150000);
    return r;
}

static int64_t rndRate(void)
{
    uint32_t k = below(8);

    if (k == 0) return (int64_t)below(100000);
    if (k == 1) return 100000 + (int64_t)below(300000);
    if (k == 2) return INT64_MAX / 100;
    return 100000;
}

static BRAssetTransferInstruction inst(int skip, int range, int percent, int32_t idx, int64_t amount)
{
    BRAssetTransferInstruction t;

    memset(&t, 0, sizeof(t));
    t.skip = skip; t.range = range; t.percent = percent; t.outputIndex = idx; t.amount = amount;
    return t;
}

int main(void)
{
    BRAssetTransferInstruction l[48];
    BRAssetRow a[MAXR], d[MAXR];
    static char tx[48][8];
    size_t i, k;
    int round;

    printf("# BRAssetEncode.h and BRAssetSendPlan.h vectors: the headers' answers, written down. Generated by\n");
    printf("# vectors/asset-send-plan/generate.c, which describes each field; do not edit (asset_send_plan_kat\n");
    printf("# checks it). One vector a line, fields separated by one space, numbers in decimal. No line occurs\n");
    printf("# twice. A is the asset sent, O another. Rows: <txid>:<vout>:<script hex or .>:<sats>:<quantity>\n");
    printf("# joined by '/' (a plain row in choose adds y/n/u: its creating transaction has a data output).\n");
    printf("# encode <version> <flags:output:amount,...|-> <script hex | refused why>\n");
    printf("# fee <assetInputs> <dgbInputs> <outputs> <opReturnBytes> <feePerKb> <fee | overflow>\n");
    printf("# select <assetRows> <dgbRows> <need> <fee> <marker> <changeMarker>\n");
    printf("#   <ok a d change dgbChange | insufficient-asset r a | insufficient-dgb r a | refused | overflow>\n");
    printf("# plan <assetRows> <dgbRows> <quantity> <feePerKb> <ready a d role:sats,... carrier est paid | refused why [numbers]>\n");
    printf("# judge <lookup> <entries> <recordedQuantity> <verified | mismatch | unavailable>\n");
    printf("# groups <rows> <quantity> <first:rowCount:total,...|-> <largest>\n");
    printf("# choose <world> <call> <rule> <indexer> <assetRows> <dgbRows> <stacks> <quantity> <feePerKb> <answer> <asks>\n");
    printf("# parse <text hex|-> <divisibility> <units | null>\n");
    printf("# format <units> <divisibility> <text>\n");

    // ---- 1. HAND: the Kotlin tests' inputs ----
    encodeLine(3, (l[0] = inst(0, 0, 0, 0, 500), l), 1);
    encodeLine(2, (l[0] = inst(0, 0, 0, 0, 1000), l), 1);
    l[0] = inst(1, 0, 0, 0, 100); l[1] = inst(0, 0, 0, 1, 50); encodeLine(3, l, 2);
    encodeLine(3, (l[0] = inst(0, 0, 0, 31, 300), l), 1);
    encodeLine(3, (l[0] = inst(0, 1, 0, 500, 50), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 1, 0, 75), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 0, 32, 1), l), 1);
    encodeLine(3, (l[0] = inst(0, 1, 0, 8192, 1), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 1, 0, 101), l), 1);
    encodeLine(1, (l[0] = inst(0, 0, 0, 0, 1), l), 1);
    encodeLine(3, l, 0);
    for (k = 0; k < 50 && k < N(l); k++) l[k] = inst(0, 0, 0, 0, 1);
    encodeLine(3, l, 35);
    l[34] = inst(0, 0, 0, 0, 500); encodeLine(3, l, 35); l[34] = inst(0, 0, 0, 0, 1);
    encodeLine(3, l, 36);
    encodeLine(3, l, 38);
    for (k = 0; k < 48; k++) l[k] = inst(1, 0, 0, 0, 1);
    encodeLine(3, l, 48);
    encodeLine(3, (l[0] = inst(0, 0, 0, 0, 10000000000000000LL), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 0, 0, BR_ASSET_FIXED_PRECISION_MAX), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 0, 0, BR_ASSET_FIXED_PRECISION_MAX + 1), l), 1);
    encodeLine(3, (l[0] = inst(0, 0, 0, 0, 4996000000000000000LL), l), 1);

    feeLine(1, 1, 3, 40, 100000); feeLine(1, 1, 3, 40, 200000); feeLine(1, 1, 3, 40, 300000); feeLine(1, 1, 2, 40, 100000);
    feeLine(2, 3, 2, 40, 100000); feeLine(1, 1, 4, 40, 100000); feeLine(1, 1, 2, 120, 100000); feeLine(2, 1, 3, 40, 100000);
    feeLine(1, 1, 3, 40, 0); feeLine(1, 1, 3, 40, 1000); feeLine(1, 1, 3, 40, 5000); feeLine(1, 1, 3, 40, 20000); feeLine(1, 1, 3, 40, 99999);
    feeLine(1, 1, 3, 80, INT64_MAX); feeLine(-1, -1, -1, -1, -1);

    a[0] = row("a", 0, NULL, 0, 600, 100); d[0] = row("b", 0, NULL, 0, 10000, 0);
    selectLine(a, 1, d, 1, 50, 500, 600, 0);
    a[0] = row("a", 0, NULL, 0, 5000, 100); selectLine(a, 1, d, 1, 100, 700, 600, 0);
    a[0] = row("small", 0, NULL, 0, 600, 10); a[1] = row("big", 0, NULL, 0, 600, 100); a[2] = row("med", 0, NULL, 0, 600, 50);
    d[0] = row("d", 0, NULL, 0, 10000, 0); selectLine(a, 3, d, 1, 80, 500, 600, 0);
    a[0] = row("a1", 0, NULL, 0, 600, 60); a[1] = row("a2", 0, NULL, 0, 600, 50); selectLine(a, 2, d, 1, 100, 500, 600, 0);
    a[0] = row("a", 0, NULL, 0, 600, 10); selectLine(a, 1, d, 1, 100, 500, 600, 0);
    a[0] = row("a", 0, NULL, 0, 600, 100); d[0] = row("d", 0, NULL, 0, 100, 0); selectLine(a, 1, d, 1, 50, 1000, 600, 0);
    d[0] = row("small", 0, NULL, 0, 500, 0); d[1] = row("big", 0, NULL, 0, 100000, 0); d[2] = row("med", 0, NULL, 0, 5000, 0);
    selectLine(a, 1, d, 3, 50, 2000, 600, 0);
    d[0] = row("d", 0, NULL, 0, 10000, 0);
    selectLine(a, 1, d, 1, 100, 500, 600, 0); selectLine(a, 1, d, 1, 50, 500, 600, 600); selectLine(a, 1, d, 1, 100, 500, 600, 600);
    selectLine(a, 1, d, 1, -1, 1000, 700, 0); selectLine(a, 1, d, 1, 0, 1000, 700, 0); selectLine(a, 1, d, 1, 50, -100, 700, 0);
    selectLine(a, 1, d, 1, 50, 1000, -1, 0); selectLine(NULL, 0, d, 1, 50, 1000, 700, 0); selectLine(a, 1, NULL, 0, 50, 1000, 700, 0);
    a[0] = row("a1", 0, NULL, 0, 700, INT64_MAX / 2 + 1); a[1] = row("a2", 0, NULL, 0, 700, INT64_MAX / 2 + 1);
    selectLine(a, 2, d, 1, 1, 1000, 700, 0);
    a[0] = row("a1", 0, NULL, 0, 700, 100); selectLine(a, 1, d, 1, INT64_MAX, 1000, 700, 0);
    a[0] = row("t1", 0, NULL, 0, 600, 5); a[1] = row("t2", 0, NULL, 0, 600, 5); a[2] = row("t3", 0, NULL, 0, 600, 5);
    selectLine(a, 3, d, 1, 6, 0, 0, 0);
    a[0] = row("f3", 0, NULL, 0, 0, 1); d[0] = row("f1", 0, NULL, 0, 4000, 0); d[1] = row("F1", 0, NULL, 0, 9000, 0);
    d[2] = row("f2", 0, NULL, 0, 4000, 0); d[3] = row("f3", 0, NULL, 0, 8000, 0);
    selectLine(a, 1, d, 4, 1, 10000, 0, 0);
    a[0] = row("a", 0, NULL, 0, INT64_MAX, 1); a[1] = row("b", 0, NULL, 0, 1, 1); selectLine(a, 2, NULL, 0, 2, 0, 0, 0);
    a[0] = row("a", 0, NULL, 0, 600, 100); d[0] = row("x", 0, NULL, 0, 500, 0); d[1] = row("y", 0, NULL, 0, 100, 0);
    selectLine(a, 1, d, 2, 100, 500, 600, 0);

    a[0] = row("a", 0, NULL, 0, 6000, 100); d[0] = row("d", 0, NULL, 0, 1000000, 0);
    planLine(a, 1, d, 1, 100, 100000); planLine(a, 1, d, 1, 40, 100000);
    a[0] = row("a", 0, NULL, 0, 200000, 100); planLine(a, 1, d, 1, 100, 100000);
    a[0] = row("a", 0, NULL, 0, 6000, 100);
    for (i = 0; i < 2; i++) {
        d[0] = row("d1", 0, NULL, 0, i ? 59200 + 5460 : 59200 + 5461, 0); d[1] = row("d2", 0, NULL, 0, 20000, 0);
        planLine(a, 1, d, 2, 100, 100000);
    }
    for (i = 0; i < 8; i++) { snprintf(tx[i], 8, "a%zu", i + 1); a[i] = row(tx[i], 0, NULL, 0, 600, 1); }
    d[0] = row("f", 0, NULL, 0, 5000000, 0); planLine(a, 8, d, 1, 8, 100000);
    a[0] = row("p", 0, S5, 5, 6000, 5); d[0] = row("f", 0, S5, 5, 1000000, 0);
    planLine(a, 1, d, 1, 2, 100000); planLine(a, 1, d, 1, 5, 100000);
    a[0] = row("p", 0, S5, 5, 6000, 8); planLine(a, 1, d, 1, 8, 100000);
    a[0] = row("p", 0, S5, 5, 6000, 2); a[1] = row("q", 0, SE, 5, 6000, 2); planLine(a, 2, d, 1, 3, 100000);
    for (i = 0; i < 39; i++) { snprintf(tx[i], 8, "c%zu", i); a[i] = row(tx[i], 0, SX, 2, 6000, 1); }
    planLine(a, 38, d, 1, 38, 100000); planLine(a, 39, d, 1, 39, 100000);
    a[0] = row("i1", 0, SX, 2, 6000, 2); a[1] = row("i2", 0, SX, 2, 6000, 2); a[2] = row("i3", 0, SX, 2, 6000, 2);
    planLine(a, 3, d, 1, 5, 100000); planLine(a, 1, d, 1, 0, 100000); planLine(a, 1, NULL, 0, 2, 100000); planLine(NULL, 0, d, 1, 1, 100000);
    planLine(a, 1, d, 1, 1, INT64_MAX);

    {
        BRAssetUnits e[2];

        e[0].assetId = ASSET; e[0].count = 5; e[0].ruleFree = 0;
        judgeLine(BR_ASSET_STACK_FOUND, e, 1, 5); judgeLine(BR_ASSET_STACK_FOUND, e, 1, 4);
        e[1].assetId = OTHER; e[1].count = 1; e[1].ruleFree = 0; judgeLine(BR_ASSET_STACK_FOUND, e, 2, 5);
        e[0].assetId = OTHER; e[0].count = 1; e[1].assetId = ASSET; e[1].count = 5; judgeLine(BR_ASSET_STACK_FOUND, e, 2, 5);
        e[0].assetId = OTHER; e[0].count = 5; judgeLine(BR_ASSET_STACK_FOUND, e, 1, 5);
        judgeLine(BR_ASSET_STACK_FOUND, e, 0, 5);
        e[0].assetId = ASSET; e[0].count = 0; judgeLine(BR_ASSET_STACK_FOUND, e, 1, 0);
        judgeLine(BR_ASSET_STACK_NOT_UNSPENT, e, 0, 5); judgeLine(BR_ASSET_STACK_UNAVAILABLE, e, 0, 5);
    }

    a[0] = row("a", 0, S5, 5, 6000, 2); a[1] = row("b", 0, S5, 5, 6000, 3); a[2] = row("c", 0, SE, 5, 6000, 4); a[3] = row("d", 0, NULL, 0, 6000, 1);
    a[3].script = (const uint8_t *)"\x07"; a[3].scriptLen = 1;
    groupsLine(a, 4, 4); groupsLine(a, 4, 6);

    {
        static const struct { const char *t; int d; } texts[] = {
            { "1", 0 }, { "100", 0 }, { "0100", 0 }, { " 3 ", 0 }, { "1234567", 0 }, { "1", 2 }, { "1.5", 2 }, { "1.50", 2 }, { "01.5", 2 },
            { "0.01", 2 }, { "0.29", 2 }, { ".5", 2 }, { " 3 ", 2 }, { "1", 8 }, { "0.00000001", 8 }, { "0.29", 8 }, { "1234.5", 8 },
            { " 3 ", 8 }, { "1,5", 2 }, { "1,5", 1 }, { "1,5", 8 }, { "1,234.5", 2 }, { "1,234,567.5", 2 }, { "1,234", 3 }, { "1,234", 2 },
            { "1,5", 0 }, { "1,234", 0 }, { "1,2,3", 2 }, { "1,234,567", 0 }, { "1e2", 0 }, { "NaN", 2 }, { "+1", 8 }, { "-1", 0 },
            { "-0", 2 }, { "1.5f", 0 }, { "0x10", 0 }, { "1_000", 0 }, { "0", 0 }, { "00", 0 }, { "0.0", 2 }, { "0,00", 2 },
            { "0.00000000", 8 }, { "1.5", 0 }, { "1.0", 0 }, { "1.234", 2 }, { "1.500", 2 }, { "0.000000001", 8 }, { "1.000000000", 8 },
            { "", 0 }, { "   ", 2 }, { ".", 8 }, { ",", 0 }, { "abc", 2 }, { "1.2.3", 0 }, { "1 000", 0 }, { "5 tokens", 0 }, { "#5", 0 },
            { "9223372036854775807", 0 }, { "9223372036854775808", 0 }, { "92233720368547758.07", 2 }, { "92233720368547758.08", 2 },
            { "92233720368.54775807", 8 }, { "92233720368.54775808", 8 }, { "99999999999999999999", 0 },
            { "00000000000000000000000000000001", 0 }, { "000000000000000000000000000000001", 0 }, { "1", -1 }, { "1", 9 },
            { "1", 18 }, { "\xc2\xa0" "5\xe3\x80\x80", 0 }, { "\xd9\xa5", 0 }, { "1,000", 3 }, { "1.", 2 },
        };

        // Every code point the trim takes (Kotlin's isWhitespace), before and after a digit; then three it
        // does not take; then the length limit counted after many grouping commas are dropped.
        static const uint32_t spaces[] = { 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xa0, 0x1680, 0x2000,
                                           0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
                                           0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0x180e, 0x200b, 0xfeff };
        static const struct { const char *t; int d; } grouped[] = {
            { "00,000,000,000,000,000,000,000,000,001.50", 2 }, { "000,000,000,000,000,000,000,000,000,001.50", 2 },
            { "00,000,000,000,000,000,000,001.50000000", 8 }, { "000,000,000,000,000,000,000,001.50000000", 8 },
        };
        char w[8];
        size_t wn;

        for (i = 0; i < N(texts); i++) parseLine(texts[i].t, strlen(texts[i].t), texts[i].d);
        for (i = 0; i < N(spaces); i++) {
            wn = utf8Of(spaces[i], w);
            w[wn] = '5';
            parseLine(w, wn + 1, 0);
            w[0] = '5';
            wn = 1 + utf8Of(spaces[i], w + 1);
            parseLine(w, wn, 0);
        }
        for (i = 0; i < N(grouped); i++) parseLine(grouped[i].t, strlen(grouped[i].t), grouped[i].d);
        formatLine(5, 0); formatLine(100, 0); formatLine(1000000, 0); formatLine(150, 2); formatLine(100, 2); formatLine(100000, 2);
        formatLine(1, 2); formatLine(123456, 2); formatLine(1, 8); formatLine(100000000, 8); formatLine(INT64_MAX, 8); formatLine(INT64_MAX, 0);
        formatLine(-150, 2); formatLine(INT64_MIN, 0); formatLine(0, 5); formatLine(1, 20);
        formatLine(12, 2); formatLine(-12, 2); formatLine(123, 2);
    }

    // ---- 2. the seeded sets ----
    for (round = 0; round < 800; round++) {
        uint32_t n = 1 + below(round % 6 == 0 ? 44 : 5), version = 2 + below(2), bad = below(10);

        for (k = 0; k < n; k++) {
            uint32_t skip = below(2), range = below(6) == 0, percent = below(6) == 0, idx = range ? below(8192) : below(32);
            uint32_t big = below(5);
            int64_t amount = percent ? (int64_t)below(101) : big == 0 ? (int64_t)below(32) : big == 1 ? (int64_t)(1 + below(999)) * 1000000 :
                             big == 2 ? (int64_t)rnd() : (int64_t)below(100000);

            l[k] = inst((int)skip, (int)range, (int)percent, (int32_t)idx, amount);
        }
        if (bad == 0) l[0].outputIndex = l[0].range ? 8192 : 32;
        if (bad == 1) l[0].amount = -1;
        if (bad == 2) version = 1 + 3 * below(2);
        encodeLine((int32_t)version, l, n);
    }
    for (round = 0; round < 300; round++) {
        uint32_t ai = below(8), di = below(8), o = below(5), op = below(84);
        int64_t rate = rndRate();

        feeLine((int32_t)ai, (int32_t)di, (int32_t)o, (int32_t)op, rate);
    }
    for (round = 0; round < 1000; round++) {
        uint32_t na = below(6), nd = below(6), nk = below(40), fk = below(12), mk = below(3);
        int64_t need = (int64_t)nk - 1, fee = fk == 0 ? -1 : (int64_t)below(100000), marker = mk == 0 ? 0 : 6000 * (int64_t)mk;

        for (k = 0; k < na; k++) a[k] = rndAsset(0);
        for (k = 0; k < nd; k++) d[k] = rndDgb();
        if (na > 0 && nd > 0 && below(4) == 0) { d[0].txid = a[0].txid; d[0].vout = a[0].vout; }
        selectLine(a, na, d, nd, need, fee, marker, (round & 1) ? 6000 : 0);
    }
    for (round = 0; round < 1000; round++) {
        uint32_t na = below(5), nd = below(6), qk = below(30);
        int64_t qty = (int64_t)qk, rate = rndRate();

        for (k = 0; k < na; k++) a[k] = rndAsset(1);
        for (k = 0; k < nd; k++) d[k] = rndDgb();
        if (round % 10 == 1) {
            uint32_t x = below(5462);

            na = 1; nd = 2;
            a[0] = row("aa", 0, SX, 2, 6000, 2); d[0] = row("dd", 0, SX, 2, 59200 + (int64_t)x, 0); d[1] = row("ee", 0, SX, 2, 20000, 0);
            qty = 1 + (int64_t)(x & 1); rate = 100000;
        }
        planLine(a, na, d, nd, qty, rate);
    }
    for (round = 0; round < 300; round++) {
        BRAssetUnits e[3];
        uint32_t n = below(4), lk = below(3), qk = below(6);
        int64_t q = (int64_t)qk - 1;

        for (k = 0; k < n; k++) {
            uint32_t id = below(3), c = below(2), ck = below(6);

            e[k].assetId = id ? ASSET : OTHER;
            e[k].count = c ? q : (int64_t)ck - 1;
            e[k].ruleFree = 0;
        }
        judgeLine((BRAssetStackLookup)lk, e, n, q);
    }
    for (round = 0; round < 400; round++) {
        uint32_t n = below(8), qk = below(40);

        for (k = 0; k < n; k++) a[k] = rndAsset(0);
        groupsLine(a, n, (int64_t)qk - 2);
    }
    for (round = 0; round < 600; round++) {
        static Kept kept;
        Stack stacks[MAXR];
        BRAssetFact parents[MAXR];
        uint32_t na = below(7), nd = below(5), calls = 1 + below(3), indexer = below(20) != 0;
        int c;

        memset(&kept, 0, sizeof(kept));
        for (k = 0; k < na; k++) {
            size_t j;
            int again;

            do {
                again = 0;
                a[k] = rndAsset(below(2));
                for (j = 0; j < k; j++) if (strcmp(a[j].txid, a[k].txid) == 0 && a[j].vout == a[k].vout) again = 1;
            } while (again);
        }
        for (k = 0; k < nd; k++) {
            uint32_t pf = below(4), rich = below(4);

            d[k] = rndDgb();
            if (rich) d[k].satoshis = 1000000;
            parents[k] = pf < 2 ? BR_ASSET_FACT_NO : pf == 2 ? BR_ASSET_FACT_YES : BR_ASSET_FACT_UNKNOWN;
        }
        for (k = 0; k < na; k++) {
            uint32_t sk = below(8), cnt = below(9);

            memset(&stacks[k], 0, sizeof(stacks[k]));
            stacks[k].lookup = BR_ASSET_STACK_FOUND;
            if (sk == 0) stacks[k].lookup = BR_ASSET_STACK_NOT_UNSPENT;
            else if (sk == 1) stacks[k].lookup = BR_ASSET_STACK_UNAVAILABLE;
            else if (sk == 2) stacks[k].n = 0;
            else if (sk == 3) { stacks[k].e[0].assetId = OTHER; stacks[k].e[0].count = 1 + (int64_t)cnt; stacks[k].n = 1; }
            else if (sk == 4) {
                stacks[k].e[0].assetId = ASSET; stacks[k].e[0].count = a[k].assetQuantity;
                stacks[k].e[1].assetId = OTHER; stacks[k].e[1].count = 1; stacks[k].n = 2;
            }
            else { stacks[k].e[0].assetId = ASSET; stacks[k].e[0].count = a[k].assetQuantity; stacks[k].n = 1; }
        }
        for (c = 0; c < (int)calls; c++) {
            uint32_t rk = below(12), qk = below(22);
            BRSweepRuleState rule = rk == 0 ? BR_SWEEP_RULE_BOUND : rk == 1 ? BR_SWEEP_RULE_UNKNOWN : BR_SWEEP_RULE_NONE;
            int64_t qty = (int64_t)qk - 1, rate = rndRate();

            chooseLine(round, c, &kept, rule, (int)indexer, a, na, d, parents, nd, stacks, qty, rate);
        }
    }
    {
        static const char *const bits[] = { "0", "1", "5", "9", ".", ",", " ", "\t", "\xc2\xa0", "e", "-", "x", "12", "345" };

        for (round = 0; round < 1500; round++) {
            char t[200];
            size_t len = 0;
            uint32_t n = below(9), dv = below(11);

            for (k = 0; k < n; k++) {
                uint32_t pick = below(N(bits));
                size_t bl = strlen(bits[pick]);

                memcpy(t + len, bits[pick], bl);
                len += bl;
            }
            t[len] = '\0';
            parseLine(t, len, (int32_t)dv - 1);
        }
        for (round = 0; round < 500; round++) {
            uint32_t kind = below(3), dv = below(12), hi = rnd(), lo = rnd();
            int64_t u = kind == 0 ? (int64_t)below(100000) : kind == 1 ? (int64_t)(((uint64_t)hi << 32) | lo) : -(int64_t)below(100000);

            formatLine(u, (int32_t)dv - 2);
        }
    }
    return 0;
}
