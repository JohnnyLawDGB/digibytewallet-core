// Vectors for BRAssetDetect.h: the header's own answers on a fixed corpus, so a platform that keeps a
// detection of its own (the Kotlin AssetManager.processIncomingAssetTx and AssetTxQuantity.kt, which its
// host-JVM tests run; or a Swift reading of them) can be held to the core without loading it. These are the
// header written down, not independent answers; the host KAT asset_detect_kat holds the header to the Kotlin
// tests' own expectations and to a line-for-line model of the Kotlin, and checks this file is current.
//
// The corpus, in the order it is written:
//   1. claims: hand-built instruction lists and seeded ones, through BRAssetClaimForOutputTotal and
//      BRAssetClaimRemainder;
//   2. worlds: a few written by hand (world 5 holds the one carrier rule's cases, BRTxAssetCarrier), then
//      seeded ones. A world is the wallet's transactions, its rows, its remainder proofs and owned scripts;
//      each of its transactions is detected twice, first with no rules answer (the detection may ask), then
//      with every id answered by the world's rule lines.
//
// THE FILE. Text, one record a line, fields separated by one space, numbers in decimal, scripts and txids in
// hex (txids in display order, lower case). A line that starts with '#' is a comment. `-` is "none".
//
//   claim <op> <total> <instructions> <vout> <first> <units> <outputCount> <claim> <remainder>
//     <op>: issuance, transfer, burn, other (a carrier that is not classified). <total>, <first>, <units>:
//     a number or `-`. <instructions>: `-`, or per instruction <flags>:<output>:<amount> joined by ','; <flags>
//     three characters s r p for skip, range and percent, each - when 0. <claim>: BRAssetClaimForOutputTotal.
//     <remainder>: BRAssetClaimRemainder, or `null`.
//
//   world <n>                                  a new world; the lines up to the next `world` belong to it
//   tx <txid> <inputs> <outputs>               <inputs>: <txid>:<index> joined by ','; <outputs>: <sats>:<script>
//   row <txid> <vout> <script> <sats> <height> <spent> <source> <credit> <quantity> <assetId>
//                                              <source>: backend, native; <credit>: unchecked, backed, verified,
//                                              mixed; <script> `.` when empty
//   proof <txid>                               its last output is proven to carry no units
//   owned <scripts>                            joined by ','; `-` for none (the owned set could not be built)
//   rule <assetId> <issuance> <api>            <issuance>: `-`, or <factsAssetId>:<opcode>:<locked>; <api>: `-` no
//                                              answer, 0 an answer without rules, 1 a rules object
//   detect <txid> <height> <outgoing> <walked> <rules> <status> <placeholder> <walkDue> <anyUnresolved> <asks>
//     One BRAssetDetect of the world's transaction <txid>, every other transaction of the world the wallet's.
//     <rules>: 0 with no rules answer given, 1 with the world's. <status>: done, not-asset, unclassifiable,
//     needs-rules, or a refusal. <asks>: the ids asked about, joined by ','.
//   out <vout> <targeted> <claimed> <credit> <write> <ask> <bound>
//     One output that gets a row, in order, after its detect line. <credit>: unknown, mixed, holds:-:<label>,
//     holds:<assetId>:<count>. <write>: nothing, or insert / update:<assetId>:<quantity>:<credit>:<source>.
//     <ask>: 1 when the indexer is asked. <bound>: `none` (no bound) or the most units believed.
//
//   An asset id may itself hold a ':' (a placeholder, "unresolved:<txid>"): split <credit> and <write> from the
//   right. An empty asset id is written `""`.
//
// The numbers drawn from the seeded stream are drawn one a statement: the order of two calls inside one
// expression is not fixed by C, and the file must be the same whatever compiler writes it.
//
// Build (it calls BRDigiAsset.c's classifier and BRAssetIdForIssuance): with the core's objects, as
// asset_detect_kat's run.sh does, then ./gen > vectors/asset-detect/vectors.txt. It exits 1, writing nothing it
// has not checked, when a fixture does not fit its buffers.
//

#include "BRAssetDetect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TMAX 16
#define IMAX 4
#define OMAX 8
#define RMAX 96
#define QMAX 8

static uint64_t RNG = 0x00d37ec7ULL;

static uint64_t rnd(void)
{
    RNG ^= RNG << 13;
    RNG ^= RNG >> 7;
    RNG ^= RNG << 17;
    return RNG;
}

static uint64_t below(uint64_t n) { return n ? rnd() % n : 0; }

static void fail(const char *why)
{
    fprintf(stderr, "generate: %s\n", why);
    exit(1);
}

static void hexOf(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static void txidOf(UInt256 h, char *out)
{
    uint8_t r[32];
    int i;

    for (i = 0; i < 32; i++) r[i] = h.u8[31 - i];
    hexOf(r, 32, out);
}

static size_t hx(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0, len = strlen(hex);

    if (len % 2 || len / 2 > cap) fail("a script does not fit");
    for (n = 0; n < len / 2; n++) {
        unsigned v;

        if (sscanf(hex + 2 * n, "%2x", &v) != 1) fail("not hex");
        out[n] = (uint8_t)v;
    }
    return n;
}

// ---- the world ----------------------------------------------------------------------------------

#define OURS   "0014111111111111111111111111111111111111111111"
#define OURS2  "0014333333333333333333333333333333333333333333"
#define THEIRS "0014222222222222222222222222222222222222222222"
#define NOTE   "6a0568656c6c6f"                 // a plain nulldata OP_RETURN, tagged nothing
#define BARE   "6aff"                           // an OP_RETURN output that is not nulldata, tagged nothing
#define PD2    "6a4d060044410215000a"
#define X "Laxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define Y "Layyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

typedef struct {
    BRTransaction tx;
    BRTxInput ins[IMAX];
    BRTxOutput outs[OMAX];
    uint8_t bytes[OMAX][120];
} Tx;

typedef struct {
    char txid[65];
    int32_t vout;
    uint8_t script[120];
    size_t scriptLen;
    int64_t sats, height, qty;
    int spent;
    BRAssetSource source;
    BRAssetCredit credit;
    int hasId;
    char id[96];
} Row;

typedef struct {
    char id[96];
    int hasFacts;
    BRAssetResolvedFacts facts;
    int hasApi, api;
} Rule;

static Tx TXS[TMAX];
static size_t TXN;
static const BRTransaction *TXP[TMAX];
static Row ROWS[RMAX];
static size_t ROWN;
static BRAssetRow VROWS[RMAX];
static UInt256 PROOFS[TMAX];
static size_t PROOFN;
static int OWNEDN;
static BRAssetScript OWNED[2];
static uint8_t OWNED_BYTES[2][32];
static Rule RULES[QMAX];
static size_t RULEN;
static BRAssetDetectRule VRULES[QMAX];

static UInt256 tid(uint32_t tag)
{
    UInt256 h;

    memset(h.u8, 0x5a, sizeof(h.u8));
    h.u8[0] = (uint8_t)tag;
    h.u8[1] = (uint8_t)(tag >> 8);
    return h;
}

static void reset(void)
{
    TXN = 0;
    ROWN = 0;
    PROOFN = 0;
    RULEN = 0;
    OWNEDN = 2;
    OWNED[0].bytes = OWNED_BYTES[0]; OWNED[0].len = hx(OURS, OWNED_BYTES[0], 32);
    OWNED[1].bytes = OWNED_BYTES[1]; OWNED[1].len = hx(OURS2, OWNED_BYTES[1], 32);
}

static Tx *tx(uint32_t tag)
{
    Tx *t;

    if (TXN >= TMAX) fail("too many transactions");
    t = &TXS[TXN++];
    memset(t, 0, sizeof(*t));
    t->tx.txHash = tid(tag);
    t->tx.inputs = t->ins;
    t->tx.outputs = t->outs;
    TXP[TXN - 1] = &t->tx;
    return t;
}

static void in(Tx *t, UInt256 h, uint32_t index)
{
    if (t->tx.inCount >= IMAX) fail("too many inputs");
    t->ins[t->tx.inCount].txHash = h;
    t->ins[t->tx.inCount].index = index;
    t->tx.inCount++;
}

static void outScript(Tx *t, const uint8_t *s, size_t n, uint64_t sats)
{
    BRTxOutput *o;

    if (t->tx.outCount >= OMAX || n > 120) fail("too many outputs");
    o = &t->outs[t->tx.outCount];
    memcpy(t->bytes[t->tx.outCount], s, n);
    o->script = t->bytes[t->tx.outCount];
    o->scriptLen = n;
    o->amount = sats;
    t->tx.outCount++;
}

static void outSats(Tx *t, const char *hex, uint64_t sats)
{
    uint8_t b[120];

    outScript(t, b, hx(hex, b, sizeof(b)), sats);
}

static void out(Tx *t, const char *hex) { outSats(t, hex, 600); }

typedef struct { uint8_t b[120]; size_t bits; } Bits;

static void put(Bits *w, uint64_t v, int n)
{
    int i;

    for (i = n - 1; i >= 0; i--) {
        size_t byte = w->bits / 8;

        if (byte >= sizeof(w->b)) fail("a carrier does not fit");
        if (w->bits % 8 == 0) w->b[byte] = 0;
        if ((v >> i) & 1) w->b[byte] |= (uint8_t)(0x80 >> (w->bits % 8));
        w->bits++;
    }
}

static void fixedAmount(Bits *w, uint64_t a)
{
    if (a < 32) { put(w, 0, 3); put(w, a, 5); }
    else { put(w, 1, 3); put(w, a & 511, 9); put(w, 0, 4); }
}

static void randomCarrier(Tx *t, int nOut)
{
    Bits w;
    uint8_t s[130];
    int ops[3] = { 0x05, 0x15, 0x25 }, op, n, i, version, flags, junk;
    uint64_t total;

    op = ops[below(3)];
    n = (int)below(4);
    version = below(5) == 0 ? 2 : 3;
    flags = below(2) ? 0x10 : 0;
    flags |= (int)(below(3) << 2);
    flags |= (int)(below(3) << 5);
    total = below(6) == 0 ? 0 : below(60);
    junk = below(10) == 0;
    memset(&w, 0, sizeof(w));
    put(&w, 0x4441, 16);
    put(&w, (uint64_t)version, 8);
    put(&w, (uint64_t)op, 8);
    if (op == 0x05) fixedAmount(&w, total);
    for (i = 0; i < n; i++) {
        uint64_t skip = below(5) == 0, range = below(5) == 0, percent = below(10) == 0, o, a;

        o = below(6) == 0 ? 31 : below((uint64_t)nOut + 1);
        a = below(4) == 0 ? 0 : below(40);
        put(&w, skip, 1);
        put(&w, range, 1);
        put(&w, percent, 1);
        put(&w, o, range ? 13 : 5);
        if (percent) put(&w, a, 8);
        else fixedAmount(&w, a);
    }
    while (w.bits % 8) put(&w, 0, 1);
    if (junk) put(&w, 0x5a, 8);
    if (op == 0x05) put(&w, (uint64_t)flags, 8);
    s[0] = 0x6a;
    s[1] = (uint8_t)(w.bits / 8);
    memcpy(s + 2, w.b, w.bits / 8);
    outScript(t, s, 2 + w.bits / 8, 0);
}

static Row *row(UInt256 h, int32_t vout, const BRTxOutput *o, BRAssetCredit credit, int64_t qty, const char *id, int spent)
{
    Row *r;

    if (ROWN >= RMAX) fail("too many rows");
    r = &ROWS[ROWN++];
    memset(r, 0, sizeof(*r));
    txidOf(h, r->txid);
    r->vout = vout;
    if (o) { memcpy(r->script, o->script, o->scriptLen); r->scriptLen = o->scriptLen; }
    r->sats = 600;
    r->height = 1;
    r->qty = qty;
    r->spent = spent;
    r->source = BR_ASSET_SOURCE_NATIVE;
    r->credit = credit;
    r->hasId = id != NULL;
    if (id) snprintf(r->id, sizeof(r->id), "%s", id);
    return r;
}

// kind: 0 free (a locked rule-free issuance, an answer without rules), 1 nothing known, 2 unlocked, 3 bound
static void rule(const char *id, int kind)
{
    Rule *r;

    if (RULEN >= QMAX) fail("too many rules");
    r = &RULES[RULEN++];
    memset(r, 0, sizeof(*r));
    snprintf(r->id, sizeof(r->id), "%s", id);
    if (kind == 1 || strlen(id) > BR_ASSET_ID_LENGTH) return;
    r->hasFacts = 1;
    snprintf(r->facts.assetId, sizeof(r->facts.assetId), "%s", id);
    r->facts.hasIssuanceOpcode = 1;
    r->facts.issuanceOpcode = (kind == 3) ? 3 : (kind == 2) ? 1 : 5;
    r->facts.hasIssuanceLocked = 1;
    r->facts.issuanceLocked = (kind == 2) ? 0 : 1;
    r->hasApi = 1;
    r->api = 0;
}

static int hasRule(const char *id)
{
    size_t i;

    for (i = 0; i < RULEN; i++) if (strcmp(RULES[i].id, id) == 0) return 1;
    return 0;
}

// ---- writing --------------------------------------------------------------------------------------

static const char *CREDITS[] = { "unchecked", "backed", "verified", "mixed" };

static const char *creditName(BRAssetCredit c) { return ((unsigned)c < 4) ? CREDITS[c] : "?"; }

static const char *STATUS[] = { "refused", "done", "not-asset", "unclassifiable", "needs-rules", "refused-arguments",
                                "refused-unreadable", "refused-rows", "refused-capacity" };

static void writeWorld(size_t n)
{
    size_t i, j;
    char h[300];

    printf("world %zu\n", n);
    for (i = 0; i < TXN; i++) {
        const BRTransaction *t = &TXS[i].tx;

        txidOf(t->txHash, h);
        printf("tx %s ", h);
        if (t->inCount == 0) printf("-");
        for (j = 0; j < t->inCount; j++) {
            txidOf(t->inputs[j].txHash, h);
            printf("%s%s:%u", j ? "," : "", h, (unsigned)t->inputs[j].index);
        }
        printf(" ");
        for (j = 0; j < t->outCount; j++) {
            hexOf(t->outputs[j].script, t->outputs[j].scriptLen, h);
            printf("%s%llu:%s", j ? "," : "", (unsigned long long)t->outputs[j].amount, h);
        }
        printf("\n");
    }
    for (i = 0; i < ROWN; i++) {
        const Row *r = &ROWS[i];

        hexOf(r->script, r->scriptLen, h);
        printf("row %s %d %s %lld %lld %d %s %s %lld %s\n", r->txid, (int)r->vout, r->scriptLen ? h : ".", (long long)r->sats,
               (long long)r->height, r->spent, r->source == BR_ASSET_SOURCE_NATIVE ? "native" : "backend", creditName(r->credit),
               (long long)r->qty, r->hasId ? (r->id[0] ? r->id : "\"\"") : "-");
    }
    for (i = 0; i < PROOFN; i++) {
        txidOf(PROOFS[i], h);
        printf("proof %s\n", h);
    }
    printf("owned %s\n", OWNEDN == 0 ? "-" : OURS "," OURS2);
    for (i = 0; i < RULEN; i++) {
        const Rule *r = &RULES[i];

        if (r->hasFacts) printf("rule %s %s:%d:%d %s\n", r->id, r->facts.assetId, (int)r->facts.issuanceOpcode,
                                r->facts.issuanceLocked, r->hasApi ? (r->api ? "1" : "0") : "-");
        else printf("rule %s - %s\n", r->id, r->hasApi ? (r->api ? "1" : "0") : "-");
    }
}

static BRAssetHoldWork WORK[RMAX + TMAX];
static BRAssetHoldRow HOLD[RMAX];
static BRAssetInputFacts INS[IMAX];
static size_t INROWS[IMAX], OUTROWS[OMAX];
static BRAssetUnits SLOTS[IMAX];
static BRAssetInputStack STACKS[IMAX];
static int64_t ALLOC[IMAX];
static const char *ASKS[IMAX];
static BRAssetDetectOutput OUTS[OMAX];
static BRAssetOutputUnits DELIV[2000];
static BRAssetDetection D;

static void detectOne(const BRTransaction *t, int64_t height, int outgoing, int walked, int withRules)
{
    BRAssetDetectView v;
    BRAssetDetectNeeds needs;
    BRAssetDetectBuffers b;
    BRAssetDetectStatus s;
    size_t i;
    char h[65];

    for (i = 0; i < ROWN; i++) {
        Row *r = &ROWS[i];

        memset(&VROWS[i], 0, sizeof(VROWS[i]));
        VROWS[i].txid = r->txid;
        VROWS[i].vout = r->vout;
        VROWS[i].script = r->scriptLen ? r->script : NULL;
        VROWS[i].scriptLen = r->scriptLen;
        VROWS[i].satoshis = r->sats;
        VROWS[i].blockHeight = r->height;
        VROWS[i].isAsset = 1;
        VROWS[i].assetId = r->hasId ? r->id : NULL;
        VROWS[i].assetQuantity = r->qty;
        VROWS[i].spent = r->spent;
        VROWS[i].source = r->source;
        VROWS[i].credit = r->credit;
    }
    for (i = 0; i < RULEN; i++) {
        VRULES[i].assetId = RULES[i].id;
        VRULES[i].issuance = RULES[i].hasFacts ? &RULES[i].facts : NULL;
        VRULES[i].hasApiRules = RULES[i].hasApi;
        VRULES[i].apiRules = RULES[i].api;
    }
    memset(&v, 0, sizeof(v));
    v.tx = t;
    v.blockHeight = height;
    v.isOutgoingUnconfirmed = outgoing;
    v.txs = TXP;
    v.txCount = TXN;
    v.owned = OWNEDN ? OWNED : NULL;
    v.ownedCount = (size_t)OWNEDN;
    v.rows = VROWS;
    v.rowCount = ROWN;
    v.proven = PROOFS;
    v.provenCount = PROOFN;
    v.rules = withRules ? VRULES : NULL;
    v.ruleCount = withRules ? RULEN : 0;
    v.walkedInSession = walked;
    if (! BRAssetDetectBounds(&v, &needs)) fail("bounds");
    if (needs.work > RMAX + TMAX || needs.holdRows > RMAX || needs.inputs > IMAX || needs.outputs > OMAX || needs.delivered > 2000)
        fail("a buffer is too small");
    memset(&b, 0, sizeof(b));
    b.work = WORK; b.workCap = needs.work;
    b.holdRows = HOLD; b.holdRowCap = needs.holdRows;
    b.inputs = INS; b.inputRows = INROWS; b.slots = SLOTS; b.stacks = STACKS; b.allocWork = ALLOC; b.asks = ASKS;
    b.inputCap = needs.inputs;
    b.outputRows = OUTROWS; b.outputs = OUTS; b.outputCap = needs.outputs;
    b.delivered = DELIV; b.deliveredCap = needs.delivered;
    s = BRAssetDetect(&v, &b, &D);
    txidOf(t->txHash, h);
    printf("detect %s %lld %d %d %d %s %s %d %d ", h, (long long)height, outgoing, walked, withRules,
           ((unsigned)s < 9) ? STATUS[s] : "?", (s == BR_ASSET_DETECT_DONE || s == BR_ASSET_DETECT_NEEDS_RULES) ? D.placeholder : "-",
           D.issuanceWalkDue, D.anyUnresolved);
    if (D.askCount == 0) printf("-");
    for (i = 0; i < D.askCount; i++) printf("%s%s", i ? "," : "", ASKS[i][0] ? ASKS[i] : "\"\"");
    printf("\n");
    for (i = 0; i < D.outputCount; i++) {
        const BRAssetDetectOutput *o = &OUTS[i];
        const BRAssetRow *r = &o->persist.row;

        printf("out %d %d %lld ", (int)o->vout, o->targeted, (long long)o->claimed);
        if (o->credit.kind == BR_ASSET_OUTPUT_UNKNOWN) printf("unknown ");
        else if (o->credit.kind == BR_ASSET_OUTPUT_MIXED) printf("mixed ");
        else if (! o->credit.hasUnits) printf("holds:-:%s ", o->credit.label ? o->credit.label : "-");
        else printf("holds:%s:%lld ", o->credit.assetId, (long long)o->credit.count);
        if (o->persist.action == BR_ASSET_PERSIST_NOTHING) printf("nothing ");
        else printf("%s:%s:%lld:%s:%s ", o->persist.action == BR_ASSET_PERSIST_INSERT ? "insert" : "update",
                    r->assetId ? (r->assetId[0] ? r->assetId : "\"\"") : "-", (long long)r->assetQuantity, creditName(r->credit),
                    r->source == BR_ASSET_SOURCE_NATIVE ? "native" : "backend");
        printf("%d ", o->askIndexer);
        if (o->bound.unbounded) printf("none\n");
        else printf("%lld\n", (long long)o->bound.max);
    }
}

static void detectWorld(size_t n)
{
    size_t i;

    writeWorld(n);
    for (i = 0; i < TXN; i++) {
        int64_t height = (int64_t)(i % 2) * 100;
        int outgoing = (i % 7) == 3, walked = (int)(i % 2);

        detectOne(&TXS[i].tx, height, outgoing, walked, 0);
        detectOne(&TXS[i].tx, height, outgoing, walked, 1);
    }
}

// ---- the claims ------------------------------------------------------------------------------------

static void claimLine(BRAssetOperation op, int hasTotal, int64_t total, const BRAssetTransferInstruction *l, size_t n,
                      int32_t vout, int hasFirst, int32_t first, int hasUnits, int64_t units, int32_t outputCount)
{
    static const char *ops[] = { "other", "issuance", "transfer", "burn" };
    int64_t c = BRAssetClaimForOutputTotal(op, hasTotal, total, l, n, vout, hasFirst, first, hasUnits, units, outputCount), r = 0;
    int known = BRAssetClaimRemainder(op, l, n, hasUnits, units, &r);
    size_t i;

    printf("claim %s ", (op == DA_ISSUANCE) ? ops[1] : (op == DA_TRANSFER) ? ops[2] : (op == DA_BURN) ? ops[3] : ops[0]);
    if (hasTotal) printf("%lld ", (long long)total); else printf("- ");
    if (n == 0) printf("-");
    for (i = 0; i < n; i++) printf("%s%c%c%c:%d:%lld", i ? "," : "", l[i].skip ? 's' : '-', l[i].range ? 'r' : '-',
                                   l[i].percent ? 'p' : '-', (int)l[i].outputIndex, (long long)l[i].amount);
    printf(" %d ", (int)vout);
    if (hasFirst) printf("%d ", (int)first); else printf("- ");
    if (hasUnits) printf("%lld ", (long long)units); else printf("- ");
    printf("%d %lld ", (int)outputCount, (long long)c);
    if (known) printf("%lld\n", (long long)r); else printf("null\n");
}

static BRAssetTransferInstruction ti(int32_t o, int64_t a, int range, int percent)
{
    BRAssetTransferInstruction t;

    memset(&t, 0, sizeof(t));
    t.outputIndex = o;
    t.amount = a;
    t.range = range;
    t.percent = percent;
    return t;
}

static void claims(void)
{
    BRAssetTransferInstruction l[3];
    BRAssetOperation ops[4] = { DA_UNDEFINED, DA_ISSUANCE, DA_TRANSFER, DA_BURN };
    int k, i;

    l[0] = ti(0, 10, 0, 0);
    claimLine(DA_TRANSFER, 0, 0, l, 1, 3, 1, 0, 1, 100, 4);
    claimLine(DA_TRANSFER, 0, 0, l, 1, 3, 1, 0, 0, 0, 4);
    l[0] = ti(0, 150, 0, 0);
    claimLine(DA_TRANSFER, 0, 0, l, 1, 3, 1, 0, 1, 100, 4);
    l[0] = ti(31, 60, 0, 0); l[1] = ti(1, 40, 0, 0); l[2] = ti(2, 5, 1, 0);
    for (i = 0; i < 4; i++) claimLine(DA_BURN, 0, 0, l, 3, i, 0, 0, 1, 130, 4);
    claimLine(DA_TRANSFER, 0, 0, l, 3, 31, 0, 0, 1, 130, 33);
    l[0] = ti(1, 8000000000000000000LL, 1, 0);
    claimLine(DA_TRANSFER, 0, 0, l, 1, 2, 1, 0, 1, 0, 3);
    l[0] = ti(0, INT64_MAX - 5, 0, 0);
    claimLine(DA_TRANSFER, 0, 0, l, 1, 0, 1, 0, 1, 10, 1);
    l[0] = ti(0, 100, 0, 0);
    claimLine(DA_ISSUANCE, 1, 100, l, 1, 0, 1, 0, 0, 0, 3);
    claimLine(DA_ISSUANCE, 1, 100, l, 1, 0, 0, 0, 0, 0, 3);
    claimLine(DA_ISSUANCE, 0, 0, l, 1, 0, 1, 0, 0, 0, 3);
    claimLine(DA_UNDEFINED, 0, 0, NULL, 0, 0, 1, 0, 1, 5, 3);

    for (k = 0; k < 200; k++) {
        BRAssetOperation op = ops[below(4)];
        int n = (int)below(4), outputCount = 1 + (int)below(6), vout = (int)below((uint64_t)outputCount + 1), hasUnits, hasFirst, hasTotal;
        int32_t first;
        int64_t units, total;

        for (i = 0; i < n; i++) {
            int32_t o = below(6) == 0 ? 31 : (int32_t)below((uint64_t)outputCount + 1);
            int64_t a = below(5) == 0 ? 0 : (int64_t)below(50);
            int range = below(5) == 0, percent = below(8) == 0;

            l[i] = ti(o, a, range, percent);
            l[i].skip = below(4) == 0;
        }
        hasUnits = below(4) != 0;
        units = (int64_t)below(120);
        hasFirst = below(5) != 0;
        first = (int32_t)below((uint64_t)outputCount);
        hasTotal = below(5) != 0;
        total = (int64_t)below(90);
        claimLine(op, hasTotal, total, l, (size_t)n, vout, hasFirst, first, hasUnits, units, outputCount);
    }
}

// ---- the worlds --------------------------------------------------------------------------------------

static void handWorlds(void)
{
    Tx *p, *t;

    // a transfer of the wallet's own X:9, plus a plain input; 5 to output 0, the rest to the last
    reset();
    p = tx(1); out(p, THEIRS);
    t = tx(2); in(t, tid(1), 0); in(t, tid(9), 0); out(t, OURS); out(t, "6a06444103150005"); out(t, OURS);
    row(tid(9), 0, &p->outs[0], BR_ASSET_CREDIT_VERIFIED, 9, X, 1);
    rule(X, 0);
    detectWorld(1);

    // the same from someone else's inputs, and with a rule-bound asset
    reset();
    t = tx(3); in(t, tid(8), 0); out(t, OURS); out(t, "6a06444103150005"); out(t, OURS);
    p = tx(4); in(p, tid(7), 0); out(p, OURS); out(p, "6a06444103150005"); out(p, OURS);
    row(tid(7), 0, NULL, BR_ASSET_CREDIT_BACKED, 9, Y, 1);
    rule(Y, 3);
    detectWorld(2);

    // issuances: locked (named from the first input) and unlocked (a placeholder); an unclassifiable carrier
    reset();
    p = tx(5); out(p, THEIRS);
    t = tx(6); in(t, tid(5), 0); out(t, OURS); out(t, "6a0a44410305201601201610"); out(t, OURS);
    t = tx(10); in(t, tid(5), 0); out(t, OURS); out(t, "6a0a44410305201601201600"); out(t, OURS);
    t = tx(11); in(t, tid(5), 0); out(t, OURS); out(t, PD2); out(t, OURS);
    detectWorld(3);

    // no owned set; a settled transaction; a plain OP_RETURN before the carrier (two nulldata outputs: the one
    // carrier rule leaves it undecided); a proof
    reset();
    OWNEDN = 0;
    t = tx(12); in(t, tid(13), 0); out(t, OURS); out(t, NOTE); out(t, "6a0644410115000a"); out(t, THEIRS);
    t = tx(14); in(t, tid(13), 0); out(t, OURS); out(t, "6a06444103150005"); out(t, OURS);
    row(tid(14), 0, &t->outs[0], BR_ASSET_CREDIT_VERIFIED, 5, X, 0);
    row(tid(14), 2, &t->outs[2], BR_ASSET_CREDIT_MIXED, 0, "unresolved:z", 0);
    PROOFS[PROOFN++] = tid(12);
    detectWorld(4);

    // the one carrier rule (BRTxAssetCarrier): an OP_RETURN that is not nulldata before the carrier (decided,
    // not the first OP_RETURN); two carriers; the encrypted-key shape and the same with output 0 at 600; an
    // unlocked issuance after an OP_RETURN that is not nulldata (walked: the rename cannot rename its rows);
    // a lone carrier that is not nulldata; the same unlocked issuance as the only OP_RETURN (walked: due)
    reset();
    p = tx(15); out(p, THEIRS);
    t = tx(16); in(t, tid(15), 0); out(t, OURS); out(t, BARE); out(t, "6a06444103150005"); out(t, OURS);
    t = tx(17); in(t, tid(15), 0); out(t, OURS); out(t, "6a0644410315000a"); out(t, "6a06444103150105"); out(t, OURS);
    t = tx(18); in(t, tid(15), 0); outSats(t, OURS, 650); out(t, "6a06444103150005"); out(t, OURS);
    t = tx(19); in(t, tid(15), 0); out(t, OURS); out(t, "6a06444103150005"); out(t, OURS);
    t = tx(21); in(t, tid(15), 0); out(t, OURS); out(t, BARE); out(t, "6a0a44410305201600201600"); out(t, OURS);
    t = tx(20); in(t, tid(15), 0); out(t, OURS); out(t, "6a06444103150005ff"); out(t, OURS);
    t = tx(22); in(t, tid(15), 0); out(t, OURS); out(t, "6a0a44410305201600201600"); out(t, OURS);
    detectWorld(5);
}

static void seededWorlds(void)
{
    size_t w, t, j, i;
    static const char *ids[3] = { X, Y, "" };

    for (w = 0; w < 60; w++) {
        size_t nTx = 2 + below(5);

        reset();
        for (t = 0; t < nTx; t++) {
            Tx *f = tx(0x100 + (uint32_t)t);
            size_t nIn = below(4), nOut = 1 + below(5), at;

            at = below(6) == 0 ? 99 : below(nOut);
            for (i = 0; i < nIn; i++) {
                uint64_t r = below(12);

                if (r < 7 && t > 0) {
                    size_t p = below(t);
                    uint32_t index = (uint32_t)below(TXS[p].tx.outCount + 1);

                    in(f, TXS[p].tx.txHash, index);
                }
                else if (r < 11) {
                    uint32_t tag = 0x900 + (uint32_t)below(3), index = (uint32_t)below(3);

                    in(f, tid(tag), index);
                }
                else in(f, tid(0x950), 0x80000000u);
            }
            for (j = 0; j < nOut; j++) {
                uint64_t r = below(12);

                if (j == at) randomCarrier(f, (int)nOut);
                else if (r < 4) out(f, OURS);
                else if (r < 6) out(f, OURS2);
                else if (r < 9) out(f, THEIRS);
                else if (r == 9) out(f, NOTE);
                else if (r == 10) randomCarrier(f, (int)nOut);
                else out(f, PD2);
            }
        }
        for (t = 0; t < nTx; t++) {
            for (j = 0; j < TXS[t].tx.outCount; j++) {
                const char *id;
                char ph[96], h[65];
                uint64_t pick;
                BRAssetCredit credit;
                int64_t qty;
                int spent;

                if (below(10) >= 4) continue;
                pick = below(6);
                if (pick == 0) id = NULL;
                else if (pick == 1) id = ids[2];
                else if (pick == 2) {
                    txidOf(TXS[below(nTx)].tx.txHash, h);
                    snprintf(ph, sizeof(ph), "unresolved:%s", h);
                    id = ph;
                }
                else if (pick == 3) id = Y;
                else id = X;
                credit = (BRAssetCredit)(below(3) == 0 ? below(4) : 1 + below(2));
                qty = below(8) == 0 ? -(int64_t)below(3) : below(3) == 0 ? 0 : (int64_t)below(30);
                spent = below(3) == 0;
                row(TXS[t].tx.txHash, (int32_t)j, &TXS[t].tx.outputs[j], credit, qty, id, spent);
            }
            if (below(7) == 0) PROOFS[PROOFN++] = TXS[t].tx.txHash;
        }
        OWNEDN = below(8) == 0 ? 0 : 2;
        if (below(2)) rule(X, (int)below(4));
        if (below(2)) rule(Y, (int)below(4));
        for (i = 0; i < ROWN; i++) if (ROWS[i].hasId && ROWS[i].id[0] && ! hasRule(ROWS[i].id)) rule(ROWS[i].id, 1);
        detectWorld(100 + w);
    }
}

int main(void)
{
    printf("# BRAssetDetect.h vectors: the header's answers, written down. Generated by vectors/asset-detect/generate.c,\n"
           "# which describes each field; do not edit (asset_detect_kat checks it). One record a line, fields separated\n"
           "# by one space, numbers in decimal, scripts and txids in hex (txids in display order). `-` is none.\n"
           "# claim <op> <total> <flags:output:amount,...> <vout> <first> <units> <outputCount> <claim> <remainder|null>\n"
           "# world <n>, then: tx <txid> <txid:index,...> <sats:script,...>; row <txid> <vout> <script|.> <sats> <height>\n"
           "#   <spent> <source> <credit> <quantity> <assetId>; proof <txid>; owned <scripts>; rule <assetId>\n"
           "#   <factsAssetId:opcode:locked|-> <api -|0|1>\n"
           "# detect <txid> <height> <outgoing> <walked> <rules> <status> <placeholder> <walkDue> <anyUnresolved> <asks>\n"
           "# out <vout> <targeted> <claimed> <credit> <write> <ask> <bound|none>\n"
           "# An asset id may hold a ':' (a placeholder): split <credit> and <write> from the right. \"\" is an empty id.\n");
    claims();
    handWorlds();
    seededWorlds();
    return 0;
}
