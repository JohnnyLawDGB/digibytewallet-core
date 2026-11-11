// Vectors for BRAssetAllocate.h and BRAssetId.h: the headers' own answers on a fixed corpus, so a
// platform that keeps an allocator of its own (Android's AssetTransferAllocator.kt, AssetCredit.kt and
// the input rules in AssetManager.kt, which its host-JVM tests run) can be held to the core without
// loading it. These are the headers written down, not independent answers; the host KAT
// asset_allocate_kat holds the headers to the Kotlin tests' own expectations and to a line-for-line
// model of the Kotlin, and checks this file is current.
//
// The corpus, in the order it is written:
//   1. HAND: the transfers, burns and issuances of the Kotlin tests (their scripts, decoded here, or
//      their instruction lists), over the inputs those tests give;
//   2. a seeded set of transfers, burns and headers of other operations, over seeded inputs;
//   3. a seeded set of issuances;
//   4. every one-row input BRAssetBackedInputStack distinguishes, then seeded input totals and
//      indexer answers;
//   5. what the ids the corpus uses say of their aggregation;
//   6. the ids of the Kotlin tests' and this file's issuances, then a seeded set.
// A line that an earlier line already states is not written again, so no line occurs twice.
//
// THE FILE. Text, one vector a line, fields separated by one space, every number in decimal. A line
// that starts with '#' is a comment. Asset ids are short names (La1, Lh1, pending, ...) that hold no
// space, ':', ',' or '/'.
//
//   allocate <operation> <version> <exact> <outputs> <instructions> <inputs> <allocation> <credits> <bounds>
//
//     BRAssetAllocate for a header of <operation> (transfer, burn, issuance or undefined) and
//     <version>, the payload read exactly (<exact> 1) or not (0), <outputs> outputs, the instruction
//     list and the inputs given, with work and out buffers that always suffice.
//       <instructions>  `-` for none, or per instruction <flags>:<output>:<amount> joined by ',';
//                       <flags> three characters s r p for skip, range and percent, each - when 0
//       <inputs>        `none` for no input, or per input, joined by '/': `?` (not known), `-` (no
//                       entry) or its entries <id>:<count>:<ruleFree> joined by ','
//       <allocation>    `indeterminate <reason>`, `none` (NOT_AN_ASSET_TRANSFER) or
//                       `allocated <voided> <deliveries>`, the deliveries in the order of `out`,
//                       <vout>:<id>:<count> joined by ',', or `-` for none. <reason> is the
//                       BRAssetAllocationWhy name in lower case, BR_ASSET_WHY_ dropped and '_' as '-'
//       <credits>       BRAssetCreditForOutput for every vout from -1 to <outputs> (to 1 when
//                       <outputs> is below 1), joined by ',': `u` UNKNOWN, `m` MIXED, `-` HOLDS
//                       nothing, `-=<label>` HOLDS nothing with a label, `<id>:<count>` HOLDS units
//                       (whose label is always their id)
//       <bounds>        BRAssetMaxDeliverable for the same vouts, joined by ',': a number, or `*` for
//                       no bound
//
//   issue <operation> <exact> <total> <aggregation> <outputs> <instructions> <id> <allocation> <credits>
//
//     BRAssetAllocateIssuance for a header of <operation>, its totalQuantity <total> (`-` when
//     hasTotalQuantity is 0) and <aggregation> (aggregatable, hybrid or dispersed), the new asset
//     named <id>; the other fields as for allocate.
//
//   stack <row> <credit> <quantity> <id> <targeted> <data-output> <stack>
//
//     BRAssetBackedInputStack of one input: <row> 1 when the wallet holds a row for it; <credit>
//     unchecked, backed, verified or mixed; <id> the row's asset id, `-` for none (NULL) and `empty`
//     for ""; <targeted> rowIsTargeted and <data-output> fundingHasDataOutput, each yes, no or
//     unknown. <stack> is `?` (not known), `-` (no entry) or <id>:<count>.
//
//   resolve <inputs> <ask> <answer>
//
//     BRAssetResolveInputUnits. <inputs>: `none`, or per input joined by '/' `r<quantity>:<targeted>`
//     (a row storing that quantity; yes, no or unknown) or `n:<asset-tx>` (no row; whether the
//     funding transaction carries a DigiAsset payload). <ask> 1 when zeroRows has room for every
//     input, 0 when it is NULL. <answer>: `known <units>`, `unknown`, or `unknown <rows> <other>` with
//     the input indices joined by ',' and otherUnits.
//
//   indexer <lookup> <entries> <answer>
//
//     BRAssetCreditFromIndexer for <lookup> found, not-unspent or unavailable and <entries> (`-` for
//     none, else <id>:<count> joined by ','). <answer>: `null` when it returns 0, else as a credit.
//
//   aggregation <id> <answer>
//
//     BRAssetAggregationOfId: aggregatable, hybrid, dispersed, or `-` when the id says nothing.
//
//   id <txid> <vout> <locked> <aggregation> <divisibility> <answer>
//
//     BRAssetIdForIssuance with a BR_ASSET_ID_BUFFER buffer; <aggregation> as a number (0, 1, 2 are
//     the three; others are refused); <answer> the id, or `null` when it returns 0.
//
// The numbers drawn from the seeded stream are drawn one a statement: the order of two calls inside
// one expression is the compiler's choice, and the file must come out the same from every compiler.
//
// Regenerate, from this directory (BRAssetId.h needs the core's hashes and base58):
//   cc -I ../.. -o /tmp/asset_allocate_vectors generate.c ../../BRBase58.c ../../BRCrypto.c \
//     ../../crypto/groestl.c ../../crypto/skein.c ../../crypto/qubit.c ../../crypto/odocrypt.c \
//     ../../crypto/sha3/*.c && /tmp/asset_allocate_vectors > vectors.txt

#include "BRAssetAllocate.h"
#include "BRAssetId.h"

#include <stdio.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof((a)[0]))

static uint64_t RNG = 0xA110CA7E2026ULL;

static uint32_t rnd(void)   // xorshift64: the same stream on every machine
{
    RNG ^= RNG << 13; RNG ^= RNG >> 7; RNG ^= RNG << 17;
    return (uint32_t)(RNG >> 24);
}

static uint32_t below(uint32_t n) { return rnd() % n; }

// A vector is written into LINE and printed by endLine, unless an earlier line was the same text.
static char LINE[16384], SEEN[1 << 22];
static size_t LINELEN = 0, SEENLEN = 0;
static int BROKEN = 0;   // a line or the corpus outgrew its buffer, or a hand vector is broken: main fails

#define OUT(...) do { \
    int w_ = snprintf(LINE + LINELEN, sizeof(LINE) - LINELEN, __VA_ARGS__); \
    if (w_ < 0 || (size_t)w_ >= sizeof(LINE) - LINELEN) BROKEN = 1; else LINELEN += (size_t)w_; \
} while (0)

static void endLine(void)
{
    size_t at = 0, size = LINELEN + 1;   // with its terminator

    while (at < SEENLEN && strcmp(SEEN + at, LINE) != 0) at += strlen(SEEN + at) + 1;

    if (at == SEENLEN) {
        if (size > sizeof(SEEN) - SEENLEN) BROKEN = 1;
        else {
            memcpy(SEEN + SEENLEN, LINE, size);
            SEENLEN += size;
            printf("%s\n", LINE);
        }
    }

    LINELEN = 0;
    LINE[0] = '\0';
}

// ---- the words ------------------------------------------------------------------------------

static const char *opWord(BRAssetOperation op)
{
    switch (op) {
        case DA_ISSUANCE: return "issuance";
        case DA_TRANSFER: return "transfer";
        case DA_BURN: return "burn";
        default: return "undefined";
    }
}

static const char *const AGGS[] = { "aggregatable", "hybrid", "dispersed" };
static const char *const FACTS[] = { "unknown", "no", "yes" };
static const char *const CREDITS[] = { "unchecked", "backed", "verified", "mixed" };
static const char *const LOOKUPS[] = { "unavailable", "not-unspent", "found" };

static const char *whyWord(BRAssetAllocationWhy why)
{
    static const char *const words[] = {
        "none", "arguments", "capacity", "issuance", "unclassifiable", "no-outputs", "no-inputs", "input-unknown",
        "percent", "rules", "not-issuance", "payload-not-exact", "no-issued-amount", "malformed-instruction",
        "non-aggregable-draw", "overflow",
    };

    if ((size_t)why >= N(words)) { BROKEN = 1; return "?"; }
    return words[why];
}

// ---- writing the answers ------------------------------------------------------------------------

static BRAssetHeader H;
static BRAssetTransferInstruction L[BR_ASSET_MAX_INSTRUCTIONS];
static size_t LN;
static BRAssetUnits U[8][8];
static BRAssetInputStack IN[8];
static size_t INN;
static int64_t W[64];
static BRAssetOutputUnits O[1024];

static void instructions(void)
{
    size_t i;

    if (LN == 0) OUT(" -");
    for (i = 0; i < LN; i++) {
        OUT("%s%c%c%c:%d:%lld", i ? "," : " ", L[i].skip ? 's' : '-', L[i].range ? 'r' : '-', L[i].percent ? 'p' : '-',
            (int)L[i].outputIndex, (long long)L[i].amount);
    }
}

static void allocation(BRAssetAllocation r)
{
    size_t i;

    if (r.status == BR_ASSET_ALLOCATION_INDETERMINATE) { OUT(" indeterminate %s", whyWord(r.why)); return; }
    if (r.status == BR_ASSET_ALLOCATION_NOT_AN_ASSET_TRANSFER) { OUT(" none"); return; }
    OUT(" allocated %d", r.instructionsVoided);
    if (r.count == 0) OUT(" -");
    for (i = 0; i < r.count; i++) OUT("%s%d:%s:%lld", i ? "," : " ", (int)O[i].vout, O[i].assetId, (long long)O[i].count);
}

static void creditWord(BRAssetOutputCredit c)
{
    if (c.kind == BR_ASSET_OUTPUT_UNKNOWN) OUT("u");
    else if (c.kind == BR_ASSET_OUTPUT_MIXED) OUT("m");
    else if (c.hasUnits) OUT("%s:%lld", c.assetId, (long long)c.count);
    else if (c.label) OUT("-=%s", c.label);
    else OUT("-");
}

static void credits(BRAssetAllocation r, int32_t outputCount)
{
    int32_t vout, last = (outputCount < 1) ? 1 : outputCount;

    for (vout = -1; vout <= last; vout++) {
        OUT(vout == -1 ? " " : ",");
        creditWord(BRAssetCreditForOutput(r, O, L, LN, vout, outputCount));
    }
}

static void bounds(int32_t outputCount)
{
    int32_t vout, last = (outputCount < 1) ? 1 : outputCount;

    for (vout = -1; vout <= last; vout++) {
        BRAssetDeliverable d = BRAssetMaxDeliverable(&H, L, LN, vout, outputCount);

        if (d.unbounded) OUT("%s*", vout == -1 ? " " : ",");
        else OUT("%s%lld", vout == -1 ? " " : ",", (long long)d.max);
    }
}

static void allocateLine(int exact, int32_t outputCount)
{
    BRAssetAllocation r = BRAssetAllocate(&H, L, LN, exact, IN, INN, outputCount, W, N(W), O, N(O));
    size_t i, j;

    if (r.why == BR_ASSET_WHY_CAPACITY || r.why == BR_ASSET_WHY_ARGUMENTS) BROKEN = 1;
    OUT("allocate %s %d %d %d", opWord(H.operation), (int)H.version, exact, (int)outputCount);
    instructions();
    if (INN == 0) OUT(" none");
    for (i = 0; i < INN; i++) {
        OUT(i ? "/" : " ");
        if (! IN[i].known) { OUT("?"); continue; }
        if (IN[i].unitCount == 0) OUT("-");
        for (j = 0; j < IN[i].unitCount; j++) {
            OUT("%s%s:%lld:%d", j ? "," : "", IN[i].units[j].assetId, (long long)IN[i].units[j].count, IN[i].units[j].ruleFree);
        }
    }
    allocation(r);
    credits(r, outputCount);
    bounds(outputCount);
    endLine();
}

static void issueLine(const char *assetId, int exact, int32_t outputCount)
{
    BRAssetAllocation r = BRAssetAllocateIssuance(&H, L, LN, assetId, outputCount, exact, O, N(O));

    if (r.why == BR_ASSET_WHY_CAPACITY || r.why == BR_ASSET_WHY_ARGUMENTS) BROKEN = 1;
    OUT("issue %s %d", opWord(H.operation), exact);
    if (H.hasTotalQuantity) OUT(" %lld", (long long)H.totalQuantity);
    else OUT(" -");
    OUT(" %s %d", AGGS[H.aggregation], (int)outputCount);
    instructions();
    OUT(" %s", assetId);
    allocation(r);
    credits(r, outputCount);
    endLine();
}

// ---- the hand vectors' notation (as in the KAT): instructions "<out>:<amount>[:<srp>]" separated by
// spaces; inputs '/'-separated, each "-", "?" or "<id>:<count>[!]" joined by ',' ('!': not rule-free)

static int64_t num(const char **p)
{
    int64_t v = 0;
    int neg = 0, digits = 0;

    if (strncmp(*p, "MAX", 3) == 0) { *p += 3; return INT64_MAX; }
    if (strncmp(*p, "HALF", 4) == 0) { *p += 4; return INT64_MAX / 2; }
    if (**p == '-') { neg = 1; (*p)++; }
    while (**p >= '0' && **p <= '9') { v = v * 10 + (**p - '0'); (*p)++; digits++; }
    if (! digits) BROKEN = 1;
    return neg ? -v : v;
}

static void header(BRAssetOperation op, int32_t version, const char *spec)
{
    const char *p = spec;

    memset(&H, 0, sizeof(H));
    H.kind = BR_ASSET_SCRIPT_ASSET;
    H.version = version;
    H.opcode = 0x15;
    H.operation = op;
    H.locked = 1;
    LN = 0;
    while (*p) {
        BRAssetTransferInstruction *t = &L[LN];

        if (*p == ' ') { p++; continue; }
        memset(t, 0, sizeof(*t));
        t->outputIndex = (int32_t)num(&p);
        if (*p++ != ':') BROKEN = 1;
        t->amount = num(&p);
        if (*p == ':') for (p++; *p && *p != ' '; p++) { if (*p == 's') t->skip = 1; if (*p == 'r') t->range = 1; if (*p == 'p') t->percent = 1; }
        t->isBurn = ! t->range && t->outputIndex == BR_ASSET_BURN_OUTPUT;
        LN++;
    }
    H.instructionCount = LN;
}

static int digit(char c) { return (c <= '9') ? c - '0' : c - 'a' + 10; }

static int script(const char *hex)
{
    uint8_t s[128];
    size_t n = 0;

    while (hex[0] && hex[1] && n < sizeof(s)) { s[n++] = (uint8_t)(digit(hex[0]) * 16 + digit(hex[1])); hex += 2; }
    if (BRAssetDecodeInstructions(s, n, &H, L, N(L)) != BR_ASSET_SCRIPT_ASSET) { BROKEN = 1; return 0; }
    LN = H.instructionCount;
    return BRAssetPayloadReadsExactly(s, n, &H, L, LN);
}

static void inputs(const char *spec)
{
    const char *p = spec;

    INN = 0;
    for (;;) {
        BRAssetInputStack *s = &IN[INN];

        s->known = 1;
        s->units = U[INN];
        s->unitCount = 0;
        if (*p == '?') { s->known = 0; p++; }
        else if (*p == '-') p++;
        else {
            for (;;) {
                const char *name = p;
                static char ids[64][16];
                static size_t idCount = 0;
                BRAssetUnits *u = &U[INN][s->unitCount++];
                size_t len, k;

                while (*p && *p != ':') p++;
                len = (size_t)(p - name);
                for (k = 0; k < idCount && (strlen(ids[k]) != len || strncmp(ids[k], name, len) != 0); k++) { }
                if (k == idCount) {
                    if (idCount >= N(ids) || len >= sizeof(ids[0])) { BROKEN = 1; return; }
                    memcpy(ids[k], name, len);
                    ids[k][len] = '\0';
                    idCount++;
                }
                u->assetId = ids[k];
                if (*p++ != ':') BROKEN = 1;
                u->count = num(&p);
                u->ruleFree = 1;
                if (*p == '!') { u->ruleFree = 0; p++; }
                if (*p != ',') break;
                p++;
            }
        }
        INN++;
        if (*p != '/') break;
        p++;
    }
    if (*p) BROKEN = 1;
}

// ---- the corpus ---------------------------------------------------------------------------------

typedef struct { const char *script, *inputs; int32_t outputs; } ScriptVector;
static const ScriptVector SCRIPTED[] = {   // AssetTransferAllocatorTest, AssetHoldCoversCreditedOutputsTest
    { "6a0b4441031500018060f423f0", "La1:1/-", 3 },
    { "6a0744410315012012", "-", 3 },
    { "6a0744410315002016", "-/-", 3 },
    { "6a0744410315002016", "La1:1", 3 },
    { "6a06444103150005", "La1:9/-", 3 },
    { "6a09444103158201002644", "La1:1/La2:1000000", 3 },
    { "6a0844410315810a000a", "La2:10/La3:10", 3 },
    { "6a06444103150005", "-/La2:9", 3 },
    { "6a06444103150005", "La1:9/?", 3 },
    { "6a06444103150509", "La1:9", 3 },
    { "6a06444103150509", "-", 3 },
    { "6a06444103250509", "La1:9", 3 },
    { "6a06444103251f09", "La1:9", 3 },
    { "6a0d444103155fffffffffffffffff", "-", 3 },
};

typedef struct { BRAssetOperation op; int32_t version; const char *insts, *inputs; int32_t outputs; } BuiltVector;
static const BuiltVector BUILT[] = {   // AssetTransferAllocatorTest, AssetHoldCoversCreditedOutputsTest, UnbackedAssetCreditTest
    { DA_TRANSFER, 3, "0:3 1:4", "La1:3,La2:4", 3 },
    { DA_TRANSFER, 3, "0:5", "La1:3,La2:4", 3 },
    { DA_TRANSFER, 3, "0:3 0:4", "La1:3,La2:4", 3 },
    { DA_TRANSFER, 3, "5:2", "La1:9", 3 },
    { DA_TRANSFER, 3, "1:3:r", "La1:10", 3 },
    { DA_BURN, 3, "31:4", "La1:10", 3 },
    { DA_TRANSFER, 3, "31:4", "La1:10", 3 },
    { DA_TRANSFER, 3, "31:4", "La1:10", 33 },
    { DA_TRANSFER, 3, "0:2:s 1:3", "La1:2/La2:3", 3 },
    { DA_TRANSFER, 2, "0:2", "-/La1:5", 3 },
    { DA_TRANSFER, 3, "0:128:p", "La1:9", 3 },
    { DA_TRANSFER, 3, "0:1", "La1:9!", 3 },
    { DA_TRANSFER, 3, "0:5", "Lh1:3/Lh1:3", 3 },
    { DA_TRANSFER, 3, "0:5", "Ld1:3/Ld1:3", 3 },
    { DA_TRANSFER, 3, "0:5", "pending:3/pending:3", 3 },
    { DA_TRANSFER, 3, "0:5", "pending:3", 3 },
    { DA_TRANSFER, 3, "0:5", "Lh1:6", 3 },
    { DA_ISSUANCE, 3, "", "-", 2 },
    { DA_TRANSFER, 3, "8000:HALF:r", "La1:9", 3 },
    { DA_TRANSFER, 3, "0:5 1:0", "La1:5", 3 },
    { DA_TRANSFER, 3, "3:3:r", "La1:12", 3 },
    { DA_TRANSFER, 3, "3:7:r", "-", 5 },
    { DA_TRANSFER, 3, "0:MAX 0:1", "-", 3 },
    { DA_TRANSFER, 3, "0:5", "?", 4 },
};

typedef struct { const char *script; int32_t outputs; int exact; } IssueVector;
static const IssueVector ISSUED[] = {   // AssetTransferAllocatorTest, AssetHoldCoversCreditedOutputsTest, UnbackedAssetCreditTest
    { "6a084441030 50a000410", 3, -1 }, { "6a0644410305 0a10", 3, -1 }, { "6a0644410305 0a10", 3, 0 },
    { "6a0844410305 0a001414", 3, -1 }, { "6a0844410305 0a050410", 3, -1 }, { "6a0844410305 0a000a10", 3, -1 },
    { "6a0844410305 0a001410", 3, -1 }, { "6a0944410305 2016012016 10", 3, -1 }, { "6a0a44410305 2016012016 10", 3, -1 },
    { "6a0744410305 201610", 2, -1 }, { "6a0744410305 201610", 3, -1 }, { "6a0a44410305 2016002016 10", 2, -1 },
    { "6a0944410305 2016012010", 3, -1 },
};

static void unspaced(const char *in, char *out)
{
    while (*in) { if (*in != ' ') *out++ = *in; in++; }
    *out = '\0';
}

static const char *const POOL[] = { "La1", "La1", "La2", "La2", "La3", "Lh1", "Ld1", "pending", "Ua1", "Uh1", "Ud1", "La", "Lx1" };

static int64_t rndCount(void)
{
    uint32_t k = below(20);

    if (k == 0) return 0;
    if (k == 1) return -1;
    if (k == 2) return INT64_MAX / 2 + (int64_t)below(3);
    return 1 + (int64_t)below(12);
}

static int64_t rndAmount(void)
{
    uint32_t k = below(24);

    if (k < 3) return 0;
    if (k == 3) return -1;
    if (k == 4) return INT64_MAX / 2 + (int64_t)below(2);
    if (k == 5) return BR_ASSET_MAX_ISSUANCE;
    return 1 + (int64_t)below(12);
}

static void rndInstructions(int32_t outputCount)
{
    size_t k, count = below(5);

    LN = count;
    for (k = 0; k < count; k++) {
        BRAssetTransferInstruction *t = &L[k];
        uint32_t where = below(12);

        memset(t, 0, sizeof(*t));
        if (where == 0) t->outputIndex = BR_ASSET_BURN_OUTPUT;
        else if (where == 1) t->outputIndex = -1;
        else t->outputIndex = (int32_t)below((uint32_t)(outputCount > 0 ? outputCount : 1) + 2);
        t->amount = rndAmount();
        t->range = (below(6) == 0);
        t->percent = (below(14) == 0);
        t->skip = (below(3) == 0);
        t->isBurn = ! t->range && t->outputIndex == BR_ASSET_BURN_OUTPUT;
    }
    H.instructionCount = LN;
}

static int32_t rndOutputs(void)
{
    uint32_t k = below(14);

    if (k == 0) return (int32_t)below(3) - 1;
    if (k == 1) return 32 + (int32_t)below(2);
    return 1 + (int32_t)below(5);
}

static void rndInputs(void)
{
    int free[N(POOL)];
    size_t i, j, n;

    for (i = 0; i < N(POOL); i++) free[i] = (below(10) != 0);
    for (i = 1; i < N(POOL); i++) if (strcmp(POOL[i], POOL[i - 1]) == 0) free[i] = free[i - 1];
    INN = (below(16) == 0) ? 0 : 1 + below(4);
    for (i = 0; i < INN; i++) {
        uint32_t k = below(12);

        n = (k < 3) ? 0 : 1 + below(3);
        IN[i].known = (k != 0);
        IN[i].units = U[i];
        IN[i].unitCount = IN[i].known ? n : 0;
        for (j = 0; j < IN[i].unitCount; j++) {
            size_t which = below((uint32_t)N(POOL));

            U[i][j].assetId = POOL[which];
            U[i][j].count = rndCount();
            U[i][j].ruleFree = free[which];
        }
    }
}

static void stackLine(int hasRow, int credit, int64_t quantity, const char *assetId, int targeted, int dataOutput)
{
    BRAssetInputFacts f;
    BRAssetUnits slot;
    BRAssetInputStack s;

    memset(&f, 0, sizeof(f));
    f.hasRow = hasRow;
    f.credit = (BRAssetCredit)credit;
    f.quantity = quantity;
    f.assetId = assetId;
    f.rowIsTargeted = (BRAssetFact)targeted;
    f.fundingHasDataOutput = (BRAssetFact)dataOutput;
    s = BRAssetBackedInputStack(&f, &slot);
    OUT("stack %d %s %lld %s %s %s", hasRow, CREDITS[credit], (long long)quantity, assetId ? (assetId[0] ? assetId : "empty") : "-",
        FACTS[targeted], FACTS[dataOutput]);
    if (! s.known) OUT(" ?");
    else if (s.unitCount == 0) OUT(" -");
    else OUT(" %s:%lld", s.units[0].assetId, (long long)s.units[0].count);
    endLine();
}

static void idLine(const char *txid, int32_t vout, int locked, int aggregation, int32_t divisibility)
{
    char id[BR_ASSET_ID_BUFFER];
    int ok = BRAssetIdForIssuance(txid, vout, locked, (BRAssetAggregation)aggregation, divisibility, id, sizeof(id));

    OUT("id %s %d %d %d %d %s", txid, (int)vout, locked, aggregation, (int)divisibility, ok ? id : "null");
    endLine();
}

int main(void)
{
    static const char *const txids[] = {
        "8a88dfb009c6a824823bf3c310101f91340611e1f8a93ba2642e66b728825178",
        "ee47fe8bacfceba55e8f99717e7133d991a74dc29fc1ee48ab370ee4c7e83de2",
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    static const int64_t quantities[] = { 0, -1, 5, INT64_MAX / 2 + 1 };
    static const char *const ids[] = { "La1", NULL, "" };
    static const int64_t totals[] = { 0, -1, 1, 10, BR_ASSET_MAX_ISSUANCE, BR_ASSET_MAX_ISSUANCE + 1 };
    char hex[128];
    size_t i, k;
    int a, b, c, d, e;

    printf("# BRAssetAllocate.h and BRAssetId.h vectors: the headers' answers, written down. Generated by\n"
           "# vectors/asset-allocate/generate.c, which describes each field; do not edit (asset_allocate_kat\n"
           "# checks it). One vector a line, fields separated by one space, numbers in decimal. No line\n"
           "# occurs twice. Instructions: <srp flags>:<output>:<amount> joined by ','. Inputs: '/'-joined,\n"
           "# each ? (unknown), - (no entry) or <id>:<count>:<ruleFree> joined by ','. Credits and bounds:\n"
           "# per vout from -1 to <outputs> (to 1 when <outputs> is below 1); u unknown, m mixed, - nothing,\n"
           "# -=<label> nothing with a label, <id>:<count> units; a bound is a number or * for none.\n"
           "# allocate <operation> <version> <exact> <outputs> <instructions> <inputs> <allocation> <credits> <bounds>\n"
           "# issue <operation> <exact> <total> <aggregation> <outputs> <instructions> <id> <allocation> <credits>\n"
           "#   <allocation>: indeterminate <reason> | none | allocated <voided> <vout:id:count,... or ->\n"
           "# stack <row> <credit> <quantity> <id> <targeted> <data-output> <? | - | id:count>\n"
           "# resolve <inputs: r<quantity>:<targeted> | n:<asset-tx>, '/'-joined> <ask> <known N | unknown [rows other]>\n"
           "# indexer <lookup> <entries> <null | credit>\n"
           "# aggregation <id> <aggregatable | hybrid | dispersed | ->\n"
           "# id <txid> <vout> <locked> <aggregation> <divisibility> <id | null>\n");

    // 1. HAND
    for (i = 0; i < N(SCRIPTED); i++) {
        int exact = script(SCRIPTED[i].script);

        inputs(SCRIPTED[i].inputs);
        allocateLine(exact, SCRIPTED[i].outputs);
    }
    for (i = 0; i < N(BUILT); i++) {
        header(BUILT[i].op, BUILT[i].version, BUILT[i].insts);
        inputs(BUILT[i].inputs);
        allocateLine(1, BUILT[i].outputs);
    }
    for (i = 0; i < N(ISSUED); i++) {
        int exact;

        unspaced(ISSUED[i].script, hex);
        exact = script(hex);
        issueLine("La9", ISSUED[i].exact < 0 ? exact : ISSUED[i].exact, ISSUED[i].outputs);
    }
    for (i = 0; i < N(totals); i++) {   // UnbackedAssetCreditTest's h(q), and a rule-bearing issuance
        header(DA_ISSUANCE, 3, "");
        H.opcode = 5;
        H.hasTotalQuantity = 1;
        H.totalQuantity = totals[i];
        issueLine("La9", 1, 2);
        issueLine("La9", 0, 2);
    }

    // 2. transfers, burns and headers of other operations
    for (i = 0; i < 1500; i++) {
        static const BRAssetOperation ops[] = { DA_TRANSFER, DA_TRANSFER, DA_TRANSFER, DA_BURN, DA_BURN, DA_ISSUANCE, DA_UNDEFINED };
        int32_t outputCount = rndOutputs();
        uint32_t version = below(4);
        BRAssetOperation op = ops[below((uint32_t)N(ops))];
        int exact = (below(10) != 0);

        header(op, (version == 0) ? (int32_t)below(3) : 3, "");
        rndInstructions(outputCount);
        rndInputs();
        allocateLine(exact, outputCount);
    }

    // 3. issuances
    for (i = 0; i < 500; i++) {
        int32_t outputCount = rndOutputs();
        uint32_t pick = below(10);
        uint32_t aggregation = below(3);
        int exact = (below(10) != 0);
        const char *assetId = POOL[below((uint32_t)N(POOL))];

        header((below(10) == 0) ? DA_TRANSFER : DA_ISSUANCE, 3, "");
        H.aggregation = (BRAssetAggregation)aggregation;
        H.hasTotalQuantity = (below(10) != 0);
        H.totalQuantity = (pick < N(totals)) ? totals[pick] : 1 + (int64_t)below(40);
        rndInstructions(outputCount);
        issueLine(assetId, exact, outputCount);
    }

    // 4. one input's stack, every case; then input totals and indexer answers
    for (a = 0; a < 2; a++)
        for (b = 0; b < 4; b++)
            for (k = 0; k < N(quantities); k++)
                for (c = 0; c < 3; c++)
                    for (d = 0; d < 3; d++)
                        for (e = 0; e < 3; e++) stackLine(a, b, quantities[k], ids[c], d, e);

    for (i = 0; i < 600; i++) {
        BRAssetInputFacts f[6];
        size_t rows[6], n = below(6), j;
        int ask = (int)below(2);
        BRAssetInputUnits r;

        for (j = 0; j < n; j++) {
            uint32_t q = below(6);

            memset(&f[j], 0, sizeof(f[j]));
            f[j].hasRow = (below(3) != 0);
            f[j].quantity = (q == 0) ? 0 : (q == 1) ? -1 : (q == 2) ? INT64_MAX / 2 + 1 : 1 + (int64_t)below(50);
            f[j].rowIsTargeted = (BRAssetFact)below(3);
            f[j].fundingIsAssetTx = (BRAssetFact)below(3);
        }
        r = BRAssetResolveInputUnits(f, n, ask ? rows : NULL, ask ? n : 0);
        OUT("resolve");
        if (n == 0) OUT(" none");
        for (j = 0; j < n; j++) {
            if (f[j].hasRow) OUT("%sr%lld:%s", j ? "/" : " ", (long long)f[j].quantity, FACTS[f[j].rowIsTargeted]);
            else OUT("%sn:%s", j ? "/" : " ", FACTS[f[j].fundingIsAssetTx]);
        }
        OUT(" %d", ask);
        if (r.known) OUT(" known %lld", (long long)r.units);
        else OUT(" unknown");
        for (j = 0; j < r.zeroRowCount; j++) OUT("%s%d", j ? "," : " ", (int)rows[j]);
        if (r.zeroRowCount) OUT(" %lld", (long long)r.otherUnits);
        endLine();
    }

    for (i = 0; i < 300; i++) {
        BRAssetUnits entries[5];
        BRAssetOutputCredit credit;
        uint32_t lookup = below(4);
        size_t n = below(5), j;
        int ok;

        for (j = 0; j < n; j++) {
            uint32_t q = below(6);
            uint32_t which = below(4);

            entries[j].assetId = (which == 0) ? "La2" : "La1";
            entries[j].count = (q == 0) ? 0 : (q == 1) ? -2 : (q == 2) ? INT64_MAX / 2 + 1 : 1 + (int64_t)below(9);
            entries[j].ruleFree = 0;
        }
        if (lookup == 3) lookup = 2;
        ok = BRAssetCreditFromIndexer((BRAssetStackLookup)lookup, entries, n, &credit);
        OUT("indexer %s", LOOKUPS[lookup]);
        if (n == 0) OUT(" -");
        for (j = 0; j < n; j++) OUT("%s%s:%lld", j ? "," : " ", entries[j].assetId, (long long)entries[j].count);
        OUT(" ");
        if (ok) creditWord(credit);
        else OUT("null");
        endLine();
    }

    // 5. what the ids say
    for (i = 0; i < N(POOL); i++) {
        BRAssetAggregation g;

        OUT("aggregation %s %s", POOL[i], BRAssetAggregationOfId(POOL[i], &g) ? AGGS[g] : "-");
        endLine();
    }

    // 6. ids
    idLine(txids[0], 1, 1, 0, 0);
    idLine(txids[1], 4, 1, 0, 2);
    for (k = 0; k < N(txids); k++)
        for (a = -1; a <= 3; a++)
            for (d = -1; d <= 8; d++) idLine(txids[k], (int32_t)k, 1, a, d);
    idLine(txids[0], 1, 0, 0, 0);
    idLine(txids[0], -1, 1, 0, 0);
    idLine(txids[0], 2147483647, 1, 0, 0);
    idLine("8a88dfb009c6a824823bf3c310101f91340611e1f8a93ba2642e66b72882517", 1, 1, 0, 0);
    idLine("8a88dfb009c6a824823bf3c310101f91340611e1f8a93ba2642e66b7288251780", 1, 1, 0, 0);
    for (i = 0; i < 150; i++) {
        static const char digits[] = "0123456789abcdef";
        char txid[65];
        uint32_t vout;

        for (k = 0; k < 64; k++) { uint32_t c16 = below(16); txid[k] = digits[c16]; }
        txid[64] = '\0';
        vout = below(400);
        idLine(txid, (int32_t)vout, 1, (int)below(3), (int32_t)below(8));
    }

    if (BROKEN) { fprintf(stderr, "generate.c: a vector did not fit its buffer, or a hand vector is broken\n"); return 1; }
    return 0;
}
