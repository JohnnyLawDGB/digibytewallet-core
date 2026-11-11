// Vectors for BRAssetDecode.h: the header's own answers on a fixed corpus, so a platform that keeps a
// reader of its own (Android's DigiAssetDecoder.kt, BitReader.kt and AssetPayloadCheck.kt, which its
// host-JVM tests run) can be held to the core without loading it. These are the header written down,
// not independent answers; the host KAT asset_decode_kat holds the header to the Kotlin tests' own
// expectations and to a line-for-line model of the Kotlin, and checks this file is current.
//
// The corpus: the scripts of the Kotlin tests and of the host KATs (SCRIPTS), a seeded set of
// issuances, transfers and burns written as an encoder writes them and then cut, lengthened or
// changed in one byte, and amounts of every length read from bit offsets 0 to 7.
//
// Regenerate, from this directory:
//   cc -I ../.. -o /tmp/asset_decode_vectors generate.c && /tmp/asset_decode_vectors > vectors.txt

#include "BRAssetDecode.h"

#include <stdio.h>
#include <string.h>

static const char *const SCRIPTS[] = {
    "6a00",
    "6a02",
    "6a4c",
    "6a0244",
    "6a014441",
    "6a024441",
    "6a024442",
    "6a4c0144",
    "6a4e0200",
    "6a034441ff",
    "6a4f024441",
    "6a0444410315",
    "6a04deadbeef",
    "6a1e44444444",
    "6a4c44410215",
    "6a4d01004441",
    "6a054441020100",
    "6a0544410205e0",
    "6a054441021503",
    "6a054441021540",
    "6a054441030510",
    "6a054441031500",
    "6a4c0344410315",
    "6a4c4c44410215",
    "6a4cfe44410315",
    "6a0644410015000a",
    "6a06444101050510",
    "6a064441010505e0",
    "6a0644410115000a",
    "6a06444102050510",
    "6a06444102150005",
    "6a0644410215000a",
    "6a06444102150020",
    "6a0644410215020a",
    "6a06444102151f01",
    "6a0644410216000a",
    "6a06444102251f01",
    "6a06444103020510",
    "6a06444103050103",
    "6a0644410305010c",
    "6a064441030501e0",
    "6a064441030501f8",
    "6a06444103050510",
    "6a06444103050a10",
    "6a06444103150005",
    "6a06444103151e01",
    "6a06444103151f01",
    "6a06444103251f01",
    "6a0644420315000a",
    "6a0844410215000a",
    "6a1e44410315000a",
    "6a4d020044410315",
    "6a4d020044420315",
    "6a4e020000004442",
    "6a4effffffff4441",
    "6b0644410215000a",
    "6a0644410315000500",
    "6a0744410105201200",
    "6a0744410105201240",
    "6a07444101052155f0",
    "6a0744410205201240",
    "6a0744410215002013",
    "6a0744410303050010",
    "6a07444103050a0010",
    "6a0744410315002016",
    "6a0744410315002052",
    "6a0744410315012012",
    "6a0744410315e00aff",
    "6a4c0644410215000a",
    "6a4c80444444444444",
    "6a4cff44410315000a",
    "6a0644410215000a0301",
    "6a0844410205011f0100",
    "6a08444102251f010101",
    "6a0844410301aaaaaaaa",
    "6a084441030501000108",
    "6a0844410305011e0100",
    "6a0844410305011f0100",
    "6a08444103050a000410",
    "6a08444103050a001414",
    "6a084441031500010209",
    "6a0844410315810a000a",
    "6a4c0644410215000a00",
    "6a4d060044410215000a",
    "6a4d060044410215020a",
    "6a4d060044410315000a",
    "6a4d0600444202150005",
    "6a4d060068656c6c6f21",
    "6a4e0200000044410315",
    "6a4e0200000044420315",
    "6a09444103050100016010",
    "6a09444103052016012010",
    "6a09444103057fffffff10",
    "6a0944410315007fffffff",
    "6a09444103158201002644",
    "6a4d010144410215002001",
    "6a0a03154001a5d21dba0007",
    "6a0a444103050a0001016010",
    "6a0a444103050a2132000110",
    "6a0a44410315802012012051",
    "6a0a444103250020221f2032",
    "6a4e0600000044410215000a",
    "6a0b4441031500018060f423f0",
    "6a0b4441031500bfffffffffff",
    "6a0c444100150000000000000000",
    "6a0c4441021503c0000000000001",
    "6a0c4441021503e0000000000001",
    "6a0c444103154001a5d21dba0007",
    "6a0c444103ff0000000000000000",
    "6a0c444203150000000000000000",
    "6a0d444103050a0001017fffffff10",
    "6a0d444103154200ffffffffffffff",
    "6a0e44410201aaaaaaaaaaaaaaaaaaaa",
    "6a0e4441021503e00000000000010201",
    "6a24aa21a9ed6fb29ce476d46dce43e21190d6c2",
    "6a17444102020102030405060708090a0b0c0d0e0f10111213",
    "6a18444102020102030405060708090a0b0c0d0e0f1011121314",
    "6a3a4441010134fdfc1f913ab9aae04fa1daf92f389248ff21f1",
    "6a19444102020102030405060708090a0b0c0d0e0f101112130510",
    "6a1a444102020102030405060708090a0b0c0d0e0f10111213140510",
    "6a264441030311111111111111111111111111111111111111111111111111111111111111110510",
    "6a264441030411111111111111111111111111111111111111111111111111111111111111110510",
    "6a2844410301111111111111111111111111111111111111111111111111111111111111111101000110",
    "6a2a44410301d66f1117234767d6892700d575511e1effcd6471013dda0e832dbb67e629d674215500215550",
    "6a2b4441030300000000000000000000000000000000000000000000000000000000000000002013ff00201300",
    "6a2b444103031a343da7c7a2b6d25667e63e24980cb56ddf65970bbd8315e99e97c0ec847d9e0510101f000510",
    "6a2b444103041a343da7c7a2b6d25667e63e24980cb56ddf65970bbd8315e99e97c0ec847d9e0510101f000510",
};
#define NSCRIPTS (sizeof(SCRIPTS) / sizeof(*SCRIPTS))

static uint64_t RNG = 0xDA5E7C0DEULL;

static uint32_t rnd(void)   // xorshift64: the same stream on every machine
{
    RNG ^= RNG << 13; RNG ^= RNG >> 7; RNG ^= RNG << 17;
    return (uint32_t)(RNG >> 24);
}

static uint32_t below(uint32_t n) { return rnd() % n; }

static void hex(const uint8_t *b, size_t len)
{
    size_t i;

    if (len == 0) printf("empty");
    for (i = 0; i < len; i++) printf("%02x", b[i]);
}

static void decodeLine(const uint8_t *s, size_t len)
{
    static const char *const ops[] = { "undefined", "issuance", "transfer", "burn" };
    static const char *const aggs[] = { "aggregatable", "hybrid", "dispersed" };
    BRAssetHeader h;
    BRAssetTransferInstruction l[BR_ASSET_MAX_INSTRUCTIONS];
    char cid[BR_ASSET_CID_BUFFER];
    BRAssetScriptKind kind = BRAssetDecodeInstructions(s, len, &h, l, BR_ASSET_MAX_INSTRUCTIONS);
    size_t i;

    printf("decode ");
    hex(s, len);
    if (kind == BR_ASSET_SCRIPT_NOT_ASSET) { printf(" not-asset\n"); return; }
    if (kind == BR_ASSET_SCRIPT_UNCLASSIFIABLE) { printf(" unclassifiable\n"); return; }

    printf(" asset %d %d %s ", (int)h.version, (int)h.opcode, ops[(int)h.operation]);
    if (h.hasMetadataHash) hex(h.metadataHash, 32); else printf("-");
    printf(" %s ", BRAssetMetadataCid(&h, cid, sizeof(cid)) ? cid : "-");
    if (h.hasTotalQuantity) printf("%lld", (long long)h.totalQuantity); else printf("-");
    printf(" %d %d %s %d %d %u", (int)h.divisibility, h.locked ? 1 : 0, aggs[(int)h.aggregation], BRAssetHeaderHasRules(&h),
           BRAssetPayloadReadsExactly(s, len, &h, l, h.instructionCount), (unsigned)h.instructionCount);
    for (i = 0; i < h.instructionCount; i++) {
        printf(" %c%c%c%c:%d:%lld", l[i].skip ? 's' : '-', l[i].range ? 'r' : '-', l[i].percent ? 'p' : '-', l[i].isBurn ? 'b' : '-',
               (int)l[i].outputIndex, (long long)l[i].amount);
    }
    printf("\n");
}

static void fixedLine(const uint8_t *b, size_t len, size_t skip)
{
    BRAssetBitReader r = BRAssetBitReaderMake(b, len);
    int64_t v = 0;

    printf("fixed ");
    hex(b, len);
    if (! BRAssetBitsSkip(&r, skip)) { printf(" %u refused %u\n", (unsigned)skip, (unsigned)r.position); return; }
    if (BRAssetBitsReadFixedPrecision(&r, &v)) printf(" %u %lld %u\n", (unsigned)skip, (long long)v, (unsigned)r.position);
    else printf(" %u refused -\n", (unsigned)skip);
}

static int digit(char c) { return (c <= '9') ? c - '0' : c - 'a' + 10; }

// One fixed precision amount of a random form into out; the byte count.
static size_t rndFixed(uint8_t *out)
{
    size_t len = 1 + below(7), i;

    for (i = 0; i < len; i++) out[i] = (uint8_t)rnd();
    if (len == 7) out[0] |= 0xc0;
    else out[0] = (uint8_t)((out[0] & 0x1f) | ((len - 1) << 5));
    if (len >= 2 && len <= 6 && below(2)) out[len - 1] &= (uint8_t)((len < 5) ? 0xf0 | below(4) : 0xf8 | below(3));
    if (len >= 4 && below(3) == 0) for (i = 1; i + 2 < len; i++) out[i] = 0;
    return len;
}

// A payload as an encoder writes it, of a random operation; its length.
static size_t rndPayload(uint8_t *p)
{
    static const uint8_t ops[] = { 1, 2, 3, 4, 5, 0x15, 0x15, 0x15, 0x25, 0x25 };
    size_t n = 0, i, count = below(5);
    uint8_t version = (uint8_t)(1 + below(3)), opcode = ops[below((uint32_t)(sizeof(ops) / sizeof(*ops)))];
    int issuance = (opcode <= 5);

    p[n++] = 0x44; p[n++] = 0x41; p[n++] = version; p[n++] = opcode;
    if (version < 3 && opcode < 3) for (i = 0; i < 20; i++) p[n++] = (uint8_t)rnd();
    if (opcode == 1 || opcode == 3 || opcode == 4) { int zero = (below(4) == 0); for (i = 0; i < 32; i++) p[n++] = zero ? 0 : (uint8_t)rnd(); }
    if (issuance) n += rndFixed(p + n);

    for (i = 0; i < count; i++) {
        int range = (below(4) == 0), percent = (below(6) == 0), skip = (below(5) == 0);
        uint32_t out = range ? below(8192) : (below(3) == 0 ? 31 : below(32));

        if (range) { p[n++] = (uint8_t)((skip << 7) | 0x40 | (percent << 5) | (out >> 8)); p[n++] = (uint8_t)out; }
        else p[n++] = (uint8_t)((skip << 7) | (percent << 5) | out);
        if (percent) p[n++] = (uint8_t)rnd();
        else n += rndFixed(p + n);
    }

    if (issuance) p[n++] = (uint8_t)(((below(8) == 0) ? rnd() | 0x0c : rnd() & ~0x0cu) | (below(3) << 2));
    return n;
}

int main(void)
{
    static const uint8_t amounts[][7] = {
        { 0x00 }, { 0x01 }, { 0x1f }, { 0x20, 0x10 }, { 0x20, 0x12 }, { 0x21, 0x55 }, { 0x3f, 0xff }, { 0x40, 0x00, 0x13 },
        { 0x5f, 0xff, 0xff }, { 0x60, 0x00, 0x00, 0x13 }, { 0x7f, 0xff, 0xff, 0xff }, { 0x80, 0x60, 0xf4, 0x23, 0xf0 },
        { 0x9f, 0xff, 0xff, 0xff, 0xff }, { 0xa0, 0x00, 0x00, 0x00, 0x00, 0x0a }, { 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff },
        { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, { 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, { 0x42, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff },
    };
    static const size_t lens[] = { 1, 1, 1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 7, 7 };
    uint8_t s[400], p[300], d[10];
    size_t i, k, n, len, skip;

    printf("# BRAssetDecode.h vectors: the header's answers, written down. Generated by\n"
           "# vectors/asset-decode/generate.c; do not edit (asset_decode_kat checks it).\n"
           "# decode <script hex or empty> not-asset\n"
           "# decode <script hex> unclassifiable\n"
           "# decode <script hex> asset <version> <opcode> <issuance|transfer|burn> <metadata hash or -> <cid or ->\n"
           "#        <total quantity or -> <divisibility> <locked> <aggregatable|hybrid|dispersed> <has rules>\n"
           "#        <payload reads exactly> <instruction count> then per instruction <srpb flags>:<output>:<amount>\n"
           "#        (s skip, r range, p percent, b burn; - where the flag is not set)\n"
           "# fixed <bytes hex> <bits skipped first> <amount> <bit position after>, or <bits skipped> refused -\n");

    decodeLine(s, 0);
    for (i = 0; i < NSCRIPTS; i++) {
        len = strlen(SCRIPTS[i]) / 2;
        for (k = 0; k < len; k++) s[k] = (uint8_t)((digit(SCRIPTS[i][2 * k]) << 4) | digit(SCRIPTS[i][2 * k + 1]));
        decodeLine(s, len);
    }

    for (i = 0; i < 900; i++) {
        uint32_t how = below(8);

        n = rndPayload(p);
        if (how == 4 && n > 5) n -= 1 + below(3);
        else if (how == 5) for (k = 1 + below(3); k > 0; k--) p[n++] = (uint8_t)rnd();
        else if (how == 6) p[below((uint32_t)n)] = (uint8_t)rnd();
        else if (how == 7 && n > 4) p[4 + below((uint32_t)(n - 4))] ^= (uint8_t)(1u << below(8));
        len = 0;
        s[len++] = 0x6a;
        if (n > 75 || below(6) == 0) { s[len++] = 0x4c; s[len++] = (uint8_t)n; }
        else if (below(60) == 0) { s[len++] = 0x4d; s[len++] = (uint8_t)n; s[len++] = 0; }
        else s[len++] = (uint8_t)n;
        memcpy(s + len, p, n);
        len += n;
        if (below(20) == 0) s[len++] = (uint8_t)rnd();
        decodeLine(s, len);
    }

    for (i = 0; i < sizeof(lens) / sizeof(*lens); i++) {
        for (skip = 0; skip < 8; skip++) {   // the amount, `skip` bits into the bytes
            memset(d, 0, sizeof(d));
            for (k = 0; k < lens[i]; k++) {
                d[k] |= (uint8_t)(amounts[i][k] >> skip);
                if (skip) d[k + 1] |= (uint8_t)(amounts[i][k] << (8 - skip));
            }
            fixedLine(d, lens[i] + (skip ? 1 : 0), skip);
            if (skip == 0 || skip == 3) fixedLine(d, lens[i] + (skip ? 1 : 0) - 1, skip);   // and one byte short
        }
    }
    for (i = 0; i < 200; i++) {
        len = rndFixed(d);
        if (below(5) == 0 && len > 1) len--;
        fixedLine(d, len, 0);
    }
    return 0;
}
