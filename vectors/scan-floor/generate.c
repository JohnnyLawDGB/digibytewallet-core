// Vectors for BRScanFloor.h and BRChainRebuild.h: the headers' own answers on a fixed corpus, so a
// platform that keeps a mirror of the floor rules (Android's HistoryRebuildOnUpgrade.kt,
// WalletManager.kt and CfRestorePreflight.kt, which its host-JVM tests run) or an executor of the
// rebuild (iOS) can be held to the core without loading it. Like vectors/cf-restore-preflight/,
// these are the headers written down, not independent answers; the host KAT scan_floor_kat holds
// the headers to a line-for-line model of the Kotlin and checks this file is current.
//
// The corpus: saved-transactions blobs for the floor minima (HistoryRebuildOnUpgradeTest's
// framing cases, and a base blob truncated at every length and with each byte inverted), every
// pair of a set of heights for the floor rules, a fixed unsorted checkpoint table
// for the lookups, every combination of the sync-start step's inputs over a set of heights, and the
// rebuild sequences, the reload steps and the kept list.
//
// Regenerate, from this directory:
//   cc -I ../.. -o /tmp/scan_floor_vectors generate.c && /tmp/scan_floor_vectors > vectors.txt

#include "BRScanFloor.h"
#include "BRChainRebuild.h"
#include "BRSavedTransactions.h"

#include <stdio.h>
#include <string.h>

static const int64_t H[] = {
    INT64_MIN, -1, 0, 1, 2, 999, 1000, 1001, 19000000, 19500000, 20000000, 21000000, 22650000,
    0x7fffffffLL, 0xffffffffLL, INT64_MAX,
};
#define NH (sizeof(H) / sizeof(*H))

// A fixed table, deliberately not sorted (the lookup does not assume it is).
static const BRCheckPoint CP[] = {
    { 20000000, { .u8 = { 0 } }, 1600000000u, 0 },
    { 0,        { .u8 = { 0 } }, 1389388394u, 0 },
    { 1000,     { .u8 = { 0 } }, 1389400000u, 0 },
    { 22650000, { .u8 = { 0 } }, 1700000000u, 0 },
    { 19000000, { .u8 = { 0 } }, 1550000000u, 0 },
    { 21000000, { .u8 = { 0 } }, 1650000000u, 0 },
};
#define NCP (sizeof(CP) / sizeof(*CP))

static const int64_t T[] = { -1, 0, 1, 1389388394, 1500000000, 1550000000, 1600000000, 1650000000, 1774252800, 1800000000 };
#define NT (sizeof(T) / sizeof(*T))


// ---- saved-transactions blobs: u32 count, then per record u32 size, u32 height, u32 time, body ----
typedef struct { uint32_t size, height, time; uint8_t bodyLen; } Rec;
static size_t blob(uint8_t *b, uint32_t count, const Rec *r, size_t n)
{
    size_t pos = 0, i, j;
    #define PUT(v) do { uint32_t _v = (v); b[pos++] = (uint8_t)_v; b[pos++] = (uint8_t)(_v >> 8); \
                        b[pos++] = (uint8_t)(_v >> 16); b[pos++] = (uint8_t)(_v >> 24); } while (0)
    PUT(count);
    for (i = 0; i < n; i++) {
        PUT(r[i].size); PUT(r[i].height); PUT(r[i].time);
        for (j = 0; j < r[i].bodyLen; j++) b[pos++] = (uint8_t)(0xa0 + j);
    }
    #undef PUT
    return pos;
}
static void minimaLine(const uint8_t *b, size_t len)
{
    BRSavedTransactionsFloor f;
    BRSavedTransactionsFloorMinima(len ? b : NULL, len, &f);
    printf("minima ");
    if (! len) printf("empty");
    for (size_t i = 0; i < len; i++) printf("%02x", b[i]);
    printf(" %u %zu %lld %lld\n", f.declaredCount, f.records, (long long)f.minConfirmedHeight, (long long)f.minRecordTime);
}
static void minimaCorpus(void)
{
    uint8_t b[512], c[512];
    size_t n, i;
    static const Rec one[] = { { 3, 21000000, 1650000000u, 3 } };
    static const Rec mixed[] = {
        { 3, 23000000, 1700000000u, 3 }, { 2, 0x7fffffffu, 1550000000u, 2 }, { 1, 19500000, 1600000000u, 1 },
        { 1, 0, 500, 1 }, { 1, 0xfffffff0u, 400, 1 }, { 2, 20000000, 0, 2 },
    };
    static const Rec unconf[] = { { 3, 0x7fffffffu, 1700000000u, 3 }, { 1, 0x7fffffffu, 1690000000u, 1 } };
    static const Rec below[] = { { 3, 22000000, 1690000000u, 3 }, { 1, 0x7fffffffu, 1600000000u, 1 }, { 2, 0x7fffffffu, 0, 2 } };
    static const Rec two[] = { { 3, 22000000, 1690000000u, 3 }, { 3, 18000000, 1500000000u, 3 } };
    static const Rec past[] = { { 3, 22000000, 1690000000u, 3 }, { 0xffffffffu, 10000000, 1400000000u, 2 } };
    static const Rec capped[] = { { 3, 1000, 1400000000u, 3 } };
    static const uint8_t small[][8] = { { 1, 0, 0 }, { 1, 0, 0, 0 }, { 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 } };

    minimaLine(b, 0);
    minimaLine(small[0], 3); minimaLine(small[1], 4); minimaLine(small[2], 8);
    n = blob(b, 0, NULL, 0); memset(b + n, 0, 20); minimaLine(b, n + 20);
    n = blob(b, 1, one, 1); minimaLine(b, n);
    n = blob(b, 6, mixed, 6); minimaLine(b, n);
    n = blob(b, 2, unconf, 2); minimaLine(b, n);
    n = blob(b, 3, below, 3); minimaLine(b, n);
    n = blob(b, 2, past, 2); minimaLine(b, n);
    n = blob(b, 10001, capped, 1); minimaLine(b, n);
    n = blob(b, 10000, capped, 1); minimaLine(b, n);
    n = blob(b, 3, two, 2); minimaLine(b, n);     // a count above the records present
    n = blob(b, 1, two, 2); minimaLine(b, n);     // a count below them
    n = blob(b, 2, two, 2);
    for (i = 0; i <= n; i++) minimaLine(b, i);    // every truncation
    for (i = 0; i < n; i++) { memcpy(c, b, n); c[i] ^= 0xff; minimaLine(c, n); }   // each byte inverted
    n = blob(b, 6, mixed, 6);
    for (i = 0; i < n; i++) { memcpy(c, b, n); c[i] ^= 0xff; minimaLine(c, n); }
}

static void floorLine(const BRScanFloor *f)
{
    printf("%lld %lld %d", (long long)f->height, (long long)f->time, f->pending);
}

int main(void)
{
    size_t i, j, k;

    printf("# BRScanFloor.h / BRChainRebuild.h vectors: the headers' answers, written down. Generated by\n");
    printf("# vectors/scan-floor/generate.c; do not edit (scan_floor_kat checks it).\n");
    printf("# checkpoint <height> <timestamp>          the table every lookup below uses, in table order\n");
    printf("# lower <existing> <candidate> <result>\n");
    printf("# birth <raw> <persist|remove> <value>\n");
    printf("# cptime <height> <time>                   over the table; \"cptime-none <height> 0\" with no table\n");
    printf("# lowerto <h> <t> <p> <height> -> <written> <h> <t> <p>\n");
    printf("# cache <h> <t> <p> <minConfirmedHeight> <minRecordTime> -> <h> <t> <p>\n");
    printf("# step <loaded> <anchor> <persisted or -> <height> <pending> -> <setBirth or -> <remove> <clear> <anchorAbove>\n");
    printf("# restoretime <stored> <floorTime> <result>\n");
    printf("# minima <blob hex or empty> <declaredCount> <records> <minConfirmedHeight> <minRecordTime>\n");
    printf("# rebuild <index> <name> / rebuild-from <index> <name> / reload <index> <name> / kept <index> <name>\n");

    minimaCorpus();

    for (i = 0; i < NCP; i++) printf("checkpoint %u %u\n", CP[i].height, CP[i].timestamp);

    for (i = 0; i < NH; i++)
        for (j = 0; j < NH; j++) printf("lower %lld %lld %lld\n", (long long)H[i], (long long)H[j], (long long)BRScanFloorLower(H[i], H[j]));

    for (i = 0; i < NH; i++) {
        int64_t v;
        int p = BRScanFloorBirthToPersist(H[i], &v);
        printf("birth %lld %s %lld\n", (long long)H[i], p ? "persist" : "remove", (long long)v);
    }

    for (i = 0; i < NH; i++) printf("cptime %lld %lld\n", (long long)H[i], (long long)BRScanFloorCheckpointTimeAtOrBelow(CP, NCP, H[i]));
    for (i = 0; i < NH; i++) printf("cptime-none %lld %lld\n", (long long)H[i], (long long)BRScanFloorCheckpointTimeAtOrBelow(NULL, 0, H[i]));

    // lowerto and cache: a record from a few heights x times x pending, against every height.
    static const int64_t RH[] = { 0, 1000, 19500000, 21000000 };
    static const int64_t RT[] = { 0, 1500000000, 1650000000 };
    for (i = 0; i < 4; i++)
        for (j = 0; j < 3; j++)
            for (int p = 0; p <= 1; p++)
                for (k = 0; k < NH; k++) {
                    BRScanFloor f = { RH[i], RT[j], p };
                    int w = BRScanFloorLowerTo(&f, H[k], CP, NCP);
                    printf("lowerto %lld %lld %d %lld -> %d ", (long long)RH[i], (long long)RT[j], p, (long long)H[k], w);
                    floorLine(&f); printf("\n");
                }
    for (i = 0; i < 4; i++)
        for (j = 0; j < 3; j++)
            for (int p = 0; p <= 1; p++)
                for (k = 0; k < NH; k++)
                    for (size_t t = 0; t < NT; t++) {
                        BRScanFloor f = { RH[i], RT[j], p };
                        BRScanFloorFromDiscardedCache(&f, H[k], T[t], CP, NCP);
                        printf("cache %lld %lld %d %lld %lld -> ", (long long)RH[i], (long long)RT[j], p, (long long)H[k], (long long)T[t]);
                        floorLine(&f); printf("\n");
                    }

    static const int64_t SH[] = { -1, 0, 15000000, 19000000, 19500000, 21500000, 22650000 };
    for (int loaded = 0; loaded <= 1; loaded++)
        for (i = 0; i < 7; i++)                       // anchor
            for (j = 0; j <= 7; j++)                  // persisted (7 = none)
                for (k = 0; k < 7; k++)               // height
                    for (int pend = 0; pend <= 1; pend++) {
                        BRScanFloorStep s = BRScanFloorHintStep(loaded, SH[i], j < 7, j < 7 ? SH[j] : 0, SH[k], pend);
                        printf("step %d %lld ", loaded, (long long)SH[i]);
                        if (j < 7) printf("%lld ", (long long)SH[j]); else printf("- ");
                        printf("%lld %d -> ", (long long)SH[k], pend);
                        if (s.setBirth) printf("%lld ", (long long)s.birth); else printf("- ");
                        printf("%d %d %d\n", s.removeBirth, s.clearHint, s.anchorAboveHint);
                    }

    for (i = 0; i < NT; i++)
        for (j = 0; j < NT; j++)
            printf("restoretime %lld %lld %lld\n", (long long)T[i], (long long)T[j], (long long)BRScanFloorRestoreCreationTime(T[i], T[j]));

    for (int n = 0; n < BRChainRebuildStepCount(0); n++)
        printf("rebuild %d %s\n", n, BRChainRebuildStepName((BRChainRebuildStep)BRChainRebuildStepAt(0, n)));
    for (int n = 0; n < BRChainRebuildStepCount(1); n++)
        printf("rebuild-from %d %s\n", n, BRChainRebuildStepName((BRChainRebuildStep)BRChainRebuildStepAt(1, n)));
    for (int n = 0; n < BR_CHAIN_REBUILD_RELOAD_COUNT; n++)
        printf("reload %d %s\n", n, BRChainRebuildReloadStepName((BRChainRebuildReloadStep)BRChainRebuildReloadStepAt(n)));
    for (int n = 0; n < BR_CHAIN_REBUILD_KEPT_COUNT; n++)
        printf("kept %d %s\n", n, BRChainRebuildKeepName(BRChainRebuildKept[n]));
    return 0;
}
