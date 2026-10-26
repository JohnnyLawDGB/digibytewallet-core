// Vectors for BRCFRestorePreflight.h: the header's own answers on a fixed corpus, so a platform
// that keeps a mirror of the rule (Android's CfRestorePreflight.kt, which its host-JVM tests run)
// can be held to the header without loading the core. Unlike vectors/derivation/, these are not
// independent: they are the header, written down. The host KAT cf_restore_preflight_kat holds the
// header to a line-for-line model of the Kotlin and checks this file is current.
//
// The corpus: CfRestorePreflightTest's blobs, and each base blob truncated at every length,
// extended, and with each byte inverted; every ledger against no window and two windows, every
// window against no ledger and two ledgers, synced (with a checkpoint) and not.
//
// Regenerate, from this directory:
//   cc -I ../.. -o /tmp/cf_restore_vectors generate.c && /tmp/cf_restore_vectors > vectors.txt

#include "BRCFRestorePreflight.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t *b; size_t len; } Blob;

static void putU32(uint8_t *b, size_t off, uint32_t v)
{
    b[off] = (uint8_t)v; b[off + 1] = (uint8_t)(v >> 8); b[off + 2] = (uint8_t)(v >> 16); b[off + 3] = (uint8_t)(v >> 24);
}

static Blob blob(const uint8_t *b, size_t len)
{
    Blob o = { malloc(len ? len : 1), len };
    if (len) memcpy(o.b, b, len);
    return o;
}

static Blob ledger(uint32_t version, uint32_t start, uint32_t scanned, uint32_t requested, uint32_t abandoned,
                   uint32_t outCount, uint32_t parkedCount)
{
    size_t header = version >= 2 ? 28 : 24, outSize = version >= 3 ? 6 : 5, parkSize = version >= 3 ? 6 : 4;
    size_t len = header + outCount * outSize + 4 + parkedCount * parkSize, i;
    uint8_t *b = calloc(1, len);
    putU32(b, 0, BR_CF_RESTORE_LEDGER_MAGIC); putU32(b, 4, version); putU32(b, 8, start);
    putU32(b, 12, scanned); putU32(b, 16, requested);
    if (version >= 2) putU32(b, 20, abandoned);
    putU32(b, version >= 2 ? 24 : 20, outCount);
    for (i = 0; i < outCount; i++) {
        putU32(b, header + i * outSize, scanned + 1 + (uint32_t)i);
        b[header + i * outSize + 4] = (uint8_t)(i & 1);
        if (outSize == 6) b[header + i * outSize + 5] = (uint8_t)(i % 3);
    }
    putU32(b, header + outCount * outSize, parkedCount);
    for (i = 0; i < parkedCount; i++) {
        size_t at = header + outCount * outSize + 4 + i * parkSize;
        putU32(b, at, scanned + 100 + (uint32_t)i);
        if (parkSize == 6) { b[at + 4] = 2; b[at + 5] = 1; }
    }
    Blob o = blob(b, len);
    free(b);
    return o;
}

static Blob window(int n, const uint32_t *lens, const uint32_t *heights)
{
    size_t len = 4, off = 4;
    int i;
    for (i = 0; i < n; i++) len += 8 + lens[i];
    uint8_t *b = calloc(1, len);
    putU32(b, 0, (uint32_t)n);
    for (i = 0; i < n; i++) {
        putU32(b, off, lens[i]); putU32(b, off + 4, heights[i]);
        memset(b + off + 8, 0x5a, lens[i]);
        off += 8 + lens[i];
    }
    Blob o = blob(b, len);
    free(b);
    return o;
}

#define MAX_BLOBS 4000
static Blob g_ledgers[MAX_BLOBS], g_windows[MAX_BLOBS];
static int g_nLedgers = 0, g_nWindows = 0;

static int add(Blob *set, int *n, Blob x)
{
    int i;
    for (i = 0; i < *n; i++) {
        if (set[i].len == x.len && (x.len == 0 || ! memcmp(set[i].b, x.b, x.len))) { free(x.b); return i; }
    }
    set[*n] = x;
    return (*n)++;
}

static void mutations(Blob base, Blob *set, int *n)
{
    size_t len, i;
    for (len = 0; len < base.len; len++) add(set, n, blob(base.b, len));
    for (len = base.len + 1; len <= base.len + 4; len += 3) {
        uint8_t *b = calloc(1, len);
        memcpy(b, base.b, base.len);
        memset(b + base.len, 0x5a, len - base.len);
        add(set, n, blob(b, len));
        free(b);
    }
    for (i = 0; i < base.len; i++) {
        Blob m = blob(base.b, base.len);
        m.b[i] ^= 0xff;
        add(set, n, m);
    }
}

static void print_blob(char kind, int id, Blob x)
{
    size_t i;
    printf("blob %c%d ", kind, id);
    if (! x.len) printf("empty");
    for (i = 0; i < x.len; i++) printf("%02x", x.b[i]);
    printf("\n");
}

static void reset_line(int l, int w, int synced, int checkpoint)
{
    Blob *lb = l >= 0 ? &g_ledgers[l] : NULL, *wb = w >= 0 ? &g_windows[w] : NULL;
    BRCFRestoreReset r = BRCFRestorePreflight(lb ? lb->b : NULL, lb ? lb->len : 0, lb != NULL,
                                              wb ? wb->b : NULL, wb ? wb->len : 0, wb != NULL, synced, checkpoint);
    if (l >= 0) printf("reset L%d ", l); else printf("reset - ");
    if (w >= 0) printf("W%d ", w); else printf("- ");
    printf("%d %d %s\n", synced, checkpoint, r == BR_CF_RESTORE_RESUME ? "RESUME" : BRCFRestoreResetName(r));
}

static void arm_line(int synced, int64_t tip, int64_t birth, int hasFloor, int64_t floor)
{
    printf("arm %d %lld %lld ", synced, (long long)tip, (long long)birth);
    if (hasFloor) printf("%lld ", (long long)floor); else printf("- ");
    printf("%lld\n", (long long)BRCFRestoreArmHeight(synced, tip, birth, hasFloor, floor));
}

int main(void)
{
    // CfRestorePreflightTest's ledgers (v3, no holes; start 900 unless given) and windows.
    Blob kl[] = {
        ledger(3, 900, 1000, 1200, 0, 0, 0), ledger(3, 900, 1000, 1200, 1100, 0, 0),
        ledger(3, 23996054, 23998330, 23998330, 0, 0, 0),
    };
    uint32_t z[3] = { 0, 0, 0 };
    uint32_t h1[] = { 1200, 1000, 900 }, h2[] = { 1200, 1100 }, h3[] = { 1200, 1150 }, h4[] = { 1200 };
    uint32_t h5[] = { 23998351, 23998052 }, lens[3] = { 7, 0, 3 }, h6[3] = { 1200, 1000, 1100 };
    Blob kw[] = { window(3, z, h1), window(2, z, h2), window(2, z, h3), window(1, z, h4), window(2, z, h5) };
    // Bases beyond the Kotlin test's: each ledger version with holes, a fresh ledger, a window
    // with block bytes.
    Blob bl[] = {
        ledger(1, 900, 1000, 1200, 0, 2, 2), ledger(2, 900, 1000, 1200, 950, 2, 2),
        ledger(3, 900, 1000, 1200, 1100, 2, 2), ledger(3, 1001, 1000, 1000, 0, 0, 0),
    };
    Blob bw = window(3, lens, h6);
    uint8_t zeros[28] = { 0 }, two[4] = { 2, 0, 0, 0 };
    size_t i;
    int l, w;

    for (i = 0; i < sizeof(kl) / sizeof(kl[0]); i++) add(g_ledgers, &g_nLedgers, kl[i]);
    for (i = 0; i < sizeof(kw) / sizeof(kw[0]); i++) add(g_windows, &g_nWindows, kw[i]);
    add(g_ledgers, &g_nLedgers, blob(zeros, sizeof(zeros)));
    add(g_windows, &g_nWindows, blob(two, sizeof(two)));
    for (i = 0; i < sizeof(bl) / sizeof(bl[0]); i++) {
        int id = add(g_ledgers, &g_nLedgers, bl[i]);
        mutations(g_ledgers[id], g_ledgers, &g_nLedgers);
    }
    mutations(g_ledgers[0], g_ledgers, &g_nLedgers);
    w = add(g_windows, &g_nWindows, bw);
    mutations(g_windows[w], g_windows, &g_nWindows);
    mutations(g_windows[0], g_windows, &g_nWindows);

    printf("# BRCFRestorePreflight.h vectors: the header's answers, written down. Generated by\n");
    printf("# vectors/cf-restore-preflight/generate.c; do not edit (cf_restore_preflight_kat checks it).\n");
    printf("# blob <id> <hex>    a stored copy; L = a scan ledger, W = a saved block window; \"empty\" = 0 bytes\n");
    printf("# reset <ledger id or -> <window id or -> <wasSynced> <hasTransactionCheckpoint> <RESUME or reason>\n");
    printf("#                    (- = no stored copy; the reason names are Android's CfRestoreResetReason)\n");
    printf("# arm <wasSynced> <savedTip> <walletBirth> <persistedBirth or -> <height>\n");
    for (l = 0; l < g_nLedgers; l++) print_blob('L', l, g_ledgers[l]);
    for (w = 0; w < g_nWindows; w++) print_blob('W', w, g_windows[w]);

    // CfRestorePreflightTest, case for case.
    reset_line(0, 0, 1, 1); reset_line(1, 1, 0, 0); reset_line(1, 2, 0, 0); reset_line(0, 1, 0, 0);
    reset_line(0, -1, 0, 0); reset_line(-1, 3, 1, 1); reset_line(-1, 3, 0, 0);
    reset_line(3, 3, 1, 1); reset_line(0, 5, 1, 1); reset_line(2, 4, 1, 0);
    // Every flag pair on the absent and base cases.
    for (l = -1; l <= 2; l++) {
        for (w = -1; w <= 1; w++) {
            int f;
            for (f = 0; f < 4; f++) reset_line(l, w, f & 1, f >> 1);
        }
    }
    // Every ledger against no window and two; every window against no ledger and two.
    for (l = 0; l < g_nLedgers; l++) {
        reset_line(l, -1, 0, 0); reset_line(l, 0, 0, 0); reset_line(l, 0, 1, 1); reset_line(l, 1, 1, 1);
    }
    for (w = 0; w < g_nWindows; w++) {
        reset_line(-1, w, 1, 1); reset_line(0, w, 0, 0); reset_line(0, w, 1, 1); reset_line(1, w, 1, 1);
    }

    // compactFilterBirthHeight: CfRestorePreflightTest's two cases, then the margin and the floor.
    arm_line(1, 23997321, 22650000, 1, 22650000);
    arm_line(0, 23997321, 22650000, 1, 22650000);
    {
        static const int64_t tips[] = { 0, 1, 99, 100, 101, 1000, 23997321, 4294967295LL };
        static const int64_t births[] = { 0, 22650000 };
        static const int64_t floors[] = { 0, 1, 22650000, 24000000 };
        size_t t, b, f;
        int s;
        for (s = 0; s <= 1; s++)
            for (t = 0; t < sizeof(tips) / sizeof(tips[0]); t++)
                for (b = 0; b < sizeof(births) / sizeof(births[0]); b++) {
                    arm_line(s, tips[t], births[b], 0, 0);
                    for (f = 0; f < sizeof(floors) / sizeof(floors[0]); f++) arm_line(s, tips[t], births[b], 1, floors[f]);
                }
    }
    return 0;
}
