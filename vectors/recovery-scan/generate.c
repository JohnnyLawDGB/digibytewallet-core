// Vectors for BRRecoveryScan.h: the header's answers for its rules (USED, ROUND STEP, DONE, SWEEP SET,
// PASSPHRASE VERDICT, RECOVERABLE VALUE) on a fixed corpus, so each platform's mirror (Android's Kotlin in
// RecoveryScanService.kt, ForeignSweep.kt, PassphraseScanVerdict.kt, RecoverableValue.kt, and iOS) can be
// held to the same answers the host KAT holds the header to. These are the header written down, not an
// independent source: the independent expectations are the hand-written values in the host KAT
// (recovery_scan_kat), which also checks this file is current.
//
// Always the shipped rule: RECOVERY_SCAN_UNFIXED is forced to 0 here. Mainnet.
//
// Regenerate, from this directory (link the core units the host KAT lists; BRTransaction.c and BRAddress.c
// with their dependencies):
//   cc -include stdint.h -I ../.. -I ../../secp256k1/include -o /tmp/recovery_scan_vectors generate.c <core units> -lm -lpthread
//   /tmp/recovery_scan_vectors > vectors.txt

#undef RECOVERY_SCAN_UNFIXED
#define RECOVERY_SCAN_UNFIXED 0
#include "BRRecoveryScan.h"

#include <stdio.h>
#include <inttypes.h>

static const char *passName(BRRecoveryPassphraseOutcome o)
{
    switch (o) {
    case BR_RECOVERY_PASSPHRASE_FOUND: return "FOUND";
    case BR_RECOVERY_PASSPHRASE_LIKELY_TYPO: return "LIKELY_TYPO";
    case BR_RECOVERY_PASSPHRASE_NONE_ANYWHERE: return "NONE_ANYWHERE";
    case BR_RECOVERY_PASSPHRASE_INCOMPLETE: return "INCOMPLETE";
    default: return "?";
    }
}

static const char *stepName(BRRecoveryScanStep s)
{
    switch (s) {
    case BR_RECOVERY_SCAN_STEP_ASK_AGAIN: return "ASK_AGAIN";
    case BR_RECOVERY_SCAN_STEP_FINISHED: return "FINISHED";
    case BR_RECOVERY_SCAN_STEP_CAPPED: return "CAPPED";
    case BR_RECOVERY_SCAN_STEP_UNREACHABLE: return "UNREACHABLE";
    case BR_RECOVERY_SCAN_STEP_NOTHING_DERIVED: return "NOTHING_DERIVED";
    default: return "?";
    }
}

static void hex(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
}

// ---- used --------------------------------------------------------------------------------------

// A script of each kind over a 20- or 32-byte program filled from a tag.
static size_t script(uint8_t *s, int kind, uint8_t tag)
{
    size_t i;
    switch (kind) {
    case 0: s[0] = 0x76; s[1] = 0xa9; s[2] = 20; for (i = 0; i < 20; i++) s[3 + i] = (uint8_t)(tag + i); s[23] = 0x88; s[24] = 0xac; return 25;
    case 1: s[0] = 0x00; s[1] = 20; for (i = 0; i < 20; i++) s[2 + i] = (uint8_t)(tag + i); return 22;
    case 2: s[0] = 0xa9; s[1] = 20; for (i = 0; i < 20; i++) s[2 + i] = (uint8_t)(tag + i); s[22] = 0x87; return 23;
    default: s[0] = 0x51; s[1] = 32; for (i = 0; i < 32; i++) s[2 + i] = (uint8_t)(tag + i); return 34;
    }
}

typedef struct { int64_t sat; uint8_t s[40]; size_t len; } Out;

static size_t rawTx(uint8_t *buf, const Out *outs, size_t n)
{
    size_t off = 0, i, k;
    buf[off++] = 2; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
    buf[off++] = 1;
    for (i = 0; i < 32; i++) buf[off++] = (uint8_t)(0x40 + i);
    buf[off++] = 1; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0xff; buf[off++] = 0xff; buf[off++] = 0xff; buf[off++] = 0xff;
    buf[off++] = (uint8_t)n;
    for (i = 0; i < n; i++) {
        for (k = 0; k < 8; k++) buf[off++] = (uint8_t)(((uint64_t)outs[i].sat >> (8 * k)) & 0xff);
        buf[off++] = (uint8_t)outs[i].len;
        memcpy(&buf[off], outs[i].s, outs[i].len); off += outs[i].len;
    }
    buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
    return off;
}

static void used(void)
{
    // Eight derived addresses: receive 0..4 and change 0..2, one of each encoding, one repeated.
    static const int kinds[8] = { 0, 1, 2, 3, 0, 1, 3, 0 };
    static const int chains[8] = { 0, 0, 0, 0, 0, 1, 1, 1 };
    static const int32_t idx[8] = { 0, 1, 2, 3, 4, 0, 1, 2 };
    char text[8][76];
    BRRecoveryScanAddress a[8];
    BRRecoveryScanSlot slots[8];
    BRRecoveryScanUsed u;
    uint8_t s[40], tx[512], junk[4] = { 1, 0, 0, 0 };
    Out outs[3];
    size_t i, len, m;

    for (i = 0; i < 8; i++) {
        size_t n = script(s, kinds[i], (uint8_t)(0x10 * (i + 1)));
        BRAddressFromScriptPubKey(text[i], sizeof(text[i]), s, n);
        a[i].address = text[i]; a[i].chain = chains[i]; a[i].index = idx[i];
    }
    a[7].address = text[4];   // the change entry at 2 repeats receive 4's address
    for (i = 0; i < 8; i++) printf("used.address %zu %d %d %s\n", i, a[i].chain, a[i].index, a[i].address);

    // A transaction paying receive 3 (P2TR) and change 1 (P2TR), and a stranger.
    outs[0].sat = 1000; outs[0].len = script(outs[0].s, 3, 0x40);
    outs[1].sat = 2000; outs[1].len = script(outs[1].s, 3, 0x70);
    outs[2].sat = 3000; outs[2].len = script(outs[2].s, 0, 0xee);
    len = rawTx(tx, outs, 3);

    BRRecoveryScanUsedBegin(&u, a, 8, slots, 8);
    printf("used.coin %s -> %d\n", a[1].address, BRRecoveryScanUsedMarkAddress(&u, a[1].address));
    printf("used.coin %s -> %d\n", a[4].address, BRRecoveryScanUsedMarkAddress(&u, a[4].address));
    printf("used.coin %s -> %d\n", "DStrangerAddressNotDerived", BRRecoveryScanUsedMarkAddress(&u, "DStrangerAddressNotDerived"));
    printf("used.tx "); hex(tx, len);
    printf(" -> %d", (int)BRRecoveryScanUsedMarkRawTx(&u, tx, len, &m)); printf(" matched=%zu\n", m);
    printf("used.tx "); hex(junk, sizeof(junk));
    printf(" -> %d", (int)BRRecoveryScanUsedMarkRawTx(&u, junk, sizeof(junk), &m)); printf(" matched=%zu\n", m);
    printf("used.is");
    for (i = 0; i < 8; i++) printf(" %d", BRRecoveryScanUsedIs(&u, i));
    printf("\nused.highest receive=%d change=%d\n", BRRecoveryScanUsedHighest(&u, 0), BRRecoveryScanUsedHighest(&u, 1));
}

// ---- round step --------------------------------------------------------------------------------

static void step(int reachable, size_t n, int32_t e, int32_t in, int32_t ue, int32_t ui, int32_t round, int32_t bound)
{
    int32_t ne = -9, ni = -9;
    BRRecoveryScanStep s = BRRecoveryScanRoundStep(reachable, n, e, in, ue, ui, round, bound, &ne, &ni);
    printf("step reachable=%d addresses=%zu windows=%d/%d used=%d/%d round=%d/%d -> %s %d/%d\n",
           reachable, n, e, in, ue, ui, round, bound, stepName(s), ne, ni);
}

// ---- done --------------------------------------------------------------------------------------

typedef struct { const char *id; size_t n; BRRecoveryScanProfileResult r[4]; } DoneCase;

static void done(const DoneCase *c)
{
    size_t out[4], k = 0, i;
    int64_t t = 0;
    BRRecoveryScanStatus st;
    printf("done %s results=", c->id);
    for (i = 0; i < c->n; i++)
        printf("%s%zu:%d:%d:%d:%" PRId64, i ? "," : "", c->r[i].addressCount, c->r[i].reachable, c->r[i].capped,
               c->r[i].isNative, c->r[i].totalSat);
    if (c->n == 0) printf("-");
    st = BRRecoveryScanTotal(c->r, c->n, NULL, c->n, &t);
    printf(" -> any=%d underived=%d all=%d capped=%d incomplete=%d cache=%d total=%s%" PRId64,
           BRRecoveryScanAnyUnreachable(c->r, c->n), BRRecoveryScanAnyNothingDerived(c->r, c->n),
           BRRecoveryScanAllUnreachable(c->r, c->n),
           BRRecoveryScanAnyCapped(c->r, c->n), BRRecoveryScanIncomplete(c->r, c->n), BRRecoveryScanMayCache(c->r, c->n),
           st == BR_RECOVERY_SCAN_OVERFLOW ? "OVERFLOW:" : "", t);
    BRRecoveryScanSweepSet(c->r, c->n, 0, out, 4, &k);
    printf(" own=");
    for (i = 0; i < k; i++) printf("%s%zu", i ? "," : "", out[i]);
    if (!k) printf("-");
    BRRecoveryScanSweepSet(c->r, c->n, 1, out, 4, &k);
    printf(" foreign=");
    for (i = 0; i < k; i++) printf("%s%zu", i ? "," : "", out[i]);
    if (!k) printf("-");
    printf("\n");
}

int main(void)
{
    static const int64_t sats[] = { INT64_MIN, -1, 0, 1, 900 };
    static const DoneCase dc[] = {
        { "empty", 0, { { 0 } } },
        { "one_failed_among_several", 3, { { 1, 0, 0, 0, 0 }, { 1, 1, 0, 0, 0 }, { 1, 1, 0, 0, 0 } } },
        { "clean_empty", 2, { { 1, 1, 0, 0, 0 }, { 1, 1, 0, 0, 0 } } },
        { "total_outage", 2, { { 1, 0, 0, 0, 0 }, { 1, 0, 0, 0, 0 } } },
        { "never_asked_not_failed", 2, { { 0, 0, 0, 0, 0 }, { 1, 1, 0, 0, 0 } } },
        { "nothing_asked", 2, { { 0, 1, 0, 0, 0 }, { 0, 0, 0, 0, 0 } } },
        { "nothing_derived_among_answered", 2, { { 0, 1, 0, 0, 0 }, { 300, 1, 0, 0, 900 } } },
        { "failure_with_funds", 2, { { 1, 0, 0, 0, 0 }, { 1, 1, 0, 0, 100000000 } } },
        { "capped", 2, { { 1, 1, 0, 0, 5 }, { 1, 1, 1, 0, 0 } } },
        { "native_and_legacy", 2, { { 400, 1, 0, 1, 200000000 }, { 300, 1, 0, 0, 100000000 } } },
        { "unfunded_and_negative", 4, { { 1, 1, 0, 0, 0 }, { 1, 1, 0, 0, -5 }, { 1, 0, 0, 1, 0 }, { 1, 1, 0, 1, 7 } } },
        { "overflow", 2, { { 1, 1, 0, 0, INT64_MAX }, { 1, 1, 0, 0, 1 } } },
    };
    size_t i, j, k;
    int h, inc, sc;

    printf("# BRRecoveryScan.h vectors: the header's answers, written down. Generated by vectors/recovery-scan/generate.c;\n");
    printf("# do not edit (recovery_scan_kat checks it is current). Mainnet.\n");
    printf("# used.address <entry> <chain> <index> <address>          (the derived addresses, in entry order)\n");
    printf("# used.coin <address> -> <1 marked | 0>; used.tx <raw hex> -> <status> matched=<outputs>  (0 OK, 5 UNPARSEABLE)\n");
    printf("# used.is <per entry>; used.highest receive=<i> change=<i>  (-1 none)\n");
    printf("# step reachable= addresses= windows=<ext>/<int> used=<ext>/<int> round=<r>/<bound> -> <step> <next ext>/<next int>\n");
    printf("# done <id> results=<addresses:reachable:capped:native:sat,...> -> any= underived= all= capped= incomplete= cache= total= own=<idx> foreign=<idx>\n");
    printf("# passphrase <with> <haveWithout> <without> <incomplete> -> <outcome>\n");
    printf("# value <findings> <ddState> <ddCents> -> exists= answered=   (ddState 0 NOT_RUN, 1 ANSWERED, 2 UNANSWERED, 3 unknown)\n");
    printf("# bound profiles=%d none=%d null_with_count=%d\n",
           BRRecoveryScanRoundBoundForProfiles(BRDerivationProfiles(NULL), BR_DERIVATION_PROFILE_COUNT),
           BRRecoveryScanRoundBound(NULL, NULL, 0), BRRecoveryScanRoundBound(NULL, NULL, 3));

    used();

    step(1, 0, 200, 100, -1, -1, 1, 20);
    step(0, 0, 200, 100, -1, -1, 1, 20);
    step(0, 300, 200, 100, 150, -1, 1, 20);
    step(1, 300, 200, 100, -1, -1, 1, 20);
    step(1, 300, 200, 100, 150, -1, 1, 20);
    step(1, 400, 300, 100, 250, -1, 2, 20);
    step(1, 500, 400, 100, 250, -1, 3, 20);
    step(1, 300, 200, 100, 190, 60, 1, 20);
    step(1, 300, 200, 100, 199, -1, 2, 2);
    step(1, 3000, 2000, 1000, 1999, -1, 19, 20);
    step(1, 3000, 2000, 1000, -1, 949, 5, 20);
    step(1, 300, 200, 100, 99, 49, 1, 20);

    for (i = 0; i < sizeof(dc) / sizeof(dc[0]); i++) done(&dc[i]);

    for (i = 0; i < sizeof(sats) / sizeof(sats[0]); i++)
        for (h = 0; h < 2; h++)
            for (j = 0; j < sizeof(sats) / sizeof(sats[0]); j++)
                for (inc = 0; inc < 2; inc++) {
                    if (!h && j != 2) continue;   // without a comparison its total is not read
                    printf("passphrase %" PRId64 " %d %" PRId64 " %d -> %s\n", sats[i], h, sats[j], inc,
                           passName(BRRecoveryPassphraseVerdict(sats[i], h, sats[j], inc)));
                }

    for (k = 0; k < 3; k++)
        for (sc = 0; sc < 4; sc++)
            for (j = 1; j < 4; j++)
                printf("value %zu %d %" PRId64 " -> exists=%d answered=%d\n", k, sc, sats[j],
                       BRRecoverableValueExists(k, sc, sats[j]), BRRecoverableValueAnswered(k, sc, sats[j]));
    return 0;
}
