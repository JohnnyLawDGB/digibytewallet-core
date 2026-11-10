// Vectors for BRReconcilePlan.h: the header's answers for its pure rules (PLAN, IMPORT STEP, COVERAGE,
// PENDING, DISTINCT OUTPOINTS, DISTINCT ADDRESSES) on a fixed corpus, so each platform's mirror (Android's
// Kotlin in ChainReconciliationService.kt and ScanPartition.kt, and iOS) can be held to the same answers
// the host KAT holds the header to. Like vectors/tx-rows/, these are the header written down, not an
// independent source: the independent expectations are the hand-written values in the host KAT
// (reconcile_plan_kat), which also checks this file is current.
//
// Always the shipped rule: RECONCILE_PLAN_UNFIXED is forced to 0 here.
//
// Txids are written as a txid string displays (the UInt256 reversed), lowercase hex. Addresses are
// written as the hex of their bytes, "_" for an empty string; "-" is an empty list.
//
// Regenerate, from this directory:
//   cc -I ../.. -I ../../secp256k1/include -o /tmp/reconcile_plan_vectors generate.c && /tmp/reconcile_plan_vectors > vectors.txt

#undef RECONCILE_PLAN_UNFIXED
#define RECONCILE_PLAN_UNFIXED 0
#include "BRReconcilePlan.h"

#include <stdio.h>
#include <inttypes.h>

// A txid from a tag byte and a serial: the serial in the first two bytes, the tag in the rest.
static UInt256 tid(uint8_t tag, uint16_t serial)
{
    UInt256 h;
    memset(h.u8, tag, sizeof(h.u8));
    h.u8[0] = (uint8_t)(serial >> 8);
    h.u8[1] = (uint8_t)serial;
    return h;
}

static void putTxid(UInt256 h)
{
    for (size_t i = sizeof(h.u8); i > 0; i--) printf("%02x", h.u8[i - 1]);
}

static const char *stepName(BRReconcileImportStep s)
{
    switch (s) {
    case BR_RECONCILE_STEP_REGISTERED: return "REGISTERED";
    case BR_RECONCILE_STEP_NOT_FETCHED: return "NOT_FETCHED";
    case BR_RECONCILE_STEP_NOT_DECODED: return "NOT_DECODED";
    case BR_RECONCILE_STEP_NOT_THE_TX: return "NOT_THE_TX";
    case BR_RECONCILE_STEP_REFUSED: return "REFUSED";
    default: return "?";
    }
}

#define MAXH 160

static void plan(const char *id, const UInt256 *known, size_t nk, const BRReconcileHistoryTx *h, size_t nh)
{
    UInt256 k[MAXH];
    BRReconcilePlanTx p[MAXH];
    size_t n = 0, i;

    memcpy(k, known, nk * sizeof(*k));
    BRReconcileSortTxHashes(k, nk);
    if (BRReconcilePlanHistoryImport(h, nh, k, nk, p, MAXH, &n) != BR_RECONCILE_OK) { printf("plan %s ERROR\n", id); return; }
    printf("plan %s known=", id);
    if (nk == 0) printf("-");
    for (i = 0; i < nk; i++) { if (i) printf(","); putTxid(known[i]); }
    printf(" history=");
    if (nh == 0) printf("-");
    for (i = 0; i < nh; i++) { if (i) printf(","); putTxid(h[i].txHash); printf("@%" PRId64, h[i].height); }
    printf(" ->");
    if (n == 0) printf(" -");
    for (i = 0; i < n; i++) { printf(" "); putTxid(p[i].txHash); printf("@%" PRId64, p[i].height); }
    printf("\n");
}

static void coveredAsked(const char *id, size_t asked, size_t answered, size_t planned, const BRReconcileImportStep *s, size_t ns)
{
    BRReconcileImportOutcome o;
    size_t i;

    BRReconcileImportBegin(&o, asked, answered, planned);
    for (i = 0; i < ns; i++) BRReconcileImportRecord(&o, s[i]);
    printf("covered %s asked=%zu answered=%zu planned=%zu steps=", id, asked, answered, planned);
    if (ns == 0) printf("-");
    for (i = 0; i < ns; i++) printf("%s%s", i ? "," : "", stepName(s[i]));
    printf(" -> imported=%zu unrecovered=%zu covered=%d\n", o.imported, o.unrecovered, BRReconcileImportCovered(&o));
}

// The Kotlin tests' passes: the node answered for every address (three of them, here).
static void covered(const char *id, size_t planned, const BRReconcileImportStep *s, size_t ns)
{
    coveredAsked(id, 3, 3, planned, s, ns);
}

static void outpoints(const char *id, const BRUTXO *u, size_t n)
{
    size_t keep[16], k = 0, i;

    if (BRReconcileDistinctOutpoints(u, n, keep, 16, &k) != BR_RECONCILE_OK) { printf("outpoints %s ERROR\n", id); return; }
    printf("outpoints %s ", id);
    if (n == 0) printf("-");
    for (i = 0; i < n; i++) { if (i) printf(","); putTxid(u[i].hash); printf(":%" PRIu32, u[i].n); }
    printf(" ->");
    if (k == 0) printf(" -");
    for (i = 0; i < k; i++) printf(" %zu", keep[i]);
    printf("\n");
}

static void putHex(const char *s, size_t len)
{
    if (len == 0) { printf("_"); return; }
    for (size_t i = 0; i < len; i++) printf("%02x", (unsigned char)s[i]);
}

static void addresses(const char *id, const char *const *a, size_t n)
{
    BRReconcileAddressSpan out[16];
    size_t k = 0, i;

    if (BRReconcileDistinctAddresses(a, n, out, 16, &k) != BR_RECONCILE_OK) { printf("addresses %s ERROR\n", id); return; }
    printf("addresses %s ", id);
    if (n == 0) printf("-");
    for (i = 0; i < n; i++) { if (i) printf(","); putHex(a[i], strlen(a[i])); }
    printf(" ->");
    if (k == 0) printf(" -");
    for (i = 0; i < k; i++) { printf(" %zu:", out[i].index); putHex(a[out[i].index] + out[i].offset, out[i].length); }
    printf("\n");
}

int main(void)
{
    printf("# BRReconcilePlan.h vectors: the header's answers, written down. Generated by vectors/reconcile-plan/generate.c;\n");
    printf("# do not edit (reconcile_plan_kat checks it is current).\n");
    printf("# Txids as displayed (lowercase hex); addresses as the hex of their bytes, _ = empty string; - = empty list.\n");
    printf("# plan <id> known=<txid,...> history=<txid@height,...> -> <txid@height>...   (the plan, in its order)\n");
    printf("# step <fetched> <decoded> <isTheTx> <registered> <step> <recovered> <mayRegister>\n");
    printf("# covered <id> asked=<n> answered=<n> planned=<n> steps=<step,...> -> imported=<n> unrecovered=<n> covered=<0|1>\n");
    printf("# pending <blockHeight> <0|1>                                               (2147483647 = TX_UNCONFIRMED)\n");
    printf("# outpoints <id> <txid:n,...> -> <index of each kept row>...\n");
    printf("# addresses <id> <addr,...> -> <index>:<trimmed addr>...\n");

    {
        const UInt256 K = tid(0x4b, 0), N1 = tid(0x31, 0), N2 = tid(0x32, 0), T = tid(0x54, 0), X = tid(0x58, 0);
        const UInt256 A = tid(0xa1, 0), B = tid(0xb2, 0), C = tid(0xc3, 0), Z = UINT256_ZERO;

        // AddressHistoryPlanTest.plan_drops_known_and_dedups_across_addresses (two address lists, concatenated)
        { UInt256 k[] = { K }; BRReconcileHistoryTx h[] = { {K, 10}, {N1, 20}, {N1, 20}, {N2, 30} };
          plan("drops_known_dedups_across_addresses", k, 1, h, 4); }
        // AddressHistoryPlanTest.plan_keeps_highest_height_for_duplicate_txid
        { BRReconcileHistoryTx h[] = { {T, 0}, {T, 99} }; plan("keeps_highest_height", NULL, 0, h, 2); }
        // AddressHistoryPlanTest.empty_history_yields_empty_plan
        { UInt256 k[] = { X }; plan("empty_history", k, 1, NULL, 0); }
        { BRReconcileHistoryTx h[] = { {T, 50}, {T, 99}, {T, 7} }; plan("highest_height_not_last", NULL, 0, h, 3); }
        { BRReconcileHistoryTx h[] = { {T, 99}, {T, 7} }; plan("highest_height_first", NULL, 0, h, 2); }
        { BRReconcileHistoryTx h[] = { {B, 1}, {A, 2}, {B, 3}, {C, 0}, {A, 1} }; plan("first_seen_order", NULL, 0, h, 5); }
        { UInt256 k[] = { A, B }; BRReconcileHistoryTx h[] = { {A, 1}, {B, 2}, {A, 3} }; plan("all_known", k, 2, h, 3); }
        { UInt256 k[] = { B }; BRReconcileHistoryTx h[] = { {B, 9}, {A, 1}, {B, 10}, {C, 2} }; plan("known_never_planned_at_any_height", k, 1, h, 4); }
        { BRReconcileHistoryTx h[] = { {Z, 5}, {A, 1}, {Z, 7} }; plan("zero_txid_dropped", NULL, 0, h, 3); }
        { BRReconcileHistoryTx h[] = { {T, -5}, {T, -1}, {A, 0} }; plan("negative_heights", NULL, 0, h, 3); }
        { BRReconcileHistoryTx h[] = { {T, INT64_MIN}, {T, INT64_MAX}, {A, INT64_MAX}, {A, INT64_MIN} }; plan("height_edges", NULL, 0, h, 4); }
        // HistoryImportCoverageTest.knownSetIsUncapped_soTruncatedOutOlderTxidsNeverEnterThePlan: a 150-transaction wallet
        {
            UInt256 k[150]; BRReconcileHistoryTx h[151];
            for (uint16_t i = 0; i < 150; i++) { k[i] = tid(0x77, (uint16_t)(i + 1)); h[i].txHash = k[i]; h[i].height = 23900121; }
            h[150].txHash = tid(0x6d, 0); h[150].height = 23900121;
            plan("wide_wallet_known_uncapped", k, 150, h, 151);
        }
    }

    for (int f = 0; f <= 1; f++) for (int d = 0; d <= 1; d++) for (int t = 0; t <= 1; t++) for (int r = 0; r <= 1; r++) {
        BRReconcileImportStep s = BRReconcileImportStepFor(f, d, t, r);
        printf("step %d %d %d %d %s %d %d\n", f, d, t, r, stepName(s), BRReconcileImportStepRecovered(s),
               BRReconcileImportMayRegister(f, d, t));
    }

    {
        const BRReconcileImportStep R = BR_RECONCILE_STEP_REGISTERED, NF = BR_RECONCILE_STEP_NOT_FETCHED,
            ND = BR_RECONCILE_STEP_NOT_DECODED, NT = BR_RECONCILE_STEP_NOT_THE_TX, RF = BR_RECONCILE_STEP_REFUSED;
        // HistoryImportCoverageTest, case for case (the steps each case's stubs produce)
        { BRReconcileImportStep s[] = { R, R, R }; covered("every_planned_tx_registered", 3, s, 3); }
        covered("nothing_planned", 0, NULL, 0);
        { BRReconcileImportStep s[] = { RF }; covered("register_rejection", 1, s, 1); }
        { BRReconcileImportStep s[] = { R, RF, R }; covered("one_rejection_among_many_successes", 3, s, 3); }
        { BRReconcileImportStep s[] = { NF }; covered("fetch_failure", 1, s, 1); }
        { BRReconcileImportStep s[] = { ND }; covered("hex_decode_failure", 1, s, 1); }
        { BRReconcileImportStep s[] = { NF, ND, RF, R }; covered("all_three_failure_modes", 4, s, 4); }
        { BRReconcileImportStep s[] = { R }; covered("wide_wallet_can_still_be_covered", 1, s, 1); }
        { BRReconcileImportStep s[] = { NT, R }; covered("bytes_of_another_transaction", 2, s, 2); }
        // beyond the Kotlin: a pass that stopped short of its plan
        { BRReconcileImportStep s[] = { R }; covered("stopped_short_of_the_plan", 2, s, 1); }
        { BRReconcileImportStep s[] = { R, R }; covered("more_recorded_than_planned", 1, s, 2); }
        { BRReconcileImportStep s[] = { (BRReconcileImportStep)99 }; covered("unknown_step_value", 1, s, 1); }
        // the addresses asked and answered (reconcileAddressHistory's early returns)
        coveredAsked("no_addresses", 0, 0, 0, NULL, 0);
        coveredAsked("history_request_failed", 5, 0, 0, NULL, 0);
        { BRReconcileImportStep s[] = { R }; coveredAsked("history_partly_answered", 600, 500, 1, s, 1); }
        { BRReconcileImportStep s[] = { R }; coveredAsked("more_answered_than_asked", 2, 3, 1, s, 1); }
        coveredAsked("every_address_answered_nothing_missing", 600, 600, 0, NULL, 0);
    }

    {
        const uint32_t hs[] = { 0, 1, 23900121, 2147483646u, 2147483647u, 2147483648u, 4294967295u };
        for (size_t i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) printf("pending %" PRIu32 " %d\n", hs[i], BRReconcileIsPending(hs[i]));
    }

    {
        const UInt256 A = tid(0xa1, 0), B = tid(0xb2, 0);
        { BRUTXO u[] = { {A, 0}, {A, 0}, {B, 1}, {A, 0} }; outpoints("repeated_rows_first_kept", u, 4); }
        { BRUTXO u[] = { {A, 0}, {A, 1}, {B, 0}, {B, 1} }; outpoints("same_txid_other_index", u, 4); }
        { BRUTXO u[] = { {B, 4294967295u}, {A, 4294967295u}, {B, 4294967295u}, {B, 0} }; outpoints("index_edges", u, 4); }
        outpoints("empty", NULL, 0);
    }

    {
        { const char *a[] = { "dgb1qaaa", "dgb1qbbb", "dgb1qaaa" }; addresses("repeated", a, 3); }
        { const char *a[] = { "  dgb1qaaa", "dgb1qaaa\r", "\tdgb1qbbb ", "dgb1qbbb" }; addresses("trimmed_then_distinct", a, 4); }
        { const char *a[] = { "", "   ", "\n", "dgb1qaaa", "" }; addresses("blank_dropped", a, 5); }
        { const char *a[] = { "\x1c" "D8abc" "\x1f", "D8abc", "\x0b" "D8abc" "\x0c" }; addresses("separators_trimmed", a, 3); }
        { const char *a[] = { "dgb1q aaa", "dgb1qaaa" }; addresses("interior_space_kept", a, 2); }
        { const char *a[] = { "DGB1QAAA", "dgb1qaaa" }; addresses("case_sensitive", a, 2); }
        { const char *a[] = { "dgb1qaaa", "dgb1qaaab", "dgb1qaaa", "dgb1qaaab" }; addresses("prefix_is_another_address", a, 4); }
        { const char *a[] = { "dgb1qaaab", "dgb1qaaa " }; addresses("prefix_after_trim", a, 2); }
        addresses("empty", NULL, 0);
    }
    return 0;
}
