//
//  BRRecoveryScan.h
//
//  The decisions of a Recover-funds scan that are not about one UTXO row: which addresses of a path the
//  lookup shows as used, what one widening round means for a path, what a finished scan may say (some
//  paths unchecked, all of them unchecked, some stopped by the cap), which paths' coins are swept, what
//  to tell someone whose passphrase found nothing, and whether the findings hold anything to offer. Until
//  2026-11 these lived only in Android's Kotlin (core/.../recovery/RecoveryScanService.kt: classifyWidening,
//  highestUsed and State.Done; ForeignSweep.kt sweepSet; PassphraseScanVerdict.kt; RecoverableValue.kt).
//  Both platforms now take them from here. BRRecoveryUtxo.h decides which rows of a lookup are coins;
//  BRRecoveryGapWindow.h decides how far a window grows; this header sits on top of both.
//
//  THE SCAN LOOP (a specification: each platform runs it, because it does network I/O). Kind B of the
//  push-down recipe: the platform keeps its own executor and its parity test holds that executor to this.
//    1. bound = BRRecoveryScanRoundBound over EVERY profile scanned, from its starting windows; fixed for
//       the whole scan. Every profile is pending at its starting windows.
//    2. Each round (round counts from 1): derive the pending profiles at their current windows
//       (BRRecoveryDerive.h), then ask the lookup about them ONE PROFILE AT A TIME, in profile order --
//       never concurrently (the lookup serialises requests and refuses concurrent ones). A profile with
//       nothing derived is not asked.
//    3. For each pending profile's answer: the coins are BRRecoveryUtxoSelect's rows; the used addresses
//       are BRRecoveryScanUsed's (below) over the selected rows' addresses and every transaction the
//       lookup returned for the profile; then BRRecoveryScanRoundStep says what the answer is:
//         ASK_AGAIN        the profile stays pending, at the windows the step gives;
//         FINISHED         this round's answer is the profile's answer;
//         CAPPED           this round's answer is kept, marked capped (not a finished answer);
//         UNREACHABLE      the lookup did not answer: this round's answer is kept, marked unreachable,
//                          and the profile is not asked again in this scan;
//         NOTHING_DERIVED  answered, empty: nothing was there to ask about.
//       Any other value is read as CAPPED. The answer a profile keeps is the one from the round that
//       ended it; a profile that is no longer pending is never asked again.
//    4. When nothing is pending, the results are reported in profile order (the table order of
//       BRDerivationProfiles.h), each summarised as a BRRecoveryScanProfileResult.
//    5. CACHING. A scan's answer may be reused for an identical request (same profiles, same derived
//       addresses) only when BRRecoveryScanMayCache holds for it: every profile that was asked was
//       answered. A partial outage is never remembered, so asking again can reach the paths that failed.
//    6. NEVER READ AN UNANSWERED LOOKUP AS "NO FUNDS". A profile whose lookup failed stays unreachable in
//       its result; it is never reported as a profile that was asked and found nothing, and a scan with
//       one is incomplete (BRRecoveryScanIncomplete) whatever the other profiles found.
//
//  USED (BRRecoveryScanUsed*). A derived address is used when the lookup shows it holding a coin (one of
//  the profile's selected rows names it) or when a transaction the lookup returned pays it: one of that
//  transaction's outputs has the address's output script. The second is how an address paid and since
//  emptied counts, so a wallet that moved its coins along a chain is still followed. Output scripts are
//  read with the core's own parser (BRTransactionParseSigned, the network format every transaction from
//  a lookup is read in) and addresses are turned into scripts with BRAddressScriptPubKey, so both
//  platforms compare the same bytes. A transaction that does not parse adds nothing (it is skipped); an
//  address the core cannot turn into a script is used only through a coin. Coins are matched on the
//  address string exactly as the lookup wrote it (no case folding). The highest used index of each chain
//  (BRRecoveryScanUsedHighest) is what BRRecoveryScanRoundStep is asked with; -1 means nothing used.
//  The raw transactions are bytes: a platform that holds them as hex decodes them first, and a
//  transaction whose hex does not decode is skipped too.
//  NETWORK. BRAddressScriptPubKey follows BRNetworkIsTestnet() at the call (P2PKH version byte, bech32
//  prefix): derive and match on the same network.
//  COST. The lookup decides how many rows and transactions there are, so nothing here is quadratic:
//  BRRecoveryScanUsedBegin sorts the derived addresses twice, by address and by script (an in-place
//  heapsort, O(n log n), no allocation, no recursion); each coin and each output is then one binary
//  search, O(log n). Equal addresses (one key written in two encodings can coincide) share one mark.
//
//  DONE. A profile was ASKED when addresses were derived for it (addressCount > 0); a profile with none
//  was never asked and so cannot have failed.
//    - BRRecoveryScanAnyUnreachable: some profile was asked and not answered. The scan is then incomplete
//      even when other profiles found funds (a balance from two paths with a third unchecked reads as
//      "that is everything").
//    - BRRecoveryScanAllUnreachable: there are results, and every profile that was asked was not
//      answered -- the lookup is down, not the wallet empty. As Kotlin's: when results exist but no
//      profile was asked, this holds too (there is no answer to report).
//    - BRRecoveryScanAnyCapped: some profile's window was stopped by its cap or the round bound.
//    - BRRecoveryScanIncomplete: AnyUnreachable or AnyCapped -- the `incomplete` the passphrase verdict
//      and the findings screen read.
//    - BRRecoveryScanTotal: the sum of the chosen profiles' totals, signed; an overflow is reported.
//  SWEEP SET (BRRecoveryScanSweeps / BRRecoveryScanSweepSet). The profiles whose coins a sweep takes:
//  every profile with a positive total. Recovering this wallet's OWN seed leaves the native profiles
//  (BRDerivationProfile.isNative) in place -- their coins are already this wallet's; recovering a
//  FOREIGN phrase takes the native profiles too, since there they belong to another wallet.
//  PASSPHRASE VERDICT (BRRecoveryPassphraseVerdict). A BIP39 passphrase has no checksum: a typo derives
//  a different, valid, empty wallet. Positive findings rank ahead of an incomplete scan -- money seen on
//  an address is seen, whatever path went unchecked -- and only the negative conclusion waits for a
//  complete scan: FOUND (funds under the passphrase), else LIKELY_TYPO (none under it, funds on the bare
//  phrase), else INCOMPLETE, else NONE_ANYWHERE. Without a comparison scan LIKELY_TYPO cannot fire.
//  RECOVERABLE VALUE (BRRecoverableValueExists / _Answered). Whether the findings hold anything to offer
//  a move for: a sweepable finding, or DigiDollar found. A DigiDollar token output carries zero
//  satoshis, so a wallet holding only dollars has no sweepable finding at all. Whether "nothing found" is
//  an answer: only when the DigiDollar lookup, if one ran, was answered. The DigiDollar scan itself is
//  the platform's; this header takes its two facts (cents found, answered or not).
//
//  Test seam (host KAT recovery_scan_kat in the Android repo): RECOVERY_SCAN_UNFIXED, tested by VALUE.
//  =1 is the comparison arm, four ways the rules go wrong: an unreachable profile (and an unanswered
//  DigiDollar lookup) read as an answered, empty one; an incomplete scan ranked ahead of a positive
//  finding; an address paid and since emptied not counted as used (coins only); the native profiles
//  swept on the wallet's own seed. Unset or =0 is what ships.
//
//  Header-only, static inline. No locking, no clock, no I/O. Allocation only inside the core's
//  transaction parser (BRRecoveryScanUsedMarkRawTx frees what it parsed before returning).
//

#ifndef BRRecoveryScan_h
#define BRRecoveryScan_h

#include "BRRecoveryGapWindow.h"
#include "BRDerivationProfiles.h"
#include "BRTransaction.h"
#include "BRAddress.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RECOVERY_SCAN_UNFIXED
#define RECOVERY_SCAN_UNFIXED 0
#endif

#define BR_RECOVERY_SCAN_SCRIPT_MAX 64   // the bridge's scriptPubKey buffer; every address script fits

typedef enum {
    BR_RECOVERY_SCAN_OK = 0,
    BR_RECOVERY_SCAN_NULL_ARGUMENT = 1,     // a required pointer was NULL (or NULL with a nonzero count)
    BR_RECOVERY_SCAN_BUFFER_TOO_SMALL = 2,  // the working space or the answer does not fit
    BR_RECOVERY_SCAN_OVERFLOW = 3,          // a total does not fit an int64
    BR_RECOVERY_SCAN_BAD_INDEX = 4,         // an index names no result
    BR_RECOVERY_SCAN_UNPARSEABLE = 5        // a raw transaction did not parse; it added nothing
} BRRecoveryScanStatus;

// ---- used addresses ------------------------------------------------------------------------------

// One derived address with its true position: chain 0 receive, 1 change; index within the chain.
typedef struct {
    const char *address;   // NUL-terminated; NULL or "" is never used
    int chain;
    int32_t index;
} BRRecoveryScanAddress;

// Working space, one per derived address; its contents are this header's.
typedef struct {
    uint8_t script[BR_RECOVERY_SCAN_SCRIPT_MAX];
    size_t scriptLen;        // 0: the address has no script
    size_t byAddress;        // the address order: position -> address
    size_t byScript;         // the script order: position -> address
    size_t addressLead;      // the first address equal to this one
    size_t scriptLead;       // the first address with this one's script
    uint8_t coin;            // on a lead: a coin names this address
    uint8_t paid;            // on a lead: a returned transaction pays this script
} BRRecoveryScanSlot;

typedef struct {
    const BRRecoveryScanAddress *addresses;
    BRRecoveryScanSlot *slots;
    size_t count;            // addresses
    size_t addressed;        // positions in the address order (addresses with a nonempty string)
    size_t scripted;         // positions in the script order (addresses with a script)
} BRRecoveryScanUsed;

static inline int _BRRecoveryScanHasAddress(const BRRecoveryScanAddress *a)
{
    return a->address != NULL && a->address[0] != '\0';
}

static inline int _BRRecoveryScanIndexCompare(size_t a, size_t b)
{
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

static inline int _BRRecoveryScanBytesCompare(const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen)
{
    size_t n = (aLen < bLen) ? aLen : bLen;
    int c = n ? memcmp(a, b, n) : 0;
    if (c) return c;
    return _BRRecoveryScanIndexCompare(aLen, bLen);
}

// Address order: by string, then by index (a total order, so the first of a run is the lowest index).
static inline int _BRRecoveryScanAddressOrder(const BRRecoveryScanUsed *u, size_t i, size_t j)
{
    int c = strcmp(u->addresses[i].address, u->addresses[j].address);
    return c ? c : _BRRecoveryScanIndexCompare(i, j);
}

static inline int _BRRecoveryScanScriptOrder(const BRRecoveryScanUsed *u, size_t i, size_t j)
{
    int c = _BRRecoveryScanBytesCompare(u->slots[i].script, u->slots[i].scriptLen,
                                        u->slots[j].script, u->slots[j].scriptLen);
    return c ? c : _BRRecoveryScanIndexCompare(i, j);
}

// An in-place heapsort of the permutation stored in field `byScript` (which != 0) or `byAddress` of
// slots[0..n): O(n log n), no allocation, no recursion.
static inline size_t *_BRRecoveryScanPerm(BRRecoveryScanUsed *u, int byScript, size_t pos)
{
    return byScript ? &u->slots[pos].byScript : &u->slots[pos].byAddress;
}

static inline int _BRRecoveryScanPermCompare(const BRRecoveryScanUsed *u, int byScript, size_t a, size_t b)
{
    return byScript ? _BRRecoveryScanScriptOrder(u, a, b) : _BRRecoveryScanAddressOrder(u, a, b);
}

static inline void _BRRecoveryScanSiftDown(BRRecoveryScanUsed *u, int byScript, size_t root, size_t n)
{
    for (;;) {
        size_t child = 2 * root + 1, top = root, t;
        if (child >= n || child < root) return;
        if (_BRRecoveryScanPermCompare(u, byScript, *_BRRecoveryScanPerm(u, byScript, top),
                                       *_BRRecoveryScanPerm(u, byScript, child)) < 0) top = child;
        if (child + 1 < n &&
            _BRRecoveryScanPermCompare(u, byScript, *_BRRecoveryScanPerm(u, byScript, top),
                                       *_BRRecoveryScanPerm(u, byScript, child + 1)) < 0) top = child + 1;
        if (top == root) return;
        t = *_BRRecoveryScanPerm(u, byScript, root);
        *_BRRecoveryScanPerm(u, byScript, root) = *_BRRecoveryScanPerm(u, byScript, top);
        *_BRRecoveryScanPerm(u, byScript, top) = t;
        root = top;
    }
}

static inline void _BRRecoveryScanSort(BRRecoveryScanUsed *u, int byScript, size_t n)
{
    size_t i, end, t;

    if (n < 2) return;
    for (i = n / 2; i > 0; i--) _BRRecoveryScanSiftDown(u, byScript, i - 1, n);
    for (end = n - 1; end > 0; end--) {
        t = *_BRRecoveryScanPerm(u, byScript, 0);
        *_BRRecoveryScanPerm(u, byScript, 0) = *_BRRecoveryScanPerm(u, byScript, end);
        *_BRRecoveryScanPerm(u, byScript, end) = t;
        _BRRecoveryScanSiftDown(u, byScript, 0, end);
    }
}

// Starts the used-address matcher over addresses[0..count), with slots[0..slotCount) as its working
// space (slotCount >= count, else BUFFER_TOO_SMALL). Both arrays must outlive *u and stay unchanged.
// Nothing is used yet. On any status but OK, *u matches nothing (count 0).
static inline BRRecoveryScanStatus BRRecoveryScanUsedBegin(BRRecoveryScanUsed *u, const BRRecoveryScanAddress addresses[],
                                                           size_t count, BRRecoveryScanSlot slots[], size_t slotCount)
{
    size_t i, p;

    if (!u) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    memset(u, 0, sizeof(*u));
    if (count == 0) return BR_RECOVERY_SCAN_OK;
    if (!addresses || !slots) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    if (slotCount < count) return BR_RECOVERY_SCAN_BUFFER_TOO_SMALL;

    u->addresses = addresses;
    u->slots = slots;
    for (i = 0; i < count; i++) {
        BRRecoveryScanSlot *s = &slots[i];
        memset(s, 0, sizeof(*s));
        s->addressLead = s->scriptLead = i;
        if (_BRRecoveryScanHasAddress(&addresses[i])) {
            size_t need = BRAddressScriptPubKey(NULL, 0, addresses[i].address);
            if (need > 0 && need <= sizeof(s->script)) s->scriptLen = BRAddressScriptPubKey(s->script, sizeof(s->script), addresses[i].address);
        }
    }
    for (i = 0; i < count; i++) {
        if (_BRRecoveryScanHasAddress(&addresses[i])) slots[u->addressed++].byAddress = i;
        if (slots[i].scriptLen > 0) slots[u->scripted++].byScript = i;
    }
    u->count = count;
    _BRRecoveryScanSort(u, 0, u->addressed);
    _BRRecoveryScanSort(u, 1, u->scripted);
    // Each run's lead is its first (lowest-index) member.
    for (p = 0; p < u->addressed; p++) {
        size_t e = slots[p].byAddress;
        if (p > 0 && strcmp(addresses[slots[p - 1].byAddress].address, addresses[e].address) == 0)
            slots[e].addressLead = slots[slots[p - 1].byAddress].addressLead;
    }
    for (p = 0; p < u->scripted; p++) {
        size_t e = slots[p].byScript, f;
        if (p == 0) continue;
        f = slots[p - 1].byScript;
        if (_BRRecoveryScanBytesCompare(slots[f].script, slots[f].scriptLen, slots[e].script, slots[e].scriptLen) == 0)
            slots[e].scriptLead = slots[f].scriptLead;
    }
    return BR_RECOVERY_SCAN_OK;
}

// A coin names address: marks every derived address equal to it. 1 when one did, 0 otherwise.
static inline int BRRecoveryScanUsedMarkAddress(BRRecoveryScanUsed *u, const char *address)
{
    size_t lo = 0, hi, e;

    if (!u || !u->slots || !address || address[0] == '\0') return 0;
    hi = u->addressed;
    while (lo < hi) {   // the first position whose address is not below `address`
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(u->addresses[u->slots[mid].byAddress].address, address) < 0) lo = mid + 1; else hi = mid;
    }
    if (lo >= u->addressed) return 0;
    e = u->slots[lo].byAddress;
    if (strcmp(u->addresses[e].address, address) != 0) return 0;
    u->slots[u->slots[e].addressLead].coin = 1;
    return 1;
}

// A returned transaction has an output with this script: marks every derived address whose script it
// is. 1 when one did, 0 otherwise.
static inline int BRRecoveryScanUsedMarkScript(BRRecoveryScanUsed *u, const uint8_t *script, size_t scriptLen)
{
    size_t lo = 0, hi, e;

    if (!u || !u->slots || !script || scriptLen == 0) return 0;
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): coins only; an address paid and since emptied is not used.
    return 0;
#endif
    hi = u->scripted;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2, m = u->slots[mid].byScript;
        if (_BRRecoveryScanBytesCompare(u->slots[m].script, u->slots[m].scriptLen, script, scriptLen) < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= u->scripted) return 0;
    e = u->slots[lo].byScript;
    if (_BRRecoveryScanBytesCompare(u->slots[e].script, u->slots[e].scriptLen, script, scriptLen) != 0) return 0;
    u->slots[u->slots[e].scriptLead].paid = 1;
    return 1;
}

// A transaction the lookup returned, as bytes in the network format: marks every derived address one of
// its outputs pays. OK when it parsed (*matched, when not NULL, is the number of outputs that paid a
// derived address); UNPARSEABLE when it did not, and nothing is marked.
static inline BRRecoveryScanStatus BRRecoveryScanUsedMarkRawTx(BRRecoveryScanUsed *u, const uint8_t *tx, size_t txLen,
                                                               size_t *matched)
{
    BRTransaction *t;
    size_t i, n = 0;

    if (matched) *matched = 0;
    if (!u) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    if (!tx || txLen == 0) return BR_RECOVERY_SCAN_UNPARSEABLE;
    t = BRTransactionParseSigned(tx, txLen);
    if (!t) return BR_RECOVERY_SCAN_UNPARSEABLE;
    for (i = 0; i < t->outCount; i++) {
        if (t->outputs[i].script && BRRecoveryScanUsedMarkScript(u, t->outputs[i].script, t->outputs[i].scriptLen)) n++;
    }
    BRTransactionFree(t);
    if (matched) *matched = n;
    return BR_RECOVERY_SCAN_OK;
}

// Whether derived address i is used. 0 past the end.
static inline int BRRecoveryScanUsedIs(const BRRecoveryScanUsed *u, size_t i)
{
    const BRRecoveryScanSlot *s;

    if (!u || !u->slots || i >= u->count) return 0;
    s = &u->slots[i];
    if (_BRRecoveryScanHasAddress(&u->addresses[i]) && u->slots[s->addressLead].coin) return 1;
    return s->scriptLen > 0 && u->slots[s->scriptLead].paid;
}

// The highest index on chain (0 receive, 1 change) among the used derived addresses; -1 when none is
// (BRRecoveryGapNext's "nothing used"). A negative index is never counted. O(n).
static inline int32_t BRRecoveryScanUsedHighest(const BRRecoveryScanUsed *u, int chain)
{
    int32_t best = -1;
    size_t i;

    if (!u || !u->slots) return -1;
    for (i = 0; i < u->count; i++) {
        const BRRecoveryScanAddress *a = &u->addresses[i];
        if (a->chain == chain && a->index > best && BRRecoveryScanUsedIs(u, i)) best = a->index;
    }
    return best;
}

// ---- one round ------------------------------------------------------------------------------------

typedef enum {
    BR_RECOVERY_SCAN_STEP_ASK_AGAIN = BR_RECOVERY_GAP_ASK_AGAIN,   // asked again, at the next windows
    BR_RECOVERY_SCAN_STEP_FINISHED = BR_RECOVERY_GAP_FINISHED,     // this round's answer is the answer
    BR_RECOVERY_SCAN_STEP_CAPPED = BR_RECOVERY_GAP_CAPPED,         // kept, marked capped
    BR_RECOVERY_SCAN_STEP_UNREACHABLE = 3,                         // kept, marked unreachable; not asked again
    BR_RECOVERY_SCAN_STEP_NOTHING_DERIVED = 4                      // answered, empty: nothing to ask about
} BRRecoveryScanStep;

// The step a BRRecoveryGapOutcome value means. Any value it does not know is CAPPED.
static inline BRRecoveryScanStep BRRecoveryScanStepForGapOutcome(int outcome)
{
    switch (outcome) {
    case BR_RECOVERY_GAP_ASK_AGAIN: return BR_RECOVERY_SCAN_STEP_ASK_AGAIN;
    case BR_RECOVERY_GAP_FINISHED: return BR_RECOVERY_SCAN_STEP_FINISHED;
    default: return BR_RECOVERY_SCAN_STEP_CAPPED;
    }
}

// The scan's round bound: BRRecoveryGapScanRoundBound of the smallest starting windows among the
// count profiles (0 and 0 when there are none). starts may be NULL only when count is 0.
static inline int32_t BRRecoveryScanRoundBound(const int32_t startExternal[], const int32_t startInternal[], size_t count)
{
    int32_t ext = 0, in = 0;
    size_t i;

    if (count > 0 && startExternal && startInternal) {
        ext = startExternal[0]; in = startInternal[0];
        for (i = 1; i < count; i++) {
            if (startExternal[i] < ext) ext = startExternal[i];
            if (startInternal[i] < in) in = startInternal[i];
        }
    }
    return BRRecoveryGapScanRoundBound(ext, in);
}

// The same bound for profiles of BRDerivationProfiles.h (their gapExternal / gapInternal).
static inline int32_t BRRecoveryScanRoundBoundForProfiles(const BRDerivationProfile profiles[], size_t count)
{
    int32_t ext = 0, in = 0;
    size_t i;

    if (count > 0 && profiles) {
        ext = profiles[0].gapExternal; in = profiles[0].gapInternal;
        for (i = 1; i < count; i++) {
            if (profiles[i].gapExternal < ext) ext = profiles[i].gapExternal;
            if (profiles[i].gapInternal < in) in = profiles[i].gapInternal;
        }
    }
    return BRRecoveryGapScanRoundBound(ext, in);
}

// What one round's answer is for a profile asked at windows external/internal: reachable nonzero when
// the lookup answered; addressCount the addresses derived (and asked about); usedExternal/usedInternal
// BRRecoveryScanUsedHighest of each chain (-1: nothing used); round from 1 of at most bound
// (BRRecoveryScanRoundBound). *nextExternal / *nextInternal (each may be NULL) are the windows to ask
// at on ASK_AGAIN, and the windows given otherwise.
static inline BRRecoveryScanStep BRRecoveryScanRoundStep(int reachable, size_t addressCount, int32_t external,
                                                         int32_t internal, int32_t usedExternal, int32_t usedInternal,
                                                         int32_t round, int32_t bound, int32_t *nextExternal,
                                                         int32_t *nextInternal)
{
    int32_t ext = external, in = internal;
    BRRecoveryScanStep step;

    if (nextExternal) *nextExternal = external;
    if (nextInternal) *nextInternal = internal;
    if (addressCount == 0) return BR_RECOVERY_SCAN_STEP_NOTHING_DERIVED;
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): an unanswered lookup read as an answer with nothing used.
    if (!reachable) { usedExternal = -1; usedInternal = -1; }
#else
    if (!reachable) return BR_RECOVERY_SCAN_STEP_UNREACHABLE;
#endif
    ext = BRRecoveryGapNext(0, external, usedExternal);
    in = BRRecoveryGapNext(1, internal, usedInternal);
    step = BRRecoveryScanStepForGapOutcome(
        BRRecoveryGapOutcome(external, internal, ext, in, usedExternal, usedInternal, round, bound));
    if (step == BR_RECOVERY_SCAN_STEP_ASK_AGAIN) {
        if (nextExternal) *nextExternal = ext;
        if (nextInternal) *nextInternal = in;
    }
    return step;
}

// ---- a finished scan ------------------------------------------------------------------------------

// One profile's answer, as a finished scan reports it.
typedef struct {
    size_t addressCount;   // addresses derived and asked about; 0: never asked
    int reachable;         // nonzero: the lookup answered
    int capped;            // nonzero: the window was stopped by its cap or the round bound (STEP_CAPPED)
    int isNative;          // the profile's BRDerivationProfile.isNative
    int64_t totalSat;      // BRRecoveryUtxoTotal of its selected rows
} BRRecoveryScanProfileResult;

// Whether r was asked and not answered.
static inline int BRRecoveryScanIsUnreachable(const BRRecoveryScanProfileResult *r)
{
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): an unreachable profile read as one that answered, empty.
    (void)r;
    return 0;
#else
    return r != NULL && r->addressCount > 0 && !r->reachable;
#endif
}

// Some profile was asked and not answered.
static inline int BRRecoveryScanAnyUnreachable(const BRRecoveryScanProfileResult results[], size_t count)
{
    size_t i;
    if (!results) return 0;
    for (i = 0; i < count; i++) if (BRRecoveryScanIsUnreachable(&results[i])) return 1;
    return 0;
}

// There are results, and every profile that was asked was not answered (also when none was asked).
static inline int BRRecoveryScanAllUnreachable(const BRRecoveryScanProfileResult results[], size_t count)
{
    size_t i;
    if (!results || count == 0) return 0;
    for (i = 0; i < count; i++) {
        if (results[i].addressCount > 0 && !BRRecoveryScanIsUnreachable(&results[i])) return 0;
    }
    return 1;
}

// Some profile's window was stopped by its cap or the round bound.
static inline int BRRecoveryScanAnyCapped(const BRRecoveryScanProfileResult results[], size_t count)
{
    size_t i;
    if (!results) return 0;
    for (i = 0; i < count; i++) if (results[i].capped) return 1;
    return 0;
}

// The scan is not a finished answer: some profile unreachable or capped.
static inline int BRRecoveryScanIncomplete(const BRRecoveryScanProfileResult results[], size_t count)
{
    return BRRecoveryScanAnyUnreachable(results, count) || BRRecoveryScanAnyCapped(results, count);
}

// Whether this answer may be cached for an identical request: every profile that was asked was answered.
static inline int BRRecoveryScanMayCache(const BRRecoveryScanProfileResult results[], size_t count)
{
    if (count > 0 && !results) return 0;
    return !BRRecoveryScanAnyUnreachable(results, count);
}

// The signed sum of the totals of results[indices[0..count)] (indices NULL: results[0..count)). *total
// is 0 unless OK.
static inline BRRecoveryScanStatus BRRecoveryScanTotal(const BRRecoveryScanProfileResult results[], size_t resultCount,
                                                       const size_t indices[], size_t count, int64_t *total)
{
    int64_t sum = 0, a;
    size_t i, k;

    if (!total) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    *total = 0;
    if (count == 0) return BR_RECOVERY_SCAN_OK;
    if (!results) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    for (i = 0; i < count; i++) {
        k = indices ? indices[i] : i;
        if (k >= resultCount) return BR_RECOVERY_SCAN_BAD_INDEX;
        a = results[k].totalSat;
        if ((a > 0 && sum > INT64_MAX - a) || (a < 0 && sum < INT64_MIN - a)) return BR_RECOVERY_SCAN_OVERFLOW;
        sum += a;
    }
    *total = sum;
    return BR_RECOVERY_SCAN_OK;
}

// ---- the sweep set --------------------------------------------------------------------------------

// Whether a sweep takes r's coins: a positive total, and not a native profile on the wallet's own seed
// (isForeign 0).
static inline int BRRecoveryScanSweeps(const BRRecoveryScanProfileResult *r, int isForeign)
{
    if (!r || r->totalSat <= 0) return 0;
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): the native profiles swept on the wallet's own seed too.
    (void)isForeign;
    return 1;
#else
    return isForeign || !r->isNative;
#endif
}

// The indices of the results a sweep takes, in result order, into out[0..capacity). *outCount is the
// number written (0 unless OK); BUFFER_TOO_SMALL when they do not fit (capacity >= count always does).
static inline BRRecoveryScanStatus BRRecoveryScanSweepSet(const BRRecoveryScanProfileResult results[], size_t count,
                                                          int isForeign, size_t out[], size_t capacity, size_t *outCount)
{
    size_t i, n = 0;

    if (!outCount) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    *outCount = 0;
    if (count == 0) return BR_RECOVERY_SCAN_OK;
    if (!results) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
    for (i = 0; i < count; i++) {
        if (!BRRecoveryScanSweeps(&results[i], isForeign)) continue;
        if (!out) return BR_RECOVERY_SCAN_NULL_ARGUMENT;
        if (n >= capacity) return BR_RECOVERY_SCAN_BUFFER_TOO_SMALL;
        out[n++] = i;
    }
    *outCount = n;
    return BR_RECOVERY_SCAN_OK;
}

// ---- the passphrase verdict -----------------------------------------------------------------------

typedef enum {
    BR_RECOVERY_PASSPHRASE_FOUND = 0,          // funds under the passphrase
    BR_RECOVERY_PASSPHRASE_LIKELY_TYPO = 1,    // none under it; the bare phrase has funds
    BR_RECOVERY_PASSPHRASE_NONE_ANYWHERE = 2,  // nothing either way: an honest empty result
    BR_RECOVERY_PASSPHRASE_INCOMPLETE = 3      // the scan could not finish: claim nothing
} BRRecoveryPassphraseOutcome;

// withPassphraseSat: the total found with the passphrase. haveWithout nonzero when a comparison scan
// without the passphrase ran, and withoutPassphraseSat is its total (ignored otherwise). incomplete:
// BRRecoveryScanIncomplete of the scan.
static inline BRRecoveryPassphraseOutcome BRRecoveryPassphraseVerdict(int64_t withPassphraseSat, int haveWithout,
                                                                      int64_t withoutPassphraseSat, int incomplete)
{
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): incompleteness ranked ahead of a positive finding.
    if (incomplete) return BR_RECOVERY_PASSPHRASE_INCOMPLETE;
#endif
    if (withPassphraseSat > 0) return BR_RECOVERY_PASSPHRASE_FOUND;
    if (haveWithout && withoutPassphraseSat > 0) return BR_RECOVERY_PASSPHRASE_LIKELY_TYPO;
    if (incomplete) return BR_RECOVERY_PASSPHRASE_INCOMPLETE;
    return BR_RECOVERY_PASSPHRASE_NONE_ANYWHERE;
}

// ---- recoverable value ----------------------------------------------------------------------------

// Whether the findings hold value worth offering a move for: sweepableFindings (the profiles of the
// sweep set) > 0, or a DigiDollar scan ran (ddScanned nonzero) and found ddCents > 0.
static inline int BRRecoverableValueExists(size_t sweepableFindings, int ddScanned, int64_t ddCents)
{
    return sweepableFindings > 0 || (ddScanned && ddCents > 0);
}

// Whether a "nothing found" is an answer rather than a gap: value exists, or no DigiDollar scan ran, or
// it ran and was answered (ddReachable nonzero). Only meaningful when BRRecoverableValueExists is 0.
static inline int BRRecoverableValueAnswered(size_t sweepableFindings, int ddScanned, int64_t ddCents, int ddReachable)
{
#if RECOVERY_SCAN_UNFIXED
    // RED ARM SEAM (recovery_scan_kat): an unanswered DigiDollar lookup read as a zero balance.
    ddReachable = 1;
#endif
    return BRRecoverableValueExists(sweepableFindings, ddScanned, ddCents) || !ddScanned || ddReachable;
}

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryScan_h
