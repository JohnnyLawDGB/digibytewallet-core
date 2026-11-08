//
//  BRRecoveryGapWindow.h
//
//  How far the plain-DGB recovery scan derives on each path (Android 4.1.3 G1), and when a path's
//  answer is finished. Until 2026-11 this lived in Android Kotlin (RecoveryGapWindow and the
//  per-path decision in RecoveryScanService.classifyWidening). Android now calls it through JNI
//  (jni_recovery_gap.c); iOS calls the same functions.
//
//  The scan used to stop at a fixed window (a profile's 200 external / 100 internal addresses) and
//  report itself complete, so a wallet used past that window lost every coin beyond it from the
//  answer. It widens each chain instead: while an address within BR_RECOVERY_GAP_EXTERNAL (or
//  BR_RECOVERY_GAP_INTERNAL) of the window's end has been used, the window grows to that gap past
//  the last used index, by at least a whole gap each time, up to BR_RECOVERY_MAX_EXTERNAL /
//  BR_RECOVERY_MAX_INTERNAL, so a misbehaving lookup cannot make it ask forever. A window the cap
//  stopped is reported as incomplete, never as a finished answer.
//
//  "Used" is what the platform's lookup shows: an address holding a coin, or one paid by a
//  transaction the lookup returned. Spent-and-emptied addresses the lookup does not return are
//  invisible, which is why the gap is wider than the BIP44 20. Working out the highest used index
//  of a chain from the derived addresses is the platform's (it holds the lookup's answer).
//
//  A platform's scan loop, per round, for each path still being asked:
//    nextExternal = BRRecoveryGapNext(0, external, usedExternal);
//    nextInternal = BRRecoveryGapNext(1, internal, usedInternal);
//    BRRecoveryGapOutcome(external, internal, nextExternal, nextInternal, usedExternal,
//                         usedInternal, round, bound)
//      BR_RECOVERY_GAP_ASK_AGAIN  derive the path at the next windows and ask again;
//      BR_RECOVERY_GAP_FINISHED   this round's answer is the path's answer;
//      BR_RECOVERY_GAP_CAPPED     this round's answer is kept, marked incomplete;
//  where round counts from 1 and bound is BRRecoveryGapScanRoundBound of the smallest starting
//  windows among the scanned paths (0 when there are none). Any other outcome value must be read
//  as CAPPED.
//
//  The inputs are what Kotlin passed, as int32_t: a negative highest-used index means "nothing
//  used" (Kotlin's null; a real index is never negative). Arithmetic wraps as Kotlin's Int did
//  (two's complement, done in uint32_t), so every input gives Kotlin's answer, including the
//  unreachable ones near INT32_MAX. Chain 0 is external, 1 internal; any other chain never grows
//  and always reads as capped, the safe answer.
//
//  Test seams (host KAT recovery_gap_window_kat in the Android repo), each failing only its own
//  cases: RECOVERY_GAP_RED (a grown window grows only to a gap past the last use, not by a whole
//  gap, so a lookup that keeps answering "used near the end" walks one address per round) and
//  RECOVERY_CAP_RED (a path the cap or the round bound stopped is reported finished, the fixed
//  window's old answer).
//
//  The DigiDollar scan's window (Android 4.1.2 row 19, m/86'/20'/0') is the second half of this
//  header, BRRecoveryDigiDollarGap*: the same idea with its own gaps, one cap, no whole-gap step and
//  no round bound. It shares the outcome values above.
//
//  Header-only, static inline. No I/O, no locking, libc only.
//

#ifndef BRRecoveryGapWindow_h
#define BRRecoveryGapWindow_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_RECOVERY_GAP_EXTERNAL 100
#define BR_RECOVERY_GAP_INTERNAL 50
#define BR_RECOVERY_MAX_EXTERNAL 2000
#define BR_RECOVERY_MAX_INTERNAL 1000

#define BR_RECOVERY_GAP_ASK_AGAIN 0
#define BR_RECOVERY_GAP_FINISHED  1
#define BR_RECOVERY_GAP_CAPPED    2

// Kotlin Int addition and subtraction: wrap modulo 2^32.
static inline int32_t _BRRecoveryGapAdd(int32_t a, int32_t b) { return (int32_t)((uint32_t)a + (uint32_t)b); }
static inline int32_t _BRRecoveryGapSub(int32_t a, int32_t b) { return (int32_t)((uint32_t)a - (uint32_t)b); }
static inline int32_t _BRRecoveryGapMax(int32_t a, int32_t b) { return a > b ? a : b; }
static inline int32_t _BRRecoveryGapMin(int32_t a, int32_t b) { return a < b ? a : b; }

static inline int32_t _BRRecoveryGapOf(int chain) { return chain == 0 ? BR_RECOVERY_GAP_EXTERNAL : BR_RECOVERY_GAP_INTERNAL; }
static inline int32_t _BRRecoveryMaxOf(int chain) { return chain == 0 ? BR_RECOVERY_MAX_EXTERNAL : BR_RECOVERY_MAX_INTERNAL; }

// The window count (addresses 0 until count) of chain should grow to, given highestUsed (< 0:
// nothing used): count when it already reaches the chain's gap past it. Never above the chain's
// cap, never below count. A window that grows grows by at least a whole gap, so a lookup that
// keeps answering "used near the far end" reaches the cap in at most (max - start) / gap rounds,
// not one per address.
static inline int32_t BRRecoveryGapNext(int chain, int32_t count, int32_t highestUsed)
{
    int32_t gap, max, wanted;

    if ((chain != 0 && chain != 1) || highestUsed < 0) return count;
    gap = _BRRecoveryGapOf(chain);
    max = _BRRecoveryMaxOf(chain);
    wanted = _BRRecoveryGapAdd(_BRRecoveryGapAdd(highestUsed, gap), 1);
    if (wanted <= count) return count;
#ifdef RECOVERY_GAP_RED
    // RED ARM SEAM (recovery_gap_window_kat): grow only to a gap past the last use.
    return _BRRecoveryGapMax(count, _BRRecoveryGapMin(wanted, max));
#else
    return _BRRecoveryGapMax(count, _BRRecoveryGapMin(_BRRecoveryGapMax(wanted, _BRRecoveryGapAdd(count, gap)), max));
#endif
}

// Whether chain's cap stopped a window that still wanted to grow: the use at highestUsed (< 0:
// nothing used) is within a gap of the cap. 1 for a chain that is neither 0 nor 1.
static inline int BRRecoveryGapCapped(int chain, int32_t highestUsed)
{
    if (chain != 0 && chain != 1) return 1;
    if (highestUsed < 0) return 0;
    return _BRRecoveryGapAdd(_BRRecoveryGapAdd(highestUsed, _BRRecoveryGapOf(chain)), 1) > _BRRecoveryMaxOf(chain);
}

// More rounds than chain's window can take to reach its cap from start, growing by a whole gap:
// ceil(max(0, cap - start) / gap) + 2. 2 for a chain that is neither 0 nor 1 (it never grows).
static inline int32_t BRRecoveryGapRoundBound(int chain, int32_t start)
{
    int32_t gap, room;

    if (chain != 0 && chain != 1) return 2;
    gap = _BRRecoveryGapOf(chain);
    room = _BRRecoveryGapMax(0, _BRRecoveryGapSub(_BRRecoveryMaxOf(chain), start));
    return _BRRecoveryGapAdd(_BRRecoveryGapSub(_BRRecoveryGapAdd(room, gap), 1) / gap, 2);
}

// The scan's round bound: the larger chain bound, from the smallest starting windows among the
// paths scanned (0 and 0 when there are none).
static inline int32_t BRRecoveryGapScanRoundBound(int32_t startExternal, int32_t startInternal)
{
    return _BRRecoveryGapMax(BRRecoveryGapRoundBound(0, startExternal), BRRecoveryGapRoundBound(1, startInternal));
}

// What one round's answer is for a path whose windows were external/internal and should now be
// nextExternal/nextInternal (BRRecoveryGapNext), on round (from 1) of at most bound
// (BRRecoveryGapScanRoundBound). A path whose windows still grow is asked again until the round
// bound; a path that stopped growing is finished, unless its cap stopped it (BRRecoveryGapCapped)
// or the round bound did while it still grew, and then it is capped: not a finished answer.
static inline int BRRecoveryGapOutcome(int32_t external, int32_t internal, int32_t nextExternal, int32_t nextInternal,
                                       int32_t usedExternal, int32_t usedInternal, int32_t round, int32_t bound)
{
    int grew = nextExternal != external || nextInternal != internal;

    if (grew && round < bound) return BR_RECOVERY_GAP_ASK_AGAIN;
#ifdef RECOVERY_CAP_RED
    // RED ARM SEAM (recovery_gap_window_kat): a stopped path is a finished answer, cap or not.
    (void)usedExternal; (void)usedInternal;
    return BR_RECOVERY_GAP_FINISHED;
#else
    if (grew || BRRecoveryGapCapped(0, usedExternal) || BRRecoveryGapCapped(1, usedInternal)) return BR_RECOVERY_GAP_CAPPED;
    return BR_RECOVERY_GAP_FINISHED;
#endif
}

// ---- The DigiDollar scan (Android 4.1.2 row 19) -------------------------------------------------
//
//  How far the DigiDollar recovery scan derives at m/86'/20'/0'. Until 2026-11 this was Android
//  Kotlin (DigiDollarGapWindow, the gaps in RecoveryScanService and its stop decision in
//  scanDigiDollar). Android now calls it through JNI (jni_recovery_gap.c); iOS calls the same
//  functions.
//
//  A wallet sends DigiDollar change to the next unused internal P2TR address, so each send with
//  change moves one index further along the internal chain. A fixed window of 10 internal addresses
//  lost the dollars of any wallet past about ten such sends, and recovery reported itself complete.
//  Each chain's window therefore starts at its gap (BR_RECOVERY_DIGIDOLLAR_GAP_EXTERNAL /
//  _INTERNAL) and, while an address within that gap of the window's end has been used (any
//  transaction touched it), grows to the gap past the last used index, up to
//  BR_RECOVERY_DIGIDOLLAR_MAX addresses per chain, so a misbehaving lookup cannot make it ask
//  forever. A window the cap stopped is not a finished answer.
//
//  It differs from the plain-DGB rule above, deliberately and as the Kotlin did: the gaps are short
//  (each DigiDollar address is its own request, not part of a batch), one cap serves both chains,
//  a grown window grows only to a gap past the last use (not by a whole gap), and there is no round
//  bound (every round derives at least one new address and the cap bounds the windows, and the
//  platform asks each address once however often the window grows).
//
//  A platform's scan loop:
//    external = BRRecoveryDigiDollarGapStart(0); internal = BRRecoveryDigiDollarGapStart(1);
//    each round, after asking the lookup about the derived addresses:
//      nextExternal = BRRecoveryDigiDollarGapNext(0, external, usedExternal);
//      nextInternal = BRRecoveryDigiDollarGapNext(1, internal, usedInternal);
//      BRRecoveryDigiDollarGapOutcome(external, internal, nextExternal, nextInternal,
//                                     usedExternal, usedInternal)
//        BR_RECOVERY_GAP_ASK_AGAIN  derive at the next windows and ask again;
//        BR_RECOVERY_GAP_FINISHED   this round's answer is the scan's answer;
//        BR_RECOVERY_GAP_CAPPED     this round's answer is kept, marked incomplete;
//  any other outcome value must be read as CAPPED.
//
//  Inputs as above: a negative highest-used index is "nothing used" (Kotlin's null), and the
//  arithmetic wraps as Kotlin's Int did. Chain 0 is external, 1 internal; any other chain starts
//  empty, never grows and always reads as capped.
//
//  Test seams (host KAT digidollar_gap_window_kat in the Android repo), each failing only its own
//  cases: DIGIDOLLAR_GAP_RED (the fixed window: a window never grows, the 4.1.2 row 19 bug) and
//  DIGIDOLLAR_CAP_RED (a scan the cap stopped is reported finished).

#define BR_RECOVERY_DIGIDOLLAR_GAP_EXTERNAL 20
#define BR_RECOVERY_DIGIDOLLAR_GAP_INTERNAL 10
#define BR_RECOVERY_DIGIDOLLAR_MAX 1000

static inline int32_t _BRRecoveryDigiDollarGapOf(int chain)
{
    return chain == 0 ? BR_RECOVERY_DIGIDOLLAR_GAP_EXTERNAL : BR_RECOVERY_DIGIDOLLAR_GAP_INTERNAL;
}

// The window (addresses 0 until it) chain's scan starts at: its gap. 0 for a chain that is neither
// 0 nor 1.
static inline int32_t BRRecoveryDigiDollarGapStart(int chain)
{
    if (chain != 0 && chain != 1) return 0;
    return _BRRecoveryDigiDollarGapOf(chain);
}

// The window count of chain should grow to, given highestUsed (< 0: nothing used): the chain's gap
// past the last use, never above BR_RECOVERY_DIGIDOLLAR_MAX; count when it already reaches that.
// As Kotlin's minOf(wanted, MAX): a count already above the cap that still wants to grow falls to
// the cap. The scan never reaches that (its windows start at the gaps and only this grows them).
static inline int32_t BRRecoveryDigiDollarGapNext(int chain, int32_t count, int32_t highestUsed)
{
    int32_t wanted;

    if ((chain != 0 && chain != 1) || highestUsed < 0) return count;
    wanted = _BRRecoveryGapAdd(_BRRecoveryGapAdd(highestUsed, _BRRecoveryDigiDollarGapOf(chain)), 1);
#ifdef DIGIDOLLAR_GAP_RED
    // RED ARM SEAM (digidollar_gap_window_kat): the fixed window, which never grows.
    (void)wanted;
    return count;
#else
    return wanted > count ? _BRRecoveryGapMin(wanted, BR_RECOVERY_DIGIDOLLAR_MAX) : count;
#endif
}

// Whether BR_RECOVERY_DIGIDOLLAR_MAX stopped chain's window while it still wanted to grow: the use
// at highestUsed (< 0: nothing used) is within the chain's gap of the cap. 1 for a chain that is
// neither 0 nor 1.
static inline int BRRecoveryDigiDollarGapCapped(int chain, int32_t highestUsed)
{
    if (chain != 0 && chain != 1) return 1;
    if (highestUsed < 0) return 0;
    return _BRRecoveryGapAdd(_BRRecoveryGapAdd(highestUsed, _BRRecoveryDigiDollarGapOf(chain)), 1) > BR_RECOVERY_DIGIDOLLAR_MAX;
}

// What one round's answer is for a scan whose windows were external/internal and should now be
// nextExternal/nextInternal (BRRecoveryDigiDollarGapNext): asked again while either window grows;
// once neither does, capped when the cap stopped either chain (BRRecoveryDigiDollarGapCapped),
// otherwise finished.
static inline int BRRecoveryDigiDollarGapOutcome(int32_t external, int32_t internal, int32_t nextExternal,
                                                 int32_t nextInternal, int32_t usedExternal, int32_t usedInternal)
{
    if (nextExternal != external || nextInternal != internal) return BR_RECOVERY_GAP_ASK_AGAIN;
#ifdef DIGIDOLLAR_CAP_RED
    // RED ARM SEAM (digidollar_gap_window_kat): a stopped scan is a finished answer, cap or not.
    (void)usedExternal; (void)usedInternal;
    return BR_RECOVERY_GAP_FINISHED;
#else
    if (BRRecoveryDigiDollarGapCapped(0, usedExternal) || BRRecoveryDigiDollarGapCapped(1, usedInternal))
        return BR_RECOVERY_GAP_CAPPED;
    return BR_RECOVERY_GAP_FINISHED;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryGapWindow_h
