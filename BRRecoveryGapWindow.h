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

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryGapWindow_h
