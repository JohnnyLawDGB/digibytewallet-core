//
//  BRDandelionEmbargo.h
//
//  The Dandelion++ embargo: after a send is stem-submitted to one Dandelion-capable peer
//  (BRPeerManagerStemPublishTx), the wallet waits a random delay; if no peer has relayed the
//  transaction back by then, it floods ("fluffs") it itself, so a send is never stranded for the
//  sake of privacy. While the embargo runs, the stranded-send sweep (BRStrandedSend.h) must not
//  re-publish the send: a flood then would announce it from this wallet to every peer and undo
//  the stem. Both platforms must draw the same delay from the same random draw, fluff on the
//  same evidence and spare the same sends, or their wire behaviour differs.
//
//  Until 2026-11 these rules lived in Android Kotlin (DandelionBroadcastPolicy.kt, the timer in
//  Broadcaster.kt), out of reach of the iOS build. This header carries them value for value; the
//  delay is bit-exact with the Kotlin double arithmetic (see BRDandelionEmbargoDelayMs).
//
//  The rules:
//    - stem only when the setting is on AND a capable peer is connected; otherwise flood. A
//      stem that finds no peer at the last instant (BRPeerManagerStemPublishTx returns 0) is
//      flooded with BRPeerManagerPublishTx;
//    - the embargo is armed when the stem returns 1: delay = BRDandelionEmbargoDelayMs(draw)
//      from a uniform draw the platform takes from its CSPRNG (the core never draws), deadline =
//      the wall clock then + delay;
//    - at the deadline: no manager -> nothing; relay count 0 on the CURRENT manager ->
//      BRPeerManagerFluffTx on it; otherwise nothing. Then the embargo is over either way;
//    - the sweep may re-publish a send only when no embargo of THIS process is pending for it.
//      An embargo ends when its deadline step has run, or when the process ends.
//
//  Clock. Deadlines are wall-clock milliseconds since the Unix epoch (Android
//  System.currentTimeMillis, iOS Date().timeIntervalSince1970 * 1000), so a deadline written
//  down survives a suspension and a manager teardown and can be re-armed on foreground. A wall
//  clock can jump; BRDandelionEmbargoRemainingMs never waits longer than
//  BR_DANDELION_EMBARGO_MAX_MS, so a clock set back cannot hold an embargo, and the sweep's spare
//  of it, for longer than the window (Android's timer is a monotonic coroutine delay and never
//  waits past the delay it drew). That holds only if the platform runs the deadline step when the
//  wait it was given ends, without asking RemainingMs again: asking again after a set-back clock
//  would wait another window. A deadline already passed at re-arm runs its step at once.
//
//  The manager torn down before the deadline (iOS frees the peer manager on every trip to the
//  background; Android rebuilds it in-process on forceReconnect -> startSync). Android's timer
//  does not know which manager it stemmed to: at the deadline it reads the relay count of
//  whatever manager is current (0 if there is none) and, on 0, calls BRPeerManagerFluffTx on
//  that manager (0 and nothing if there is none). A new manager has no publish entry for the
//  stem, so that fluff is a no-op (BRPeerManagerFluffTx: "no-op if the tx isn't in the publish
//  list"), the embargo ends, and the send is flooded by the next stranded-send sweep through the
//  ordinary publish path (BRPeerManagerPublishTx; every 90 s with peers on both platforms). So
//  across a teardown the deadline itself sends nothing in the usual case, and the stem is
//  released to the sweep. This header keeps exactly that: the deadline step reads and acts on
//  the CURRENT manager, never the one the stem went to, and a platform must not substitute an
//  immediate flood. This is a consequence of Android's timer, not a rule Android states; it is
//  adopted for parity and is the owner's to confirm. If it changes (for instance to flood at the
//  deadline on a manager that is not the stem's), it changes here and on both platforms at once.
//  One corner follows from it unchanged: a new manager that took the send from a peer while
//  still syncing lists it for publish without counting the relay, and the fluff then announces
//  it to every peer. That send is already on the network.
//
//  Process death. Android keeps pending embargoes in memory (Broadcaster.kt:33): after a restart
//  there are none and the sweep re-publishes at once. A platform that persists its deadlines
//  must do the same: an embargo armed by an earlier process is not pending, and its deadline
//  step is not run (BRDandelionEmbargoIsPending).
//
//  Android references (line numbers at tag v4.1.3; the behaviour is unchanged on develop as of
//  2026-11-13, where some of these lines have moved):
//    core/.../core/dandelion/DandelionBroadcastPolicy.kt:6-7 (window), :11-12 (stem), :16
//    (fluff), :28 (sweep), :32-35 (delay); Broadcaster.kt:52-62 (broadcast), :64-79 (embargo
//    timer; :65 the draw, SecureRandom.nextDouble), :71 (a relay count it cannot read counts as
//    relayed); native/.../bridge/jni_transaction.c:603-624 (fluff and relay count with no
//    manager); jni_peer.c:879-893 (the in-process teardown); app/.../SyncService.kt:3772 (the
//    sweep's spare), :4387 (the sweep's 90 s).
//
//  Host KAT: digibytewallet-android native/src/test/host/dandelion_embargo_kat/, against
//  vectors/dandelion-embargo/vectors.txt (Android's arithmetic, computed outside this header).
//  Comparison seams, each failing only its own cases: DANDELION_EMBARGO_DELAY_RED (the exact
//  integer quotient instead of Kotlin's rounded product), DANDELION_EMBARGO_REARM_RED (no cap on
//  a re-armed wait) and DANDELION_EMBARGO_PENDING_RED (an embargo from an earlier process is
//  still pending).
//  Header-only, static inline, no state, no clock and no randomness of its own.
//

#ifndef BRDandelionEmbargo_h
#define BRDandelionEmbargo_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__cplusplus)
#define BR_DANDELION_STATIC_ASSERT(c, m, n) static_assert(c, m)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define BR_DANDELION_STATIC_ASSERT(c, m, n) _Static_assert(c, m)
#else
#define BR_DANDELION_STATIC_ASSERT(c, m, n) typedef char n[(c) ? 1 : -1]
#endif

// The embargo window, ms: about the network's stem-to-fluff time plus margin.
#define BR_DANDELION_EMBARGO_MIN_MS   10000LL
#define BR_DANDELION_EMBARGO_MAX_MS   30000LL
// MAX - MIN.
#define BR_DANDELION_EMBARGO_SPAN_MS  20000LL

// A draw is a uniform integer in [0, BR_DANDELION_EMBARGO_DRAW_LIMIT): 53 random bits, the bits
// Java's Random.nextDouble scales by 2^-53. 2^53, and 2^53 - 1.
#define BR_DANDELION_EMBARGO_DRAW_BITS   53
#define BR_DANDELION_EMBARGO_DRAW_LIMIT  9007199254740992ULL
#define BR_DANDELION_EMBARGO_DRAW_MAX    9007199254740991ULL

// SPAN * 2^48 / 2^53 = SPAN / 32: the product draw * 2^-53 * SPAN is (draw * 625) * 2^-48.
#define _BR_DANDELION_EMBARGO_SPAN_Q48   625ULL

BR_DANDELION_STATIC_ASSERT(BR_DANDELION_EMBARGO_SPAN_MS == BR_DANDELION_EMBARGO_MAX_MS - BR_DANDELION_EMBARGO_MIN_MS,
                           "SPAN is MAX - MIN", br_dandelion_assert_span);
BR_DANDELION_STATIC_ASSERT(BR_DANDELION_EMBARGO_DRAW_LIMIT == (1ULL << BR_DANDELION_EMBARGO_DRAW_BITS),
                           "DRAW_LIMIT is 2^DRAW_BITS", br_dandelion_assert_limit);
BR_DANDELION_STATIC_ASSERT(BR_DANDELION_EMBARGO_DRAW_MAX == BR_DANDELION_EMBARGO_DRAW_LIMIT - 1,
                           "DRAW_MAX is DRAW_LIMIT - 1", br_dandelion_assert_max);
BR_DANDELION_STATIC_ASSERT(_BR_DANDELION_EMBARGO_SPAN_Q48 * 32 == (unsigned long long)BR_DANDELION_EMBARGO_SPAN_MS,
                           "SPAN_Q48 is SPAN / 32", br_dandelion_assert_q48);
// draw * SPAN_Q48 fits 64 bits for every draw, so the product below is exact.
BR_DANDELION_STATIC_ASSERT(_BR_DANDELION_EMBARGO_SPAN_Q48 < 1024 && BR_DANDELION_EMBARGO_DRAW_BITS + 10 <= 64,
                           "draw * SPAN_Q48 fits uint64", br_dandelion_assert_fits);

// Stem (BRPeerManagerStemPublishTx) only when the user's setting is on and a Dandelion-capable
// peer is connected; otherwise flood (BRPeerManagerPublishTx). BRPeerManagerHasDandelionPeer
// already includes the manager's own copy of the setting; the platform's setting is checked too.
static inline int BRDandelionShouldStem(int enabled, int hasDandelionPeer)
{
    return enabled && hasDandelionPeer;
}

// The draw from 64 uniform random bits (the platform's CSPRNG: SecRandomCopyBytes, SecureRandom;
// any byte order): the top 53 bits. A value that is already a draw (below DRAW_LIMIT) must not
// be passed through this again. Android's SecureRandom.nextDouble() is exactly draw * 2^-53, so
// a Kotlin caller may also pass (rng01 * 2^53).toLong() for its existing draw.
static inline uint64_t BRDandelionEmbargoDraw(uint64_t random64)
{
    return random64 >> (64 - BR_DANDELION_EMBARGO_DRAW_BITS);
}

// The embargo delay, ms, for a draw. Bit-exact with DandelionBroadcastPolicy.kt's
//     EMBARGO_MIN_MS + (rng01.coerceIn(0.0, 1.0) * (EMBARGO_MAX_MS - EMBARGO_MIN_MS)).toLong()
// at rng01 = draw * 2^-53, in integers only, so it does not depend on the compiler's floating
// point. In the Kotlin, draw * 2^-53 is exact, the product with 20000.0 is the one rounding
// (to nearest, ties to even, to 53 significant bits), and toLong truncates. The exact product is
// (draw * 625) * 2^-48; it is rounded here to 53 significant bits as the double multiply rounds
// it, then truncated. The plain quotient floor(draw * 20000 / 2^53) is 1 ms short of Android
// wherever the rounding carries the product up to a whole millisecond (7434 of the draws within
// 3 of a millisecond boundary; DANDELION_EMBARGO_DELAY_RED is that quotient). Android's own test
// input 0.999 is one: 0.999 * 20000.0 rounds to 19980.0, so Android waits 29980 ms, and the
// quotient says 29979.
//
//   draw 0                -> 10000 (MIN)
//   draw 2^52             -> 20000
//   draw 2^53 - 1         -> 29999 (the largest draw: just under MAX, as Android's largest
//                                   nextDouble, 1 - 2^-53, gives 29999)
//   draw >= 2^53          -> 30000 (MAX: Android's rng01 >= 1.0, clamped to 1.0; never drawn)
//
// The result is always in [MIN, MAX].
static inline int64_t BRDandelionEmbargoDelayMs(uint64_t draw)
{
    uint64_t n;

    if (draw >= BR_DANDELION_EMBARGO_DRAW_LIMIT) return BR_DANDELION_EMBARGO_MAX_MS;
    n = draw * _BR_DANDELION_EMBARGO_SPAN_Q48;   // < 2^63
#ifndef DANDELION_EMBARGO_DELAY_RED
    if (n >= BR_DANDELION_EMBARGO_DRAW_LIMIT) {
        // Round n to 53 significant bits, to nearest, ties to even.
        unsigned s = 0;
        uint64_t rem, half;

        while ((n >> s) >= BR_DANDELION_EMBARGO_DRAW_LIMIT) s++;
        rem = n & ((1ULL << s) - 1);
        half = 1ULL << (s - 1);
        n -= rem;
        if (rem > half || (rem == half && ((n >> s) & 1))) n += 1ULL << s;   // <= 2^63: no overflow
    }
#else
    // RED ARM SEAM (dandelion_embargo_kat): the exact quotient, without the double's rounding.
#endif
    return BR_DANDELION_EMBARGO_MIN_MS + (int64_t)(n >> 48);
}

// The embargo's deadline, wall-clock ms: the time the stem returned 1, plus the delay
// (BRDandelionEmbargoDelayMs, so within the window). Saturates at INT64_MAX and INT64_MIN, so no
// input overflows.
static inline int64_t BRDandelionEmbargoDeadlineMs(int64_t stemmedAtMs, int64_t delayMs)
{
    if (delayMs > 0 && stemmedAtMs > INT64_MAX - delayMs) return INT64_MAX;
    if (delayMs < 0 && stemmedAtMs < INT64_MIN - delayMs) return INT64_MIN;
    return stemmedAtMs + delayMs;
}

// How long to wait, ms, from nowMs (wall clock) for an embargo due at deadlineMs: at arming and
// at every re-arm (iOS: on foreground, after the trip to the background suspended its timer).
// 0 when the deadline has passed or is now: run the deadline step at once. Never more than
// BR_DANDELION_EMBARGO_MAX_MS, so a clock set back cannot stretch the embargo, provided the
// platform runs the deadline step when this wait ends rather than asking again.
static inline int64_t BRDandelionEmbargoRemainingMs(int64_t nowMs, int64_t deadlineMs)
{
    uint64_t left;

    if (nowMs >= deadlineMs) return 0;
    left = (uint64_t)deadlineMs - (uint64_t)nowMs;   // > 0, exact in unsigned arithmetic
#ifndef DANDELION_EMBARGO_REARM_RED
    if (left > (uint64_t)BR_DANDELION_EMBARGO_MAX_MS) return BR_DANDELION_EMBARGO_MAX_MS;
#else
    // RED ARM SEAM (dandelion_embargo_kat): the wait is not capped.
    if (left > (uint64_t)INT64_MAX) return INT64_MAX;
#endif
    return (int64_t)left;
}

// Fluff at the deadline exactly when no peer has relayed the send back
// (BRPeerManagerRelayCount == 0): the stem peer dropped it, or it has not spread. The stem peer's
// own getdata is not counted as a relay. A platform that cannot read the count treats it as
// relayed and does not fluff (Broadcaster.kt:71); the C read itself cannot fail.
static inline int BRDandelionEmbargoShouldFluff(size_t relayCount)
{
    return relayCount == 0;
}

typedef enum {
    // Nothing to send. The embargo is over.
    BRDandelionDeadlineRelease = 0,
    // BRPeerManagerFluffTx(current manager, txHash). Then the embargo is over.
    BRDandelionDeadlineFluff = 1,
} BRDandelionDeadlineAction;

// The deadline step, against the manager that is CURRENT at the deadline, whichever manager the
// stem went to: haveManager is whether one exists, relayCount its BRPeerManagerRelayCount for the
// send (pass 0 without a manager). Without a manager nothing is sent (Android reads 0 and its
// fluff returns at once). On a manager that is not the stem's, the fluff finds no publish entry
// and sends nothing: the send is left to the stranded-send sweep (see the teardown note above).
// After either answer the platform ends the embargo, so the sweep may re-publish.
static inline BRDandelionDeadlineAction BRDandelionEmbargoAtDeadline(int haveManager, size_t relayCount)
{
    if (! haveManager) return BRDandelionDeadlineRelease;
    return BRDandelionEmbargoShouldFluff(relayCount) ? BRDandelionDeadlineFluff : BRDandelionDeadlineRelease;
}

// Whether an embargo is pending: armed by THIS process, and its deadline step not yet run.
// Pending from the moment the stem returns 1 until the deadline step has finished, including the
// time between the deadline and that step. An embargo written down by an earlier process is not
// pending, whatever its deadline: Android's are in memory and a restart has none.
static inline int BRDandelionEmbargoIsPending(int armedByThisProcess, int deadlineStepRun)
{
#ifdef DANDELION_EMBARGO_PENDING_RED
    // RED ARM SEAM (dandelion_embargo_kat): a persisted embargo outlives its process.
    (void)armedByThisProcess;
    return ! deadlineStepRun;
#else
    return armedByThisProcess && ! deadlineStepRun;
#endif
}

// Whether the stranded-send sweep may re-publish (flood) a recorded, unconfirmed send: only when
// no embargo is pending for it. Deliberately not keyed on the relay count: the count says only
// whether some peer echoed the send back, not whether this process's embargo has run, and the
// embargo is what decides a re-publish.
static inline int BRDandelionEmbargoSweepMayRepublish(int embargoPending)
{
    return ! embargoPending;
}

#ifdef __cplusplus
}
#endif

#endif // BRDandelionEmbargo_h
