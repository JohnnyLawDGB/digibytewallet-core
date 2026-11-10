//
//  BRCoinReservation.h
//
//  A coin signed for one send is never signed into another before the first is published. Moved from the Android JNI
//  bridge (bridge/coin_reservation.{c,h}), unchanged, so every signer on every platform shares one reservation.
//
//  The wallet marks a send's coins spent when the transaction is registered at publish. Between the signature and that
//  registration nothing else holds them, so the signer claims a signed transaction's inputs for its txid and refuses a
//  transaction one of whose inputs another txid holds. The publish releases the claim once the wallet's record holds
//  the coins as spent. A claim whose transaction is never published lapses after BR_COIN_RESERVATION_TTL_S.
//
//  The rules, exactly as the bridge applies them:
//    - one process-wide table of at most BR_COIN_RESERVATION_MAX outpoints, each held by one owner (a txid), guarded by
//      one pthread mutex: every call below takes it for its whole duration;
//    - a claim first drops every entry whose expiry is not after `now` (expires > now survives; expires == now lapses);
//    - it is refused, taking nothing, when any input is held by another owner, or when the entries held plus the
//      inputs not yet held (counted per input, so an outpoint listed twice and not yet held counts twice) would exceed
//      BR_COIN_RESERVATION_MAX;
//    - granted, every input is taken for the owner or, held by it already, renewed: its expiry becomes
//      now + BR_COIN_RESERVATION_TTL_S;
//    - inputs == NULL with inCount > 0 is refused without touching the table; inCount == 0 is granted;
//    - release drops every entry the owner holds (an owner holding nothing: no change); clear drops every entry.
//
//  THE CLOCK. The core reads none: `now` is the caller's, in seconds. The rules for it:
//    - it is non-decreasing from call to call, and never wall time (a wall clock can be set by the user or by the
//      network);
//    - every caller sharing the table, in every thread, takes it from the same clock;
//    - a forward jump lapses claims early, before their sends are published, which reopens the window in which a
//      second send is signed on the same coins;
//    - a backward step keeps the claims already held longer (their expiries stay where they were), which is safe; a
//      claim made or renewed after the step expires TTL after the stepped `now`;
//    - a NaN `now` drops the whole table (no expiry compares after NaN) and the claim it makes is granted; its own
//      entries then lapse at the next claim made with any `now`.
//  The Android bridge passes clock_gettime(CLOCK_MONOTONIC), which on Linux does not advance while the device is
//  suspended. On Darwin, CLOCK_MONOTONIC keeps advancing while the device sleeps, so the same call on iOS would lapse
//  every claim across a sleep of TTL or longer where Android keeps it. An iOS caller that matches Android uses
//  clock_gettime(CLOCK_UPTIME_RAW) (Darwin, clock_gettime(3): monotonic, does not advance while the system is asleep,
//  equal to mach_absolute_time converted), and every iOS caller uses that one.
//
//  Host KAT: digibytewallet-android native/src/test/host/coin_reservation_core_kat/ (runs the bridge's files and these
//  side by side and requires the same answers).
//  Comparison arms for that KAT only, read in BRCoinReservation.c: BR_COIN_RESERVATION_UNFIXED (every claim granted),
//  BR_COIN_RESERVATION_RED_TTL_INCLUSIVE (an entry survives at expires == now), BR_COIN_RESERVATION_RED_CAP_OFF_BY_ONE
//  (a claim reaching exactly the bound is refused), BR_COIN_RESERVATION_RED_NO_LOCK (the mutex is not taken).
//

#ifndef BRCoinReservation_h
#define BRCoinReservation_h

#include "BRTransaction.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Seconds a claim lasts when its transaction is never published.
#define BR_COIN_RESERVATION_TTL_S 60.0
// Outpoints held at once; a claim that would not fit is refused (the send is not signed).
#define BR_COIN_RESERVATION_MAX 512

// Claims inputs[0..inCount) for owner at time now (seconds on the caller's one monotonic, non-decreasing clock; see THE
// CLOCK above). 1: granted (a claim the owner already holds is renewed); 0: refused -- one of them is held by another
// owner, or the table is full. A refused claim takes nothing.
int BRCoinReservationClaim(UInt256 owner, const BRTxInput *inputs, size_t inCount, double now);

// Releases every outpoint owner holds.
void BRCoinReservationRelease(UInt256 owner);

// Drops every claim (a test, or a wallet torn down).
void BRCoinReservationClear(void);

#ifdef __cplusplus
}
#endif

#endif // BRCoinReservation_h
