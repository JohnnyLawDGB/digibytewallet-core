//
//  BRCoinReservation.c
//
//  See BRCoinReservation.h. Moved from the Android JNI bridge (bridge/coin_reservation.c) without a change of rule; the
//  bridge's clock (coin_reservation_now) stays with the caller.
//

#include "BRCoinReservation.h"

#include <pthread.h>

#ifndef BR_COIN_RESERVATION_UNFIXED
#define BR_COIN_RESERVATION_UNFIXED 0
#endif

#ifdef BR_COIN_RESERVATION_RED_NO_LOCK
#define _lock()   ((void)0)
#define _unlock() ((void)0)
#else
#define _lock()   pthread_mutex_lock(&_claimLock)
#define _unlock() pthread_mutex_unlock(&_claimLock)
#endif

typedef struct {
    UInt256 owner;     // the txid that holds it
    UInt256 hash;      // the outpoint
    uint32_t n;
    double expires;
} _BRCoinClaim;

static _BRCoinClaim _claims[BR_COIN_RESERVATION_MAX];
static size_t _claimCount = 0;
static pthread_mutex_t _claimLock = PTHREAD_MUTEX_INITIALIZER;

// Caller holds _claimLock.
static void _dropExpired(double now)
{
    size_t j = 0;

    for (size_t i = 0; i < _claimCount; i++) {
#ifdef BR_COIN_RESERVATION_RED_TTL_INCLUSIVE
        if (_claims[i].expires >= now) _claims[j++] = _claims[i];
#else
        if (_claims[i].expires > now) _claims[j++] = _claims[i];
#endif
    }

    _claimCount = j;
}

// Caller holds _claimLock. The index of the claim on (hash, n), or -1.
static long _find(UInt256 hash, uint32_t n)
{
    for (size_t i = 0; i < _claimCount; i++) {
        if (_claims[i].n == n && UInt256Eq(_claims[i].hash, hash)) return (long)i;
    }

    return -1;
}

int BRCoinReservationClaim(UInt256 owner, const BRTxInput *inputs, size_t inCount, double now)
{
#if BR_COIN_RESERVATION_UNFIXED
    (void)owner; (void)inputs; (void)inCount; (void)now;
    return 1;
#else
    int granted = 1;
    size_t fresh = 0;

    if (! inputs && inCount > 0) return 0;
    _lock();
    _dropExpired(now);

    // First pass: refuse before taking anything.
    for (size_t i = 0; i < inCount && granted; i++) {
        long at = _find(inputs[i].txHash, inputs[i].index);

        if (at >= 0 && ! UInt256Eq(_claims[at].owner, owner)) granted = 0;
        else if (at < 0) fresh++;
    }

#ifdef BR_COIN_RESERVATION_RED_CAP_OFF_BY_ONE
    if (granted && _claimCount + fresh >= BR_COIN_RESERVATION_MAX) granted = 0;
#else
    if (granted && _claimCount + fresh > BR_COIN_RESERVATION_MAX) granted = 0;
#endif

    // Second pass: take or renew. Duplicate inputs in one transaction find their own claim.
    for (size_t i = 0; i < inCount && granted; i++) {
        long at = _find(inputs[i].txHash, inputs[i].index);

        if (at < 0) {
            at = (long)_claimCount++;
            _claims[at].owner = owner;
            _claims[at].hash = inputs[i].txHash;
            _claims[at].n = inputs[i].index;
        }

        _claims[at].expires = now + BR_COIN_RESERVATION_TTL_S;
    }

    _unlock();
    return granted;
#endif
}

void BRCoinReservationRelease(UInt256 owner)
{
    size_t j = 0;

    _lock();

    for (size_t i = 0; i < _claimCount; i++) {
        if (! UInt256Eq(_claims[i].owner, owner)) _claims[j++] = _claims[i];
    }

    _claimCount = j;
    _unlock();
}

void BRCoinReservationClear(void)
{
    _lock();
    _claimCount = 0;
    _unlock();
}
