//
//  BRRecoveryDate.h
//
//  When a wallet is restored, the person says roughly when it was created, and that decides
//  where the scan starts: a floor too late hides every earlier transaction. So the dates offered
//  and the floor each one gives must be the same on both platforms. Until 2026-10 the table lived
//  in Android's UI (RecoveryDateScreen.recoveryDateOptions) and the floor rule was copied into
//  Android's bridge (jni_peer.c getWalletBirthCheckpointHeight) and BRPeerManagerNewEx.
//
//  The dates: one per year from 2014 to BR_RECOVERY_LAST_YEAR, each January 1 00:00 UTC, except
//  2014, which is the genesis block's time (DigiByte launched 2014-01-10); "I don't remember" is
//  also the genesis time (a full scan). The floor: the latest compiled checkpoint whose time is
//  at least a week before the creation time (the first checkpoint always qualifies), the same
//  anchor BRPeerManagerNewEx takes from earliestKeyTime, so a week of clock and history slack
//  sits below the floor.
//
//  Extend BR_RECOVERY_LAST_YEAR each January, for both platforms at once.
//
//  Host KAT: digibytewallet-android native/src/test/host/recovery_date_kat/.
//  Header-only, static inline.
//

#ifndef BRRecoveryDate_h
#define BRRecoveryDate_h

#include "BRChainParams.h"   // BRCheckPoint
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_RECOVERY_GENESIS_TIMESTAMP 1389388394u   // the genesis block, 2014-01-10
#define BR_RECOVERY_FIRST_YEAR        2014
#define BR_RECOVERY_LAST_YEAR         2026
#define BR_RECOVERY_FLOOR_MARGIN      604800u       // a week, in seconds

// January 1 00:00 UTC of year (proleptic Gregorian; days-from-civil), for 1970 <= year <= 2105.
static inline uint32_t _BRRecoveryJan1(int year)
{
    int64_t y = (int64_t)year - 1;   // March-based year of the previous December
    int64_t era = y / 400, yoe = y - era * 400;
    int64_t doy = 306;               // Jan 1 is day 306 of a March-based year
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    return (uint32_t)(days * 86400);
}

// The creation time offered for year (2014 is the genesis time). 0 outside the table.
static inline uint32_t BRRecoveryDateTimestamp(int year)
{
    if (year < BR_RECOVERY_FIRST_YEAR || year > BR_RECOVERY_LAST_YEAR) return 0;
    return year == BR_RECOVERY_FIRST_YEAR ? BR_RECOVERY_GENESIS_TIMESTAMP : _BRRecoveryJan1(year);
}

// The height a restore created at creationTime scans from.
static inline uint32_t BRRecoveryBirthCheckpointHeight(const BRCheckPoint *checkpoints, size_t count, uint32_t creationTime)
{
    uint32_t height = 0;
    for (size_t i = 0; checkpoints && i < count; i++) {
#ifdef RECOVERY_DATE_RED
        // RED ARM SEAM (recovery_date_kat): no margin, so the floor can sit at the creation time.
        if (i == 0 || checkpoints[i].timestamp < creationTime) height = checkpoints[i].height;
#else
        if (i == 0 || (uint64_t)checkpoints[i].timestamp + BR_RECOVERY_FLOOR_MARGIN < creationTime) height = checkpoints[i].height;
#endif
    }
    return height;
}

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryDate_h
