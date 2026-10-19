//
//  BRCFRestorePreflight.h
//
//  What a cold start does with the chain state the last session left: resume from it, or rebuild
//  the header window and the filter scan from the wallet's birth. A wallet that resumes from state
//  it cannot trust shows a balance that is silently short (a height it never scans is a payment
//  it never sees), and two wallets on one seed that decide this differently disagree about which
//  heights they have looked at. Until 2026-10 the rule lived in Kotlin (CfRestorePreflight.kt:
//  cfRestoreResetReason, its two blob readers, and compactFilterBirthHeight), and iOS resumed
//  where Android rebuilt.
//
//  The decision (BRCFRestorePreflight), in this order:
//    synced, but no transaction checkpoint was ever written     -> MISSING_TRANSACTION_CHECKPOINT
//    no ledger: synced with a saved header window               -> MISSING_LEDGER
//               otherwise                                       -> resume (nothing was scanned)
//    a ledger this check cannot read                            -> INVALID_LEDGER
//    a ledger with no saved header window                       -> HEADER_WINDOW_MISSING
//    a saved header window this check cannot read               -> INVALID_SAVED_BLOCKS
//    the lowest height the scan still needs, max(scanned + 1, abandoned below), under the
//    window's lowest block                                      -> HEADER_WINDOW_MISSING
//    otherwise                                                  -> resume
//  "No ledger" and "no window" mean no stored copy at all (none written, or the read failed). An
//  empty stored copy is present, and unreadable.
//
//  The readers check structure only and read no block. They are stricter than the parsers that
//  load the same blobs: BRCFScanLedgerParse accepts a ledger whose frontier is inconsistent (scanned
//  + 1 below its start, or requested below scanned), and BRSavedBlocksDeserialize reads a truncated
//  window short, where this calls both unreadable. Everything this reads as valid, those parsers
//  load in full; BRCFScanLedger.c checks at compile time that the format numbers below are its own.
//
//  On a reset the platform deletes the saved header window, the filter-header chain, the ledger
//  and the abandonment record, clears "has synced", and stores the wallet's birth checkpoint as
//  the scan floor (removing the floor when that is 0, the genesis anchor). Wallet keys and known
//  transactions are kept. Committing "has synced" later removes the floor again.
//
//  The arming height (BRCFRestoreArmHeight), the height the platform arms the filter fetch at
//  (BRPeerManagerEnableAutoCompactFilterFetch) before restoring the ledger: 100 below the saved
//  window's tip when there is one, else the wallet's birth checkpoint; a wallet that has not yet
//  synced takes its stored floor first. A synced wallet ignores the floor: a stale deep floor
//  would ask the resume snap to account for history it has already scanned.
//
//  Host KAT: digibytewallet-android native/src/test/host/cf_restore_preflight_kat/
//  (CfRestorePreflightTest case for case, and a line-for-line model of the Kotlin compared
//  against this header). Vectors: vectors/cf-restore-preflight/, this header's answers on a fixed
//  corpus, which Android's host-JVM CfRestorePreflightVectorsTest holds its Kotlin to; a change to
//  the rule regenerates them (the KAT fails until it does). Header-only, static inline.
//

#ifndef BRCFRestorePreflight_h
#define BRCFRestorePreflight_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_CF_RESTORE_LEDGER_MAGIC          0x43464C31u   // "CFL1"
#define BR_CF_RESTORE_LEDGER_VERSION_MAX    3u            // the newest ledger version read; newer is unreadable
#define BR_CF_RESTORE_LEDGER_ENTRIES_MAX    4096u         // outstanding holes, and parked holes, each
#define BR_CF_RESTORE_SAVED_BLOCKS_MAX      100000u       // blocks in a saved header window
#define BR_CF_RESTORE_RESUME_MARGIN         100           // a resume arms this far below the saved tip

typedef enum {
    BR_CF_RESTORE_RESUME = 0,
    BR_CF_RESTORE_MISSING_LEDGER,
    BR_CF_RESTORE_MISSING_TRANSACTION_CHECKPOINT,
    BR_CF_RESTORE_INVALID_LEDGER,
    BR_CF_RESTORE_INVALID_SAVED_BLOCKS,
    BR_CF_RESTORE_HEADER_WINDOW_MISSING,
} BRCFRestoreReset;

// The name each platform records for a reset (Android's CfRestoreResetReason names); "" to resume.
static inline const char *BRCFRestoreResetName(BRCFRestoreReset reset)
{
    switch (reset) {
        case BR_CF_RESTORE_MISSING_LEDGER:                  return "MISSING_LEDGER";
        case BR_CF_RESTORE_MISSING_TRANSACTION_CHECKPOINT:  return "MISSING_TRANSACTION_CHECKPOINT";
        case BR_CF_RESTORE_INVALID_LEDGER:                  return "INVALID_LEDGER";
        case BR_CF_RESTORE_INVALID_SAVED_BLOCKS:            return "INVALID_SAVED_BLOCKS";
        case BR_CF_RESTORE_HEADER_WINDOW_MISSING:           return "HEADER_WINDOW_MISSING";
        default:                                            return "";
    }
}

static inline uint32_t _BRCFRestoreU32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// A scan ledger blob (BRCFScanLedgerSerialize, versions 1 to 3): 1 and its frontier when its
// structure is whole, else 0.
//   [magic][version][start][scannedThrough][requestedThrough][abandonedBelow, v2+]
//   [outstanding count][count x (4 + 1, or 4 + 2 from v3)][parked count][count x (4, or 4 + 2 from v3)]
// Bytes after the parked entries are ignored.
static inline int BRCFRestoreLedgerFrontier(const uint8_t *b, size_t len,
                                            uint32_t *scannedThrough, uint32_t *abandonedBelow)
{
    uint32_t version, start, scanned, requested, abandoned = 0, outCount, parkedCount;
    uint64_t header, parkedAt, need;

    if (len < 24 || ! b || _BRCFRestoreU32(b) != BR_CF_RESTORE_LEDGER_MAGIC) return 0;
    version = _BRCFRestoreU32(b + 4);
    if (version < 1 || version > BR_CF_RESTORE_LEDGER_VERSION_MAX) return 0;
    start     = _BRCFRestoreU32(b + 8);
    scanned   = _BRCFRestoreU32(b + 12);
    requested = _BRCFRestoreU32(b + 16);
    if (version >= 2) {
        if (len < 28) return 0;
        abandoned = _BRCFRestoreU32(b + 20);
    }
#ifndef CF_RESTORE_FRONTIER_RED
    // RED ARM SEAM (cf_restore_preflight_kat): without this, the ledger BRCFScanLedgerParse accepts.
    if ((uint64_t)scanned + 1 < start || requested < scanned) return 0;
#else
    (void)start; (void)requested;
#endif
    header   = version >= 2 ? 28 : 24;
    outCount = _BRCFRestoreU32(b + (version >= 2 ? 24 : 20));
    if (outCount > BR_CF_RESTORE_LEDGER_ENTRIES_MAX) return 0;
    parkedAt = header + (uint64_t)outCount * (version >= 3 ? 6 : 5);
    if (parkedAt + 4 > len) return 0;
    parkedCount = _BRCFRestoreU32(b + parkedAt);
    if (parkedCount > BR_CF_RESTORE_LEDGER_ENTRIES_MAX) return 0;
    need = parkedAt + 4 + (uint64_t)parkedCount * (version >= 3 ? 6 : 4);
    if (need > len) return 0;

    if (scannedThrough) *scannedThrough = scanned;
    if (abandonedBelow) *abandonedBelow = abandoned;
    return 1;
}

// A saved header window blob (the saveBlocks callback's buffer, BRSavedBlocksDeserialize's input):
// 1 and the lowest block height in it when its structure is whole, else 0.
//   [count, 1 to BR_CF_RESTORE_SAVED_BLOCKS_MAX][count x ([blockLen][height][blockLen bytes])]
// Every entry must be complete (a truncated window is unreadable); bytes after the last are ignored.
static inline int BRCFRestoreSavedBlocksFloor(const uint8_t *b, size_t len, uint32_t *floorHeight)
{
    uint32_t count, i, lowest = UINT32_MAX;
    size_t off = 4;

    if (len < 4 || ! b) return 0;
    count = _BRCFRestoreU32(b);
    if (count < 1 || count > BR_CF_RESTORE_SAVED_BLOCKS_MAX) return 0;
    for (i = 0; i < count; i++) {
        uint32_t blockLen, height;

        if (len - off < 8) break;                        // off <= len holds throughout
        blockLen = _BRCFRestoreU32(b + off);
        height   = _BRCFRestoreU32(b + off + 4);
        if (blockLen > INT32_MAX || blockLen > len - off - 8) break;
        if (height < lowest) lowest = height;
        off += 8 + (size_t)blockLen;
    }
#ifndef CF_RESTORE_TRUNCATION_RED
    // RED ARM SEAM (cf_restore_preflight_kat): without this, a truncated window reads short, as
    // BRSavedBlocksDeserialize reads it.
    if (i < count) return 0;
#endif
    if (floorHeight) *floorHeight = lowest;
    return 1;
}

// The cold-start decision. A blob is absent when has* is 0 (b is then ignored); present with
// len 0 is an empty stored copy. wasSynced is the stored "has synced"; hasTransactionCheckpoint is
// whether a transaction checkpoint was ever written (on Android, transactions_checkpointed or a
// saved_transactions entry).
static inline BRCFRestoreReset BRCFRestorePreflight(const uint8_t *ledger, size_t ledgerLen, int hasLedger,
                                                    const uint8_t *savedBlocks, size_t savedBlocksLen,
                                                    int hasSavedBlocks, int wasSynced,
                                                    int hasTransactionCheckpoint)
{
    uint32_t scanned = 0, abandoned = 0, floorHeight = 0;
    uint64_t lowestNeeded;

#ifdef CF_RESTORE_PREFLIGHT_RED
    // RED ARM SEAM (cf_restore_preflight_kat): no preflight, the iOS port before 2026-10-19.
    (void)ledger; (void)ledgerLen; (void)hasLedger; (void)savedBlocks; (void)savedBlocksLen;
    (void)hasSavedBlocks; (void)wasSynced; (void)hasTransactionCheckpoint;
    (void)scanned; (void)abandoned; (void)floorHeight; (void)lowestNeeded;
    return BR_CF_RESTORE_RESUME;
#else
    if (wasSynced && ! hasTransactionCheckpoint) return BR_CF_RESTORE_MISSING_TRANSACTION_CHECKPOINT;
    if (! hasLedger) return (wasSynced && hasSavedBlocks) ? BR_CF_RESTORE_MISSING_LEDGER : BR_CF_RESTORE_RESUME;
    if (! BRCFRestoreLedgerFrontier(ledger, ledgerLen, &scanned, &abandoned)) return BR_CF_RESTORE_INVALID_LEDGER;
    if (! hasSavedBlocks) return BR_CF_RESTORE_HEADER_WINDOW_MISSING;
    if (! BRCFRestoreSavedBlocksFloor(savedBlocks, savedBlocksLen, &floorHeight)) return BR_CF_RESTORE_INVALID_SAVED_BLOCKS;
    lowestNeeded = (uint64_t)scanned + 1;
    if (abandoned > lowestNeeded) lowestNeeded = abandoned;
    return lowestNeeded < floorHeight ? BR_CF_RESTORE_HEADER_WINDOW_MISSING : BR_CF_RESTORE_RESUME;
#endif
}

// The height to arm the filter fetch at (see the banner). savedTip is the highest height in the
// saved window as loaded (0 when none); walletBirth the wallet's birth checkpoint
// (BRRecoveryBirthCheckpointHeight over the wallet's creation time, 0 when there is no wallet);
// persistedBirth the stored scan floor, read only when hasPersistedBirth.
static inline int64_t BRCFRestoreArmHeight(int wasSynced, int64_t savedTip, int64_t walletBirth,
                                           int hasPersistedBirth, int64_t persistedBirth)
{
    int64_t resume = savedTip > 0
        ? (savedTip - BR_CF_RESTORE_RESUME_MARGIN > 0 ? savedTip - BR_CF_RESTORE_RESUME_MARGIN : 0)
        : walletBirth;
#ifdef CF_RESTORE_ARM_RED
    // RED ARM SEAM (cf_restore_preflight_kat): the stored floor wins even after sync (the iOS port
    // before 2026-10-19).
    (void)wasSynced;
    return hasPersistedBirth ? persistedBirth : resume;
#else
    return (wasSynced || ! hasPersistedBirth) ? resume : persistedBirth;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRCFRestorePreflight_h
