//
//  BRSavedTransactions.h
//
//  The reader for the wallet's saved-transactions blob, the persistence format written
//  by BRWalletSerializeTransactions (BRWallet.h):
//
//    [4 bytes LE: transaction count]
//    repeated: [4 bytes LE txSize][4 bytes LE blockHeight][4 bytes LE timestamp][txSize bytes]
//
//  The writer has been in the core all along; the reader lived in the Android JNI bridge
//  (saved_transactions_deserialize.h), which the iOS XCFramework does not contain. A
//  persistence format with its writer in one place and its reader in another is two
//  implementations of one format, and iOS could not persist transactions at all without a
//  third. Same move as BRSavedBlocks.h. The logic is the bridge's, including its
//  2026-10-09 bounds fix: each record is checked as `txSize > len - pos`, which cannot wrap
//  (the earlier `pos + txSize > len` wrapped on a 32-bit size_t, BB-2026-10-09-harley F4).
//
//  Height and timestamp are part of the record, not decoration: a confirmed transaction
//  restored without its height reads as unconfirmed, and the balance a user sees after a
//  restart changes.
//
//  Every record is a transaction the wallet registered, and the wallet registers only signed
//  transactions, so each one is read with BRTransactionParseSigned (BRTransaction.h).
//  BRTransactionParse also accepts the wallet's internal unsigned form and decides per input
//  which it is reading: a signed input whose scriptSig also reads as a scriptPubKey
//  (OP_0 PUSH20 / PUSH32) is taken for an unsigned one, and the rest of the transaction
//  misparses -- wrong txid and outputs, or no transaction at all. The Android bridge's
//  reader moved to BRTransactionParseSigned in 4.1.2; this one must read the same bytes the
//  same way, or a relaunch restores a different wallet on iOS than on Android.
//
//  Host KAT: digibytewallet-android native/src/test/host/saved_transactions_core_kat/ (the reader);
//  scan_floor_kat (BRSavedTransactionsFloorMinima, the floor a discarded blob leaves);
//  tx_ckpt_short_restore_kat (BRSavedTransactionsDeclaredCount, BRSavedTransactionsRestoreCheck).
//  Header-only, static inline; no locking or I/O.
//

#ifndef BRSavedTransactions_h
#define BRSavedTransactions_h

#include "BRInt.h"
#include "BRTransaction.h"
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// TX-CKPT-CAP: the ONE limit on how many records a saved-transactions blob may hold. The
// writer (BRWalletSerializeTransactions) refuses to write a blob above it and both readers
// (this one and the Android bridge's saved_transactions_deserialize.h) refuse to read one,
// so the wallet never writes a checkpoint its own reader drops. Until 2026-11 only the
// readers had a limit (10,000) and the writer wrote any count: a wallet past 10,000
// transactions saved a checkpoint that loaded as nothing on the next launch.
//
// The limit bounds the record-pointer array the reader allocates before it has parsed
// anything (8 bytes a record, under 1 MB here), whatever count a corrupt blob claims; the
// records themselves are bounded by the blob, which ends the walk. It is set well above any
// wallet the SPV core can hold usably: the balance pass is quadratic in the unspent set.
//
// What happens above it (the writer emits nothing):
//  - a wallet that grows past it keeps its last checkpoint and scan ledger (the app writes
//    the ledger and "has synced" only after a checkpoint lands), and sync never reports
//    complete. Launches resume from that frozen ledger only while the saved near-tip header
//    window still reaches down to it; once the window has moved past it, the next launch
//    finds the frontier below the window (HEADER_WINDOW_MISSING) and rebuilds from the
//    birth floor, and so does every launch after it while the wallet stays above the limit;
//  - a stored checkpoint that is itself above the limit (written before the writer had one)
//    is refused by the reader, so the app records a short restore and rebuilds from the
//    birth floor; the rebuilt wallet passes the limit again, nothing replaces that
//    checkpoint, and so EVERY launch rebuilds from the birth floor.
// Funds are never hidden (the scan finds them each time); the cost is the rescan. The app
// leaves a breadcrumb in dgb_diag when the refusal starts. The Kotlin mirror
// (SavedTransactionsCheckpoint.MAX_RECORDS) is held to this value by a source gate.
#ifdef TX_CKPT_CAP_UNFIXED
// RED-gate shape only: the reader limit as it was, with no writer limit. Never defined in
// a production build.
#define BR_SAVED_TRANSACTIONS_MAX_COUNT     10000u
#else
#define BR_SAVED_TRANSACTIONS_MAX_COUNT     100000u
#endif
#define BR_SAVED_TRANSACTIONS_RECORD_HEADER 12u

// Parses a saved-transactions blob. On a sane count, allocates *outTxs and returns the
// number parsed (which may be 0). The caller owns the array -- free() it whenever it is
// non-NULL -- and each BRTransaction in it, which BRWalletNew / BRWalletOpenWithKeys take
// over when the transactions are handed to them. On a
// corrupt count (0 or above BR_SAVED_TRANSACTIONS_MAX_COUNT), a NULL or short blob, or a
// failed allocation, sets *outTxs = NULL and returns 0. A record running past the blob
// ends the walk; the records before it are kept. A record that does not parse as a signed
// transaction is skipped.
static inline size_t BRSavedTransactionsDeserialize(const uint8_t *buf, size_t len, BRTransaction ***outTxs)
{
    size_t pos = 0, loaded = 0;
    uint32_t txCount;
    BRTransaction **txs;

    *outTxs = NULL;
    if (! buf || len < 4) return 0;

    txCount = UInt32GetLE(&buf[pos]); pos += 4;
    if (txCount == 0 || txCount > BR_SAVED_TRANSACTIONS_MAX_COUNT) return 0;

    txs = (BRTransaction **)calloc(txCount, sizeof(BRTransaction *));
    if (! txs) return 0;

    for (uint32_t i = 0; i < txCount && pos + BR_SAVED_TRANSACTIONS_RECORD_HEADER <= len; i++) {
        uint32_t txSize = UInt32GetLE(&buf[pos]); pos += 4;
        uint32_t height = UInt32GetLE(&buf[pos]); pos += 4;
        uint32_t timestamp = UInt32GetLE(&buf[pos]); pos += 4;
        BRTransaction *tx;

        if (txSize > len - pos) break;   // pos <= len holds here (loop condition)
#ifdef SAVED_TRANSACTIONS_UNSIGNED_PARSE_UNFIXED
        // RED-gate shape only: the inferring parser, which misreads a signed input shaped
        // like a scriptPubKey. Never defined in a production build.
        tx = BRTransactionParse(&buf[pos], txSize);
#else
        tx = BRTransactionParseSigned(&buf[pos], txSize);
#endif
        pos += txSize;
        if (! tx) continue;
#ifdef SAVED_TRANSACTIONS_METADATA_UNFIXED
        // RED-gate shape only: a reader that restores the transaction bytes and drops
        // the height and timestamp. Never defined in a production build.
        (void)height; (void)timestamp;
#else
        tx->blockHeight = height;
        tx->timestamp = timestamp;
#endif
        txs[loaded++] = tx;
    }

    *outTxs = txs;
    return loaded;
}

// What a saved-transactions blob says about the scan floor, read from its framing only (no
// transaction is parsed): the declared count, the number of whole records, the lowest real block
// height among them and the lowest record time. A rebuild that discards the blob carries these into
// the floor record first (BRScanFloorFromDiscardedCache, BRScanFloor.h), so the rescan reaches every
// transaction the blob held. The rules are Android's HistoryRebuildOnUpgrade.summarize:
//   - a blob of 4 bytes or fewer (or NULL) is empty: declared count 0;
//   - a declared count of 0 is empty; above BR_SAVED_TRANSACTIONS_MAX_COUNT it gives no records and
//     no minima (declaredCount is reported, so the blob is not empty);
//   - the walk takes whole records while a 12-byte record header fits; a record whose size runs past
//     the end stops it, and gives nothing;
//   - the floor height comes only from records at a real height, 0 < height < TX_UNCONFIRMED;
//   - the floor time comes from records with 1 <= height <= TX_UNCONFIRMED (confirmed, or
//     unconfirmed: their time is when they were seen) and a time above 0;
//   - 0 means none for either minimum.
typedef struct {
    uint32_t declaredCount;
    size_t records;
    int64_t minConfirmedHeight;
    int64_t minRecordTime;
} BRSavedTransactionsFloor;

// The blob's floor minima. Never fails; *out is always written (out must not be NULL).
static inline void BRSavedTransactionsFloorMinima(const uint8_t *buf, size_t len, BRSavedTransactionsFloor *out)
{
    size_t pos = 4;
    uint32_t count;

    out->declaredCount = 0; out->records = 0; out->minConfirmedHeight = 0; out->minRecordTime = 0;
    if (! buf || len <= 4) return;
    count = UInt32GetLE(buf);
    out->declaredCount = count;
    if (count == 0 || count > BR_SAVED_TRANSACTIONS_MAX_COUNT) return;

    for (uint32_t i = 0; i < count && BR_SAVED_TRANSACTIONS_RECORD_HEADER <= len - pos; i++) {
        uint32_t size = UInt32GetLE(&buf[pos]);
        uint32_t height = UInt32GetLE(&buf[pos + 4]);
        uint32_t time = UInt32GetLE(&buf[pos + 8]);

        pos += BR_SAVED_TRANSACTIONS_RECORD_HEADER;
        if (size > len - pos) break;   // pos <= len holds here
        pos += size;
        out->records++;
#ifdef SAVED_TRANSACTIONS_FLOOR_SENTINEL_RED
        // RED ARM SEAM (scan_floor_kat): the unconfirmed sentinel read as a block height.
        if (height >= 1 && height <= (uint32_t)TX_UNCONFIRMED) {
#else
        if (height >= 1 && height < (uint32_t)TX_UNCONFIRMED) {
#endif
            if (out->minConfirmedHeight == 0 || height < out->minConfirmedHeight) out->minConfirmedHeight = height;
        }
        if (height >= 1 && height <= (uint32_t)TX_UNCONFIRMED && time > 0 &&
            (out->minRecordTime == 0 || time < out->minRecordTime)) out->minRecordTime = time;
    }
}

// ---- the short restore (TX-CKPT-CAP) ------------------------------------------------------------
//
// The checkpoint is a cache of the wallet's history, and the compact-filter scan resumes from a
// frontier that assumes the cache restored. So at the restore, before the wallet is built from the
// records, the count the checkpoint DECLARES is compared with what the reader loaded. A restore
// short of it is recorded, and the next sync start rebuilds the headers, filters and scan ledger
// from the wallet's birth floor instead of resuming near the tip without that history. Until
// 2026-11 the rule lived only in Android's Kotlin (SavedTransactionsCheckpoint.declaredCount,
// isShort and recordRestore; WalletManager.restoreFromDisk; CfRestorePreflight.kt's
// TRANSACTION_CHECKPOINT_SHORT), and iOS opened the short wallet and resumed near the tip.
//
// The verdict (BRSavedTransactionsRestoreCheck), Android's outcomes value for value:
//   the file is there but could not be read, or holds fewer than 4 bytes  -> SHORT_UNREADABLE,
//                                                                           record -1;
//   the file is there: the reader loaded fewer records than it declares   -> SHORT_LOADED,
//                                                                           record the declared count;
//                      otherwise (a declared count of 0 included)         -> COMPLETE;
//   no file, while "transactions checkpointed" is set with a stored
//   record count above 0 (the file was lost)                              -> SHORT_FILE_LOST,
//                                                                           record that count;
//   no file otherwise (never checkpointed, or an empty wallet's count 0)  -> COMPLETE (no checkpoint
//                                                                           is the preflight's
//                                                                           MISSING_TRANSACTION_CHECKPOINT).
//   "Loaded" is the READER's count (BRSavedTransactionsDeserialize's return; Android's
//   loadSerializedTransactions), not what the wallet then kept: a repeated, unsigned or out-of-range
//   record the wallet declines is not history the frontier assumed. With a file present the stored
//   count is not read: the file is judged by what it declares.
//
// What the platform does with it (Android's, which iOS takes as is):
//   - the stored count is the declared count of the checkpoint last written (0 for none), committed
//     with the "transactions checkpointed" flag; a platform that stores no count cannot tell a lost
//     file from an empty wallet, and must store it;
//   - a SHORT verdict is recorded (the record value) before the wallet is built, and the record is
//     STICKY: a COMPLETE verdict later never clears it (a checkpoint written from the short wallet
//     declares the short count and would hide the shortfall). Only the rebuild clears it, in the same
//     commit that clears "has synced";
//   - at the sync start a recorded short restore is a reset decided BEFORE BRCFRestorePreflight,
//     whatever else the stored state says, named BR_SAVED_TRANSACTIONS_SHORT_RESET_NAME, and carried
//     out as BRCFRestorePreflight.h's reset (window, filter headers, ledger and abandonment record
//     deleted, "has synced" cleared, the birth checkpoint stored as the scan floor);
//   - a load the platform deliberately skipped (Android: a history rebuild in progress, which reads
//     no file) is not judged at all.
//
// MACRO CONVENTION: SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED is tested by VALUE (#if), a set of bits,
// each one comparison arm of tx_ckpt_short_restore_kat; unset or =0 ships. Never defined in a
// production build.
//   1   no verdict: every restore is COMPLETE (the iOS port before 2026-11, Android 4.1.3).
//   2   a lost file is COMPLETE: only a file that is there is judged.
//   4   a lost file is short on the flag alone, the stored count not read (an empty wallet's
//       checkpoint of 0 records with no file rebuilds).
//   8   an unreadable file is COMPLETE.
//   16  the declared count read as BRSavedTransactionsFloorMinima reads it: a blob of 4 bytes or
//       fewer declares 0 (a 4-byte blob that declares records and holds none reads as complete).
#ifndef SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED
#define SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED 0
#endif
#define SAVED_TRANSACTIONS_SHORT_RED_NO_VERDICT     1
#define SAVED_TRANSACTIONS_SHORT_RED_LOST_IGNORED   2
#define SAVED_TRANSACTIONS_SHORT_RED_FLAG_ALONE     4
#define SAVED_TRANSACTIONS_SHORT_RED_UNREADABLE_OK  8
#define SAVED_TRANSACTIONS_SHORT_RED_FLOOR_COUNT    16

// The declared count of a checkpoint whose count cannot be read (Kotlin: UNREADABLE).
#define BR_SAVED_TRANSACTIONS_UNREADABLE (-1)

// The name a platform records for the sync-start reset (Android's CfRestoreResetReason).
#define BR_SAVED_TRANSACTIONS_SHORT_RESET_NAME "TRANSACTION_CHECKPOINT_SHORT"

typedef enum {
    BR_SAVED_TX_RESTORE_COMPLETE = 0,           // resume as BRCFRestorePreflight decides
    BR_SAVED_TX_RESTORE_SHORT_LOADED = 1,       // the reader loaded fewer records than the file declares
    BR_SAVED_TX_RESTORE_SHORT_UNREADABLE = 2,   // the file is there and its count cannot be read
    BR_SAVED_TX_RESTORE_SHORT_FILE_LOST = 3      // no file, after a checkpoint of records landed
} BRSavedTransactionsRestore;

// The record count a stored checkpoint declares, its leading u32 little-endian (Kotlin:
// SavedTransactionsCheckpoint.declaredCount): 0 to 4,294,967,295, or BR_SAVED_TRANSACTIONS_UNREADABLE
// when it holds fewer than 4 bytes (NULL too). Unlike BRSavedTransactionsFloorMinima's declaredCount,
// a blob of exactly 4 bytes declares its count.
static inline int64_t BRSavedTransactionsDeclaredCount(const uint8_t *buf, size_t len)
{
#if (SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED & SAVED_TRANSACTIONS_SHORT_RED_FLOOR_COUNT)
    // RED ARM SEAM (tx_ckpt_short_restore_kat): BRSavedTransactionsFloorMinima's reading.
    if (! buf || len < 4) return BR_SAVED_TRANSACTIONS_UNREADABLE;
    if (len == 4) return 0;
#else
    if (! buf || len < 4) return BR_SAVED_TRANSACTIONS_UNREADABLE;
#endif
    return (int64_t)UInt32GetLE(buf);
}

// Whether a restore is short (see the banner). fileExists: a checkpoint file is there. fileRead: its
// bytes were read (read only when fileExists). declaredCount: BRSavedTransactionsDeclaredCount of those
// bytes (read only when the file was read). readerLoaded: what BRSavedTransactionsDeserialize returned
// for them (0 when it was not called). checkpointed: the stored "transactions checkpointed" flag.
// checkpointedCount: the record count stored beside it (read only when the flag is set; 0 or less is
// none). On a SHORT verdict *recordOut (when not NULL) is set to the value to record: the declared or
// stored count, or BR_SAVED_TRANSACTIONS_UNREADABLE; on COMPLETE it is left as it was.
static inline BRSavedTransactionsRestore BRSavedTransactionsRestoreCheck(int fileExists, int fileRead,
                                                                         int64_t declaredCount, uint64_t readerLoaded,
                                                                         int checkpointed, int64_t checkpointedCount,
                                                                         int64_t *recordOut)
{
    BRSavedTransactionsRestore verdict = BR_SAVED_TX_RESTORE_COMPLETE;
    int64_t record = 0;

    if (! fileExists) {
        int64_t stored = checkpointed ? checkpointedCount : 0;
#if (SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED & SAVED_TRANSACTIONS_SHORT_RED_FLAG_ALONE)
        // RED ARM SEAM (tx_ckpt_short_restore_kat): the flag alone.
        if (checkpointed) { verdict = BR_SAVED_TX_RESTORE_SHORT_FILE_LOST; record = stored; }
#else
        if (stored > 0) { verdict = BR_SAVED_TX_RESTORE_SHORT_FILE_LOST; record = stored; }
#endif
#if (SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED & SAVED_TRANSACTIONS_SHORT_RED_LOST_IGNORED)
        // RED ARM SEAM (tx_ckpt_short_restore_kat): only a file that is there is judged.
        verdict = BR_SAVED_TX_RESTORE_COMPLETE;
#endif
    }
    else if (! fileRead || declaredCount < 0) {
#if ! (SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED & SAVED_TRANSACTIONS_SHORT_RED_UNREADABLE_OK)
        verdict = BR_SAVED_TX_RESTORE_SHORT_UNREADABLE;
        record = BR_SAVED_TRANSACTIONS_UNREADABLE;
#endif
    }
    else if (readerLoaded < (uint64_t)declaredCount) {
        verdict = BR_SAVED_TX_RESTORE_SHORT_LOADED;
        record = declaredCount;
    }
#if (SAVED_TRANSACTIONS_SHORT_RESTORE_UNFIXED & SAVED_TRANSACTIONS_SHORT_RED_NO_VERDICT)
    // RED ARM SEAM (tx_ckpt_short_restore_kat): no verdict at all.
    verdict = BR_SAVED_TX_RESTORE_COMPLETE;
#endif
    if (verdict != BR_SAVED_TX_RESTORE_COMPLETE && recordOut) *recordOut = record;
    return verdict;
}

// The verdict's name in logs ("" for COMPLETE).
static inline const char *BRSavedTransactionsRestoreName(BRSavedTransactionsRestore verdict)
{
    switch (verdict) {
        case BR_SAVED_TX_RESTORE_SHORT_LOADED:     return "SHORT_LOADED";
        case BR_SAVED_TX_RESTORE_SHORT_UNREADABLE: return "SHORT_UNREADABLE";
        case BR_SAVED_TX_RESTORE_SHORT_FILE_LOST:  return "SHORT_FILE_LOST";
        default:                                   return "";
    }
}

#ifdef __cplusplus
}
#endif

#endif // BRSavedTransactions_h
