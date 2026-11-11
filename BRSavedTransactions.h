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
//  Host KAT: digibytewallet-android native/src/test/host/saved_transactions_core_kat/.
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

#ifdef __cplusplus
}
#endif

#endif // BRSavedTransactions_h
