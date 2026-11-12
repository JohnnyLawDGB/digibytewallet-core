//
//  BRServerTxImport.h
//
//  Importing a transaction a server reported, and confirming a pending wallet transaction at a height a server
//  reported. Moved from the Android JNI bridge (jni_transaction.c: registerRawTransaction, confirmTransaction,
//  _applyServerHeight and the unprovable-height accumulator behind takeUnprovableServerHeight), unchanged, so every
//  platform runs the same procedure. The bridge's JNI handling (byte arrays, the txid string, PEER_GUARD, logging)
//  stays on the platform side; everything that changes the wallet is here.
//
//  BRServerTxImport(wallet, manager, bytes, height, timestamp, note):
//    1. no wallet, or no bytes                       -> BR_SERVER_TX_NO_INPUT
//    2. BRTransactionParseSigned fails               -> BR_SERVER_TX_PARSE_FAILED
//    3. the parsed tx is not signed                  -> BR_SERVER_TX_UNSIGNED
//    4. the wallet already has a record of the hash (BRWalletCopyTransactionForHash):
//         at a height                                -> BR_SERVER_TX_ALREADY_CONFIRMED, nothing changes
//         pending: the server height is applied (step 6) to the record
//                  BR_SERVER_HEIGHT_TAKEN            -> BR_SERVER_TX_PROMOTED
//                  any other answer                  -> BR_SERVER_TX_ALREADY_PENDING (an UNPROVABLE answer is noted;
//                                                       the record stays as it is)
//    5. otherwise the tx is registered pending (blockHeight TX_UNCONFIRMED, timestamp 0) with
//       BRWalletRegisterTransactionUnproven. Refused -> BR_SERVER_TX_NOT_WALLET; the tx is freed unless the wallet's
//       record of the hash is now this very object (an unconfirmed non-wallet tx the wallet keeps).
//    6. the server height is applied (BRServerTxApplyHeight). BR_SERVER_HEIGHT_UNPROVABLE -> the tx is removed again
//       (BRWalletRemoveTransaction) -> BR_SERVER_TX_NOT_KEPT_UNPROVABLE. Any other answer -> BR_SERVER_TX_IMPORTED.
//  The platform's "added" boolean (the bridge's return value) is BRServerTxImportAdded(result).
//
//  BRServerTxApplyHeight: a height <= 0 or >= TX_UNCONFIRMED, or no manager, is BR_SERVER_HEIGHT_REFUSED without
//  calling BRPeerManagerApplyServerHeight; otherwise its answer, and an UNPROVABLE answer notes the height.
//
//  BRServerTxConfirm(wallet, manager, txHash, height, timestamp, note): 1 only when the wallet has a pending record of
//  txHash and the applied height's answer is BR_SERVER_HEIGHT_TAKEN. The height range is checked before the wallet is
//  read.
//
//  BRServerTxUnprovableNote: caller-owned, zero-initialised. Keeps the LOWEST height noted since the last
//  BRServerTxUnprovableNoteTake, which returns it (0 = none) and resets it to 0. Atomic, relaxed, like the bridge's
//  static it replaces; one note per wallet session (the bridge kept one per process).
//
//  The caller keeps wallet and manager alive for the whole call (Android: PEER_GUARD).
//  Host KAT: digibytewallet-android native/src/test/host/server_tx_import_kat/ (runs the bridge's functions and these
//  side by side and requires the same answers and the same wallet afterwards).
//  Header-only, static inline; no locking or I/O of its own.
//

#ifndef BRServerTxImport_h
#define BRServerTxImport_h

#include "BRPeerManager.h"
#include "BRTransaction.h"
#include "BRWallet.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t height;   // 0 = none; read and written only through the functions below
} BRServerTxUnprovableNote;

static inline void BRServerTxUnprovableNoteAdd(BRServerTxUnprovableNote *note, uint32_t height)
{
    if (! note) return;
    uint32_t cur = __atomic_load_n(&note->height, __ATOMIC_RELAXED);
    while ((cur == 0 || height < cur) &&
           ! __atomic_compare_exchange_n(&note->height, &cur, height, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}

static inline uint32_t BRServerTxUnprovableNoteTake(BRServerTxUnprovableNote *note)
{
    return note ? __atomic_exchange_n(&note->height, 0, __ATOMIC_RELAXED) : 0;
}

// What a call did with the server height, for the platform's log: applied is 0 when BRPeerManagerApplyServerHeight
// was not called (no manager, height out of range, or no step reached it), and result is then BR_SERVER_HEIGHT_REFUSED.
typedef struct {
    int applied;
    BRServerHeightResult result;
} BRServerTxHeightLog;

static inline BRServerHeightResult BRServerTxApplyHeight(BRPeerManager *manager, UInt256 txHash, int64_t blockHeight,
                                                         int64_t blockTimestamp, BRServerTxUnprovableNote *note,
                                                         BRServerTxHeightLog *log)
{
    if (! manager || blockHeight <= 0 || blockHeight >= (int64_t)TX_UNCONFIRMED) return BR_SERVER_HEIGHT_REFUSED;
    BRServerHeightResult r = BRPeerManagerApplyServerHeight(manager, txHash, (uint32_t)blockHeight,
                                                            (uint32_t)blockTimestamp);
    if (log) { log->applied = 1; log->result = r; }
    if (r == BR_SERVER_HEIGHT_UNPROVABLE) BRServerTxUnprovableNoteAdd(note, (uint32_t)blockHeight);
    return r;
}

typedef enum {
    BR_SERVER_TX_NO_INPUT = 0,           // no wallet, or no bytes
    BR_SERVER_TX_PARSE_FAILED = 1,       // BRTransactionParseSigned refused the bytes
    BR_SERVER_TX_UNSIGNED = 2,           // parsed, but not signed
    BR_SERVER_TX_ALREADY_CONFIRMED = 3,  // the wallet has a record of it at a height: nothing changed
    BR_SERVER_TX_ALREADY_PENDING = 4,    // the wallet has a pending record; the height was applied and not taken
    BR_SERVER_TX_PROMOTED = 5,           // the wallet had a pending record; the height was taken
    BR_SERVER_TX_NOT_WALLET = 6,         // BRWalletRegisterTransactionUnproven refused it
    BR_SERVER_TX_NOT_KEPT_UNPROVABLE = 7,// registered, then removed: the height's answer was UNPROVABLE (noted)
    BR_SERVER_TX_IMPORTED = 8,           // registered pending, and kept
} BRServerTxImportResult;

// The bridge's boolean answer for a result.
static inline int BRServerTxImportAdded(BRServerTxImportResult r)
{
    return r == BR_SERVER_TX_IMPORTED || r == BR_SERVER_TX_PROMOTED;
}

static inline BRServerTxImportResult BRServerTxImport(BRWallet *wallet, BRPeerManager *manager, const uint8_t *buf,
                                                      size_t len, int64_t blockHeight, int64_t blockTimestamp,
                                                      BRServerTxUnprovableNote *note, BRServerTxHeightLog *log)
{
    if (log) { log->applied = 0; log->result = BR_SERVER_HEIGHT_REFUSED; }
    if (! wallet || ! buf || len == 0) return BR_SERVER_TX_NO_INPUT;

    BRTransaction *tx = BRTransactionParseSigned(buf, len);
    if (! tx) return BR_SERVER_TX_PARSE_FAILED;
    if (! BRTransactionIsSigned(tx)) {
        BRTransactionFree(tx);
        return BR_SERVER_TX_UNSIGNED;
    }

    // The wallet's record is read from a copy taken under its lock.
    BRTransaction *existing = BRWalletCopyTransactionForHash(wallet, tx->txHash);
    if (existing) {
        BRServerTxImportResult r = BR_SERVER_TX_ALREADY_CONFIRMED;
        if (existing->blockHeight == TX_UNCONFIRMED) {
            r = BRServerTxApplyHeight(manager, existing->txHash, blockHeight, blockTimestamp, note, log)
                == BR_SERVER_HEIGHT_TAKEN ? BR_SERVER_TX_PROMOTED : BR_SERVER_TX_ALREADY_PENDING;
        }
        BRTransactionFree(existing);
        BRTransactionFree(tx);
        return r;
    }

    // Registered pending; the server height is applied after.
    tx->blockHeight = TX_UNCONFIRMED;
    tx->timestamp = 0;

    UInt256 txHash = tx->txHash;
    if (! BRWalletRegisterTransactionUnproven(wallet, tx)) {
        // The wallet keeps an unconfirmed non-wallet tx; it keeps nothing else it refused. Free the tx unless the
        // wallet's record of the hash is this object.
        if (BRWalletTransactionForHash(wallet, txHash) != tx) BRTransactionFree(tx);
        return BR_SERVER_TX_NOT_WALLET;
    }
    if (BRServerTxApplyHeight(manager, txHash, blockHeight, blockTimestamp, note, log) == BR_SERVER_HEIGHT_UNPROVABLE) {
        BRWalletRemoveTransaction(wallet, txHash);
        return BR_SERVER_TX_NOT_KEPT_UNPROVABLE;
    }
    return BR_SERVER_TX_IMPORTED;
}

static inline int BRServerTxConfirm(BRWallet *wallet, BRPeerManager *manager, UInt256 txHash, int64_t blockHeight,
                                    int64_t blockTimestamp, BRServerTxUnprovableNote *note, BRServerTxHeightLog *log)
{
    if (log) { log->applied = 0; log->result = BR_SERVER_HEIGHT_REFUSED; }
    if (! wallet) return 0;
    if (blockHeight <= 0 || blockHeight >= (int64_t)TX_UNCONFIRMED) return 0;

    // The height is read from a copy taken under the wallet lock.
    BRTransaction *existing = BRWalletCopyTransactionForHash(wallet, txHash);
    int pending = existing && existing->blockHeight == TX_UNCONFIRMED;
    if (existing) BRTransactionFree(existing);
    if (! pending) return 0;
    return BRServerTxApplyHeight(manager, txHash, blockHeight, blockTimestamp, note, log) == BR_SERVER_HEIGHT_TAKEN;
}

#ifdef __cplusplus
}
#endif

#endif // BRServerTxImport_h
