//
//  BRTxRows.h
//
//  The wallet's transaction list as both apps show it: one row per wallet transaction, its amount,
//  fee and date, in one order. Android and iOS each built this list themselves and disagreed on all
//  four (Android corrected a send's amount from its own record of what it broadcast, iOS showed
//  received - sent; Android read an unknown fee as 0; iOS showed a pending row with no date and
//  sorted pending first, Android sorted by date). The rows decide what a person reads as their
//  history, so both platforms take them from here and neither re-sorts or re-computes them.
//
//  THE RULE (decided by the owner, 2026-11-08):
//    - AMOUNT (D1). A row's amount is signed: positive = in, negative = out.
//        * a DigiDollar transaction (BRDigiDollarTxType != 0): received - sent, whatever it pays
//          others. A mint sends DGB away as collateral and a redemption brings it back; its row is the
//          DGB the wallet's balance moved by;
//        * a send -- some input is the wallet's and the transaction pays others something
//          (toOthers > 0): -toOthers, the payee amount only. The fee is the row's own field, never
//          folded into the amount. A DigiAsset transfer therefore reads as minus its marker output;
//        * otherwise (a receive, a send to the wallet itself, a sweep of a foreign key into the
//          wallet): received - sent.
//      toOthers = the transaction's outputs minus what it pays the wallet (BRWalletAmountReceivedFromTx),
//      so every output is counted exactly once, on one side or the other. An input is the wallet's when
//      the coin it spends is a wallet output (BRWalletAmountSentByTx sees it), or -- for a coin whose
//      transaction the wallet does not hold -- when the input's own address, or the native-segwit
//      address of the public key its witness carries, is a wallet address. The second test is what
//      keeps a send whose parents were never downloaded (a restored wallet) from reading as a receive
//      of its change.
//      KNOWN GAP: a Taproot key-path input carries only a signature. With its parent missing nothing in
//      the transaction says the coin was the wallet's, so such a send still reads as received - sent
//      (its change, positive). tx_rows_amount_kat pins this (taproot_keypath_missing_parent).
//    - FEE (D2). BRWalletFeeForTx: the inputs minus the outputs when the wallet holds every parent;
//      BR_TX_ROW_FEE_UNKNOWN (UINT64_MAX) otherwise. Unknown is shown as unknown, never as a figure
//      (not 0, not a partial sum).
//    - DATE (D3). shownTimestamp = timestamp, or `now` while the transaction has none (0 until its
//      block is seen). `now` is the caller's clock: this header never reads one.
//    - ORDER. shownTimestamp descending, then blockHeight descending (an unconfirmed row's
//      TX_UNCONFIRMED is the highest), then walletIndex ascending -- the row's position in the wallet's
//      own oldest-first list when it was read. A total order: two rows never compare equal, so every
//      platform lists the same rows in the same order. Platforms never re-sort.
//
//  READING A WALLET. BRWalletTxRows copies the wallet's transactions in one lock hold
//  (BRWalletCopyTransactions), computes every row from those copies, sorts, and writes the first
//  maxRows. It keeps no pointer into the wallet, does no I/O, and allocates only for the length of
//  the call. Each wallet call it makes takes the wallet's lock, which is not recursive: the caller
//  must NOT hold it. The wallet may change while the rows are computed (a peer thread); every row is
//  then still computed from one copy of one transaction, as getTransactionDetails is today.
//
//  Shared vectors: vectors/tx-rows/ (the pure rules, written down). Host KATs
//  (digibytewallet-android native/src/test/host/): tx_rows_order_kat, tx_rows_amount_kat,
//  tx_rows_wallet_kat.
//  Header-only, static inline.
//

#ifndef BRTxRows_h
#define BRTxRows_h

#include "BRWallet.h"        // BRWalletCopyTransactions, BRWalletAmount*, BRWalletFeeForTx, BRWalletContainsAddress
#include "BRTransaction.h"   // BRTransaction, TX_UNCONFIRMED
#include "BRDigiDollar.h"    // BRDigiDollarTxType
#include "BRAddress.h"       // BRVarInt, BRAddressFromScriptPubKey
#include "BRCrypto.h"        // BRHash160
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// MACRO CONVENTION: TX_ROWS_UNFIXED is tested by VALUE (#if). =1 is the host KATs' comparison arm: the
// rows as the platforms read them before this header -- every amount received - sent, an unknown fee
// read as 0 (Android's toLongOrNull() ?: 0L on "18446744073709551615"), the raw timestamp (0 while
// pending, iOS), and iOS's order (unconfirmed first, then height descending, then timestamp
// descending, ties in the wallet's order). Unset or =0 is what ships.
#ifndef TX_ROWS_UNFIXED
#define TX_ROWS_UNFIXED 0
#endif

// The fee of a row whose fee the wallet cannot know. A literal for Swift; it is UINT64_MAX, the value
// BRWalletFeeForTx returns.
#define BR_TX_ROW_FEE_UNKNOWN 0xFFFFFFFFFFFFFFFFULL
typedef char _BRTxRowFeeUnknownIsFeeForTxs[(BR_TX_ROW_FEE_UNKNOWN == UINT64_MAX) ? 1 : -1];

// Which part of the AMOUNT rule a row took. The zero value is the plain one.
typedef enum {
    BRTxRowAmountNet = 0,         // received - sent
    BRTxRowAmountPayee = 1,       // -toOthers: a send, the payee amount only
    BRTxRowAmountDigiDollar = 2   // received - sent, because the transaction is a DigiDollar one
} BRTxRowAmountRule;

typedef struct {
    UInt256 txHash;           // the wallet's byte order (UInt256.u8); a txid displays it reversed
    int64_t amount;           // signed, satoshis: positive = in, negative = out (the AMOUNT rule)
    uint64_t fee;             // satoshis, or BR_TX_ROW_FEE_UNKNOWN
    uint64_t sent;            // BRWalletAmountSentByTx: wallet coins spent that the wallet holds the parents of
    uint64_t received;        // BRWalletAmountReceivedFromTx: outputs paying the wallet
    uint64_t toOthers;        // the outputs minus received
    uint32_t blockHeight;     // TX_UNCONFIRMED (INT32_MAX) while unconfirmed
    uint32_t timestamp;       // the transaction's own: 0 until its block is seen
    uint32_t shownTimestamp;  // the date shown and sorted on (the DATE rule)
    uint32_t walletIndex;     // position in the wallet's oldest-first list when read (the ORDER tiebreak)
    uint32_t ddType;          // BRDigiDollarTxType: 0, or DD_TYPE_MINT / _TRANSFER / _REDEEM
    uint8_t ownsInput;        // 1 when some input is the wallet's (see the AMOUNT rule)
    uint8_t rule;             // a BRTxRowAmountRule
} BRTxRow;

// ---- the pure rules ----------------------------------------------------------------------------

// The date a row shows and sorts on: its own timestamp, or the caller's `now` while it has none.
static inline uint32_t BRTxRowShownTimestamp(uint32_t timestamp, uint32_t now)
{
#if TX_ROWS_UNFIXED
    (void)now;
    return timestamp;   // comparison arm: iOS showed and sorted on the raw 0
#else
    return timestamp ? timestamp : now;
#endif
}

// Which amount a transaction's row shows. isDigiDollar: BRDigiDollarTxType != 0; ownsInput: some
// input is the wallet's; toOthers: what it pays outside the wallet.
static inline BRTxRowAmountRule BRTxRowAmountRuleFor(int isDigiDollar, int ownsInput, uint64_t toOthers)
{
#if TX_ROWS_UNFIXED
    (void)isDigiDollar; (void)ownsInput; (void)toOthers;
    return BRTxRowAmountNet;   // comparison arm: received - sent for every transaction
#else
    if (isDigiDollar) return BRTxRowAmountDigiDollar;
    if (ownsInput && toOthers > 0) return BRTxRowAmountPayee;
    return BRTxRowAmountNet;
#endif
}

// The signed amount for a rule, saturating at INT64_MIN / INT64_MAX (a value no real transaction
// reaches, but one the wallet's saturating sums can).
static inline int64_t BRTxRowAmountFor(BRTxRowAmountRule rule, uint64_t received, uint64_t sent, uint64_t toOthers)
{
    if (rule == BRTxRowAmountPayee) {
        return (toOthers > (uint64_t)INT64_MAX) ? INT64_MIN : -(int64_t)toOthers;
    }
    // BRTxRowAmountNet, BRTxRowAmountDigiDollar, and any other value: received - sent
    if (received >= sent) {
        uint64_t d = received - sent;
        return (d > (uint64_t)INT64_MAX) ? INT64_MAX : (int64_t)d;
    }
    else {
        uint64_t d = sent - received;
        return (d > (uint64_t)INT64_MAX) ? INT64_MIN : -(int64_t)d;
    }
}

// The fee a row shows: the wallet's figure, or BR_TX_ROW_FEE_UNKNOWN when it has none.
static inline uint64_t BRTxRowFeeFor(uint64_t walletFee)
{
#if TX_ROWS_UNFIXED
    return (walletFee == UINT64_MAX) ? 0 : walletFee;   // comparison arm: Android read unknown as 0
#else
    return walletFee;
#endif
}

// The ORDER: negative when a is listed before b, positive when after. 0 only for the same row
// (equal walletIndex), so a sort by it is the same on every platform whatever the sort's stability.
static inline int BRTxRowCompare(const BRTxRow *a, const BRTxRow *b)
{
#if TX_ROWS_UNFIXED
    // comparison arm, iOS's order: unconfirmed first, then height descending, then timestamp
    // descending, ties in the wallet's order
    int ap = (a->blockHeight == TX_UNCONFIRMED), bp = (b->blockHeight == TX_UNCONFIRMED);
    if (ap != bp) return ap ? -1 : 1;
    if (a->blockHeight != b->blockHeight) return (a->blockHeight > b->blockHeight) ? -1 : 1;
    if (a->timestamp != b->timestamp) return (a->timestamp > b->timestamp) ? -1 : 1;
#else
    if (a->shownTimestamp != b->shownTimestamp) return (a->shownTimestamp > b->shownTimestamp) ? -1 : 1;
    if (a->blockHeight != b->blockHeight) return (a->blockHeight > b->blockHeight) ? -1 : 1;
#endif
    if (a->walletIndex != b->walletIndex) return (a->walletIndex < b->walletIndex) ? -1 : 1;
    return 0;
}

// ---- reading the wallet ------------------------------------------------------------------------

// The native-segwit address of the public key a P2WPKH witness carries (two items, the second a
// 33-byte compressed key), written to addr. 0 when the witness is not that shape. The core's
// BRAddressFromWitness does not derive one, so a parsed transaction's P2WPKH input has no address.
static inline size_t _BRTxRowWitnessAddress(char *addr, size_t addrLen, const uint8_t *witness, size_t witLen)
{
    size_t off = 0, n = 0, intLen = 0, keyOff = 0, keyLen = 0;

    if (! witness || witLen == 0) return 0;
    while (off < witLen) {
        uint64_t len = BRVarInt(&witness[off], witLen - off, &intLen);
        if (intLen == 0 || intLen > witLen - off) return 0;
        off += intLen;
        if (len > witLen - off) return 0;
        n++;
        if (n == 2) { keyOff = off; keyLen = (size_t)len; }
        off += (size_t)len;
    }
    if (n != 2 || keyLen != 33 || (witness[keyOff] != 0x02 && witness[keyOff] != 0x03)) return 0;

    uint8_t spk[22] = { 0x00, 0x14 };
    BRHash160(&spk[2], &witness[keyOff], keyLen);
    return BRAddressFromScriptPubKey(addr, addrLen, spk, sizeof(spk));
}

// Whether some input of tx is the wallet's (the AMOUNT rule's test). sent: BRWalletAmountSentByTx.
static inline int _BRTxRowOwnsInput(BRWallet *wallet, const BRTransaction *tx, uint64_t sent)
{
    if (sent > 0) return 1;
    for (size_t i = 0; i < tx->inCount; i++) {
        const BRTxInput *in = &tx->inputs[i];
        char addr[sizeof(in->address)];

        if (in->address[0] != '\0') {
            memcpy(addr, in->address, sizeof(addr));
            addr[sizeof(addr) - 1] = '\0';
        }
        else if (! _BRTxRowWitnessAddress(addr, sizeof(addr), in->witness, in->witLen)) continue;
        if (addr[0] != '\0' && BRWalletContainsAddress(wallet, addr)) return 1;
    }
    return 0;
}

// The row for tx, a transaction of wallet (or a copy of one), at walletIndex in the wallet's
// oldest-first list. now: the caller's clock (the DATE rule). The caller must not hold the wallet's lock.
static inline void BRWalletTxRowFill(BRWallet *wallet, const BRTransaction *tx, uint32_t walletIndex, uint32_t now,
                                     BRTxRow *row)
{
    uint64_t out = 0;

    memset(row, 0, sizeof(*row));
    row->txHash = tx->txHash;
    row->received = BRWalletAmountReceivedFromTx(wallet, tx);
    row->sent = BRWalletAmountSentByTx(wallet, tx);
    for (size_t i = 0; i < tx->outCount; i++) {
        out = (tx->outputs[i].amount > UINT64_MAX - out) ? UINT64_MAX : out + tx->outputs[i].amount;
    }
    row->toOthers = (out > row->received) ? out - row->received : 0;
    row->fee = BRTxRowFeeFor(BRWalletFeeForTx(wallet, tx));
    row->blockHeight = tx->blockHeight;
    row->timestamp = tx->timestamp;
    row->shownTimestamp = BRTxRowShownTimestamp(tx->timestamp, now);
    row->walletIndex = walletIndex;
    row->ddType = (uint32_t)BRDigiDollarTxType(tx);
    row->ownsInput = (uint8_t)_BRTxRowOwnsInput(wallet, tx, row->sent);
    row->rule = (uint8_t)BRTxRowAmountRuleFor(row->ddType != 0, row->ownsInput, row->toOthers);
    row->amount = BRTxRowAmountFor((BRTxRowAmountRule)row->rule, row->received, row->sent, row->toOthers);
}

// How many rows the wallet has now: one per registered transaction.
static inline size_t BRWalletTxRowCount(BRWallet *wallet)
{
    return BRWalletTransactions(wallet, NULL, 0);
}

static inline int _BRTxRowQsortCompare(const void *a, const void *b)
{
    return BRTxRowCompare((const BRTxRow *)a, (const BRTxRow *)b);
}

// Writes the wallet's rows to rows, in the ORDER, the first maxRows of them (the newest), and returns
// how many it wrote. rows NULL: writes nothing and returns how many rows there are (as
// BRWalletTransactions does); maxRows 0: writes nothing and returns 0. Returns 0, writing nothing, if
// it cannot allocate the copies. now: the caller's clock (the DATE rule). The caller must not hold the
// wallet's lock.
static inline size_t BRWalletTxRows(BRWallet *wallet, uint32_t now, BRTxRow *rows, size_t maxRows)
{
    size_t count, i, n;
    BRTransaction **txs;
    BRTxRow *all;

    if (! wallet) return 0;
    count = BRWalletTransactions(wallet, NULL, 0);
    if (! rows) return count;
    if (maxRows == 0 || count == 0) return 0;
    if (count > SIZE_MAX / sizeof(BRTxRow) || count > UINT32_MAX) return 0;

    txs = (BRTransaction **)calloc(count, sizeof(*txs));
    all = (BRTxRow *)calloc(count, sizeof(*all));
    if (! txs || ! all) { free(txs); free(all); return 0; }

    count = BRWalletCopyTransactions(wallet, txs, count);   // one lock hold; fewer if the wallet shrank
    for (i = 0, n = 0; i < count; i++) {
        if (! txs[i]) continue;   // a copy that could not be allocated: no row rather than an empty one
        BRWalletTxRowFill(wallet, txs[i], (uint32_t)i, now, &all[n++]);
        BRTransactionFree(txs[i]);
    }
    free(txs);

    qsort(all, n, sizeof(*all), _BRTxRowQsortCompare);
    if (maxRows > n) maxRows = n;
    memcpy(rows, all, maxRows * sizeof(*rows));
    free(all);
    return maxRows;
}

#ifdef __cplusplus
}
#endif

#endif // BRTxRows_h
