//
//  BRDigiDollarEvent.h
//
//  What a DigiDollar transaction did for this wallet, for its row in the activity list. Until 2026-11
//  the rule lived in Android's JNI bridge (native/src/main/jni/bridge/digidollar_event.h: dd_event_of),
//  and the wallet's two answers to it beside the bridge's digiDollarEvent (jni_transaction.c:
//  _ddEventPaysWallet, _ddEventSpendsWallet). Moved unchanged, so that both platforms name a DigiDollar
//  row by one rule. Display only: nothing here feeds a spend or a balance.
//
//  A row says what the transaction IS -- a mint, a transfer sent, a transfer received, a transfer to
//  this wallet's own address, a redemption -- read from the transaction's DigiDollar type and from
//  whose DigiDollar it spends and pays. The DGB a DigiDollar transaction moves says nothing of that:
//  a mint locks DGB as collateral (DGB leaves) while dollars arrive, a transfer to yourself spends
//  only its fee, and a redemption returns collateral (DGB arrives) while dollars are burned.
//
//    MINTED         a mint: `cents` is what it created (paid to this wallet when any was).
//    SENT           a transfer this wallet paid for, to someone else: `cents` is what they were paid,
//                   `changeCents` what came back.
//    RECEIVED       a transfer this wallet did not pay for: `cents` is what it was paid.
//    SELF_TRANSFER  a transfer this wallet paid for in which every dollar came back to it: `cents` is its
//                   payment (its first DigiDollar output, where a transfer pays its recipient),
//                   `changeCents` the rest.
//    REDEEMED       a redemption: `cents` is what was burned -- the wallet's dollars it spent less the
//                   change back -- and `changeCents` the change.
//    NONE           not a DigiDollar transaction, or one that moved none of this wallet's dollars; also
//                   a NULL tx or wallet view, and amounts whose sum does not fit an int64 (no row is
//                   shown, rather than one with a wrapped amount).
//
//  THE RULE (BRDigiDollarEventOf) asks the wallet two things through BRDigiDollarEventWallet: whether an
//  output pays it, and whether an input spends one of its outputs (and if so how many cents of
//  DigiDollar that output held). It takes no lock and reads nothing but tx and those answers.
//
//  THE WALLET'S ANSWERS (BRWalletDigiDollarEvent, BRWalletDigiDollarEventForHash) are the bridge's: an
//  output pays the wallet when it has an address the wallet contains; an input spends the wallet's
//  output when the wallet holds the transaction it names, that transaction has the output, and the
//  output's address is the wallet's -- its cents are then BRDigiDollarOutputAmount of that output (-1: a
//  DGB coin). They call the wallet's accessors (BRWalletContainsAddress, BRWalletCopyTransactionForHash),
//  each of which takes the wallet's lock: the caller must NOT hold it. Each spent transaction is a copy
//  taken under that lock and freed before the answer returns. BRWalletDigiDollarEventForHash also copies
//  the transaction itself, by its internal (little-endian) hash, and answers 0 when the wallet does not
//  hold it. A platform that can free its wallet while another thread reads it keeps its own guard around
//  the call (Android: WALLET_READ_GUARD).
//
//  Header-only, static inline; no I/O, no clock. The rule allocates nothing; the wallet's answers
//  allocate only the transaction copies above.
//
//  Test seams (host KAT digidollar_event_core_kat in the Android repo), each tested by VALUE (#if); unset
//  or =0 is what ships:
//    DIGIDOLLAR_EVENT_UNFIXED=1    the rule the activity list used before: the direction read from the
//                                  sign of the transaction's DGB movement (dgbNet), then the dollars paid
//                                  to others (when DGB left) or to the wallet (when DGB arrived).
//    DD_EVENT_OVERFLOW_UNFIXED=1   the cent sums are plain adds, which overflow for amounts no
//                                  transaction can carry.
//

#ifndef BRDigiDollarEvent_h
#define BRDigiDollarEvent_h

#include "BRWallet.h"        // BRWallet, BRWalletContainsAddress, BRWalletCopyTransactionForHash
#include "BRTransaction.h"   // BRTransaction, BRTxInput, BRTxOutput, BRTransactionFree
#include "BRDigiDollar.h"    // BRDigiDollarTxType, BRDigiDollarOutputAmount, DD_TYPE_*
#include "BRInt.h"           // UInt256
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIGIDOLLAR_EVENT_UNFIXED
#define DIGIDOLLAR_EVENT_UNFIXED 0
#endif

#ifndef DD_EVENT_OVERFLOW_UNFIXED
#define DD_EVENT_OVERFLOW_UNFIXED 0
#endif

typedef enum {
    BR_DIGIDOLLAR_EVENT_NONE = 0,
    BR_DIGIDOLLAR_EVENT_MINTED = 1,
    BR_DIGIDOLLAR_EVENT_SENT = 2,
    BR_DIGIDOLLAR_EVENT_RECEIVED = 3,
    BR_DIGIDOLLAR_EVENT_SELF_TRANSFER = 4,
    BR_DIGIDOLLAR_EVENT_REDEEMED = 5
} BRDigiDollarEventKind;

typedef struct {
    BRDigiDollarEventKind kind;
    int64_t cents;         // the cents the row shows: minted, sent, received, moved to the wallet itself, or burned
    int64_t changeCents;   // DigiDollar paid back to this wallet as change (sent transfers and redemptions), else 0
} BRDigiDollarEvent;

typedef struct {
    void *ctx;
    // 1 when `output` pays an address of this wallet.
    int (*paysWallet)(void *ctx, const BRTxOutput *output);
    // 1 when `input` spends an output of this wallet; *ddCents is then the DigiDollar cents that output
    // held, or -1 when it held none (a DGB coin) or they cannot be told.
    int (*spendsWallet)(void *ctx, const BRTxInput *input, int64_t *ddCents);
    // Only DIGIDOLLAR_EVENT_UNFIXED reads it: the transaction's net DGB movement for the wallet.
    int64_t (*dgbNet)(void *ctx, const BRTransaction *tx);
} BRDigiDollarEventWallet;

// acc += v, or 0 when the sum would not fit an int64. DD_EVENT_OVERFLOW_UNFIXED keeps the plain add for
// the KAT's comparison arm.
static inline int _BRDigiDollarEventAdd(int64_t *acc, int64_t v)
{
#if DD_EVENT_OVERFLOW_UNFIXED
    *acc += v;
    return 1;
#else
    return ! __builtin_add_overflow(*acc, v, acc);
#endif
}

static inline BRDigiDollarEvent BRDigiDollarEventOf(const BRTransaction *tx, const BRDigiDollarEventWallet *w)
{
    BRDigiDollarEvent ev = { BR_DIGIDOLLAR_EVENT_NONE, 0, 0 };
    int64_t own = 0, other = 0, first = 0;
    int type;

    if (! tx || ! w || ! w->paysWallet || ! w->spendsWallet) return ev;
    type = BRDigiDollarTxType(tx);
    if (type == 0) return ev;

    // The DigiDollar each output carries, by whose it is.
    for (size_t i = 0; i < tx->outCount; i++) {
        int64_t c = BRDigiDollarOutputAmount(tx, i);
        if (c <= 0) continue;   // not a DigiDollar token output
        if (first == 0) first = c;
        // Amounts no transaction can carry -- their sum does not fit an int64 -- make no activity row,
        // rather than one with a wrapped amount.
        if (! _BRDigiDollarEventAdd(w->paysWallet(w->ctx, &tx->outputs[i]) ? &own : &other, c)) return ev;
    }

#if DIGIDOLLAR_EVENT_UNFIXED
    {
        int isSend = w->dgbNet && w->dgbNet(w->ctx, tx) < 0;
        ev.kind = isSend ? BR_DIGIDOLLAR_EVENT_SENT : BR_DIGIDOLLAR_EVENT_RECEIVED;
        ev.cents = isSend ? other : own;
        return ev;
    }
#else
    {
        int spendsOwn = 0;
        int64_t ownSpent = 0;

        for (size_t i = 0; i < tx->inCount; i++) {
            int64_t c = -1;
            if (! w->spendsWallet(w->ctx, &tx->inputs[i], &c)) continue;
            spendsOwn = 1;
            if (c > 0 && ! _BRDigiDollarEventAdd(&ownSpent, c)) return (BRDigiDollarEvent){ BR_DIGIDOLLAR_EVENT_NONE, 0, 0 };
        }

        switch (type) {
        case DD_TYPE_MINT:
            ev.kind = BR_DIGIDOLLAR_EVENT_MINTED;
            ev.cents = own > 0 ? own : other;
            break;
        case DD_TYPE_TRANSFER:
            if (spendsOwn && other > 0) {
                ev.kind = BR_DIGIDOLLAR_EVENT_SENT; ev.cents = other; ev.changeCents = own;
            } else if (spendsOwn && own > 0) {
                // every dollar paid back to the wallet: the payment is the first output, the rest change
                ev.kind = BR_DIGIDOLLAR_EVENT_SELF_TRANSFER; ev.cents = first; ev.changeCents = own - first;
            } else if (! spendsOwn && own > 0) {
                ev.kind = BR_DIGIDOLLAR_EVENT_RECEIVED; ev.cents = own;
            }
            break;
        case DD_TYPE_REDEEM:
            ev.kind = BR_DIGIDOLLAR_EVENT_REDEEMED;
            ev.cents = ownSpent > own ? ownSpent - own : 0;
            ev.changeCents = own;
            break;
        default:
            break;
        }
        return ev;
    }
#endif
}

// ---- the wallet's answers (the bridge's _ddEventPaysWallet and _ddEventSpendsWallet) ----

static inline int _BRWalletDigiDollarEventPays(void *ctx, const BRTxOutput *output)
{
    return output->address[0] != '\0' && BRWalletContainsAddress((BRWallet *)ctx, output->address);
}

static inline int _BRWalletDigiDollarEventSpends(void *ctx, const BRTxInput *input, int64_t *ddCents)
{
    BRWallet *wallet = (BRWallet *)ctx;
    // a copy taken under the wallet lock; freed on every path
    BRTransaction *spent = BRWalletCopyTransactionForHash(wallet, input->txHash);
    int pays = 0;
    *ddCents = -1;
    if (spent && input->index < spent->outCount) {
        const BRTxOutput *output = &spent->outputs[input->index];
        if (output->address[0] != '\0' && BRWalletContainsAddress(wallet, output->address)) {
            *ddCents = BRDigiDollarOutputAmount(spent, input->index);   // -1: a DGB coin, not DigiDollar
            pays = 1;
        }
    }
    if (spent) BRTransactionFree(spent);
    return pays;
}

// What tx did for `wallet`. NONE when wallet or tx is NULL. The caller must not hold the wallet's lock.
static inline BRDigiDollarEvent BRWalletDigiDollarEvent(BRWallet *wallet, const BRTransaction *tx)
{
    BRDigiDollarEventWallet w = { wallet, _BRWalletDigiDollarEventPays, _BRWalletDigiDollarEventSpends, NULL };
    BRDigiDollarEvent none = { BR_DIGIDOLLAR_EVENT_NONE, 0, 0 };

    if (! wallet || ! tx) return none;
    return BRDigiDollarEventOf(tx, &w);
}

// The same for the transaction the wallet holds under txHash (internal byte order): 1 with *out set, or
// 0 (out untouched) when wallet or out is NULL or the wallet does not hold it.
static inline int BRWalletDigiDollarEventForHash(BRWallet *wallet, UInt256 txHash, BRDigiDollarEvent *out)
{
    BRTransaction *tx;

    if (! wallet || ! out) return 0;
    tx = BRWalletCopyTransactionForHash(wallet, txHash);   // a copy taken under the wallet lock
    if (! tx) return 0;
    *out = BRWalletDigiDollarEvent(wallet, tx);
    BRTransactionFree(tx);
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiDollarEvent_h
