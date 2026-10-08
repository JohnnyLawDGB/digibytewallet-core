//
//  BRWallet.c
//
//  Created by Aaron Voisine on 9/1/15.
//  Copyright (c) 2015 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include "BRWallet.h"
#include "BRSet.h"
#include "BRAddress.h"
#include "BRArray.h"
#include "BRBech32.h"
#include "BRDigiAsset.h"
#include "BRDigiDollar.h"
#include "BRNetwork.h"
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <float.h>
#include <pthread.h>
#include <assert.h>

struct BRWalletStruct {
    uint64_t balance, totalSent, totalReceived, feePerKb, *balanceHist;
    uint32_t blockHeight;
    BRUTXO *utxos;
    BRUTXO *assetUtxos;
    // Outpoints an out-of-band authority (the Kotlin asset layer) has told us carry
    // DigiAsset units that BRTxOutputIsAsset cannot see from the transaction alone --
    // chiefly implicit change, where the units the transfer instructions did not assign
    // ride on the tx's LAST output. Unlike assetUtxos this list is NOT rebuilt from the
    // transaction set, so the exclusion survives every _BRWalletUpdateBalance.
    BRUTXO *assetOverrides;
    BRUTXO *ddUtxos;      // DigiDollar token UTXOs (zero-value P2TR, cents-denominated)
    uint64_t ddBalance;   // DigiDollar balance in CENTS (never mixed with the sat balance)
    // Coin-generation outputs paid to this wallet are spendable only once the chain tip is at
    // least the maturity depth past the coin's own height. Until then their value is carried
    // here and NOT in balance/utxos. nextMaturityHeight is the lowest tip at which one of them
    // becomes spendable (UINT32_MAX when none is held); coinbaseOutputs counts every owned
    // coin-generation output, mature or not, so BRWalletSetBlockHeight can decide in O(1)
    // whether a new tip can change the balance at all. All three are refilled by every rebuild.
    uint64_t immatureBalance;
    uint32_t nextMaturityHeight;
    size_t coinbaseOutputs;
    BRTransaction **transactions;
    BRMasterPubKey masterPubKey;
    BRAddress *internalChain, *externalChain;
    BRAddress *internalChainSegwit, *externalChainSegwit;
    // Monotonic stamp for "the enumerated address set changed". Sourced from a
    // process-global counter so a REPLACEMENT wallet can never collide with a
    // predecessor's value, even if malloc hands back the same chunk. See
    // BRWalletAddrSetKey.
    uint64_t addrGen;
    // Legacy key support: populated by BRWalletNewDual for recovery scanning of old m/0H addresses
    BRMasterPubKey legacyPubKey;
    int hasLegacyKey;
    BRAddress *legacyExternalChain;
    BRAddress *legacyInternalChain;
    BRAddress *legacyExternalChainSegwit;
    BRAddress *legacyInternalChainSegwit;
    // Taproot (BIP86 / P2TR) support: derived from taprootPubKey (m/86'), dormant until installed
    BRMasterPubKey taprootPubKey;
    int hasTaprootKey;
    BRAddress *taprootExternalChain;
    BRAddress *taprootInternalChain;
    // Explicitly-watched addresses persisted independently of the derived chains
    // (every address ever shown on the Receive screen). Always included in the
    // BIP158 match set (BRWalletAllAddrs) and containment checks, so a receive to an
    // address that later falls outside the gap-limit window is never missed. Kept as
    // a PLAIN array iterated directly — never inserted into the allAddrs BRSet as
    // &watchedAddrs[i], to avoid the realloc-dangling use-after-free class.
    BRAddress *watchedAddrs;
    BRSet *allTx, *invalidTx, *pendingTx, *spentOutputs, *usedAddrs, *allAddrs;
    void *callbackInfo;
    void (*balanceChanged)(void *info, uint64_t balance);
    void (*txAdded)(void *info, BRTransaction *tx);
    void (*txUpdated)(void *info, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight, uint32_t timestamp);
    void (*txDeleted)(void *info, UInt256 txHash, int notifyUser, int recommendRescan);
    pthread_mutex_t lock;
};

inline static uint64_t _txFee(uint64_t feePerKb, size_t size)
{
    // standard fee based on tx size
    uint64_t standardFee = size*TX_FEE_PER_KB/1000,
    // fee using feePerKb, rounded up to nearest 100 satoshi
    fee = (((size*feePerKb/1000) + 99)/100)*100;
    
    return (fee > standardFee) ? fee : standardFee;
}

// chain position of first tx output address that appears in chain
inline static size_t _txChainIndex(const BRTransaction *tx, const BRAddress *addrChain)
{
    for (size_t i = array_count(addrChain); i > 0; i--) {
        for (size_t j = 0; j < tx->outCount; j++) {
            if (BRAddressEq(tx->outputs[j].address, &addrChain[i - 1])) return i - 1;
        }
    }
    
    return SIZE_MAX;
}

// The number of input-chain links a single comparison will walk before it stops and
// lets the chain-position tie-break decide. It is far above the ancestor depth of any
// honest unconfirmed chain, so the order the wallet presents is unchanged for real
// transactions; it exists only so that a peer-relayed chain of unconfirmed
// transactions cannot make the walk scale with the chain length -- and so the
// insertion sort that drives it cannot become cubic -- and so that a crafted cycle in
// the input graph cannot recurse without end.
#ifndef WALLET_ASCENDING_DEPTH_UNFIXED
#define WALLET_MAX_ASCENDING_STEPS 256
#endif

#ifdef KAT_ASCENDING_COUNTER
// Test-only instrumentation (never defined in an app build): counts the input-chain
// links walked by the current comparison and records the largest any one comparison
// walked, so a host KAT can prove the walk is bounded per comparison rather than
// scaling with the chain length. Inert unless the KAT build defines the macro.
size_t _kat_asc_steps = 0, _kat_asc_max = 0;
#endif

inline static int _BRWalletTxIsAscendingBudget(BRWallet *wallet, const BRTransaction *tx1,
                                               const BRTransaction *tx2, unsigned *budget)
{
    if (! tx1 || ! tx2) return 0;
#ifdef KAT_ASCENDING_COUNTER
    _kat_asc_steps++;
#endif
    if (tx1->blockHeight > tx2->blockHeight) return 1;
    if (tx1->blockHeight < tx2->blockHeight) return 0;

    for (size_t i = 0; i < tx1->inCount; i++) {
        if (UInt256Eq(tx1->inputs[i].txHash, tx2->txHash)) return 1;
    }

    for (size_t i = 0; i < tx2->inCount; i++) {
        if (UInt256Eq(tx2->inputs[i].txHash, tx1->txHash)) return 0;
    }

    for (size_t i = 0; i < tx1->inCount; i++) {
#ifndef WALLET_ASCENDING_DEPTH_UNFIXED
        // bound the total number of links walked per comparison, across depth and
        // breadth alike; when the budget is spent the walk stops and the result falls
        // through to the chain-position ordering, exactly as an exhausted honest walk
        // would.
        if (*budget == 0) return 0;
        (*budget)--;
#endif
        if (_BRWalletTxIsAscendingBudget(wallet, BRSetGet(wallet->allTx, &(tx1->inputs[i].txHash)), tx2, budget)) return 1;
    }

    return 0;
}

inline static int _BRWalletTxIsAscending(BRWallet *wallet, const BRTransaction *tx1, const BRTransaction *tx2)
{
#ifndef WALLET_ASCENDING_DEPTH_UNFIXED
    unsigned budget = WALLET_MAX_ASCENDING_STEPS;
#else
    unsigned budget = 0; // the comparison arm does not bound the walk
#endif
#ifdef KAT_ASCENDING_COUNTER
    _kat_asc_steps = 0;
    int r = _BRWalletTxIsAscendingBudget(wallet, tx1, tx2, &budget);
    if (_kat_asc_steps > _kat_asc_max) _kat_asc_max = _kat_asc_steps;
    return r;
#else
    return _BRWalletTxIsAscendingBudget(wallet, tx1, tx2, &budget);
#endif
}

inline static int _BRWalletTxCompare(BRWallet *wallet, const BRTransaction *tx1, const BRTransaction *tx2)
{
    size_t i, j;

    if (_BRWalletTxIsAscending(wallet, tx1, tx2)) return 1;
    if (_BRWalletTxIsAscending(wallet, tx2, tx1)) return -1;
    i = _txChainIndex(tx1, wallet->internalChain);
    j = _txChainIndex(tx2, (i == SIZE_MAX) ? wallet->externalChain : wallet->internalChain);
    if (i == SIZE_MAX && j != SIZE_MAX) i = _txChainIndex((BRTransaction *)tx1, wallet->externalChain);
    if (i != SIZE_MAX && j != SIZE_MAX && i != j) return (i > j) ? 1 : -1;
    return 0;
}

// inserts tx into wallet->transactions, keeping wallet->transactions sorted by date, oldest first (insertion sort)
inline static void _BRWalletInsertTx(BRWallet *wallet, BRTransaction *tx)
{
    size_t i = array_count(wallet->transactions);
    
    array_set_count(wallet->transactions, i + 1);
    
    while (i > 0 && _BRWalletTxCompare(wallet, wallet->transactions[i - 1], tx) > 0) {
        wallet->transactions[i] = wallet->transactions[i - 1];
        i--;
    }
    
    wallet->transactions[i] = tx;
}

// non-threadsafe version of BRWalletContainsTransaction()
static int _BRWalletContainsTx(BRWallet *wallet, const BRTransaction *tx)
{
    int r = 0;
    
    for (size_t i = 0; ! r && i < tx->outCount; i++) {
        if (BRSetContains(wallet->allAddrs, tx->outputs[i].address)) r = 1;
//        else if (tx->outputs[i].scriptLen == 22) {
//            // try to extract P2WPKH (?)
//            char address[91];
//            BRBech32Encode(&address[0], DIGIBYTE_PUBKEY_BECH32, tx->outputs[i].script);
//            if (BRSetContains(wallet->allAddrs, &address[0])) r = 1;
//        }
    }
    
    for (size_t i = 0; ! r && i < tx->inCount; i++) {
        BRTransaction *t = BRSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount && BRSetContains(wallet->allAddrs, t->outputs[n].address)) r = 1;
    }
    
    return r;
}

//static int _BRWalletTxIsSend(BRWallet *wallet, BRTransaction *tx)
//{
//    int r = 0;
//    
//    for (size_t i = 0; ! r && i < tx->inCount; i++) {
//        if (BRSetContains(wallet->allAddrs, tx->inputs[i].address)) r = 1;
//    }
//    
//    return r;
//}

// Process-global, monotonic, never reused. Stamped into wallet->addrGen at construction
// and re-stamped on every append to an enumerated address chain, so a cached derivative of
// the address set (see the compact-filter element cache in BRPeerManager) can detect a
// change with one comparison — including a change of WALLET, which a count cannot see: two
// different seeds produce identical address counts with fully disjoint address sets
// (measured: 1045 == 1045, 0 shared).
//
// Guarded by its own leaf mutex rather than wallet->lock: the bump sites already hold
// wallet->lock, and taking it here would be a recursive acquire.
static pthread_mutex_t g_addrGenLock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_addrGenCounter = 0;

static uint64_t _brNextAddrGen(void)
{
    uint64_t g;

    pthread_mutex_lock(&g_addrGenLock);
    g = ++g_addrGenCounter;
    pthread_mutex_unlock(&g_addrGenLock);
    return g;
}

// Has an outpoint been registered as asset-bearing out of band? See assetOverrides.
// Caller holds wallet->lock (or is still inside BRWalletNew).
static int _BRWalletIsAssetOverride(BRWallet *wallet, UInt256 txHash, uint32_t n)
{
    for (size_t i = 0; i < array_count(wallet->assetOverrides); i++) {
        if (UInt256Eq(wallet->assetOverrides[i].hash, txHash) && wallet->assetOverrides[i].n == n)
            return 1;
    }

    return 0;
}

// A coin-generation transaction: exactly one input whose previous output is the null outpoint
// (all-zero hash, index 0xffffffff). Same shape as the reference client's IsCoinBase().
static int _BRTxIsCoinbase(const BRTransaction *tx)
{
    return tx->inCount == 1 && UInt256IsZero(tx->inputs[0].txHash) && tx->inputs[0].index == 0xffffffff;
}

// Blocks a coin-generation output must be buried under before it may be spent, keyed on the
// coin's OWN height (consensus/consensus.h COINBASE_MATURITY = 8 below 145,000, else 100).
// Testnet's mempool applies 100 at every height, so the wallet never assumes less there: a coin
// the wallet counted as spendable must never be one the network refuses to relay.
static uint32_t _BRCoinbaseMaturity(uint32_t coinHeight)
{
    return (coinHeight < 145000 && ! BRNetworkIsTestnet()) ? 8 : 100;
}

#ifdef WALLET_KAT_COUNT_REBUILD
// Host-KAT-only: counts full balance rebuilds so a gate can assert the rebuild is SKIPPED when a
// pushed tip cannot change any balance. A gate on wall-clock could not tell a skipped rebuild
// from a fast machine. Never defined in production.
unsigned long _walletKatRebuilds = 0;
#endif

// Money range (MAX_MONEY, BRTransaction.h). A transaction whose outputs are out of range is not a
// transaction any node accepts: no output above MAX_MONEY and outputs summing to at most MAX_MONEY.
// Each output is bounded before it is added, so the running sum cannot wrap.
static int _BRWalletTxMoneyRangeOK(const BRTransaction *tx)
{
    uint64_t total = 0;

    for (size_t i = 0; i < tx->outCount; i++) {
        if (tx->outputs[i].amount > MAX_MONEY) return 0;
        total += tx->outputs[i].amount;
        if (total > MAX_MONEY) return 0;
    }

    return 1;
}

// Sums of wallet amounts saturate instead of wrapping: a wallet total is never smaller than a part
// of it, nor larger than its parts after a subtraction.
static uint64_t _BRMoneyAdd(uint64_t a, uint64_t b) { return (b > UINT64_MAX - a) ? UINT64_MAX : a + b; }
static uint64_t _BRMoneySub(uint64_t a, uint64_t b) { return (b > a) ? 0 : a - b; }

static void _BRWalletUpdateBalance(BRWallet *wallet)
{
    int isInvalid, isPending, isCoinbase, immature;
    uint64_t balance = 0, prevBalance = 0;
    uint64_t ddBalance = 0;
    uint64_t immatureBalance = 0;
    uint32_t matureAt = 0, nextMaturity = UINT32_MAX;
    uint32_t ddFloor = BRNetworkDigiDollarActivationHeight();
    size_t coinbaseOutputs = 0;
    time_t now = time(NULL);
    size_t i, j;
    BRTransaction *tx, *t;
    BRTxOutput o;

#ifdef WALLET_KAT_COUNT_REBUILD
    _walletKatRebuilds++;   // host-KAT only; never defined in production
#endif
    array_clear(wallet->utxos);
    array_clear(wallet->assetUtxos);
    array_clear(wallet->ddUtxos);
    array_clear(wallet->balanceHist);
    BRSetClear(wallet->spentOutputs);
    BRSetClear(wallet->invalidTx);
    BRSetClear(wallet->pendingTx);
    BRSetClear(wallet->usedAddrs);
    wallet->totalSent = 0;
    wallet->totalReceived = 0;

    for (i = 0; i < array_count(wallet->transactions); i++) {
        tx = wallet->transactions[i];

        // check if any inputs are invalid or already spent
        if (tx->blockHeight == TX_UNCONFIRMED) {
            for (j = 0, isInvalid = 0; ! isInvalid && j < tx->inCount; j++) {
                if (BRSetContains(wallet->spentOutputs, &tx->inputs[j]) ||
                    BRSetContains(wallet->invalidTx, &tx->inputs[j].txHash))
                    isInvalid = 1;
            }
        
            if (isInvalid) {
                BRSetAdd(wallet->invalidTx, tx);
                array_add(wallet->balanceHist, balance);
                continue;
            }
        }

        // add inputs to spent output set
        for (j = 0; j < tx->inCount; j++) {
            BRSetAdd(wallet->spentOutputs, &tx->inputs[j]);
        }

        // check if tx is pending
        if (tx->blockHeight == TX_UNCONFIRMED) {
            isPending = (BRTransactionSize(tx) > TX_MAX_SIZE) ? 1 : 0; // check tx size is under TX_MAX_SIZE
            
            for (j = 0; ! isPending && j < tx->outCount; j++) {
                if (tx->outputs[j].amount < TX_MIN_OUTPUT_AMOUNT) isPending = 1; // check that no outputs are dust
            }

            for (j = 0; ! isPending && j < tx->inCount; j++) {
                if (tx->inputs[j].sequence < UINT32_MAX - 1) isPending = 1; // check for replace-by-fee
                if (tx->inputs[j].sequence < UINT32_MAX && tx->lockTime < TX_MAX_LOCK_HEIGHT &&
                    tx->lockTime > wallet->blockHeight + 1) isPending = 1; // future lockTime
                if (tx->inputs[j].sequence < UINT32_MAX && tx->lockTime > now) isPending = 1; // future lockTime
                if (BRSetContains(wallet->pendingTx, &tx->inputs[j].txHash)) isPending = 1; // check for pending inputs
            }
            
            if (isPending) {
                BRSetAdd(wallet->pendingTx, tx);

                // A pending tx's outputs are not credited -- but the wallet must still record
                // which of its addresses were PAID, or an unconfirmed receive never marks the
                // address used and the Receive screen keeps handing out the same address.
                //
                // This matters disproportionately for DigiDollar: a DD token output is
                // zero-value by protocol (the dollar amount lives in the OP_RETURN), so it
                // ALWAYS trips the dust check above. Before this, the `continue` skipped the
                // whole output loop and an unconfirmed DD receive left no trace at all in the
                // wallet's address bookkeeping. A plain DGB receive is credited at 0-conf, so
                // for DGB a late confirmation is only cosmetic -- which is exactly why the
                // "missed receive" symptom looked DigiDollar-specific.
                //
                // Credit is still withheld until the tx confirms; only the used-address
                // bookkeeping happens here.
                for (j = 0; j < tx->outCount; j++) {
                    if (tx->outputs[j].address[0] != '\0')
                        BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);
                }

                array_add(wallet->balanceHist, balance);
                continue;
            }
        }

        // A coin-generation output is spendable only once the tip is at least the maturity
        // depth past the coin's own height (tip >= H + maturity; the reference wallet's
        // convention). An unconfirmed one is immature by definition. Decided once per tx.
#ifdef COINBASE_MATURITY_UNFIXED
        isCoinbase = 0;   // comparison arm: coin-generation outputs credited like any other
#else
        isCoinbase = _BRTxIsCoinbase(tx);
#endif
        immature = 0;
        if (isCoinbase) {
            if (tx->blockHeight == TX_UNCONFIRMED) {
                immature = 1;
            }
            else {
                matureAt = tx->blockHeight + _BRCoinbaseMaturity(tx->blockHeight);
                immature = (wallet->blockHeight < matureAt) ? 1 : 0;
            }
        }

        // add outputs to UTXO set
        // TODO: don't add outputs below TX_MIN_OUTPUT_AMOUNT
        for (j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') {
                BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);

                if (BRSetContains(wallet->allAddrs, tx->outputs[j].address)) {
                    if (isCoinbase) {
                        coinbaseOutputs++;

                        if (immature) {
                            // carried separately; never in utxos/ddUtxos/assetUtxos or balance.
                            // The address is still recorded as used (above).
                            immatureBalance = _BRMoneyAdd(immatureBalance, tx->outputs[j].amount);
                            if (tx->blockHeight != TX_UNCONFIRMED && matureAt < nextMaturity) nextMaturity = matureAt;
                            continue;
                        }
                    }

                    // If the tx contains an asset, we will skip the DUST transactions,
                    // otherwise there would be a chance of burning the received assets.
                    // Hence, skip adding the 600 dsatoshi transactions to the utxos.
#if DEBUG
                    printf("ASSETS: Checking %s:%d\n", u256hex(UInt256Reverse(tx->txHash)), j);
#endif
                    // A DigiDollar-shaped output is credited only when confirmed at or above the
                    // network's DigiDollar activation floor (BRNetworkDigiDollarActivationHeight,
                    // keyed on the coin's height like the reference client). Below it the output
                    // is ordinary history: it falls through to the asset and plain branches.
#ifdef DD_ACTIVATION_FLOOR_UNFIXED
                    int64_t ddCents = BRDigiDollarOutputAmount(tx, (uint32_t)j);   // comparison arm: no floor
#else
                    int64_t ddCents = (tx->blockHeight != TX_UNCONFIRMED && tx->blockHeight >= ddFloor) ?
                                      BRDigiDollarOutputAmount(tx, (uint32_t)j) : -1;
#endif
                    if (ddCents >= 0) {
                        array_add(wallet->ddUtxos, ((BRUTXO) { tx->txHash, (uint32_t)j }));
                        ddBalance += (uint64_t)ddCents;
                        balance += 0; // DD tokens are zero-value; never touch the DGB balance
                    } else if (BRTxOutputIsAsset(tx, &tx->outputs[j]) ||
                               _BRWalletIsAssetOverride(wallet, tx->txHash, (uint32_t)j)) {
                        // Held: an output an asset instruction names, one the asset layer
                        // registered, or any output of a transaction whose DigiAsset carrier
                        // cannot be classified (BRTxOutputIsAsset fails closed on those).
                        array_add(wallet->assetUtxos, ((BRUTXO) { tx->txHash, (uint32_t)j }));
                        balance += 0;
                    } else {
                        // Add the UTXO to the internal list of utxos and add the balance
                        array_add(wallet->utxos, ((BRUTXO) { tx->txHash, (uint32_t)j }));
                        balance = _BRMoneyAdd(balance, tx->outputs[j].amount);
                    }
                }
            } else {
                balance += 0;
            }
        }
        // transaction ordering is not guaranteed, so check the entire UTXO set against the entire spent output set
        for (j = array_count(wallet->utxos); j > 0; j--) {
            t = BRSetGet(wallet->allTx, &wallet->utxos[j - 1].hash);
            o = t->outputs[wallet->utxos[j - 1].n];
            if (BRSetContains(wallet->spentOutputs, &wallet->utxos[j - 1])) {
                balance = _BRMoneySub(balance, o.amount);
                array_rm(wallet->utxos, j - 1);
            }
        }
        
        if (prevBalance < balance) wallet->totalReceived += balance - prevBalance;
        if (balance < prevBalance) wallet->totalSent += prevBalance - balance;
        array_add(wallet->balanceHist, balance);
        prevBalance = balance;
    }

    //No longer applicable, balance is not for all transactions considering assets
    assert(array_count(wallet->balanceHist) == array_count(wallet->transactions));

    // prune spent DD UTXOs so ddBalance is spendable, not cumulative (spentOutputs is
    // fully populated after the tx loop). Mirrors the DGB utxo prune at :269-276.
    for (j = array_count(wallet->ddUtxos); j > 0; j--) {
        if (BRSetContains(wallet->spentOutputs, &wallet->ddUtxos[j - 1])) {
            BRTransaction *dt = BRSetGet(wallet->allTx, &wallet->ddUtxos[j - 1].hash);
            int64_t c = dt ? BRDigiDollarOutputAmount(dt, wallet->ddUtxos[j - 1].n) : -1;
            if (c > 0 && ddBalance >= (uint64_t)c) ddBalance -= (uint64_t)c;
            array_rm(wallet->ddUtxos, j - 1);
        }
    }
    wallet->ddBalance = ddBalance;
    wallet->immatureBalance = immatureBalance;
    wallet->nextMaturityHeight = nextMaturity;
    wallet->coinbaseOutputs = coinbaseOutputs;
    wallet->balance = balance;
}

// Raises wallet->blockHeight to the highest confirmed height among the loaded transactions so a
// restored wallet evaluates maturity against a tip it has evidence for, rather than 0, until the
// peer manager pushes the real tip. Never lowers it. Caller holds wallet->lock (or is inside
// BRWalletNew before the wallet is shared).
static void _BRWalletSeedBlockHeight(BRWallet *wallet)
{
    for (size_t i = 0; i < array_count(wallet->transactions); i++) {
        uint32_t h = wallet->transactions[i]->blockHeight;

        if (h != TX_UNCONFIRMED && h > wallet->blockHeight) wallet->blockHeight = h;
    }
}

// allocates and populates a BRWallet struct which must be freed by calling BRWalletFree()
BRWallet *BRWalletNew(BRTransaction *transactions[], size_t txCount, BRMasterPubKey mpk)
{
    BRWallet *wallet = NULL;
    BRTransaction *tx;

    assert(transactions != NULL || txCount == 0);
    wallet = calloc(1, sizeof(*wallet));
    assert(wallet != NULL);
    array_new(wallet->utxos, 100);
    array_new(wallet->assetUtxos, 30);
    array_new(wallet->assetOverrides, 10);
    array_new(wallet->ddUtxos, 30);
    array_new(wallet->transactions, txCount + 100);
    wallet->feePerKb = DEFAULT_FEE_PER_KB;
    wallet->masterPubKey = mpk;
    wallet->addrGen = _brNextAddrGen();   // distinct from every prior wallet in this process
    array_new(wallet->internalChain, 50);
    array_new(wallet->externalChain, 50);
    array_new(wallet->internalChainSegwit, 50);
    array_new(wallet->externalChainSegwit, 50);
    wallet->hasLegacyKey = 0;
    array_new(wallet->legacyExternalChain, 50);
    array_new(wallet->legacyInternalChain, 50);
    array_new(wallet->legacyExternalChainSegwit, 50);
    array_new(wallet->legacyInternalChainSegwit, 50);
    array_new(wallet->taprootExternalChain, 50);
    array_new(wallet->taprootInternalChain, 50);
    array_new(wallet->watchedAddrs, 16);
    wallet->hasTaprootKey = 0;
    array_new(wallet->balanceHist, txCount + 100);
    wallet->allTx = BRSetNew(BRTransactionHash, BRTransactionEq, txCount + 100);
    wallet->invalidTx = BRSetNew(BRTransactionHash, BRTransactionEq, 10);
    wallet->pendingTx = BRSetNew(BRTransactionHash, BRTransactionEq, 10);
    wallet->spentOutputs = BRSetNew(BRUTXOHash, BRUTXOEq, txCount + 100);
    wallet->usedAddrs = BRSetNew(BRAddressHash, BRAddressEq, txCount + 100);
    wallet->allAddrs = BRSetNew(BRAddressHash, BRAddressEq, txCount + 100);
    pthread_mutex_init(&wallet->lock, NULL);

    for (size_t i = 0; transactions && i < txCount; i++) {
        tx = transactions[i];
        if (! BRTransactionIsSigned(tx) || BRSetContains(wallet->allTx, tx)) continue;
        if (! _BRWalletTxMoneyRangeOK(tx)) continue;   // never a valid transaction: not loaded
        BRSetAdd(wallet->allTx, tx);
        _BRWalletInsertTx(wallet, tx);

        for (size_t j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);
        }
    }

    _BRWalletSeedBlockHeight(wallet);

    // +100 buffer past each chain's standard gap limit so in-flight
    // change addresses generated by a publishTransaction that happened
    // *after* the last saved_transactions snapshot are still in
    // allAddrs when the peer relays the tx back post-restart.
    // Without the +100, a force-stop between broadcast and the next
    // sync-complete save would leave the change address outside the
    // watch set; BRWalletRegisterTransaction would then silently
    // reject the relayed tx, and the user's balance regresses by
    // the full input value (not just the send amount). Matches the
    // bloom-filter look-ahead at BRPeerManager.c:318-321.
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 1);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 1);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 0);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 0);
    _BRWalletUpdateBalance(wallet);

    if (txCount > 0 && ! _BRWalletContainsTx(wallet, transactions[0])) { // verify transactions match master pubKey
        BRWalletFree(wallet);
        wallet = NULL;
    }
    
    return wallet;
}

// internal helper: generate up to 'count' addresses from mpk on chain/nativeSegwit,
// add them to addrChain and wallet->allAddrs
static void _BRWalletPregenLegacyChain(BRWallet *wallet, BRAddress **addrChainPtr,
                                        BRMasterPubKey mpk, uint32_t chain,
                                        int nativeSegwit, uint32_t count)
{
    BRAddress *addrChain = *addrChainPtr;
    uint32_t startCount = (uint32_t)array_count(addrChain);
    for (uint32_t idx = startCount; idx < count; idx++) {
        BRKey key;
        BRAddress address = BR_ADDRESS_NONE;
        uint8_t pubKey[BRBIP32PubKey(NULL, 0, mpk, chain, idx)];
        size_t len = BRBIP32PubKey(pubKey, sizeof(pubKey), mpk, chain, idx);
        if (! BRKeySetPubKey(&key, pubKey, len)) break;
        if (nativeSegwit) {
            if (! BRKeySegwitAddress(&key, address.s, sizeof(address), OP_0) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        } else {
            if (! BRKeyAddress(&key, address.s, sizeof(address)) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        }
        array_add(addrChain, address);
        wallet->addrGen = _brNextAddrGen();   // enumerated address set changed
    }
    // Add to allAddrs only AFTER the array has reached its final size. array_add()
    // above reallocs the chain when it grows past its initial capacity (50); with
    // count=150 (SEQUENCE_GAP_LIMIT_EXTERNAL_LEGACY) that realloc ALWAYS happens
    // mid-loop. Storing &addrChain[i] into allAddrs inside the loop left pointers into
    // the pre-realloc (freed) block — a use-after-free that crashed
    // BRWalletContainsAddress (strlen on freed memory) and corrupted address matching
    // once the freed block was reused. Re-point from the final base here. This chain
    // starts empty at init (startCount==0), so every entry is (re)added from the
    // stable location. Regression-guarded by legacy_gap_uaf_kat (ASan).
    for (uint32_t idx = startCount; idx < (uint32_t)array_count(addrChain); idx++) {
        BRSetAdd(wallet->allAddrs, &addrChain[idx]);
    }
    *addrChainPtr = addrChain;
}

// allocates a wallet with dual master key support for BIP84 migration
// mpkBIP84  — BIP84 master pub key (m/84'/20'/0', "Bitcoin seed") — primary key for new addresses
// mpkLegacy — legacy master pub key (m/0H, "DigiByte seed") — used only for recovery scanning
BRWallet *BRWalletNewDual(BRTransaction *transactions[], size_t txCount,
                          BRMasterPubKey mpkBIP84, BRMasterPubKey mpkLegacy)
{
    // CRITICAL: Create wallet EMPTY first, then register legacy addresses,
    // THEN add transactions. If transactions are passed to BRWalletNew before
    // legacy addresses exist, old transactions (which reference m/0H addresses)
    // are rejected because the wallet only knows BIP84 addresses at that point.
    BRWallet *wallet = BRWalletNew(NULL, 0, mpkBIP84);
    if (! wallet) return NULL;

    // Install legacy key and pre-generate legacy addresses BEFORE adding transactions
    wallet->legacyPubKey = mpkLegacy;
    wallet->hasLegacyKey = 1;

    pthread_mutex_lock(&wallet->lock);

    _BRWalletPregenLegacyChain(wallet, &wallet->legacyExternalChain,
                               mpkLegacy, SEQUENCE_EXTERNAL_CHAIN, 0,
                               SEQUENCE_GAP_LIMIT_EXTERNAL_LEGACY);
    _BRWalletPregenLegacyChain(wallet, &wallet->legacyInternalChain,
                               mpkLegacy, SEQUENCE_INTERNAL_CHAIN, 0,
                               SEQUENCE_GAP_LIMIT_INTERNAL_LEGACY);
    _BRWalletPregenLegacyChain(wallet, &wallet->legacyExternalChainSegwit,
                               mpkLegacy, SEQUENCE_EXTERNAL_CHAIN, 1,
                               SEQUENCE_GAP_LIMIT_EXTERNAL_LEGACY);
    _BRWalletPregenLegacyChain(wallet, &wallet->legacyInternalChainSegwit,
                               mpkLegacy, SEQUENCE_INTERNAL_CHAIN, 1,
                               SEQUENCE_GAP_LIMIT_INTERNAL_LEGACY);

    pthread_mutex_unlock(&wallet->lock);

    // NOW bulk-add saved transactions — use the same trusted approach as
    // BRWalletNew: add ALL transactions to allTx and usedAddrs first,
    // THEN update balance. This avoids _BRWalletContainsTx rejecting
    // child transactions whose parent txs haven't been registered yet
    // (which caused send transactions to be silently dropped).
    if (transactions && txCount > 0) {
        pthread_mutex_lock(&wallet->lock);
        for (size_t i = 0; i < txCount; i++) {
            BRTransaction *tx = transactions[i];
            if (! tx || ! BRTransactionIsSigned(tx) || BRSetContains(wallet->allTx, tx)) continue;
            if (! _BRWalletTxMoneyRangeOK(tx)) continue;   // never a valid transaction: not loaded
            BRSetAdd(wallet->allTx, tx);
            _BRWalletInsertTx(wallet, tx);

            for (size_t j = 0; j < tx->outCount; j++) {
                if (tx->outputs[j].address[0] != '\0') BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);
            }
        }
        _BRWalletSeedBlockHeight(wallet);
        pthread_mutex_unlock(&wallet->lock);

        // Extend BIP84 chains past every used address before computing balance.
        // Without this, _BRWalletUpdateBalance skips outputs whose addresses
        // are beyond the gap-limit window pre-genned by BRWalletNew(NULL,0,…)
        // above — the wallet shows full tx history but balance == 0 until a
        // later SPV register fires this same extension as a side effect.
        // +100 buffer past the standard gap matches the bloom-filter
        // look-ahead so in-flight change addresses from a publishTransaction
        // that didn't make it into saved_transactions are still in allAddrs
        // when the peer relays the tx back post-restart.
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 1);
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 1);
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 0);
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 0);

        pthread_mutex_lock(&wallet->lock);
        _BRWalletUpdateBalance(wallet);
        pthread_mutex_unlock(&wallet->lock);
    }

    return wallet;
}

// installs the BIP86 Taproot master pub key and pre-generates the P2TR external + internal
// gap windows. See BRWallet.h for the fund-safety contract (taprootMpk must be the m/86'
// twin of the wallet's own seed). Call once, right after wallet creation, before syncing.
void BRWalletSetTaprootKey(BRWallet *wallet, BRMasterPubKey taprootMpk)
{
    assert(wallet != NULL);

    wallet->taprootPubKey = taprootMpk;
    wallet->hasTaprootKey = 1;

    // Pre-generate gap+100 P2TR receive (external) + change (internal) addresses over the
    // m/86' key (scriptType 2). The +100 look-ahead mirrors BRWalletNew's BIP84/legacy
    // pre-gen so a taproot address that a relayed-back tx pays is already in allAddrs
    // post-restart. Uses the PLAIN gap constants (matches BRWallet.c:345-348). Do NOT hold
    // wallet->lock here — BRWalletUnusedAddrs takes it internally (non-recursive).
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL + 100, 0, 2);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL + 100, 1, 2);

    // Re-run the balance computation now that the taproot (m/86') addresses are in
    // wallet->allAddrs. On the recover path (recoverWalletFromBytes → BRWalletNewDual →
    // BRWalletSetTaprootKey), BRWalletNewDual has already bulk-loaded the saved
    // transactions and run _BRWalletUpdateBalance while hasTaprootKey==0 and the taproot
    // chains were empty — so any saved P2TR output failed
    // BRSetContains(wallet->allAddrs, output.address) and was dropped from utxos/balance
    // (the "post-upgrade zero-balance" failure class, here for Taproot receives; a resync
    // does NOT recover it because the relayed-back tx is already in allTx and
    // BRWalletRegisterTransaction early-returns without recomputing). Now that the P2TR
    // addresses are registered, re-scan the wallet's transactions so those outputs are
    // credited immediately, without waiting for an unrelated balance event. On the
    // fresh-create path (BRWalletNew, no transactions) this is a harmless no-op.
    // _BRWalletUpdateBalance does not lock internally, so hold wallet->lock here (matches
    // the BRWalletNewDual call site at BRWallet.c:453-455).
    pthread_mutex_lock(&wallet->lock);
    _BRWalletUpdateBalance(wallet);
    pthread_mutex_unlock(&wallet->lock);
}

// returns non-zero if any UTXO in the wallet belongs to the legacy key chains (old m/0H addresses)
int BRWalletHasLegacyFunds(BRWallet *wallet)
{
    assert(wallet != NULL);
    if (! wallet->hasLegacyKey) return 0;

    int r = 0;
    pthread_mutex_lock(&wallet->lock);

    for (size_t i = 0; ! r && i < array_count(wallet->utxos); i++) {
        BRTransaction *tx = BRSetGet(wallet->allTx, &wallet->utxos[i].hash);
        if (! tx || wallet->utxos[i].n >= tx->outCount) continue;
        const char *addr = tx->outputs[wallet->utxos[i].n].address;

        for (size_t j = 0; ! r && j < array_count(wallet->legacyExternalChain); j++) {
            if (strcmp(addr, wallet->legacyExternalChain[j].s) == 0) r = 1;
        }
        for (size_t j = 0; ! r && j < array_count(wallet->legacyInternalChain); j++) {
            if (strcmp(addr, wallet->legacyInternalChain[j].s) == 0) r = 1;
        }
        for (size_t j = 0; ! r && j < array_count(wallet->legacyExternalChainSegwit); j++) {
            if (strcmp(addr, wallet->legacyExternalChainSegwit[j].s) == 0) r = 1;
        }
        for (size_t j = 0; ! r && j < array_count(wallet->legacyInternalChainSegwit); j++) {
            if (strcmp(addr, wallet->legacyInternalChainSegwit[j].s) == 0) r = 1;
        }
    }

    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// not thread-safe, set callbacks once after BRWalletNew(), before calling other BRWallet functions
// info is a void pointer that will be passed along with each callback call
// void balanceChanged(void *, uint64_t) - called when the wallet balance changes
// void txAdded(void *, BRTransaction *) - called when transaction is added to the wallet
// void txUpdated(void *, const UInt256[], size_t, uint32_t, uint32_t)
//   - called when the blockHeight or timestamp of previously added transactions are updated
// void txDeleted(void *, UInt256) - called when a previously added transaction is removed from the wallet
// NOTE: if a transaction is deleted, and BRWalletAmountSentByTx() is greater than 0, recommend the user do a rescan
void BRWalletSetCallbacks(BRWallet *wallet, void *info,
                          void (*balanceChanged)(void *info, uint64_t balance),
                          void (*txAdded)(void *info, BRTransaction *tx),
                          void (*txUpdated)(void *info, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                            uint32_t timestamp),
                          void (*txDeleted)(void *info, UInt256 txHash, int notifyUser, int recommendRescan))
{
    assert(wallet != NULL);
    wallet->callbackInfo = info;
    wallet->balanceChanged = balanceChanged;
    wallet->txAdded = txAdded;
    wallet->txUpdated = txUpdated;
    wallet->txDeleted = txDeleted;
}

// wallets are composed of chains of addresses
// each chain is traversed until a gap of a number of addresses is found that haven't been used in any transactions
// this function writes to addrs an array of <gapLimit> unused addresses following the last used address in the chain
// the internal chain is used for change addresses and the external chain for receive addresses
// addrs may be NULL to only generate addresses for BRWalletContainsAddress()
// returns the number addresses written to addrs
size_t BRWalletUnusedAddrs(BRWallet *wallet, BRAddress addrs[], uint32_t gapLimit, int internal, int scriptType)
{
    // scriptType: 0 = P2PKH (legacy), 1 = P2WPKH (native segwit / BIP84), 2 = P2TR (taproot / BIP86)
    BRAddress *addrChain;
    size_t i, j = 0, count, startCount;
    uint32_t chain = (internal) ? SEQUENCE_INTERNAL_CHAIN : SEQUENCE_EXTERNAL_CHAIN;

    assert(wallet != NULL);
    assert(gapLimit > 0);
    assert(scriptType == 0 || scriptType == 1 || scriptType == 2);
    pthread_mutex_lock(&wallet->lock);

    // No BIP86 key installed → there is no taproot chain to walk. Return early
    // instead of deriving over a zeroed master pubkey, which trips the
    // assert(mpk != BR_MASTER_PUBKEY_NONE) in BRBIP32PubKey under a debug build.
    // Callers that pre-gen the P2TR window before a key exists (bloom filter load,
    // compact-filter peer connect) rely on this being a clean no-op.
    if (scriptType == 2 && ! wallet->hasTaprootKey) {
        pthread_mutex_unlock(&wallet->lock);
        return 0;
    }

    if (scriptType == 2) {
        addrChain = (internal) ? wallet->taprootInternalChain : wallet->taprootExternalChain;
    } else if (scriptType == 1) {
        addrChain = (internal) ? wallet->internalChainSegwit : wallet->externalChainSegwit;
    } else {
        addrChain = (internal) ? wallet->internalChain : wallet->externalChain;
    }
    
    i = count = startCount = array_count(addrChain);
    
    // keep only the trailing contiguous block of addresses with no transactions
    while (i > 0 && ! BRSetContains(wallet->usedAddrs, &addrChain[i - 1])) i--;
    
    // YOSHI: To this point we should be good to go
    // The usedAddrs will contain any addresses (in any format)
    
    while (i + gapLimit > count) { // generate new addresses up to gapLimit
        BRKey key;
        BRAddress address = BR_ADDRESS_NONE;
        
        // Taproot MUST derive over the m/86' taprootPubKey — deriving P2TR over the
        // m/84' masterPubKey would yield unrecoverable (fund-loss) addresses.
        BRMasterPubKey mpk = (scriptType == 2) ? wallet->taprootPubKey : wallet->masterPubKey;

        // Generate the pubkey from seed and write it into pubKey
        uint8_t pubKey[BRBIP32PubKey(NULL, 0, mpk, chain, count)];
        size_t len = BRBIP32PubKey(pubKey, sizeof(pubKey), mpk, chain, (uint32_t)count);

        // Convert pubKey to internal format
        if (! BRKeySetPubKey(&key, pubKey, len)) break;

        if (scriptType == 2) {
            // Generate the P2TR (taproot, dgb1p...)
            if (!BRKeyTaprootAddress(&key, address.s, sizeof(address)) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        } else if (scriptType == 1) {
            // Generate the P2WPKH
            if (!BRKeySegwitAddress(&key, address.s, sizeof(address), OP_0) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        } else {
            // Generate the P2PKH
            if (!BRKeyAddress(&key, address.s, sizeof(address)) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        }
        
        array_add(addrChain, address);
        wallet->addrGen = _brNextAddrGen();   // enumerated address set changed
        count++;
        
        // Address is already used
        if (BRSetContains(wallet->usedAddrs, &address)) i = count;
    }

    if (addrs && i + gapLimit <= count) {
        for (j = 0; j < gapLimit; j++) {
            addrs[j] = addrChain[i + j];
        }
    }
    
    // was addrChain moved to a new memory location?
    if (addrChain == (internal ? wallet->internalChain : wallet->externalChain) ||
        addrChain == (internal ? wallet->internalChainSegwit : wallet->externalChainSegwit) ||
        addrChain == (internal ? wallet->taprootInternalChain : wallet->taprootExternalChain)) {
        for (i = startCount; i < count; i++) {
            BRSetAdd(wallet->allAddrs, &addrChain[i]);
        }
    }
    else {
        // Reassign the addressChain, if it got reallocated
        if (scriptType == 2) {
            if (internal) wallet->taprootInternalChain = addrChain;
            if (! internal) wallet->taprootExternalChain = addrChain;
        } else if (scriptType == 1) {
            if (internal) wallet->internalChainSegwit = addrChain;
            if (! internal) wallet->externalChainSegwit = addrChain;
        } else {
            if (internal) wallet->internalChain = addrChain;
            if (! internal) wallet->externalChain = addrChain;
        }
        
        // Clear and rebuild allAddrs
        BRSetClear(wallet->allAddrs);

        for (i = array_count(wallet->internalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->internalChain[i - 1]);
        }
        
        for (i = array_count(wallet->externalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->externalChain[i - 1]);
        }
        
        for (i = array_count(wallet->internalChainSegwit); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->internalChainSegwit[i - 1]);
        }

        for (i = array_count(wallet->externalChainSegwit); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->externalChainSegwit[i - 1]);
        }

        // Legacy chains (previously OMITTED — any array-growth realloc silently evicted
        // recovery addresses from allAddrs, hiding incoming funds on old m/0H paths).
        for (i = array_count(wallet->legacyInternalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->legacyInternalChain[i - 1]);
        }

        for (i = array_count(wallet->legacyExternalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->legacyExternalChain[i - 1]);
        }

        for (i = array_count(wallet->legacyInternalChainSegwit); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->legacyInternalChainSegwit[i - 1]);
        }

        for (i = array_count(wallet->legacyExternalChainSegwit); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->legacyExternalChainSegwit[i - 1]);
        }

        // Taproot chains (empty/dormant until the BIP86 key is installed).
        for (i = array_count(wallet->taprootInternalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->taprootInternalChain[i - 1]);
        }

        for (i = array_count(wallet->taprootExternalChain); i > 0; i--) {
            BRSetAdd(wallet->allAddrs, &wallet->taprootExternalChain[i - 1]);
        }
    }

    pthread_mutex_unlock(&wallet->lock);
    return j;
}

// current wallet balance, not including transactions known to be invalid
uint64_t BRWalletBalance(BRWallet *wallet)
{
    uint64_t balance;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    balance = wallet->balance;
    pthread_mutex_unlock(&wallet->lock);
    return balance;
}

// DigiDollar balance in CENTS (USD). Separate from BRWalletBalance (satoshis).
uint64_t BRWalletDigiDollarBalance(BRWallet *wallet)
{
    uint64_t b;
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    b = wallet->ddBalance;
    pthread_mutex_unlock(&wallet->lock);
    return b;
}

// value of the wallet's coin-generation outputs that are not yet spendable (the chain tip is
// below coin height + maturity). Not part of BRWalletBalance; moves into it as the tip advances.
uint64_t BRWalletImmatureBalance(BRWallet *wallet)
{
    uint64_t b;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    b = wallet->immatureBalance;
    pthread_mutex_unlock(&wallet->lock);
    return b;
}

// writes unspent outputs to utxos and returns the number of outputs written, or total number available if utxos is NULL
size_t BRWalletUTXOs(BRWallet *wallet, BRUTXO *utxos, size_t utxosCount)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (! utxos || array_count(wallet->utxos) < utxosCount) utxosCount = array_count(wallet->utxos);

    for (size_t i = 0; utxos && i < utxosCount; i++) {
        utxos[i] = wallet->utxos[i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return utxosCount;
}

// populates utxos with the wallet's unspent DigiDollar token outputs and returns their
// number. Returns the count if utxos is NULL. (Pair each with BRDigiDollarOutputAmount for cents.)
size_t BRWalletDigiDollarUTXOs(BRWallet *wallet, BRUTXO *utxos, size_t utxosCount)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (! utxos || array_count(wallet->ddUtxos) < utxosCount) utxosCount = array_count(wallet->ddUtxos);
    for (size_t i = 0; utxos && i < utxosCount; i++) utxos[i] = wallet->ddUtxos[i];
    pthread_mutex_unlock(&wallet->lock);
    return utxosCount;
}

// true if the outpoint (txHash, n) is in the spentOutputs set. spentOutputs is
// cleared and rebuilt on every _BRWalletUpdateBalance from every registered
// tx's inputs (see BRSetAdd(wallet->spentOutputs, &tx->inputs[j])), so it is
// authoritative for spends of ALL output kinds including DigiAsset markers —
// unlike wallet->assetUtxos, which is never pruned of spends.
int BRWalletOutpointSpent(BRWallet *wallet, UInt256 txHash, uint32_t n)
{
    assert(wallet != NULL);
    BRUTXO o = { txHash, n };
    pthread_mutex_lock(&wallet->lock);
    int spent = BRSetContains(wallet->spentOutputs, &o) ? 1 : 0;
    pthread_mutex_unlock(&wallet->lock);
    return spent;
}

// writes transactions registered in the wallet, sorted by date, oldest first, to the given transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t BRWalletTransactions(BRWallet *wallet, BRTransaction *transactions[], size_t txCount)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (! transactions || array_count(wallet->transactions) < txCount) txCount = array_count(wallet->transactions);

    for (size_t i = 0; transactions && i < txCount; i++) {
        transactions[i] = wallet->transactions[i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return txCount;
}

// Serializes ALL registered transactions into `buf` as a single persistence blob,
// oldest-first, holding wallet->lock across BOTH the sizing pass and the write pass.
//
// This is the lock-safe replacement for the old getSerializedTransactions JNI shape
// (BRWalletTransactions to COPY raw BRTransaction* pointers, unlock, then serialize the
// copies) — the SAME lock-release-then-use class as the saveBlocks race. Because a
// BRTransaction can be freed under wallet->lock by BRWalletRemoveTransaction (at-tip
// cleanup / reconcile), serializing a copied-out pointer with the lock released is a
// use-after-free. Here every dereference of wallet->transactions[i] happens inside one
// lock hold, so no tx can be freed mid-serialize. BRTransactionSerialize is a pure read
// of the tx (no wallet re-entry, no callback, no other lock), so holding wallet->lock
// across it introduces no lock-ordering inversion.
//
// Wire layout (byte-identical to the previous getSerializedTransactions output, so
// persisted `saved_transactions` blobs stay round-trip compatible with
// loadSerializedTransactions):
//   [4] tx count (LE)
//   per tx: [4] serialized length (LE)  [4] blockHeight (LE)  [4] timestamp (LE)  [N] tx bytes
//
// Two-pass (size then fill) contract: if buf == NULL, or bufLen is too small to hold the
// whole blob, nothing is written and the total number of bytes REQUIRED is returned (query
// the size with buf == NULL, malloc it, then call again). When the blob fits, it is written
// and the number of bytes WRITTEN is returned (== the required size). The caller distinguishes
// "written" from "needs a bigger buffer" by comparing the return value against bufLen.
size_t BRWalletSerializeTransactions(BRWallet *wallet, uint8_t *buf, size_t bufLen)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    size_t txCount = array_count(wallet->transactions);

    // size pass (under the lock): count header + per-tx (len + height + timestamp + data)
    size_t totalSize = 4;
    for (size_t i = 0; i < txCount; i++) {
        totalSize += 4 + 4 + 4 + BRTransactionSerialize(wallet->transactions[i], NULL, 0);
    }

    // size-only query, or buffer too small: report the required size, write nothing.
    if (! buf || bufLen < totalSize) {
        pthread_mutex_unlock(&wallet->lock);
        return totalSize;
    }

    // write pass (same lock hold — the size just computed cannot go stale)
    size_t pos = 0;
    UInt32SetLE(&buf[pos], (uint32_t)txCount); pos += 4;
    for (size_t i = 0; i < txCount; i++) {
        BRTransaction *tx = wallet->transactions[i];
        size_t len = BRTransactionSerialize(tx, NULL, 0);
        UInt32SetLE(&buf[pos], (uint32_t)len);       pos += 4;
        UInt32SetLE(&buf[pos], tx->blockHeight);     pos += 4;
        UInt32SetLE(&buf[pos], tx->timestamp);       pos += 4;
        BRTransactionSerialize(tx, &buf[pos], len);  pos += len;
    }

    pthread_mutex_unlock(&wallet->lock);
    return pos; // == totalSize
}

// writes transactions registered in the wallet, and that were unconfirmed before blockHeight, to the transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t BRWalletTxUnconfirmedBefore(BRWallet *wallet, BRTransaction *transactions[], size_t txCount,
                                   uint32_t blockHeight)
{
    size_t total, n = 0;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    total = array_count(wallet->transactions);
    while (n < total && wallet->transactions[(total - n) - 1]->blockHeight >= blockHeight) n++;
    if (! transactions || n < txCount) txCount = n;

    for (size_t i = 0; transactions && i < txCount; i++) {
        transactions[i] = wallet->transactions[(total - n) + i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return txCount;
}

// total amount spent from the wallet (exluding change)
uint64_t BRWalletTotalSent(BRWallet *wallet)
{
    uint64_t totalSent;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    totalSent = wallet->totalSent;
    pthread_mutex_unlock(&wallet->lock);
    return totalSent;
}

// total amount received by the wallet (exluding change)
uint64_t BRWalletTotalReceived(BRWallet *wallet)
{
    uint64_t totalReceived;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    totalReceived = wallet->totalReceived;
    pthread_mutex_unlock(&wallet->lock);
    return totalReceived;
}

// fee-per-kb of transaction size to use when creating a transaction
uint64_t BRWalletFeePerKb(BRWallet *wallet)
{
    uint64_t feePerKb;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    feePerKb = wallet->feePerKb;
    pthread_mutex_unlock(&wallet->lock);
    return feePerKb;
}

void BRWalletSetFeePerKb(BRWallet *wallet, uint64_t feePerKb)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    wallet->feePerKb = feePerKb;
    pthread_mutex_unlock(&wallet->lock);
}

// returns the first unused external address
BRAddress BRWalletReceiveAddress(BRWallet *wallet, int useSegwitAddress)
{
    BRAddress addr = BR_ADDRESS_NONE;
    
    BRWalletUnusedAddrs(wallet, &addr, 1, 0, useSegwitAddress);
    return addr;
}

// returns the first unused internal address
BRAddress BRWalletInternalChangeAddress(BRWallet *wallet)
{
    BRAddress addr = BR_ADDRESS_NONE;
    
    BRWalletUnusedAddrs(wallet, &addr, 1, 1, 1);
    return addr;
}

// Is watched entry i emitted in the watched tail? CALLER MUST HOLD wallet->lock.
//
// Each address is listed once. BRWalletAddWatchedAddress first resolves a pin into the derived
// set when it belongs to one of the wallet's chains, and a derived address is already emitted by
// its chain, so the tail carries only pins that are NOT derived. allAddrs is exactly the union of
// the derived chains enumerated below (legacy chains are populated only with the legacy key,
// taproot chains only with the BIP86 key), so membership in it is "already emitted above"; a
// skipped pin therefore loses no address and no filter element.
static int _BRWalletWatchedTailEmitsLocked(BRWallet *wallet, size_t i)
{
#ifdef ADDR_SET_DISTINCT_UNFIXED
    (void)wallet; (void)i;   // comparison arm only (host KAT): the tail emitted whole
    return 1;
#else
    return BRSetContains(wallet->allAddrs, wallet->watchedAddrs[i].s) ? 0 : 1;
#endif
}

// Enumerate every address chain in the canonical emission order:
//   primary BIP84 (internal segwit, internal legacy, external segwit, external legacy),
//   then the legacy m/0H chains, then the BIP86 taproot chains, then the explicitly-watched
//   tail. The taproot chains are the SOLE source of P2TR (and therefore DigiDollar) filter
//   elements, so they MUST be enumerated or a received P2TR is never watched/credited.
//
// Every address appears once: the watched tail holds only the pins that are not derived
// (_BRWalletWatchedTailEmitsLocked). Pinned by addr_set_distinct_kat.
//
// CALLER MUST HOLD wallet->lock.
//
// out == NULL : returns the TOTAL available, unclamped (outCount ignored).
// out != NULL : writes at most outCount entries — every write bounds-checked against
//               outCount, so a set larger than the caller's buffer TRUNCATES rather than
//               overrunning it — and returns the number actually written.
// origins, if non-NULL, receives the derived/watched split of whatever was counted or written.
static size_t _BRWalletCollectAddrsLocked(BRWallet *wallet, BRAddress *out, size_t outCount,
                                          BRWalletAddrOrigins *origins)
{
    BRAddress *chains[10];
    size_t counts[10];
    size_t nchains = 0, total = 0, derivedTotal = 0, watchedTotal = 0, c, i;

    chains[nchains] = wallet->internalChainSegwit;
    counts[nchains++] = array_count(wallet->internalChainSegwit);
    chains[nchains] = wallet->internalChain;
    counts[nchains++] = array_count(wallet->internalChain);
    chains[nchains] = wallet->externalChainSegwit;
    counts[nchains++] = array_count(wallet->externalChainSegwit);
    chains[nchains] = wallet->externalChain;
    counts[nchains++] = array_count(wallet->externalChain);

    if (wallet->hasLegacyKey) { // populated only by BRWalletNewDual
        chains[nchains] = wallet->legacyInternalChainSegwit;
        counts[nchains++] = array_count(wallet->legacyInternalChainSegwit);
        chains[nchains] = wallet->legacyInternalChain;
        counts[nchains++] = array_count(wallet->legacyInternalChain);
        chains[nchains] = wallet->legacyExternalChainSegwit;
        counts[nchains++] = array_count(wallet->legacyExternalChainSegwit);
        chains[nchains] = wallet->legacyExternalChain;
        counts[nchains++] = array_count(wallet->legacyExternalChain);
    }

    if (wallet->hasTaprootKey) { // populated only by BRWalletSetTaprootKey
        chains[nchains] = wallet->taprootInternalChain;
        counts[nchains++] = array_count(wallet->taprootInternalChain);
        chains[nchains] = wallet->taprootExternalChain;
        counts[nchains++] = array_count(wallet->taprootExternalChain);
    }

    // everything enumerated so far is derived (and signable); the watched tail follows
    for (c = 0; c < nchains; c++) derivedTotal += counts[c];
    for (i = 0; i < array_count(wallet->watchedAddrs); i++) {
        if (_BRWalletWatchedTailEmitsLocked(wallet, i)) watchedTotal++;
    }
    total = derivedTotal + watchedTotal;

    if (! out) {
        if (origins) { origins->derived = derivedTotal; origins->watched = watchedTotal; }
        return total;
    }

    size_t written = 0, writtenDerived = 0;
    for (c = 0; c < nchains && written < outCount; c++) {
        for (i = 0; i < counts[c] && written < outCount; i++) {
            out[written++] = chains[c][i];
            writtenDerived++;
        }
    }
    for (i = 0; i < array_count(wallet->watchedAddrs) && written < outCount; i++) {
        if (_BRWalletWatchedTailEmitsLocked(wallet, i)) out[written++] = wallet->watchedAddrs[i];
    }

    if (origins) { origins->derived = writtenDerived; origins->watched = written - writtenDerived; }
    return written;
}

// writes all addresses previously genereated with BRWalletUnusedAddrs() to addrs
// see BRWallet.h for the two-branch return contract (addrs==NULL sizes, addrs!=NULL fills)
size_t BRWalletAllAddrs(BRWallet *wallet, BRAddress addrs[], size_t addrsCount)
{
    size_t r;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    r = _BRWalletCollectAddrsLocked(wallet, addrs, addrs ? addrsCount : 0, NULL);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// Single-call snapshot — no window between sizing and filling. See BRWallet.h for the
// deadlock rationale behind allocating inside the lock.
size_t BRWalletAllAddrsCount(BRWallet *wallet)
{
    size_t n;

    if (! wallet) return 0;
    pthread_mutex_lock(&wallet->lock);
    n = _BRWalletCollectAddrsLocked(wallet, NULL, 0, NULL);   // sizing pass only: no encode, no malloc
    pthread_mutex_unlock(&wallet->lock);
    return n;
}

void BRWalletAddrSetKey(BRWallet *wallet, uint64_t *outGen, size_t *outCount)
{
    if (outGen) *outGen = 0;
    if (outCount) *outCount = 0;
    if (! wallet) return;

    // BOTH fields under ONE hold: read separately they could straddle an append and
    // produce a pair that never actually existed, which is exactly the stale-key hazard
    // this accessor is meant to close.
    pthread_mutex_lock(&wallet->lock);
    if (outGen) *outGen = wallet->addrGen;
    if (outCount) *outCount = _BRWalletCollectAddrsLocked(wallet, NULL, 0, NULL);
    pthread_mutex_unlock(&wallet->lock);
}

BRAddress *BRWalletCopyAllAddrs(BRWallet *wallet, size_t *countOut, BRWalletAddrOrigins *originsOut)
{
    BRAddress *addrs = NULL;
    size_t total, written = 0;

    if (countOut) *countOut = 0;
    if (originsOut) { originsOut->derived = 0; originsOut->watched = 0; }
    if (! wallet) return NULL;

    pthread_mutex_lock(&wallet->lock);
    // Both calls run under the SAME hold, so `total` cannot go stale before the fill.
    total = _BRWalletCollectAddrsLocked(wallet, NULL, 0, NULL);
    if (total > 0) {
        addrs = (BRAddress *)malloc(total * sizeof(*addrs));
        if (addrs) written = _BRWalletCollectAddrsLocked(wallet, addrs, total, originsOut);
    }
    pthread_mutex_unlock(&wallet->lock);

    if (! addrs || written == 0) {
        free(addrs);                  // NULL-safe; also covers the total>0 but written==0 case
        if (originsOut) { originsOut->derived = 0; originsOut->watched = 0; }
        return NULL;
    }

    if (countOut) *countOut = written;
    return addrs;
}

// true if the address was previously generated by BRWalletUnusedAddrs() (even if it's now used)
int BRWalletContainsAddress(BRWallet *wallet, const char *addr)
{
    int r = 0;

    assert(wallet != NULL);
    assert(addr != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (addr) {
        r = BRSetContains(wallet->allAddrs, addr);
        // Also check the explicitly-watched set (Receive-screen addresses that may
        // have fallen outside the derived gap window). Linear scan — this set is
        // small and BRAddress.s is a fixed inline buffer, so no dangling risk.
        for (size_t i = 0; ! r && i < array_count(wallet->watchedAddrs); i++) {
            if (strncmp(wallet->watchedAddrs[i].s, addr, sizeof(wallet->watchedAddrs[i].s)) == 0) r = 1;
        }
    }
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// Register an address to watch permanently, independent of gap-limit derivation.
// Idempotent: no-op if already watched. Used to pin every address ever shown on
// the Receive screen into the BIP158 match set so a receive to it is never missed.
// Is this address in the DERIVED set (as opposed to merely watched)? Caller must hold
// wallet->lock. Being derived is what makes an address creditable AND signable.
static int _BRWalletIsDerivedLocked(BRWallet *wallet, const char *addr)
{
    return BRSetContains(wallet->allAddrs, addr) ? 1 : 0;
}

// How far past the current chain end we are willing to derive while trying to resolve a
// watched address to a real chain index. Bounded on purpose: each step is EC point maths
// over 6 chain/scriptType combinations, and every derived address also becomes a compact-
// filter element, so an unbounded search would cost both CPU and filter bandwidth.
#define WATCH_RESOLVE_MAX_SPAN 200

// Try to make a watched address DERIVED by extending whichever chain it belongs to.
//
// WHY THIS MATTERS: a watch-only address is enumerated by BRWalletAllAddrs, so it becomes a
// BIP158 filter element and a payment to it DOES get its block downloaded — but the credit
// side never consults watchedAddrs (_BRWalletContainsTx and _BRWalletUpdateBalance both gate
// on the allAddrs BRSet), so the transaction is then discarded. Half a feature.
//
// It cannot be fixed by simply OR-ing a watchedAddrs scan into those gates: BRWalletSignTransaction
// resolves an address to a key INDEX by scanning the derived chain arrays, and never looks at
// watchedAddrs. Crediting a watch-only address would therefore produce balance the wallet can
// see, select for spending, and then fail to sign — unspendable funds, strictly worse than the
// current behaviour. The invariant to preserve is: credit if and only if derived.
//
// So instead of widening the credit gate, we widen the DERIVED set. Caller must NOT hold
// wallet->lock — BRWalletUnusedAddrs takes it internally and it is non-recursive (BRWallet.c:517).
// Returns 1 if the address ended up derived.
static int _BRWalletResolveWatchedToDerived(BRWallet *wallet, const char *addr)
{
    int derived;

    pthread_mutex_lock(&wallet->lock);
    derived = _BRWalletIsDerivedLocked(wallet, addr);
    pthread_mutex_unlock(&wallet->lock);
    if (derived) return 1;   // the common case: it was handed out by BRWalletUnusedAddrs

    for (uint32_t span = 50; span <= WATCH_RESOLVE_MAX_SPAN; span += 50) {
        for (int scriptType = 0; scriptType <= 2; scriptType++) {
            for (int internal = 0; internal <= 1; internal++)
                BRWalletUnusedAddrs(wallet, NULL, span, internal, scriptType);
        }

        pthread_mutex_lock(&wallet->lock);
        derived = _BRWalletIsDerivedLocked(wallet, addr);
        pthread_mutex_unlock(&wallet->lock);
        if (derived) return 1;
    }

    // Not ours, or further out than we are willing to derive. It stays watch-only: it will
    // still match compact filters, but a payment to it cannot be credited. Kept rather than
    // rejected so the match is not lost outright.
    return 0;
}

void BRWalletAddWatchedAddress(BRWallet *wallet, const char *addr)
{
    assert(wallet != NULL);
    assert(addr != NULL);
    if (! addr || ! addr[0]) return;
    if (! BRAddressIsValid(addr)) return;

    // Before pinning, try to bring it into the derived set so a payment to it can actually
    // be credited and later spent — not merely matched.
    _BRWalletResolveWatchedToDerived(wallet, addr);

    pthread_mutex_lock(&wallet->lock);
    int known = 0;
    for (size_t i = 0; i < array_count(wallet->watchedAddrs); i++) {
        if (strncmp(wallet->watchedAddrs[i].s, addr, sizeof(wallet->watchedAddrs[i].s)) == 0) { known = 1; break; }
    }
    if (! known) {
        BRAddress a = BR_ADDRESS_NONE;
        strncpy(a.s, addr, sizeof(a.s) - 1);
        array_add(wallet->watchedAddrs, a);   // plain array; no &array[i] stored anywhere
        wallet->addrGen = _brNextAddrGen();   // enumerated address set changed
    }
    pthread_mutex_unlock(&wallet->lock);
}

// true if the address was previously used as an output in any wallet transaction
int BRWalletAddressIsUsed(BRWallet *wallet, const char *addr)
{
    int r = 0;

    assert(wallet != NULL);
    assert(addr != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (addr) r = BRSetContains(wallet->usedAddrs, addr);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// returns an unsigned transaction that sends the specified amount from the wallet to the given address
// result must be freed by calling BRTransactionFree()
BRTransaction *BRWalletCreateTransaction(BRWallet *wallet, uint64_t amount, const char *addr)
{
    BRTxOutput o = BR_TX_OUTPUT_NONE;
    
    assert(wallet != NULL);
    assert(amount > 0);
    assert(addr != NULL && BRAddressIsValid(addr));
    o.amount = amount;
    BRTxOutputSetAddress(&o, addr);
    BRTransaction *tx = BRWalletCreateTxForOutputs(wallet, &o, 1);
    if (o.script) array_free(o.script);   // the builder copied it into its own output
    return tx;
}

// True when the output's script is one of the exact templates BRTransactionSign spends for a wallet
// key: P2PKH, P2SH (BIP49 P2SH-P2WPKH), P2WPKH or P2TR. Coin selection skips any other output, so an
// output credited by mistake is left unspent instead of failing every send it is picked for.
static int _BRWalletOutputSignable(const BRTxOutput *out)
{
    const uint8_t *s = out->script;
    size_t n = out->scriptLen;

    if (! s) return 0;
    if (n == 25) return s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 && s[23] == OP_EQUALVERIFY &&
                        s[24] == OP_CHECKSIG;                                       // P2PKH
    if (n == 23) return s[0] == OP_HASH160 && s[1] == 20 && s[22] == OP_EQUAL;      // P2SH
    if (n == 22) return s[0] == OP_0 && s[1] == 20;                                 // P2WPKH
    if (n == 34) return s[0] == OP_1 && s[1] == 32;                                 // P2TR
    return 0;
}

// True when an unconfirmed tx is the wallet's own: every input spends an output paying a wallet address
// that is itself confirmed or, in turn, the wallet's own unconfirmed tx, and it pays out no more than it
// spends. That is a send or its change. It cannot be counterfeited: an unconfirmed tx that spends a
// wallet output is registered only with a valid signature for that output (_BRWalletInputsSigned), or
// through BRWalletRegisterTransactionTrusted (a tx this wallet signed, or one a block delivered), so
// such a tx was signed with the wallet's keys. Anything else unconfirmed came from someone else and is
// not a coin until a block confirms it. `budget` is shared by every check in one selection (a shared
// ancestor would otherwise be visited once per path, per coin); running out answers "not own".
// Caller holds wallet->lock.
#ifdef WALLET_KAT_COUNT_WALK
// Host-KAT-only: counts input visits of the own-unconfirmed walk, so a gate can bound the work of one
// selection without timing it. Never defined in production.
unsigned long _walletKatWalkVisits = 0;
#endif

static int _BRWalletTxIsOwnUnconfirmed(BRWallet *wallet, const BRTransaction *tx, int depth, int *budget)
{
    uint64_t in = 0, out = 0;

    if (depth <= 0 || tx->inCount == 0) return 0;

    for (size_t i = 0; i < tx->inCount; i++) {
        BRTransaction *p = BRSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;

        if (--*budget < 0) return 0;
#ifdef WALLET_KAT_COUNT_WALK
        _walletKatWalkVisits++;
#endif
        if (! p || n >= p->outCount || ! BRSetContains(wallet->allAddrs, p->outputs[n].address)) return 0;
        if (p->blockHeight == TX_UNCONFIRMED && ! _BRWalletTxIsOwnUnconfirmed(wallet, p, depth - 1, budget)) return 0;
        in = _BRMoneyAdd(in, p->outputs[n].amount);
    }

    for (size_t i = 0; i < tx->outCount; i++) out = _BRMoneyAdd(out, tx->outputs[i].amount);
    return out <= in;   // a send never pays out more than it spends
}

#define SELECT_WALK_BUDGET 10000   // input visits per selection, for every own-unconfirmed check together

// Coin selection takes confirmed coins on its first pass and the wallet's own unconfirmed change on
// its second; an unconfirmed coin received from someone else is never selected. `budget` is the one
// SELECT_WALK_BUDGET of the calling selection. Caller holds wallet->lock.
static int _BRWalletUtxoSelectable(BRWallet *wallet, const BRTransaction *tx, int pass, int *budget)
{
    if (tx->blockHeight != TX_UNCONFIRMED) return pass == 0;
    return pass == 1 && _BRWalletTxIsOwnUnconfirmed(wallet, tx, 25, budget);
}

// Either pass: confirmed, or the wallet's own unconfirmed. Caller holds wallet->lock.
static int _BRWalletUtxoSelectableAny(BRWallet *wallet, const BRTransaction *tx, int *budget)
{
    return _BRWalletUtxoSelectable(wallet, tx, 0, budget) || _BRWalletUtxoSelectable(wallet, tx, 1, budget);
}

// The UTXOs coin selection would draw from, in its order: confirmed coins, then the wallet's own
// unconfirmed change -- never an asset-held or unsignable output, nor an unconfirmed coin someone else
// sent. For builders outside this file (the DigiAsset send's DGB fee inputs) so they spend by the same
// rule. Returns the number written, or the total when utxos is NULL.
size_t BRWalletSelectableUTXOs(BRWallet *wallet, BRUTXO *utxos, size_t utxosCount)
{
    size_t n, k, w = 0;
    int budget = SELECT_WALK_BUDGET;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    n = array_count(wallet->utxos);

    for (k = 0; k < 2*n && (! utxos || w < utxosCount); k++) {
        BRUTXO *o = &wallet->utxos[k % n];
        BRTransaction *tx = BRSetGet(wallet->allTx, o);

        if (! tx || o->n >= tx->outCount) continue;
        if (BRWalletUtxoIsAsset(wallet, o)) continue;
        if (! _BRWalletOutputSignable(&tx->outputs[o->n])) continue;
        if (! _BRWalletUtxoSelectable(wallet, tx, k >= n, &budget)) continue;
        if (utxos) utxos[w] = *o;
        w++;
    }

    pthread_mutex_unlock(&wallet->lock);
    return w;
}

// BRWalletMinOutputAmount at a given rate.
static uint64_t _BRMinOutputAmountAt(uint64_t feePerKb)
{
    uint64_t amount = (TX_MIN_OUTPUT_AMOUNT*feePerKb + MIN_FEE_PER_KB - 1)/MIN_FEE_PER_KB;

    return (amount > TX_MIN_OUTPUT_AMOUNT) ? amount : TX_MIN_OUTPUT_AMOUNT;
}

static BRTransaction *_BRWalletCreateTxForOutputsAt(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount,
                                                    int force, uint64_t feePerKb);

// The same as BRWalletCreateTransaction, at `feePerKb` for this one build (0: the wallet's rate). The
// wallet's own rate is neither read for the fee nor changed, so a custom rate cannot outlive its send
// and no concurrent build or feefilter update can mix into it.
BRTransaction *BRWalletCreateTransactionAtFeePerKb(BRWallet *wallet, uint64_t amount, const char *addr,
                                                   uint64_t feePerKb)
{
    BRTxOutput o = BR_TX_OUTPUT_NONE;
    BRTransaction *tx;

    assert(wallet != NULL);
    assert(amount > 0);
    assert(addr != NULL && BRAddressIsValid(addr));
    o.amount = amount;
    BRTxOutputSetAddress(&o, addr);
    tx = _BRWalletCreateTxForOutputsAt(wallet, &o, 1, 0, feePerKb ? feePerKb : BRWalletFeePerKb(wallet));
    if (o.script) array_free(o.script);
    return tx;
}

BRTransaction *BRWalletCreateTxForOutputsEx(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount, int force) {
    return _BRWalletCreateTxForOutputsAt(wallet, outputs, outCount, force, BRWalletFeePerKb(wallet));
}

static BRTransaction *_BRWalletCreateTxForOutputsAt(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount,
                                                    int force, uint64_t feePerKb)
{
    BRTransaction *tx, *transaction = BRTransactionNew();
    uint64_t feeAmount, amount = 0, balance = 0, minAmount;
    size_t i, j, k, nUtxos, cpfpSize = 0;
    int budget = SELECT_WALK_BUDGET;
    BRUTXO *o;
    BRAddress addr = BR_ADDRESS_NONE;
    
    assert(wallet != NULL);
    assert(outputs != NULL && outCount > 0);
    
    for (i = 0; outputs && i < outCount; i++) {
        assert(outputs[i].script != NULL && outputs[i].scriptLen > 0);
        BRTransactionAddOutput(transaction, outputs[i].amount, outputs[i].script,
                               outputs[i].scriptLen);
        amount += outputs[i].amount;
    }
    
    minAmount = _BRMinOutputAmountAt(feePerKb);
    pthread_mutex_lock(&wallet->lock);
    feeAmount = _txFee(feePerKb, BRTransactionVSize(transaction) + TX_OUTPUT_SIZE);
    
    // TODO: use up all UTXOs for all used addresses to avoid leaving funds in addresses whose public key is revealed
    // TODO: avoid combining addresses in a single transaction when possible to reduce information leakage
    // TODO: use up UTXOs received from any of the output scripts that this transaction sends funds to, to mitigate an
    //       attacker double spending and requesting a refund
    // Two passes over the UTXOs (k < nUtxos, then the rest): confirmed coins first, then the wallet's
    // own unconfirmed change (_BRWalletUtxoSelectable).
    for (k = 0, nUtxos = array_count(wallet->utxos); k < 2*nUtxos; k++) {
        i = k % nUtxos;
        o = &wallet->utxos[i];
        tx = BRSetGet(wallet->allTx, o);
        
        if (! tx || o->n >= tx->outCount) continue;
        if (BRWalletUtxoIsAsset(wallet, o)) continue;
        if (! _BRWalletOutputSignable(&tx->outputs[o->n])) continue;   // never select what cannot be signed
        if (! _BRWalletUtxoSelectable(wallet, tx, k >= nUtxos, &budget)) continue;

        BRTransactionAddInput(transaction, tx->txHash, o->n, tx->outputs[o->n].amount,
                              tx->outputs[o->n].script, tx->outputs[o->n].scriptLen, NULL, 0, NULL, 0, TXIN_SEQUENCE);
        
        if (BRTransactionVSize(transaction) + TX_OUTPUT_SIZE > TX_MAX_SIZE) { // transaction size-in-bytes too large
            BRTransactionFree(transaction);
            transaction = NULL;
            
            // check for sufficient total funds before building a smaller transaction
            if (wallet->balance < amount + _txFee(feePerKb, 10 + array_count(wallet->utxos)*TX_INPUT_SIZE +
                                                  (outCount + 1)*TX_OUTPUT_SIZE + cpfpSize)) break;
            pthread_mutex_unlock(&wallet->lock);
            
            if (outputs[outCount - 1].amount > amount + feeAmount + minAmount - balance) {
                BRTxOutput newOutputs[outCount];
                
                for (j = 0; j < outCount; j++) {
                    newOutputs[j] = outputs[j];
                }
                
                newOutputs[outCount - 1].amount -= amount + feeAmount - balance; // reduce last output amount
                transaction = _BRWalletCreateTxForOutputsAt(wallet, newOutputs, outCount, 0, feePerKb);
            }
            else transaction = _BRWalletCreateTxForOutputsAt(wallet, outputs, outCount - 1, 0, feePerKb); // remove last output
            
            balance = amount = feeAmount = 0;
            pthread_mutex_lock(&wallet->lock);
            break;
        }
        
        balance = _BRMoneyAdd(balance, tx->outputs[o->n].amount);
        
        //        // size of unconfirmed, non-change inputs for child-pays-for-parent fee
        //        // don't include parent tx with more than 10 inputs or 10 outputs
        //        if (tx->blockHeight == TX_UNCONFIRMED && tx->inCount <= 10 && tx->outCount <= 10 &&
        //            ! _BRWalletTxIsSend(wallet, tx)) cpfpSize += BRTransactionSize(tx);
        
        // fee amount after adding a change output
        feeAmount = _txFee(feePerKb, BRTransactionVSize(transaction) + TX_OUTPUT_SIZE + cpfpSize);
        
        // increase fee to round off remaining wallet balance to nearest 100 satoshi
        if (wallet->balance > amount + feeAmount) feeAmount += (wallet->balance - (amount + feeAmount)) % 100;
        
        if (balance == amount + feeAmount || balance >= amount + feeAmount + minAmount) break;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    
    if (transaction && (outCount < 1 || balance < amount + feeAmount) && !force) { // no outputs/insufficient funds
        BRTransactionFree(transaction);
        transaction = NULL;
    }
    else if (transaction && balance - (amount + feeAmount) > minAmount) { // add change output
        BRWalletUnusedAddrs(wallet, &addr, 1, 1, 1);
        uint8_t script[BRAddressScriptPubKey(NULL, 0, addr.s)];
        size_t scriptLen = BRAddressScriptPubKey(script, sizeof(script), addr.s);
        
        BRTransactionAddOutput(transaction, balance - (amount + feeAmount), script, scriptLen);
        BRTransactionShuffleOutputs(transaction);
    }
    
    return transaction;
}

// returns an unsigned transaction that satisifes the given transaction outputs, without going to fail due to missing balance
// result must be freed by calling BRTransactionFree()
BRTransaction *BRWalletForceCreateTxForOutputs(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount) {
    return BRWalletCreateTxForOutputsEx(wallet, outputs, outCount, 1);
}

#define DD_MIN_FEE 10000000ULL          // 0.1 DGB fee floor (matches DigiByte Core DD builder, wire spec §6)
#define DD_MIN_OUTPUT_CENTS 100LL       // $1.00 per-output minimum (consensus minOutputAmount)
#define DD_MAX_OUTPUT_CENTS 10000000LL  // $100,000 per-transfer-output max (digidollar/validation.cpp:1150)

// Allocation for the transfer builder's per-call working sets, sized with a checked multiply:
// returns NULL if count*size would wrap or the request is refused. A count of 0 still allocates one
// slot so the returned pointer is always valid to free.
static void *_ddAllocWork(size_t count, size_t size)
{
    size_t bytes;
    if (count == 0) count = 1;
    if (__builtin_mul_overflow(count, size, &bytes)) return NULL;
    return malloc(bytes);
}

// A DigiDollar change amount is acceptable when there is no change at all, or the change is itself a
// valid stand-alone output amount in [DD_MIN_OUTPUT_CENTS, DD_MAX_OUTPUT_CENTS]. Change below the
// $1.00 output floor, or above the per-output cap, is not acceptable.
static int _ddChangeAcceptable(uint64_t ddChange)
{
    if (ddChange == 0) return 1;
    return (int64_t)ddChange >= DD_MIN_OUTPUT_CENTS && (int64_t)ddChange <= DD_MAX_OUTPUT_CENTS;
}

// The widest coin that can never carry a running total from below the acceptable change band's floor
// to above its ceiling in one step -- the band is DD_MAX_OUTPUT_CENTS - DD_MIN_OUTPUT_CENTS + 1 cents
// wide, so a coin no wider than that always lands a total that reaches the floor inside the band.
#define DD_LOW_COIN_MAX (DD_MAX_OUTPUT_CENTS - DD_MIN_OUTPUT_CENTS + 1)

// One snapshotted DigiDollar coin of the transfer builder's working set (value by copy, so the set
// is usable after the wallet lock is dropped).
struct _ddSel { UInt256 hash; uint32_t n; int64_t c; uint8_t script[42]; size_t scriptLen; };

// Chooses a selection out of the working set `sel[0..m)` -- sorted ascending by cents -- that covers
// `cents` with an acceptable change, compacts the chosen coins to the front of the array in
// largest-first order, and sets *outCount to how many were chosen. Returns 1 on a selection, 0 when
// the holding admits none.
//
// THE INVARIANT THIS ESTABLISHES, together with the smallest-first prefix its caller has already
// tried: 0 is returned only where NO subset of the working set covers `cents` with an acceptable
// change -- for every holding whose coins are each at least DD_MIN_OUTPUT_CENTS, which is what a
// DigiDollar output amount always is. Two steps here, and why between them they account for every
// subset:
//   (1) a coin worth more than cents + DD_MAX_OUTPUT_CENTS is set aside. Every subset holding one
//       totals past that, so its change is above the cap: setting it aside cannot lose a selection.
//       The `hi` coins left each fit under that ceiling on their own.
//   (2) largest-first accumulation, taking the first running total whose change is acceptable.
//   (3) failing that: the largest "high part" that itself fits under the ceiling -- nothing at all,
//       the single largest coin, or the highest-summing pair -- topped up with "low" coins (each at
//       most DD_LOW_COIN_MAX) largest-first until the total reaches the band's floor. A low coin is
//       never wider than the band, so the first total to reach the floor is still under the ceiling
//       and that selection is acceptable. Three or more coins wider than DD_LOW_COIN_MAX already sum
//       past the ceiling, so those three candidates are every high part a selection can have; the
//       largest of them is the one that gets nearest the floor, so if it cannot reach it none can.
//   and that is all that is needed: if step (3) cannot reach the floor then every subset totals below
//   it, so the only acceptable change left is none at all -- and a selection with no change is every
//   low coin plus at most one high coin (two high coins already sum past `cents`), which is exactly
//   what the caller's smallest-first prefix takes, so the caller never reaches here for one.
static int _ddSelectAcceptable(struct _ddSel *sel, size_t m, uint64_t cents, size_t *outCount)
{
    uint64_t lim   = cents + (uint64_t)DD_MAX_OUTPUT_CENTS;   // no acceptable selection totals more
    uint64_t least = cents + (uint64_t)DD_MIN_OUTPUT_CENTS;   // ... and none with change totals less
    size_t hi = m;
    while (hi > 0 && (uint64_t)sel[hi - 1].c > lim) hi--;                                      // (1)
    size_t nlow = hi;                                         // low coins are sel[0..nlow)
    while (nlow > 0 && sel[nlow - 1].c > DD_LOW_COIN_MAX) nlow--;
    uint64_t tlow = 0;
    for (size_t i = 0; i < nlow; i++) tlow += (uint64_t)sel[i].c;

    size_t r0 = 0, r1 = 0, e0 = m, e1 = m;   // chosen = the range sel[r0,r1) plus sel[e0] and sel[e1]
    int found = 0;

    uint64_t s = 0;                                                                            // (2)
    for (size_t k = hi; k > 0 && ! found; k--) {
        s += (uint64_t)sel[k - 1].c;
        if (s >= cents && _ddChangeAcceptable(s - cents)) { r0 = k - 1; r1 = hi; found = 1; }
    }

    if (! found) {                                                                             // (3)
        uint64_t g = 0; size_t h0 = m, h1 = m;
        if (hi > nlow) { g = (uint64_t)sel[hi - 1].c; h0 = hi - 1; }          // the largest single
        if (hi > nlow + 1) {                                                 // the best-summing pair
            size_t i = nlow, j = hi - 1;
            while (i < j) {
                uint64_t t = (uint64_t)sel[i].c + (uint64_t)sel[j].c;
                if (t > lim) j--;
                else { if (t > g) { g = t; h0 = i; h1 = j; } i++; }
            }
        }
        if (g + tlow >= least) {
            uint64_t t = g; size_t i = nlow;
            while (t < least && i > 0) { i--; t += (uint64_t)sel[i].c; }      // low coins, largest-first
            r0 = i; r1 = nlow; e0 = h0; e1 = h1; found = 1;
        }
    }

    if (! found) return 0;

    size_t w = 0;                            // compact the chosen coins to the front in array order
    for (size_t i = 0; i < hi; i++) {        // (w <= i throughout, so nothing is overwritten unread)
        if (i != e0 && i != e1 && (i < r0 || i >= r1)) continue;
        if (w != i) sel[w] = sel[i];
        w++;
    }
    for (size_t i = 0, j = w; i + 1 < j; i++) {                       // ... then reverse the front,
        j--; struct _ddSel t = sel[i]; sel[i] = sel[j]; sel[j] = t;   // so the coins go largest-first
    }
    *outCount = w;
    return 1;
}

// Builds an UNSIGNED DigiDollar transfer paying `cents` to `recipientKey32`. Selects DD UTXOs to cover
// `cents` and DGB UTXOs for the fee, emits recipient DD + DD change + DGB change + OP_RETURN, version
// 0x02000770. Returns the unsigned tx (caller signs with BRWalletSignTransaction), or NULL on failure.
// All wallet reads happen under a SINGLE lock hold (inputs snapshotted by value incl. scriptPubKey bytes);
// the tx is then built unlocked -- BRWalletUnusedAddrs takes wallet->lock internally.
// The fee does not depend on BRWalletSetFeePerKb: it is DD_MIN_FEE (or the size at DEFAULT_FEE_PER_KB,
// if larger) plus any DGB change below TX_MIN_OUTPUT_AMOUNT.
BRTransaction *BRWalletCreateDigiDollarTransfer(BRWallet *wallet, const uint8_t recipientKey32[32],
                                                uint64_t cents)
{
    assert(wallet != NULL); assert(recipientKey32 != NULL);
    if (! wallet->hasTaprootKey) return NULL;
    if ((int64_t)cents < DD_MIN_OUTPUT_CENTS || (int64_t)cents > DD_MAX_OUTPUT_CENTS) return NULL;

    struct _feeSel { UInt256 hash; uint32_t n; uint64_t amt; uint8_t script[42]; size_t scriptLen; };

    pthread_mutex_lock(&wallet->lock);

    // --- snapshot our DD UTXOs (hash, n, cents, scriptPubKey bytes) on the HEAP, sort smallest-first.
    // The working set is sized on the heap with a checked multiply and released on EVERY return path
    // below -- including the early returns taken while wallet->lock is held. ---
    size_t ddN = array_count(wallet->ddUtxos);
    struct _ddSel *ddsel = _ddAllocWork(ddN, sizeof(*ddsel));
    if (! ddsel) { pthread_mutex_unlock(&wallet->lock); return NULL; }              // allocation refused
    size_t m = 0;
    for (size_t i = 0; i < ddN; i++) {
        BRTransaction *dt = BRSetGet(wallet->allTx, &wallet->ddUtxos[i].hash);
        if (! dt) continue;
        uint32_t n = wallet->ddUtxos[i].n;
        if (n >= dt->outCount || dt->outputs[n].scriptLen > sizeof(ddsel[m].script)) continue;
        int64_t c = BRDigiDollarOutputAmount(dt, n);
        if (c <= 0) continue;
        ddsel[m].hash = wallet->ddUtxos[i].hash; ddsel[m].n = n; ddsel[m].c = c;
        ddsel[m].scriptLen = dt->outputs[n].scriptLen;
        memcpy(ddsel[m].script, dt->outputs[n].script, ddsel[m].scriptLen);
        m++;
    }
    for (size_t i = 1; i < m; i++) { // insertion sort ascending by cents
        struct _ddSel k = ddsel[i]; size_t j = i;
        while (j > 0 && ddsel[j-1].c > k.c) { ddsel[j] = ddsel[j-1]; j--; }
        ddsel[j] = k;
    }
    uint64_t selDD = 0; size_t ddIn = 0;
    for (size_t i = 0; i < m && selDD < cents; i++) { selDD += (uint64_t)ddsel[i].c; ddIn++; }
    if (selDD < cents) { free(ddsel); pthread_mutex_unlock(&wallet->lock); return NULL; }   // insufficient DD
    uint64_t ddChange = selDD - cents;

    // The smallest-first prefix is what the wallet has always selected; keep it byte-for-byte when
    // its change is acceptable. Only when that change would fall in a refused band (below the $1.00
    // output floor, or above the per-output cap) does the builder look for another selection before
    // it refuses -- and it then refuses only where the holding admits no acceptable selection at all
    // (see _ddSelectAcceptable). This path is reached ONLY where the prior builder returned NULL, so
    // a send that already builds is untouched.
    if (! _ddChangeAcceptable(ddChange)) {
        size_t altIn = 0;
        if (! _ddSelectAcceptable(ddsel, m, cents, &altIn)) {
            free(ddsel); pthread_mutex_unlock(&wallet->lock); return NULL;   // no acceptable selection
        }
        selDD = 0;
        for (size_t i = 0; i < altIn; i++) selDD += (uint64_t)ddsel[i].c;
        ddIn = altIn; ddChange = selDD - cents;
    }

    // --- snapshot DGB fee UTXOs on the HEAP; DD_MIN_FEE floor dominates the size-based estimate ---
    // The rate is DEFAULT_FEE_PER_KB, never wallet->feePerKb: that one is whatever the last DGB send
    // or a peer's feefilter left there, and a DigiDollar send is confirmed showing the DD_MIN_FEE
    // floor. At the default rate the floor is what is paid, plus at most a sub-dust DGB change below.
    size_t feeN = array_count(wallet->utxos);
    struct _feeSel *feesel = _ddAllocWork(feeN, sizeof(*feesel));
    if (! feesel) { free(ddsel); pthread_mutex_unlock(&wallet->lock); return NULL; }    // allocation refused
    size_t fm = 0; uint64_t dgbIn = 0, fee = DD_MIN_FEE, feePerKb = DEFAULT_FEE_PER_KB;
    int budget = SELECT_WALK_BUDGET;
    for (size_t i = 0; i < feeN; i++) {
        BRUTXO *o = &wallet->utxos[i];
        BRTransaction *ut = BRSetGet(wallet->allTx, o);
        if (! ut || o->n >= ut->outCount || ut->outputs[o->n].scriptLen > sizeof(feesel[fm].script)) continue;
        if (! _BRWalletOutputSignable(&ut->outputs[o->n])) continue;   // never select what cannot be signed
        if (! _BRWalletUtxoSelectableAny(wallet, ut, &budget)) continue;
        feesel[fm].hash = ut->txHash; feesel[fm].n = o->n; feesel[fm].amt = ut->outputs[o->n].amount;
        feesel[fm].scriptLen = ut->outputs[o->n].scriptLen;
        memcpy(feesel[fm].script, ut->outputs[o->n].script, feesel[fm].scriptLen);
        dgbIn = _BRMoneyAdd(dgbIn, feesel[fm].amt); fm++;
        size_t est = 10 + ddIn*57 + fm*68 + 3*TX_OUTPUT_SIZE + 32; // DD in + fee in + ~3 outs + OP_RETURN
        fee = _txFee(feePerKb, est); if (fee < DD_MIN_FEE) fee = DD_MIN_FEE;
        if (dgbIn >= fee) break;
    }
    if (dgbIn < fee) { free(ddsel); free(feesel); pthread_mutex_unlock(&wallet->lock); return NULL; } // insufficient DGB for fee
    uint64_t dgbChange = dgbIn - fee;

    pthread_mutex_unlock(&wallet->lock);

    // --- build the tx UNLOCKED (these helpers take wallet->lock internally) ---
    // DGB change below this goes to the fee. It is the dust amount at the same DEFAULT_FEE_PER_KB
    // (BRWalletMinOutputAmount at that rate, = TX_MIN_OUTPUT_AMOUNT), not one scaled by a stale rate.
    uint64_t dust = TX_MIN_OUTPUT_AMOUNT;
    BRAddress ddCa = BR_ADDRESS_NONE, dgbCa = BR_ADDRESS_NONE;
    if (ddChange > 0) {
        BRWalletUnusedAddrs(wallet, &ddCa, 1, 1, 2);                 // internal taproot change (we own it)
        if (ddCa.s[0] == '\0') { free(ddsel); free(feesel); return NULL; }  // change addr must resolve -- fail closed
    }
    int emitDgb = (dgbChange >= dust);
    if (emitDgb) { BRWalletUnusedAddrs(wallet, &dgbCa, 1, 1, 1); emitDgb = (dgbCa.s[0] != '\0'); }

    BRTransaction *tx = BRTransactionNew();
    tx->version = 0x02000770;

    uint8_t rspk[34] = { 0x51, 0x20 }; memcpy(rspk + 2, recipientKey32, 32);
    BRTransactionAddOutput(tx, 0, rspk, 34);                         // vout0 recipient (verbatim, no re-tweak)
    if (ddChange > 0) {
        uint8_t cspk[42]; size_t cl = BRAddressScriptPubKey(cspk, sizeof(cspk), ddCa.s);
        BRTransactionAddOutput(tx, 0, cspk, cl);                     // vout1 DD change, value 0
    }
    if (emitDgb) {
        uint8_t dspk[42]; size_t dl = BRAddressScriptPubKey(dspk, sizeof(dspk), dgbCa.s);
        BRTransactionAddOutput(tx, dgbChange, dspk, dl);            // DGB change
    }
    // OP_RETURN LAST. Each variable-length push is bounded to orr's capacity before it is written, so
    // the metadata is never written past the buffer (a guard: with the two amounts the maximum is 26
    // bytes, well within the 32-byte capacity today; the bound holds if more amounts are ever added).
    uint8_t orr[32]; size_t ol = 0;
    orr[ol++]=0x6a; orr[ol++]=0x02; orr[ol++]=0x44; orr[ol++]=0x44; orr[ol++]=0x01; orr[ol++]=0x02;
    uint8_t enc[9]; size_t el = BRDigiDollarWriteScriptNum((int64_t)cents, enc);
    if (ol + 1 + el > sizeof(orr)) { BRTransactionFree(tx); free(ddsel); free(feesel); return NULL; }
    orr[ol++] = (uint8_t)el; memcpy(orr + ol, enc, el); ol += el;
    if (ddChange > 0) {
        el = BRDigiDollarWriteScriptNum((int64_t)ddChange, enc);
        if (ol + 1 + el > sizeof(orr)) { BRTransactionFree(tx); free(ddsel); free(feesel); return NULL; }
        orr[ol++] = (uint8_t)el; memcpy(orr + ol, enc, el); ol += el;
    }
    BRTransactionAddOutput(tx, 0, orr, ol);

    for (size_t i = 0; i < ddIn; i++)                                // DD inputs at value 0
        BRTransactionAddInput(tx, ddsel[i].hash, ddsel[i].n, 0, ddsel[i].script, ddsel[i].scriptLen,
                              NULL, 0, NULL, 0, TXIN_SEQUENCE);
    for (size_t i = 0; i < fm; i++)                                  // DGB fee inputs at real value
        BRTransactionAddInput(tx, feesel[i].hash, feesel[i].n, feesel[i].amt, feesel[i].script,
                              feesel[i].scriptLen, NULL, 0, NULL, 0, TXIN_SEQUENCE);

    free(ddsel); free(feesel);
    return tx;   // NO shuffle (output order is consensus-significant)
}

// returns an unsigned transaction that satisifes the given transaction outputs
// result must be freed by calling BRTransactionFree()
BRTransaction *BRWalletCreateTxForOutputs(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount)
{
    return BRWalletCreateTxForOutputsEx(wallet, outputs, outCount, 0);
}

int BRWalletGetAddressPrivateKey(BRWallet* wallet, BRKey* key, const char* address, size_t addressLen, const void *seed, size_t seedLen) {
    assert(key != NULL && "Key must not be NULL");
    
    uint32_t j;
    uint32_t j1;
    
    for (j = (uint32_t)array_count(wallet->internalChainSegwit); j > 0; j--) {
        j1 = j - 1;
        if (BRAddressEq(address, &wallet->internalChainSegwit[j1])) {
            BRBIP32PrivKeyList(key, 1, seed, seedLen, SEQUENCE_INTERNAL_CHAIN, &j1);
            return 1;
        }
    }
    
    for (j = (uint32_t)array_count(wallet->internalChain); j > 0; j--) {
        j1 = j - 1;
        if (BRAddressEq(address, &wallet->internalChain[j1])) {
            BRBIP32PrivKeyList(key, 1, seed, seedLen, SEQUENCE_INTERNAL_CHAIN, &j1);
            return 1;
        }
    }
    
    for (j = (uint32_t)array_count(wallet->externalChainSegwit); j > 0; j--) {
        j1 = j - 1;
        if (BRAddressEq(address, &wallet->externalChainSegwit[j1])) {
            BRBIP32PrivKeyList(key, 1, seed, seedLen, SEQUENCE_EXTERNAL_CHAIN, &j1);
            return 1;
        }
    }

    for (j = (uint32_t)array_count(wallet->externalChain); j > 0; j--) {
        j1 = j - 1;
        if (BRAddressEq(address, &wallet->externalChain[j1])) {
            BRBIP32PrivKeyList(key, 1, seed, seedLen, SEQUENCE_EXTERNAL_CHAIN, &j1);
            return 1;
        }
    }
    
    return 0;
}

// signs any inputs in tx that can be signed using private keys from the wallet
// forkId is 0 for bitcoin, 0x40 for b-cash
// seed is the master private key (wallet seed) corresponding to the master public key given when the wallet was created
// returns true if all inputs were signed, or false if there was an error or not all inputs were able to be signed
int BRWalletSignTransaction(BRWallet *wallet, BRTransaction *tx, int forkId, const void *seed, size_t seedLen)
{
    // BIP84 (primary) chain indices — use BRBIP32PrivKeyListBIP84 for these
    uint32_t j, bip84InternalIdx[tx->inCount], bip84ExternalIdx[tx->inCount];
    size_t i, bip84InternalCount = 0, bip84ExternalCount = 0;
    // Legacy chain indices — use BRBIP32PrivKeyList (DigiByte seed, m/0H) for these
    uint32_t legacyInternalIdx[tx->inCount], legacyExternalIdx[tx->inCount];
    size_t legacyInternalCount = 0, legacyExternalCount = 0;
    // Taproot chain indices — use BRBIP32PrivKeyListBIP86 (m/86'/20'/0') for these
    uint32_t taprootInternalIdx[tx->inCount], taprootExternalIdx[tx->inCount];
    size_t taprootInternalCount = 0, taprootExternalCount = 0;
    int r = 0;

    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);

    for (i = 0; tx && i < tx->inCount; i++) {
        // BIP84 primary chains (masterPubKey — m/84'/20'/0')
        for (j = (uint32_t)array_count(wallet->internalChainSegwit); j > 0; j--) {
            if (BRAddressEq(tx->inputs[i].address, &wallet->internalChainSegwit[j - 1]))
                bip84InternalIdx[bip84InternalCount++] = j - 1;
        }

        for (j = (uint32_t)array_count(wallet->internalChain); j > 0; j--) {
            if (BRAddressEq(tx->inputs[i].address, &wallet->internalChain[j - 1]))
                bip84InternalIdx[bip84InternalCount++] = j - 1;
        }

        for (j = (uint32_t)array_count(wallet->externalChainSegwit); j > 0; j--) {
            if (BRAddressEq(tx->inputs[i].address, &wallet->externalChainSegwit[j - 1]))
                bip84ExternalIdx[bip84ExternalCount++] = j - 1;
        }

        for (j = (uint32_t)array_count(wallet->externalChain); j > 0; j--) {
            if (BRAddressEq(tx->inputs[i].address, &wallet->externalChain[j - 1]))
                bip84ExternalIdx[bip84ExternalCount++] = j - 1;
        }

        // Legacy chains (legacyPubKey — m/0H, DigiByte seed)
        if (wallet->hasLegacyKey) {
            for (j = (uint32_t)array_count(wallet->legacyInternalChainSegwit); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->legacyInternalChainSegwit[j - 1]))
                    legacyInternalIdx[legacyInternalCount++] = j - 1;
            }

            for (j = (uint32_t)array_count(wallet->legacyInternalChain); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->legacyInternalChain[j - 1]))
                    legacyInternalIdx[legacyInternalCount++] = j - 1;
            }

            for (j = (uint32_t)array_count(wallet->legacyExternalChainSegwit); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->legacyExternalChainSegwit[j - 1]))
                    legacyExternalIdx[legacyExternalCount++] = j - 1;
            }

            for (j = (uint32_t)array_count(wallet->legacyExternalChain); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->legacyExternalChain[j - 1]))
                    legacyExternalIdx[legacyExternalCount++] = j - 1;
            }
        }

        // Taproot chains (taprootPubKey — m/86'/20'/0', same seed). P2TR inputs are
        // matched by their dgb1p… address; the actual output-key match + Schnorr
        // signing happens in BRTransactionSign's witness-v1 branch.
        if (wallet->hasTaprootKey) {
            for (j = (uint32_t)array_count(wallet->taprootInternalChain); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->taprootInternalChain[j - 1]))
                    taprootInternalIdx[taprootInternalCount++] = j - 1;
            }

            for (j = (uint32_t)array_count(wallet->taprootExternalChain); j > 0; j--) {
                if (BRAddressEq(tx->inputs[i].address, &wallet->taprootExternalChain[j - 1]))
                    taprootExternalIdx[taprootExternalCount++] = j - 1;
            }
        }
    }

    pthread_mutex_unlock(&wallet->lock);

    size_t totalKeys = bip84InternalCount + bip84ExternalCount + legacyInternalCount + legacyExternalCount +
                       taprootInternalCount + taprootExternalCount;
    BRKey keys[totalKeys];

    if (seed) {
        size_t keyOff = 0;
        // BIP84 keys: use "Bitcoin seed" + m/84'/20'/0'
        BRBIP32PrivKeyListBIP84(keys + keyOff, bip84InternalCount, seed, seedLen,
                                SEQUENCE_INTERNAL_CHAIN, bip84InternalIdx);
        keyOff += bip84InternalCount;
        BRBIP32PrivKeyListBIP84(keys + keyOff, bip84ExternalCount, seed, seedLen,
                                SEQUENCE_EXTERNAL_CHAIN, bip84ExternalIdx);
        keyOff += bip84ExternalCount;
        // Legacy keys: use "DigiByte seed" + m/0H
        BRBIP32PrivKeyList(keys + keyOff, legacyInternalCount, seed, seedLen,
                           SEQUENCE_INTERNAL_CHAIN, legacyInternalIdx);
        keyOff += legacyInternalCount;
        BRBIP32PrivKeyList(keys + keyOff, legacyExternalCount, seed, seedLen,
                           SEQUENCE_EXTERNAL_CHAIN, legacyExternalIdx);
        keyOff += legacyExternalCount;
        // Taproot keys: use "Bitcoin seed" + m/86'/20'/0' (BIP86). The child privkey
        // here is the INTERNAL key d; BRKeyTaprootSchnorrSign applies the BIP86 taptweak.
        BRBIP32PrivKeyListBIP86(keys + keyOff, taprootInternalCount, seed, seedLen,
                                SEQUENCE_INTERNAL_CHAIN, taprootInternalIdx);
        keyOff += taprootInternalCount;
        BRBIP32PrivKeyListBIP86(keys + keyOff, taprootExternalCount, seed, seedLen,
                                SEQUENCE_EXTERNAL_CHAIN, taprootExternalIdx);
        // TODO: XXX wipe seed callback
        seed = NULL;
        if (tx) r = BRTransactionSign(tx, forkId, keys, totalKeys);
        for (i = 0; i < totalKeys; i++) BRKeyClean(&keys[i]);
    }
    else r = -1; // user canceled authentication

    return r;
}

// true if the given transaction is associated with the wallet (even if it hasn't been registered)
int BRWalletContainsTransaction(BRWallet *wallet, const BRTransaction *tx)
{
    int r = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (tx) r = _BRWalletContainsTx(wallet, tx);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// adds a transaction to the wallet, or returns false if it isn't associated with the wallet
// True when every input of tx that spends an output paying a wallet address carries a valid signature
// for that output (BRTransactionVerifyInput, against the prevout the wallet holds). An input it cannot
// verify -- a type or hash type it does not handle, or a P2TR spend beside an input whose prevout the
// wallet does not hold -- counts as unsigned. Inputs spending anything else are not the wallet's to
// judge. Caller holds wallet->lock.
static int _BRWalletInputsSigned(BRWallet *wallet, const BRTransaction *tx)
{
    BRTransaction *t = NULL;
    int r = 1;

    for (size_t i = 0; r && i < tx->inCount; i++) {
        BRTransaction *p = BRSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;

        if (! p || n >= p->outCount || ! BRSetContains(wallet->allAddrs, p->outputs[n].address)) continue;

        if (! t) { // a copy carrying each prevout the wallet holds, as the signer sees them
            t = BRTransactionCopy(tx);
            if (! t) return 0;

            for (size_t k = 0; k < t->inCount; k++) {
                BRTransaction *pk = BRSetGet(wallet->allTx, &t->inputs[k].txHash);
                uint32_t nk = t->inputs[k].index;

                if (! pk || nk >= pk->outCount || ! pk->outputs[nk].script) continue;
                BRTxInputSetScript(&t->inputs[k], pk->outputs[nk].script, pk->outputs[nk].scriptLen);
                t->inputs[k].amount = pk->outputs[nk].amount;
            }
        }

        r = BRTransactionVerifyInput(t, i);
    }

    if (t) BRTransactionFree(t);
    return r;
}

// Registers tx. checkInputs: an UNCONFIRMED tx that spends a wallet output must sign it validly
// (_BRWalletInputsSigned), or it is refused until a block delivers it. A peer can relay any unconfirmed
// tx and nothing else checks it, so without this a tx with a junk scriptSig would mark the wallet's coin
// spent and stand in for it as unconfirmed change. A refused tx -- this, or out of the money range -- is
// not kept at all: the caller still owns it.
static int _BRWalletRegisterTx(BRWallet *wallet, BRTransaction *tx, int checkInputs)
{
    int wasAdded = 0, r = 1;
    
    assert(wallet != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));
    
    if (tx && BRTransactionIsSigned(tx)) {
        pthread_mutex_lock(&wallet->lock);

        if (! BRSetContains(wallet->allTx, tx)) {
            if (! _BRWalletTxMoneyRangeOK(tx) ||
                (checkInputs && tx->blockHeight == TX_UNCONFIRMED && ! _BRWalletInputsSigned(wallet, tx))) {
                r = 0;   // refused and not kept, at any height
            }
            else if (_BRWalletContainsTx(wallet, tx)) {
                // TODO: verify signatures when possible
                // TODO: handle tx replacement with input sequence numbers
                //       (for now, replacements appear invalid until confirmation)
                BRSetAdd(wallet->allTx, tx);
                _BRWalletInsertTx(wallet, tx);
                _BRWalletUpdateBalance(wallet);
                wasAdded = 1;
            }
            else { // keep track of unconfirmed non-wallet tx for invalid tx checks and child-pays-for-parent fees
                   // BUG: limit total non-wallet unconfirmed tx to avoid memory exhaustion attack
                if (tx->blockHeight == TX_UNCONFIRMED) BRSetAdd(wallet->allTx, tx);
                r = 0;
                // BUG: XXX memory leak if tx is not added to wallet->allTx, and we can't just free it
            }
        }
    
        pthread_mutex_unlock(&wallet->lock);
    }
    else r = 0;

    if (wasAdded) {
        // when a wallet address is used in a transaction, generate a new address to replace it
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 1);
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 1);
        // Legacy P2PKH (scriptType 0) must walk forward too. In bloom mode this
        // extension lived in _peerRelayedTx behind `if (manager->bloomFilter != NULL)`,
        // which never runs in COMPACT_FILTERS_ONLY — so the legacy watched window
        // froze at its initial pregen and a legacy receive past that cushion was
        // silently missed (block never cfilter-matched). Extend it here,
        // mode-independent, alongside the segwit chain.
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 0);
        BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 0);
        // Extend the taproot (P2TR / BIP86) gap too, so when a taproot address is
        // used the next taproot window is generated into allAddrs and stays watched
        // by bloom + BIP158 (BRWalletAllAddrs). No-op until the BIP86 key is installed.
        if (wallet->hasTaprootKey) {
            BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 2);
            BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 2);
        }
        // ⚠️ KNOWN HAZARD — lock-release-then-use, SAME CLASS as the saveBlocks race
        // (fixed in seq/saveblocks-serialize-under-lock / the 2026-07-26 spec). wallet->lock
        // was released at :1610, yet these callbacks are handed the LIVE `tx` pointer — owned
        // by wallet->allTx, freeable under the lock by BRWalletRemoveTransaction — so a
        // concurrent free during the JNI serialize of `tx` is a UAF on the credit path.
        // NOT yet fixed here (no crash record; BRTransaction is ref-counted/shared, so the fix
        // differs from the block path) — tracked as its own spec/review/TSan item. DO NOT
        // extend this release-then-dispatch-a-live-pointer pattern to new callbacks/sites.
        if (wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
        if (wallet->txAdded) wallet->txAdded(wallet->callbackInfo, tx);
    }

    return r;
}

int BRWalletRegisterTransaction(BRWallet *wallet, BRTransaction *tx)
{
    return _BRWalletRegisterTx(wallet, tx, 1);
}

int BRWalletRegisterTransactionTrusted(BRWallet *wallet, BRTransaction *tx)
{
    return _BRWalletRegisterTx(wallet, tx, 0);
}

// removes a tx from the wallet and calls BRTransactionFree() on it, along with any tx that depend on its outputs
void BRWalletRemoveTransaction(BRWallet *wallet, UInt256 txHash)
{
    BRTransaction *tx, *t;
    UInt256 *hashes = NULL;
    int notifyUser = 0, recommendRescan = 0;

    assert(wallet != NULL);
    assert(! UInt256IsZero(txHash));
    pthread_mutex_lock(&wallet->lock);
    tx = BRSetGet(wallet->allTx, &txHash);

    if (tx) {
        array_new(hashes, 0);

        for (size_t i = array_count(wallet->transactions); i > 0; i--) { // find depedent transactions
            t = wallet->transactions[i - 1];
            if (t->blockHeight < tx->blockHeight) break;
            if (BRTransactionEq(tx, t)) continue;
            
            for (size_t j = 0; j < t->inCount; j++) {
                if (! UInt256Eq(t->inputs[j].txHash, txHash)) continue;
                array_add(hashes, t->txHash);
                break;
            }
        }
        
        if (array_count(hashes) > 0) {
            pthread_mutex_unlock(&wallet->lock);
            
            for (size_t i = array_count(hashes); i > 0; i--) {
                BRWalletRemoveTransaction(wallet, hashes[i - 1]);
            }
            
            BRWalletRemoveTransaction(wallet, txHash);
        }
        else {
            BRSetRemove(wallet->allTx, tx);
            
            for (size_t i = array_count(wallet->transactions); i > 0; i--) {
                if (! BRTransactionEq(wallet->transactions[i - 1], tx)) continue;
                array_rm(wallet->transactions, i - 1);
                break;
            }
            
            _BRWalletUpdateBalance(wallet);
            pthread_mutex_unlock(&wallet->lock);
            
            // if this is for a transaction we sent, and it wasn't already known to be invalid, notify user
            if (BRWalletAmountSentByTx(wallet, tx) > 0 && BRWalletTransactionIsValid(wallet, tx)) {
                recommendRescan = notifyUser = 1;
                
                for (size_t i = 0; i < tx->inCount; i++) { // only recommend a rescan if all inputs are confirmed
                    t = BRWalletTransactionForHash(wallet, tx->inputs[i].txHash);
                    if (t && t->blockHeight != TX_UNCONFIRMED) continue;
                    recommendRescan = 0;
                    break;
                }
            }

            BRTransactionFree(tx);
            if (wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
            if (wallet->txDeleted) wallet->txDeleted(wallet->callbackInfo, txHash, notifyUser, recommendRescan);
        }
        
        array_free(hashes);
    }
    else pthread_mutex_unlock(&wallet->lock);
}

// returns the transaction with the given hash if it's been registered in the wallet
BRTransaction *BRWalletTransactionForHash(BRWallet *wallet, UInt256 txHash)
{
    BRTransaction *tx;
    
    assert(wallet != NULL);
    if (UInt256IsZero(txHash)) { return NULL;}
    pthread_mutex_lock(&wallet->lock);
    tx = BRSetGet(wallet->allTx, &txHash);
    pthread_mutex_unlock(&wallet->lock);
    return tx;
}

// true if no previous wallet transaction spends any of the given transaction's inputs, and no inputs are invalid
int BRWalletTransactionIsValid(BRWallet *wallet, const BRTransaction *tx)
{
    BRTransaction *t;
    int r = 1;

    assert(wallet != NULL);
    assert(tx != NULL);
    if (!BRTransactionIsSigned(tx)) {
        return 0;
    }
    if (! _BRWalletTxMoneyRangeOK(tx)) return 0;

    // TODO: XXX attempted double spends should cause conflicted tx to remain unverified until they're confirmed
    // TODO: XXX conflicted tx with the same wallet outputs should be presented as the same tx to the user

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be invalid
        pthread_mutex_lock(&wallet->lock);

        if (! BRSetContains(wallet->allTx, tx)) {
            for (size_t i = 0; r && i < tx->inCount; i++) {
                if (BRSetContains(wallet->spentOutputs, &tx->inputs[i]))
                    r = 0;
            }
        }
        else if (BRSetContains(wallet->invalidTx, tx))
            r = 0;

        pthread_mutex_unlock(&wallet->lock);

        for (size_t i = 0; r && i < tx->inCount; i++) {
            t = BRWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && ! BRWalletTransactionIsValid(wallet, t))
                r = 0;
        }
    }
    
    return r;
}

// true if tx cannot be immediately spent (i.e. if it or an input tx can be replaced-by-fee)
int BRWalletTransactionIsPending(BRWallet *wallet, const BRTransaction *tx)
{
    BRTransaction *t;
    time_t now = time(NULL);
    uint32_t blockHeight;
    int r = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));
    pthread_mutex_lock(&wallet->lock);
    blockHeight = wallet->blockHeight;
    pthread_mutex_unlock(&wallet->lock);

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be postdated
        if (BRTransactionSize(tx) > TX_MAX_SIZE) r = 1; // check transaction size is under TX_MAX_SIZE
        
        for (size_t i = 0; ! r && i < tx->inCount; i++) {
            if (tx->inputs[i].sequence < UINT32_MAX - 1) r = 1; // check for replace-by-fee
            if (tx->inputs[i].sequence < UINT32_MAX && tx->lockTime < TX_MAX_LOCK_HEIGHT &&
                tx->lockTime > blockHeight + 1) r = 1; // future lockTime
            if (tx->inputs[i].sequence < UINT32_MAX && tx->lockTime > now) r = 1; // future lockTime
        }
        
        for (size_t i = 0; ! r && i < tx->outCount; i++) { // check that no outputs are dust
            if (tx->outputs[i].amount < TX_MIN_OUTPUT_AMOUNT) r = 1;
        }
        
        for (size_t i = 0; ! r && i < tx->inCount; i++) { // check if any inputs are known to be pending
            t = BRWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && BRWalletTransactionIsPending(wallet, t)) r = 1;
        }
    }
    
    return r;
}

// true if tx is considered 0-conf safe (valid and not pending, timestamp is greater than 0, and no unverified inputs)
int BRWalletTransactionIsVerified(BRWallet *wallet, const BRTransaction *tx)
{
    BRTransaction *t;
    int r = 1;

    assert(wallet != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be unverified
        if (tx->timestamp == 0 || ! BRWalletTransactionIsValid(wallet, tx) ||
            BRWalletTransactionIsPending(wallet, tx)) r = 0;
            
        for (size_t i = 0; r && i < tx->inCount; i++) { // check if any inputs are known to be unverified
            t = BRWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && ! BRWalletTransactionIsVerified(wallet, t)) r = 0;
        }
    }
    
    return r;
}

// set the block heights and timestamps for the given transactions
// use height TX_UNCONFIRMED and timestamp 0 to indicate a tx should remain marked as unverified (not 0-conf safe)
void BRWalletUpdateTransactions(BRWallet *wallet, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                uint32_t timestamp)
{
    BRTransaction *tx;
    UInt256 hashes[txCount];
    int needsUpdate = 0;
    uint32_t oldHeight;
    size_t i, j, k;

    assert(wallet != NULL);
    assert(txHashes != NULL || txCount == 0);
    pthread_mutex_lock(&wallet->lock);

    // TX_UNCONFIRMED (INT32_MAX) is a stamp, not a height: the peer manager uses it to set or clear
    // an unconfirmed tx's timestamp, and it must never become the wallet's notion of the tip.
    if (blockHeight != TX_UNCONFIRMED && blockHeight > wallet->blockHeight) {
        wallet->blockHeight = blockHeight;
        // a held coin-generation output may have reached maturity at this height
        if (wallet->coinbaseOutputs > 0 && blockHeight >= wallet->nextMaturityHeight) needsUpdate = 1;
    }

    for (i = 0, j = 0; txHashes && i < txCount; i++) {
        tx = BRSetGet(wallet->allTx, &txHashes[i]);
        if (! tx || (tx->blockHeight == blockHeight && tx->timestamp == timestamp)) continue;
        oldHeight = tx->blockHeight;
        tx->timestamp = timestamp;
        tx->blockHeight = blockHeight;
        
        if (_BRWalletContainsTx(wallet, tx)) {
            for (k = array_count(wallet->transactions); k > 0; k--) { // remove and re-insert tx to keep wallet sorted
                if (! BRTransactionEq(wallet->transactions[k - 1], tx)) continue;
                array_rm(wallet->transactions, k - 1);
                _BRWalletInsertTx(wallet, tx);
                break;
            }
            
            hashes[j++] = txHashes[i];
            // re-evaluate the balance when the tx was withheld (pending/invalid), when it is a
            // coin-generation tx (its maturity is keyed on the height just stamped), or when an
            // already-confirmed tx moved to a different height (height-keyed credit rules).
            if (BRSetContains(wallet->pendingTx, tx) || BRSetContains(wallet->invalidTx, tx) ||
                _BRTxIsCoinbase(tx) || (oldHeight != TX_UNCONFIRMED && oldHeight != blockHeight)) needsUpdate = 1;
        }
        else if (blockHeight != TX_UNCONFIRMED && ! wallet->hasLegacyKey) {
            // Remove confirmed non-wallet tx — but NOT in dual-key wallets.
            // Dual-key wallets have saved transactions from the old key tree
            // whose parent/child relationships are needed for correct send
            // amount calculation. Removing a parent tx causes
            // BRWalletAmountSentByTx to return 0, making sends disappear.
            BRSetRemove(wallet->allTx, tx);
            BRTransactionFree(tx);
        }
    }
    
    if (needsUpdate) _BRWalletUpdateBalance(wallet);
    pthread_mutex_unlock(&wallet->lock);
    if (j > 0 && wallet->txUpdated) wallet->txUpdated(wallet->callbackInfo, hashes, j, blockHeight, timestamp);
}

// marks all transactions confirmed after blockHeight as unconfirmed (useful for chain re-orgs)
void BRWalletSetTxUnconfirmedAfter(BRWallet *wallet, uint32_t blockHeight)
{
    size_t i, j, count;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    wallet->blockHeight = blockHeight;
    count = i = array_count(wallet->transactions);
    while (i > 0 && wallet->transactions[i - 1]->blockHeight > blockHeight) i--;
    count -= i;

    UInt256 hashes[count];

    for (j = 0; j < count; j++) {
        wallet->transactions[i + j]->blockHeight = TX_UNCONFIRMED;
        hashes[j] = wallet->transactions[i + j]->txHash;
    }
    
    if (count > 0) _BRWalletUpdateBalance(wallet);
    pthread_mutex_unlock(&wallet->lock);
    if (count > 0 && wallet->txUpdated) wallet->txUpdated(wallet->callbackInfo, hashes, count, TX_UNCONFIRMED, 0);
}

// records the chain tip as the peer manager knows it: the height of its last verified block, never
// an estimate. Not monotonic -- a lower tip is accepted (reorg, rescan) and simply makes a young
// coin-generation output unspendable again, the safe side. The balance is rebuilt only when the new
// tip can change it: no coin-generation output held -> O(1) return (the common case, so a batch of
// thousands of headers costs nothing here); tip did not fall and no held output reached maturity ->
// return; otherwise rebuild. balanceChanged fires only if the spendable balance actually changed,
// after the wallet lock is released. May be called with the peer manager's lock held (the existing
// manager -> wallet order); never calls back into the caller while holding wallet->lock.
void BRWalletSetBlockHeight(BRWallet *wallet, uint32_t blockHeight)
{
    uint64_t oldBalance = 0, newBalance = 0;
    uint32_t oldHeight;
    int changed = 0;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    oldHeight = wallet->blockHeight;
    wallet->blockHeight = blockHeight;

    if (wallet->coinbaseOutputs > 0 && ! (blockHeight >= oldHeight && blockHeight < wallet->nextMaturityHeight)) {
        oldBalance = wallet->balance;
        _BRWalletUpdateBalance(wallet);
        newBalance = wallet->balance;
        changed = (newBalance != oldBalance);
    }

    pthread_mutex_unlock(&wallet->lock);
    if (changed && wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, newBalance);
}

// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
uint64_t BRWalletAmountReceivedFromTx(BRWallet *wallet, const BRTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
    for (size_t i = 0; tx && i < tx->outCount; i++) {
        if (BRSetContains(wallet->allAddrs, tx->outputs[i].address)) amount = _BRMoneyAdd(amount, tx->outputs[i].amount);
    }
    
    pthread_mutex_unlock(&wallet->lock);
    return amount;
}

// returns the amount sent from the wallet by the trasaction (total wallet outputs consumed, change and fee included)
uint64_t BRWalletAmountSentByTx(BRWallet *wallet, const BRTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->inCount; i++) {
        BRTransaction *t = BRSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount && BRSetContains(wallet->allAddrs, t->outputs[n].address)) {
            amount = _BRMoneyAdd(amount, t->outputs[n].amount);
        }
    }
    
    pthread_mutex_unlock(&wallet->lock);
    return amount;
}

// returns the fee for the given transaction if all its inputs are from wallet transactions, UINT64_MAX otherwise
uint64_t BRWalletFeeForTx(BRWallet *wallet, const BRTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->inCount && amount != UINT64_MAX; i++) {
        BRTransaction *t = BRSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount) {
            amount = _BRMoneyAdd(amount, t->outputs[n].amount);
            if (amount == UINT64_MAX) amount = UINT64_MAX - 1;   // a saturated sum is not "unknown"
        }
        else amount = UINT64_MAX;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    
    // outputs above the inputs: no fee a valid tx can pay, so the fee is reported as unknown
    for (size_t i = 0; tx && i < tx->outCount && amount != UINT64_MAX; i++) {
        amount = (tx->outputs[i].amount > amount) ? UINT64_MAX : amount - tx->outputs[i].amount;
    }
    
    return amount;
}

// historical wallet balance after the given transaction, or current balance if transaction is not registered in wallet
uint64_t BRWalletBalanceAfterTx(BRWallet *wallet, const BRTransaction *tx)
{
    uint64_t balance;
    
    assert(wallet != NULL);
    assert(tx != NULL/* && BRTransactionIsSigned(tx)*/);
    pthread_mutex_lock(&wallet->lock);
    balance = wallet->balance;
    
    for (size_t i = array_count(wallet->transactions); tx && i > 0; i--) {
        if (! BRTransactionEq(tx, wallet->transactions[i - 1])) continue;
        balance = wallet->balanceHist[i - 1];
        break;
    }

    pthread_mutex_unlock(&wallet->lock);
    return balance;
}

// fee that will be added for a transaction of the given size in bytes
uint64_t BRWalletFeeForTxSize(BRWallet *wallet, size_t size)
{
    uint64_t fee;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    fee = _txFee(wallet->feePerKb, size);
    pthread_mutex_unlock(&wallet->lock);
    return fee;
}

// fee that will be added for a transaction of the given amount
uint64_t BRWalletFeeForTxAmount(BRWallet *wallet, uint64_t amount)
{
    static const uint8_t dummyScript[] = { OP_DUP, OP_HASH160, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUALVERIFY, OP_CHECKSIG };
    BRTxOutput o = BR_TX_OUTPUT_NONE;
    BRTransaction *tx;
    uint64_t fee = 0, maxAmount = 0;
    
    assert(wallet != NULL);
    assert(amount > 0);
    maxAmount = BRWalletMaxOutputAmount(wallet);
    o.amount = (amount < maxAmount) ? amount : maxAmount;
    BRTxOutputSetScript(&o, dummyScript, sizeof(dummyScript)); // unspendable dummy scriptPubKey
    tx = BRWalletCreateTxForOutputs(wallet, &o, 1);

    if (tx) {
        fee = BRWalletFeeForTx(wallet, tx);
        BRTransactionFree(tx);
    }
    
    return fee;
}

// fee that will be added for a transaction of the given amount (forcing transaction creation)
uint64_t BRWalletForceFeeForTxAmount(BRWallet *wallet, uint64_t amount)
{
    static const uint8_t dummyScript[] = { OP_DUP, OP_HASH160, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUALVERIFY, OP_CHECKSIG };
    BRTxOutput o = BR_TX_OUTPUT_NONE;
    BRTransaction *tx;
    uint64_t fee = 0, maxAmount = 0;
    
    assert(wallet != NULL);
    assert(amount > 0);
    maxAmount = BRWalletMaxOutputAmount(wallet);
    o.amount = (amount < maxAmount) ? amount : maxAmount;
    BRTxOutputSetScript(&o, dummyScript, sizeof(dummyScript)); // unspendable dummy scriptPubKey
    tx = BRWalletForceCreateTxForOutputs(wallet, &o, 1);
    
    if (tx) {
        fee = BRWalletFeeForTx(wallet, tx);
        BRTransactionFree(tx);
    }
    
    return fee;
}

// outputs below this amount are uneconomical due to fees (TX_MIN_OUTPUT_AMOUNT is the absolute minimum output amount)
uint64_t BRWalletMinOutputAmount(BRWallet *wallet)
{
    uint64_t amount;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    amount = (TX_MIN_OUTPUT_AMOUNT*wallet->feePerKb + MIN_FEE_PER_KB - 1)/MIN_FEE_PER_KB;
    pthread_mutex_unlock(&wallet->lock);
    return (amount > TX_MIN_OUTPUT_AMOUNT) ? amount : TX_MIN_OUTPUT_AMOUNT;
}

// maximum amount that can be sent from the wallet to a single address after fees
uint64_t BRWalletMaxOutputAmount(BRWallet *wallet)
{
    BRTransaction *tx;
    BRUTXO *o;
    uint64_t fee, amount = 0;
    size_t i, txSize, cpfpSize = 0, inCount = 0;
    int budget = SELECT_WALK_BUDGET;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    for (i = array_count(wallet->utxos); i > 0; i--) {
        o = &wallet->utxos[i - 1];
        tx = BRSetGet(wallet->allTx, &o->hash);
        if (! tx || o->n >= tx->outCount) continue;
        if (! _BRWalletOutputSignable(&tx->outputs[o->n])) continue;   // what selection would skip
        if (! _BRWalletUtxoSelectableAny(wallet, tx, &budget)) continue;
        inCount++;
        amount = _BRMoneyAdd(amount, tx->outputs[o->n].amount);
        
//        // size of unconfirmed, non-change inputs for child-pays-for-parent fee
//        // don't include parent tx with more than 10 inputs or 10 outputs
//        if (tx->blockHeight == TX_UNCONFIRMED && tx->inCount <= 10 && tx->outCount <= 10 &&
//            ! _BRWalletTxIsSend(wallet, tx)) cpfpSize += BRTransactionSize(tx);
    }

    txSize = 8 + BRVarIntSize(inCount) + TX_INPUT_SIZE*inCount + BRVarIntSize(2) + TX_OUTPUT_SIZE*2;
    fee = _txFee(wallet->feePerKb, txSize + cpfpSize);
    pthread_mutex_unlock(&wallet->lock);
    
    return (amount > fee) ? amount - fee : 0;
}

// frees memory allocated for wallet, and calls BRTransactionFree() for all registered transactions
void BRWalletFree(BRWallet *wallet)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    BRSetFree(wallet->allAddrs);
    BRSetFree(wallet->usedAddrs);
    BRSetFree(wallet->allTx);
    BRSetFree(wallet->invalidTx);
    BRSetFree(wallet->pendingTx);
    BRSetFree(wallet->spentOutputs);
    array_free(wallet->internalChain);
    array_free(wallet->externalChain);
    array_free(wallet->externalChainSegwit);
    array_free(wallet->internalChainSegwit);
    array_free(wallet->legacyExternalChain);
    array_free(wallet->legacyInternalChain);
    array_free(wallet->legacyExternalChainSegwit);
    array_free(wallet->legacyInternalChainSegwit);
    array_free(wallet->taprootExternalChain);
    array_free(wallet->taprootInternalChain);
    array_free(wallet->watchedAddrs);
    array_free(wallet->balanceHist);

    for (size_t i = array_count(wallet->transactions); i > 0; i--) {
        BRTransactionFree(wallet->transactions[i - 1]);
    }

    array_free(wallet->transactions);
    array_free(wallet->utxos);
    array_free(wallet->assetUtxos);
    array_free(wallet->assetOverrides);
    array_free(wallet->ddUtxos);
    pthread_mutex_unlock(&wallet->lock);
    pthread_mutex_destroy(&wallet->lock);
    free(wallet);
}

// returns the given amount (in satoshis) in local currency units (i.e. pennies, pence)
// price is local currency units per bitcoin
int64_t BRLocalAmount(int64_t amount, double price)
{
    int64_t localAmount = llabs(amount)*price/SATOSHIS;
    
    // if amount is not 0, but is too small to be represented in local currency, return minimum non-zero localAmount
    if (localAmount == 0 && amount != 0) localAmount = 1;
    return (amount < 0) ? -localAmount : localAmount;
}

// returns the given local currency amount in satoshis
// price is local currency units (i.e. pennies, pence) per bitcoin
int64_t BRBitcoinAmount(int64_t localAmount, double price)
{
    int overflowbits = 0;
    int64_t p = 10, min, max, amount = 0, lamt = llabs(localAmount);

    if (lamt != 0 && price > 0) {
        while (lamt + 1 > INT64_MAX/SATOSHIS) lamt /= 2, overflowbits++; // make sure we won't overflow an int64_t
        min = lamt*SATOSHIS/price; // minimum amount that safely matches localAmount
        max = (lamt + 1)*SATOSHIS/price - 1; // maximum amount that safely matches localAmount
        amount = (min + max)/2; // average min and max
        while (overflowbits > 0) lamt *= 2, min *= 2, max *= 2, amount *= 2, overflowbits--;
        
        if (amount >= MAX_MONEY) return (localAmount < 0) ? -MAX_MONEY : MAX_MONEY;
        while ((amount/p)*p >= min && p <= INT64_MAX/10) p *= 10; // lowest decimal precision matching localAmount
        p /= 10;
        amount = (amount/p)*p;
    }
    
    return (localAmount < 0) ? -amount : amount;
}

void BRFixAssetInputs(BRWallet *wallet, BRTransaction *assetTransaction)
{
    for (size_t j = 0; j < array_count(wallet->transactions); j++) {
        BRTransaction *t = wallet->transactions[j];
        for (size_t i = 0; i < array_count(assetTransaction->inputs); i++) {
            BRTxInput input = assetTransaction->inputs[i];
            if(UInt256Eq(input.txHash, t->txHash)){
                BRTxOutput output = t->outputs[input.index];
                BRTxInputSetScript(&input, output.script, output.scriptLen);
                assetTransaction->inputs[i] = input;
            }
        }
    }
}

// Record that (txHash, n) carries DigiAsset units, so it is held in assetUtxos instead of
// the spendable utxos set and no plain-DGB coin selection can reach it.
//
// The tx-local classifier BRTxOutputIsAsset only recognises outputs an explicit transfer
// instruction targets. DigiAssets also credits every unassigned input unit to the
// transaction's LAST output (DigiAsset_Core DigiByteTransaction.cpp, decodeAssetTransfer),
// and deciding whether such a remainder exists requires the INPUT quantities -- a
// chain-walk plus a per-outpoint store that lives in the Kotlin layer, not here. So the
// asset layer resolves it and registers the outcome through this call, fail-closed:
// registered whenever the remainder is positive OR unknown.
//
// Durable across _BRWalletUpdateBalance (the override list is not rebuilt from the tx set)
// but NOT across process restart -- the caller replays its registrations after wallet load.
// Idempotent. Returns 1 if this call newly excluded the outpoint, 0 if it was already
// registered.
// The composed spent/held answer for one outpoint, as the asset layer consumes it:
//    0 SPENT       the outpoint is in the wallet's spentOutputs set
//    1 HELD        the funding tx is known, valid, and the outpoint is unspent
//   -1 UNDETECTED  the wallet has no record of the funding tx (e.g. below the scan floor)
//   -2 CONFLICTED  the funding tx is known but INVALID -- another transaction spent its
//                  inputs, which is what a stuck send looks like after the user re-sends
//
// CONFLICTED exists because spent-ness cannot see it. Nothing ever spends the abandoned
// attempt's OWN change output, so BRWalletOutpointSpent answers "unspent" forever while
// BRWalletTransactionForHash answers "known" -- the pair reads HELD, and the asset layer
// counts one send's change twice (measured: a supply-10 asset displaying 18).
// BRWalletTransactionIsValid is the only predicate that separates them.
int BRWalletOutpointAssetState(BRWallet *wallet, UInt256 txHash, uint32_t n)
{
    BRTransaction *tx;

    assert(wallet != NULL);
    if (BRWalletOutpointSpent(wallet, txHash, n)) return 0;

    tx = BRWalletTransactionForHash(wallet, txHash);
    if (! tx) return -1;
    if (! BRWalletTransactionIsValid(wallet, tx)) return -2;
    return 1;
}

int BRWalletRegisterAssetOutpoint(BRWallet *wallet, UInt256 txHash, uint32_t n)
{
    int added = 0;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    if (! _BRWalletIsAssetOverride(wallet, txHash, n)) {
        array_add(wallet->assetOverrides, ((BRUTXO) { txHash, n }));
        added = 1;
        _BRWalletUpdateBalance(wallet);
    }

    pthread_mutex_unlock(&wallet->lock);
    return added;
}

int BRWalletUtxoIsAsset(BRWallet* wallet, BRUTXO* utxo) {
    for (int j = 0; j < array_count(wallet->assetUtxos); ++j) {
        BRUTXO* assetUtxo = &wallet->assetUtxos[j];
        if (UInt256Eq(utxo->hash, assetUtxo->hash) && utxo->n == assetUtxo->n)
            return 1;
    }
    
    return 0;
}

BRTransaction* BRGetTransactions(BRWallet *wallet)
{
    return *wallet->transactions;
}

BRUTXO* BRGetUTXO(BRWallet *wallet)
{
    return wallet->utxos;
}

int BRWalletHasAssetUtxo(BRWallet* wallet, const char* txid, int index) {    
    UInt256 hash = UInt256Reverse(uint256(txid));
    
    for (size_t j = 0; j < array_count(wallet->assetUtxos); j++) {
        BRUTXO* utxo = &wallet->assetUtxos[j];
        if (UInt256Eq(utxo->hash, hash) && utxo->n == index) return 1;
    }
    
    return 0;
}

// Same as BROutputSpendable, but callable from Swift
int BRWalletUtxoSpendable(BRWallet* wallet, const char* txid, int index) {
    UInt256 hash = UInt256Reverse(uint256(txid));
    
    BRTxInput input;
    input.txHash = UInt256Reverse(uint256(txid));
    input.index = index;

    if (BRSetContains(wallet->spentOutputs, &input)) return 0;
    return 1;
}

void _printUtxo(void* info, void* utxo) {
    BRUTXO* u = utxo;
    printf("  UTXO %s %d\n", u256hex(UInt256Reverse(u->hash)), u->n);
}

void BRWalletPrintUtxos(BRWallet* wallet) {
#if DEBUG
    size_t count;
    
    printf("UTXOS:\n");
    for (size_t j = array_count(wallet->utxos); j > 0; j--) {
        _printUtxo(NULL, &wallet->utxos[j - 1]);
    }
    
    printf("ASSET UTXOS:\n");
    for (size_t j = array_count(wallet->assetUtxos); j > 0; j--) {
        _printUtxo(NULL, &wallet->assetUtxos[j - 1]);
    }
    
    printf("SPENT UTXOS:\n");
    BRSetApply(wallet->spentOutputs, NULL, _printUtxo);
#endif
}

BRTransaction* BRGetTxForUTXO(BRWallet *wallet, BRUTXO utxo)
{
    BRTransaction *t = BRSetGet(wallet->allTx, &utxo.hash);
    return t;
}

uint8_t BROutputSpendable(BRWallet *wallet, const BRTxOutput output)
{
    if (BROutpointIsAsset(&output) > 0) return 0;
    if (BRSetContains(wallet->spentOutputs, &output)) return 0;
    return 1;
}
