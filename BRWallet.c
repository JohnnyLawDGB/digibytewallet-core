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
    BRTransaction **transactions;
    BRMasterPubKey masterPubKey;
    BRAddress *internalChain, *externalChain;
    BRAddress *internalChainSegwit, *externalChainSegwit;
    // Legacy key support: populated by BRWalletNewDual for recovery scanning of old m/0H addresses
    BRMasterPubKey legacyPubKey;
    int hasLegacyKey;
    BRAddress *legacyExternalChain;
    BRAddress *legacyInternalChain;
    BRAddress *legacyExternalChainSegwit;
    BRAddress *legacyInternalChainSegwit;
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

inline static int _BRWalletTxIsAscending(BRWallet *wallet, const BRTransaction *tx1, const BRTransaction *tx2)
{
    if (! tx1 || ! tx2) return 0;
    if (tx1->blockHeight > tx2->blockHeight) return 1;
    if (tx1->blockHeight < tx2->blockHeight) return 0;
    
    for (size_t i = 0; i < tx1->inCount; i++) {
        if (UInt256Eq(tx1->inputs[i].txHash, tx2->txHash)) return 1;
    }
    
    for (size_t i = 0; i < tx2->inCount; i++) {
        if (UInt256Eq(tx2->inputs[i].txHash, tx1->txHash)) return 0;
    }

    for (size_t i = 0; i < tx1->inCount; i++) {
        if (_BRWalletTxIsAscending(wallet, BRSetGet(wallet->allTx, &(tx1->inputs[i].txHash)), tx2)) return 1;
    }

    return 0;
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

static void _BRWalletUpdateBalance(BRWallet *wallet)
{
    int isInvalid, isPending;
    uint64_t balance = 0, prevBalance = 0;
    time_t now = time(NULL);
    size_t i, j;
    BRTransaction *tx, *t;
    BRTxOutput o;

    array_clear(wallet->utxos);
    array_clear(wallet->assetUtxos);
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
                array_add(wallet->balanceHist, balance);
                continue;
            }
        }

        // add outputs to UTXO set
        // TODO: don't add outputs below TX_MIN_OUTPUT_AMOUNT
        // TODO: don't add coin generation outputs < 100 blocks deep
        // NOTE: balance/UTXOs will then need to be recalculated when last block changes
        for (j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') {
                BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);
                
                if (BRSetContains(wallet->allAddrs, tx->outputs[j].address)) {
                    // If the tx contains an asset, we will skip the DUST transactions,
                    // otherwise there would be a chance of burning the received assets.
                    // Hence, skip adding the 600 dsatoshi transactions to the utxos.
#if DEBUG
                    printf("ASSETS: Checking %s:%d\n", u256hex(UInt256Reverse(tx->txHash)), j);
#endif
                    if (BRTxOutputIsAsset(tx, &tx->outputs[j])) {
                        array_add(wallet->assetUtxos, ((BRUTXO) { tx->txHash, (uint32_t)j }));
                        balance += 0;
                    } else {
                        // Add the UTXO to the internal list of utxos and add the balance
                        array_add(wallet->utxos, ((BRUTXO) { tx->txHash, (uint32_t)j }));
                        balance += tx->outputs[j].amount;
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
                balance -= o.amount;
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
    wallet->balance = balance;
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
    array_new(wallet->transactions, txCount + 100);
    wallet->feePerKb = DEFAULT_FEE_PER_KB;
    wallet->masterPubKey = mpk;
    array_new(wallet->internalChain, 50);
    array_new(wallet->externalChain, 50);
    array_new(wallet->internalChainSegwit, 50);
    array_new(wallet->externalChainSegwit, 50);
    wallet->hasLegacyKey = 0;
    array_new(wallet->legacyExternalChain, 50);
    array_new(wallet->legacyInternalChain, 50);
    array_new(wallet->legacyExternalChainSegwit, 50);
    array_new(wallet->legacyInternalChainSegwit, 50);
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
        BRSetAdd(wallet->allTx, tx);
        _BRWalletInsertTx(wallet, tx);

        for (size_t j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') BRSetAdd(wallet->usedAddrs, tx->outputs[j].address);
        }
    }
    
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 1);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 1);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0, 0);
    BRWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1, 0);
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
        BRSetAdd(wallet->allAddrs, &addrChain[array_count(addrChain) - 1]);
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

    // NOW register saved transactions — both BIP84 and legacy addresses are
    // in allAddrs, so transactions from either key tree will be recognized.
    if (transactions && txCount > 0) {
        for (size_t i = 0; i < txCount; i++) {
            if (transactions[i]) {
                BRWalletRegisterTransaction(wallet, transactions[i]);
            }
        }
    }

    return wallet;
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
size_t BRWalletUnusedAddrs(BRWallet *wallet, BRAddress addrs[], uint32_t gapLimit, int internal, int nativeSegwit)
{
    BRAddress *addrChain;
    size_t i, j = 0, count, startCount;
    uint32_t chain = (internal) ? SEQUENCE_INTERNAL_CHAIN : SEQUENCE_EXTERNAL_CHAIN;

    assert(wallet != NULL);
    assert(gapLimit > 0);
    pthread_mutex_lock(&wallet->lock);
    
    if (nativeSegwit) {
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
        
        // Generate the pubkey from seed and write it into pubKey
        uint8_t pubKey[BRBIP32PubKey(NULL, 0, wallet->masterPubKey, chain, count)];
        size_t len = BRBIP32PubKey(pubKey, sizeof(pubKey), wallet->masterPubKey, chain, (uint32_t)count);
        
        // Convert pubKey to internal format
        if (! BRKeySetPubKey(&key, pubKey, len)) break;
        
        if (nativeSegwit) {
            // Generate the P2WPKH
            if (!BRKeySegwitAddress(&key, address.s, sizeof(address), OP_0) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        } else {
            // Generate the P2PKH
            if (!BRKeyAddress(&key, address.s, sizeof(address)) ||
                BRAddressEq(&address, &BR_ADDRESS_NONE)) break;
        }
        
        array_add(addrChain, address);
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
        addrChain == (internal ? wallet->internalChainSegwit : wallet->externalChainSegwit)) {
        for (i = startCount; i < count; i++) {
            BRSetAdd(wallet->allAddrs, &addrChain[i]);
        }
    }
    else {
        // Reassign the addressChain, if it got reallocated
        if (nativeSegwit) {
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

// writes all addresses previously genereated with BRWalletUnusedAddrs() to addrs
// returns the number addresses written, or total number available if addrs is NULL
size_t BRWalletAllAddrs(BRWallet *wallet, BRAddress addrs[], size_t addrsCount)
{
    size_t i, internalCount = 0, externalCount = 0;
    size_t internalCountSegwit, externalCountSegwit = 0;
    // Legacy chain counts
    size_t legIntCount = 0, legExtCount = 0, legIntSegCount = 0, legExtSegCount = 0;
    size_t rest = (addrsCount == 0 ? 100000 : addrsCount);

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    internalCountSegwit = (! addrs || array_count(wallet->internalChainSegwit) < rest) ?
        array_count(wallet->internalChainSegwit) : (addrsCount / 4);
    rest -= internalCountSegwit;

    internalCount = (! addrs || array_count(wallet->internalChain) < rest) ?
        array_count(wallet->internalChain) : (addrsCount / 4);
    rest -= internalCount;

    // Add the segwit addresses first
    for (i = 0; addrs && i < internalCountSegwit; i++)
        addrs[i] = wallet->internalChainSegwit[i];

    // Add the legacy addresses second
    for (i = 0; addrs && i < internalCount; i++)
        addrs[i + internalCountSegwit] = wallet->internalChain[i];

    externalCountSegwit = (! addrs || array_count(wallet->externalChainSegwit) < rest) ?
        array_count(wallet->externalChainSegwit) : (addrsCount / 4);
    rest -= externalCountSegwit;

    externalCount = (! addrs || array_count(wallet->externalChain) < rest) ?
                    array_count(wallet->externalChain) : rest;
    rest -= externalCount;

    // Add the external segwit addresses first
    for (i = 0; addrs && i < externalCountSegwit; i++)
        addrs[i + internalCount + internalCountSegwit] = wallet->externalChainSegwit[i];

    // Add the external legacy addresses second
    for (i = 0; addrs && i < externalCount; i++)
        addrs[i + internalCount + internalCountSegwit + externalCountSegwit] = wallet->externalChain[i];

    // Add legacy key chains (populated only when hasLegacyKey == 1)
    size_t primaryTotal = internalCount + externalCount + internalCountSegwit + externalCountSegwit;
    if (wallet->hasLegacyKey) {
        legIntSegCount = (! addrs || array_count(wallet->legacyInternalChainSegwit) < rest) ?
            array_count(wallet->legacyInternalChainSegwit) : rest;
        rest -= legIntSegCount;
        legIntCount = (! addrs || array_count(wallet->legacyInternalChain) < rest) ?
            array_count(wallet->legacyInternalChain) : rest;
        rest -= legIntCount;
        legExtSegCount = (! addrs || array_count(wallet->legacyExternalChainSegwit) < rest) ?
            array_count(wallet->legacyExternalChainSegwit) : rest;
        rest -= legExtSegCount;
        legExtCount = (! addrs || array_count(wallet->legacyExternalChain) < rest) ?
            array_count(wallet->legacyExternalChain) : rest;

        size_t off = primaryTotal;
        for (i = 0; addrs && i < legIntSegCount; i++)
            addrs[off + i] = wallet->legacyInternalChainSegwit[i];
        off += legIntSegCount;
        for (i = 0; addrs && i < legIntCount; i++)
            addrs[off + i] = wallet->legacyInternalChain[i];
        off += legIntCount;
        for (i = 0; addrs && i < legExtSegCount; i++)
            addrs[off + i] = wallet->legacyExternalChainSegwit[i];
        off += legExtSegCount;
        for (i = 0; addrs && i < legExtCount; i++)
            addrs[off + i] = wallet->legacyExternalChain[i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return primaryTotal + legIntCount + legExtCount + legIntSegCount + legExtSegCount;
}

// true if the address was previously generated by BRWalletUnusedAddrs() (even if it's now used)
int BRWalletContainsAddress(BRWallet *wallet, const char *addr)
{
    int r = 0;

    assert(wallet != NULL);
    assert(addr != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (addr) r = BRSetContains(wallet->allAddrs, addr);
    pthread_mutex_unlock(&wallet->lock);
    return r;
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
    return BRWalletCreateTxForOutputs(wallet, &o, 1);
}

BRTransaction *BRWalletCreateTxForOutputsEx(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount, int force) {
    BRTransaction *tx, *transaction = BRTransactionNew();
    uint64_t feeAmount, amount = 0, balance = 0, minAmount;
    size_t i, j, cpfpSize = 0;
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
    
    minAmount = BRWalletMinOutputAmount(wallet);
    pthread_mutex_lock(&wallet->lock);
    feeAmount = _txFee(wallet->feePerKb, BRTransactionVSize(transaction) + TX_OUTPUT_SIZE);
    
    // TODO: use up all UTXOs for all used addresses to avoid leaving funds in addresses whose public key is revealed
    // TODO: avoid combining addresses in a single transaction when possible to reduce information leakage
    // TODO: use up UTXOs received from any of the output scripts that this transaction sends funds to, to mitigate an
    //       attacker double spending and requesting a refund
    for (i = 0; i < array_count(wallet->utxos); i++) {
        o = &wallet->utxos[i];
        tx = BRSetGet(wallet->allTx, o);
        
        if (! tx || o->n >= tx->outCount) continue;
        if (BRWalletUtxoIsAsset(wallet, o)) continue;

        BRTransactionAddInput(transaction, tx->txHash, o->n, tx->outputs[o->n].amount,
                              tx->outputs[o->n].script, tx->outputs[o->n].scriptLen, NULL, 0, NULL, 0, TXIN_SEQUENCE);
        
        if (BRTransactionVSize(transaction) + TX_OUTPUT_SIZE > TX_MAX_SIZE) { // transaction size-in-bytes too large
            BRTransactionFree(transaction);
            transaction = NULL;
            
            // check for sufficient total funds before building a smaller transaction
            if (wallet->balance < amount + _txFee(wallet->feePerKb, 10 + array_count(wallet->utxos)*TX_INPUT_SIZE +
                                                  (outCount + 1)*TX_OUTPUT_SIZE + cpfpSize)) break;
            pthread_mutex_unlock(&wallet->lock);
            
            if (outputs[outCount - 1].amount > amount + feeAmount + minAmount - balance) {
                BRTxOutput newOutputs[outCount];
                
                for (j = 0; j < outCount; j++) {
                    newOutputs[j] = outputs[j];
                }
                
                newOutputs[outCount - 1].amount -= amount + feeAmount - balance; // reduce last output amount
                transaction = BRWalletCreateTxForOutputs(wallet, newOutputs, outCount);
            }
            else transaction = BRWalletCreateTxForOutputs(wallet, outputs, outCount - 1); // remove last output
            
            balance = amount = feeAmount = 0;
            pthread_mutex_lock(&wallet->lock);
            break;
        }
        
        balance += tx->outputs[o->n].amount;
        
        //        // size of unconfirmed, non-change inputs for child-pays-for-parent fee
        //        // don't include parent tx with more than 10 inputs or 10 outputs
        //        if (tx->blockHeight == TX_UNCONFIRMED && tx->inCount <= 10 && tx->outCount <= 10 &&
        //            ! _BRWalletTxIsSend(wallet, tx)) cpfpSize += BRTransactionSize(tx);
        
        // fee amount after adding a change output
        feeAmount = _txFee(wallet->feePerKb, BRTransactionVSize(transaction) + TX_OUTPUT_SIZE + cpfpSize);
        
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
    }

    pthread_mutex_unlock(&wallet->lock);

    size_t totalKeys = bip84InternalCount + bip84ExternalCount + legacyInternalCount + legacyExternalCount;
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
int BRWalletRegisterTransaction(BRWallet *wallet, BRTransaction *tx)
{
    int wasAdded = 0, r = 1;
    
    assert(wallet != NULL);
    assert(tx != NULL && BRTransactionIsSigned(tx));
    
    if (tx && BRTransactionIsSigned(tx)) {
        pthread_mutex_lock(&wallet->lock);

        if (! BRSetContains(wallet->allTx, tx)) {
            if (_BRWalletContainsTx(wallet, tx)) {
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
        if (wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
        if (wallet->txAdded) wallet->txAdded(wallet->callbackInfo, tx);
    }

    return r;
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
    size_t i, j, k;
    
    assert(wallet != NULL);
    assert(txHashes != NULL || txCount == 0);
    pthread_mutex_lock(&wallet->lock);
    if (blockHeight > wallet->blockHeight) wallet->blockHeight = blockHeight;
    
    for (i = 0, j = 0; txHashes && i < txCount; i++) {
        tx = BRSetGet(wallet->allTx, &txHashes[i]);
        if (! tx || (tx->blockHeight == blockHeight && tx->timestamp == timestamp)) continue;
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
            if (BRSetContains(wallet->pendingTx, tx) || BRSetContains(wallet->invalidTx, tx)) needsUpdate = 1;
        }
        else if (blockHeight != TX_UNCONFIRMED) { // remove and free confirmed non-wallet tx
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

// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
uint64_t BRWalletAmountReceivedFromTx(BRWallet *wallet, const BRTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
    for (size_t i = 0; tx && i < tx->outCount; i++) {
        if (BRSetContains(wallet->allAddrs, tx->outputs[i].address)) amount += tx->outputs[i].amount;
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
            amount += t->outputs[n].amount;
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
            amount += t->outputs[n].amount;
        }
        else amount = UINT64_MAX;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->outCount && amount != UINT64_MAX; i++) {
        amount -= tx->outputs[i].amount;
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

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    for (i = array_count(wallet->utxos); i > 0; i--) {
        o = &wallet->utxos[i - 1];
        tx = BRSetGet(wallet->allTx, &o->hash);
        if (! tx || o->n >= tx->outCount) continue;
        inCount++;
        amount += tx->outputs[o->n].amount;
        
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
    array_free(wallet->balanceHist);

    for (size_t i = array_count(wallet->transactions); i > 0; i--) {
        BRTransactionFree(wallet->transactions[i - 1]);
    }

    array_free(wallet->transactions);
    array_free(wallet->utxos);
    array_free(wallet->assetUtxos);
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
