//
//  BRWallet.h
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

#ifndef BRWallet_h
#define BRWallet_h

#include "BRTransaction.h"
#include "BRAddress.h"
#include "BRBIP32Sequence.h"
#include "BRInt.h"
#include <string.h>

#define wallet_log(...) _wallet_log("%s:%"PRIu16" " _va_first(__VA_ARGS__, NULL) "\n", _va_rest(__VA_ARGS__, NULL))
#define _va_first(first, ...) first
#define _va_rest(first, ...) __VA_ARGS__

#if defined(TARGET_OS_MAC)
#include <Foundation/Foundation.h>
#define _wallet_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
#include <android/log.h>
#define _wallet_log(...) __android_log_print(ANDROID_LOG_DEBUG, "digiwallet", __VA_ARGS__)
#else
#include <stdio.h>
    #ifdef DEBUG
        #define _wallet_log(...) printf(__VA_ARGS__)
    #else
        #define _wallet_log(...)
    #endif
#endif

#if defined(TARGET_OS_MAC)
    #include <Foundation/Foundation.h>
    #define debug_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
    #include <android/log.h>
    #define debug_log(...) __android_log_print(ANDROID_LOG_DEBUG, "digiwallet", __VA_ARGS__)
#else
    #include <stdio.h>
    #ifdef DEBUG
        #define debug_log(...) printf(__VA_ARGS__)
    #else
        #define debug_log(...)
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_FEE_PER_KB 100000ULL                        // DigiByte 8.26+ default: 100 sat/byte = 100,000 sat/KB
#define MIN_FEE_PER_KB     100000ULL                        // DigiByte 8.26+ min relay fee: 100,000 sat/KB
#define MAX_FEE_PER_KB     ((1000100ULL*1000 + 190)/191)   // slightly higher than a 10000bit fee on a 191byte tx

typedef struct {
    UInt256 hash;
    uint32_t n;
} BRUTXO;
    


inline static size_t BRUTXOHash(const void *utxo)
{
    // (hash xor n)*FNV_PRIME
    return (size_t)((((const BRUTXO *)utxo)->hash.u32[0] ^ ((const BRUTXO *)utxo)->n)*0x01000193);
}

inline static int BRUTXOEq(const void *utxo, const void *otherUtxo)
{
    return (utxo == otherUtxo || (UInt256Eq(((const BRUTXO *)utxo)->hash, ((const BRUTXO *)otherUtxo)->hash) &&
                                  ((const BRUTXO *)utxo)->n == ((const BRUTXO *)otherUtxo)->n));
}

typedef struct BRWalletStruct BRWallet;
    
// allocates and populates a BRWallet struct that must be freed by calling BRWalletFree()
BRWallet *BRWalletNew(BRTransaction *transactions[], size_t txCount, BRMasterPubKey mpk);

// allocates a wallet with dual master key support: mpkBIP84 is the primary BIP84 key (m/84'/20'/0'),
// mpkLegacy is the legacy key (m/0H, "DigiByte seed") used only for recovery scanning of old addresses.
// Both address sets are included in the bloom filter and UTXO tracking.
// must be freed by calling BRWalletFree()
BRWallet *BRWalletNewDual(BRTransaction *transactions[], size_t txCount,
                          BRMasterPubKey mpkBIP84, BRMasterPubKey mpkLegacy);

// returns non-zero if any UTXO in the wallet belongs to the legacy key chains (old m/0H addresses)
int BRWalletHasLegacyFunds(BRWallet *wallet);

// installs the BIP86 (Taproot / P2TR) master pub key (m/86'/20'/0') and pre-generates the
// gap+100 external (receive) and internal (change) P2TR address windows, so
// BRWalletReceiveAddress()/BRWalletUnusedAddrs() with scriptType 2 return dgb1p… addresses.
// Call once, right after wallet creation, before syncing.
// FUND-SAFETY: taprootMpk MUST be the m/86' twin derived from the SAME seed as the wallet's
// BIP84 masterPubKey — deriving P2TR over the m/84' key would produce unrecoverable addresses.
void BRWalletSetTaprootKey(BRWallet *wallet, BRMasterPubKey taprootMpk);

// not thread-safe, set callbacks once after BRWalletNew(), before calling other BRWallet functions
// info is a void pointer that will be passed along with each callback call
// void balanceChanged(void *, uint64_t) - called when the wallet balance changes
// void txAdded(void *, BRTransaction *) - called when transaction is added to the wallet
// void txUpdated(void *, const UInt256[], size_t, uint32_t, uint32_t)
//   - called when the blockHeight or timestamp of previously added transactions are updated
// void txDeleted(void *, UInt256, int, int) - called when a previously added transaction is removed from the wallet
void BRWalletSetCallbacks(BRWallet *wallet, void *info,
                          void (*balanceChanged)(void *info, uint64_t balance),
                          void (*txAdded)(void *info, BRTransaction *tx),
                          void (*txUpdated)(void *info, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                            uint32_t timestamp),
                          void (*txDeleted)(void *info, UInt256 txHash, int notifyUser, int recommendRescan));

// wallets are composed of chains of addresses
// each chain is traversed until a gap of a number of addresses is found that haven't been used in any transactions
// this function writes to addrs an array of <gapLimit> unused addresses following the last used address in the chain
// the internal chain is used for change addresses and the external chain for receive addresses
// addrs may be NULL to only generate addresses for BRWalletContainsAddress()
// scriptType selects the address encoding: 0 = P2PKH, 1 = P2WPKH (native segwit), 2 = P2TR (taproot)
// returns the number addresses written to addrs
size_t BRWalletUnusedAddrs(BRWallet *wallet, BRAddress addrs[], uint32_t gapLimit, int internal, int scriptType);

// returns the first unused external address
BRAddress BRWalletReceiveAddress(BRWallet *wallet, int useSegwit);

// returns the first unused internal address
BRAddress BRWalletInternalChangeAddress(BRWallet *wallet);
    
// writes all addresses previously genereated with BRWalletUnusedAddrs() to addrs
//
// RETURN CONTRACT — two explicit branches, relied on by every caller:
//   addrs == NULL : returns the TOTAL available, UNCLAMPED. addrsCount is ignored entirely.
//                   This is the sizing protocol; it must never be reduced by any bound, or a
//                   caller sizing a malloc from it silently gets an empty set.
//   addrs != NULL : returns the number of addresses actually WRITTEN, always <= addrsCount.
//
// The fill path is bounds-checked against addrsCount unconditionally, so a wallet that grows
// between a caller's sizing call and its fill call truncates rather than overrunning the buffer.
// PREFER BRWalletCopyAllAddrs() for new code: this two-call form releases wallet->lock between
// the calls, so the set it sizes is not necessarily the set it fills.
size_t BRWalletAllAddrs(BRWallet *wallet, BRAddress addrs[], size_t addrsCount);

// Where each address in a BRWalletCopyAllAddrs() snapshot came from. The snapshot is ordered
// derived-chains-first, then the explicitly-watched tail, so entries [0, derived) are derived
// and [derived, derived + watched) are watched pins.
typedef struct {
    size_t derived;   // BIP84 primary + legacy m/0H + BIP86 taproot chains
    size_t watched;   // explicitly-watched pins (BRWalletAddWatchedAddress)
} BRWalletAddrOrigins;

// Snapshot every address the wallet knows, allocating the buffer internally under a SINGLE
// wallet->lock hold so the address set cannot change between sizing and filling — the TOCTOU
// window that makes the two-call BRWalletAllAddrs() form unsafe.
//
// Allocating inside the lock (rather than exporting a lock/unlock pair so a caller could hold it
// across two calls) is deliberate: wallet->lock is NON-RECURSIVE and BRWalletUnusedAddrs() takes
// it internally, so any caller-held-lock scheme deadlocks. malloc never re-enters BRWallet, so
// wallet->lock remains a leaf lock with respect to the allocator.
//
// countOut receives the number of addresses; originsOut may be NULL if the split is not needed.
// Returns a malloc'd buffer the CALLER FREES WITH free(), or NULL (with *countOut = 0) on
// allocation failure or an empty wallet.
BRAddress *BRWalletCopyAllAddrs(BRWallet *wallet, size_t *countOut, BRWalletAddrOrigins *originsOut);

// How many addresses a BRWalletCopyAllAddrs() snapshot would contain, without building one.
//
// O(1): the sum of array_count over the derived chains and the watched pins — no allocation, no
// address encoding, no crypto. It exists as a CHANGE DETECTOR for callers that cache anything
// derived from the address set (see the compact-filter element cache in BRPeerManager), and it is
// cheap enough to call on a per-message path.
//
// Sound as such a detector because every chain here is append-only: addresses are added by
// BRWalletUnusedAddrs / the pregen helpers / BRWalletAddWatchedAddress and never removed or
// rewritten in place, so any change to the SET also changes this COUNT. A caller may therefore
// treat an unchanged count as "the address set is unchanged".
//
// Takes wallet->lock, which is a leaf lock, so this is safe to call with another subsystem's lock
// held (BRWalletGetFilterElements already does exactly that from under the peer manager's lock).
size_t BRWalletAllAddrsCount(BRWallet *wallet);

// Consistent snapshot of the change-detection key for the enumerated address set:
// a monotonic generation stamp and the address count, read under ONE lock hold.
//
// addrGen is sourced from a process-global counter, bumped at every append to an
// enumerated chain and at wallet construction. It therefore detects, in one comparison:
//   - any append (the common case);
//   - a change of WALLET, which the count alone CANNOT see — two different seeds produce
//     identical address counts with fully disjoint sets (measured: 1045 == 1045, 0 shared),
//     and being process-global it is immune to malloc handing back the same chunk.
// The count is kept alongside it as defence-in-depth: if a future author adds a chain
// mutation and forgets to bump addrGen, the count still catches it, so a missed bump
// degrades to a weaker check rather than to silent fund loss.
//
// NOT sufficient on its own. The emitted element BYTES are a function of (address strings,
// network), because BRAddressScriptPubKey encodes per BRNetworkIsTestnet(). A network
// switch leaves both fields unchanged while changing the elements — measured: count
// 645 -> 645, elements 645 -> 0. Any cache keyed on this MUST also compare
// BRNetworkIsTestnet().
void BRWalletAddrSetKey(BRWallet *wallet, uint64_t *outGen, size_t *outCount);

// true if the address was previously generated by BRWalletUnusedAddrs() (even if it's now used)
int BRWalletContainsAddress(BRWallet *wallet, const char *addr);

// Pin an address to watch permanently, independent of gap-limit derivation. Idempotent.
// Every address ever shown on the Receive screen is registered here so a receive to it is
// always in the BIP158 match set / balance detection, even if it later falls outside the
// derived window. Stored as a plain array (never as BRSet pointers) to avoid UAF.
void BRWalletAddWatchedAddress(BRWallet *wallet, const char *addr);

// true if the address was previously used as an input or output in any wallet transaction
int BRWalletAddressIsUsed(BRWallet *wallet, const char *addr);

// writes transactions registered in the wallet, sorted by date, oldest first, to the given transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t BRWalletTransactions(BRWallet *wallet, BRTransaction *transactions[], size_t txCount);

// serializes ALL registered transactions (oldest first) into `buf` as one persistence blob,
// holding wallet->lock across the ENTIRE size+write pass so no BRTransaction can be freed
// mid-serialize (the lock-safe replacement for the BRWalletTransactions-copy-then-serialize
// shape — same lock-release-then-use class as the saveBlocks race). Wire layout:
//   [4] tx count, then per tx: [4] serialized len, [4] blockHeight, [4] timestamp, [N] tx bytes.
// If buf == NULL or bufLen is too small, nothing is written and the REQUIRED size is returned;
// otherwise the blob is written and the number of bytes WRITTEN (== required size) is returned.
size_t BRWalletSerializeTransactions(BRWallet *wallet, uint8_t *buf, size_t bufLen);

// writes transactions registered in the wallet, and that were unconfirmed before blockHeight, to the transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t BRWalletTxUnconfirmedBefore(BRWallet *wallet, BRTransaction *transactions[], size_t txCount,
                                   uint32_t blockHeight);

// current wallet balance, not including transactions known to be invalid
uint64_t BRWalletBalance(BRWallet *wallet);

// wallet DigiDollar balance in cents (USD) — separate from the satoshi balance
uint64_t BRWalletDigiDollarBalance(BRWallet *wallet);

// total amount spent from the wallet (exluding change)
uint64_t BRWalletTotalSent(BRWallet *wallet);

// total amount received by the wallet (exluding change)
uint64_t BRWalletTotalReceived(BRWallet *wallet);

// writes unspent outputs to utxos and returns the number of outputs written, or number available if utxos is NULL
size_t BRWalletUTXOs(BRWallet *wallet, BRUTXO utxos[], size_t utxosCount);

// wallet's unspent DigiDollar token UTXOs (SEND coin-selection input)
size_t BRWalletDigiDollarUTXOs(BRWallet *wallet, BRUTXO utxos[], size_t utxosCount);

// true if the outpoint (txHash, n) has been spent by a registered tx. Reads the
// authoritative spentOutputs set (rebuilt every balance update from every
// registered tx's inputs — DGB, DigiAsset and DigiDollar alike), so it is the
// correct sovereign source of asset-marker spent-ness (assetUtxos is not pruned
// of spends and must not be used for this).
int BRWalletOutpointSpent(BRWallet *wallet, UInt256 txHash, uint32_t n);

// fee-per-kb of transaction size to use when creating a transaction
uint64_t BRWalletFeePerKb(BRWallet *wallet);
void BRWalletSetFeePerKb(BRWallet *wallet, uint64_t feePerKb);

// returns an unsigned transaction that sends the specified amount from the wallet to the given address
// result must be freed using BRTransactionFree()
BRTransaction *BRWalletCreateTransaction(BRWallet *wallet, uint64_t amount, const char *addr);

// returns an unsigned transaction that satisifes the given transaction outputs
// result must be freed using BRTransactionFree()
BRTransaction *BRWalletCreateTxForOutputs(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount);

// Build an unsigned DigiDollar transfer of `cents` to `recipientKey32` (decoded TD-address key);
// NULL on shortfall. Sign with BRWalletSignTransaction. Result freed by BRTransactionFree().
BRTransaction *BRWalletCreateDigiDollarTransfer(BRWallet *wallet, const uint8_t recipientKey32[32],
                                                uint64_t cents);

int BRWalletGetAddressPrivateKey(BRWallet* wallet, BRKey* key, const char* address, size_t addressLen, const void *seed, size_t seedLen);

// signs any inputs in tx that can be signed using private keys from the wallet
// forkId is 0 for bitcoin, 0x40 for b-cash
// seed is the master private key (wallet seed) corresponding to the master public key given when the wallet was created
// returns true if all inputs were signed, or false if there was an error or not all inputs were able to be signed
int BRWalletSignTransaction(BRWallet *wallet, BRTransaction *tx, int forkId, const void *seed, size_t seedLen);

// true if the given transaction is associated with the wallet (even if it hasn't been registered)
int BRWalletContainsTransaction(BRWallet *wallet, const BRTransaction *tx);

// adds a transaction to the wallet, or returns false if it isn't associated with the wallet
int BRWalletRegisterTransaction(BRWallet *wallet, BRTransaction *tx);

// removes a tx from the wallet and calls BRTransactionFree() on it, along with any tx that depend on its outputs
void BRWalletRemoveTransaction(BRWallet *wallet, UInt256 txHash);

// returns the transaction with the given hash if it's been registered in the wallet
BRTransaction *BRWalletTransactionForHash(BRWallet *wallet, UInt256 txHash);

// true if no previous wallet transaction spends any of the given transaction's inputs, and no inputs are invalid
int BRWalletTransactionIsValid(BRWallet *wallet, const BRTransaction *tx);

// true if transaction cannot be immediately spent (i.e. if it or an input tx can be replaced-by-fee)
int BRWalletTransactionIsPending(BRWallet *wallet, const BRTransaction *tx);

// true if tx is considered 0-conf safe (valid and not pending, timestamp is greater than 0, and no unverified inputs)
int BRWalletTransactionIsVerified(BRWallet *wallet, const BRTransaction *tx);

void BRFixAssetInputs(BRWallet *wallet, BRTransaction *assetTransaction);

// set the block heights and timestamps for the given transactions
// use height TX_UNCONFIRMED and timestamp 0 to indicate a tx should remain marked as unverified (not 0-conf safe)
void BRWalletUpdateTransactions(BRWallet *wallet, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                uint32_t timestamp);
    
// marks all transactions confirmed after blockHeight as unconfirmed (useful for chain re-orgs)
void BRWalletSetTxUnconfirmedAfter(BRWallet *wallet, uint32_t blockHeight);

// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
uint64_t BRWalletAmountReceivedFromTx(BRWallet *wallet, const BRTransaction *tx);

// returns the amount sent from the wallet by the trasaction (total wallet outputs consumed, change and fee included)
uint64_t BRWalletAmountSentByTx(BRWallet *wallet, const BRTransaction *tx);

// returns the fee for the given transaction if all its inputs are from wallet transactions, UINT64_MAX otherwise
uint64_t BRWalletFeeForTx(BRWallet *wallet, const BRTransaction *tx);

// historical wallet balance after the given transaction, or current balance if transaction is not registered in wallet
uint64_t BRWalletBalanceAfterTx(BRWallet *wallet, const BRTransaction *tx);

// fee that will be added for a transaction of the given size in bytes
uint64_t BRWalletFeeForTxSize(BRWallet *wallet, size_t size);

// fee that will be added for a transaction of the given amount
uint64_t BRWalletFeeForTxAmount(BRWallet *wallet, uint64_t amount);
    
// fee that will be added for a transaction of the given amount, without failing due to missing balances
uint64_t BRWalletForceFeeForTxAmount(BRWallet *wallet, uint64_t amount);

// outputs below this amount are uneconomical due to fees (TX_MIN_OUTPUT_AMOUNT is the absolute minimum output amount)
uint64_t BRWalletMinOutputAmount(BRWallet *wallet);

// maximum amount that can be sent from the wallet to a single address after fees
uint64_t BRWalletMaxOutputAmount(BRWallet *wallet);

// frees memory allocated for wallet, and calls BRTransactionFree() for all registered transactions
void BRWalletFree(BRWallet *wallet);

// returns the given amount (in satoshis) in local currency units (i.e. pennies, pence)
// price is local currency units per bitcoin
int64_t BRLocalAmount(int64_t amount, double price);

// returns the given local currency amount in satoshis
// price is local currency units (i.e. pennies, pence) per bitcoin
int64_t BRBitcoinAmount(int64_t localAmount, double price);

BRUTXO * BRGetUTXO(BRWallet *wallet);

int BRWalletUtxoIsAsset(BRWallet* wallet, BRUTXO* utxo);

int BRWalletHasAssetUtxo(BRWallet* wallet, const char* txid, int index);

int BRWalletUtxoSpendable(BRWallet* wallet, const char* txid, int index);

void BRWalletPrintUtxos(BRWallet* wallet);

BRTransaction* BRGetTransactions(BRWallet *wallet);

BRTransaction * BRGetTxForUTXO(BRWallet *wallet, BRUTXO utxo);

uint8_t BROutputSpendable(BRWallet *wallet, const BRTxOutput output);

#ifdef __cplusplus
}
#endif

#endif // BRWallet_h
