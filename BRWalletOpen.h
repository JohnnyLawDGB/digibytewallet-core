//
//  BRWalletOpen.h
//
//  The ONE recipe for opening a wallet from its seed: which key trees it
//  watches, in what order they are installed, and how saved transactions are
//  loaded. Shared by every platform so that the same seed gives the same
//  address set -- and therefore the same balance -- on Android and iOS.
//
//  Until 2026-10 the recipe lived in the Android JNI bridge (jni_wallet.c,
//  create/recoverWalletFromBytes), an Android-only compilation unit, and iOS
//  wrote its own: BRWalletNew over the BIP84 key alone. That iOS wallet watched
//  neither the legacy breadwallet tree nor the BIP86 Taproot tree, so funds on
//  either were invisible on iOS while Android counted them -- a severity-1
//  divergence (digibytewallet-ios docs/port-plan-4.0.89.md, D2). Android also
//  disagreed with itself: the session that CREATED a wallet used BRWalletNew
//  (no legacy tree) and every later unlock used BRWalletNewDual. This header is
//  the single recipe both paths and both platforms now call.
//
//  The trees, all from the same BIP39 seed:
//    BIP84  m/84'/20'/0'  "Bitcoin seed"   P2WPKH  -- receive and change
//    legacy m/0H          "DigiByte seed"  P2PKH + P2WPKH -- breadwallet-era
//                                           coins, watched so a restored old
//                                           seed shows its funds
//    BIP86  m/86'/20'/0'  "Bitcoin seed"   P2TR    -- Taproot / DigiDollar
//
//  Order is load-bearing and lives in BRWalletNewDual / BRWalletSetTaprootKey:
//  the legacy chains are registered BEFORE saved transactions are added (or
//  old m/0H transactions are rejected), and installing the Taproot key re-runs
//  the balance so saved P2TR outputs are credited. Do not reorder here.
//
//  Host KAT: digibytewallet-android native/src/test/host/wallet_open_kat/.
//  Header-only, static inline; no locking or I/O of its own.
//

#ifndef BRWalletOpen_h
#define BRWalletOpen_h

#include "BRWallet.h"
#include "BRBIP32Sequence.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The key trees a wallet opened by this recipe watches, as data, so a platform
// parity test can assert the set rather than infer it.
#define BR_WALLET_TREE_BIP84    0x1u
#define BR_WALLET_TREE_LEGACY   0x2u
#define BR_WALLET_TREE_BIP86    0x4u
#define BR_WALLET_OPEN_TREES    (BR_WALLET_TREE_BIP84 | BR_WALLET_TREE_LEGACY | BR_WALLET_TREE_BIP86)

// The three master PUBLIC keys a wallet is opened from. Public data: a platform
// may store these to open the wallet -- and sync -- without reading the seed,
// which then is needed only to sign.
typedef struct {
    BRMasterPubKey bip84;
    BRMasterPubKey legacy;
    BRMasterPubKey bip86;
} BRWalletMasterKeys;

// Derives the three master public keys from a BIP39 seed (BRBIP39DeriveKey
// output, normally 64 bytes). The caller still owns, and zeroes, the seed.
static inline BRWalletMasterKeys BRWalletMasterKeysFromSeed(const void *seed, size_t seedLen)
{
    BRWalletMasterKeys keys;

    keys.bip84 = BRBIP32MasterPubKeyBIP84(seed, seedLen);
    keys.legacy = BRBIP32MasterPubKeyLegacy(seed, seedLen);
    keys.bip86 = BRBIP32MasterPubKeyBIP86(seed, seedLen);
    return keys;
}

// Opens a wallet watching every tree in BR_WALLET_OPEN_TREES. Use this for a new
// wallet, a restored wallet and every later unlock alike.
//
// transactions/txCount: saved transactions, exactly as for BRWalletNew -- the
// wallet takes ownership of each BRTransaction, the array stays the caller's.
// Pass NULL, 0 for a wallet with no history.
//
// Returns NULL if the wallet could not be created. Free with BRWalletFree().
static inline BRWallet *BRWalletOpenWithKeys(BRTransaction *transactions[], size_t txCount,
                                             BRWalletMasterKeys keys)
{
#ifdef WALLET_OPEN_SINGLE_TREE_UNFIXED
    // RED-gate shape only: the iOS recipe before 2026-10-10, BIP84 alone. Never
    // defined in a production build.
    return BRWalletNew(transactions, txCount, keys.bip84);
#else
    BRWallet *wallet = BRWalletNewDual(transactions, txCount, keys.bip84, keys.legacy);

    if (wallet) BRWalletSetTaprootKey(wallet, keys.bip86);
    return wallet;
#endif
}

// BRWalletOpenWithKeys over keys derived from seed. The caller zeroes the seed.
static inline BRWallet *BRWalletOpenFromSeed(const void *seed, size_t seedLen,
                                             BRTransaction *transactions[], size_t txCount)
{
    return BRWalletOpenWithKeys(transactions, txCount, BRWalletMasterKeysFromSeed(seed, seedLen));
}

#ifdef __cplusplus
}
#endif

#endif // BRWalletOpen_h
