//
//  BRWatchDescriptor.h
//
//  Watch-only ("cold account") descriptors: read the public kit a HoldFast Vault (or any BIP380 wallet)
//  exports, refuse anything that is not a DigiByte account key, derive its addresses, and answer "does
//  this address belong to that cold seed?" before anyone funds it.
//
//  WHAT IS ACCEPTED. One output descriptor per call, exactly as the Vault writes it (dgb-coldprep 2.0,
//  src/core.js deriveWallet/buildWatchKit), BIP380 checksum required:
//
//      wpkh([73c5da0a/84h/20h/0h]xpub.../0/*)#xw9vv378        P2WPKH, dgb1q...
//      tr([73c5da0a/86h/20h/0h]xpub.../0/*)#z6f6ngtx          P2TR (BIP86 key path), dgb1p...
//      sh(wpkh([73c5da0a/49h/20h/0h]xpub.../0/*))#05raepzf    P2SH-P2WPKH, S...
//      pkh([73c5da0a/44h/20h/0h]xpub.../0/*)#a5xmpgaa         P2PKH, D...
//
//  The key origin is mandatory: its master fingerprint is what a person compares with the Vault screen,
//  and its coin type is the chain tag. DigiByte and Dogecoin legacy addresses both start with "D" and
//  share a version byte, so the address alone cannot tell them apart; the origin can (coin type 20 vs 3).
//  Anything whose coin type is not this network's (20 on mainnet, 1 on testnet) is refused with
//  BR_WATCH_ERR_WRONG_CHAIN, and coinType is still filled in so the screen can say which chain it is.
//
//  Also refused: a missing or wrong checksum (a mistyped key would watch someone else's addresses), any
//  private key (xprv/tprv), an origin purpose that does not match its wrapper (wpkh with 44h), an origin
//  that is not three hardened levels, an xpub whose depth and child number disagree with the origin, a
//  path other than /0/* or /1/*, and anything with more than one key (multisig is a later phase).
//
//  DERIVATION. `mpk` is the account key at m/purpose'/coin'/account', in the form BRBIP32PubKey and
//  BRWalletNewDual / BRWalletSetTaprootKey take: a keyless wallet built from the P2WPKH and P2TR
//  descriptors is the same wallet, address for address, as HoldFast's own wallet for that seed. mpk is
//  byte for byte what BRBIP32MasterPubKeyBIP84 / BIP86 return for the seed: its fingerPrint is the SEED's
//  fingerprint from the origin, as those functions set it, not the parent fingerprint the xpub serializes.
//
//  Test seam (host KAT watch_descriptor_kat in the Android repo): WATCH_DESCRIPTOR_RED_CHAIN skips the
//  coin-type check, the plausible slip of trusting an address prefix. Only the wrong-chain cases may fail
//  under it.
//
//  No I/O, no allocation, no locking. Reads BRNetworkIsTestnet() for the expected coin type and version.
//

#ifndef BRWatchDescriptor_h
#define BRWatchDescriptor_h

#include <stddef.h>
#include <stdint.h>
#include "BRBIP32Sequence.h"
#include "BRDerivationProfiles.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_WATCH_DESCRIPTOR_MAX_LEN  512       // longest descriptor accepted, checksum included
#define BR_WATCH_FIND_LIMIT_MAX      100000u   // cap on BRWatchDescriptorFindAddress's per-branch search
#define BR_WATCH_COIN_TYPE_MAINNET   20        // SLIP-44 DigiByte
#define BR_WATCH_COIN_TYPE_TESTNET   1

typedef enum {
    BR_WATCH_OK = 0,
    BR_WATCH_ERR_NULL,            // no descriptor, or no output struct
    BR_WATCH_ERR_TOO_LONG,
    BR_WATCH_ERR_NO_CHECKSUM,     // no "#xxxxxxxx" at the end
    BR_WATCH_ERR_BAD_CHECKSUM,    // checksum does not match: a typo or a changed character
    BR_WATCH_ERR_SCRIPT,          // not one of wpkh(), tr(), sh(wpkh()), pkh(), or malformed
    BR_WATCH_ERR_NO_ORIGIN,       // no [fingerprint/path] before the key
    BR_WATCH_ERR_ORIGIN,          // origin is not 8 hex digits and three hardened levels
    BR_WATCH_ERR_PURPOSE,         // origin purpose does not match the wrapper
    BR_WATCH_ERR_WRONG_CHAIN,     // origin coin type is not this network's (coinType says which it is)
    BR_WATCH_ERR_PRIVATE_KEY,     // an xprv/tprv: never imported into a watch-only account
    BR_WATCH_ERR_XPUB,            // not a valid extended public key for this network
    BR_WATCH_ERR_XPUB_ORIGIN,     // xpub depth or child number disagrees with the origin
    BR_WATCH_ERR_PATH,            // derivation after the key is not /0/* or /1/*
} BRWatchResult;

typedef struct {
    int format;                    // BR_DERIVATION_FORMAT_P2PKH / _P2WPKH / _P2SH_P2WPKH / _P2TR
    uint8_t masterFingerprint[4];  // the seed's fingerprint, as printed in the origin (big-endian bytes)
    uint32_t purpose;              // 44, 49, 84 or 86 (unhardened value)
    uint32_t coinType;             // filled in even on BR_WATCH_ERR_WRONG_CHAIN
    uint32_t account;              // unhardened value
    uint32_t branch;               // 0 receive, 1 change: the branch the descriptor itself names
    BRMasterPubKey mpk;            // account-level key
} BRWatchDescriptor;

// Parses and validates one descriptor. On BR_WATCH_OK every field of *out is set. On an error, *out is
// zeroed except for the fields already read when the error was found (coinType on WRONG_CHAIN).
BRWatchResult BRWatchDescriptorParse(BRWatchDescriptor *out, const char *descriptor);

// Short stable name of a result, for logs and for the platform's message lookup ("wrong_chain").
const char *BRWatchResultName(BRWatchResult result);

// Writes the descriptor's master fingerprint as 8 lowercase hex digits plus NUL to out (9 bytes).
void BRWatchDescriptorFingerprintHex(const BRWatchDescriptor *d, char out[9]);

// Writes the address at m/purpose'/coin'/account'/chain/index in the descriptor's own format to addr.
// chain is 0 (receive) or 1 (change), whatever branch the descriptor named. Returns the number of
// bytes written including the NUL, or 0 on failure (bad arguments, a buffer too small, a derivation that
// fails).
size_t BRWatchDescriptorAddress(const BRWatchDescriptor *d, uint32_t chain, uint32_t index,
                                char *addr, size_t addrLen);

// Looks for addr among indexes 0..limit-1 of the receive branch, then of the change branch. Bech32
// addresses compare without regard to case (QR codes often carry them in upper case). limit is capped at
// BR_WATCH_FIND_LIMIT_MAX. Returns 1 and sets *chain and *index when found, else 0.
int BRWatchDescriptorFindAddress(const BRWatchDescriptor *d, const char *addr, uint32_t limit,
                                 uint32_t *chain, uint32_t *index);

#ifdef __cplusplus
}
#endif

#endif // BRWatchDescriptor_h
