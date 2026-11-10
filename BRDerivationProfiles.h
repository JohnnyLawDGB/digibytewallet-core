//
//  BRDerivationProfiles.h
//
//  The derivation profiles "Recover funds" probes when a person enters a recovery phrase: each one a
//  master HMAC key, a hardened path prefix, the address encodings to write each key as, whether it is
//  this wallet's own derivation, and the window it starts at. Until 2026-11 the table lived only in
//  Android Kotlin (core/.../recovery/DerivationProfile.kt, BUILT_INS); both platforms now read it here,
//  and BRRecoveryDerive.h derives the addresses.
//
//  THE TABLE (in this order, the order the scan reports results in):
//    0  BIP84 DGB (current wallet)       "Bitcoin seed"   m/84'/20'/0'  P2WPKH, then P2PKH   native
//    1  Legacy DigiByte mobile wallet    "DigiByte seed"  m/0'          P2PKH
//    2  Legacy m/0H with standard HMAC   "Bitcoin seed"   m/0'          P2PKH
//    3  BIP44 DGB                        "Bitcoin seed"   m/44'/20'/0'  P2PKH
//    4  BIP44 wrong-coin accident        "Bitcoin seed"   m/44'/0'/0'   P2PKH
//    5  BIP49 DGB (P2SH-wrapped segwit)  "Bitcoin seed"   m/49'/20'/0'  P2SH-P2WPKH
//    6  BIP86 DGB (Taproot)              "Bitcoin seed"   m/86'/20'/0'  P2TR                 native
//  Every profile starts at BR_DERIVATION_GAP_EXTERNAL_START external and BR_DERIVATION_GAP_INTERNAL_START
//  internal addresses; BRRecoveryGapWindow.h decides how a window grows from there.
//
//  FORMATS. formats[0] is the profile's own encoding (Kotlin's addressFormat); the rest are other
//  encodings of the SAME keys (Kotlin's extraAddressFormats), probed because the wallet hands them out:
//  the Receive screen offers the BIP84 key as bech32 and as legacy D..., so profile 0 is probed as both.
//  P2SH-P2WPKH is deliberately not an extra encoding anywhere (Android's reconcile backend refuses S...
//  addresses, and one refused address fails the whole batch). A platform derives every listed format and
//  merges them per profile, keeping the first entry for an address seen twice.
//
//  "native" means this wallet's own sync already watches the path, so recovering the wallet's own phrase
//  sweeps nothing from it; the UI imports rather than sweeps.
//
//  Paths are stored as Kotlin's prefixPath is: every element carries BIP32_HARD (0x80000000), written
//  here as a literal so this header needs nothing but libc. BRRecoveryDeriveAddresses takes them as is.
//
//  label and description are the English strings Android shows in the scan results (they are not
//  localised there either). Every value in this header is a plain literal so Swift imports it.
//
//  Test seam (host KAT derivation_profiles_kat in the Android repo): DERIVATION_PROFILES_RED gives the
//  BIP49 profile the P2WPKH encoding instead of P2SH-P2WPKH -- a plausible porting slip. Only the BIP49
//  cases may fail under it.
//
//  Header-only, static inline. No I/O, no locking, libc only.
//

#ifndef BRDerivationProfiles_h
#define BRDerivationProfiles_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_DERIVATION_HMAC_STANDARD "Bitcoin seed"
#define BR_DERIVATION_HMAC_DIGIBYTE "DigiByte seed"

// Address encodings, as Android's bridge numbers them.
#define BR_DERIVATION_FORMAT_P2PKH       0   // D...
#define BR_DERIVATION_FORMAT_P2WPKH      1   // dgb1q...
#define BR_DERIVATION_FORMAT_P2SH_P2WPKH 2   // S...
#define BR_DERIVATION_FORMAT_P2TR        3   // dgb1p... (BIP86 key path)
#define BR_DERIVATION_FORMAT_COUNT       4

// The window every profile starts at (Kotlin's DEFAULT_GAP_EXTERNAL / DEFAULT_GAP_INTERNAL).
#define BR_DERIVATION_GAP_EXTERNAL_START 200
#define BR_DERIVATION_GAP_INTERNAL_START 100

#define BR_DERIVATION_PROFILE_COUNT 7
#define BR_DERIVATION_PATH_MAX      3    // the longest prefix in the table
#define BR_DERIVATION_FORMATS_MAX   2    // the most encodings any profile is probed as

#define BR_DERIVATION_HARD 0x80000000u   // BIP32_HARD, restated as a literal (libc only); the KAT checks they agree

typedef struct {
    const char *label;
    const char *description;
    const char *hmacKey;
    uint32_t path[BR_DERIVATION_PATH_MAX];   // hardened prefix; entries past pathLen are 0
    size_t pathLen;
    int formats[BR_DERIVATION_FORMATS_MAX];  // formats[0] first; entries past formatCount are -1
    size_t formatCount;
    int isNative;
    int32_t gapExternal;                     // starting windows
    int32_t gapInternal;
} BRDerivationProfile;

// The table. The array lives inside the function so a translation unit that never asks for it carries
// no copy of it.
static inline const BRDerivationProfile *BRDerivationProfiles(size_t *count)
{
    static const BRDerivationProfile profiles[BR_DERIVATION_PROFILE_COUNT] = {
        { "BIP84 DGB (current wallet)",
          "m/84'/20'/0' \xE2\x80\x94 native bech32 addresses (dgb1q\xE2\x80\xA6)",
          BR_DERIVATION_HMAC_STANDARD,
          { 84 | BR_DERIVATION_HARD, 20 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD }, 3,
          { BR_DERIVATION_FORMAT_P2WPKH, BR_DERIVATION_FORMAT_P2PKH }, 2,
          1, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "Legacy DigiByte mobile wallet",
          "m/0H with \"DigiByte seed\" HMAC \xE2\x80\x94 pre-BIP84 DGB BreadWallet",
          BR_DERIVATION_HMAC_DIGIBYTE,
          { 0 | BR_DERIVATION_HARD, 0, 0 }, 1,
          { BR_DERIVATION_FORMAT_P2PKH, -1 }, 1,
          0, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "Legacy m/0H with standard HMAC",
          "m/0H with \"Bitcoin seed\" HMAC \xE2\x80\x94 early non-DGB BreadWallet forks",
          BR_DERIVATION_HMAC_STANDARD,
          { 0 | BR_DERIVATION_HARD, 0, 0 }, 1,
          { BR_DERIVATION_FORMAT_P2PKH, -1 }, 1,
          0, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "BIP44 DGB",
          "m/44'/20'/0' \xE2\x80\x94 Coinomi, Trezor, Ledger-compatible DGB",
          BR_DERIVATION_HMAC_STANDARD,
          { 44 | BR_DERIVATION_HARD, 20 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD }, 3,
          { BR_DERIVATION_FORMAT_P2PKH, -1 }, 1,
          0, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "BIP44 wrong-coin accident",
          "m/44'/0'/0' \xE2\x80\x94 seeds typed into a BTC wallet then imported back",
          BR_DERIVATION_HMAC_STANDARD,
          { 44 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD }, 3,
          { BR_DERIVATION_FORMAT_P2PKH, -1 }, 1,
          0, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "BIP49 DGB (P2SH-wrapped segwit)",
          "m/49'/20'/0' \xE2\x80\x94 wrapped segwit addresses (S\xE2\x80\xA6)",
          BR_DERIVATION_HMAC_STANDARD,
          { 49 | BR_DERIVATION_HARD, 20 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD }, 3,
#ifdef DERIVATION_PROFILES_RED
          // RED ARM SEAM (derivation_profiles_kat): the wrapped profile written as native segwit.
          { BR_DERIVATION_FORMAT_P2WPKH, -1 }, 1,
#else
          { BR_DERIVATION_FORMAT_P2SH_P2WPKH, -1 }, 1,
#endif
          0, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
        { "BIP86 DGB (Taproot)",
          "m/86'/20'/0' \xE2\x80\x94 taproot addresses (dgb1p\xE2\x80\xA6)",
          BR_DERIVATION_HMAC_STANDARD,
          { 86 | BR_DERIVATION_HARD, 20 | BR_DERIVATION_HARD, 0 | BR_DERIVATION_HARD }, 3,
          { BR_DERIVATION_FORMAT_P2TR, -1 }, 1,
          1, BR_DERIVATION_GAP_EXTERNAL_START, BR_DERIVATION_GAP_INTERNAL_START },
    };

    if (count) *count = BR_DERIVATION_PROFILE_COUNT;
    return profiles;
}

// Profile i, or NULL past the end.
static inline const BRDerivationProfile *BRDerivationProfileAt(size_t i)
{
    return (i < BR_DERIVATION_PROFILE_COUNT) ? &BRDerivationProfiles(NULL)[i] : NULL;
}

#ifdef __cplusplus
}
#endif

#endif // BRDerivationProfiles_h
