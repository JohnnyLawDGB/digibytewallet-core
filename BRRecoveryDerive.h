//
//  BRRecoveryDerive.h
//
//  The addresses "Recover funds" asks about for a recovery phrase: the phrase's BIP39 seed, then, per
//  derivation profile (BRDerivationProfiles.h) and encoding, the first gapExternal receive and
//  gapInternal change addresses. Until 2026-11 this was Android's bridge (jni_derive.c, mnemonicToSeed
//  and deriveAddresses); these functions give the same bytes for the same inputs, and the host KAT
//  derivation_profiles_kat holds the two together for every profile.
//
//  SEED. BRRecoveryMnemonicToSeed(seed, phrase, phraseLen, passphrase, passphraseLen):
//    - phrase: phraseLen bytes of UTF-8, not NUL-terminated; refused when phraseLen >= 512. The phrase
//      is not checked against the word list or its checksum (the bridge does not either). As in the
//      bridge, the derivation reads the phrase up to its first NUL byte, if it has one.
//    - passphrase: NULL or passphraseLen 0 means none (the same seed as the empty passphrase); refused
//      when passphraseLen >= 129, and refused -- never truncated -- when it contains a NUL byte
//      (Android 4.1.2 row 25). The caller NFKD-normalises it first, as BIP39 specifies.
//    - writes 64 bytes and returns 1; on a refusal writes 64 zero bytes and returns 0.
//
//  ADDRESSES. BRRecoveryDeriveAddresses(out, outSlots, seed, seedLen, hmacKey, path, pathLen,
//  gapExternal, gapInternal, addressFormat) derives the master public key at the hardened prefix `path`
//  (elements carry BIP32_HARD, as BRDerivationProfile.path does) from the seed with HMAC key `hmacKey`,
//  then writes, into consecutive BR_RECOVERY_ADDRESS_SLOT-byte slots of `out`:
//      slot 0 .. gapExternal-1                       chain 0 (receive), index = slot
//      slot gapExternal .. gapExternal+gapInternal-1  chain 1 (change),  index = slot - gapExternal
//  each slot a NUL-terminated address in addressFormat (BR_DERIVATION_FORMAT_*), or the empty string
//  where that child could not be derived or encoded (the bridge leaves those positions null). A slot
//  keeps its position either way: an empty slot never shifts a later address onto another child key.
//  BRRecoveryDerivedSlot reads a slot back with its (chain, index).
//  Returns 1, having written gapExternal + gapInternal slots. Returns 0 and writes nothing when: out,
//  seed or hmacKey is NULL; path is NULL with pathLen > 0; seedLen is 0 or above 64; a gap is
//  negative; addressFormat is not 0..3; or outSlots < gapExternal + gapInternal. Two gaps of 0 is
//  success with nothing written. Also refused: gapExternal + gapInternal slots that would not fit in
//  SIZE_MAX bytes (a 32-bit build).
//
//  NETWORK. Results depend on BRNetworkIsTestnet() at the call: P2PKH's version byte and the bech32 prefix
//  (P2WPKH, P2TR) follow it; P2SH-P2WPKH always uses DIGIBYTE_SCRIPT_ADDRESS, as the bridge does. Every
//  vector in vectors/recovery-derivation/ is mainnet.
//
//  Seed material (the copy of the phrase and passphrase, the master public key) is zeroed before
//  return. The caller owns every buffer, and zeroes its own seed. No I/O, no locking, no allocation.
//
//  Test seams (derivation_profiles_kat): RECOVERY_SEED_NUL_RED accepts a passphrase with a NUL, which the
//  derivation then reads only up to the NUL (the pre-4.1.2 shape); only the NUL refusal case may fail.
//  RECOVERY_ENCODER_RED writes P2SH-P2WPKH with the legacy script version byte (5, "3...") instead of
//  DIGIBYTE_SCRIPT_ADDRESS (63, "S..."); only the cases that encode format 2 may fail.
//
//  Header-only, static inline over the core's BIP32/BIP39/key/address functions.
//

#ifndef BRRecoveryDerive_h
#define BRRecoveryDerive_h

#include "BRDerivationProfiles.h"
#include "BRBIP32Sequence.h"
#include "BRBIP39Mnemonic.h"
#include "BRKey.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRCrypto.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_RECOVERY_SEED_LEN           64
#define BR_RECOVERY_PHRASE_MAX         511   // bytes; 512 and above is refused
#define BR_RECOVERY_PASSPHRASE_MAX     128   // bytes; 129 and above is refused
#define BR_RECOVERY_ADDRESS_SLOT       91    // bytes per address slot, NUL included (the bridge's buffer)

// The public key's address in addressFormat, into out (outLen bytes). 1 on success, 0 otherwise (out
// then holds the empty string when outLen > 0). jni_derive.c pubkey_to_address, format for format, except
// that what the core's encoders would assert on is refused here instead: a NULL key, outLen below
// BR_RECOVERY_ADDRESS_SLOT, and P2WPKH of an uncompressed key.
static inline int BRRecoveryAddressForKey(BRKey *key, int addressFormat, char *out, size_t outLen)
{
    size_t n = 0;

    if (! out || outLen == 0) return 0;
    out[0] = '\0';
    if (! key || outLen < BR_RECOVERY_ADDRESS_SLOT) return 0;
    if (addressFormat == BR_DERIVATION_FORMAT_P2WPKH && ! key->compressed) return 0;
    switch (addressFormat) {
    case BR_DERIVATION_FORMAT_P2PKH:
        n = BRKeyAddress(key, out, outLen);
        break;
    case BR_DERIVATION_FORMAT_P2WPKH:
        n = BRKeySegwitAddress(key, out, outLen, OP_0);
        break;
    case BR_DERIVATION_FORMAT_P2SH_P2WPKH: {
        // redeemScript = OP_0 <push 20> <hash160(pubkey)>, wrapped in P2SH.
        UInt160 pkh = BRKeyHash160(key), scriptHash;
        uint8_t witness[22], data[21];

        witness[0] = 0x00;
        witness[1] = 0x14;
        memcpy(&witness[2], &pkh, 20);
        BRHash160(&scriptHash, witness, sizeof(witness));
#ifdef RECOVERY_ENCODER_RED
        data[0] = DIGIBYTE_SCRIPT_ADDRESS_LEGACY;   // RED ARM SEAM (derivation_profiles_kat)
#else
        data[0] = DIGIBYTE_SCRIPT_ADDRESS;
#endif
        memcpy(&data[1], &scriptHash, 20);
        n = BRBase58CheckEncode(out, outLen, data, sizeof(data));
        break;
    }
    case BR_DERIVATION_FORMAT_P2TR:
        n = BRKeyTaprootAddress(key, out, outLen);
        break;
    default:
        return 0;
    }
    if (n > 0 && n <= outLen) return 1;
    out[0] = '\0';
    return 0;
}

static inline int BRRecoveryMnemonicToSeed(uint8_t seed[BR_RECOVERY_SEED_LEN],
                                           const void *phrase, size_t phraseLen,
                                           const void *passphrase, size_t passphraseLen)
{
    char phraseCopy[BR_RECOVERY_PHRASE_MAX + 1], passCopy[BR_RECOVERY_PASSPHRASE_MAX + 1];

    if (! seed) return 0;
    mem_clean(seed, BR_RECOVERY_SEED_LEN);
    if (! phrase || phraseLen > BR_RECOVERY_PHRASE_MAX) return 0;
    if (! passphrase) passphraseLen = 0;
    if (passphraseLen > BR_RECOVERY_PASSPHRASE_MAX) return 0;
#ifndef RECOVERY_SEED_NUL_RED
    if (passphraseLen > 0 && memchr(passphrase, 0, passphraseLen) != NULL) return 0;
#endif

    memcpy(phraseCopy, phrase, phraseLen);
    phraseCopy[phraseLen] = '\0';
    if (passphraseLen > 0) memcpy(passCopy, passphrase, passphraseLen);
    passCopy[passphraseLen] = '\0';

    BRBIP39DeriveKey(seed, phraseCopy, passCopy[0] ? passCopy : NULL);
    mem_clean(phraseCopy, sizeof(phraseCopy));
    mem_clean(passCopy, sizeof(passCopy));
    return 1;
}

static inline int BRRecoveryDeriveAddresses(char *out, size_t outSlots,
                                            const void *seed, size_t seedLen,
                                            const char *hmacKey, const uint32_t *path, size_t pathLen,
                                            int32_t gapExternal, int32_t gapInternal, int addressFormat)
{
    BRMasterPubKey mpk;
    BRKey child;
    uint8_t pub[33];
    size_t slot = 0, total;
    uint32_t chain;

    if (! out || ! seed || ! hmacKey || (! path && pathLen > 0)) return 0;
    if (seedLen == 0 || seedLen > BR_RECOVERY_SEED_LEN) return 0;
    if (gapExternal < 0 || gapInternal < 0) return 0;
    if (addressFormat < 0 || addressFormat >= BR_DERIVATION_FORMAT_COUNT) return 0;
    total = (size_t)gapExternal + (size_t)gapInternal;   // no wrap: two int32_t maxima fit in a 32-bit size_t
    // Every slot offset below is slot * BR_RECOVERY_ADDRESS_SLOT with slot < total, so bounding total bounds
    // them all (a 32-bit build reaches this with gaps in the tens of millions).
    if (total > SIZE_MAX / BR_RECOVERY_ADDRESS_SLOT) return 0;
    if (outSlots < total) return 0;
    if (total == 0) return 1;

    mpk = BRBIP32MasterPubKeyPath(seed, seedLen, hmacKey, path, pathLen);

    for (chain = 0; chain < 2; chain++) {
        int32_t gap = (chain == 0) ? gapExternal : gapInternal, index;

        for (index = 0; index < gap; index++, slot++) {
            char *addr = out + slot * BR_RECOVERY_ADDRESS_SLOT;
            size_t pubLen = BRBIP32PubKey(pub, sizeof(pub), mpk, chain, (uint32_t)index);

            addr[0] = '\0';
            if (pubLen == 0) continue;
            BRKeySetPubKey(&child, pub, pubLen);
            BRRecoveryAddressForKey(&child, addressFormat, addr, BR_RECOVERY_ADDRESS_SLOT);
            BRKeyClean(&child);
        }
    }

    mem_clean(pub, sizeof(pub));
    mem_clean(&mpk, sizeof(mpk));
    return 1;
}

// Slot `slot` of a BRRecoveryDeriveAddresses result written with gapExternal: its address, or NULL when
// the slot is empty or slot is past the result (total slots = gapExternal + gapInternal, passed as
// slots). chain and index (either may be NULL) receive the slot's true position, empty or not, so a
// caller that drops empty slots never re-numbers the survivors.
static inline const char *BRRecoveryDerivedSlot(const char *out, size_t slots, int32_t gapExternal, size_t slot,
                                                uint32_t *chain, uint32_t *index)
{
    const char *addr;

    if (! out || gapExternal < 0 || slot >= slots) return NULL;
    if (chain) *chain = (slot < (size_t)gapExternal) ? 0 : 1;
    if (index) *index = (uint32_t)((slot < (size_t)gapExternal) ? slot : slot - (size_t)gapExternal);
    addr = out + slot * BR_RECOVERY_ADDRESS_SLOT;
    return addr[0] ? addr : NULL;
}

#ifdef __cplusplus
}
#endif

#endif // BRRecoveryDerive_h
