//
//  BRDigiScopePins.h
//
//  The certificate pins for api.digiscope.me, the one server the wallets talk to besides
//  DigiByte peers (the seeder peer list, DigiScope, the Hub). Both platforms pin it, and a pin
//  set that differs between them means one platform can be talked to by a server the other would
//  refuse. Android hand-copied its pin into three clients once; a rotation updated one of them
//  and the other two failed for weeks. One list, here, for every client on every platform.
//
//  A pin is "sha256/" + base64(SHA-256(SubjectPublicKeyInfo DER)), as OkHttp writes it. A
//  connection is accepted when the system trusts the chain AND any certificate in it matches a
//  current pin. The leaf AND the Let's Encrypt intermediate are pinned, so a routine leaf renewal
//  with a new key does not break the wallet while the intermediate stays.
//
//  ROTATION: move outgoing pins to the retired list and add the new ones; never re-add a retired
//  pin (the KAT refuses overlap). Extract the live pins with:
//    openssl s_client -connect api.digiscope.me:443 -servername api.digiscope.me -showcerts \
//      </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
//      | openssl dgst -sha256 -binary | openssl enc -base64
//  (that pipeline reads the first certificate only; repeat per certificate for the intermediate)
//
//  Verified against the live chain 2026-10-10: leaf CN=api.digiscope.me (EC P-256, valid to
//  2026-12-21) and Let's Encrypt YE1 (EC P-384, valid to 2028-09-02) both match.
//
//  Host KAT: digibytewallet-android native/src/test/host/digiscope_pins_kat/.
//  Header-only, static inline.
//

#ifndef BRDigiScopePins_h
#define BRDigiScopePins_h

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_DIGISCOPE_HOST "api.digiscope.me"

static const char *const _brDigiScopePins[] = {
    "sha256/mxkNfnacx0nKcMPntNt/8/iv7iEoVNyg0WkCOt2FdU0=",   // leaf (CN=api.digiscope.me)
    "sha256/brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",   // Let's Encrypt intermediate YE1
#ifdef DIGISCOPE_PINS_RED
    "sha256/VDo86Ks/QFE3kVoOXkmNVWTovKKNMFQsBd4KGvoP8OU=",   // RED ARM SEAM: a retired pin left live
#endif
};

static const char *const _brDigiScopeRetiredPins[] = {
    "sha256/VDo86Ks/QFE3kVoOXkmNVWTovKKNMFQsBd4KGvoP8OU=",   // old leaf, retired 2026-07-10
    "sha256/y7xVm0TVJNahMr2sZydE2jQH8SquXV9yLF9seROHHHU=",   // old intermediate, retired 2026-07-10
};

static inline size_t BRDigiScopePinCount(void)
{
    return sizeof(_brDigiScopePins) / sizeof(_brDigiScopePins[0]);
}

// The i-th current pin, or NULL past the end.
static inline const char *BRDigiScopePinAt(size_t i)
{
    return i < BRDigiScopePinCount() ? _brDigiScopePins[i] : NULL;
}

static inline size_t BRDigiScopeRetiredPinCount(void)
{
    return sizeof(_brDigiScopeRetiredPins) / sizeof(_brDigiScopeRetiredPins[0]);
}

static inline const char *BRDigiScopeRetiredPinAt(size_t i)
{
    return i < BRDigiScopeRetiredPinCount() ? _brDigiScopeRetiredPins[i] : NULL;
}

// 1 when pin (NUL-terminated, "sha256/..." form) is a CURRENT pin. A retired pin never matches.
static inline int BRDigiScopePinMatches(const char *pin)
{
    if (! pin) return 0;
    for (size_t i = 0; i < BRDigiScopeRetiredPinCount(); i++) if (strcmp(pin, _brDigiScopeRetiredPins[i]) == 0) return 0;
    for (size_t i = 0; i < BRDigiScopePinCount(); i++) if (strcmp(pin, _brDigiScopePins[i]) == 0) return 1;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiScopePins_h
