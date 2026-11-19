//
//  BRDigiId.h
//
//  Digi-ID: the per-site identity key (SLIP-0013) and the signing of a login message. Until 2026-11
//  this lived only in the Android bridge (native/src/main/jni/bridge/slip13.c, seed_derive_identity_key
//  in jni_wallet.c, and jni_wallet_sign.c: sign_with_key, base64_encode, write_varint, message_utf8 and
//  the entry points signMessage, signIdentityMessage and identityAddress). It moves here unchanged: for
//  the same seed, URI bytes, index and message bytes, every key, address and signature here under the
//  root BR_DIGIID_ROOT_DIGIBYTE is byte-identical to the bridge's, and every input the bridge refuses is
//  refused here. The bridge takes no root: its per-site master key is always DIGIBYTE's, so it has no
//  answer for BR_DIGIID_ROOT_STANDARD to match.
//
//  Which of the two identities a login signs with is decided here as well (THE DIGISCOPE LIST and THE
//  CHOICE below: BRDigiIdIsDigiScopeHost, BRDigiIdChooseIdentity). The rule comes from the two apps, which
//  each held a list of DigiScope's two hosts and decided for itself (Android's IdentityKeyPolicy.kt, a
//  Swift list on iOS). An app keeps its own list only until it calls this.
//
//  THE RULES:
//    - THE PER-SITE IDENTITY of a site's URI and an account index i under a root is the key at
//      m/13'/A'/B'/C'/D', every step hardened, where h = SHA256(LE32(i) || uri) and A, B, C, D are h's
//      first 16 bytes read as four little-endian uint32 (SLIP-0013, the derivation of BitID's BIP draft),
//      and m is the BIP32 master key the root names, HMAC-SHA512(key, seed) with key:
//        BR_DIGIID_ROOT_DIGIBYTE  "DigiByte seed", BRBIP32PrivKeyPath's (the bread-wallet tree): every
//                                 per-site identity the bridge and this header gave before the root was
//                                 an argument;
//        BR_DIGIID_ROOT_STANDARD  "Bitcoin seed", BIP32's own (BR_DERIVATION_HMAC_STANDARD): the one
//                                 SLIP-0013 specifies, and the one Coinomi signs with.
//      The same URI and index give a different identity under each root.
//    - THE ROOT is an argument of every per-site call (BRDigiIdSiteKey, BRDigiIdSignSite, BRDigiIdAddress),
//      and this header has no default: the caller passes the root of the wallet it signs for, which is
//      that wallet's setting, not this header's. 0 is no root (BR_DIGIID_ROOT_NONE), so a zeroed or unset
//      value derives nothing; it is REFUSED, as is every value but DIGIBYTE and STANDARD. In
//      BRDigiIdAddress the root sits beside hasUri, and C passes an int where the enum goes, and the enum
//      where an int goes, without a word; so hasUri is 0 or 1, and every other value is REFUSED. A call
//      with the two swapped is then refused, or, for DIGIBYTE with a URI, is the same call: it never
//      answers another root's identity.
//    - THE URI is hashed as the bytes given, with no normalisation. The Android app passes the
//      callback URL DigiIdRequest keeps verbatim ("https://host/path", no query), and the bridge
//      reads it with GetStringUTFChars, so the bytes Android hashes are what ART writes for the
//      URL's UTF-16 code units (BRDigiIdUriBytesFromUtf16): UTF-8, with a surrogate pair as its
//      four-byte character, except U+0000 as C0 80 and a surrogate without its partner as its own
//      three bytes. (ART writes four-byte sequences although the JNI specification's modified UTF-8
//      would write a pair as two three-byte halves. It has done so since Android 8.0, API 26, the
//      app's minimum, and says it will not change: runtime/jni/jni_internal.cc, kUtfUse4ByteSequence.)
//      For a URI with no U+0000 and no lone surrogate these are its standard UTF-8 bytes, and a Swift
//      String never holds a lone surrogate; but a URI that may hold U+0000 must go through
//      BRDigiIdUriBytesFromUtf16, or its site gets another identity than on Android.
//    - THE SHARED IDENTITY is the key at m/0'/0/0 (BRBIP32PrivKey, chain 0, index 0): one address for
//      every site, the identity DigiScope logs in with. It takes no root: its m is always DIGIBYTE's
//      (BRDigiIdSharedKey, BRDigiIdSignShared). BRDigiIdAddress takes a root for its per-site branch and
//      refuses an unknown one on both branches; on the shared branch both roots give the one address.
//    - THE DIGISCOPE LIST is two hosts, "digiscope.me" and "api.digiscope.me", and no other
//      (BRDigiIdIsDigiScopeHost). A host is on it when its bytes are exactly one of the two. Nothing is
//      folded, trimmed or matched in part, so a name under either host, a trailing dot, a lookalike,
//      another letter case and a host with a NUL among its bytes are all off the list. The host compared
//      is the request's PARSED domain: the callback's host as the app's one parse reads it, which
//      lower-cases its letters.
//    - THE CHOICE of the identity a login signs with (BRDigiIdChooseIdentity) is made from the request's
//      host and callback URL and from two properties of the wallet that signs: its digiScopeIdentity
//      (BRDigiIdScopeIdentity) and its siteKeyRoot (THE ROOT).
//        A host on THE DIGISCOPE LIST, digiScopeIdentity SHARED: THE SHARED IDENTITY.
//        A host on THE DIGISCOPE LIST, digiScopeIdentity SITE: THE PER-SITE IDENTITY of
//          BR_DIGIID_DIGISCOPE_LOGIN_URI, DigiScope's one login callback, under the wallet's root, and
//          never of the request's own callback. Every DigiScope request then signs as one account: for
//          a phrase restored from Coinomi, the account Coinomi's login made.
//        Every other host: THE PER-SITE IDENTITY of the request's callback URL under the wallet's root,
//          whatever digiScopeIdentity is.
//      Both properties are checked on every call, also where the answer does not use them. 0 is no value
//      (BR_DIGIID_SCOPE_NONE, BR_DIGIID_ROOT_NONE): it and every unknown value are REFUSED, so a zeroed
//      or unset property chooses nothing. THE DIGISCOPE LIST and THE CHOICE have this ONE COPY, and
//      this is the contract: an app stores the two properties with the wallet, passes them in, and signs
//      with what the answer names; it keeps no list of its own and does not decide which key signs.
//      Neither app calls it yet. Until each does, it decides for itself from a list of its own that must
//      equal this one: Android's IdentityKeyPolicy.kt (DIGISCOPE_HOSTS), which digiid_core_kat's SOURCE
//      GATE holds to this list, and iOS's DigiIdIdentityPolicy.sharedIdentityHosts, which nothing here
//      can read.
//    - THE ANSWER'S URI for a host off the list is the caller's own pointer: nothing is copied, so it is
//      valid only while the caller's callback bytes are. C keeps them as long as it likes. Swift does
//      not: an array or String passed where a pointer goes is a pointer for that one call only, so a
//      Swift caller makes the choice AND signs inside one withUnsafeBufferPointer (or withCString) over
//      the callback's bytes, or takes only `kind` and `root` from the answer and gives the signing call
//      its own callback bytes again. Reading choice.uri after that scope is a dead pointer: a login
//      signed as some other identity, or a crash. On a DigiScope host the URI is this header's literal
//      and lives as long as the program.
//    - A MESSAGE is signed over SHA256(SHA256("\x19DigiByte Signed Message:\n" || prefix || message)),
//      where prefix is the message length written as the bridge writes it: one byte below 0xfd; 0xfd
//      and two little-endian bytes up to 0xffff; 0xfe and four up to 0xffffffff; 0xff and eight above
//      (a full compact size, as a verifier reads it: MSG-LEN).
//    - THE SIGNATURE is BRKeyCompactSign's 65 bytes (deterministic, RFC 6979) over that hash with the
//      key marked compressed, written as padded base64. THE ANSWER is "<address>|<base64 signature>",
//      NUL-terminated, where the address is the key's P2PKH address, or for addressFormat 2 (the shared
//      identity only) its P2WPKH address. The per-site identity always answers with P2PKH.
//    - THE MESSAGE BYTES are what the app sends: the standard UTF-8 of the message's UTF-16 code units
//      (BRDigiIdUtf8FromUtf16), a surrogate without its partner written '?' as Java's and okio's
//      encoders write it.
//    - REFUSED (BR_DIGIID_REFUSED, and no key, address or answer): no seed (the wallet is locked); no
//      message; no URI where one is needed; an account index below zero; an unknown root (THE ROOT) on
//      any call that takes one, and a hasUri that is neither 0 nor 1 (THE ROOT), even where `work` is
//      too small as well; the shared identity's address asked for any index but 0. Where a URI or a
//      message is hashed, a NULL pointer is "no value" and an empty one is a non-NULL pointer with length
//      0. The bridge signs an empty message, so a caller with one passes a non-NULL pointer: Swift does
//      not promise a non-nil baseAddress for an empty buffer (an UnsafeRawBufferPointer's may be nil), and
//      nil here is REFUSED. THE CHOICE refuses more, and its answer is then all zero (no identity): a
//      host that is NULL or empty; a digiScopeIdentity that is neither SHARED nor SITE; an unknown root;
//      and, for a host off THE DIGISCOPE LIST, a callback URL that is NULL or empty.
//    - THE CALLER'S OWN REFUSAL: the bridge also refuses all three calls while there is no wallet
//      (g_wallet NULL, read under WALLET_READ_GUARD). That check is not here; a caller makes it, and
//      passes no seed when it fails.
//    - THE NETWORK: an address, and so every answer, is the mainnet or testnet form as the
//      process-wide BRNetworkIsTestnet() says when it is called (BRKeyAddress, BRDigiByteBech32Hrp),
//      as in the bridge. The caller sets the network before it calls.
//    - CAPACITY (BR_DIGIID_CAPACITY): a caller buffer is too small. `work` holds the bytes that are
//      hashed (the header allocates nothing), `out` the answer with its NUL. The sizes are below.
//    - A KEY THAT GIVES NO ADDRESS (BR_DIGIID_NO_ADDRESS) or NO SIGNATURE (BR_DIGIID_NOT_SIGNED) is
//      refused as the bridge refuses it. Neither happens for a key BIP32 derived.
//
//  KEY MATERIAL: every BRKey these functions hold is wiped (BRKeyClean) before they return, on every
//  path; BRDigiIdSignWithKey and BRDigiIdAddressWithKey wipe the caller's key the same way, as the
//  bridge's sign_with_key did, and BRDigiIdAddress hands its key to BRDigiIdAddressWithKey.
//  Nothing here logs, and nothing reads a clock or a random source.
//
//  No allocation, no wallet, no network I/O (but see THE NETWORK above), no clock, no I/O. Header-only,
//  static inline; its includes are libc, BRKey.h (BRKey, addresses, BRKeyCompactSign, BRKeyClean),
//  BRBIP32Sequence.h (BRBIP32PrivKeyPath, BRBIP32PrivKeyArrayPath, BRBIP32PrivKey), BRCrypto.h (BRSHA256,
//  BRSHA256_2) and BRDerivationProfiles.h (BR_DERIVATION_HMAC_STANDARD; libc only, nothing to link), so a
//  program that calls it links BRKey.c, BRBIP32Sequence.c, BRCrypto.c and what they need. Nothing in the
//  core calls it yet.
//
//  Test seams (host KAT digiid_core_kat in the Android repo): DIGIID_UNFIXED, tested by VALUE as a set
//  of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0 is what ships.
//    1     DIGIID_RED_INDEX_BIG_ENDIAN    the account index is hashed big-endian.
//    2     DIGIID_RED_WORDS_BIG_ENDIAN    A, B, C, D are read from the hash big-endian.
//    4     DIGIID_RED_SOFT_PATH           A, B, C, D are not hardened.
//    8     DIGIID_RED_NEGATIVE_INDEX      a negative account index is taken as its uint32 bits.
//    16    DIGIID_RED_SHARED_ANY_INDEX    the shared identity's address is given for any index.
//    32    DIGIID_RED_LOW_BYTE_LENGTH     a message over 0xffff bytes is prefixed one byte, its length's low byte.
//    64    DIGIID_RED_SINGLE_SHA          the message is hashed once.
//    128   DIGIID_RED_UNCOMPRESSED        the key is not marked compressed before it signs.
//    256   DIGIID_RED_SEGWIT_IGNORED      address format 2 answers with the P2PKH address.
//    512   DIGIID_RED_KEY_KEPT            BRDigiIdSignWithKey leaves the caller's key unwiped on success.
//    1024  DIGIID_RED_LONE_SURROGATE_KEPT a surrogate without its partner is written as three bytes.
//    2048  DIGIID_RED_MODIFIED_UTF8       U+0000 is written C0 80 and a surrogate pair as two halves.
//    4096  DIGIID_RED_SHARED_PATH         the shared identity is m/0'/1/0.
//    8192  DIGIID_RED_BASE64_UNPADDED     the signature's base64 has no '=' padding.
//    16384 DIGIID_RED_URI_SPEC_PAIRS      BRDigiIdUriBytesFromUtf16 writes a surrogate pair as two
//                                         three-byte halves (the JNI specification's form, not ART's).
//    32768 DIGIID_RED_URI_AS_MESSAGE      BRDigiIdUriBytesFromUtf16 writes U+0000 as one 00 byte and a
//                                         lone surrogate as '?' (the message's rules).
//    65536 DIGIID_RED_ADDRESS_KEY_KEPT    BRDigiIdAddressWithKey leaves the caller's key unwiped.
//    131072 DIGIID_RED_ROOT_IGNORED       every known root derives with "DigiByte seed" (the per-site
//                                         master key before the root was an argument).
//    262144 DIGIID_RED_ROOT_ALWAYS_STANDARD
//                                         every known root derives with "Bitcoin seed" (the constant
//                                         swapped in place, which moves every existing identity).
//    524288 DIGIID_RED_ANY_ROOT           a root that is neither DIGIBYTE nor STANDARD is not refused: it
//                                         derives with "DigiByte seed" and answers BR_DIGIID_OK, and
//                                         BRDigiIdChooseIdentity chooses with it (every copy of the refusal).
//    1048576 DIGIID_RED_ANY_HASURI        BRDigiIdAddress takes any nonzero hasUri as 1, so a root swapped
//                                         with hasUri is not refused (STANDARD, 1 swapped answers DIGIBYTE's
//                                         per-site address).
//    2097152 DIGIID_RED_LIST_SUFFIX       a name ending in ".digiscope.me" counts as a DigiScope host (a
//                                         suffix match in place of the exact one).
//    4194304 DIGIID_RED_LIST_CASEFOLD     BRDigiIdIsDigiScopeHost compares without regard to letter case, so
//                                         a spelling no parse gives ("API.DigiScope.me") is on the list.
//    8388608 DIGIID_RED_SITE_SIGNS_SHARED a wallet whose digiScopeIdentity is SITE still gets the shared
//                                         identity on a DigiScope host (the rule before the property), and
//                                         signs in as another account without a word.
//    16777216 DIGIID_RED_SITE_USES_CALLBACK
//                                         SITE on a DigiScope host answers the request's own callback, not
//                                         BR_DIGIID_DIGISCOPE_LOGIN_URI.
//    33554432 DIGIID_RED_ANY_SCOPE        a digiScopeIdentity that is neither SHARED nor SITE is not refused:
//                                         BRDigiIdChooseIdentity chooses as it does for SITE.
//    67108864 DIGIID_RED_LIST_API_ONLY    only "api.digiscope.me", the login URL's host, is on the list;
//                                         "digiscope.me" is not.
//    134217728 DIGIID_RED_LIST_PREFIX     a name that begins with a listed host counts as one (the length
//                                         is not compared: a trailing dot, a port, "digiscope.me.other.example",
//                                         the host's NUL counted in).
//    268435456 DIGIID_RED_SHARED_NAMES_ROOT
//                                         the SHARED answer names the wallet's siteKeyRoot, not
//                                         BR_DIGIID_ROOT_NONE.
//    536870912 DIGIID_RED_CALLBACK_DECIDES
//                                         a request whose callback is BR_DIGIID_DIGISCOPE_LOGIN_URI gets
//                                         DigiScope's answer on any host (the callback read where the host
//                                         decides: another site that names that URL is given DigiScope's
//                                         identity).
//    1073741824 DIGIID_RED_REFUSAL_KEEPS_OUT
//                                         a refusal from BRDigiIdChooseIdentity leaves *out as the caller
//                                         had it, not all zero.
//    2147483648 DIGIID_RED_NO_CALLBACK_ANSWERS
//                                         a host off the list with no callback URL is not refused: the
//                                         answer is SITE with no URI.
//

#ifndef BRDigiId_h
#define BRDigiId_h

#include "BRBIP32Sequence.h"   // BRBIP32PrivKeyPath, BRBIP32PrivKeyArrayPath, BRBIP32PrivKey, BIP32_HARD
#include "BRCrypto.h"          // BRSHA256, BRSHA256_2
#include "BRDerivationProfiles.h"   // BR_DERIVATION_HMAC_STANDARD
#include "BRKey.h"             // BRKey, BRKeyAddress, BRKeySegwitAddress, BRKeyCompactSign, BRKeyClean
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIGIID_UNFIXED
#define DIGIID_UNFIXED 0
#endif

#define DIGIID_RED_INDEX_BIG_ENDIAN    1
#define DIGIID_RED_WORDS_BIG_ENDIAN    2
#define DIGIID_RED_SOFT_PATH           4
#define DIGIID_RED_NEGATIVE_INDEX      8
#define DIGIID_RED_SHARED_ANY_INDEX    16
#define DIGIID_RED_LOW_BYTE_LENGTH     32
#define DIGIID_RED_SINGLE_SHA          64
#define DIGIID_RED_UNCOMPRESSED        128
#define DIGIID_RED_SEGWIT_IGNORED      256
#define DIGIID_RED_KEY_KEPT            512
#define DIGIID_RED_LONE_SURROGATE_KEPT 1024
#define DIGIID_RED_MODIFIED_UTF8       2048
#define DIGIID_RED_SHARED_PATH         4096
#define DIGIID_RED_BASE64_UNPADDED     8192
#define DIGIID_RED_URI_SPEC_PAIRS      16384
#define DIGIID_RED_URI_AS_MESSAGE      32768
#define DIGIID_RED_ADDRESS_KEY_KEPT    65536
#define DIGIID_RED_ROOT_IGNORED        131072
#define DIGIID_RED_ROOT_ALWAYS_STANDARD 262144
#define DIGIID_RED_ANY_ROOT            524288
#define DIGIID_RED_ANY_HASURI          1048576
#define DIGIID_RED_LIST_SUFFIX         2097152
#define DIGIID_RED_LIST_CASEFOLD       4194304
#define DIGIID_RED_SITE_SIGNS_SHARED   8388608
#define DIGIID_RED_SITE_USES_CALLBACK  16777216
#define DIGIID_RED_ANY_SCOPE           33554432
#define DIGIID_RED_LIST_API_ONLY       67108864
#define DIGIID_RED_LIST_PREFIX         134217728
#define DIGIID_RED_SHARED_NAMES_ROOT   268435456
#define DIGIID_RED_CALLBACK_DECIDES    536870912
#define DIGIID_RED_REFUSAL_KEEPS_OUT   1073741824
#define DIGIID_RED_NO_CALLBACK_ANSWERS 2147483648

typedef enum {
    BR_DIGIID_OK = 0,
    BR_DIGIID_REFUSED = 1,      // no seed, message or URI; an index below zero; an unknown root; a hasUri but 0 or 1;
                                // the shared identity at index != 0; from BRDigiIdChooseIdentity, no host, an
                                // unknown digiScopeIdentity, or no callback URL for a host off the list
    BR_DIGIID_CAPACITY = 2,     // `work` or `out` is too small
    BR_DIGIID_NO_ADDRESS = 3,   // the key gives no address
    BR_DIGIID_NOT_SIGNED = 4    // BRKeyCompactSign gave no signature
} BRDigiIdStatus;

// The master key of a per-site identity (THE PER-SITE IDENTITY, THE ROOT). The zero value is the one that
// derives nothing.
typedef enum {
    BR_DIGIID_ROOT_NONE = 0,        // no root: REFUSED by every call that takes one
    BR_DIGIID_ROOT_DIGIBYTE = 1,    // "DigiByte seed" (BRBIP32PrivKeyPath's)
    BR_DIGIID_ROOT_STANDARD = 2     // "Bitcoin seed" (BR_DERIVATION_HMAC_STANDARD)
} BRDigiIdRoot;

// What a wallet signs DigiScope with: its digiScopeIdentity (THE CHOICE), a property each app stores with the
// wallet and passes to BRDigiIdChooseIdentity. The zero value is the one that chooses nothing.
typedef enum {
    BR_DIGIID_SCOPE_NONE = 0,       // no value: REFUSED
    BR_DIGIID_SCOPE_SHARED = 1,     // the shared identity, m/0'/0/0
    BR_DIGIID_SCOPE_SITE = 2        // the per-site identity of BR_DIGIID_DIGISCOPE_LOGIN_URI under the wallet's root
} BRDigiIdScopeIdentity;

// The identity BRDigiIdChooseIdentity chose. The zero value is no identity: what a refusal leaves.
typedef enum {
    BR_DIGIID_IDENTITY_NONE = 0,    // nothing was chosen
    BR_DIGIID_IDENTITY_SHARED = 1,  // the shared identity: BRDigiIdSignShared signs
    BR_DIGIID_IDENTITY_SITE = 2     // the per-site identity of uri under root: BRDigiIdSignSite signs
} BRDigiIdIdentityKind;

// BRDigiIdChooseIdentity's answer. uri[0, uriLen) and root mean something for BR_DIGIID_IDENTITY_SITE only:
// the URI the per-site identity is derived from, and its master-key root. For BR_DIGIID_IDENTITY_SHARED they
// are NULL, 0 and BR_DIGIID_ROOT_NONE, and after a refusal every byte is zero.
typedef struct {
    BRDigiIdIdentityKind kind;
    const char *uri;                // not owned: the header's literal, or the caller's callbackUri
    size_t uriLen;
    BRDigiIdRoot root;
} BRDigiIdChoice;

// DigiScope's one login and step-up callback URL: the URI a wallet whose digiScopeIdentity is SITE derives
// its DigiScope identity from, on every DigiScope host and for every request (THE CHOICE). ASCII, hashed as
// these bytes (THE URI). A plain literal, so that Swift imports it.
#define BR_DIGIID_DIGISCOPE_LOGIN_URI "https://api.digiscope.me/api/auth/digiid/callback"

// The longest answer with its NUL: a 74-character address (the bridge's 75-byte buffer), '|', and the
// 88 base64 characters of a 65-byte signature. Any `out` this long holds every answer.
#define BR_DIGIID_ANSWER_CAPACITY 164
// The longest address with its NUL.
#define BR_DIGIID_ADDRESS_CAPACITY 75
// "\x19DigiByte Signed Message:\n": its length, and the most bytes the length prefix takes.
#define BR_DIGIID_MESSAGE_HEADER_LENGTH 26
#define BR_DIGIID_MESSAGE_PREFIX_MAX 9

// ---- the per-site path ----------------------------------------------------------------------------

// The `work` bytes BRDigiIdSlip13Indexes needs for a URI of uriLen bytes: 4 + uriLen, or 0 when that
// does not fit a size_t.
static inline size_t BRDigiIdIndexesWorkSize(size_t uriLen)
{
    return (uriLen > SIZE_MAX - 4) ? 0 : 4 + uriLen;
}

// A, B, C, D of the per-site path for uri[0, uriLen) and account index `index` into out[0..3], WITHOUT
// the hardened bit (the bridge's slip13_indexes). On anything but BR_DIGIID_OK out[] is zeroed (when
// there is one). Refused: no out, no uri. CAPACITY: work[0, workCap) cannot hold
// BRDigiIdIndexesWorkSize(uriLen) bytes.
static inline BRDigiIdStatus BRDigiIdSlip13Indexes(uint32_t out[4], const char *uri, size_t uriLen, uint32_t index,
                                                   uint8_t *work, size_t workCap)
{
    uint8_t h[32];
    size_t need = BRDigiIdIndexesWorkSize(uriLen);
    int i;

    if (out) memset(out, 0, 4 * sizeof(uint32_t));
    if (! out || ! uri) return BR_DIGIID_REFUSED;
    if (need == 0 || ! work || workCap < need) return BR_DIGIID_CAPACITY;

#if (DIGIID_UNFIXED & DIGIID_RED_INDEX_BIG_ENDIAN)
    work[0] = (uint8_t)((index >> 24) & 0xff);
    work[1] = (uint8_t)((index >> 16) & 0xff);
    work[2] = (uint8_t)((index >> 8) & 0xff);
    work[3] = (uint8_t)(index & 0xff);
#else
    work[0] = (uint8_t)(index & 0xff);
    work[1] = (uint8_t)((index >> 8) & 0xff);
    work[2] = (uint8_t)((index >> 16) & 0xff);
    work[3] = (uint8_t)((index >> 24) & 0xff);
#endif
    if (uriLen > 0) memcpy(work + 4, uri, uriLen);
    BRSHA256(h, work, need);

    for (i = 0; i < 4; i++) {
#if (DIGIID_UNFIXED & DIGIID_RED_WORDS_BIG_ENDIAN)
        out[i] = ((uint32_t)h[4 * i] << 24) | ((uint32_t)h[4 * i + 1] << 16) | ((uint32_t)h[4 * i + 2] << 8) |
                 (uint32_t)h[4 * i + 3];
#else
        out[i] = (uint32_t)h[4 * i] | ((uint32_t)h[4 * i + 1] << 8) | ((uint32_t)h[4 * i + 2] << 16) |
                 ((uint32_t)h[4 * i + 3] << 24);
#endif
    }

    return BR_DIGIID_OK;
}

// ---- the two identities ---------------------------------------------------------------------------

// The per-site identity key of uri[0, uriLen) at account `index` under `root` into *key, from seed[0,
// seedLen) (the bridge's seed_derive_identity_key, for BR_DIGIID_ROOT_DIGIBYTE; the bridge's seed is
// BRBIP39DeriveKey's 64 bytes). On anything but BR_DIGIID_OK *key is wiped. Refused: no key, no seed, no
// uri, index < 0, a root that is neither BR_DIGIID_ROOT_DIGIBYTE nor BR_DIGIID_ROOT_STANDARD (before
// CAPACITY is looked at). CAPACITY as BRDigiIdSlip13Indexes.
static inline BRDigiIdStatus BRDigiIdSiteKey(BRKey *key, const void *seed, size_t seedLen, BRDigiIdRoot root,
                                             const char *uri, size_t uriLen, int32_t index, uint8_t *work,
                                             size_t workCap)
{
    uint32_t idx[4], hard = BIP32_HARD;
    BRDigiIdRoot master = root;   // the root the key is derived under
    BRDigiIdStatus status;

    if (key) BRKeyClean(key);
    if (! key || ! seed || ! uri) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (index < 0) return BR_DIGIID_REFUSED;
#endif
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_ROOT)
    if (root != BR_DIGIID_ROOT_DIGIBYTE && root != BR_DIGIID_ROOT_STANDARD) return BR_DIGIID_REFUSED;
#endif

    status = BRDigiIdSlip13Indexes(idx, uri, uriLen, (uint32_t)index, work, workCap);
    if (status != BR_DIGIID_OK) return status;
#if (DIGIID_UNFIXED & DIGIID_RED_SOFT_PATH)
    hard = 0;
#endif
#if (DIGIID_UNFIXED & DIGIID_RED_ROOT_IGNORED)
    master = BR_DIGIID_ROOT_DIGIBYTE;
#endif
#if (DIGIID_UNFIXED & DIGIID_RED_ROOT_ALWAYS_STANDARD)
    master = BR_DIGIID_ROOT_STANDARD;
#endif
    if (master == BR_DIGIID_ROOT_STANDARD) {
        const uint32_t path[5] = { 13 | BIP32_HARD, idx[0] | hard, idx[1] | hard, idx[2] | hard, idx[3] | hard };

        BRBIP32PrivKeyArrayPath(key, seed, seedLen, BR_DERIVATION_HMAC_STANDARD, path, 5);
        return BR_DIGIID_OK;
    }
    // BR_DIGIID_ROOT_DIGIBYTE, the only other root the refusal above lets through
    BRBIP32PrivKeyPath(key, seed, seedLen, 5, 13 | BIP32_HARD, idx[0] | hard, idx[1] | hard, idx[2] | hard,
                       idx[3] | hard);
    return BR_DIGIID_OK;
}

// The shared identity key, m/0'/0/0, into *key from seed[0, seedLen) (the bridge's seed_derive_key(key,
// 0, 0)); it takes no root (THE SHARED IDENTITY). On anything but BR_DIGIID_OK *key is wiped. Refused: no
// key, no seed.
static inline BRDigiIdStatus BRDigiIdSharedKey(BRKey *key, const void *seed, size_t seedLen)
{
    if (key) BRKeyClean(key);
    if (! key || ! seed) return BR_DIGIID_REFUSED;
#if (DIGIID_UNFIXED & DIGIID_RED_SHARED_PATH)
    BRBIP32PrivKey(key, seed, seedLen, 1, 0);
#else
    BRBIP32PrivKey(key, seed, seedLen, 0, 0);
#endif
    return BR_DIGIID_OK;
}

// ---- the message ----------------------------------------------------------------------------------

// The length prefix the bridge writes for a message of msgLen bytes into out[0, 9): its byte count (1, 3,
// 5 or 9; the bridge's signed_message.h).
static inline size_t BRDigiIdMessagePrefix(uint8_t out[BR_DIGIID_MESSAGE_PREFIX_MAX], size_t msgLen)
{
    uint64_t val = (uint64_t)msgLen;

    if (val < 0xfd) {
        out[0] = (uint8_t)val;
        return 1;
    }
    else if (val <= 0xffff) {
        out[0] = 0xfd;
        out[1] = (uint8_t)(val & 0xff);
        out[2] = (uint8_t)((val >> 8) & 0xff);
        return 3;
    }
#if (DIGIID_UNFIXED & DIGIID_RED_LOW_BYTE_LENGTH)
    out[0] = (uint8_t)val;
    return 1;
#else
    if (val <= 0xffffffffULL) {
        out[0] = 0xfe;
        for (int i = 0; i < 4; i++) out[1 + i] = (uint8_t)((val >> (8 * i)) & 0xff);
        return 5;
    }
    out[0] = 0xff;
    for (int i = 0; i < 8; i++) out[1 + i] = (uint8_t)((val >> (8 * i)) & 0xff);
    return 9;
#endif
}

// The `work` bytes BRDigiIdMessageDigest needs for a message of msgLen bytes: the header, the prefix and
// the message, or 0 when that does not fit a size_t.
static inline size_t BRDigiIdDigestWorkSize(size_t msgLen)
{
    uint8_t prefix[BR_DIGIID_MESSAGE_PREFIX_MAX];
    size_t fixed = BR_DIGIID_MESSAGE_HEADER_LENGTH + BRDigiIdMessagePrefix(prefix, msgLen);

    return (msgLen > SIZE_MAX - fixed) ? 0 : fixed + msgLen;
}

// The hash a message of msg[0, msgLen) is signed over into *md (see THE RULES). Refused: no md, no msg.
// CAPACITY: work[0, workCap) cannot hold BRDigiIdDigestWorkSize(msgLen) bytes. On anything but
// BR_DIGIID_OK *md is zero (when there is one).
static inline BRDigiIdStatus BRDigiIdMessageDigest(UInt256 *md, const uint8_t *msg, size_t msgLen, uint8_t *work,
                                                   size_t workCap)
{
    static const char header[] = "\x19" "DigiByte Signed Message:\n";
    uint8_t prefix[BR_DIGIID_MESSAGE_PREFIX_MAX];
    size_t prefixLen, need = BRDigiIdDigestWorkSize(msgLen);

    if (md) memset(md, 0, sizeof(*md));
    if (! md || ! msg) return BR_DIGIID_REFUSED;
    if (need == 0 || ! work || workCap < need) return BR_DIGIID_CAPACITY;

    prefixLen = BRDigiIdMessagePrefix(prefix, msgLen);
    memcpy(work, header, BR_DIGIID_MESSAGE_HEADER_LENGTH);
    memcpy(work + BR_DIGIID_MESSAGE_HEADER_LENGTH, prefix, prefixLen);
    if (msgLen > 0) memcpy(work + BR_DIGIID_MESSAGE_HEADER_LENGTH + prefixLen, msg, msgLen);
#if (DIGIID_UNFIXED & DIGIID_RED_SINGLE_SHA)
    BRSHA256(md, work, need);
#else
    BRSHA256_2(md, work, need);
#endif
    return BR_DIGIID_OK;
}

// The standard UTF-8 of units[0, count), UTF-16 code units, into out[0, outCap) (the bridge's
// message_utf8): a surrogate pair as its four-byte character, a surrogate without its partner as '?'.
// *outLen is the UTF-8's byte count on BR_DIGIID_OK and on CAPACITY (so a caller can size `out`; nothing
// is written then); at most 3 * count. Refused: no outLen, no units. No NUL is written.
static inline BRDigiIdStatus BRDigiIdUtf8FromUtf16(uint8_t *out, size_t outCap, size_t *outLen, const uint16_t *units,
                                                   size_t count)
{
    size_t i, len = 0, pass;

    if (outLen) *outLen = 0;
    if (! outLen || ! units) return BR_DIGIID_REFUSED;

    for (pass = 0; pass < 2; pass++) {   // pass 0 counts, pass 1 writes
        if (pass == 1 && (! out || outCap < len)) return BR_DIGIID_CAPACITY;
        len = 0;

        for (i = 0; i < count; i++) {
            uint32_t c = units[i];
            uint8_t b[4];
            size_t n, k;

#if (DIGIID_UNFIXED & DIGIID_RED_MODIFIED_UTF8)
            if (c != 0 && c < 0x80) {
#else
            if (c < 0x80) {
#endif
                b[0] = (uint8_t)c;
                n = 1;
            }
            else if (c < 0x800) {
                b[0] = (uint8_t)(0xC0 | (c >> 6));
                b[1] = (uint8_t)(0x80 | (c & 0x3F));
                n = 2;
            }
#if ! (DIGIID_UNFIXED & DIGIID_RED_MODIFIED_UTF8)
            else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < count && units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF) {
                uint32_t cp = 0x10000 + ((c - 0xD800) << 10) + ((uint32_t)units[i + 1] - 0xDC00);

                i++;
                b[0] = (uint8_t)(0xF0 | (cp >> 18));
                b[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
                b[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                b[3] = (uint8_t)(0x80 | (cp & 0x3F));
                n = 4;
            }
#endif
#if ! (DIGIID_UNFIXED & (DIGIID_RED_LONE_SURROGATE_KEPT | DIGIID_RED_MODIFIED_UTF8))
            else if (c >= 0xD800 && c <= 0xDFFF) {
                b[0] = '?';
                n = 1;
            }
#endif
            else {
                b[0] = (uint8_t)(0xE0 | (c >> 12));
                b[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
                b[2] = (uint8_t)(0x80 | (c & 0x3F));
                n = 3;
            }

            if (pass == 1) for (k = 0; k < n; k++) out[len + k] = b[k];
            len += n;
        }
        *outLen = len;
    }

    return BR_DIGIID_OK;
}

// The bytes Android hashes for a URI of UTF-16 code units units[0, count) (THE URI, above: what ART's
// GetStringUTFChars writes) into out[0, outCap): a unit 1..0x7F as one byte; U+0000 and 0x80..0x7FF as
// two; a high surrogate followed by a low one as the pair's four-byte character; every other unit, a
// lone surrogate included, as three. *outLen is the byte count on BR_DIGIID_OK and on CAPACITY (so a
// caller can size `out`; nothing is written then); at most 3 * count. Refused: no outLen, no units. No
// NUL is written, and none can occur in the bytes.
static inline BRDigiIdStatus BRDigiIdUriBytesFromUtf16(uint8_t *out, size_t outCap, size_t *outLen, const uint16_t *units,
                                                       size_t count)
{
    size_t i, len = 0, pass;

    if (outLen) *outLen = 0;
    if (! outLen || ! units) return BR_DIGIID_REFUSED;

    for (pass = 0; pass < 2; pass++) {   // pass 0 counts, pass 1 writes
        if (pass == 1 && (! out || outCap < len)) return BR_DIGIID_CAPACITY;
        len = 0;

        for (i = 0; i < count; i++) {
            uint32_t c = units[i];
            uint8_t b[4];
            size_t n, k;

#if (DIGIID_UNFIXED & DIGIID_RED_URI_AS_MESSAGE)
            if (c < 0x80) {
#else
            if (c != 0 && c < 0x80) {
#endif
                b[0] = (uint8_t)c;
                n = 1;
            }
            else if (c < 0x800) {
                b[0] = (uint8_t)(0xC0 | (c >> 6));
                b[1] = (uint8_t)(0x80 | (c & 0x3F));
                n = 2;
            }
#if ! (DIGIID_UNFIXED & DIGIID_RED_URI_SPEC_PAIRS)
            else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < count && units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF) {
                uint32_t cp = 0x10000 + ((c - 0xD800) << 10) + ((uint32_t)units[i + 1] - 0xDC00);

                i++;
                b[0] = (uint8_t)(0xF0 | (cp >> 18));
                b[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
                b[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                b[3] = (uint8_t)(0x80 | (cp & 0x3F));
                n = 4;
            }
#endif
#if (DIGIID_UNFIXED & DIGIID_RED_URI_AS_MESSAGE)
            else if (c >= 0xD800 && c <= 0xDFFF) {
                b[0] = '?';
                n = 1;
            }
#endif
            else {
                b[0] = (uint8_t)(0xE0 | (c >> 12));
                b[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
                b[2] = (uint8_t)(0x80 | (c & 0x3F));
                n = 3;
            }

            if (pass == 1) for (k = 0; k < n; k++) out[len + k] = b[k];
            len += n;
        }
        *outLen = len;
    }

    return BR_DIGIID_OK;
}

// ---- signing --------------------------------------------------------------------------------------

// Padded base64 of in[0, inLen) into out with a NUL; the characters written. `out` holds
// 4 * ((inLen + 2) / 3) + 1 bytes (the bridge's base64_encode).
static inline size_t _BRDigiIdBase64(char *out, const uint8_t *in, size_t inLen)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, pos = 0;

    for (i = 0; i < inLen; i += 3) {
        uint32_t n = ((uint32_t)in[i]) << 16;

        if (i + 1 < inLen) n |= ((uint32_t)in[i + 1]) << 8;
        if (i + 2 < inLen) n |= (uint32_t)in[i + 2];
        out[pos++] = table[(n >> 18) & 0x3F];
        out[pos++] = table[(n >> 12) & 0x3F];
#if (DIGIID_UNFIXED & DIGIID_RED_BASE64_UNPADDED)
        if (i + 1 < inLen) out[pos++] = table[(n >> 6) & 0x3F];
        if (i + 2 < inLen) out[pos++] = table[n & 0x3F];
#else
        out[pos++] = (i + 1 < inLen) ? table[(n >> 6) & 0x3F] : '=';
        out[pos++] = (i + 2 < inLen) ? table[n & 0x3F] : '=';
#endif
    }
    out[pos] = '\0';
    return pos;
}

// The P2PKH address of *key, an already-derived key marked compressed (the address identityAddress
// gives), NUL-terminated into out[0, outCap). *key is WIPED before this returns, on every path. On
// anything but BR_DIGIID_OK out[0] is NUL (when outCap > 0). Refused: no key, no out. NO_ADDRESS: the
// key gives none. CAPACITY: out cannot hold the address (BR_DIGIID_ADDRESS_CAPACITY always suffices).
static inline BRDigiIdStatus BRDigiIdAddressWithKey(char *out, size_t outCap, BRKey *key)
{
    char addr[BR_DIGIID_ADDRESS_CAPACITY];
    size_t addrLen;

    if (out && outCap > 0) out[0] = '\0';
    if (! key) return BR_DIGIID_REFUSED;
    if (! out) {
        BRKeyClean(key);
        return BR_DIGIID_REFUSED;
    }

#if ! (DIGIID_UNFIXED & DIGIID_RED_UNCOMPRESSED)
    key->compressed = 1;
#endif
    memset(addr, 0, sizeof(addr));
    BRKeyAddress(key, addr, sizeof(addr));
#if ! (DIGIID_UNFIXED & DIGIID_RED_ADDRESS_KEY_KEPT)
    BRKeyClean(key);
#endif
    if (addr[0] == '\0') return BR_DIGIID_NO_ADDRESS;

    addrLen = strlen(addr);
    if (outCap < addrLen + 1) return BR_DIGIID_CAPACITY;
    memcpy(out, addr, addrLen + 1);
    return BR_DIGIID_OK;
}

// Signs msg[0, msgLen) with *key, an already-derived key, and writes the answer "<address>|<base64
// signature>" with its NUL into out[0, outCap) (the bridge's sign_with_key): the address is P2WPKH for
// addressFormat 2 and P2PKH for any other value. *key is marked compressed, and WIPED before this
// returns, on every path. On anything but BR_DIGIID_OK out[0] is NUL (when outCap > 0). Refused: no key,
// no out, no msg. CAPACITY: work cannot hold BRDigiIdDigestWorkSize(msgLen) bytes, or out the answer
// (BR_DIGIID_ANSWER_CAPACITY always suffices).
static inline BRDigiIdStatus BRDigiIdSignWithKey(char *out, size_t outCap, BRKey *key, const uint8_t *msg, size_t msgLen,
                                                 int32_t addressFormat, uint8_t *work, size_t workCap)
{
    char addr[BR_DIGIID_ADDRESS_CAPACITY], sigB64[92];
    uint8_t compactSig[65];
    UInt256 md;
    size_t addrLen, sigLen, b64Len;
    BRDigiIdStatus status;

    if (out && outCap > 0) out[0] = '\0';
    if (! key) return BR_DIGIID_REFUSED;
    if (! out || ! msg) {
        BRKeyClean(key);
        return BR_DIGIID_REFUSED;
    }

#if ! (DIGIID_UNFIXED & DIGIID_RED_UNCOMPRESSED)
    key->compressed = 1;
#endif
    memset(addr, 0, sizeof(addr));
#if ! (DIGIID_UNFIXED & DIGIID_RED_SEGWIT_IGNORED)
    if (addressFormat == 2) BRKeySegwitAddress(key, addr, sizeof(addr), 0);
    else
#endif
    BRKeyAddress(key, addr, sizeof(addr));
    (void)addressFormat;

    if (addr[0] == '\0') {
        BRKeyClean(key);
        return BR_DIGIID_NO_ADDRESS;
    }

    status = BRDigiIdMessageDigest(&md, msg, msgLen, work, workCap);
    if (status != BR_DIGIID_OK) {
        BRKeyClean(key);
        return status;
    }

    sigLen = BRKeyCompactSign(key, compactSig, sizeof(compactSig), md);
#if (DIGIID_UNFIXED & DIGIID_RED_KEY_KEPT)
    if (sigLen == 0) BRKeyClean(key);
#else
    BRKeyClean(key);
#endif
    if (sigLen == 0) return BR_DIGIID_NOT_SIGNED;

    b64Len = _BRDigiIdBase64(sigB64, compactSig, sigLen);
    addrLen = strlen(addr);
    if (outCap < addrLen + 1 + b64Len + 1) return BR_DIGIID_CAPACITY;
    memcpy(out, addr, addrLen);
    out[addrLen] = '|';
    memcpy(out + addrLen + 1, sigB64, b64Len + 1);
    return BR_DIGIID_OK;
}

// The `work` bytes BRDigiIdSignSite needs: the larger of BRDigiIdIndexesWorkSize(uriLen) and
// BRDigiIdDigestWorkSize(msgLen), or 0 when either does not fit a size_t.
static inline size_t BRDigiIdSignSiteWorkSize(size_t uriLen, size_t msgLen)
{
    size_t a = BRDigiIdIndexesWorkSize(uriLen), b = BRDigiIdDigestWorkSize(msgLen);

    return (a == 0 || b == 0) ? 0 : (a > b ? a : b);
}

// A login signed with the SHARED identity (the bridge's signMessage; no root): the answer for msg[0,
// msgLen) into out, P2WPKH for addressFormat 2 and P2PKH otherwise. Refused: no seed (a locked wallet), no
// msg, no out. CAPACITY as BRDigiIdSignWithKey.
static inline BRDigiIdStatus BRDigiIdSignShared(char *out, size_t outCap, const void *seed, size_t seedLen,
                                                const uint8_t *msg, size_t msgLen, int32_t addressFormat, uint8_t *work,
                                                size_t workCap)
{
    BRKey key;

    if (out && outCap > 0) out[0] = '\0';
    if (! out || ! seed || ! msg) return BR_DIGIID_REFUSED;
    if (BRDigiIdSharedKey(&key, seed, seedLen) != BR_DIGIID_OK) {
        BRKeyClean(&key);
        return BR_DIGIID_REFUSED;
    }
    return BRDigiIdSignWithKey(out, outCap, &key, msg, msgLen, addressFormat, work, workCap);   // wipes key
}

// A login signed with the PER-SITE identity of uri[0, uriLen) at account `index` under `root` (the
// bridge's signIdentityMessage, for BR_DIGIID_ROOT_DIGIBYTE): the answer for msg[0, msgLen) into out,
// always P2PKH. Refused: no seed, no msg, no uri, no out, index < 0, a root that is neither
// BR_DIGIID_ROOT_DIGIBYTE nor BR_DIGIID_ROOT_STANDARD. CAPACITY: work cannot hold
// BRDigiIdSignSiteWorkSize(uriLen, msgLen) bytes, or out the answer.
static inline BRDigiIdStatus BRDigiIdSignSite(char *out, size_t outCap, const void *seed, size_t seedLen,
                                              BRDigiIdRoot root, const uint8_t *msg, size_t msgLen, const char *uri,
                                              size_t uriLen, int32_t index, uint8_t *work, size_t workCap)
{
    BRKey key;
    BRDigiIdStatus status;

    if (out && outCap > 0) out[0] = '\0';
    if (! out || ! seed || ! msg || ! uri) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (index < 0) return BR_DIGIID_REFUSED;
#endif
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_ROOT)
    if (root != BR_DIGIID_ROOT_DIGIBYTE && root != BR_DIGIID_ROOT_STANDARD) return BR_DIGIID_REFUSED;
#endif

    status = BRDigiIdSiteKey(&key, seed, seedLen, root, uri, uriLen, index, work, workCap);
    if (status != BR_DIGIID_OK) {
        BRKeyClean(&key);
        return status;
    }
    return BRDigiIdSignWithKey(out, outCap, &key, msg, msgLen, 0, work, workCap);   // wipes key
}

// The P2PKH address a login would sign with, without signing (the bridge's identityAddress, for
// BR_DIGIID_ROOT_DIGIBYTE): the per-site identity of uri[0, uriLen) at account `index` under `root` when
// hasUri is 1, the shared identity when it is 0 (index must then be 0, and both roots give the one shared
// address). NUL-terminated into out[0, outCap). Refused: no seed, no out, index < 0, a root that is
// neither BR_DIGIID_ROOT_DIGIBYTE nor BR_DIGIID_ROOT_STANDARD (with or without hasUri), a hasUri that is
// neither 0 nor 1 (so a root swapped with it is refused: THE ROOT), hasUri with no uri, no hasUri with
// index != 0. CAPACITY: work cannot hold BRDigiIdIndexesWorkSize(uriLen) bytes (when hasUri), or out the
// address (BR_DIGIID_ADDRESS_CAPACITY always suffices).
static inline BRDigiIdStatus BRDigiIdAddress(char *out, size_t outCap, const void *seed, size_t seedLen,
                                             BRDigiIdRoot root, int hasUri, const char *uri, size_t uriLen,
                                             int32_t index, uint8_t *work, size_t workCap)
{
    BRKey key;
    BRDigiIdStatus status;

    if (out && outCap > 0) out[0] = '\0';
#if (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (! out || ! seed) return BR_DIGIID_REFUSED;
#else
    if (! out || ! seed || index < 0) return BR_DIGIID_REFUSED;
#endif
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_ROOT)
    if (root != BR_DIGIID_ROOT_DIGIBYTE && root != BR_DIGIID_ROOT_STANDARD) return BR_DIGIID_REFUSED;
#endif
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_HASURI)
    if (hasUri != 0 && hasUri != 1) return BR_DIGIID_REFUSED;   // a root swapped into hasUri's place is refused here (THE ROOT)
#endif

    if (hasUri) status = BRDigiIdSiteKey(&key, seed, seedLen, root, uri, uriLen, index, work, workCap);
#if (DIGIID_UNFIXED & DIGIID_RED_SHARED_ANY_INDEX)
    else status = BRDigiIdSharedKey(&key, seed, seedLen);
#else
    else status = (index == 0) ? BRDigiIdSharedKey(&key, seed, seedLen) : BR_DIGIID_REFUSED;
#endif
    if (status != BR_DIGIID_OK) {
        BRKeyClean(&key);
        return status;
    }
    return BRDigiIdAddressWithKey(out, outCap, &key);   // wipes key
}

// ---- which identity signs -------------------------------------------------------------------------

// 1 when host[0, hostLen) is on THE DIGISCOPE LIST: its hostLen bytes are exactly "digiscope.me" or exactly
// "api.digiscope.me". 0 for everything else: no host (NULL), an empty one, a name under either host, a
// trailing dot, a lookalike, another letter case, and any host with a NUL among its bytes (all hostLen bytes
// are compared, and no listed host has one). The caller passes the request's PARSED domain, which the parse
// lower-cased: nothing is folded here. This is the list's one copy. A caller that wants the identity to sign
// with asks BRDigiIdChooseIdentity, which reads it.
static inline int BRDigiIdIsDigiScopeHost(const char *host, size_t hostLen)
{
    static const char *const list[] = { "digiscope.me", "api.digiscope.me" };
    size_t i, n;

    if (! host || hostLen == 0) return 0;

#if (DIGIID_UNFIXED & DIGIID_RED_LIST_API_ONLY)
    for (i = 1; i < sizeof(list) / sizeof(list[0]); i++) {
#else
    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
#endif
        n = strlen(list[i]);
#if (DIGIID_UNFIXED & DIGIID_RED_LIST_PREFIX)
        if (hostLen > n && memcmp(host, list[i], n) == 0) return 1;
#endif
#if (DIGIID_UNFIXED & DIGIID_RED_LIST_SUFFIX)
        if (hostLen > n && host[hostLen - n - 1] == '.' && memcmp(host + (hostLen - n), list[i], n) == 0) return 1;
#endif
        if (hostLen != n) continue;
#if (DIGIID_UNFIXED & DIGIID_RED_LIST_CASEFOLD)
        {
            size_t k;

            for (k = 0; k < n; k++) {
                char c = host[k];

                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                if (c != list[i][k]) break;
            }
            if (k == n) return 1;
        }
#else
        if (memcmp(host, list[i], n) == 0) return 1;
#endif
    }

    return 0;
}

// THE CHOICE: the identity a login to `host` signs with, into *out, for a wallet whose digiScopeIdentity is
// `scope` and whose per-site master-key root is `siteKeyRoot`. host[0, hostLen) is the request's PARSED
// domain, as BRDigiIdIsDigiScopeHost takes it, and callbackUri[0, callbackLen) the same request's callback
// URL, the bytes THE URI names; the two are not compared with each other here. The answers:
//   a DigiScope host, scope SHARED   { BR_DIGIID_IDENTITY_SHARED, NULL, 0, BR_DIGIID_ROOT_NONE }
//   a DigiScope host, scope SITE     { BR_DIGIID_IDENTITY_SITE, BR_DIGIID_DIGISCOPE_LOGIN_URI, its length,
//                                      siteKeyRoot }: never the request's own callback
//   any other host                   { BR_DIGIID_IDENTITY_SITE, callbackUri, callbackLen, siteKeyRoot },
//                                      whatever scope is: the caller's own pointer, valid while its bytes are
//                                      and no longer (THE ANSWER'S URI: a Swift caller chooses and signs
//                                      inside one withUnsafeBufferPointer over the callback, or signs with
//                                      its own callback bytes and takes only kind and root from here)
// A DigiScope host needs no callback: a caller that signs for DigiScope without a request, as the Hub's own
// login does, passes NULL. The caller then signs with BRDigiIdSignShared for SHARED, and for SITE with
// BRDigiIdSignSite under out->root over out->uri (BRDigiIdAddress with hasUri 1 gives that address). The
// SHARED answer names no root, as the shared identity takes none: BRDigiIdAddress refuses
// BR_DIGIID_ROOT_NONE on both its branches, so for the shared address it is given the wallet's own root,
// with hasUri 0.
// Refused, with *out all zero (kind BR_DIGIID_IDENTITY_NONE) when there is one: no out; a host that is NULL
// or empty; a scope that is neither BR_DIGIID_SCOPE_SHARED nor BR_DIGIID_SCOPE_SITE; a root that is neither
// BR_DIGIID_ROOT_DIGIBYTE nor BR_DIGIID_ROOT_STANDARD; a host off the list with a callback that is NULL or
// empty. scope and siteKeyRoot are checked on every call, also where the answer does not use them. Nothing
// is derived, hashed, copied or allocated here, and no key is held.
static inline BRDigiIdStatus BRDigiIdChooseIdentity(BRDigiIdChoice *out, const char *host, size_t hostLen,
                                                    const char *callbackUri, size_t callbackLen,
                                                    BRDigiIdScopeIdentity scope, BRDigiIdRoot siteKeyRoot)
{
    if (! out) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_REFUSAL_KEEPS_OUT)
    memset(out, 0, sizeof(*out));   // no identity: kind NONE, uriLen 0, root NONE, and the padding between them
    out->uri = NULL;
#endif
    if (! host || hostLen == 0) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_SCOPE)
    if (scope != BR_DIGIID_SCOPE_SHARED && scope != BR_DIGIID_SCOPE_SITE) return BR_DIGIID_REFUSED;
#endif
#if ! (DIGIID_UNFIXED & DIGIID_RED_ANY_ROOT)
    if (siteKeyRoot != BR_DIGIID_ROOT_DIGIBYTE && siteKeyRoot != BR_DIGIID_ROOT_STANDARD) return BR_DIGIID_REFUSED;
#endif

    // Every answer below writes all four fields, so none of them rests on the zeroing above.
#if (DIGIID_UNFIXED & DIGIID_RED_CALLBACK_DECIDES)
    if (BRDigiIdIsDigiScopeHost(host, hostLen) ||
        (callbackUri && callbackLen == sizeof(BR_DIGIID_DIGISCOPE_LOGIN_URI) - 1 &&
         memcmp(callbackUri, BR_DIGIID_DIGISCOPE_LOGIN_URI, callbackLen) == 0)) {
#else
    if (BRDigiIdIsDigiScopeHost(host, hostLen)) {
#endif
#if (DIGIID_UNFIXED & DIGIID_RED_SITE_SIGNS_SHARED)
        if (1) {
#else
        if (scope == BR_DIGIID_SCOPE_SHARED) {
#endif
            out->kind = BR_DIGIID_IDENTITY_SHARED;   // no URI and no root: the shared identity takes none
            out->uri = NULL;
            out->uriLen = 0;
#if (DIGIID_UNFIXED & DIGIID_RED_SHARED_NAMES_ROOT)
            out->root = siteKeyRoot;
#else
            out->root = BR_DIGIID_ROOT_NONE;
#endif
            return BR_DIGIID_OK;
        }
#if ! (DIGIID_UNFIXED & DIGIID_RED_SITE_USES_CALLBACK)
        out->kind = BR_DIGIID_IDENTITY_SITE;
        out->uri = BR_DIGIID_DIGISCOPE_LOGIN_URI;
        out->uriLen = sizeof(BR_DIGIID_DIGISCOPE_LOGIN_URI) - 1;
        out->root = siteKeyRoot;
        return BR_DIGIID_OK;
#endif
    }

#if (DIGIID_UNFIXED & DIGIID_RED_NO_CALLBACK_ANSWERS)
    if (! callbackUri || callbackLen == 0) { callbackUri = NULL; callbackLen = 0; }
#else
    if (! callbackUri || callbackLen == 0) return BR_DIGIID_REFUSED;
#endif
    out->kind = BR_DIGIID_IDENTITY_SITE;
    out->uri = callbackUri;
    out->uriLen = callbackLen;
    out->root = siteKeyRoot;
    return BR_DIGIID_OK;
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiId_h
