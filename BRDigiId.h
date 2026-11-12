//
//  BRDigiId.h
//
//  Digi-ID: the per-site identity key (SLIP-0013) and the signing of a login message. Until 2026-11
//  this lived only in the Android bridge (native/src/main/jni/bridge/slip13.c, seed_derive_identity_key
//  in jni_wallet.c, and jni_wallet_sign.c: sign_with_key, base64_encode, write_varint, message_utf8 and
//  the entry points signMessage, signIdentityMessage and identityAddress). It moves here unchanged: for
//  the same seed, URI bytes, index and message bytes, every key, address and signature here is
//  byte-identical to the bridge's, and every input the bridge refuses is refused here.
//
//  THE RULES:
//    - THE PER-SITE IDENTITY of a site's URI and an account index i is the key at m/13'/A'/B'/C'/D',
//      every step hardened, where h = SHA256(LE32(i) || uri) and A, B, C, D are h's first 16 bytes read
//      as four little-endian uint32 (SLIP-0013, the derivation of BitID's BIP draft).
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
//      every site, the identity DigiScope logs in with.
//    - A MESSAGE is signed over SHA256(SHA256("\x19DigiByte Signed Message:\n" || prefix || message)),
//      where prefix is the message length written as the bridge writes it: one byte below 0xfd; 0xfd
//      and two little-endian bytes up to 0xffff; above 0xffff one byte, the length's low byte.
//    - THE SIGNATURE is BRKeyCompactSign's 65 bytes (deterministic, RFC 6979) over that hash with the
//      key marked compressed, written as padded base64. THE ANSWER is "<address>|<base64 signature>",
//      NUL-terminated, where the address is the key's P2PKH address, or for addressFormat 2 (the shared
//      identity only) its P2WPKH address. The per-site identity always answers with P2PKH.
//    - THE MESSAGE BYTES are what the app sends: the standard UTF-8 of the message's UTF-16 code units
//      (BRDigiIdUtf8FromUtf16), a surrogate without its partner written '?' as Java's and okio's
//      encoders write it.
//    - REFUSED (BR_DIGIID_REFUSED, and no key, address or answer): no seed (the wallet is locked); no
//      message; no URI where one is needed; an account index below zero; the shared identity's address
//      asked for any index but 0. A NULL pointer is "no value": an empty URI or message is a non-NULL
//      pointer with length 0. The bridge signs an empty message, so a caller with one passes a
//      non-NULL pointer: Swift does not promise a non-nil baseAddress for an empty buffer (an
//      UnsafeRawBufferPointer's may be nil), and nil here is REFUSED.
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
//  BRBIP32Sequence.h (BRBIP32PrivKeyPath, BRBIP32PrivKey) and BRCrypto.h (BRSHA256, BRSHA256_2), so a
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
//    32    DIGIID_RED_COMPACT_SIZE        a message over 0xffff bytes is prefixed 0xfe and four length bytes.
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
//

#ifndef BRDigiId_h
#define BRDigiId_h

#include "BRBIP32Sequence.h"   // BRBIP32PrivKeyPath, BRBIP32PrivKey, BIP32_HARD
#include "BRCrypto.h"          // BRSHA256, BRSHA256_2
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
#define DIGIID_RED_COMPACT_SIZE        32
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

typedef enum {
    BR_DIGIID_OK = 0,
    BR_DIGIID_REFUSED = 1,      // no seed, message or URI; an index below zero; the shared identity at index != 0
    BR_DIGIID_CAPACITY = 2,     // `work` or `out` is too small
    BR_DIGIID_NO_ADDRESS = 3,   // the key gives no address
    BR_DIGIID_NOT_SIGNED = 4    // BRKeyCompactSign gave no signature
} BRDigiIdStatus;

// The longest answer with its NUL: a 74-character address (the bridge's 75-byte buffer), '|', and the
// 88 base64 characters of a 65-byte signature. Any `out` this long holds every answer.
#define BR_DIGIID_ANSWER_CAPACITY 164
// The longest address with its NUL.
#define BR_DIGIID_ADDRESS_CAPACITY 75
// "\x19DigiByte Signed Message:\n": its length, and the most bytes the length prefix takes.
#define BR_DIGIID_MESSAGE_HEADER_LENGTH 26
#define BR_DIGIID_MESSAGE_PREFIX_MAX 5

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

// The per-site identity key of uri[0, uriLen) at account `index` into *key, from seed[0, seedLen) (the
// bridge's seed_derive_identity_key; the bridge's seed is BRBIP39DeriveKey's 64 bytes). On anything but
// BR_DIGIID_OK *key is wiped. Refused: no key, no seed, no uri, index < 0. CAPACITY as
// BRDigiIdSlip13Indexes.
static inline BRDigiIdStatus BRDigiIdSiteKey(BRKey *key, const void *seed, size_t seedLen, const char *uri, size_t uriLen,
                                             int32_t index, uint8_t *work, size_t workCap)
{
    uint32_t idx[4], hard = BIP32_HARD;
    BRDigiIdStatus status;

    if (key) BRKeyClean(key);
    if (! key || ! seed || ! uri) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (index < 0) return BR_DIGIID_REFUSED;
#endif

    status = BRDigiIdSlip13Indexes(idx, uri, uriLen, (uint32_t)index, work, workCap);
    if (status != BR_DIGIID_OK) return status;
#if (DIGIID_UNFIXED & DIGIID_RED_SOFT_PATH)
    hard = 0;
#endif
    BRBIP32PrivKeyPath(key, seed, seedLen, 5, 13 | BIP32_HARD, idx[0] | hard, idx[1] | hard, idx[2] | hard,
                       idx[3] | hard);
    return BR_DIGIID_OK;
}

// The shared identity key, m/0'/0/0, into *key from seed[0, seedLen) (the bridge's seed_derive_key(key,
// 0, 0)). On anything but BR_DIGIID_OK *key is wiped. Refused: no key, no seed.
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

// The length prefix the bridge writes for a message of msgLen bytes into out[0, 5): its byte count (1 or
// 3; see THE RULES for a message over 0xffff bytes).
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
#if (DIGIID_UNFIXED & DIGIID_RED_COMPACT_SIZE)
    out[0] = 0xfe;
    out[1] = (uint8_t)(val & 0xff);
    out[2] = (uint8_t)((val >> 8) & 0xff);
    out[3] = (uint8_t)((val >> 16) & 0xff);
    out[4] = (uint8_t)((val >> 24) & 0xff);
    return 5;
#else
    out[0] = (uint8_t)val;
    return 1;
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

// A login signed with the SHARED identity (the bridge's signMessage): the answer for msg[0, msgLen) into
// out, P2WPKH for addressFormat 2 and P2PKH otherwise. Refused: no seed (a locked wallet), no msg, no
// out. CAPACITY as BRDigiIdSignWithKey.
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

// A login signed with the PER-SITE identity of uri[0, uriLen) at account `index` (the bridge's
// signIdentityMessage): the answer for msg[0, msgLen) into out, always P2PKH. Refused: no seed, no msg,
// no uri, no out, index < 0. CAPACITY: work cannot hold BRDigiIdSignSiteWorkSize(uriLen, msgLen) bytes,
// or out the answer.
static inline BRDigiIdStatus BRDigiIdSignSite(char *out, size_t outCap, const void *seed, size_t seedLen,
                                              const uint8_t *msg, size_t msgLen, const char *uri, size_t uriLen,
                                              int32_t index, uint8_t *work, size_t workCap)
{
    BRKey key;
    BRDigiIdStatus status;

    if (out && outCap > 0) out[0] = '\0';
    if (! out || ! seed || ! msg || ! uri) return BR_DIGIID_REFUSED;
#if ! (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (index < 0) return BR_DIGIID_REFUSED;
#endif

    status = BRDigiIdSiteKey(&key, seed, seedLen, uri, uriLen, index, work, workCap);
    if (status != BR_DIGIID_OK) {
        BRKeyClean(&key);
        return status;
    }
    return BRDigiIdSignWithKey(out, outCap, &key, msg, msgLen, 0, work, workCap);   // wipes key
}

// The P2PKH address a login would sign with, without signing (the bridge's identityAddress): the
// per-site identity of uri[0, uriLen) at account `index` when hasUri, the shared identity otherwise
// (index must then be 0). NUL-terminated into out[0, outCap). Refused: no seed, no out, index < 0,
// hasUri with no uri, no hasUri with index != 0. CAPACITY: work cannot hold
// BRDigiIdIndexesWorkSize(uriLen) bytes (when hasUri), or out the address (BR_DIGIID_ADDRESS_CAPACITY
// always suffices).
static inline BRDigiIdStatus BRDigiIdAddress(char *out, size_t outCap, const void *seed, size_t seedLen, int hasUri,
                                             const char *uri, size_t uriLen, int32_t index, uint8_t *work,
                                             size_t workCap)
{
    BRKey key;
    BRDigiIdStatus status;

    if (out && outCap > 0) out[0] = '\0';
#if (DIGIID_UNFIXED & DIGIID_RED_NEGATIVE_INDEX)
    if (! out || ! seed) return BR_DIGIID_REFUSED;
#else
    if (! out || ! seed || index < 0) return BR_DIGIID_REFUSED;
#endif

    if (hasUri) status = BRDigiIdSiteKey(&key, seed, seedLen, uri, uriLen, index, work, workCap);
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

#ifdef __cplusplus
}
#endif

#endif // BRDigiId_h
