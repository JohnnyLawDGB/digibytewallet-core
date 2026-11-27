//
//  BRWatchDescriptor.c
//
//  See BRWatchDescriptor.h for what is accepted and why.
//

#include "BRWatchDescriptor.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRCrypto.h"
#include "BRKey.h"
#include "BRNetwork.h"
#include <string.h>
#include <ctype.h>

#define XPUB_VERSION_MAINNET 0x0488b21eu   // xpub
#define XPRV_VERSION_MAINNET 0x0488ade4u   // xprv
#define XPUB_VERSION_TESTNET 0x043587cfu   // tpub
#define XPRV_VERSION_TESTNET 0x04358394u   // tprv
#define XKEY_LEN             78
#define XKEY_STR_MAX         120

// ------------------------------------------------------------------ BIP380 checksum

static const char DESC_INPUT[] =
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
static const char DESC_CHECK[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint64_t _descPolymod(uint64_t c, int val)
{
    static const uint64_t gen[5] = { 0xf5dee51989ULL, 0xa9fdca3312ULL, 0x1bab10e32dULL,
                                     0x3706b1677aULL, 0x644d626ffdULL };
    uint8_t c0 = (uint8_t)(c >> 35);

    c = ((c & 0x7ffffffffULL) << 5) ^ (uint64_t)val;
    for (int i = 0; i < 5; i++) if ((c0 >> i) & 1) c ^= gen[i];
    return c;
}

// writes the 8-character checksum of desc[0..len) to out (9 bytes); returns 0 on an invalid character
static int _descChecksum(const char *desc, size_t len, char out[9])
{
    uint64_t c = 1;
    int cls = 0, clsCount = 0;

    for (size_t i = 0; i < len; i++) {
        const char *p = (desc[i] != '\0') ? strchr(DESC_INPUT, desc[i]) : NULL;

        if (! p) return 0;
        int pos = (int)(p - DESC_INPUT);
        c = _descPolymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clsCount == 3) {
            c = _descPolymod(c, cls);
            cls = 0;
            clsCount = 0;
        }
    }
    if (clsCount > 0) c = _descPolymod(c, cls);
    for (int i = 0; i < 8; i++) c = _descPolymod(c, 0);
    c ^= 1;
    for (int i = 0; i < 8; i++) out[i] = DESC_CHECK[(c >> (5 * (7 - i))) & 31];
    out[8] = '\0';
    return 1;
}

// ------------------------------------------------------------------ small parsers

static int _hexNibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// reads one path element "<digits>" followed by a hardened marker (h, H or '); returns chars consumed or 0
static size_t _readHardened(const char *s, size_t len, uint32_t *value)
{
    size_t i = 0;
    uint64_t v = 0;

    while (i < len && s[i] >= '0' && s[i] <= '9') {
        v = v * 10 + (uint64_t)(s[i] - '0');
        if (v >= BIP32_HARD) return 0;
        i++;
    }
    if (i == 0 || i > 10 || i >= len) return 0;
    if (i > 1 && s[0] == '0') return 0;                       // no leading zeros
    if (s[i] != 'h' && s[i] != 'H' && s[i] != '\'') return 0;
    *value = (uint32_t)v;
    return i + 1;
}

// ------------------------------------------------------------------ parse

BRWatchResult BRWatchDescriptorParse(BRWatchDescriptor *out, const char *descriptor)
{
    if (! out) return BR_WATCH_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (! descriptor) return BR_WATCH_ERR_NULL;

    size_t total = strlen(descriptor);
    if (total > BR_WATCH_DESCRIPTOR_MAX_LEN) return BR_WATCH_ERR_TOO_LONG;

    // checksum: "#" plus 8 characters at the very end
    const char *hash = strrchr(descriptor, '#');
    if (! hash || (size_t)(descriptor + total - hash) != 9) return BR_WATCH_ERR_NO_CHECKSUM;

    size_t len = (size_t)(hash - descriptor);
    char expect[9];
    if (! _descChecksum(descriptor, len, expect) || memcmp(expect, hash + 1, 8) != 0) return BR_WATCH_ERR_BAD_CHECKSUM;

    // wrapper
    const char *s = descriptor;
    size_t open, close;
    uint32_t wantPurpose;
    int format;

    if (len > 9 && strncmp(s, "sh(wpkh(", 8) == 0 && strncmp(s + len - 2, "))", 2) == 0) {
        open = 8; close = 2; wantPurpose = 49; format = BR_DERIVATION_FORMAT_P2SH_P2WPKH;
    } else if (len > 6 && strncmp(s, "wpkh(", 5) == 0 && s[len - 1] == ')') {
        open = 5; close = 1; wantPurpose = 84; format = BR_DERIVATION_FORMAT_P2WPKH;
    } else if (len > 4 && strncmp(s, "tr(", 3) == 0 && s[len - 1] == ')') {
        open = 3; close = 1; wantPurpose = 86; format = BR_DERIVATION_FORMAT_P2TR;
    } else if (len > 5 && strncmp(s, "pkh(", 4) == 0 && s[len - 1] == ')') {
        open = 4; close = 1; wantPurpose = 44; format = BR_DERIVATION_FORMAT_P2PKH;
    } else return BR_WATCH_ERR_SCRIPT;

    const char *k = s + open;                  // the key expression
    size_t klen = len - open - close;

    // one key only: no commas or nested parentheses (multisig, script trees)
    for (size_t i = 0; i < klen; i++) {
        if (k[i] == ',' || k[i] == '(' || k[i] == ')') return BR_WATCH_ERR_SCRIPT;
    }

    // origin: [ffffffff/purpose'/coin'/account']
    if (klen == 0 || k[0] != '[') return BR_WATCH_ERR_NO_ORIGIN;
    const char *end = memchr(k, ']', klen);
    if (! end) return BR_WATCH_ERR_ORIGIN;

    size_t olen = (size_t)(end - k) - 1;       // inside the brackets
    const char *o = k + 1;
    if (olen < 9 || o[8] != '/') return BR_WATCH_ERR_ORIGIN;
    for (int i = 0; i < 4; i++) {
        int hi = _hexNibble(o[2 * i]), lo = _hexNibble(o[2 * i + 1]);
        if (hi < 0 || lo < 0) return BR_WATCH_ERR_ORIGIN;
        out->masterFingerprint[i] = (uint8_t)((hi << 4) | lo);
    }

    uint32_t levels[3];
    size_t pos = 9;
    for (int i = 0; i < 3; i++) {
        size_t n = _readHardened(o + pos, olen - pos, &levels[i]);
        if (n == 0) return BR_WATCH_ERR_ORIGIN;
        pos += n;
        if (i < 2) {
            if (pos >= olen || o[pos] != '/') return BR_WATCH_ERR_ORIGIN;
            pos++;
        }
    }
    if (pos != olen) return BR_WATCH_ERR_ORIGIN;  // more than three levels

    out->purpose = levels[0];
    out->coinType = levels[1];
    out->account = levels[2];
    if (out->purpose != wantPurpose) return BR_WATCH_ERR_PURPOSE;

    uint32_t wantCoin = BRNetworkIsTestnet() ? BR_WATCH_COIN_TYPE_TESTNET : BR_WATCH_COIN_TYPE_MAINNET;
#ifndef WATCH_DESCRIPTOR_RED_CHAIN
    if (out->coinType != wantCoin) {
        uint32_t found = out->coinType;
        memset(out, 0, sizeof(*out));
        out->coinType = found;
        return BR_WATCH_ERR_WRONG_CHAIN;
    }
#else
    (void)wantCoin;   // RED ARM SEAM (watch_descriptor_kat): trusts the prefix, never the coin type
#endif

    // extended key, then the derivation suffix
    const char *x = end + 1;
    size_t rest = klen - (size_t)(x - k);
    const char *slash = memchr(x, '/', rest);
    if (! slash) return BR_WATCH_ERR_PATH;

    size_t xlen = (size_t)(slash - x);
    if (xlen == 0 || xlen >= XKEY_STR_MAX) return BR_WATCH_ERR_XPUB;

    char xstr[XKEY_STR_MAX];
    memcpy(xstr, x, xlen);
    xstr[xlen] = '\0';

    uint8_t raw[XKEY_LEN + 1];
    size_t rawLen = BRBase58CheckDecode(raw, sizeof(raw), xstr);
    memset(xstr, 0, sizeof(xstr));
    if (rawLen != XKEY_LEN) return BR_WATCH_ERR_XPUB;

    uint32_t version = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    if (version == XPRV_VERSION_MAINNET || version == XPRV_VERSION_TESTNET || raw[45] == 0x00) {
        memset(raw, 0, sizeof(raw));
        memset(out, 0, sizeof(*out));
        return BR_WATCH_ERR_PRIVATE_KEY;
    }

    uint32_t wantVersion = BRNetworkIsTestnet() ? XPUB_VERSION_TESTNET : XPUB_VERSION_MAINNET;
    if (version != wantVersion || (raw[45] != 0x02 && raw[45] != 0x03)) return BR_WATCH_ERR_XPUB;

    BRKey check;
    if (! BRKeySetPubKey(&check, &raw[45], 33)) return BR_WATCH_ERR_XPUB;   // not a point on the curve
    BRKeyClean(&check);

    uint32_t child = ((uint32_t)raw[9] << 24) | ((uint32_t)raw[10] << 16) | ((uint32_t)raw[11] << 8) | raw[12];
    if (raw[4] != 3 || child != (out->account | BIP32_HARD)) return BR_WATCH_ERR_XPUB_ORIGIN;

    // suffix: exactly /0/* or /1/*
    size_t slen = rest - xlen;
    if (slen != 4 || slash[2] != '/' || slash[3] != '*' || (slash[1] != '0' && slash[1] != '1')) return BR_WATCH_ERR_PATH;

    out->branch = (uint32_t)(slash[1] - '0');
    out->format = format;
    // HoldFast's own account keys (BRBIP32MasterPubKeyBIP84/BIP86) carry the SEED's fingerprint, not the
    // parent's that the xpub serializes, so take it from the origin: the cold account's key is then the hot
    // wallet's key byte for byte. Memory order, as BRKeyHash160(&key).u32[0] stores it.
    memcpy(&out->mpk.fingerPrint, out->masterFingerprint, sizeof(out->mpk.fingerPrint));
    memcpy(&out->mpk.chainCode, &raw[13], sizeof(out->mpk.chainCode));
    memcpy(out->mpk.pubKey, &raw[45], sizeof(out->mpk.pubKey));
    return BR_WATCH_OK;
}

const char *BRWatchResultName(BRWatchResult result)
{
    switch (result) {
        case BR_WATCH_OK:               return "ok";
        case BR_WATCH_ERR_NULL:         return "null";
        case BR_WATCH_ERR_TOO_LONG:     return "too_long";
        case BR_WATCH_ERR_NO_CHECKSUM:  return "no_checksum";
        case BR_WATCH_ERR_BAD_CHECKSUM: return "bad_checksum";
        case BR_WATCH_ERR_SCRIPT:       return "script";
        case BR_WATCH_ERR_NO_ORIGIN:    return "no_origin";
        case BR_WATCH_ERR_ORIGIN:       return "origin";
        case BR_WATCH_ERR_PURPOSE:      return "purpose";
        case BR_WATCH_ERR_WRONG_CHAIN:  return "wrong_chain";
        case BR_WATCH_ERR_PRIVATE_KEY:  return "private_key";
        case BR_WATCH_ERR_XPUB:         return "xpub";
        case BR_WATCH_ERR_XPUB_ORIGIN:  return "xpub_origin";
        case BR_WATCH_ERR_PATH:         return "path";
    }
    return "unknown";
}

void BRWatchDescriptorFingerprintHex(const BRWatchDescriptor *d, char out[9])
{
    static const char hex[] = "0123456789abcdef";

    if (! out) return;
    if (! d) { out[0] = '\0'; return; }
    for (int i = 0; i < 4; i++) {
        out[2 * i] = hex[d->masterFingerprint[i] >> 4];
        out[2 * i + 1] = hex[d->masterFingerprint[i] & 0x0f];
    }
    out[8] = '\0';
}

// ------------------------------------------------------------------ derivation

size_t BRWatchDescriptorAddress(const BRWatchDescriptor *d, uint32_t chain, uint32_t index,
                                char *addr, size_t addrLen)
{
    uint8_t pub[33];
    BRKey key;
    size_t n = 0;

    if (! d || ! addr || addrLen == 0 || chain > 1 || (index & BIP32_HARD)) return 0;
    if (BRBIP32PubKey(pub, sizeof(pub), d->mpk, chain, index) != sizeof(pub)) return 0;
    if (! BRKeySetPubKey(&key, pub, sizeof(pub))) return 0;

    char tmp[100];
    switch (d->format) {
        case BR_DERIVATION_FORMAT_P2PKH:
            n = BRKeyAddress(&key, tmp, sizeof(tmp));
            break;
        case BR_DERIVATION_FORMAT_P2WPKH:
            n = BRKeySegwitAddress(&key, tmp, sizeof(tmp), 0);
            break;
        case BR_DERIVATION_FORMAT_P2TR:
            n = BRKeyTaprootAddress(&key, tmp, sizeof(tmp));
            break;
        case BR_DERIVATION_FORMAT_P2SH_P2WPKH: {
            uint8_t redeem[22] = { 0x00, 0x14 }, spk[23] = { 0xa9, 0x14 };
            BRHash160(&redeem[2], pub, sizeof(pub));
            BRHash160(&spk[2], redeem, sizeof(redeem));
            spk[22] = 0x87;
            n = BRAddressFromScriptPubKey(tmp, sizeof(tmp), spk, sizeof(spk));
            break;
        }
        default:
            n = 0;
    }
    BRKeyClean(&key);

    // BRKey* writers count the NUL; be strict about it either way
    if (n == 0 || n > sizeof(tmp)) return 0;
    size_t slen = strnlen(tmp, sizeof(tmp));
    if (slen == 0 || slen == sizeof(tmp) || slen + 1 > addrLen) return 0;
    memcpy(addr, tmp, slen + 1);
    return slen + 1;
}

static int _isBech32(const char *a)
{
    const char *hrp = BRNetworkIsTestnet() ? "dgbt1" : "dgb1";
    size_t n = strlen(hrp);

    for (size_t i = 0; i < n; i++) {
        if (a[i] == '\0' || tolower((unsigned char)a[i]) != hrp[i]) return 0;
    }
    return 1;
}

static int _sameAddress(const char *a, const char *b, int bech32)
{
    if (! bech32) return strcmp(a, b) == 0;
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

int BRWatchDescriptorFindAddress(const BRWatchDescriptor *d, const char *addr, uint32_t limit,
                                 uint32_t *chain, uint32_t *index)
{
    char buf[100];

    if (! d || ! addr || addr[0] == '\0' || strlen(addr) >= sizeof(buf)) return 0;
    if (limit > BR_WATCH_FIND_LIMIT_MAX) limit = BR_WATCH_FIND_LIMIT_MAX;

    int bech32 = _isBech32(addr);
    for (uint32_t c = 0; c <= 1; c++) {
        for (uint32_t i = 0; i < limit; i++) {
            if (BRWatchDescriptorAddress(d, c, i, buf, sizeof(buf)) == 0) return 0;
            if (_sameAddress(addr, buf, bech32)) {
                if (chain) *chain = c;
                if (index) *index = i;
                return 1;
            }
        }
    }
    return 0;
}
