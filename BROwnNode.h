//
//  BROwnNode.h
//
//  The user's own node: which host and port a typed address or a scanned `dgbnode://` link names,
//  whether a host is an IPv4 address, whether a host name may be looked up, and what the core's
//  peer status says about the node. These decide which peer the wallet dials (and whether a name
//  lookup leaves Tor), so both platforms take them from here. Until 2026-10 this lived in Kotlin
//  (CustomNode.parse, OwnNodeUri.parse, OwnNodeAddress, SyncService.refreshOwnNodeHealth).
//
//  BROwnNodeParseHostPort (CustomNode.parse, the typed field): "host" or "host:port". Trimmed as
//  Kotlin's trim() trims (ASCII 9-13 and 28-31, and Unicode Zs, Zl, Zp). The port is after the
//  LAST ':', trimmed, Kotlin's toIntOrNull (an optional sign, then decimal digits; overflow is no
//  number) and 1..65535; without one, the default. The host is trimmed again and must be
//  non-empty with no "//" (a URL) and no ':' (IPv6). Any other bytes are accepted, as Kotlin
//  accepts them.
//  BROwnNodeUriParse (OwnNodeUri.parse, a scanned or pasted reference): `dgbnode://host[:port]
//  [?net=&label=]`, or a raw host[:port]. The host:port must be letters, digits, '.', '-' and
//  ':' only, and a `.onion` host is refused (not yet supported). Query values are decoded as
//  java.net.URLDecoder decodes them; where URLDecoder would throw, the raw value is used, as
//  Kotlin's catch does. net is the last "mainnet" or "testnet" given; the label is the last
//  label= value, decoded but NOT filtered: the platform filters it for display (letters, digits,
//  whitespace, "-_.", trimmed, at most 32 UTF-16 units), since a label decides nothing.
//  BROwnNodeIPv4Literal (OwnNodeAddress.ipv4Literal): four dot-separated groups of one to three
//  ASCII digits, each at most 255, canonicalised ("010.1.2.3" is 10.1.2.3).
//  BROwnNodeResolvePlan (OwnNodeAddress.resolve): an IPv4 address is used as given; with Tor on,
//  a host name is refused, never looked up (the device's resolver would send the query beside Tor,
//  naming the user's node to whoever watches the network); otherwise the platform looks it up
//  and dials the first IPv4 address.
//  BROwnNodeHealthFor (refreshOwnNodeHealth): BRPeerManagerCompactFilterPeerStatus 3 (connected
//  and answering cfheaders) is serving, 1 (in the pool, not yet connected) is connecting, and
//  anything else is dark: 2 (connected but serving no filters, a node without
//  peerblockfilters=1) is exactly the misconfiguration this status exists to show.
//
//  BROwnNodeWatchdogMayPin: while an own node is pinned, the sync watchdogs leave the pin slot
//  alone (see the function).
//
//  Where this refuses what Kotlin accepts (iOS shows the address as invalid; Android saves it and
//  then cannot use it): a port written in non-ASCII digits, a host longer than the caller's
//  buffer, and letters outside ASCII in a dgbnode:// host (Android's lookup cannot resolve them
//  either). A percent escape written in non-ASCII hex digits reads as malformed (the raw value).
//
//  Host KAT: digibytewallet-android native/src/test/host/own_node_kat/ (CustomNodeTest,
//  OwnNodeUriTest and OwnNodeAddressTest, case for case, plus the edges above).
//  Header-only, static inline.
//

#ifndef BROwnNode_h
#define BROwnNode_h

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_OWN_NODE_MAINNET_PORT  12024
#define BR_OWN_NODE_TESTNET_PORT  12033
#define BR_OWN_NODE_HOST_MAX      256     // a host buffer this size holds any DNS name (253) and its NUL
#define BR_OWN_NODE_IPV4_MAX      16      // "255.255.255.255" and its NUL
#define BR_OWN_NODE_LABEL_UNITS   32      // the platform's display cap, in UTF-16 units

typedef enum {
    BROwnNodeNetUnspecified = 0,
    BROwnNodeNetMainnet,
    BROwnNodeNetTestnet
} BROwnNodeNet;

typedef enum {
    BROwnNodeUseAddress = 0,        // ipv4 holds the address to dial
    BROwnNodeRefusedUnderTor,       // a host name while Tor is on: not looked up, not pinned
    BROwnNodeNeedsLookup            // a host name, Tor off: the platform resolves it (first IPv4)
} BROwnNodeResolve;

typedef enum {
    BROwnNodeHealthUnpaired = 0,    // no own node configured (the platform's own state)
    BROwnNodeHealthConnecting,
    BROwnNodeHealthServing,
    BROwnNodeHealthDark
} BROwnNodeHealth;

// The byte length of a Kotlin whitespace character at s[0..len) (from the front, or ending at
// the back when fromEnd), else 0. UTF-8: ASCII 9-13 and 28-31 and space; U+0085 is not one (Java's
// isWhitespace excludes it); U+00A0, U+1680, U+2000-200A, U+2028, U+2029, U+202F, U+205F, U+3000.
static inline size_t _BROwnNodeWs(const unsigned char *s, size_t len, int fromEnd)
{
    if (len == 0) return 0;
    if (! fromEnd) {
        unsigned char c = s[0];
        if (c == ' ' || (c >= 9 && c <= 13) || (c >= 28 && c <= 31)) return 1;
        if (len >= 2 && c == 0xC2 && s[1] == 0xA0) return 2;
        if (len >= 3 && c == 0xE1 && s[1] == 0x9A && s[2] == 0x80) return 3;
        if (len >= 3 && c == 0xE2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8A) || s[2] == 0xA8 ||
                                                      s[2] == 0xA9 || s[2] == 0xAF)) return 3;
        if (len >= 3 && c == 0xE2 && s[1] == 0x81 && s[2] == 0x9F) return 3;
        if (len >= 3 && c == 0xE3 && s[1] == 0x80 && s[2] == 0x80) return 3;
        return 0;
    }
    if (len >= 3) {
        size_t n = _BROwnNodeWs(s + len - 3, 3, 0);
        if (n == 3) return 3;
    }
    if (len >= 2 && s[len - 2] == 0xC2 && s[len - 1] == 0xA0) return 2;
    return _BROwnNodeWs(s + len - 1, 1, 0) == 1 ? 1 : 0;
}

// Kotlin's trim(): narrows [*start, *end) past whitespace at both ends.
static inline void _BROwnNodeTrim(const char *s, size_t *start, size_t *end)
{
    size_t n;

    while (*start < *end && (n = _BROwnNodeWs((const unsigned char *)s + *start, *end - *start, 0)) > 0) *start += n;
    while (*end > *start && (n = _BROwnNodeWs((const unsigned char *)s + *start, *end - *start, 1)) > 0) *end -= n;
}

// Kotlin's String.toIntOrNull over s[0..len): optional '+' or '-', then one or more ASCII digits,
// no overflow of a 32-bit Int. Returns 1 and writes *out, else 0.
static inline int _BROwnNodeToInt(const char *s, size_t len, int64_t *out)
{
    size_t i = 0;
    int neg = 0;
    int64_t v = 0;

    if (len == 0) return 0;
    if (s[0] == '+' || s[0] == '-') { neg = (s[0] == '-'); i = 1; if (len == 1) return 0; }
    for (; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (s[i] - '0');
        if (v > 2147483648LL) return 0;
    }
    if (! neg && v > 2147483647LL) return 0;
    *out = neg ? -v : v;
    return 1;
}

static inline int BROwnNodeParseHostPort(const char *raw, uint16_t defaultPort, char *host, size_t hostCap,
                                         uint16_t *port)
{
    size_t start = 0, end, hs, he, idx = 0, i;
    int64_t p = defaultPort;
    int found = 0;

    if (! raw || ! host || hostCap == 0 || ! port) return 0;
    end = strlen(raw);
    _BROwnNodeTrim(raw, &start, &end);
    if (start == end) return 0;
    for (i = end; i > start; i--) if (raw[i - 1] == ':') { idx = i - 1; found = 1; break; }
    hs = start; he = found ? idx : end;
    if (found) {
        size_t ps = idx + 1, pe = end;
        _BROwnNodeTrim(raw, &ps, &pe);
        if (! _BROwnNodeToInt(raw + ps, pe - ps, &p) || p < 1 || p > 65535) return 0;
        _BROwnNodeTrim(raw, &hs, &he);
    }
    if (hs == he) return 0;
    for (i = hs; i < he; i++) {
        if (raw[i] == ':') return 0;                                           // IPv6
        if (raw[i] == '/' && i + 1 < he && raw[i + 1] == '/') return 0;        // a URL
    }
    if (he - hs >= hostCap) return 0;
    memcpy(host, raw + hs, he - hs);
    host[he - hs] = '\0';
    *port = (uint16_t)p;
    return 1;
}

static inline int _BROwnNodeHex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// java.net.URLDecoder.decode(s, "UTF-8") over s[0..len) into out (capacity >= len): '+' is a
// space; each run of %XX is bytes, where XX is Integer.parseInt(XX, 16) (so "+F" is 15 and "-0"
// is 0, a negative value throws); a '%' that cannot start a full escape throws. Returns the
// decoded length, or -1 where URLDecoder throws (the caller then uses the raw value).
static inline long _BROwnNodeUrlDecode(const char *s, size_t len, char *out)
{
    size_t i = 0, n = 0;

    while (i < len) {
        char c = s[i];

        if (c == '+') { out[n++] = ' '; i++; continue; }
        if (c != '%') { out[n++] = c; i++; continue; }
        while (i + 2 < len && c == '%') {
            const unsigned char a = (unsigned char)s[i + 1], b = (unsigned char)s[i + 2];
            int v;

            if (a == '+' || a == '-') {
                if (_BROwnNodeHex(b) < 0) return -1;
                v = (a == '-') ? -_BROwnNodeHex(b) : _BROwnNodeHex(b);
            }
            else if (_BROwnNodeHex(a) < 0 || _BROwnNodeHex(b) < 0) return -1;
            else v = _BROwnNodeHex(a) << 4 | _BROwnNodeHex(b);
            if (v < 0) return -1;
            out[n++] = (char)v;
            i += 3;
            if (i < len) c = s[i];
        }
        if (i < len && c == '%') return -1;   // an incomplete trailing escape
    }
    return (long)n;
}

static inline int _BROwnNodeSane(const char *s, size_t len)
{
    size_t i;

    if (len == 0) return 0;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (! ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '-' || c == ':')) return 0;
    }
    return 1;
}

// label/labelCap: the last label= value, decoded, NOT NUL-terminated by meaning (it may hold a NUL
// byte); *labelLen is its length, or -1 when no label= was given. A labelCap of strlen(raw) is
// always enough. Returns 1 when raw names a node.
static inline int BROwnNodeUriParse(const char *raw, uint16_t defaultPort, char *host, size_t hostCap,
                                    uint16_t *port, BROwnNodeNet *net, char *label, size_t labelCap, long *labelLen)
{
    static const char scheme[] = "dgbnode://";
    size_t start = 0, end, body, q, hs, he, i;
    char hp[BR_OWN_NODE_HOST_MAX + 8];

    if (! raw || ! net || ! labelLen) return 0;
    *net = BROwnNodeNetUnspecified;
    *labelLen = -1;
    end = strlen(raw);
    _BROwnNodeTrim(raw, &start, &end);
    if (start == end) return 0;
    if (end - start < sizeof(scheme) - 1 || memcmp(raw + start, scheme, sizeof(scheme) - 1) != 0) {
        if (! _BROwnNodeSane(raw + start, end - start) || end - start >= sizeof(hp)) return 0;
        memcpy(hp, raw + start, end - start);
        hp[end - start] = '\0';
        return BROwnNodeParseHostPort(hp, defaultPort, host, hostCap, port);
    }
    body = start + sizeof(scheme) - 1;
    for (q = body; q < end && raw[q] != '?'; q++);
    hs = body; he = q;
    _BROwnNodeTrim(raw, &hs, &he);
    if (! _BROwnNodeSane(raw + hs, he - hs) || he - hs >= sizeof(hp)) return 0;
    {   // ".onion", case-insensitively, before the last ':' (or the whole host:port without one)
        size_t hend = he;
        for (i = he; i > hs; i--) if (raw[i - 1] == ':') { hend = i - 1; break; }
        if (hend - hs >= 6) {
            const char *t = raw + hend - 6, *onion = ".onion";
            size_t k;
            int same = 1;
            for (k = 0; k < 6; k++) {
                char c = t[k];
                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                if (c != onion[k]) { same = 0; break; }
            }
            if (same) return 0;
        }
    }
    memcpy(hp, raw + hs, he - hs);
    hp[he - hs] = '\0';
    if (! BROwnNodeParseHostPort(hp, defaultPort, host, hostCap, port)) return 0;
    if (q < end) {
        size_t p = q + 1;
        while (p <= end) {
            size_t e = p, eq;
            while (e < end && raw[e] != '&') e++;
            for (eq = p; eq < e && raw[eq] != '='; eq++);
            if (eq < e) {
                const char *v = raw + eq + 1;
                size_t vlen = e - eq - 1;
                if (eq - p == 3 && memcmp(raw + p, "net", 3) == 0) {
                    // Each decoded byte takes 1 or 3 characters, so only a value under 22 characters
                    // can decode to a 7-letter word, and a longer raw value is not one either.
                    char dec[32];
                    long dl = vlen < sizeof(dec) ? _BROwnNodeUrlDecode(v, vlen, dec) : -1;
                    const char *val = dl >= 0 ? dec : v;
                    size_t len = dl >= 0 ? (size_t)dl : vlen;
                    if (len == 7 && memcmp(val, "mainnet", 7) == 0) *net = BROwnNodeNetMainnet;
                    else if (len == 7 && memcmp(val, "testnet", 7) == 0) *net = BROwnNodeNetTestnet;
                }
                else if (eq - p == 5 && memcmp(raw + p, "label", 5) == 0 && label && labelCap >= vlen) {
                    long dl = _BROwnNodeUrlDecode(v, vlen, label);
                    if (dl < 0) { memcpy(label, v, vlen); dl = (long)vlen; }
                    *labelLen = dl;
                }
            }
            if (e >= end) break;
            p = e + 1;
        }
    }
    return 1;
}

static inline int BROwnNodeIPv4Literal(const char *host, char *out, size_t outCap)
{
    size_t start = 0, end, i;
    int octet[4], parts = 0, digits = 0, v = 0;

    if (! host || ! out || outCap < BR_OWN_NODE_IPV4_MAX) return 0;
    end = strlen(host);
    _BROwnNodeTrim(host, &start, &end);
    for (i = start; i <= end; i++) {
        if (i == end || host[i] == '.') {
            if (digits == 0 || v > 255 || parts == 4) return 0;
            octet[parts++] = v;
            digits = 0; v = 0;
        }
        else if (host[i] >= '0' && host[i] <= '9' && digits < 3) { v = v * 10 + (host[i] - '0'); digits++; }
        else return 0;
    }
    if (parts != 4) return 0;
    {   // "255.255.255.255" at most: snprintf is avoided to stay libc-light and exact
        char *o = out;
        for (i = 0; i < 4; i++) {
            int x = octet[i];
            if (i) *o++ = '.';
            if (x >= 100) *o++ = (char)('0' + x / 100);
            if (x >= 10) *o++ = (char)('0' + (x / 10) % 10);
            *o++ = (char)('0' + x % 10);
        }
        *o = '\0';
    }
    return 1;
}

static inline BROwnNodeResolve BROwnNodeResolvePlan(const char *host, int torEnabled, char *ipv4, size_t ipv4Cap)
{
    if (BROwnNodeIPv4Literal(host, ipv4, ipv4Cap)) return BROwnNodeUseAddress;
#ifdef OWN_NODE_RED
    // RED ARM SEAM (own_node_kat): the Tor setting ignored, so a host name is looked up beside Tor.
    (void)torEnabled;
#else
    if (torEnabled) return BROwnNodeRefusedUnderTor;
#endif
    return BROwnNodeNeedsLookup;
}

static inline BROwnNodeHealth BROwnNodeHealthFor(int compactFilterPeerStatus)
{
    return compactFilterPeerStatus == 3 ? BROwnNodeHealthServing
         : compactFilterPeerStatus == 1 ? BROwnNodeHealthConnecting : BROwnNodeHealthDark;
}

// The sync watchdogs' canon-peer pin (BRSyncWatchdog.h: the fast tip-stall tier and the corrupt-
// chain heal) shares the peer manager's single pin slot with the own node. While an own node is
// pinned, the watchdogs neither pin a canon peer nor clear the slot when the scan recovers: the
// own node stays the pin, and an exclusive own node stays exclusive. (Android's watchdog pinned
// and cleared regardless, which dropped an exclusive own node to public peers for the rest of
// the session.)
static inline int BROwnNodeWatchdogMayPin(int ownNodePinned)
{
    return ownNodePinned ? 0 : 1;
}

#ifdef __cplusplus
}
#endif

#endif // BROwnNode_h
