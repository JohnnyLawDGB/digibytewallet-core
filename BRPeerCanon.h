//
//  BRPeerCanon.h
//
//  The peer CANON: the hardcoded BIP157/158 compact-filter peers the wallet
//  must always be able to reach, for each network. This is the wallet's only
//  reliable filter source -- the seeder (api.digiscope.me) is the fallback when
//  the canon fails, and the DNS/addr-relayed pool is junk (old nodes tens of
//  thousands of blocks behind, non-SPV nodes). A wallet that cannot find these
//  peers cannot sync, full stop.
//
//  Until 2026-09 this table lived in the Android JNI bridge (jni_peer.c), an
//  Android-only compilation unit that the iOS XCFramework does not contain. It
//  is moved here because it decides what goes on the wire at bootstrap: a
//  platform that carries its own copy of the canon is a platform whose fresh
//  install can be stranded on a different peer set, and an operator rotation
//  fixed on one platform silently leaves the other one dialling dead IPs.
//
//  Two properties of the table are load-bearing and the host KAT enforces both
//  (native/src/test/host/peer_canon_kat/):
//
//    1. Every entry is an IPv4 LITERAL, never a hostname. The bootstrap path
//       is sovereignty-critical: a hostname puts a DNS resolver -- and whoever
//       controls that name -- between a fresh install and its first filter
//       peer. BRPeerCanonParseIPv4 below is deliberately a pure parser with no
//       resolver behind it, so a hostname cannot slip in and "work" on a
//       developer's network.
//    2. The mainnet set is MULTI-OPERATOR. 134.199.198.90 (digiscope.me, the
//       author's node) is one-of-N and listed first, not THE peer. The set
//       spans distinct /16s, but that is only a rough diversity signal -- not a
//       guarantee of operator/ASN independence. Several fall in shared-hosting
//       ranges and some may be co-located or author-run, so the cfheaders
//       continuity quorum's real independence is bounded by the seeder set's
//       actual operator diversity. A curated multi-operator bootstrap, strictly
//       better than the single peer it replaced; not a trustless one.
//
//  SNAPSHOT 2026-07-15 -- re-pull from the seeder when operators rotate.
//
//  The mainnet set is the DigiDollar oracle set: persistent filter-serving
//  nodes the capability-aware seeder advertises, running Core 9.26 with
//  blockfilterindex + peerblockfilters. The set is MIXED -- some also serve
//  bloom (0x44d), some are CF-only (0x449). All are tagged NODE_NETWORK |
//  NODE_COMPACT_FILTERS here so BRPeerManager's filter-first selection dials
//  them and the CF accept gate keeps them; the real service bits from each
//  peer's version message govern retention afterwards.
//
//  testnet26 has no seeder at all, so its three public nodes stand in for the
//  whole mechanism. 95.111.238.51 is a verified compact-filter testnet26 node
//  and is listed first; the other two are connectivity fallbacks.
//
//  Header-only, static inline, no BRPeerManager, no locking, no I/O, no
//  resolver. The P2P port is deliberately NOT restated here: it is
//  BRChainParams.h's `standardPort` (12024 mainnet / 12033 testnet26), and a
//  second statement of a port is a second thing that can drift. Callers dial
//  the canon on the active chain's standardPort.
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

#ifndef BRPeerCanon_h
#define BRPeerCanon_h

#include <stdint.h>
#include <stddef.h>

#include "BRInt.h"          // UInt128, UINT128_ZERO, UInt128Eq
#include "BRPeer.h"         // SERVICES_NODE_NETWORK / SERVICES_NODE_COMPACT_FILTERS

#ifdef __cplusplus
extern "C" {
#endif

// How every canon peer is tagged when injected. Full node + compact filters,
// never bloom: bloom was excised in 4.0.0 and a bloom-tagged peer would be
// deprioritised by filter-first selection while the wallet dials for filters.
#define BR_PEER_CANON_SERVICES (SERVICES_NODE_NETWORK | SERVICES_NODE_COMPACT_FILTERS)

// Set sizes are stated ONCE, here, and the tables below are declared with
// exactly these bounds: one entry too many is a compile error, one too few
// leaves a NULL the KAT's every-entry-parses check trips on.
#define BR_PEER_CANON_MAINNET_COUNT 15
#define BR_PEER_CANON_TESTNET_COUNT 3

// Capacity bound for a caller's stack array that must hold either set. A
// plain literal, not max(mainnet, testnet) as an expression: Swift imports
// only simple macros, and this one is what an iOS caller sizes its buffer
// with. The KAT asserts both set sizes fit under it.
#define BR_PEER_CANON_MAX_COUNT 15

// The table for a network, as dotted-quad literals. `count` receives the
// entry count. The arrays live inside the function so a translation unit that
// includes this header and never asks for the table does not carry -- or warn
// about -- an unused copy of it.
static inline const char *const *BRPeerCanonIPs(int testnet, size_t *count)
{
    static const char *const mainnet[BR_PEER_CANON_MAINNET_COUNT] = {
#ifdef PEER_CANON_HOSTNAME_UNFIXED
        // RED-gate shape only: the pre-oracle-bootstrap wallet, whose single
        // priority peer was a HOSTNAME resolved through DNS on the bootstrap
        // path. Never defined in a production build.
        "digiscope.me",
#else
        "134.199.198.90",   // digiscope.me -- author node, one-of-N, listed first
#endif
        "129.212.182.152",
        "134.56.44.241",
        "174.131.163.123",
        "64.182.71.26",
        "66.64.43.14",
        "172.104.191.6",
        "103.230.156.247",
        "216.250.127.199",
        "112.213.39.221",
        "101.103.12.129",
        "95.111.238.51",
        "84.30.137.73",
        "109.123.231.205",
        "147.93.171.46",
    };
    static const char *const testnet26[BR_PEER_CANON_TESTNET_COUNT] = {
        "95.111.238.51",    // verified compact-filter testnet26 node
        "164.68.98.125",
        "129.212.182.152",
    };

    if (testnet) {
        if (count) *count = BR_PEER_CANON_TESTNET_COUNT;
        return testnet26;
    }
    if (count) *count = BR_PEER_CANON_MAINNET_COUNT;
    return mainnet;
}

static inline size_t BRPeerCanonCount(int testnet)
{
    return testnet ? BR_PEER_CANON_TESTNET_COUNT : BR_PEER_CANON_MAINNET_COUNT;
}

// Entry `i` of the network's table, or NULL past the end.
static inline const char *BRPeerCanonIPAt(int testnet, size_t i)
{
    size_t count = 0;
    const char *const *ips = BRPeerCanonIPs(testnet, &count);
    return (i < count) ? ips[i] : NULL;
}

// Parse a dotted-quad IPv4 LITERAL into the IPv4-mapped IPv6 form the peer
// manager uses everywhere (::ffff:a.b.c.d -- u16[5] == 0xffff, the address in
// u8[12..15] in network byte order). Returns 1 on success, 0 on anything that
// is not exactly four decimal octets: a hostname, a fifth octet, an octet over
// 255, a leading zero, leading/trailing junk. Matches inet_pton(AF_INET)'s
// acceptance on those inputs -- the KAT cross-checks -- but without a resolver
// anywhere near it, which is the point: a hostname in the table fails here on
// every network, not just one without DNS.
static inline int BRPeerCanonParseIPv4(const char *s, UInt128 *out)
{
    UInt128 addr = UINT128_ZERO;
    int octet;

    if (! s) return 0;

    for (octet = 0; octet < 4; octet++) {
        unsigned value = 0;
        int digits = 0;

        if (octet > 0) {
            if (*s != '.') return 0;
            s++;
        }
        while (*s >= '0' && *s <= '9') {
            if (digits == 1 && value == 0) return 0;   // leading zero ("01")
            value = value*10 + (unsigned)(*s - '0');
            digits++;
            if (digits > 3 || value > 255) return 0;
            s++;
        }
        if (digits == 0) return 0;
        addr.u8[12 + octet] = (uint8_t)value;
    }
    if (*s != '\0') return 0;

    addr.u16[5] = 0xffff;
    if (out) *out = addr;
    return 1;
}

// Fill `out` with up to `max` parsed canon addresses for the network and return
// how many were written. An entry that fails to parse is skipped rather than
// written as zero, so a caller never dials ::. The KAT proves nothing is
// skipped in the production table.
static inline size_t BRPeerCanonAddrs(int testnet, UInt128 *out, size_t max)
{
    size_t count = 0, written = 0, i;
    const char *const *ips = BRPeerCanonIPs(testnet, &count);

    for (i = 0; i < count && written < max; i++) {
        UInt128 addr;
        if (! BRPeerCanonParseIPv4(ips[i], &addr)) continue;
        out[written++] = addr;
    }
    return written;
}

// Is `addr` (IPv4-mapped, as the peer manager holds it) one of the network's
// canon peers? Used to exempt the canon from PERSISTED penalties: a wallet the
// fleet is refusing will penalise most of it in-session, which is correct, but
// coming back up skipping the whole fleet it must reach first is the on-ramp
// to 0 peers -> watchdog -> recreate -> floor-to-birth.
static inline int BRPeerCanonContains(int testnet, UInt128 addr)
{
    size_t count = 0, i;
    const char *const *ips = BRPeerCanonIPs(testnet, &count);

    for (i = 0; i < count; i++) {
        UInt128 canon;
        if (BRPeerCanonParseIPv4(ips[i], &canon) && UInt128Eq(canon, addr)) return 1;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // BRPeerCanon_h
