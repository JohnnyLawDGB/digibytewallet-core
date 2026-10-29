//
//  BRSeederPeers.h
//
//  The seeder's peer list (https://api.digiscope.me/api/peers?capability=filter): which peers
//  it adds to the manager's candidate pool, tagged with which services, and when the cached list
//  is fetched again. The wallet's first choice is always the peer canon (BRPeerCanon.h); the
//  seeder's filter-validated peers are added beside it at every sync start, so the wallet still
//  has filter peers when the canon cannot be reached. Both platforms must add the same peers
//  with the same service bits, or the filter-first selection picks differently.
//
//  Until 2026-10 these rules lived in Android-only code: the service parse in
//  PeerServicesPolicy.kt (parseSeederServicesHex), the default tag in the JNI bridge
//  (jni_peer.c, INJECT_DEFAULT_SERVICES) and the refresh interval in SyncService.kt.
//
//  The rules:
//    - services_hex: ASCII-trimmed, one leading "0x"/"0X" removed, then 1 to 16 hex digits with
//      a value that fits a signed 64-bit integer (Kotlin's Long). Anything else is 0, "unknown";
//    - a peer whose services are unknown (0) is added tagged BR_PEER_CANON_SERVICES (full blocks
//      + compact filters), never as bloom-only: the wallet is filter-only, and an untagged peer
//      must still count toward the filter-first pool;
//    - only an IPv4 dotted-quad literal is added (the seeder serves IPv4), as IPv4-mapped;
//    - the cached list is fetched again when it is empty or older than
//      BR_SEEDER_REFRESH_MS (one hour).
//  Differences from the Kotlin: trimming is ASCII only, and a sign is not accepted ("-1" was -1,
//  i.e. every service bit). The seeder writes plain "0x44d".
//
//  An own-node in exclusive mode adds no seeder peer at all; that state is the platform's (it
//  pins the node), so the platform skips this call then.
//
//  Host KAT: digibytewallet-android native/src/test/host/seeder_peers_kat/.
//  Header-only, static inline.
//

#ifndef BRSeederPeers_h
#define BRSeederPeers_h

#include "BRPeerManager.h"
#include "BRPeerCanon.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// How long a fetched seeder list is used before it is fetched again: one hour.
#define BR_SEEDER_REFRESH_MS 3600000LL

static inline int _BRSeederIsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// The seeder's services_hex, as service bits; 0 when it is absent or cannot be read.
static inline uint64_t BRSeederServicesParse(const char *s, size_t len)
{
    size_t a = 0, b = len, i;
    uint64_t v = 0;

    if (! s) return 0;
    while (a < b && _BRSeederIsSpace(s[a])) a++;
    while (b > a && _BRSeederIsSpace(s[b - 1])) b--;
#ifdef SEEDER_PEERS_RED
    // RED ARM SEAM (seeder_peers_kat): the prefix is not removed, so "0x44d" reads as 0.
#else
    if (b - a >= 2 && s[a] == '0' && (s[a + 1] == 'x' || s[a + 1] == 'X')) a += 2;
#endif
    if (a == b || b - a > 16) return 0;
    for (i = a; i < b; i++) {
        char c = s[i];
        int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (d < 0) return 0;
        v = v << 4 | (uint64_t)d;
    }
    return (v > (uint64_t)INT64_MAX) ? 0 : v;
}

// The service bits a seeder peer is added with: its own, or the canon's when unknown.
static inline uint64_t BRSeederPeerServices(uint64_t parsed)
{
#ifdef SEEDER_PEERS_RED
    return parsed;                      // RED: an unknown peer is added with no services at all
#else
    return parsed != 0 ? parsed : (uint64_t)BR_PEER_CANON_SERVICES;
#endif
}

// Whether a cached list fetched at lastFetchMs (0: never) is fetched again at nowMs. Time
// differences wrap as Kotlin's Long does.
static inline int BRSeederShouldRefresh(int64_t lastFetchMs, int64_t nowMs, size_t cachedCount)
{
    int64_t age = (int64_t)((uint64_t)nowMs - (uint64_t)lastFetchMs);
    return cachedCount == 0 || age > BR_SEEDER_REFRESH_MS;
}

// Parses an IPv4 dotted-quad literal into the manager's IPv4-mapped form. Returns 1 on success.
static inline int BRSeederPeerAddress(const char *ipv4, UInt128 *out)
{
    struct in_addr a;
    if (! ipv4 || ! out || inet_pton(AF_INET, ipv4, &a) != 1) return 0;
    *out = UINT128_ZERO;
    out->u16[5] = 0xffff;
    memcpy(&out->u32[3], &a, 4);
    return 1;
}

// Adds one seeder peer to the manager's candidate pool. Returns 1 if newly added, 0 if it was
// already known or ipv4 is not an IPv4 literal.
static inline int BRSeederPeerAdd(BRPeerManager *manager, const char *ipv4, uint16_t port, uint64_t parsedServices)
{
    UInt128 addr;
    if (! manager || ! BRSeederPeerAddress(ipv4, &addr)) return 0;
    return BRPeerManagerAddPeer(manager, addr, port, BRSeederPeerServices(parsedServices));
}

#ifdef __cplusplus
}
#endif

#endif // BRSeederPeers_h
