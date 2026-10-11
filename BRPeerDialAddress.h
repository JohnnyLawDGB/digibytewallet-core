//
//  BRPeerDialAddress.h
//
//  The socket address to dial for a peer on a DIRECT connection (no SOCKS proxy).
//
//  IPv4 peers (stored IPv4-mapped, ::ffff:a.b.c.d) are resolved through getaddrinfo on their
//  dotted-quad literal:
//    - on a network with IPv4, the answer is the same AF_INET address the core has always
//      dialled;
//    - on an IPv6-only network with DNS64/NAT64, Apple's getaddrinfo answers with a
//      SYNTHESIZED IPv6 address (the network's NAT64 prefix + the IPv4 address), the only
//      route to an IPv4 peer there. This is Apple's documented path ("Supporting IPv6-only
//      Networks": resolve the IPv4 literal with AI_DEFAULT).
//  App Review tests every app on an IPv6-only network. The peer canon and the seeds' answers
//  are IPv4, so before this an iPhone on such a network reached no peer at all: the core
//  dialled a sockaddr_in6 holding the IPv4-MAPPED address, then a sockaddr_in, and neither
//  routes where there is no IPv4.
//
//  The peer's identity does not change: peer->address stays IPv4-mapped, so penalties, bans,
//  the canon and every log line key on the same address on every platform and network. Only
//  the socket address differs.
//
//  Android: bionic's getaddrinfo answers an IPv4 literal with AF_INET (Android reaches IPv4 over
//  CLAT/464XLAT on IPv6-only networks), so Android dials exactly what it did before.
//
//  getaddrinfo may block for NAT64 prefix discovery (RFC 7050: one DNS query, cached by the
//  system). Call this on the peer's own thread before connect, never under the manager lock.
//  If the resolver fails or answers with nothing usable, the result is the AF_INET address.
//
//  Host KAT: digibytewallet-android native/src/test/host/peer_dial_address_kat/.
//  Header-only, static inline.
//

#ifndef BRPeerDialAddress_h
#define BRPeerDialAddress_h

#include "BRInt.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Apple's NAT64 guide resolves with AI_DEFAULT (AI_V4MAPPED_CFG | AI_ADDRCONFIG). Elsewhere
// there is no AI_DEFAULT, and plain getaddrinfo on an IPv4 literal answers AF_INET.
#ifdef AI_DEFAULT
#define BR_PEER_DIAL_AI_FLAGS AI_DEFAULT
#else
#define BR_PEER_DIAL_AI_FLAGS 0
#endif

// The resolver, replaceable only by the host KAT (which simulates a DNS64 network).
#ifndef BR_PEER_DIAL_GETADDRINFO
#define BR_PEER_DIAL_GETADDRINFO getaddrinfo
#endif
#ifndef BR_PEER_DIAL_FREEADDRINFO
#define BR_PEER_DIAL_FREEADDRINFO freeaddrinfo
#endif

static inline int BRPeerAddressIsIPv4Mapped(UInt128 address)
{
    return (address.u64[0] == 0 && address.u16[4] == 0 && address.u16[5] == 0xffff);
}

// Fills *out and *outLen with the address to connect() to for the peer at address:port, and
// returns its family, AF_INET or AF_INET6 (create the socket with the matching PF_).
static inline int BRPeerDialAddress(UInt128 address, uint16_t port,
                                    struct sockaddr_storage *out, socklen_t *outLen)
{
    memset(out, 0, sizeof(*out));

    if (! BRPeerAddressIsIPv4Mapped(address)) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)out;
        a6->sin6_family = AF_INET6;
        memcpy(&a6->sin6_addr, &address, sizeof(a6->sin6_addr));
        a6->sin6_port = htons(port);
        *outLen = sizeof(*a6);
        return AF_INET6;
    }

#ifndef PEER_DIAL_ADDRESS_NAT64_UNFIXED
    // RED ARM SEAM (peer_dial_address_kat): -DPEER_DIAL_ADDRESS_NAT64_UNFIXED skips the resolver,
    // as the core did before 2026-10.
    {
        char literal[INET_ADDRSTRLEN], service[8];
        struct addrinfo hints, *res = NULL, *p;
        int family = 0;

        if (inet_ntop(AF_INET, &address.u32[3], literal, sizeof(literal)) != NULL) {
            snprintf(service, sizeof(service), "%u", (unsigned)port);
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = BR_PEER_DIAL_AI_FLAGS;

            if (BR_PEER_DIAL_GETADDRINFO(literal, service, &hints, &res) == 0) {
                for (p = res; p && ! family; p = p->ai_next) {
                    if (! p->ai_addr || p->ai_addrlen > (socklen_t)sizeof(*out)) continue;
                    if (p->ai_family == AF_INET6 && p->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
                        memcpy(out, p->ai_addr, p->ai_addrlen);
                        ((struct sockaddr_in6 *)out)->sin6_port = htons(port);
                        *outLen = p->ai_addrlen;
                        family = AF_INET6;
                    }
                    else if (p->ai_family == AF_INET && p->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
                        memcpy(out, p->ai_addr, p->ai_addrlen);
                        ((struct sockaddr_in *)out)->sin_port = htons(port);
                        *outLen = p->ai_addrlen;
                        family = AF_INET;
                    }
                }
                if (res) BR_PEER_DIAL_FREEADDRINFO(res);
                if (family) return family;
                memset(out, 0, sizeof(*out));
            }
        }
    }
#endif

    {
        struct sockaddr_in *a4 = (struct sockaddr_in *)out;
        a4->sin_family = AF_INET;
        memcpy(&a4->sin_addr, &address.u32[3], sizeof(a4->sin_addr));
        a4->sin_port = htons(port);
        *outLen = sizeof(*a4);
        return AF_INET;
    }
}

#ifdef __cplusplus
}
#endif

#endif // BRPeerDialAddress_h
