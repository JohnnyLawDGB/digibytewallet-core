//
//  BRPeerCFStatus.h
//
//  Compact-filter peer status, computed from three booleans the peer
//  manager gathers about a candidate peer:
//    inPool    — a peer with this addr:port exists in manager->peers
//    connected — that peer's status is Connected with an open socket
//    served    — that peer has answered a cfheaders/cfilter request this
//                session
//  Feeds the own-node first-class pairing connectivity UI (Task 2+): the
//  pinned node's row shows UNKNOWN/CONNECTING/CONNECTED_NOT_SERVING/SERVING
//  so the user can see whether their own node is actually relaying filters,
//  not just connected.
//
//  This header holds ONLY the pure mapping over caller-supplied booleans
//  (no BRPeerManager struct, no locking, no I/O) so it's testable
//  standalone on the host (see native/src/test/host/cf_peer_status_kat/).
//  Modeled on BRPeerPenalty.h / BRPeerPin.h's static-inline-predicate-in-a-
//  header shape.
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

#ifndef BRPeerCFStatus_h
#define BRPeerCFStatus_h

#include <stdint.h>

// Compact-filter peer status, computed from three booleans the manager gathers:
//   inPool    — a peer with this addr:port exists in manager->peers
//   connected — that peer's status is Connected with an open socket
//   served    — that peer has answered a cfheaders/cfilter request this session
// Pure so the mapping is host-KAT-testable without the manager.
enum {
    BR_CF_PEER_UNKNOWN               = 0,
    BR_CF_PEER_CONNECTING            = 1,
    BR_CF_PEER_CONNECTED_NOT_SERVING = 2,
    BR_CF_PEER_SERVING               = 3,
};

static inline int BRComputeCFPeerStatus(int inPool, int connected, int served)
{
    if (! inPool) return BR_CF_PEER_UNKNOWN;
    if (! connected) return BR_CF_PEER_CONNECTING;
    return served ? BR_CF_PEER_SERVING : BR_CF_PEER_CONNECTED_NOT_SERVING;
}

#endif // BRPeerCFStatus_h
