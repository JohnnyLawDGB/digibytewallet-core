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
//   served    — that peer has answered a cfheaders/cfilter request this session and no
//               request of ours to it has stalled since (OWNNODE-LIVE, BRCFServedClock below)
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

// OWNNODE-LIVE. `served` means serving compact filters NOW, not "answered once this session". A peer
// that answered earlier and then let a request of ours go unanswered is no longer serving: a paired
// node that does this must read CONNECTED_NOT_SERVING (the own-node DARK banner), not SERVING.
//
// One clock per request class (getcfheaders, getcfilters), per peer that has served. A send starts
// the clock if it is stopped and advances it otherwise; an answer OF THE SAME CLASS stops it (a node
// that still answers cfheaders but has stopped answering cfilters is not serving the scan). "Answer"
// here is any well-formed answer of that class, including one the wallet cannot use because of its
// own state (a re-anchored or full chain, a reorg, a header race): the node answered. The clock reads
// stalled when
//   - at least CF_SERVED_STALE_SENDS sends went unanswered (the original and a retry), and
//   - the first of them is CF_SERVED_STALE_SECS old, and
//   - the NEWEST of them is at least `retrySecs` (the request timeout) old.
// The last condition is what keeps a healthy node from flickering dark after a device sleep: the
// requests sent before the sleep read ancient, but the wallet's wake retry is the newest send, and a
// serving node answers it within the timeout. The clocks also restart when the peer disconnects or
// reconnects (BRCFServedClockAnswer), because a request sent on a socket that closed is never
// answered. A clock that runs backwards never reads stalled.
//
// Scope: this sees a request that stalled. A caught-up wallet asks nothing until a new block arrives,
// so a node that stops relaying blocks while still answering pings starts no clock and keeps reading
// SERVING; that case reaches DARK through the tip-stall watchdog's peer-manager rebuild, after which
// the served ring is empty and the node reads CONNECTED_NOT_SERVING until it answers again.
#ifndef CF_SERVED_STALE_SECS
#define CF_SERVED_STALE_SECS  90
#endif
#define CF_SERVED_STALE_SENDS 2

typedef struct {
    int64_t  firstSend;   // when the oldest unanswered send went out (valid while sends > 0)
    int64_t  lastSend;    // when the newest unanswered send went out (valid while sends > 0)
    uint32_t sends;       // unanswered sends since the last answer; 0 = clock stopped
} BRCFServedClock;

static inline void BRCFServedClockSend(BRCFServedClock *c, int64_t now)
{
    if (c->sends == 0) c->firstSend = now;
    if (c->sends < UINT32_MAX) c->sends++;
    c->lastSend = now;
}

static inline void BRCFServedClockAnswer(BRCFServedClock *c)
{
    c->sends = 0; c->firstSend = 0; c->lastSend = 0;
}

static inline int BRCFServedClockStalled(const BRCFServedClock *c, int64_t now, int64_t retrySecs)
{
    if (c->sends < CF_SERVED_STALE_SENDS) return 0;
    if (now - c->firstSend < CF_SERVED_STALE_SECS) return 0;
    return now - c->lastSend >= retrySecs;
}

#endif // BRPeerCFStatus_h
