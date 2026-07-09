//
//  BRPeerPenalty.h
//
//  Session-scoped penalty predicate for the peer manager's filter-first
//  dial loop (BRPeerManager.c:2448-2472). Fixes the "node isn't synced"
//  churn: _peerConnected's reject at BRPeerManager.c:914-916 disconnects a
//  behind peer but nothing remembered that rejection, so the very next
//  BRPeerManagerConnect() pass re-dialed the same still-behind peer again
//  -- observed live as one peer dialed 122x in a tight loop while the
//  wallet held 0 connected peers. BRPeerManager now keeps a small
//  fixed-size ring buffer of (address, port, until) entries and the dial
//  loop skips any candidate still inside its penalty window.
//
//  This header holds ONLY the pure predicate over caller-supplied parallel
//  arrays (no BRPeerManager struct, no locking, no I/O) so it's testable
//  standalone on the host (see native/src/test/host/peer_penalty_kat/).
//  Modeled on BRPeerServices.h's static-inline-predicate-in-a-header shape.
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

#ifndef BRPeerPenalty_h
#define BRPeerPenalty_h

#include <time.h>
#include "BRInt.h" // UInt128, UInt128Eq

// Is (a, p) currently penalized? True iff some entry i < count matches
// BOTH the address and the port AND its penalty window hasn't lapsed yet
// (until[i] > now, strict -- an entry expires exactly at its deadline, not
// one tick after). Pure function of the caller-supplied parallel arrays;
// does no bounds checking beyond `count` (caller-owned invariant, same as
// every other fixed-size-ring-buffer helper in this codebase).
static inline int BRPeerPenaltyContains(const UInt128 *addrs, const uint16_t *ports, const time_t *until,
                                         size_t count, UInt128 a, uint16_t p, time_t now)
{
    for (size_t i = 0; i < count; i++) {
        if (ports[i] == p && UInt128Eq(addrs[i], a) && until[i] > now) return 1;
    }
    return 0;
}

#endif // BRPeerPenalty_h
