//
//  BRPeerPin.h
//
//  Pure predicate for the "own-node first-class pairing" feature: is a
//  candidate peer the user's pinned own-node (address:port)? A pin is
//  "set" when pinnedPort != 0 (an all-zero addr/port means no pin has been
//  configured). The peer manager will use this to give the pinned node
//  priority treatment in the dial loop and connectivity UI (Task 2+).
//
//  This header holds ONLY the pure predicate over caller-supplied values
//  (no BRPeerManager struct, no locking, no I/O) so it's testable
//  standalone on the host (see native/src/test/host/own_node_pin_kat/).
//  Modeled on BRPeerPenalty.h's static-inline-predicate-in-a-header shape.
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

#ifndef BRPeerPin_h
#define BRPeerPin_h

#include <stdint.h>
#include "BRInt.h"   // UInt128, UInt128Eq, UINT128_ZERO

// Pure predicate: is candidate addr:port the pinned own-node? A pin is "set" when
// pinnedPort != 0 (a zero addr/port means no pin). Modeled on BRPeerPenalty.h's
// static-inline-predicate shape so it is host-testable with no BRPeerManager.c.
static inline int BRPeerIsPinned(UInt128 pinnedAddr, uint16_t pinnedPort, UInt128 a, uint16_t p)
{
    if (pinnedPort == 0) return 0;                 // no pin configured
    return (UInt128Eq(pinnedAddr, a) && pinnedPort == p) ? 1 : 0;
}

#endif // BRPeerPin_h
