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
#include <string.h> // memcpy
#include "BRInt.h" // UInt128, UInt128Eq, UInt16/32/64 get/set

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

// ---- persistence -------------------------------------------------------------
//
// The penalty set used to die with the process, so every cold start re-dialled peers
// the previous session had already learned were behind — the "one peer dialled 122x"
// churn, reintroduced once per launch. These two helpers round-trip it through a blob
// the Kotlin layer persists alongside the saved peers.
//
// Wire format, little-endian: [4-byte count][per entry: 16-byte addr, 2-byte port,
// 8-byte absolute deadline]. Deadlines are absolute on purpose: a blob written days
// ago must expire on read rather than re-penalize a peer that has long since recovered.
// Both directions drop lapsed entries, so a wallet that sat closed for an hour starts
// with a clean slate.

#define BR_PEER_PENALTY_ENTRY_BYTES 26u
#define BR_PEER_PENALTY_HEADER_BYTES 4u

// Serialize the live (unexpired) entries into [buf]. Returns bytes written, or 0 if the
// buffer is too small — never a truncated blob, which would deserialize into garbage
// penalties on the next launch.
static inline size_t BRPeerPenaltySerialize(const UInt128 *addrs, const uint16_t *ports,
                                            const time_t *until, size_t count, time_t now,
                                            uint8_t *buf, size_t bufLen)
{
    size_t live = 0, pos;

    if (! buf) return 0;
    for (size_t i = 0; i < count; i++) if (until[i] > now) live++;
    if (bufLen < BR_PEER_PENALTY_HEADER_BYTES + live * BR_PEER_PENALTY_ENTRY_BYTES) return 0;

    UInt32SetLE(buf, (uint32_t)live);
    pos = BR_PEER_PENALTY_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        if (until[i] <= now) continue;
        memcpy(&buf[pos], &addrs[i], 16); pos += 16;
        UInt16SetLE(&buf[pos], ports[i]); pos += 2;
        UInt64SetLE(&buf[pos], (uint64_t)until[i]); pos += 8;
    }

    return pos;
}

// Restore penalties from [buf], dropping any whose deadline has already lapsed and
// stopping at [maxCount]. Returns the number restored. A short, empty or malformed blob
// restores nothing rather than inventing entries — this input comes off disk.
static inline size_t BRPeerPenaltyDeserialize(const uint8_t *buf, size_t bufLen, time_t now,
                                              UInt128 *addrs, uint16_t *ports, time_t *until,
                                              size_t maxCount)
{
    size_t claimed, pos = BR_PEER_PENALTY_HEADER_BYTES, out = 0;

    if (! buf || bufLen < BR_PEER_PENALTY_HEADER_BYTES) return 0;
    claimed = (size_t)UInt32GetLE(buf);
    if (bufLen < BR_PEER_PENALTY_HEADER_BYTES + claimed * BR_PEER_PENALTY_ENTRY_BYTES) return 0;

    for (size_t i = 0; i < claimed && out < maxCount; i++) {
        UInt128 a;
        uint16_t p;
        time_t u;

        memcpy(&a, &buf[pos], 16); pos += 16;
        p = UInt16GetLE(&buf[pos]); pos += 2;
        u = (time_t)UInt64GetLE(&buf[pos]); pos += 8;
        if (u <= now) continue;
        addrs[out] = a;
        ports[out] = p;
        until[out] = u;
        out++;
    }

    return out;
}

#endif // BRPeerPenalty_h
