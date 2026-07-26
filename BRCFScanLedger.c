//
//  BRCFScanLedger.c
//
//  Implementation of the pure per-height compact-filter scan-completeness
//  ledger. See BRCFScanLedger.h and
//  docs/superpowers/specs/2026-07-25-cf-scan-ledger-design.md.
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

#include "BRCFScanLedger.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define UINT32_MAX_VAL 0xffffffffu

// ---- outstanding[] helpers (sorted ascending by height) --------------------

// First index i with outstanding[i].height >= height. Linear over a small,
// sorted, mostly-front-removed array (spec §3: O(gap), fine at these sizes).
static size_t _cfLedgerLowerBound(const BRCFScanLedger *l, uint32_t height)
{
    size_t i = 0;
    while (i < l->outstandingCount && l->outstanding[i].height < height) i++;
    return i;
}

// Advance scannedThrough over the newly-contiguous evaluated run. The lowest
// hole is min(outstanding[0].height, gaveUp[0]) — both arrays are sorted — and
// scannedThrough may climb to just below it, bounded by requestedThrough. This
// is equivalent to the spec's per-height "while scannedThrough+1 <= ceiling and
// scannedThrough+1 not outstanding" walk, since forward CF requests are
// contiguous so every non-hole height in range is evaluated.
static void _cfLedgerAdvance(BRCFScanLedger *l)
{
    uint32_t ceiling = l->requestedThrough;
    uint32_t firstHole = UINT32_MAX_VAL;

    if (l->outstandingCount > 0) firstHole = l->outstanding[0].height;
    if (l->gaveUpCount > 0 && l->gaveUp[0] < firstHole) firstHole = l->gaveUp[0];

    if (firstHole != UINT32_MAX_VAL) {
        uint32_t cap = (firstHole > 0) ? firstHole - 1 : 0;
        if (cap < ceiling) ceiling = cap;
    }
    if (l->scannedThrough < ceiling) l->scannedThrough = ceiling; // never move backward
}

// ---- gaveUp[] helpers (sorted ascending) -----------------------------------

// Insert height into gaveUp (sorted, de-duplicated). Returns 1 if present after
// the call (added or already there), 0 if full (never silently drops — the
// caller keeps the height in outstanding instead).
static int _cfLedgerAddGaveUp(BRCFScanLedger *l, uint32_t height)
{
    size_t i = 0;
    while (i < l->gaveUpCount && l->gaveUp[i] < height) i++;
    if (i < l->gaveUpCount && l->gaveUp[i] == height) return 1; // already present
    if (l->gaveUpCount >= CF_GAVEUP_MAX) return 0;              // full: caller keeps it outstanding
    memmove(&l->gaveUp[i + 1], &l->gaveUp[i], (l->gaveUpCount - i) * sizeof(uint32_t));
    l->gaveUp[i] = height;
    l->gaveUpCount++;
    return 1;
}

static void _cfLedgerRemoveGaveUp(BRCFScanLedger *l, uint32_t height)
{
    size_t i = 0;
    while (i < l->gaveUpCount && l->gaveUp[i] < height) i++;
    if (i < l->gaveUpCount && l->gaveUp[i] == height) {
        memmove(&l->gaveUp[i], &l->gaveUp[i + 1], (l->gaveUpCount - i - 1) * sizeof(uint32_t));
        l->gaveUpCount--;
    }
}

// ---- filter-byte buffer (§7, header-race hold) -----------------------------

#define CF_FILTER_BUF_MAGIC 0x43464246u  // "CFBF" — marks a live (Init'd/Parse'd) filter buffer

static void _cfLedgerFreeFilterEntry(BRCFFilterBufEntry *e)
{
    if (! e) return;
    free(e->bytes);
    free(e);
}

// Free every buffered entry and reset the buffer to empty. Guarded by
// filterBufMagic: on a struct that has never been through Init/Parse/
// BufferFilter (raw/uninitialized memory), filterBufCount and filterBuf[] are
// garbage — the magic check keeps this a safe no-op in that case instead of
// calling free() on whatever garbage bit pattern happens to look like a
// pointer. On a genuinely live ledger the magic is set and every entry is
// freed as expected.
static void _cfLedgerFreeFilterBuffer(BRCFScanLedger *l)
{
    if (l->filterBufMagic == CF_FILTER_BUF_MAGIC) {
        size_t n = l->filterBufCount;
        if (n > CF_FILTER_BUF_SLOTS) n = CF_FILTER_BUF_SLOTS; // defensive bound
        for (size_t i = 0; i < n; i++) {
            _cfLedgerFreeFilterEntry(l->filterBuf[i]);
            l->filterBuf[i] = NULL;
        }
    }
    l->filterBufCount = 0;
    l->bufferedBytes  = 0;
}

static void _cfLedgerEvictOldestFilter(BRCFScanLedger *l)
{
    if (l->filterBufCount == 0) return;
    BRCFFilterBufEntry *e = l->filterBuf[0];
    l->bufferedBytes -= e->len;
    _cfLedgerFreeFilterEntry(e);
    memmove(&l->filterBuf[0], &l->filterBuf[1], (l->filterBufCount - 1) * sizeof(l->filterBuf[0]));
    l->filterBufCount--;
}

int BRCFScanLedgerBufferFilter(BRCFScanLedger *l, UInt256 blockHash,
                               const uint8_t *bytes, size_t len, uint32_t now)
{
    l->filterBufMagic = CF_FILTER_BUF_MAGIC; // this ledger is definitely live now

    if (len > CF_FILTER_BUFFER_MAX_BYTES) return 0; // can never fit even alone

    // De-dup by hash: replace bytes in place, keeping the entry's FIFO position.
    for (size_t i = 0; i < l->filterBufCount; i++) {
        BRCFFilterBufEntry *e = l->filterBuf[i];
        if (UInt256Eq(e->blockHash, blockHash)) {
            uint8_t *copy = malloc(len ? len : 1);
            memcpy(copy, bytes, len);
            free(e->bytes);
            e->bytes = copy;
            l->bufferedBytes = l->bufferedBytes - e->len + len;
            e->len = len;
            e->at  = now;
            // >= (not just >): keep the resident total strictly under the cap
            // once a churn is underway, rather than letting it settle exactly
            // AT the cap — see BufferFilter's insert-path comment below.
            while (l->bufferedBytes >= CF_FILTER_BUFFER_MAX_BYTES && l->filterBufCount > 1) {
                _cfLedgerEvictOldestFilter(l);
            }
            return 1;
        }
    }

    // FIFO-evict-oldest while the incoming filter would meet-or-push us over
    // budget. >= (not just >): CF_FILTER_BUFFER_MAX_BYTES divides evenly by
    // common filter sizes, so a strict > would let bufferedBytes settle
    // exactly AT the cap and never trigger again on same-size churn — using
    // >= keeps eviction live (a byte-for-byte swap never grows unbounded).
    while (l->bufferedBytes + len >= CF_FILTER_BUFFER_MAX_BYTES && l->filterBufCount > 0) {
        _cfLedgerEvictOldestFilter(l);
    }
    // Fixed-capacity backstop, independent of the byte budget — guards against
    // a pathological run of many tiny filters exhausting the pointer array.
    if (l->filterBufCount >= CF_FILTER_BUF_SLOTS) {
        _cfLedgerEvictOldestFilter(l);
    }

    BRCFFilterBufEntry *entry = malloc(sizeof(*entry));
    entry->blockHash = blockHash;
    entry->bytes     = malloc(len ? len : 1);
    memcpy(entry->bytes, bytes, len);
    entry->len = len;
    entry->at  = now;

    l->filterBuf[l->filterBufCount] = entry;
    l->filterBufCount++;
    l->bufferedBytes += len;
    return 1;
}

size_t BRCFScanLedgerDrainConnected(BRCFScanLedger *l,
                                    int (*isReady)(void *ctx, UInt256 blockHash, uint32_t *outHeight),
                                    void *ctx,
                                    uint8_t *scratch, size_t scratchCap,
                                    int (*evalFn)(void *ctx, uint32_t height, UInt256 blockHash,
                                                  const uint8_t *bytes, size_t len),
                                    size_t maxDrain)
{
    size_t removed   = 0;
    size_t processed = 0;
    size_t i = 0;

    while (i < l->filterBufCount && processed < maxDrain) {
        BRCFFilterBufEntry *e = l->filterBuf[i];
        uint32_t height = 0;

        if (! isReady || ! isReady(ctx, e->blockHash, &height)) {
            i++; // not ready yet — leave it, check the next entry
            continue;
        }

        processed++;

        size_t n = e->len;
        if (n > scratchCap) n = scratchCap; // defensive: never overrun the caller's scratch buffer
        if (scratch && n > 0) memcpy(scratch, e->bytes, n);

        int credited = evalFn ? evalFn(ctx, height, e->blockHash, scratch, n) : 0;
        if (credited) {
            l->bufferedBytes -= e->len;
            _cfLedgerFreeFilterEntry(e);
            memmove(&l->filterBuf[i], &l->filterBuf[i + 1],
                    (l->filterBufCount - i - 1) * sizeof(l->filterBuf[0]));
            l->filterBufCount--;
            removed++;
            // do not advance i — the next entry has shifted into slot i
        } else {
            i++; // evalFn couldn't dispatch this tick (e.g. no CF peer) — keep, retry next tick
        }
    }
    return removed;
}

void BRCFScanLedgerClearFilterBuffer(BRCFScanLedger *l)
{
    _cfLedgerFreeFilterBuffer(l);
}

void BRCFScanLedgerFree(BRCFScanLedger *l)
{
    _cfLedgerFreeFilterBuffer(l);
}

size_t BRCFScanLedgerBufferedCount(const BRCFScanLedger *l) { return l->filterBufCount; }
size_t BRCFScanLedgerBufferedBytes(const BRCFScanLedger *l) { return l->bufferedBytes; }

// ---- init ------------------------------------------------------------------

void BRCFScanLedgerInit(BRCFScanLedger *l, uint32_t start)
{
    _cfLedgerFreeFilterBuffer(l); // BEFORE the memset below — else a live filterBuf[] leaks
    memset(l, 0, sizeof(*l));
    l->filterBufMagic = CF_FILTER_BUF_MAGIC;
    l->start = start;
    // Nothing evaluated/requested yet: floor sits just below the birth height.
    // Birth height is a real block (>0); guard the genesis degenerate case.
    l->scannedThrough   = (start > 0) ? start - 1 : 0;
    l->requestedThrough = l->scannedThrough;
}

// ---- record requested ------------------------------------------------------

// Insert one height into outstanding (sorted, de-duplicated). A height already
// present just refreshes its target (a re-request). Overflow drops the OLDEST
// (front / lowest-height) entry in-module; returns that dropped height so the
// caller can report it (CF_LEDGER_NO_DROP if nothing was evicted).
static uint32_t _cfLedgerInsertOutstanding(BRCFScanLedger *l, uint32_t height,
                                           UInt128 peer, uint16_t port, uint32_t now)
{
    size_t i = _cfLedgerLowerBound(l, height);
    uint32_t dropped = CF_LEDGER_NO_DROP;

    if (i < l->outstandingCount && l->outstanding[i].height == height) {
        // Already outstanding — a re-request records the new target/clock.
        l->outstanding[i].peer        = peer;
        l->outstanding[i].port        = port;
        l->outstanding[i].requestedAt = now;
        return dropped;
    }

    if (l->outstandingCount >= CF_OUTSTANDING_MAX) {
        // Drop the oldest (front, lowest height). Coverage cap — caller reports it.
        dropped = l->outstanding[0].height;
        memmove(&l->outstanding[0], &l->outstanding[1],
                (l->outstandingCount - 1) * sizeof(BRCFOutstanding));
        l->outstandingCount--;
        if (i > 0) i--; // indices shifted down by the front removal
    }

    memmove(&l->outstanding[i + 1], &l->outstanding[i],
            (l->outstandingCount - i) * sizeof(BRCFOutstanding));
    l->outstanding[i].height      = height;
    l->outstanding[i].peer        = peer;
    l->outstanding[i].port        = port;
    l->outstanding[i].requestedAt = now;
    l->outstanding[i].attempts    = 0;
    l->outstanding[i].headerRace  = 0;
    l->outstandingCount++;
    return dropped;
}

// Same as BRCFScanLedgerRecordRequested but never silent about CF_OUTSTANDING_MAX
// overflow: returns the count of oldest heights evicted to make room, and (if
// outLow/outHigh non-NULL) their [low..high] range (CF_LEDGER_NO_DROP if none).
int BRCFScanLedgerRecordRequestedDropped(BRCFScanLedger *l, uint32_t startH, uint32_t stopH,
                                         UInt128 peer, uint16_t port, uint32_t now,
                                         uint32_t *outLow, uint32_t *outHigh)
{
    if (stopH < startH) return 0;
    int n = 0; uint32_t lo = CF_LEDGER_NO_DROP, hi = 0;
    for (uint32_t h = startH; ; h++) {
        uint32_t d = _cfLedgerInsertOutstanding(l, h, peer, port, now);
        if (d != CF_LEDGER_NO_DROP) { n++; if (d < lo) lo = d; if (d > hi) hi = d; }
        if (h == stopH) break;                       // guards h==UINT32_MAX
    }
    if (stopH > l->requestedThrough) l->requestedThrough = stopH;   // ★ MUST NOT drop this (scannedThrough ceiling)
    if (outLow) *outLow = (n ? lo : CF_LEDGER_NO_DROP);
    if (outHigh) *outHigh = (n ? hi : CF_LEDGER_NO_DROP);
    return n;
}

void BRCFScanLedgerRecordRequested(BRCFScanLedger *l, uint32_t startH, uint32_t stopH,
                                   UInt128 peer, uint16_t port, uint32_t now)
{
    BRCFScanLedgerRecordRequestedDropped(l, startH, stopH, peer, port, now, NULL, NULL);
}

// ---- mark evaluated --------------------------------------------------------

void BRCFScanLedgerMarkEvaluated(BRCFScanLedger *l, uint32_t height)
{
    size_t i = _cfLedgerLowerBound(l, height);
    if (i < l->outstandingCount && l->outstanding[i].height == height) {
        memmove(&l->outstanding[i], &l->outstanding[i + 1],
                (l->outstandingCount - i - 1) * sizeof(BRCFOutstanding));
        l->outstandingCount--;
    }
    // Defensive: an evaluated height is no longer a hole, wherever it lived.
    _cfLedgerRemoveGaveUp(l, height);
    _cfLedgerAdvance(l);
}

// ---- mark header race ------------------------------------------------------

void BRCFScanLedgerMarkHeaderRace(BRCFScanLedger *l, uint32_t height)
{
    size_t i = _cfLedgerLowerBound(l, height);
    if (i < l->outstandingCount && l->outstanding[i].height == height) {
        l->outstanding[i].headerRace = 1; // keep outstanding, flag the fast retry
        return;
    }
    // Defensive: a header-race drop must never be lost even if bookkeeping
    // drifted — record it as an outstanding hole (zeroed target, flagged).
    _cfLedgerInsertOutstanding(l, height, UINT128_ZERO, 0, 0);
    i = _cfLedgerLowerBound(l, height);
    if (i < l->outstandingCount && l->outstanding[i].height == height) {
        l->outstanding[i].headerRace = 1;
    }
    if (height > l->requestedThrough) l->requestedThrough = height;
}

// ---- re-arm on peer disconnect ---------------------------------------------

void BRCFScanLedgerReArmPeer(BRCFScanLedger *l, UInt128 peer, uint16_t port)
{
    for (size_t i = 0; i < l->outstandingCount; i++) {
        if (l->outstanding[i].port == port && UInt128Eq(l->outstanding[i].peer, peer)) {
            l->outstanding[i].peer = UINT128_ZERO; // clear so the driver picks someone else
            l->outstanding[i].port = 0;
            // height + attempts intentionally preserved
        }
    }
}

// ---- Phase-2 re-request driver ---------------------------------------------

// Backoff before the NEXT re-request of an entry. attempts = re-requests
// already made (0-indexed): header-race first retry short-circuits to 10s,
// otherwise min(BASE << attempts, CAP) → 30/60/120/120/120.
static uint32_t _cfLedgerRerequestDelay(const BRCFOutstanding *e)
{
    if (e->headerRace && e->attempts == 0) return CF_REREQ_HEADERRACE_SECS;

    uint32_t d = CF_REREQ_BASE_SECS;
    for (uint32_t k = 0; k < e->attempts; k++) {
        d <<= 1;
        if (d >= CF_REREQ_BACKOFF_CAP_SECS) { d = CF_REREQ_BACKOFF_CAP_SECS; break; }
    }
    if (d > CF_REREQ_BACKOFF_CAP_SECS) d = CF_REREQ_BACKOFF_CAP_SECS;
    return d;
}

int BRCFScanLedgerNextRerequest(BRCFScanLedger *l, uint32_t now, uint32_t *outHeight)
{
    // 1. Retire any capped entries to gaveUp (reported, never dropped). If gaveUp
    //    is full they stay outstanding but are no longer offered (step 2 skips
    //    them) — still counted/reported, so nothing is lost.
    for (size_t i = 0; i < l->outstandingCount; ) {
        if (l->outstanding[i].attempts >= CF_REREQ_MAX_ATTEMPTS &&
            _cfLedgerAddGaveUp(l, l->outstanding[i].height)) {
            memmove(&l->outstanding[i], &l->outstanding[i + 1],
                    (l->outstandingCount - i - 1) * sizeof(BRCFOutstanding));
            l->outstandingCount--;
            continue; // do not advance i — a new entry shifted into this slot
        }
        i++;
    }

    l->lastDriveAt = now;

    // 2. Offer the lowest-height entry whose backoff has elapsed.
    for (size_t i = 0; i < l->outstandingCount; i++) {
        BRCFOutstanding *e = &l->outstanding[i];
        if (e->attempts >= CF_REREQ_MAX_ATTEMPTS) continue; // capped (gaveUp-full case)

        uint32_t delay   = _cfLedgerRerequestDelay(e);
        uint32_t elapsed = (now >= e->requestedAt) ? (now - e->requestedAt) : 0;
        if (elapsed >= delay) {
            e->attempts++;
            e->requestedAt = now;   // re-stamp for the next backoff step
            if (outHeight) *outHeight = e->height;
            return 1;
        }
    }
    return 0;
}

// ---- reporters -------------------------------------------------------------

uint32_t BRCFScanLedgerScannedThrough(const BRCFScanLedger *l) { return l->scannedThrough; }
size_t   BRCFScanLedgerOutstandingCount(const BRCFScanLedger *l) { return l->outstandingCount; }
size_t   BRCFScanLedgerGaveUpCount(const BRCFScanLedger *l) { return l->gaveUpCount; }

size_t BRCFScanLedgerHoleRanges(const BRCFScanLedger *l, uint32_t *outStarts, uint32_t *outEnds, size_t cap)
{
    if (cap == 0 || outStarts == NULL || outEnds == NULL) return 0;

    size_t oi = 0, gi = 0, nRanges = 0;
    uint32_t curStart = 0, curEnd = 0;
    int have = 0;

    // Merge the two sorted height sources (outstanding heights, gaveUp) and
    // coalesce contiguous runs into [start..end] ranges.
    while (oi < l->outstandingCount || gi < l->gaveUpCount) {
        uint32_t h;
        if (oi < l->outstandingCount &&
            (gi >= l->gaveUpCount || l->outstanding[oi].height <= l->gaveUp[gi])) {
            h = l->outstanding[oi].height;
            oi++;
            if (gi < l->gaveUpCount && l->gaveUp[gi] == h) gi++; // defensive de-dup
        } else {
            h = l->gaveUp[gi];
            gi++;
        }

        if (! have) {
            curStart = curEnd = h;
            have = 1;
        } else if (h == curEnd) {
            // duplicate, ignore
        } else if (h == curEnd + 1) {
            curEnd = h;
        } else {
            outStarts[nRanges] = curStart;
            outEnds[nRanges]   = curEnd;
            nRanges++;
            if (nRanges == cap) return nRanges; // arrays full
            curStart = curEnd = h;
        }
    }
    if (have && nRanges < cap) {
        outStarts[nRanges] = curStart;
        outEnds[nRanges]   = curEnd;
        nRanges++;
    }
    return nRanges;
}

// ---- pending-confirm -------------------------------------------------------

void BRCFScanLedgerRecordPending(BRCFScanLedger *l, UInt256 blockHash,
                                 const UInt256 *txHashes, size_t n, uint32_t now)
{
    if (n > CF_PENDING_TX_MAX) n = CF_PENDING_TX_MAX; // cap; a block with more wallet txs is pathological

    // Re-record of the same block replaces its tx set.
    for (size_t i = 0; i < l->pendingCount; i++) {
        if (UInt256Eq(l->pending[i].blockHash, blockHash)) {
            l->pending[i].txCount = (uint16_t)n;
            for (size_t j = 0; j < n; j++) l->pending[i].txHashes[j] = txHashes[j];
            l->pending[i].recordedAt = now;
            return;
        }
    }

    if (l->pendingCount >= CF_PENDING_CONFIRM_MAX) {
        // Drop the oldest (front). Caller logs; pending is a transient assoc.
        memmove(&l->pending[0], &l->pending[1],
                (l->pendingCount - 1) * sizeof(BRCFPendingConfirm));
        l->pendingCount--;
    }

    BRCFPendingConfirm *p = &l->pending[l->pendingCount];
    p->blockHash  = blockHash;
    p->txCount    = (uint16_t)n;
    p->recordedAt = now;
    for (size_t j = 0; j < n; j++) p->txHashes[j] = txHashes[j];
    l->pendingCount++;
}

size_t BRCFScanLedgerTakePending(BRCFScanLedger *l, UInt256 blockHash, UInt256 *outTx, size_t cap)
{
    for (size_t i = 0; i < l->pendingCount; i++) {
        if (! UInt256Eq(l->pending[i].blockHash, blockHash)) continue;

        size_t n = l->pending[i].txCount;
        if (n > cap) n = cap;
        for (size_t j = 0; j < n && outTx; j++) outTx[j] = l->pending[i].txHashes[j];

        memmove(&l->pending[i], &l->pending[i + 1],
                (l->pendingCount - i - 1) * sizeof(BRCFPendingConfirm));
        l->pendingCount--;
        return n;
    }
    return 0;
}

// ---- persistence -----------------------------------------------------------
//
// Blob layout (little-endian, deterministic so the round-trip is byte-identical):
//   magic u32 | version u32 | start u32 | scannedThrough u32 | requestedThrough u32
//   outstandingCount u32 | { height u32, headerRace u8 } * count
//   gaveUpCount u32 | { height u32 } * count
// Persisted set only (§5): NOT attempts/timestamps/peers, NOT pending.

#define CF_LEDGER_MAGIC   0x43464C31u  // "CFL1"
#define CF_LEDGER_VERSION 1u

static void _putU32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t _getU32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static size_t _cfLedgerSerializedSize(const BRCFScanLedger *l)
{
    return 4 /*magic*/ + 4 /*version*/ + 4 /*start*/ + 4 /*scanned*/ + 4 /*requested*/
         + 4 /*outCount*/ + l->outstandingCount * (4 + 1)
         + 4 /*gaveUpCount*/ + l->gaveUpCount * 4;
}

size_t BRCFScanLedgerSerialize(const BRCFScanLedger *l, uint8_t *buf, size_t buflen)
{
    size_t need = _cfLedgerSerializedSize(l);
    if (buf == NULL || buflen < need) return need; // sizing query / too small: don't write

    uint8_t *p = buf;
    _putU32(p, CF_LEDGER_MAGIC);      p += 4;
    _putU32(p, CF_LEDGER_VERSION);    p += 4;
    _putU32(p, l->start);             p += 4;
    _putU32(p, l->scannedThrough);    p += 4;
    _putU32(p, l->requestedThrough);  p += 4;

    _putU32(p, (uint32_t)l->outstandingCount); p += 4;
    for (size_t i = 0; i < l->outstandingCount; i++) {
        _putU32(p, l->outstanding[i].height); p += 4;
        *p++ = l->outstanding[i].headerRace;
    }

    _putU32(p, (uint32_t)l->gaveUpCount); p += 4;
    for (size_t i = 0; i < l->gaveUpCount; i++) {
        _putU32(p, l->gaveUp[i]); p += 4;
    }
    return need;
}

int BRCFScanLedgerParse(BRCFScanLedger *l, const uint8_t *buf, size_t buflen)
{
    // Garbled/short blob -> empty ledger (caller rebuilds via re-anchor/rescan).
    _cfLedgerFreeFilterBuffer(l); // BEFORE the memset below — else a live filterBuf[] leaks
    memset(l, 0, sizeof(*l));
    l->filterBufMagic = CF_FILTER_BUF_MAGIC;
    if (buf == NULL || buflen < 24) return 0;

    const uint8_t *p = buf;
    size_t remaining = buflen;

    if (_getU32(p) != CF_LEDGER_MAGIC)   return 0;
    if (_getU32(p + 4) != CF_LEDGER_VERSION) return 0;
    l->start            = _getU32(p + 8);
    l->scannedThrough   = _getU32(p + 12);
    l->requestedThrough = _getU32(p + 16);
    uint32_t outCount   = _getU32(p + 20);
    p += 24; remaining -= 24;

    if (outCount > CF_OUTSTANDING_MAX) return 0;
    if (remaining < (size_t)outCount * (4 + 1) + 4) return 0;

    for (uint32_t i = 0; i < outCount; i++) {
        l->outstanding[i].height      = _getU32(p); p += 4;
        l->outstanding[i].headerRace  = *p++;
        // reset (not persisted, §5): fresh process -> fresh peers
        l->outstanding[i].peer        = UINT128_ZERO;
        l->outstanding[i].port        = 0;
        l->outstanding[i].requestedAt = 0;
        l->outstanding[i].attempts    = 0;
    }
    l->outstandingCount = outCount;
    remaining -= (size_t)outCount * (4 + 1);

    uint32_t gaveUpCount = _getU32(p); p += 4; remaining -= 4;
    if (gaveUpCount > CF_GAVEUP_MAX) return 0;
    if (remaining < (size_t)gaveUpCount * 4) return 0;

    for (uint32_t i = 0; i < gaveUpCount; i++) {
        l->gaveUp[i] = _getU32(p); p += 4;
    }
    l->gaveUpCount = gaveUpCount;

    // pending is transient — not persisted; lastDriveAt resets.
    l->pendingCount = 0;
    l->lastDriveAt  = 0;
    return 1;
}
