//
//  BRWalletFilterElements.c
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRWalletFilterElements.h"
#include "BRWallet.h"
#include "BRAddress.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Build-time observability.
//
// Deliberately NO logging from this file. BRWalletGetFilterElements runs once per
// cfilter — up to 1000 per batch, tens of millions across a deep sync — and it runs
// with the peer manager's lock held, so an unconditional log line here would both
// flood logd's per-uid ring (evicting the diagnostics we rely on) and extend exactly
// the lock-hold window the sync work is trying to shrink. Instead we keep a snapshot
// of the last build and let the JNI/Kotlin layer emit one line when it CHANGES.
//
// Guarded by a dedicated leaf mutex: written on peer threads, read from a JVM thread,
// and a multi-field struct read without synchronisation is a torn read on ARM. This
// mutex is never held while acquiring any other lock.
//
// `owner` scopes the snapshot to one wallet so a host KAT building two wallets cannot
// read the other's counters.
// ---------------------------------------------------------------------------
static pthread_mutex_t g_statsLock = PTHREAD_MUTEX_INITIALIZER;
static BRWalletFilterElementsStats g_stats;
static const BRWallet *g_statsOwner = NULL;

static void _recordStats(const BRWallet *wallet, const BRWalletFilterElementsStats *s)
{
    pthread_mutex_lock(&g_statsLock);
    size_t priorFailures = (g_statsOwner == wallet) ? g_stats.allocFailures : 0;
    g_stats = *s;
    g_stats.allocFailures = priorFailures; // sticky across builds; only reset on owner change
    g_statsOwner = wallet;
    pthread_mutex_unlock(&g_statsLock);
}

static void _recordAllocFailure(const BRWallet *wallet)
{
    pthread_mutex_lock(&g_statsLock);
    if (g_statsOwner != wallet) { memset(&g_stats, 0, sizeof(g_stats)); g_statsOwner = wallet; }
    g_stats.allocFailures++;
    pthread_mutex_unlock(&g_statsLock);
}

int BRWalletFilterElementsGetStats(const BRWallet *wallet, BRWalletFilterElementsStats *out)
{
    int r = 0;

    if (! out) return 0;
    pthread_mutex_lock(&g_statsLock);
    if (g_statsOwner && (! wallet || g_statsOwner == wallet)) { *out = g_stats; r = 1; }
    pthread_mutex_unlock(&g_statsLock);
    return r;
}

BRWalletFilterElements *BRWalletGetFilterElements(BRWallet *wallet)
{
    BRWalletFilterElementsStats stats;
    BRWalletAddrOrigins origins;
    size_t addrCount = 0;

    if (!wallet) return NULL;

    memset(&stats, 0, sizeof(stats));

    // Single-call snapshot: the address set cannot change between sizing and filling.
    // The old two-call BRWalletAllAddrs form released wallet->lock in between, so a chain
    // that grew in that window either overran this buffer (heap corruption) or silently
    // truncated the match set (missed receives). See BRWallet.h.
    BRAddress *addrs = BRWalletCopyAllAddrs(wallet, &addrCount, &origins);
    if (!addrs || addrCount == 0) { free(addrs); return NULL; }
    stats.addrs = addrCount;

    // First pass: query each scriptPubKey length, accumulate total backing size.
    // BRAddressScriptPubKey returns 0 for anything it cannot encode — COUNTED as
    // `dropped` rather than vanishing without trace, which is what let a whole class of
    // watch-set bugs hide through a release cycle.
    size_t *lens = (size_t *)calloc(addrCount, sizeof(*lens));
    if (!lens) { free(addrs); _recordAllocFailure(wallet); return NULL; }

    size_t totalLen = 0;
    size_t validCount = 0;
    for (size_t i = 0; i < addrCount; i++) {
        size_t n = BRAddressScriptPubKey(NULL, 0, addrs[i].s);
        if (n == 0) {
            stats.dropped++;
            if (stats.firstDroppedPrefix[0] == '\0') {
                // Prefix ONLY — never the full address. These counters are surfaced to
                // logs, which may leave the device.
                strncpy(stats.firstDroppedPrefix, addrs[i].s, sizeof(stats.firstDroppedPrefix) - 1);
            }
            continue;
        }
        lens[i] = n;
        totalLen += n;
        validCount++;
    }

    if (validCount == 0) {
        free(addrs);
        free(lens);
        _recordStats(wallet, &stats);
        return NULL;
    }

    uint8_t *backing = (uint8_t *)malloc(totalLen);
    const uint8_t **elements = (const uint8_t **)malloc(validCount * sizeof(*elements));
    size_t *elementLens = (size_t *)malloc(validCount * sizeof(*elementLens));
    BRWalletFilterElements *fe = (BRWalletFilterElements *)malloc(sizeof(*fe));
    if (!backing || !elements || !elementLens || !fe) {
        free(backing);
        free(elements);
        free(elementLens);
        free(fe);
        free(addrs);
        free(lens);
        _recordAllocFailure(wallet);
        return NULL;
    }

    // Second pass: write the script bytes into backing and record pointers.
    size_t off = 0;
    size_t j = 0;
    for (size_t i = 0; i < addrCount; i++) {
        if (lens[i] == 0) continue;
        size_t wrote = BRAddressScriptPubKey(&backing[off], lens[i], addrs[i].s);
        if (wrote != lens[i]) {
            // Length disagreed between passes — impossible now that the address set is a
            // private snapshot, but never emit a partial element if it ever happens.
            stats.dropped++;
            continue;
        }
        elements[j] = &backing[off];
        elementLens[j] = lens[i];
        off += lens[i];
        j++;
        // Attribute the element to its source. There is deliberately NO separate
        // DigiDollar bucket: a DD address is Base58Check over a 34-byte payload that
        // BRAddressScriptPubKey cannot encode, and it needs none — a DD token output is a
        // plain P2TR script, so the identical 34-byte element (OP_1 0x20 X(Q)) is already
        // emitted by taprootExternalChain[0]. Pinned by filter_elements_kat.
        if (i < origins.derived) stats.derived++; else stats.watched++;
    }

    free(addrs);
    free(lens);

    if (j == 0) {
        free(backing);
        free(elements);
        free(elementLens);
        free(fe);
        _recordStats(wallet, &stats);
        return NULL;
    }

    stats.elements = j;
    _recordStats(wallet, &stats);

    fe->count = j;
    fe->elements = elements;
    fe->elementLens = elementLens;
    fe->backing = backing;
    return fe;
}

void BRWalletFilterElementsFree(BRWalletFilterElements *fe)
{
    if (!fe) return;
    free(fe->backing);
    free((void *)fe->elements);
    free(fe->elementLens);
    free(fe);
}
