//
//  BRWalletFilterElements.c
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRWalletFilterElements.h"
#include "BRWallet.h"
#include "BRAddress.h"

#include <stdlib.h>
#include <string.h>

BRWalletFilterElements *BRWalletGetFilterElements(BRWallet *wallet)
{
    if (!wallet) return NULL;

    size_t addrCount = BRWalletAllAddrs(wallet, NULL, 0);
    if (addrCount == 0) return NULL;

    BRAddress *addrs = (BRAddress *)malloc(addrCount * sizeof(*addrs));
    if (!addrs) return NULL;
    addrCount = BRWalletAllAddrs(wallet, addrs, addrCount);
    if (addrCount == 0) { free(addrs); return NULL; }

    // First pass: query each scriptPubKey length, accumulate total backing
    // size. BRAddressScriptPubKey returns 0 for unparseable addresses;
    // those are skipped silently.
    size_t *lens = (size_t *)calloc(addrCount, sizeof(*lens));
    if (!lens) { free(addrs); return NULL; }

    size_t totalLen = 0;
    size_t validCount = 0;
    for (size_t i = 0; i < addrCount; i++) {
        size_t n = BRAddressScriptPubKey(NULL, 0, addrs[i].s);
        if (n == 0) continue;
        lens[i] = n;
        totalLen += n;
        validCount++;
    }

    if (validCount == 0) {
        free(addrs);
        free(lens);
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
        return NULL;
    }

    // Second pass: write the script bytes into backing and record pointers.
    size_t off = 0;
    size_t j = 0;
    for (size_t i = 0; i < addrCount; i++) {
        if (lens[i] == 0) continue;
        size_t wrote = BRAddressScriptPubKey(&backing[off], lens[i], addrs[i].s);
        if (wrote != lens[i]) {
            // Address became unparseable between passes — implausible but
            // not impossible if the wallet mutates concurrently. Drop the
            // entry rather than emit a partial element.
            continue;
        }
        elements[j] = &backing[off];
        elementLens[j] = lens[i];
        off += lens[i];
        j++;
    }

    free(addrs);
    free(lens);

    if (j == 0) {
        free(backing);
        free(elements);
        free(elementLens);
        free(fe);
        return NULL;
    }

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
