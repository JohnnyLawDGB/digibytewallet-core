//
//  BRCompactFilterChainTests.c
//
//  Tests for BRCompactFilterChain.{c,h}. Pure data-structure tests —
//  no peers, no sockets. Verify append continuity, look-up by height,
//  filter verification, and serialize/deserialize round-trip.
//
//  Host-only file (not compiled into the Android NDK build). Call
//  BRCompactFilterChainTests() from a custom runner to exercise.
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRCompactFilterChain.h"
#include "BRGCSFilter.h"
#include "BRCrypto.h"
#include "BRInt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECT(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); return 1; } } while (0)

static UInt256 u256_fill(uint8_t b)
{
    UInt256 h;
    memset(h.u8, b, sizeof(h.u8));
    return h;
}

// ---- Basic creation + accessors -----------------------------------------

static int test_empty_chain_invariants(void)
{
    UInt256 anchor = u256_fill(0x77);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 100, anchor);
    EXPECT(c != NULL, "create returned NULL");

    EXPECT(BRCompactFilterChainType(c) == 0, "type accessor wrong");
    EXPECT(BRCompactFilterChainStartHeight(c) == 100, "startHeight accessor wrong");
    EXPECT(BRCompactFilterChainCount(c) == 0, "empty chain should have count=0");
    EXPECT(BRCompactFilterChainNextHeight(c) == 100, "NextHeight on empty chain should be startHeight");
    EXPECT(UInt256Eq(BRCompactFilterChainTipHeader(c), anchor), "tip on empty chain should be anchor");

    // Anchor lookup: querying startHeight - 1 returns the anchor.
    EXPECT(UInt256Eq(BRCompactFilterChainHeader(c, 99), anchor), "header at anchor height wrong");
    // Out-of-range lookups return zero.
    UInt256 z = BRCompactFilterChainHeader(c, 100);
    EXPECT(UInt256IsZero(z), "header at first non-extended height should be ZERO");
    z = BRCompactFilterChainHeader(c, 0);
    EXPECT(UInt256IsZero(z), "header far below startHeight should be ZERO");

    BRCompactFilterChainFree(c);
    return 0;
}

// ---- Append + continuity -------------------------------------------------

static int test_append_extends_chain(void)
{
    UInt256 anchor = u256_fill(0xa1);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 50, anchor);

    UInt256 h0 = u256_fill(0x10);
    UInt256 h1 = u256_fill(0x20);
    UInt256 batch[] = { h0, h1 };

    int ok = BRCompactFilterChainAppend(c, anchor, batch, 2);
    EXPECT(ok == 1, "append should succeed against tip = anchor");
    EXPECT(BRCompactFilterChainCount(c) == 2, "count after append");
    EXPECT(BRCompactFilterChainNextHeight(c) == 52, "NextHeight after append");

    // Recompute filterHeader[50] and filterHeader[51] independently.
    UInt256 hdr50 = BRGCSFilterHeader(h0, anchor);
    UInt256 hdr51 = BRGCSFilterHeader(h1, hdr50);

    EXPECT(UInt256Eq(BRCompactFilterChainHeader(c, 50), hdr50), "header[50] wrong");
    EXPECT(UInt256Eq(BRCompactFilterChainHeader(c, 51), hdr51), "header[51] wrong");
    EXPECT(UInt256Eq(BRCompactFilterChainTipHeader(c), hdr51), "tip header wrong");

    BRCompactFilterChainFree(c);
    return 0;
}

static int test_append_continuity_rejection(void)
{
    UInt256 anchor = u256_fill(0xa2);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 0, anchor);

    UInt256 bogusPrev = u256_fill(0xff); // not equal to tip
    UInt256 h0 = u256_fill(0x99);

    int ok = BRCompactFilterChainAppend(c, bogusPrev, &h0, 1);
    EXPECT(ok == 0, "append with wrong prev should fail");
    EXPECT(BRCompactFilterChainCount(c) == 0, "chain should be unchanged after failed append");

    BRCompactFilterChainFree(c);
    return 0;
}

static int test_append_empty_batch_is_noop(void)
{
    UInt256 anchor = u256_fill(0xa3);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 10, anchor);

    int ok = BRCompactFilterChainAppend(c, anchor, NULL, 0);
    EXPECT(ok == 1, "empty append should succeed");
    EXPECT(BRCompactFilterChainCount(c) == 0, "empty append should not change count");

    BRCompactFilterChainFree(c);
    return 0;
}

// ---- Filter verification -------------------------------------------------

static int test_verify_filter(void)
{
    // We need a real encoded filter so BRSHA256_2 yields a meaningful hash
    // that the chain can chain forward and verify.
    UInt256 anchor = u256_fill(0xb0);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 100, anchor);

    // Fake "encoded filter" — we just need bytes whose dSHA256 we can
    // chain into header[100] via BRGCSFilterHeader.
    uint8_t enc[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    UInt256 filterHash;
    BRSHA256_2(&filterHash, enc, sizeof(enc));

    int ok = BRCompactFilterChainAppend(c, anchor, &filterHash, 1);
    EXPECT(ok == 1, "append should succeed");

    EXPECT(BRCompactFilterChainVerifyFilter(c, 100, enc, sizeof(enc)) == 1,
           "verify against the correct filter bytes should pass");

    uint8_t tampered[8];
    memcpy(tampered, enc, sizeof(enc));
    tampered[0] ^= 0x55;
    EXPECT(BRCompactFilterChainVerifyFilter(c, 100, tampered, sizeof(tampered)) == 0,
           "verify against tampered filter bytes should fail");

    // Out-of-range heights fail rather than crash.
    EXPECT(BRCompactFilterChainVerifyFilter(c, 200, enc, sizeof(enc)) == 0,
           "verify out-of-range height should return 0");

    BRCompactFilterChainFree(c);
    return 0;
}

// ---- Serialize / Deserialize --------------------------------------------

static int test_serialize_round_trip(void)
{
    UInt256 anchor = u256_fill(0xc0);
    BRCompactFilterChain *c = BRCompactFilterChainNew(0, 1234, anchor);

    UInt256 batch[3] = { u256_fill(0x01), u256_fill(0x02), u256_fill(0x03) };
    int ok = BRCompactFilterChainAppend(c, anchor, batch, 3);
    EXPECT(ok == 1, "append must succeed before round-trip");

    // Query size, then serialize.
    size_t need = BRCompactFilterChainSerialize(c, NULL, 0);
    EXPECT(need > 0, "serialize size query should be >0");
    uint8_t *buf = (uint8_t *)malloc(need);
    size_t got = BRCompactFilterChainSerialize(c, buf, need);
    EXPECT(got == need, "serialize wrote unexpected size");

    BRCompactFilterChain *roundtripped = BRCompactFilterChainDeserialize(buf, need);
    EXPECT(roundtripped != NULL, "deserialize returned NULL");
    EXPECT(BRCompactFilterChainType(roundtripped) == BRCompactFilterChainType(c), "type mismatch");
    EXPECT(BRCompactFilterChainStartHeight(roundtripped) == BRCompactFilterChainStartHeight(c), "startHeight mismatch");
    EXPECT(BRCompactFilterChainCount(roundtripped) == BRCompactFilterChainCount(c), "count mismatch");
    EXPECT(UInt256Eq(BRCompactFilterChainTipHeader(roundtripped), BRCompactFilterChainTipHeader(c)),
           "tip mismatch after round-trip");

    // Every header at every height must match.
    for (uint32_t h = 1234; h < 1234 + 3; h++) {
        EXPECT(UInt256Eq(BRCompactFilterChainHeader(c, h), BRCompactFilterChainHeader(roundtripped, h)),
               "header mismatch at some height after round-trip");
    }
    EXPECT(UInt256Eq(BRCompactFilterChainHeader(roundtripped, 1233), anchor),
           "anchor lost in round-trip");

    free(buf);
    BRCompactFilterChainFree(c);
    BRCompactFilterChainFree(roundtripped);
    return 0;
}

static int test_deserialize_rejects_garbage(void)
{
    // Way too short
    EXPECT(BRCompactFilterChainDeserialize((const uint8_t *)"x", 1) == NULL,
           "deserialize must reject too-short buffer");
    EXPECT(BRCompactFilterChainDeserialize(NULL, 0) == NULL,
           "deserialize must reject NULL buffer");

    // Build a buffer with wrong magic.
    uint8_t bad[50] = {0};
    bad[0] = 0xde; bad[1] = 0xad; bad[2] = 0xbe; bad[3] = 0xef;
    EXPECT(BRCompactFilterChainDeserialize(bad, sizeof(bad)) == NULL,
           "deserialize must reject wrong magic");

    return 0;
}

// ---- Entry point ---------------------------------------------------------

int BRCompactFilterChainTests(void)
{
    int r = 0;
    r |= test_empty_chain_invariants();
    r |= test_append_extends_chain();
    r |= test_append_continuity_rejection();
    r |= test_append_empty_batch_is_noop();
    r |= test_verify_filter();
    r |= test_serialize_round_trip();
    r |= test_deserialize_rejects_garbage();
    if (r == 0) {
        printf("BRCompactFilterChainTests: all passing\n");
    } else {
        printf("BRCompactFilterChainTests: FAILURE\n");
    }
    return r;
}
