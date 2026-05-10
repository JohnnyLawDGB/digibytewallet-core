//
//  BRCompactFilterMsgTests.c
//
//  Round-trip tests for the BIP 157 compact-filter wire protocol added to
//  BRPeer.{c,h}. Each test builds canonical wire bytes for one of the
//  response message types (cfheaders / cfilter / cfcheckpt), feeds them
//  through BRPeerAcceptMessageTest, and asserts the registered callback
//  receives the correctly-decoded fields. Malformed-message cases assert
//  the handler rejects without invoking the callback or crashing.
//
//  This test file is host-only — the Android NDK build compiles BRPeer.c
//  but does not link tests. To run, link against the existing test.c
//  harness or invoke BRCompactFilterMsgTests() from a custom runner.
//
//  Copyright (c) 2026 JohnnyLawDGB. MIT license.
//

#include "BRPeer.h"
#include "BRInt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration: test hook exposing the static dispatcher.
void BRPeerAcceptMessageTest(BRPeer *peer, const uint8_t *msg, size_t msgLen, const char *type);

#define TEST_CHAIN_MAGIC 0xdab6c3fau // arbitrary; the dispatcher ignores magic

// ---- Capture state for callbacks ----------------------------------------

typedef struct {
    int cfheaders_calls;
    uint8_t cfheaders_filter_type;
    UInt256 cfheaders_stop_hash;
    UInt256 cfheaders_prev_filter_header;
    UInt256 cfheaders_hashes[8];
    size_t  cfheaders_count;

    int cfilter_calls;
    uint8_t cfilter_filter_type;
    UInt256 cfilter_block_hash;
    uint8_t cfilter_bytes[256];
    size_t  cfilter_byte_count;

    int cfcheckpt_calls;
    uint8_t cfcheckpt_filter_type;
    UInt256 cfcheckpt_stop_hash;
    UInt256 cfcheckpt_headers[8];
    size_t  cfcheckpt_count;
} CFCapture;

static CFCapture g_cap;

static void reset_capture(void)
{
    memset(&g_cap, 0, sizeof(g_cap));
}

static void cap_cfheaders(void *info, uint8_t filterType, UInt256 stopHash, UInt256 prevFilterHeader,
                          const UInt256 *filterHashes, size_t count)
{
    (void)info;
    g_cap.cfheaders_calls++;
    g_cap.cfheaders_filter_type = filterType;
    g_cap.cfheaders_stop_hash = stopHash;
    g_cap.cfheaders_prev_filter_header = prevFilterHeader;
    g_cap.cfheaders_count = count;
    size_t cap = sizeof(g_cap.cfheaders_hashes)/sizeof(g_cap.cfheaders_hashes[0]);
    size_t n = (count < cap) ? count : cap;
    for (size_t i = 0; i < n; i++) g_cap.cfheaders_hashes[i] = filterHashes[i];
}

static void cap_cfilter(void *info, uint8_t filterType, UInt256 blockHash,
                        const uint8_t *encoded, size_t encodedLen)
{
    (void)info;
    g_cap.cfilter_calls++;
    g_cap.cfilter_filter_type = filterType;
    g_cap.cfilter_block_hash = blockHash;
    g_cap.cfilter_byte_count = (encodedLen < sizeof(g_cap.cfilter_bytes)) ? encodedLen : sizeof(g_cap.cfilter_bytes);
    memcpy(g_cap.cfilter_bytes, encoded, g_cap.cfilter_byte_count);
}

static void cap_cfcheckpt(void *info, uint8_t filterType, UInt256 stopHash,
                          const UInt256 *filterHeaders, size_t count)
{
    (void)info;
    g_cap.cfcheckpt_calls++;
    g_cap.cfcheckpt_filter_type = filterType;
    g_cap.cfcheckpt_stop_hash = stopHash;
    g_cap.cfcheckpt_count = count;
    size_t cap = sizeof(g_cap.cfcheckpt_headers)/sizeof(g_cap.cfcheckpt_headers[0]);
    size_t n = (count < cap) ? count : cap;
    for (size_t i = 0; i < n; i++) g_cap.cfcheckpt_headers[i] = filterHeaders[i];
}

// ---- Helpers -------------------------------------------------------------

static UInt256 u256_fill(uint8_t b)
{
    UInt256 h;
    memset(h.u8, b, sizeof(h.u8));
    return h;
}

#define EXPECT(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); return 1; } } while (0)

// ---- Tests ---------------------------------------------------------------

static int test_cfheaders_roundtrip(void)
{
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, cap_cfheaders, NULL, NULL);
    reset_capture();

    UInt256 stop = u256_fill(0xaa), prev = u256_fill(0xbb);
    UInt256 h0 = u256_fill(0x10), h1 = u256_fill(0x20), h2 = u256_fill(0x30);

    // type(1) + stop(32) + prev(32) + varint(1 byte for count=3) + 3*32
    uint8_t buf[1 + 32 + 32 + 1 + 3*32];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memcpy(&buf[off], stop.u8, 32); off += 32;
    memcpy(&buf[off], prev.u8, 32); off += 32;
    buf[off++] = 3; // CompactSize(3)
    memcpy(&buf[off], h0.u8, 32); off += 32;
    memcpy(&buf[off], h1.u8, 32); off += 32;
    memcpy(&buf[off], h2.u8, 32); off += 32;

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFHEADERS);
    EXPECT(g_cap.cfheaders_calls == 1, "cfheaders callback not fired");
    EXPECT(g_cap.cfheaders_filter_type == FILTER_TYPE_BASIC, "filter type mismatch");
    EXPECT(UInt256Eq(g_cap.cfheaders_stop_hash, stop), "stop hash mismatch");
    EXPECT(UInt256Eq(g_cap.cfheaders_prev_filter_header, prev), "prev filter header mismatch");
    EXPECT(g_cap.cfheaders_count == 3, "count mismatch");
    EXPECT(UInt256Eq(g_cap.cfheaders_hashes[0], h0), "hash[0] mismatch");
    EXPECT(UInt256Eq(g_cap.cfheaders_hashes[1], h1), "hash[1] mismatch");
    EXPECT(UInt256Eq(g_cap.cfheaders_hashes[2], h2), "hash[2] mismatch");

    BRPeerFree(p);
    return 0;
}

static int test_cfheaders_malformed_count_oversize(void)
{
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, cap_cfheaders, NULL, NULL);
    reset_capture();

    // Claim 0xffff filter hashes but provide none -- accept handler must reject.
    uint8_t buf[1 + 32 + 32 + 3];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memset(&buf[off], 0xaa, 32); off += 32;
    memset(&buf[off], 0xbb, 32); off += 32;
    buf[off++] = 0xfd;     // CompactSize prefix for 2-byte value
    buf[off++] = 0xff;
    buf[off++] = 0xff;

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFHEADERS);
    EXPECT(g_cap.cfheaders_calls == 0, "malformed cfheaders should not invoke callback");

    BRPeerFree(p);
    return 0;
}

static int test_cfilter_roundtrip(void)
{
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, NULL, cap_cfilter, NULL);
    reset_capture();

    UInt256 blk = u256_fill(0x5a);
    uint8_t filterBytes[7] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    uint8_t buf[1 + 32 + 1 + sizeof(filterBytes)];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memcpy(&buf[off], blk.u8, 32); off += 32;
    buf[off++] = (uint8_t)sizeof(filterBytes); // CompactSize(7)
    memcpy(&buf[off], filterBytes, sizeof(filterBytes));
    off += sizeof(filterBytes);

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFILTER);
    EXPECT(g_cap.cfilter_calls == 1, "cfilter callback not fired");
    EXPECT(g_cap.cfilter_filter_type == FILTER_TYPE_BASIC, "filter type mismatch");
    EXPECT(UInt256Eq(g_cap.cfilter_block_hash, blk), "block hash mismatch");
    EXPECT(g_cap.cfilter_byte_count == sizeof(filterBytes), "byte count mismatch");
    EXPECT(memcmp(g_cap.cfilter_bytes, filterBytes, sizeof(filterBytes)) == 0, "filter bytes mismatch");

    BRPeerFree(p);
    return 0;
}

static int test_cfilter_malformed_length_mismatch(void)
{
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, NULL, cap_cfilter, NULL);
    reset_capture();

    // Declare 10 filter bytes but provide 5 -- accept handler must reject.
    uint8_t buf[1 + 32 + 1 + 5];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memset(&buf[off], 0x77, 32); off += 32;
    buf[off++] = 10;
    memset(&buf[off], 0xab, 5);
    off += 5;

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFILTER);
    EXPECT(g_cap.cfilter_calls == 0, "malformed cfilter should not invoke callback");

    BRPeerFree(p);
    return 0;
}

static int test_cfcheckpt_roundtrip(void)
{
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, NULL, NULL, cap_cfcheckpt);
    reset_capture();

    UInt256 stop = u256_fill(0xcc);
    UInt256 hdr0 = u256_fill(0x40), hdr1 = u256_fill(0x50);

    uint8_t buf[1 + 32 + 1 + 2*32];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memcpy(&buf[off], stop.u8, 32); off += 32;
    buf[off++] = 2;
    memcpy(&buf[off], hdr0.u8, 32); off += 32;
    memcpy(&buf[off], hdr1.u8, 32); off += 32;

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFCHECKPT);
    EXPECT(g_cap.cfcheckpt_calls == 1, "cfcheckpt callback not fired");
    EXPECT(g_cap.cfcheckpt_filter_type == FILTER_TYPE_BASIC, "filter type mismatch");
    EXPECT(UInt256Eq(g_cap.cfcheckpt_stop_hash, stop), "stop hash mismatch");
    EXPECT(g_cap.cfcheckpt_count == 2, "count mismatch");
    EXPECT(UInt256Eq(g_cap.cfcheckpt_headers[0], hdr0), "header[0] mismatch");
    EXPECT(UInt256Eq(g_cap.cfcheckpt_headers[1], hdr1), "header[1] mismatch");

    BRPeerFree(p);
    return 0;
}

static int test_callbacks_optional_null(void)
{
    // NULL callbacks must not crash when the dispatcher routes a well-formed
    // message — they just discard the decoded payload.
    BRPeer *p = BRPeerNew(TEST_CHAIN_MAGIC);
    BRPeerSetCompactFilterCallbacks(p, NULL, NULL, NULL);
    reset_capture();

    uint8_t buf[1 + 32 + 1 + 1];
    size_t off = 0;
    buf[off++] = FILTER_TYPE_BASIC;
    memset(&buf[off], 0x42, 32); off += 32;
    buf[off++] = 1;
    buf[off++] = 0x99;

    BRPeerAcceptMessageTest(p, buf, off, MSG_CFILTER); // should not crash
    EXPECT(g_cap.cfilter_calls == 0, "no callback was registered; capture should be empty");

    BRPeerFree(p);
    return 0;
}

// ---- Entry point ---------------------------------------------------------

int BRCompactFilterMsgTests(void)
{
    int r = 0;
    r |= test_cfheaders_roundtrip();
    r |= test_cfheaders_malformed_count_oversize();
    r |= test_cfilter_roundtrip();
    r |= test_cfilter_malformed_length_mismatch();
    r |= test_cfcheckpt_roundtrip();
    r |= test_callbacks_optional_null();
    if (r == 0) {
        printf("BRCompactFilterMsgTests: all passing\n");
    } else {
        printf("BRCompactFilterMsgTests: FAILURE\n");
    }
    return r;
}
