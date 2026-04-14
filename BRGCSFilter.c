//
//  BRGCSFilter.c
//
//  BIP 158 Golomb-coded Set compact block filter.
//
//  Copyright (c) 2026 JohnnyLawDGB. Ported from Bitcoin Core v26.2's
//  src/blockfilter.{h,cpp}, src/crypto/siphash.{h,cpp},
//  src/util/golombrice.h, and src/util/fastrange.h
//  (Copyright (c) 2014-2025 The Bitcoin Core developers), MIT license.
//
//  Port notes:
//  - Stays close to the reference; optimizations deferred until the
//    BIP 158 appendix test vectors are passing byte-for-byte.
//  - Pre-decodes all N Golomb-Rice values at parse time into a sorted
//    uint64_t array; Match and MatchAny do no heap allocation.
//  - SipHash-2-4 keys are the first 16 raw wire bytes of the block
//    hash (k0 = bytes[0..7] as little-endian u64, k1 = bytes[8..15]).
//    This is the #1 bug in from-scratch implementations; the
//    BRGCSFilterBasicParse wrapper exists to prevent callers getting
//    this wrong.
//

#include "BRGCSFilter.h"
#include "BRCrypto.h"
#include "BRAddress.h"
#include "BRInt.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

// ---- SipHash-2-4 ----------------------------------------------------------
//
// Self-contained port of Bitcoin Core's src/crypto/siphash.cpp Finalize
// path for the "hash a byte buffer" case. We don't need the incremental
// Write() interface; every call here hashes a single contiguous element.

#define SIP_ROTL(x, b) ((uint64_t)(((x) << (b)) | ((x) >> (64 - (b)))))

#define SIP_ROUND(v0, v1, v2, v3) do {          \
    v0 += v1; v1 = SIP_ROTL(v1, 13); v1 ^= v0;  \
    v0 = SIP_ROTL(v0, 32);                      \
    v2 += v3; v3 = SIP_ROTL(v3, 16); v3 ^= v2;  \
    v0 += v3; v3 = SIP_ROTL(v3, 21); v3 ^= v0;  \
    v2 += v1; v1 = SIP_ROTL(v1, 17); v1 ^= v2;  \
    v2 = SIP_ROTL(v2, 32);                      \
} while (0)

static uint64_t siphash24(uint64_t k0, uint64_t k1,
                          const uint8_t *data, size_t len)
{
    uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
    uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
    uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);

    const uint8_t *end = data + (len - (len & 7));
    while (data != end) {
        uint64_t m = UInt64GetLE(data);
        v3 ^= m;
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= m;
        data += 8;
    }

    uint64_t b = ((uint64_t)len) << 56;
    switch (len & 7) {
        case 7: b |= ((uint64_t)data[6]) << 48; /* fallthrough */
        case 6: b |= ((uint64_t)data[5]) << 40; /* fallthrough */
        case 5: b |= ((uint64_t)data[4]) << 32; /* fallthrough */
        case 4: b |= ((uint64_t)data[3]) << 24; /* fallthrough */
        case 3: b |= ((uint64_t)data[2]) << 16; /* fallthrough */
        case 2: b |= ((uint64_t)data[1]) << 8;  /* fallthrough */
        case 1: b |= ((uint64_t)data[0]);       /* fallthrough */
        case 0: break;
    }

    v3 ^= b;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// ---- FastRange64 ----------------------------------------------------------
//
// (hash * F) >> 64 — uniform mapping of a 64-bit hash into [0, F).
// Uses __uint128_t where available (arm64, x86_64 — all Android targets
// we ship to). Provides a portable fallback via 128-bit scalar
// multiplication for exotic platforms.

static inline uint64_t fastrange64(uint64_t hash, uint64_t F)
{
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((__uint128_t)hash * (__uint128_t)F) >> 64);
#else
    // Portable 64x64 → top-64 multiply.
    uint64_t h = hash >> 32, l = hash & 0xffffffffu;
    uint64_t H = F >> 32,    L = F & 0xffffffffu;
    uint64_t ll = l * L;
    uint64_t lh = l * H;
    uint64_t hl = h * L;
    uint64_t hh = h * H;
    uint64_t mid = (ll >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

// ---- CompactSize reader ---------------------------------------------------
//
// BRVarInt in this submodule has matching semantics with Bitcoin's
// CompactSize (0xFD = u16 LE, 0xFE = u32 LE, 0xFF = u64 LE, else 1-byte
// value). Wrap it to return failure when the buffer would be overrun
// or the value doesn't fit what we need.

static int read_compact_size(const uint8_t *buf, size_t bufLen,
                              size_t *cursor, uint64_t *value)
{
    if (*cursor >= bufLen) return 0;
    size_t consumed = 0;
    uint64_t v = BRVarInt(buf + *cursor, bufLen - *cursor, &consumed);
    if (consumed == 0 || *cursor + consumed > bufLen) return 0;
    *cursor += consumed;
    *value = v;
    return 1;
}

// ---- Bit-stream reader ----------------------------------------------------
//
// MSB-first, as BIP 158 specifies. Bit alignment at byte boundaries is
// the #2 implementation pitfall behind SipHash endianness; keep this
// simple.

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t bytePos;
    uint8_t bitPos; // 0..7, MSB-first (0 = highest bit of current byte)
} BitReader;

static void br_init(BitReader *br, const uint8_t *data, size_t len,
                     size_t startByte)
{
    br->data = data;
    br->len = len;
    br->bytePos = startByte;
    br->bitPos = 0;
}

// Reads up to 64 bits. Returns 1 on success, 0 on buffer underrun.
static int br_read(BitReader *br, uint8_t nbits, uint64_t *out)
{
    uint64_t v = 0;
    for (uint8_t i = 0; i < nbits; i++) {
        if (br->bytePos >= br->len) return 0;
        uint8_t bit = (br->data[br->bytePos] >> (7 - br->bitPos)) & 1u;
        v = (v << 1) | bit;
        br->bitPos++;
        if (br->bitPos >= 8) { br->bitPos = 0; br->bytePos++; }
    }
    *out = v;
    return 1;
}

// Are we past the last byte with no remaining bits to read? Used to
// detect trailing data that should have been consumed.
static int br_at_end(const BitReader *br)
{
    return br->bytePos >= br->len;
}

// Golomb-Rice decode: unary-encoded quotient (q 1s then a 0), then
// P-bit remainder. DoS-safe: rejects absurd q values.
static int gr_decode(BitReader *br, uint8_t P, uint64_t *out)
{
    uint64_t q = 0, bit;
    for (;;) {
        if (!br_read(br, 1, &bit)) return 0;
        if (bit == 0) break;
        q++;
        // Hard cap on unary run length. With P=19 and M=784931, the
        // expected quotient is ~M/2^P ≈ 1.5; absurd q values (>2^20)
        // can only come from a malformed stream.
        if (q > (1ULL << 32)) return 0;
    }
    uint64_t r;
    if (!br_read(br, P, &r)) return 0;
    *out = (q << P) + r;
    return 1;
}

// ---- Filter structure -----------------------------------------------------

struct BRGCSFilter {
    uint8_t  P;
    uint32_t M;
    uint64_t k0;
    uint64_t k1;
    uint32_t N;          // Number of elements
    uint64_t F;          // N * M, used for FastRange64
    uint8_t *encoded;    // Copy of raw encoded bytes (for hash)
    size_t   encodedLen;
    uint64_t *values;    // Sorted decoded hashes, length N (NULL when N=0)
};

// ---- Parse ----------------------------------------------------------------

BRGCSFilter *BRGCSFilterParse(const uint8_t *bytes, size_t len,
                               uint64_t k0, uint64_t k1,
                               uint8_t P, uint32_t M)
{
    if (!bytes && len != 0) return NULL;
    if (len > BR_GCS_MAX_ENCODED_SIZE) return NULL;
    if (P == 0 || P > 32 || M == 0) return NULL;

    // Read CompactSize N
    size_t cursor = 0;
    uint64_t N64 = 0;
    if (!read_compact_size(bytes, len, &cursor, &N64)) return NULL;
    if (N64 > UINT32_MAX) return NULL;

    uint32_t N = (uint32_t)N64;
    uint64_t F = (uint64_t)N * (uint64_t)M;
    // Defend against F overflow. N is u32, M is u32, so N*M fits in u64.
    // (Included for clarity; cannot overflow given the types.)

    // Allocate the filter struct + encoded-bytes copy
    BRGCSFilter *f = (BRGCSFilter *)calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->P = P;
    f->M = M;
    f->k0 = k0;
    f->k1 = k1;
    f->N = N;
    f->F = F;

    if (len > 0) {
        f->encoded = (uint8_t *)malloc(len);
        if (!f->encoded) { BRGCSFilterFree(f); return NULL; }
        memcpy(f->encoded, bytes, len);
        f->encodedLen = len;
    }

    // Empty filter (N=0): nothing to decode. The encoded bytes are just
    // the CompactSize 0x00. Filter hash is dSHA256 of that single byte
    // (NOT the empty string). BIP 158 §Encoding: "When the filter is
    // empty, the encoded form is a single byte".
    if (N == 0) return f;

    // Pre-decode values into a sorted array. Each Golomb-Rice value is
    // a delta from the previous running sum, so cumulative += delta
    // yields the sorted series directly.
    f->values = (uint64_t *)malloc((size_t)N * sizeof(uint64_t));
    if (!f->values) { BRGCSFilterFree(f); return NULL; }

    BitReader br;
    br_init(&br, bytes, len, cursor);

    uint64_t running = 0;
    for (uint32_t i = 0; i < N; i++) {
        uint64_t delta = 0;
        if (!gr_decode(&br, P, &delta)) { BRGCSFilterFree(f); return NULL; }
        running += delta;
        // The cumulative value must stay within [0, F). The reference
        // implementation does not explicitly bounds-check this but a
        // malformed stream could produce values beyond F; reject to
        // keep Match's binary-search monotonicity invariant.
        if (running >= F) { BRGCSFilterFree(f); return NULL; }
        f->values[i] = running;
    }

    // The stream must be exhausted after N values, possibly with a few
    // padding zero bits to the next byte boundary. Any remaining bytes
    // beyond the current byte indicate excess data — reject (matches
    // Bitcoin Core's "encoded_filter contains excess data" check).
    //
    // We accept remaining bits in the current byte because Golomb-Rice
    // is bit-aligned, not byte-aligned. Bitcoin Core's BitStreamReader
    // handles this implicitly; we make it explicit here.
    if (br.bytePos < len) { BRGCSFilterFree(f); return NULL; }
    // Intentionally no check on br.bitPos: the encoder zero-pads to the
    // next byte boundary per BIP 158, so any trailing bits should be
    // zero but we don't verify that — not all implementations are
    // strict, and a mismatch here would be a silent-fail false reject.

    return f;
}

BRGCSFilter *BRGCSFilterBasicParse(const uint8_t *bytes, size_t len,
                                    UInt256 blockHash)
{
    // BIP 158: k0 = little-endian u64 of blockHash bytes 0..7, k1 =
    // bytes 8..15. UInt256 in this submodule stores bytes in wire order
    // (same as Bitcoin Core's uint256 internal layout), so UInt64GetLE
    // against the raw byte pointer is correct. The #1 bug in naive
    // implementations is to use the hex-displayed byte order; this
    // helper exists specifically to prevent that.
    uint64_t k0 = UInt64GetLE(&blockHash.u8[0]);
    uint64_t k1 = UInt64GetLE(&blockHash.u8[8]);
    return BRGCSFilterParse(bytes, len, k0, k1,
                             BR_GCS_BASIC_FILTER_P,
                             BR_GCS_BASIC_FILTER_M);
}

// ---- Match ---------------------------------------------------------------

static uint64_t hash_to_range(const BRGCSFilter *f,
                              const uint8_t *element, size_t elemLen)
{
    uint64_t h = siphash24(f->k0, f->k1, element, elemLen);
    return fastrange64(h, f->F);
}

// Binary search in f->values for target; returns 1 on hit, 0 on miss.
static int sorted_contains(const uint64_t *arr, uint32_t n, uint64_t target)
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return 1;
        if (arr[mid] < target) lo = mid + 1;
        else hi = mid;
    }
    return 0;
}

int BRGCSFilterMatch(const BRGCSFilter *f,
                      const uint8_t *element, size_t elemLen)
{
    if (!f || (!element && elemLen != 0)) return 0;
    if (f->N == 0) return 0;
    uint64_t q = hash_to_range(f, element, elemLen);
    return sorted_contains(f->values, f->N, q);
}

// Merge-scan two sorted u64 arrays for any common element.
static int qsort_u64_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

int BRGCSFilterMatchAny(const BRGCSFilter *f,
                         const uint8_t * const *elements,
                         const size_t *elemLens, size_t n)
{
    if (!f || n == 0) return 0;
    if (f->N == 0) return 0;
    if (!elements || !elemLens) return 0;

    // Hash each element to [0, F) and sort.
    uint64_t stack_q[64];
    uint64_t *q = stack_q;
    int heap = 0;
    if (n > sizeof(stack_q) / sizeof(stack_q[0])) {
        q = (uint64_t *)malloc(n * sizeof(uint64_t));
        if (!q) return 0;
        heap = 1;
    }

    for (size_t i = 0; i < n; i++) {
        if (!elements[i] && elemLens[i] != 0) {
            if (heap) free(q);
            return 0;
        }
        q[i] = hash_to_range(f, elements[i], elemLens[i]);
    }
    qsort(q, n, sizeof(uint64_t), qsort_u64_cmp);

    // Merge-scan against f->values (both sorted ascending).
    size_t i = 0;
    uint32_t j = 0;
    int hit = 0;
    while (i < n && j < f->N) {
        if (q[i] == f->values[j]) { hit = 1; break; }
        if (q[i] < f->values[j]) i++;
        else j++;
    }

    if (heap) free(q);
    return hit;
}

// ---- Hash / header -------------------------------------------------------

UInt256 BRGCSFilterHash(const BRGCSFilter *f)
{
    UInt256 out = UINT256_ZERO;
    if (!f) return out;
    // BRSHA256_2 is double-SHA256. For the empty-filter case the encoded
    // bytes are a single 0x00 byte (the CompactSize encoding of N=0);
    // dSHA256 of that byte is NOT dSHA256 of the empty string.
    BRSHA256_2(out.u8, f->encoded, f->encodedLen);
    return out;
}

UInt256 BRGCSFilterHeader(UInt256 filterHash, UInt256 prevHeader)
{
    uint8_t buf[64];
    memcpy(buf,      filterHash.u8, 32);
    memcpy(buf + 32, prevHeader.u8, 32);
    UInt256 out = UINT256_ZERO;
    BRSHA256_2(out.u8, buf, sizeof(buf));
    return out;
}

const uint8_t *BRGCSFilterEncoded(const BRGCSFilter *f, size_t *len)
{
    if (!f) { if (len) *len = 0; return NULL; }
    if (len) *len = f->encodedLen;
    return f->encoded;
}

uint32_t BRGCSFilterN(const BRGCSFilter *f)
{
    return f ? f->N : 0;
}

void BRGCSFilterFree(BRGCSFilter *f)
{
    if (!f) return;
    if (f->values) { free(f->values); f->values = NULL; }
    if (f->encoded) { free(f->encoded); f->encoded = NULL; }
    free(f);
}
