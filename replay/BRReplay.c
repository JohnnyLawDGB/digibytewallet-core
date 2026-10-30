//
//  BRReplay.c
//
//  See BRReplay.h and docs/replay-harness.md.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
//  associated documentation files (the "Software"), to deal in the Software without restriction,
//  including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
//  subject to the following conditions: The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
//

#include "BRReplay.h"
#include "BRPeer.h"
#include "BRMerkleBlock.h"
#include "BRTransaction.h"
#include "BRCrypto.h"
#include "BRGCSFilter.h"
#include "BRChainParams.h"
#include "BRSavedBlocks.h"
#include "BRCFRestorePreflight.h"
#include "BRWalletOpen.h"
#include "BRBIP39Mnemonic.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REC_HEADER_LEN   (1 + 1 + 8 + 12 + 4)   // dir, peer, time, command, length
#define FRAME_LEN        24
#define MAX_FRAME_BODY   (32u*1024u*1024u)
#define SERVE_HEADERS    2000u                  // headers per answer, as a DigiByte node
#define SERVE_CFHEADERS  2000u                  // BIP 157 limits
#define SERVE_CFILTERS   1000u
#define INV_TX           1u
#define INV_BLOCK        2u
#define INV_WITNESS_FLAG 0x40000000u
#define BR_REPLAY_STALL_SECS 15.0                // see BRReplayRun

static double _now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec/1e9;
}

static void _hexOf(UInt256 internal, char out[65])
{
    static const char digits[] = "0123456789abcdef";
    UInt256 h = UInt256Reverse(internal);   // display (RPC) order

    for (size_t i = 0; i < 32; i++) {
        out[2*i] = digits[h.u8[i] >> 4];
        out[2*i + 1] = digits[h.u8[i] & 0x0f];
    }
    out[64] = '\0';
}

static size_t _varIntGet(const uint8_t *b, size_t len, size_t *off, uint64_t *v)
{
    size_t n = 0;

    *v = BRVarInt(&b[*off], (*off <= len ? len - *off : 0), &n);
    if (n == 0 || *off + n > len) return 0;
    *off += n;
    return n;
}

// ---- recording ----------------------------------------------------------------------------------------

struct BRReplayRecordingStruct {
    uint8_t *buf;
    size_t len;
    BRReplayRecord *records;
    size_t count;
};

BRReplayRecording *BRReplayRecordingParse(const uint8_t *buf, size_t len)
{
    BRReplayRecording *r;
    size_t off = 8, cap = 64;

    if (! buf || len < 8 || memcmp(buf, BR_REPLAY_MAGIC, 8) != 0) return NULL;
    r = calloc(1, sizeof(*r));
    if (! r) return NULL;
    r->buf = malloc(len);
    r->records = malloc(cap*sizeof(*r->records));
    if (! r->buf || ! r->records) { BRReplayRecordingFree(r); return NULL; }
    memcpy(r->buf, buf, len);
    r->len = len;

    while (off < len) {
        BRReplayRecord rec;

        if (len - off < REC_HEADER_LEN) { BRReplayRecordingFree(r); return NULL; }
        rec.dir = (char)r->buf[off];
        rec.peer = r->buf[off + 1];
        rec.timeUs = UInt64GetLE(&r->buf[off + 2]);
        memcpy(rec.type, &r->buf[off + 10], 12);
        rec.type[12] = '\0';
        rec.len = UInt32GetLE(&r->buf[off + 22]);
        off += REC_HEADER_LEN;
        if (rec.len > len - off ||
            (rec.dir != BR_REPLAY_DIR_IN && rec.dir != BR_REPLAY_DIR_OUT && rec.dir != BR_REPLAY_DIR_META)) {
            BRReplayRecordingFree(r);
            return NULL;
        }
        rec.payload = &r->buf[off];
        off += rec.len;
        if (r->count == cap) {
            BRReplayRecord *bigger = realloc(r->records, (cap *= 2)*sizeof(*r->records));

            if (! bigger) { BRReplayRecordingFree(r); return NULL; }
            r->records = bigger;
        }
        r->records[r->count++] = rec;
    }
    return r;
}

BRReplayRecording *BRReplayRecordingRead(const char *path)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    long len;
    BRReplayRecording *r = NULL;

    if (! f) return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (len = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (buf = malloc((size_t)len)) && fread(buf, 1, (size_t)len, f) == (size_t)len) {
        r = BRReplayRecordingParse(buf, (size_t)len);
    }
    free(buf);
    fclose(f);
    return r;
}

void BRReplayRecordingFree(BRReplayRecording *r)
{
    if (! r) return;
    free(r->records);
    free(r->buf);
    free(r);
}

size_t BRReplayRecordingCount(const BRReplayRecording *r) { return r ? r->count : 0; }

const BRReplayRecord *BRReplayRecordingAt(const BRReplayRecording *r, size_t i)
{
    return (r && i < r->count) ? &r->records[i] : NULL;
}

// The value is copied out of the record into a thread-local buffer (at most 255 bytes, the rest cut):
// the returned pointer stays valid until this thread's next call, and is never the recording's own memory.
const char *BRReplayRecordingSession(const BRReplayRecording *r, const char *key)
{
    static __thread char value[256];
    size_t keyLen = key ? strlen(key) : 0;

    for (size_t i = 0; r && keyLen && i < r->count; i++) {
        const BRReplayRecord *rec = &r->records[i];
        size_t off = 0;

        if (rec->dir != BR_REPLAY_DIR_META || strcmp(rec->type, "session") != 0) continue;
        while (off < rec->len) {
            size_t end = off;

            while (end < rec->len && rec->payload[end] != '\n') end++;
            if (end - off > keyLen && memcmp(&rec->payload[off], key, keyLen) == 0 && rec->payload[off + keyLen] == '=') {
                size_t vlen = end - off - keyLen - 1;

                if (vlen >= sizeof(value)) vlen = sizeof(value) - 1;
                memcpy(value, &rec->payload[off + keyLen + 1], vlen);
                value[vlen] = '\0';
                return value;
            }
            off = end + 1;
        }
    }
    return NULL;
}

uint32_t BRReplayRecordingSessionU32(const BRReplayRecording *r, const char *key, uint32_t def)
{
    const char *v = BRReplayRecordingSession(r, key);
    char *end = NULL;
    unsigned long x;

    if (! v || ! *v) return def;
    x = strtoul(v, &end, 10);
    return (end && *end == '\0' && x <= UINT32_MAX) ? (uint32_t)x : def;
}

// Compiled only with BR_PEER_MESSAGE_TAP (BRPeer.h): the recorder needs the core's tap, which a release
// core does not have.
#ifdef BR_PEER_MESSAGE_TAP
// ---- recorder -----------------------------------------------------------------------------------------

#define RECORDER_PEERS_MAX 64

struct BRReplayRecorderStruct {
    FILE *f;
    pthread_mutex_t lock;
    double start;
    size_t messages;
    size_t peerCount;
    UInt128 peerAddr[RECORDER_PEERS_MAX];
    uint16_t peerPort[RECORDER_PEERS_MAX];
    BRPeerMessageTap tap;    // {_recorderTap, this}: installed while recording
};

static void _recorderWrite(BRReplayRecorder *rec, char dir, uint8_t peer, const char *type,
                           const uint8_t *payload, size_t len)
{
    uint8_t h[REC_HEADER_LEN];

    memset(h, 0, sizeof(h));
    h[0] = (uint8_t)dir;
    h[1] = peer;
    UInt64SetLE(&h[2], (uint64_t)((_now() - rec->start)*1e6));
    strncpy((char *)&h[10], type, 12);
    UInt32SetLE(&h[22], (uint32_t)len);
    fwrite(h, 1, sizeof(h), rec->f);
    if (len) fwrite(payload, 1, len, rec->f);
}

static void _recorderTap(void *info, const BRPeer *peer, int outbound, const char *type,
                         const uint8_t *payload, size_t len)
{
    BRReplayRecorder *rec = info;
    size_t i;

    pthread_mutex_lock(&rec->lock);
    for (i = 0; i < rec->peerCount; i++) {
        if (UInt128Eq(rec->peerAddr[i], peer->address) && rec->peerPort[i] == peer->port) break;
    }
    if (i == rec->peerCount && i < RECORDER_PEERS_MAX) {
        uint8_t meta[18];

        rec->peerAddr[i] = peer->address;
        rec->peerPort[i] = peer->port;
        rec->peerCount++;
        memcpy(meta, peer->address.u8, 16);
        UInt16SetBE(&meta[16], peer->port);
        _recorderWrite(rec, BR_REPLAY_DIR_META, (uint8_t)i, "peer", meta, sizeof(meta));
    }
    if (i < RECORDER_PEERS_MAX) {
        _recorderWrite(rec, outbound ? BR_REPLAY_DIR_OUT : BR_REPLAY_DIR_IN, (uint8_t)i, type, payload, len);
        rec->messages++;
    }
    pthread_mutex_unlock(&rec->lock);
}

BRReplayRecorder *BRReplayRecorderStart(const char *path)
{
    BRReplayRecorder *rec = calloc(1, sizeof(*rec));

    if (! rec) return NULL;
    rec->f = fopen(path, "wb");
    if (! rec->f) { free(rec); return NULL; }
    pthread_mutex_init(&rec->lock, NULL);
    rec->start = _now();
    fwrite(BR_REPLAY_MAGIC, 1, 8, rec->f);
    rec->tap.fn = _recorderTap;
    rec->tap.info = rec;
    BRPeerSetMessageTap(&rec->tap);
    return rec;
}

void BRReplayRecorderAddMeta(BRReplayRecorder *rec, const char *type, const uint8_t *payload, size_t len)
{
    pthread_mutex_lock(&rec->lock);
    _recorderWrite(rec, BR_REPLAY_DIR_META, 0, type, payload, len);
    pthread_mutex_unlock(&rec->lock);
}

size_t BRReplayRecorderStop(BRReplayRecorder *rec)
{
    size_t n;

    BRPeerSetMessageTap(NULL);
    pthread_mutex_lock(&rec->lock);
    n = rec->messages;
    fclose(rec->f);
    pthread_mutex_unlock(&rec->lock);
    pthread_mutex_destroy(&rec->lock);
    free(rec);
    return n;
}
#endif // BR_PEER_MESSAGE_TAP

// ---- server -------------------------------------------------------------------------------------------

#define SERVER_CLIENTS_MAX 8
#define SERVER_MISSING_MAX 256

typedef struct {
    int fd;
    uint8_t *buf;
    size_t len, cap;
} _Client;

struct BRReplayServerStruct {
    const BRReplayRecording *rec;
    uint32_t magic;
    const BRReplayRecord *version;

    // the header chain: heights from .. from+headerCount-1
    uint32_t from;
    size_t headerCount;
    UInt256 *headerHash;
    const uint8_t **header;          // 80 bytes each, inside the recording

    // filter data for heights cfFrom .. cfFrom+cfCount-1
    uint32_t cfFrom;
    size_t cfCount;
    UInt256 cfPrev;                  // the filter header at cfFrom - 1
    UInt256 *cfHash, *cfHeader;
    const BRReplayRecord **cfilter;  // by height offset, NULL where the recording has none

    const BRReplayRecord **blocks;
    UInt256 *blockHash;
    size_t blockCount;

    int listenFd;
    uint16_t port;
    volatile int stop;
    pthread_t thread;
    pthread_mutex_t lock;            // stats and missing
    BRReplayServerStats stats;
    UInt256 missing[SERVER_MISSING_MAX];
    size_t missingCount;
    _Client clients[SERVER_CLIENTS_MAX];
};

static long _heightOf(const BRReplayServer *s, UInt256 hash)
{
    for (size_t i = s->headerCount; i > 0; i--) {
        if (UInt256Eq(s->headerHash[i - 1], hash)) return (long)(s->from + i - 1);
    }
    return -1;
}

static int _indexRecording(BRReplayServer *s)
{
    const BRReplayRecording *r = s->rec;
    size_t headerCap = 0, cfCap = 0;

    s->from = BRReplayRecordingSessionU32(r, "headers_from", 0);
    if (s->from == 0) return 0;

    // version and headers first: cfheaders and cfilters are placed by height
    for (size_t i = 0; i < r->count; i++) {
        const BRReplayRecord *rec = &r->records[i];
        uint64_t n;
        size_t off = 0;

        // the saved window a session resumed from (meta "savedheaders", written by BRReplayRun's recorder),
        // then the peer's headers messages, in record order
        if (rec->dir == BR_REPLAY_DIR_META && strcmp(rec->type, "savedheaders") == 0) { }
        else if (rec->dir != BR_REPLAY_DIR_IN) continue;
        else if (! s->version && strcmp(rec->type, "version") == 0) { s->version = rec; continue; }
        else if (strcmp(rec->type, "headers") != 0) continue;
        if (! _varIntGet(rec->payload, rec->len, &off, &n)) return 0;
        for (uint64_t k = 0; k < n; k++) {
            uint64_t txn;
            UInt256 hash;

            if (rec->len - off < 80) return 0;
            BRSHA256_2(&hash, &rec->payload[off], 80);
            if (s->headerCount > 0 &&
                ! UInt256Eq(UInt256Get(&rec->payload[off + 4]), s->headerHash[s->headerCount - 1])) {
                off += 80;
                if (! _varIntGet(rec->payload, rec->len, &off, &txn)) return 0;
                continue;   // not on the chain being served (a repeat or a fork); skip it
            }
            if (s->headerCount == headerCap) {
                headerCap = headerCap ? headerCap*2 : 1024;
                s->headerHash = realloc(s->headerHash, headerCap*sizeof(*s->headerHash));
                s->header = realloc(s->header, headerCap*sizeof(*s->header));
                if (! s->headerHash || ! s->header) return 0;
            }
            s->headerHash[s->headerCount] = hash;
            s->header[s->headerCount++] = &rec->payload[off];
            off += 80;
            if (! _varIntGet(rec->payload, rec->len, &off, &txn)) return 0;
        }
    }
    if (! s->version || s->headerCount == 0) return 0;

    s->cfCount = 0;
    for (size_t i = 0; i < r->count; i++) {
        const BRReplayRecord *rec = &r->records[i];

        if (rec->dir != BR_REPLAY_DIR_IN) continue;
        if (strcmp(rec->type, "cfheaders") == 0 && rec->len >= 1 + 32 + 32 && rec->payload[0] == 0) {
            UInt256 stop = UInt256Get(&rec->payload[1]), prev = UInt256Get(&rec->payload[33]);
            size_t off = 65;
            uint64_t n;
            long hs = _heightOf(s, stop);

            if (! _varIntGet(rec->payload, rec->len, &off, &n) || n == 0 || hs < 0 || (uint64_t)hs + 1 < n ||
                (rec->len - off) / 32 < n) continue;
            uint32_t start = (uint32_t)(hs - (long)n + 1);
            if (s->cfCount == 0) {
                s->cfFrom = start;
                s->cfPrev = prev;
            }
            else if (start != s->cfFrom + s->cfCount ||
                     ! UInt256Eq(prev, s->cfHeader[s->cfCount - 1])) continue;   // only a contiguous run
            if (s->cfCount + n > cfCap) {
                cfCap = s->cfCount + n;
                s->cfHash = realloc(s->cfHash, cfCap*sizeof(*s->cfHash));
                s->cfHeader = realloc(s->cfHeader, cfCap*sizeof(*s->cfHeader));
                if (! s->cfHash || ! s->cfHeader) return 0;
            }
            for (uint64_t k = 0; k < n; k++, off += 32) {
                UInt256 fh = UInt256Get(&rec->payload[off]);
                UInt256 before = s->cfCount ? s->cfHeader[s->cfCount - 1] : s->cfPrev;

                s->cfHash[s->cfCount] = fh;
                s->cfHeader[s->cfCount++] = BRGCSFilterHeader(fh, before);
            }
        }
    }
    if (s->cfCount) {
        s->cfilter = calloc(s->cfCount, sizeof(*s->cfilter));
        if (! s->cfilter) return 0;
    }

    for (size_t i = 0; i < r->count; i++) {
        const BRReplayRecord *rec = &r->records[i];

        if (rec->dir != BR_REPLAY_DIR_IN) continue;
        if (strcmp(rec->type, "cfilter") == 0 && rec->len >= 33 && rec->payload[0] == 0) {
            long h = _heightOf(s, UInt256Get(&rec->payload[1]));

            if (h >= (long)s->cfFrom && (size_t)(h - s->cfFrom) < s->cfCount) s->cfilter[h - s->cfFrom] = rec;
        }
        else if (strcmp(rec->type, "block") == 0 && rec->len >= 80) {
            s->blocks = realloc(s->blocks, (s->blockCount + 1)*sizeof(*s->blocks));
            s->blockHash = realloc(s->blockHash, (s->blockCount + 1)*sizeof(*s->blockHash));
            if (! s->blocks || ! s->blockHash) return 0;
            BRSHA256_2(&s->blockHash[s->blockCount], rec->payload, 80);
            s->blocks[s->blockCount++] = rec;
        }
    }
    return 1;
}

static int _writeAll(int fd, const uint8_t *b, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, b, len, 0);

        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        b += n;
        len -= (size_t)n;
    }
    return 1;
}

static void _send(BRReplayServer *s, int fd, const char *type, const uint8_t *payload, size_t len)
{
    uint8_t h[FRAME_LEN];
    UInt256 hash;

    memset(h, 0, sizeof(h));
    UInt32SetLE(&h[0], s->magic);
    strncpy((char *)&h[4], type, 12);
    UInt32SetLE(&h[16], (uint32_t)len);
    BRSHA256_2(&hash, payload, len);
    memcpy(&h[20], hash.u8, 4);
    if (_writeAll(fd, h, sizeof(h)) && (len == 0 || _writeAll(fd, payload, len))) {
        pthread_mutex_lock(&s->lock);
        s->stats.served++;
        pthread_mutex_unlock(&s->lock);
    }
}

static void _count(BRReplayServer *s, size_t *field)
{
    pthread_mutex_lock(&s->lock);
    (*field)++;
    pthread_mutex_unlock(&s->lock);
}

// The recorded version, its start height set to the served tip and its time to now: the recording's own
// peer was at a later tip, and a peer's clock is read against ours.
static void _sendVersion(BRReplayServer *s, int fd)
{
    const BRReplayRecord *v = s->version;
    uint8_t *p = malloc(v->len);
    size_t off = 80;
    uint64_t uaLen;

    if (! p) return;
    memcpy(p, v->payload, v->len);
    if (v->len > 80 && _varIntGet(p, v->len, &off, &uaLen) && uaLen <= v->len - off && v->len - off - uaLen >= 4) {
        UInt64SetLE(&p[12], (uint64_t)time(NULL));
        UInt32SetLE(&p[off + uaLen], s->from + (uint32_t)s->headerCount - 1);
    }
    _send(s, fd, "version", p, v->len);
    free(p);
    _send(s, fd, "verack", NULL, 0);
}

static void _serveGetheaders(BRReplayServer *s, int fd, const uint8_t *p, size_t len)
{
    size_t off = 4, first = SIZE_MAX, stopAt = s->headerCount - 1, count, at = 0;
    uint64_t n;
    uint8_t *out;

    // n locators and the stop hash; n is the peer's (here the wallet's) number, so no n + 1 that could wrap
    if (len < 4 || ! _varIntGet(p, len, &off, &n) || (len - off) / 32 == 0 || n > (len - off) / 32 - 1) {
        _count(s, &s->stats.unserved);
        return;
    }
    for (uint64_t k = 0; k < n && first == SIZE_MAX; k++) {
        long h = _heightOf(s, UInt256Get(&p[off + 32*k]));

        if (h >= 0) first = (size_t)(h - s->from) + 1;
    }
    {
        long hs = _heightOf(s, UInt256Get(&p[off + 32*n]));

        if (hs >= 0) stopAt = (size_t)(hs - s->from);
    }
    if (first == SIZE_MAX) first = s->headerCount;   // no locator on the chain: nothing to give
    count = (first <= stopAt) ? stopAt - first + 1 : 0;
    if (count > SERVE_HEADERS) count = SERVE_HEADERS;
    out = malloc(9 + count*81);
    if (! out) return;
    at = BRVarIntSet(out, 9, count);
    for (size_t k = 0; k < count; k++) {
        memcpy(&out[at], s->header[first + k], 80);
        out[at + 80] = 0;
        at += 81;
    }
    _send(s, fd, "headers", out, at);
    free(out);
}

static void _serveGetcfheaders(BRReplayServer *s, int fd, const uint8_t *p, size_t len)
{
    uint32_t start;
    long hs;
    uint8_t *out;
    size_t n, at;

    if (len < 37 || p[0] != 0) { _count(s, &s->stats.unserved); return; }
    start = UInt32GetLE(&p[1]);
    hs = _heightOf(s, UInt256Get(&p[5]));
    if (hs < 0 || start > (uint32_t)hs || start < s->cfFrom || (size_t)(hs - s->cfFrom) >= s->cfCount ||
        (uint32_t)hs - start + 1 > SERVE_CFHEADERS) {
        _count(s, &s->stats.unserved);
        return;
    }
    n = (uint32_t)hs - start + 1;
    out = malloc(1 + 64 + 9 + 32*n);
    if (! out) return;
    out[0] = 0;
    memcpy(&out[1], &p[5], 32);
    UInt256Set(&out[33], start == s->cfFrom ? s->cfPrev : s->cfHeader[start - s->cfFrom - 1]);
    at = 65 + BRVarIntSet(&out[65], 9, n);
    for (size_t k = 0; k < n; k++, at += 32) UInt256Set(&out[at], s->cfHash[start - s->cfFrom + k]);
    _send(s, fd, "cfheaders", out, at);
    free(out);
}

static void _serveGetcfilters(BRReplayServer *s, int fd, const uint8_t *p, size_t len)
{
    uint32_t start;
    long hs;
    int gap = 0;

    if (len < 37 || p[0] != 0) { _count(s, &s->stats.unserved); return; }
    start = UInt32GetLE(&p[1]);
    hs = _heightOf(s, UInt256Get(&p[5]));
    if (hs < 0 || start > (uint32_t)hs || (uint32_t)hs - start + 1 > SERVE_CFILTERS) { _count(s, &s->stats.unserved); return; }
    for (uint32_t h = start; h <= (uint32_t)hs; h++) {
        const BRReplayRecord *f = (h >= s->cfFrom && h - s->cfFrom < s->cfCount) ? s->cfilter[h - s->cfFrom] : NULL;

        if (f) _send(s, fd, "cfilter", f->payload, f->len);
        else gap = 1;
    }
    if (gap) _count(s, &s->stats.unserved);
}

static void _serveGetdata(BRReplayServer *s, int fd, const uint8_t *p, size_t len)
{
    size_t off = 0, nf = 0;
    uint64_t n;
    uint8_t *notfound;

    if (! _varIntGet(p, len, &off, &n) || (len - off) / 36 < n) { _count(s, &s->stats.unserved); return; }
    notfound = malloc(9 + 36*n);
    if (! notfound) return;
    for (uint64_t k = 0; k < n; k++) {
        const uint8_t *item = &p[off + 36*k];
        uint32_t type = UInt32GetLE(item) & ~INV_WITNESS_FLAG;
        UInt256 hash = UInt256Get(&item[4]);
        const BRReplayRecord *found = NULL;

        if (type == INV_BLOCK) {
#ifdef REPLAY_RED_NO_BLOCKS
            // RED ARM SEAM (replay_snapshot_kat): the server holds no blocks, as a peer that withholds the
            // blocks a wallet's filters matched; the payments in them never reach the wallet.
            for (size_t b = 0; b < 0 && ! found; b++) {
#else
            for (size_t b = 0; b < s->blockCount && ! found; b++) {
#endif
                if (UInt256Eq(s->blockHash[b], hash)) found = s->blocks[b];
            }
            if (! found) {
                pthread_mutex_lock(&s->lock);
                s->stats.missingBlocks++;
                int seen = 0;
                for (size_t m = 0; m < s->missingCount; m++) if (UInt256Eq(s->missing[m], hash)) seen = 1;
                if (! seen && s->missingCount < SERVER_MISSING_MAX) s->missing[s->missingCount++] = hash;
                pthread_mutex_unlock(&s->lock);
            }
        }
        if (found) _send(s, fd, "block", found->payload, found->len);
        else memcpy(&notfound[9 + 36*nf++], item, 36);
    }
    if (nf > 0) {
        size_t vl = BRVarIntSize(nf);

        memmove(&notfound[vl], &notfound[9], 36*nf);
        BRVarIntSet(notfound, vl, nf);
        _send(s, fd, "notfound", notfound, vl + 36*nf);
    }
    free(notfound);
}

static void _serveMessage(BRReplayServer *s, int fd, const char *type, const uint8_t *p, size_t len)
{
    _count(s, &s->stats.requests);
    if (strcmp(type, "version") == 0) _sendVersion(s, fd);
    else if (strcmp(type, "ping") == 0) _send(s, fd, "pong", p, len);
    else if (strcmp(type, "getheaders") == 0) _serveGetheaders(s, fd, p, len);
    else if (strcmp(type, "getcfheaders") == 0) _serveGetcfheaders(s, fd, p, len);
    else if (strcmp(type, "getcfilters") == 0) _serveGetcfilters(s, fd, p, len);
    else if (strcmp(type, "getdata") == 0) _serveGetdata(s, fd, p, len);
    else if (strcmp(type, "tx") == 0 || strcmp(type, "inv") == 0 || strcmp(type, MSG_DANDELION_TX) == 0) {
        _count(s, &s->stats.relayAttempts);
    }
    else if (strcmp(type, "getcfcheckpt") == 0 || strcmp(type, "getblocks") == 0) _count(s, &s->stats.unserved);
    // verack, mempool, getaddr, sendheaders, feefilter, ...: a real peer may answer these; the recording
    // holds nothing the wallet's state depends on for them, so nothing is sent.
}

static void _closeClient(_Client *c)
{
    if (c->fd >= 0) close(c->fd);
    free(c->buf);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

// Reads what has arrived; serves every complete frame. 0 when the client is gone.
static int _readClient(BRReplayServer *s, _Client *c)
{
    uint8_t chunk[65536];
    ssize_t n = recv(c->fd, chunk, sizeof(chunk), 0);

    if (n < 0 && (errno == EINTR || errno == EAGAIN)) return 1;
    if (n <= 0) return 0;
    if (c->len + (size_t)n > c->cap) {
        size_t cap = (c->len + (size_t)n)*2;
        uint8_t *bigger = realloc(c->buf, cap);

        if (! bigger) return 0;
        c->buf = bigger;
        c->cap = cap;
    }
    memcpy(&c->buf[c->len], chunk, (size_t)n);
    c->len += (size_t)n;

    while (c->len >= FRAME_LEN) {
        uint32_t bodyLen = UInt32GetLE(&c->buf[16]);
        char type[13];

        if (UInt32GetLE(c->buf) != s->magic || bodyLen > MAX_FRAME_BODY) return 0;
        if (c->len < FRAME_LEN + bodyLen) break;
        memcpy(type, &c->buf[4], 12);
        type[12] = '\0';
        _serveMessage(s, c->fd, type, &c->buf[FRAME_LEN], bodyLen);
        memmove(c->buf, &c->buf[FRAME_LEN + bodyLen], c->len - FRAME_LEN - bodyLen);
        c->len -= FRAME_LEN + bodyLen;
    }
    return 1;
}

static void *_serverThread(void *arg)
{
    BRReplayServer *s = arg;

    while (! s->stop) {
        struct pollfd fds[1 + SERVER_CLIENTS_MAX];
        int map[1 + SERVER_CLIENTS_MAX];
        nfds_t nfds = 0;

        fds[nfds].fd = s->listenFd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; map[nfds++] = -1;
        for (int i = 0; i < SERVER_CLIENTS_MAX; i++) {
            if (s->clients[i].fd < 0) continue;
            fds[nfds].fd = s->clients[i].fd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; map[nfds++] = i;
        }
        if (poll(fds, nfds, 100) <= 0) continue;
        for (nfds_t k = 0; k < nfds; k++) {
            if (! fds[k].revents) continue;
            if (map[k] < 0) {
                int fd = accept(s->listenFd, NULL, NULL);
                int slot = -1;

                if (fd < 0) continue;
                for (int i = 0; i < SERVER_CLIENTS_MAX && slot < 0; i++) if (s->clients[i].fd < 0) slot = i;
                if (slot < 0) { close(fd); continue; }
#ifdef SO_NOSIGPIPE
                { int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)); }
#endif
                s->clients[slot].fd = fd;
                _count(s, &s->stats.connections);
            }
            else if (! _readClient(s, &s->clients[map[k]])) _closeClient(&s->clients[map[k]]);
        }
    }
    return NULL;
}

static void _serverFree(BRReplayServer *s)
{
    for (int i = 0; i < SERVER_CLIENTS_MAX; i++) if (s->clients[i].fd >= 0) _closeClient(&s->clients[i]);
    if (s->listenFd >= 0) close(s->listenFd);
    free(s->headerHash); free(s->header);
    free(s->cfHash); free(s->cfHeader); free(s->cfilter);
    free(s->blocks); free(s->blockHash);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

BRReplayServer *BRReplayServerStart(const BRReplayRecording *recording, uint16_t *port)
{
    BRReplayServer *s = calloc(1, sizeof(*s));
    struct sockaddr_in sa;
    socklen_t saLen = sizeof(sa);

    if (! s) return NULL;
    pthread_mutex_init(&s->lock, NULL);
    s->listenFd = -1;
    for (int i = 0; i < SERVER_CLIENTS_MAX; i++) s->clients[i].fd = -1;
    s->rec = recording;
    s->magic = BRMainNetParams.magicNumber;
    if (! recording || ! _indexRecording(s)) { _serverFree(s); return NULL; }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    s->listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listenFd < 0 || bind(s->listenFd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(s->listenFd, 8) != 0 || getsockname(s->listenFd, (struct sockaddr *)&sa, &saLen) != 0) {
        _serverFree(s);
        return NULL;
    }
    s->port = ntohs(sa.sin_port);
    if (pthread_create(&s->thread, NULL, _serverThread, s) != 0) { _serverFree(s); return NULL; }
    if (port) *port = s->port;
    return s;
}

BRReplayServerStats BRReplayServerGetStats(BRReplayServer *s)
{
    BRReplayServerStats st;

    pthread_mutex_lock(&s->lock);
    st = s->stats;
    pthread_mutex_unlock(&s->lock);
    return st;
}

size_t BRReplayServerMissingBlocks(BRReplayServer *s, UInt256 hashes[], size_t max)
{
    size_t n;

    pthread_mutex_lock(&s->lock);
    n = s->missingCount < max ? s->missingCount : max;
    if (hashes) memcpy(hashes, s->missing, n*sizeof(*hashes));
    pthread_mutex_unlock(&s->lock);
    return n;
}

uint32_t BRReplayServerTip(BRReplayServer *s, UInt256 *hash)
{
    if (hash) *hash = s->headerHash[s->headerCount - 1];
    return s->from + (uint32_t)s->headerCount - 1;
}

void BRReplayServerStop(BRReplayServer *s)
{
    if (! s) return;
    s->stop = 1;
    pthread_join(s->thread, NULL);
    _serverFree(s);
}

// ---- snapshot -----------------------------------------------------------------------------------------

typedef struct { char *buf; size_t cap, len; } _Out;

static void _put(_Out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void _put(_Out *o, const char *fmt, ...)
{
    va_list ap;
    char tmp[512];
    int n;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (o->len + (size_t)n < o->cap) memcpy(&o->buf[o->len], tmp, (size_t)n + 1);
    else if (o->len < o->cap && o->cap > 0) o->buf[o->len] = '\0';
    o->len += (size_t)n;
}

static int _txCompare(const void *a, const void *b)
{
    const BRTransaction *x = *(BRTransaction * const *)a, *y = *(BRTransaction * const *)b;

    if (x->blockHeight != y->blockHeight) return x->blockHeight < y->blockHeight ? -1 : 1;
    return memcmp(UInt256Reverse(x->txHash).u8, UInt256Reverse(y->txHash).u8, 32);
}

static int _utxoCompare(const void *a, const void *b)
{
    const BRUTXO *x = a, *y = b;
    int c = memcmp(UInt256Reverse(x->hash).u8, UInt256Reverse(y->hash).u8, 32);

    if (c) return c;
    return x->n < y->n ? -1 : (x->n > y->n);
}

size_t BRReplaySnapshot(BRWallet *wallet, BRPeerManager *manager, char *buf, size_t bufLen)
{
    _Out o = { buf, bufLen, 0 };
    UInt256 tipHash = UINT256_ZERO;
    uint32_t tip = manager ? BRPeerManagerLastBlockInfo(manager, &tipHash) : 0;
    char hex[65];
    size_t n;

    if (buf && bufLen) buf[0] = '\0';
    _put(&o, "replay-snapshot 1\n");
    _hexOf(tipHash, hex);
    _put(&o, "tip %u %s\n", tip, hex);
    _put(&o, "balance %llu\n", (unsigned long long)BRWalletBalance(wallet));

    n = BRWalletTransactions(wallet, NULL, 0);
    if (n) {
        BRTransaction **txs = calloc(n, sizeof(*txs));

        if (txs) {
            n = BRWalletTransactions(wallet, txs, n);
            qsort(txs, n, sizeof(*txs), _txCompare);
            for (size_t i = 0; i < n; i++) {
                uint64_t fee = BRWalletFeeForTx(wallet, txs[i]);
                char height[16], feeText[24];

                _hexOf(txs[i]->txHash, hex);
                if (txs[i]->blockHeight == TX_UNCONFIRMED) snprintf(height, sizeof(height), "unconfirmed");
                else snprintf(height, sizeof(height), "%u", txs[i]->blockHeight);
                if (fee == UINT64_MAX) snprintf(feeText, sizeof(feeText), "unknown");
                else snprintf(feeText, sizeof(feeText), "%llu", (unsigned long long)fee);
                _put(&o, "tx %s %s received %llu sent %llu fee %s\n", hex, height,
                     (unsigned long long)BRWalletAmountReceivedFromTx(wallet, txs[i]),
                     (unsigned long long)BRWalletAmountSentByTx(wallet, txs[i]), feeText);
            }
            free(txs);
        }
    }

    n = BRWalletUTXOs(wallet, NULL, 0);
    if (n) {
        BRUTXO *u = calloc(n, sizeof(*u));

        if (u) {
            n = BRWalletUTXOs(wallet, u, n);
            qsort(u, n, sizeof(*u), _utxoCompare);
            for (size_t i = 0; i < n; i++) {
                BRTransaction *tx = BRWalletTransactionForHash(wallet, u[i].hash);
                unsigned long long amount = (tx && u[i].n < tx->outCount) ? (unsigned long long)tx->outputs[u[i].n].amount : 0;

                _hexOf(u[i].hash, hex);
                _put(&o, "utxo %s:%u %llu\n", hex, u[i].n, amount);
            }
            free(u);
        }
    }
    return o.len;
}

// ---- the reference session ----------------------------------------------------------------------------

static void _cbSyncStarted(void *info) { (void)info; }
static void _cbSyncStopped(void *info, int error) { (void)info; (void)error; }
static void _cbTxStatus(void *info) { (void)info; }
static void _cbSaveBlocks(void *info, int replace, const uint8_t *b, size_t len, uint64_t *check)
{
    (void)info; (void)replace; (void)b; (void)len; (void)check;
}
static void _cbSavePeers(void *info, int replace, const BRPeer peers[], size_t n)
{
    (void)info; (void)replace; (void)peers; (void)n;
}
static int _cbReachable(void *info) { (void)info; return 1; }
static void _cbThreadCleanup(void *info) { (void)info; }

// The recording's saved window [headers_from .. saved_tip] in the core's saved-blocks format (tip first,
// as the core writes it), read back through BRSavedBlocksDeserialize as both apps read theirs.
static size_t _savedBlocks(const BRReplayServer *s, uint32_t savedTip, BRMerkleBlock ***blocks)
{
    size_t count, cap, at = 4;
    uint8_t *blob;

    *blocks = NULL;
    if (savedTip < s->from || savedTip - s->from >= s->headerCount) return 0;
    count = savedTip - s->from + 1;
    cap = 4 + count*(8 + 128);
    blob = malloc(cap);
    if (! blob) return 0;
    UInt32SetLE(blob, (uint32_t)count);
    for (size_t k = count; k > 0; k--) {
        BRMerkleBlock *b = BRMerkleBlockParse(s->header[k - 1], 80);
        size_t len = b ? BRMerkleBlockSerialize(b, NULL, 0) : 0;

        if (! b || len == 0 || at + 8 + len > cap) { if (b) BRMerkleBlockFree(b); free(blob); return 0; }
        UInt32SetLE(&blob[at], (uint32_t)len);
        UInt32SetLE(&blob[at + 4], s->from + (uint32_t)k - 1);
        BRMerkleBlockSerialize(b, &blob[at + 8], len);
        at += 8 + len;
        BRMerkleBlockFree(b);
    }
    count = BRSavedBlocksDeserialize(blob, at, blocks);
    free(blob);
    return count;
}

BRReplayRunResult BRReplayRun(const BRReplayRecording *recording, BRWallet *wallet, BRReplayRunOptions opt,
                              char *snapshot, size_t snapshotLen)
{
    BRReplayRunResult res;
    BRReplayServer *server;
#ifdef BR_PEER_MESSAGE_TAP
    BRReplayRecorder *recorder = NULL;
#endif
    BRPeerManager *m;
    BRMerkleBlock **blocks = NULL;
    size_t blockCount;
    uint16_t port = 0;
    uint32_t tip, savedTip, birth;
    UInt128 loopback = UINT128_ZERO;
    double start = _now(), timeout = opt.timeoutSecs > 0 ? opt.timeoutSecs : 120.0;
    double tick = opt.keepAliveSecs > 0 ? opt.keepAliveSecs : 0.25;
    int stable = 0;
    uint64_t lastBalance = UINT64_MAX;
    size_t lastTxCount = SIZE_MAX;
    uint32_t lastNeeded = 0, lastHeight = 0;
    double lastProgress = start;

    memset(&res, 0, sizeof(res));
    if (snapshot && snapshotLen) snapshot[0] = '\0';
#ifndef BR_PEER_MESSAGE_TAP
    if (opt.recordPath) return res;   // no tap in this core: a recording was asked for and cannot be made
#endif
    server = BRReplayServerStart(recording, &port);
    if (! server) return res;
    tip = BRReplayServerTip(server, NULL);
    savedTip = BRReplayRecordingSessionU32(recording, "saved_tip", 0);
    birth = BRReplayRecordingSessionU32(recording, "birth", 0);

    blockCount = _savedBlocks(server, savedTip, &blocks);
    m = BRPeerManagerNew(&BRMainNetParams, wallet, birth, blocks, blockCount, NULL, 0);
    free(blocks);   // the array only: the manager adopted the blocks
    BRPeerManagerSetCallbacks(m, NULL, _cbSyncStarted, _cbSyncStopped, _cbTxStatus, _cbSaveBlocks, _cbSavePeers,
                              _cbReachable, _cbThreadCleanup);
    BRPeerManagerSetSyncMode(m, BR_SYNC_MODE_COMPACT_FILTERS_ONLY);
    // The apps' resume: a synced wallet with a saved window arms 100 below its tip (BRCFRestorePreflight.h),
    // then snaps the cursor to the (empty) restored ledger's frontier.
    res.armHeight = (uint32_t)BRCFRestoreArmHeight(1, savedTip, 0, 0, 0);
    BRPeerManagerEnableAutoCompactFilterFetch(m, res.armHeight);
    BRPeerManagerSnapAutoFetchThroughToScanFrontier(m);

    loopback.u16[5] = 0xffff;
    loopback.u8[12] = 127;
    loopback.u8[15] = 1;
    // as the apps pair an own node: into the candidate pool, then pinned, exclusive
    BRPeerManagerAddPeer(m, loopback, port, SERVICES_NODE_NETWORK | SERVICES_NODE_WITNESS | SERVICES_NODE_COMPACT_FILTERS);
    BRPeerManagerSetPinnedPeer(m, loopback, port, 1);

#ifdef BR_PEER_MESSAGE_TAP
    if (opt.recordPath) {
        recorder = BRReplayRecorderStart(opt.recordPath);
        if (recorder) {
            // the session this recording replays with: the same keys as the one it was made from
            static const char *keys[] = { "headers_from", "saved_tip", "saved_count", "tip", "arm", "birth", "wallet" };
            char session[1024];
            size_t at = 0;

            for (size_t k = 0; k < sizeof(keys)/sizeof(*keys); k++) {
                const char *v = BRReplayRecordingSession(recording, keys[k]);

                if (v) at += (size_t)snprintf(&session[at], sizeof(session) - at, "%s=%s\n", keys[k], v);
                if (at >= sizeof(session)) at = sizeof(session) - 1;
            }
            BRReplayRecorderAddMeta(recorder, "session", (const uint8_t *)session, at);
            // and the saved window it resumes from, which no peer sends in this session
            if (savedTip >= server->from && savedTip - server->from < server->headerCount) {
                size_t n = savedTip - server->from + 1, len = 0;
                uint8_t *h = malloc(9 + 81*n);

                if (h) {
                    len = BRVarIntSet(h, 9, n);
                    for (size_t k = 0; k < n; k++, len += 81) { memcpy(&h[len], server->header[k], 80); h[len + 80] = 0; }
                    BRReplayRecorderAddMeta(recorder, "savedheaders", h, len);
                    free(h);
                }
            }
        }
    }

#endif

    BRPeerManagerConnect(m);
    while (_now() - start < timeout) {
        struct timespec ts = { 0, (long)(tick*1e9) };
        uint64_t balance;
        size_t txCount;

        nanosleep(&ts, NULL);
        BRPeerManagerKeepAlive(m);
        balance = BRWalletBalance(wallet);
        txCount = BRWalletTransactions(wallet, NULL, 0);
        uint32_t height = BRPeerManagerLastBlockHeight(m), needed = BRPeerManagerLowestNeededHeight(m);

        if (height == tip && needed > tip && balance == lastBalance && txCount == lastTxCount) {
            if (++stable >= 8) { res.done = 1; break; }
        }
        else stable = 0;
        // A run that has stopped moving (no header, scan, balance or history change) for
        // BR_REPLAY_STALL_SECS is over: it will not finish, and waiting out the timeout proves nothing more.
        if (height != lastHeight || needed != lastNeeded || balance != lastBalance || txCount != lastTxCount) {
            lastProgress = _now();
        }
        else if (_now() - lastProgress > BR_REPLAY_STALL_SECS) break;
        lastBalance = balance;
        lastTxCount = txCount;
        lastHeight = height;
        lastNeeded = needed;
    }
#ifdef BR_PEER_MESSAGE_TAP
    if (! BRPeerManagerDisconnect(m)) {
        // A peer thread outlived the bounded wait and may still be inside the tap: the run does not
        // count, and the recorder is flushed and left allocated rather than freed under that thread.
        res.done = 0;
        if (recorder) {
            BRPeerSetMessageTap(NULL);
            pthread_mutex_lock(&recorder->lock);
            fflush(recorder->f);
            pthread_mutex_unlock(&recorder->lock);
            recorder = NULL;
        }
    }
    if (recorder) BRReplayRecorderStop(recorder);
#else
    if (! BRPeerManagerDisconnect(m)) res.done = 0;
#endif
    res.secs = _now() - start;
    res.server = BRReplayServerGetStats(server);
    if (snapshot) BRReplaySnapshot(wallet, m, snapshot, snapshotLen);
    BRPeerManagerFree(m);
    BRReplayServerStop(server);
    return res;
}

// ---- the plain-types entry point ----------------------------------------------------------------------

const char *BRReplayTestSeedPhrase(const char *name)
{
    // PUBLIC test vectors only. A recording names its wallet by one of these; there is no way to replay
    // into any other seed through this entry point.
    if (name && strcmp(name, "bip39-test-abandon-about") == 0) {
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    }
    return NULL;
}

int BRReplayRunFile(const char *recordingPath, double timeoutSecs, char *snapshot, size_t snapshotLen)
{
    BRReplayRecording *r = recordingPath ? BRReplayRecordingRead(recordingPath) : NULL;
    const char *phrase;
    BRWallet *wallet;
    BRReplayRunOptions opt;
    BRReplayRunResult res;
    uint8_t seed[64];
    size_t len;
    int ok;

    if (snapshot && snapshotLen) snapshot[0] = '\0';
    if (! r) return 0;
    phrase = BRReplayTestSeedPhrase(BRReplayRecordingSession(r, "wallet"));
    if (! phrase) { BRReplayRecordingFree(r); return 0; }
    BRBIP39DeriveKey(seed, phrase, NULL);
    wallet = BRWalletOpenFromSeed(seed, sizeof(seed), NULL, 0);
    memset(seed, 0, sizeof(seed));
    if (! wallet) { BRReplayRecordingFree(r); return 0; }

    memset(&opt, 0, sizeof(opt));
    opt.timeoutSecs = timeoutSecs;
    res = BRReplayRun(r, wallet, opt, snapshot, snapshotLen);
    ok = res.done && res.server.unserved == 0 && res.server.missingBlocks == 0 && res.server.relayAttempts == 0;
    len = snapshot ? strlen(snapshot) : 0;
    if (! ok && snapshot && len < snapshotLen) {
        snprintf(&snapshot[len], snapshotLen - len, "# not ok: done %d, unserved %zu, missing blocks %zu, relay attempts %zu\n",
                 res.done, res.server.unserved, res.server.missingBlocks, res.server.relayAttempts);
    }
    BRWalletFree(wallet);
    BRReplayRecordingFree(r);
    return ok;
}
