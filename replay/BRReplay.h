//
//  BRReplay.h
//
//  The replay harness: record a sync's peer messages, replay them into a wallet with no network, and
//  reduce the result to a canonical snapshot that two builds (Android, iOS) must produce byte for byte.
//  Design and file format: docs/replay-harness.md.
//
//  NOT PART OF EITHER APP. These files live under replay/ so neither app's core build picks them up
//  (Android lists its core sources in native/CMakeLists.txt; the iOS XCFramework takes BR*.c at the top
//  level). Test targets and host tools compile them. The recording hook they install,
//  BRPeerSetMessageTap, is in BRPeer.c and is inert (NULL) unless a test sets it.
//
//  Pieces:
//    Recording   the file: a list of records, each a peer message (in = peer to wallet, out = wallet to
//                peer) or a meta record, with the peer it belongs to and its time in the recording.
//    Recorder    a BRPeerMessageTap that appends every message the core reads or sends to a recording.
//    Server      a fake peer on 127.0.0.1 that answers the wallet's requests from a recording's peer
//                messages, by content: headers, cfheaders, cfilters and blocks the recording holds.
//                It never relays anything anywhere; a tx or inv the wallet sends is only counted.
//    Snapshot    the wallet state the platforms must agree on, as canonical text.
//    Run         the reference session: a wallet resumed from the recording's saved headers, armed and
//                pinned to the server the way both apps do it, run until the scan reaches the tip.
//
//  Threads: the server runs its own thread. Everything else is called from one thread.
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

#ifndef BRReplay_h
#define BRReplay_h

#include "BRInt.h"
#include "BRWallet.h"
#include "BRPeerManager.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_REPLAY_MAGIC "DGBREC01"   // 8 bytes at the start of a recording

#define BR_REPLAY_DIR_IN   'I'       // a message the peer sent the wallet
#define BR_REPLAY_DIR_OUT  'O'       // a message the wallet sent the peer
#define BR_REPLAY_DIR_META 'M'       // not a message: "peer", "session" (see docs/replay-harness.md)

typedef struct {
    char dir;                // BR_REPLAY_DIR_*
    uint8_t peer;            // which peer of the recording (meta "peer" records number them from 0)
    uint64_t timeUs;         // microseconds since the recording started
    char type[13];           // the command field, NUL-terminated
    uint32_t len;
    const uint8_t *payload;  // the message body (no frame header); owned by the recording
} BRReplayRecord;

typedef struct BRReplayRecordingStruct BRReplayRecording;

// Parses a recording (the buffer is copied). NULL if it is not one: a bad magic, or a record that runs
// past the end.
BRReplayRecording *BRReplayRecordingParse(const uint8_t *buf, size_t len);
BRReplayRecording *BRReplayRecordingRead(const char *path);
void BRReplayRecordingFree(BRReplayRecording *recording);

size_t BRReplayRecordingCount(const BRReplayRecording *recording);
const BRReplayRecord *BRReplayRecordingAt(const BRReplayRecording *recording, size_t i);

// A session value (meta "session" records hold key=value lines), or NULL. *_U32 returns def if absent.
const char *BRReplayRecordingSession(const BRReplayRecording *recording, const char *key);
uint32_t BRReplayRecordingSessionU32(const BRReplayRecording *recording, const char *key, uint32_t def);

// ---- recorder ---------------------------------------------------------------------------------------

typedef struct BRReplayRecorderStruct BRReplayRecorder;

// Starts recording every peer message in the process to path (installs the BRPeer message tap). The
// recording opens with the meta records given (may be none). NULL if the file cannot be written.
BRReplayRecorder *BRReplayRecorderStart(const char *path);
void BRReplayRecorderAddMeta(BRReplayRecorder *recorder, const char *type, const uint8_t *payload, size_t len);
// Removes the tap and closes the file. Call only after every peer has ended (BRPeerManagerDisconnect).
// Returns the number of messages recorded.
size_t BRReplayRecorderStop(BRReplayRecorder *recorder);

// ---- server -----------------------------------------------------------------------------------------

typedef struct BRReplayServerStruct BRReplayServer;

typedef struct {
    size_t connections;      // TCP connections accepted
    size_t requests;         // messages the wallet sent
    size_t served;           // messages the server sent
    size_t unserved;         // requests it could not answer from the recording (a getcfheaders for a range
                             // it does not hold, a getcfcheckpt, ...)
    size_t missingBlocks;    // getdata block hashes the recording does not hold
    size_t relayAttempts;    // tx / inv / dandelion messages from the wallet: counted, never forwarded
} BRReplayServerStats;

// Indexes the recording's peer-to-wallet messages and starts listening on 127.0.0.1 at an ephemeral port
// (*port). The recording must outlive the server. NULL if the recording has no version message or no
// headers, or the socket cannot be opened.
BRReplayServer *BRReplayServerStart(const BRReplayRecording *recording, uint16_t *port);
BRReplayServerStats BRReplayServerGetStats(BRReplayServer *server);
// Up to max block hashes the wallet asked for and the recording does not hold (display order is
// UInt256Reverse of these). Returns how many were written.
size_t BRReplayServerMissingBlocks(BRReplayServer *server, UInt256 hashes[], size_t max);
// The served chain's tip (the recording's last header) and its height.
uint32_t BRReplayServerTip(BRReplayServer *server, UInt256 *hash);
void BRReplayServerStop(BRReplayServer *server);

// ---- snapshot ---------------------------------------------------------------------------------------

// The state compared across platforms, as canonical text (docs/replay-harness.md, "What is compared"):
//   replay-snapshot 1
//   tip <height> <block hash>
//   balance <satoshis>
//   tx <txid> <height|unconfirmed> received <sats> sent <sats> fee <sats|unknown>    (by height, then txid)
//   utxo <txid>:<index> <sats>                                                       (by txid, then index)
// Hashes in display (RPC) order. Writes at most bufLen bytes including the NUL; returns the length the
// whole snapshot needs (excluding the NUL), so a return >= bufLen means it was cut short.
size_t BRReplaySnapshot(BRWallet *wallet, BRPeerManager *manager, char *buf, size_t bufLen);

// ---- the reference session --------------------------------------------------------------------------

typedef struct {
    double timeoutSecs;      // give up after this long (0: 120 s), or once nothing has moved for 15 s
    double keepAliveSecs;    // BRPeerManagerKeepAlive cadence (0: 0.25 s; the apps tick every 10 s)
    const char *recordPath;  // if set, record this session's messages here (BRReplayRecorder)
} BRReplayRunOptions;

typedef struct {
    int done;                // the header tip and the scan both reached the server's tip, and held
    double secs;
    uint32_t armHeight;      // the height the scan was armed at (BRCFRestoreArmHeight)
    BRReplayServerStats server;
} BRReplayRunResult;

// One session against a replay server for `recording`: the wallet (opened by the caller, normally
// BRWalletOpenFromSeed over a test seed, and with no transactions) resumes from the recording's saved
// headers (session keys headers_from, saved_tip) as both apps resume from saved blocks, syncs compact
// filters only, armed at BRCFRestoreArmHeight, through the server pinned as an exclusive own node. Writes
// the snapshot to buf (as BRReplaySnapshot) and returns the run's result. The wallet stays the caller's.
BRReplayRunResult BRReplayRun(const BRReplayRecording *recording, BRWallet *wallet, BRReplayRunOptions options,
                              char *snapshot, size_t snapshotLen);

// ---- the plain-types entry point ---------------------------------------------------------------------

// For a platform test that cannot share the core's C types (Swift through a bridging header, JNI):
// replays the recording at recordingPath with BRReplayRun into a wallet opened (BRWalletOpenFromSeed, the
// apps' recipe) from the recording's session key `wallet`, which must name one of the PUBLIC test seeds
// this file knows (BRReplayTestSeedPhrase) -- never a real wallet. Writes the snapshot to snapshot (as
// BRReplaySnapshot) and returns 1 when the run finished (BRReplayRunResult.done) with nothing unserved,
// no block missing and no relay attempt; 0 otherwise, with the reason as a "# ..." line after the snapshot.
// Call BRSetNetwork(0) (mainnet) first.
int BRReplayRunFile(const char *recordingPath, double timeoutSecs, char *snapshot, size_t snapshotLen);

// The phrase of a public BIP39 test seed by its fixture name, or NULL. Known: "bip39-test-abandon-about"
// (the BIP39 vector "abandon" x11 "about", empty passphrase).
const char *BRReplayTestSeedPhrase(const char *name);

#ifdef __cplusplus
}
#endif

#endif // BRReplay_h
