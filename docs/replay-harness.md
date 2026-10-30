# Replay harness

Track 3 of the iOS port plan's §19.2: record one real sync, replay it into the Android and iOS
builds, and compare balance, history and UTXOs exactly, so that a difference between the two
platforms shows up in minutes, on every change. Same seed, same peer messages, same wallet
state. A behaviour may be absent on one platform; a different wallet state is severity 1.

Code: `replay/BRReplay.{h,c}`. Fixtures: `replay/fixtures/`. Recorder for fixtures:
`replay/tools/fetch_window.py`. Gate: the Android repo's host KAT
`native/src/test/host/replay_snapshot_kat/`.

## Shape

```
  record                              replay                                compare
  ------                              ------                                -------
  peer messages, both directions,     replay server on 127.0.0.1 answers    BRReplaySnapshot:
  per peer, timed and ordered         the wallet's requests from the        canonical text, equal
  (BRPeerSetMessageTap in a test      recording; the real core connects     byte for byte to the
  build, or the fetch tool against    to it as an exclusive own node        committed .snapshot
  a public peer)
```

### Where it hooks in

At the core's peer message layer, which both apps share. `BRPeerSetMessageTap` (BRPeer.h) is
called with every complete, checksum-valid message read from a peer, before it is handled, and
with every message about to go out on a peer's socket (after the send gates: a message the
socket or the Tor rule refuses is not recorded). It is process-wide; the caller's `{fn, info}`
pair is published as one atomic pointer. `BRReplayRecorderStart` installs a tap that writes the
recording format below.

**The tap exists only in a test build.** It is compiled in with `-DBR_PEER_MESSAGE_TAP`, which
no app build defines; without it the declarations are absent and the two call sites expand to
nothing, so a release `BRPeer.c` carries no tap code and no tap symbol (the Android KAT checks
the symbol table of a build without the flag). The flag together with `NDEBUG`, which every
release build defines, is a compile error, with no override. The recorder (`replay/`) is under
the same flag; replaying needs no hook and runs against any core, a release one included.

**Never commit a tap recording of any wallet but the public test seed.** A recording holds every
message the wallet exchanged: its addresses and transactions (in the blocks its filters matched
and in anything it sends), and the network addresses of the machine that recorded it (the peers'
version messages carry it, and the recorder writes each peer's address). Only a recording of a
public test seed, with those address fields zeroed as `replay/tools/fetch_window.py` zeroes them,
belongs in a repository.

The replay needs no hook at all: the server is an ordinary peer on 127.0.0.1, and the wallet
reaches it through the same path a user's own node takes (`BRPeerManagerAddPeer` +
`BRPeerManagerSetPinnedPeer(..., exclusive)`). So the replay runs the real sockets, the real
peer threads, the real keepalive, and either app could be pointed at it unchanged.

### How a replay drives the wallet with no network

The server indexes the recording's peer-to-wallet messages by content and answers what the
wallet asks:

| Wallet sends | Server answers |
|---|---|
| `version` | the recorded `version`, its start height set to the recording's tip and its time to now; then `verack` |
| `ping` | `pong` with the same nonce |
| `getheaders` | the recorded headers after the first locator it holds, up to 2,000, to the stop hash or the tip |
| `getcfheaders` | the recorded filter hashes for the range, with the previous filter header recomputed from the recorded batch |
| `getcfilters` | the recorded `cfilter` for each height in the range |
| `getdata` (block) | the recorded `block`, or `notfound` and the hash noted as missing |
| `tx`, `inv`, `dandeliontx` | nothing: counted as a relay attempt (a replay must have none) |
| `getcfcheckpt`, anything else it cannot answer | nothing: counted as unserved |

Answering by content rather than by position makes the replay independent of timing: the
wallet's threads may ask in a different order on another run or another platform and get the
same answers. The recorded order and times stay in the file for inspection and for a later
strict-order replay.

The session around it is the reference resume (`BRReplayRun`), the one both apps run on a cold
start with saved blocks: the recording's saved window of headers is written in the core's
saved-blocks format and read back with `BRSavedBlocksDeserialize`; the wallet is
`BRWalletOpenFromSeed` (the apps' recipe, `BRWalletOpen.h`); compact filters only; the scan is
armed at `BRCFRestoreArmHeight` (100 below the saved tip) and the cursor snapped to the
(empty) ledger's frontier; `BRPeerManagerKeepAlive` ticks every 0.25 s (the apps: 10 s). The
run is done when the header tip and the scan frontier have both passed the recording's tip and
balance and history have held for 2 s; it stops early once nothing has moved for 15 s.

### What is compared

`BRReplaySnapshot`, canonical text:

```
replay-snapshot 1
tip <height> <block hash>
balance <satoshis>
tx <txid> <height|unconfirmed> received <sats> sent <sats> fee <sats|unknown>   (by height, then txid)
utxo <txid>:<index> <sats>                                                      (by txid, then index)
```

Hashes in display order. The last block's height and hash come from the manager under its lock
(`BRPeerManagerLastBlockInfo`); the rest from the wallet's public API. Not yet compared:
DigiAsset and DigiDollar holdings, the receive address, the scan ledger (next steps below).

## The recording format

Binary, little-endian. The magic `DGBREC01`, then records to the end of the file:

| Bytes | Field |
|---|---|
| 1 | direction: `I` peer to wallet, `O` wallet to peer, `M` meta |
| 1 | peer index (a `peer` meta record names each) |
| 8 | microseconds since the recording started |
| 12 | command, NUL-padded (the frame's command field) |
| 4 | payload length |
| n | payload: the message body, without the 24-byte frame header (magic, command, length and checksum are recomputed) |

Meta records:

- `peer`: 16-byte IPv6 (IPv4-mapped) address and 2-byte big-endian port.
- `session`: `key=value` lines. `wallet` names the seed, and must be a public test seed
  (`BRReplayTestSeedPhrase`; today `bip39-test-abandon-about`, the BIP39 vector "abandon" x11
  "about"). `headers_from` is the height of the first header; `saved_tip` the top of the saved
  window the session resumes from (`saved_count` headers); `tip` the last header; `arm` the
  height the recording expects the scan to be armed at; `birth` the wallet's creation time.
- `savedheaders`: the saved window as a `headers` payload, for a session recorded by the tap
  (no peer sends the headers a wallet already holds).

## Fixtures

Both are **synthetic recordings of real data**: every peer message in them is what a public
DigiByte peer (`134.199.198.90`, one of the canon nodes) sent, but the requests were made by
`replay/tools/fetch_window.py`, not by a wallet. One change to the bytes as received: the version
message's two network-address fields (addr_recv, which is the fetching machine's own public
address as the peer saw it, and addr_from) are zeroed when the tool writes the recording, since
the fixtures are public; nothing the replay serves depends on them. The server also patches the
version's start height and time at replay time. A live capture of a wallet sync was impractical: a fresh wallet starts at
the newest checkpoint, about 110,000 blocks below the tip, so even the headers would be several
MB. A resume from 300 saved headers keeps each fixture near 75 KB.

| Fixture | Window | What the test seed's wallet sees |
|---|---|---|
| `test-abandon-24460800` | saved to 24,460,600; scan 24,460,500 .. 24,460,800 | a 2 DGB receive at 24,460,708; a self-send spending it at 24,460,713 (fee 15,400); balance 1.999846 DGB in two UTXOs |
| `test-abandon-23924600` | saved to 23,924,400; scan 23,924,300 .. 23,924,600 | a zero-value Taproot (BIP86) output of a DigiDollar-style transfer at 23,924,456; a 0.3 DGB receive; the spend of both (fee 0.1 DGB); a 0.2 DGB spend; balance 0 |

The `.snapshot` beside each was produced by the replay and then checked, line by line, against
the public explorer digiexplorer.info on 2026-10-29 (amounts, fees, heights, and that both UTXOs
of the first fixture were unspent at the window's tip), so the expectation is not derived from
the code under test. The second fixture is the one that catches the 2026-10 iOS wallet recipe
(BIP84 alone): replayed with `-DWALLET_OPEN_SINGLE_TREE_UNFIXED` it loses the Taproot
transaction and the spend's fee.

To record another window: run the tool once without `--block`, replay it (the replay names every
block its filters matched and the server did not hold), and run the tool again with those blocks:

```
python3 -I replay/tools/fetch_window.py --peer 134.199.198.90 --saved-tip H0 --tip H1 --arm H0-100 \
    --session wallet=bip39-test-abandon-about --session birth=<unix time> [--block <hash> ...] --out x.rec
```

The tool is read-only: version, verack, pong, getheaders, getcfheaders, getcfilters and getdata.
It never sends a transaction or an announcement. Keep windows clear of the 50,000-block
checkpoints, so a later checkpoint table cannot change the replay.

## Platforms

- **Core / Android build:** `replay_snapshot_kat` (Android repo) builds every core unit the apps
  build plus `replay/BRReplay.c`, at the shipped header check levels, 64- and 32-bit with
  AddressSanitizer, and replays both fixtures against their snapshots. It builds with
  `-DBR_PEER_MESSAGE_TAP` for its recording round trip, and checks that a build without the flag
  has no tap symbol and that the flag with `NDEBUG` does not compile. Core CI runs it on every
  core PR.
- **iOS build:** an XCTest replays the same fixtures through the core as the iOS XCFramework
  builds it (`BRReplayRunFile`, a plain-types entry point Swift can call) and compares with the
  same snapshot files. That core is the release-shaped one (NDEBUG, no tap): the replay needs no
  hook.

Both compare to one committed snapshot, so a build whose wallet state differs fails on its side.

`replay/` is outside both apps' core builds (Android lists its sources in `native/CMakeLists.txt`;
the iOS XCFramework takes the top-level `BR*.c`): the server and recorder never ship.

## Next

1. Platform drivers that set the session up through each app's own code (Android `jni_peer.c`
   `startSync` and the Kotlin arming; iOS `WalletCore.connect`), instead of the reference resume.
   That is where most remaining platform divergence can live (arm height, saved-block handling,
   own-node pinning order).
2. A fresh-wallet fixture (birth checkpoint, no saved blocks), once a compact recording of the
   headers from a checkpoint is worked out.
3. DigiAsset and DigiDollar holdings, the receive address and the scan ledger in the snapshot.
4. A strict-order replay mode that feeds `I` records in their recorded order, for bugs that
   depend on arrival order.
5. Fixtures for a reorg, a legacy (`m/0'`) receive and an unconfirmed transaction.
