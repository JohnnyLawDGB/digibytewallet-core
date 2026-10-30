#!/usr/bin/env python3
"""Fetch a window of real DigiByte chain data from one public peer and write it as a replay recording.

    fetch_window.py --peer HOST[:PORT] --saved-tip H0 --tip H1 --arm A [--saved-count N]
                    [--block HASH ...] --session KEY=VALUE ... --out FILE

READ-ONLY. The only messages this sends are version, verack, pong, getheaders, getcfheaders,
getcfilters and getdata for blocks. It never sends inv, tx or anything that announces or relays data.

What it records (docs/replay-harness.md, "The recording format"), all from the peer:
  * the peer's version message (the replay server patches its start height to the window's tip);
  * headers H0-N+1 .. H1 (N = --saved-count, the window the wallet resumes from, and the new headers
    it syncs), as the peer's own headers messages;
  * cfheaders and cfilters for A .. H1 (A = the scan's arm height);
  * the full blocks named by --block (the blocks the wallet's filters match; run the replay once
    without them and it names every block it asked for and did not get).
Every peer message is written as it arrived, with its arrival time and order. Meta records carry the
peer's address and the session (wallet, arm height, ...) the replay builds.

The heights' block hashes come from the headers themselves: the first header's parent is looked up by
height on the public explorer (digiexplorer.info, read-only), and every header after it must link to
the one before.
"""
import argparse
import hashlib
import json
import socket
import struct
import sys
import time
import urllib.request

MAGIC = 0xDAB6C3FA          # mainnet, wire bytes fa c3 b6 da
PORT = 12024
PROTOCOL_VERSION = 70019
FILTER_BASIC = 0
INV_BLOCK = 2
REC_MAGIC = b"DGBREC01"


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_varint(b, off):
    x = b[off]
    if x < 0xfd:
        return x, off + 1
    if x == 0xfd:
        return struct.unpack_from("<H", b, off + 1)[0], off + 3
    if x == 0xfe:
        return struct.unpack_from("<I", b, off + 1)[0], off + 5
    return struct.unpack_from("<Q", b, off + 1)[0], off + 9


class Recording:
    def __init__(self):
        self.t0 = time.monotonic()
        self.records = []

    def add(self, direction, peer, command, payload):
        t = int((time.monotonic() - self.t0) * 1e6)
        self.records.append((direction, peer, t, command, payload))

    def write(self, path):
        with open(path, "wb") as f:
            f.write(REC_MAGIC)
            for d, p, t, c, pl in self.records:
                cmd = c.encode() if isinstance(c, str) else c
                f.write(struct.pack("<BBQ", ord(d), p, t) + cmd.ljust(12, b"\0") + struct.pack("<I", len(pl)) + pl)


class Peer:
    def __init__(self, host, port, rec):
        self.rec = rec
        self.sock = socket.create_connection((host, port), timeout=30)
        self.buf = b""

    def send(self, command, payload=b""):
        assert command in ("version", "verack", "pong", "getheaders", "getcfheaders", "getcfilters", "getdata")
        hdr = struct.pack("<I", MAGIC) + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4]
        self.sock.sendall(hdr + payload)

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self):
        """The next message; pings are answered (and recorded) here."""
        while True:
            hdr = self._read(24)
            magic, cmd, length, chk = struct.unpack("<I12sI4s", hdr)
            if magic != MAGIC:
                raise ValueError("bad magic")
            payload = self._read(length)
            if dsha(payload)[:4] != chk:
                raise ValueError("bad checksum")
            command = cmd.rstrip(b"\0").decode()
            self.rec.add("I", 0, command, payload)
            if command == "ping":
                self.send("pong", payload)
                continue
            return command, payload

    def wait_for(self, *commands):
        while True:
            c, p = self.recv()
            if c in commands:
                return c, p


def explorer_hash_at(height):
    with urllib.request.urlopen("https://digiexplorer.info/api/block-height/%d" % height, timeout=30) as r:
        return bytes.fromhex(r.read().decode().strip())[::-1]   # to internal (little-endian) order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer", required=True)
    ap.add_argument("--saved-tip", type=int, required=True)
    ap.add_argument("--saved-count", type=int, default=300)
    ap.add_argument("--tip", type=int, required=True)
    ap.add_argument("--arm", type=int, required=True)
    ap.add_argument("--block", action="append", default=[], help="block hash (display order) to fetch in full")
    ap.add_argument("--session", action="append", default=[], help="KEY=VALUE for the session meta record")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    host, _, port = a.peer.partition(":")
    port = int(port or PORT)
    first = a.saved_tip - a.saved_count + 1
    assert first <= a.arm <= a.tip and a.saved_tip < a.tip and a.tip - a.arm < 1000

    rec = Recording()
    try:
        addr = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except OSError:
        addr = host
    rec.add("M", 0, "peer", b"\0" * 10 + b"\xff\xff" + socket.inet_aton(addr) + struct.pack(">H", port))
    session = ["headers_from=%d" % first, "saved_tip=%d" % a.saved_tip, "saved_count=%d" % a.saved_count, "tip=%d" % a.tip,
               "arm=%d" % a.arm] + a.session
    rec.add("M", 0, "session", ("\n".join(session) + "\n").encode())

    parent = explorer_hash_at(first - 1)
    tip_hash = explorer_hash_at(a.tip)   # hashStop: the peer's headers end at the window's tip
    p = Peer(host, port, rec)
    ver = (struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time())) + struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" +
           b"\0" * 4 + struct.pack(">H", 0) + struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" + b"\0" * 4 +
           struct.pack(">H", 0) + struct.pack("<Q", 0x5eed) + varint(len(b"/replay-fetch:1/")) + b"/replay-fetch:1/" +
           struct.pack("<i", 0) + b"\0")
    p.send("version", ver)
    p.wait_for("version")
    p.wait_for("verack")
    p.send("verack")

    # headers first .. tip, as the peer's own headers messages (each holds up to 2000 or more)
    headers = []           # (height, hash, 80 bytes)
    prev = parent
    while len(headers) < a.tip - first + 1:
        p.send("getheaders", struct.pack("<I", PROTOCOL_VERSION) + varint(1) + prev + tip_hash)
        _, pl = p.wait_for("headers")
        n, off = read_varint(pl, 0)
        if n == 0:
            raise RuntimeError("peer has no headers past %s" % prev[::-1].hex())
        for _ in range(n):
            h = pl[off:off + 80]
            _, off = read_varint(pl, off + 80)
            if h[4:36] != prev:
                raise RuntimeError("headers do not link")
            prev = dsha(h)
            headers.append((first + len(headers), prev, h))
            if len(headers) == a.tip - first + 1:
                break
    by_height = {ht: hs for ht, hs, _ in headers}
    stop = by_height[a.tip]
    if stop != tip_hash:
        raise RuntimeError("the peer's chain and the explorer disagree at the tip")

    p.send("getcfheaders", struct.pack("<BI", FILTER_BASIC, a.arm) + stop)
    p.wait_for("cfheaders")

    p.send("getcfilters", struct.pack("<BI", FILTER_BASIC, a.arm) + stop)
    for _ in range(a.tip - a.arm + 1):
        p.wait_for("cfilter")

    if a.block:
        inv = varint(len(a.block)) + b"".join(struct.pack("<I", INV_BLOCK) + bytes.fromhex(h)[::-1] for h in a.block)
        p.send("getdata", inv)
        for _ in a.block:
            p.wait_for("block")

    p.sock.close()
    rec.write(a.out)
    print(json.dumps({"out": a.out, "records": len(rec.records), "first": first, "tip": a.tip,
                      "tip_hash": stop[::-1].hex()}))


if __name__ == "__main__":
    sys.exit(main())
