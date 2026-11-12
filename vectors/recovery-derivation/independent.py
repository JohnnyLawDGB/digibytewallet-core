#!/usr/bin/env python3
"""Recover funds vectors from an implementation INDEPENDENT of the core (Python standard library only).

vectors.txt beside this file is the core's headers written down (generate.c). This script derives the
same addresses from the specifications -- BIP39, BIP32, secp256k1, Base58Check, Bech32/Bech32m, the
BIP86 tweak -- sharing no code with the core, and with the profile table written out by hand from
Android's DerivationProfile.kt rather than read from BRDerivationProfiles.h. vectors/derivation/ already
covers profiles 0, 1 and 6 independently; this file covers every profile, including 2 (m/0' with
"Bitcoin seed"), 3 and 4 (the BIP44 paths) and 5 (P2SH-P2WPKH), which nothing else checks independently.
Derived from the independent deriver written for the review of core PR #63.

The host KAT derivation_profiles_kat (Android repo) holds the core to independent.txt.

Usage:   python3 -I independent.py > independent.txt          (mainnet)
"""

import hashlib
import hmac

COUNT = 10          # first 10 receive (chain 0) and 10 change (chain 1) addresses
H = 0x80000000

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def ser(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(b):
    b = b + hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(v):
    g = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    c = 1
    for x in v:
        t = c >> 25
        c = ((c & 0x1FFFFFF) << 5) ^ x
        for i in range(5):
            if (t >> i) & 1:
                c ^= g[i]
    return c


def bech32(hrp, ver, prog):
    acc = bits = 0
    d = [ver]
    for b in prog:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            d.append((acc >> bits) & 31)
    if bits:
        d.append((acc << (5 - bits)) & 31)
    const = 1 if ver == 0 else 0x2BC830A3   # bech32 for v0, bech32m (BIP350) for v1
    hx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(hx + d + [0] * 6) ^ const
    return hrp + "1" + "".join(CH[x] for x in d) + "".join(CH[(pm >> 5 * (5 - i)) & 31] for i in range(6))


def tagged(tag, m):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + m).digest()


def master(seed, key):
    i = hmac.new(key, seed, hashlib.sha512).digest()
    return int.from_bytes(i[:32], "big"), i[32:]


def ckd_priv(k, c, i):
    if i & H:
        data = b"\0" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    else:
        data = ser(mul(k)) + i.to_bytes(4, "big")
    d = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(d[:32], "big") + k) % N, d[32:]


def ckd_pub(K, c, i):
    d = hmac.new(c, ser(K) + i.to_bytes(4, "big"), hashlib.sha512).digest()
    return add(mul(int.from_bytes(d[:32], "big")), K), d[32:]


def address(K, fmt):
    pk = ser(K)
    if fmt == 0:                                       # P2PKH, version 30 ("D")
        return b58check(bytes([30]) + h160(pk))
    if fmt == 1:                                       # P2WPKH
        return bech32("dgb", 0, h160(pk))
    if fmt == 2:                                       # P2SH-P2WPKH, version 63 ("S")
        return b58check(bytes([63]) + h160(b"\x00\x14" + h160(pk)))
    if fmt == 3:                                       # P2TR key path, BIP86 (no script tree)
        x = K[0]
        even = K if K[1] % 2 == 0 else (K[0], P - K[1])
        t = int.from_bytes(tagged("TapTweak", x.to_bytes(32, "big")), "big")
        return bech32("dgb", 1, add(even, mul(t))[0].to_bytes(32, "big"))
    raise ValueError(fmt)


# Written by hand from DerivationProfile.kt BUILT_INS: (hmac key, hardened path, formats probed).
PROFILES = [
    (b"Bitcoin seed", [84, 20, 0], [1, 0]),
    (b"DigiByte seed", [0], [0]),
    (b"Bitcoin seed", [0], [0]),
    (b"Bitcoin seed", [44, 20, 0], [0]),
    (b"Bitcoin seed", [44, 0, 0], [0]),
    (b"Bitcoin seed", [49, 20, 0], [2]),
    (b"Bitcoin seed", [86, 20, 0], [3]),
]
SEEDS = [
    ("abandon " * 11 + "about", ""),
    ("abandon " * 11 + "about", "TREZOR"),
    ("legal winner thank year wave sausage worth useful legal winner thank yellow", ""),
    ("legal winner thank year wave sausage worth useful legal winner thank yellow", "TREZOR"),
]


def main():
    print("# Recover funds vectors from an implementation INDEPENDENT of the core: vectors/recovery-derivation/")
    print("# independent.py (Python standard library only, profile table written by hand). Do not edit.")
    print("# network: mainnet")
    print("# seed <s> <64-byte BIP39 seed, hex>      (s as in vectors.txt)")
    print("# indep <s> <profile> <format> <chain> <index> <address>   (first %d of each chain)" % COUNT)
    for s, (mnemonic, passphrase) in enumerate(SEEDS):
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic" + passphrase.encode(), 2048)
        print("seed %d %s" % (s, seed.hex()))
        for p, (key, path, formats) in enumerate(PROFILES):
            k, c = master(seed, key)
            for e in path:
                k, c = ckd_priv(k, c, e | H)
            acct = (mul(k), c)
            for fmt in formats:
                for chain in (0, 1):
                    K1, c1 = ckd_pub(acct[0], acct[1], chain)
                    for index in range(COUNT):
                        K2, _ = ckd_pub(K1, c1, index)
                        print("indep %d %d %d %d %d %s" % (s, p, fmt, chain, index, address(K2, fmt)))


if __name__ == "__main__":
    main()
