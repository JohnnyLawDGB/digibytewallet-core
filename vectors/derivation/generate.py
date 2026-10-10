#!/usr/bin/env python3
"""Derivation vectors for the DigiByte wallet, from an implementation INDEPENDENT of the core.

Every address the shared wallet recipe watches (BRWalletOpen.h) comes from one of four
derivations, and both platforms must produce exactly the same addresses from the same seed:

  bip84   P2WPKH  m/84'/20'/0'/chain/index   master HMAC key "Bitcoin seed"   dgb1q...
  bip86   P2TR    m/86'/20'/0'/chain/index   master HMAC key "Bitcoin seed"   dgb1p... (BIP86 tweak)
  legacy  P2PKH   m/0'/chain/index           master HMAC key "DigiByte seed"  D...
  legacy  P2WPKH  m/0'/chain/index           master HMAC key "DigiByte seed"  dgb1q...

The legacy tree is breadwallet's, with a NON-STANDARD master key ("DigiByte seed"), which is
why no standard tool can produce its vectors: this script implements BIP39, BIP32, secp256k1,
Base58Check, Bech32/Bech32m and the BIP86 tweak from their specifications, in the Python
standard library only, sharing no code with the core. The core is checked AGAINST this file
(host KAT derivation_vectors_kat; the iOS test target reads the same file).

Usage:   python3 -I generate.py > abandon-about.txt
         python3 -I generate.py TREZOR > abandon-about-trezor.txt

The optional argument is a BIP39 passphrase (NFKD-normalized, as BIP39 specifies), so the
passphrase path is held to the same independent vectors. "TREZOR" is the passphrase of the
published BIP39 test vectors.
"""

import hashlib
import hmac
import sys
import unicodedata

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSPHRASE = ""
COUNT = 20          # first 20 receive (chain 0) and 20 change (chain 1) addresses per derivation
HRP = "dgb"
P2PKH_VERSION = 30  # DigiByte mainnet "D"
H = 0x80000000      # hardened

# --- secp256k1 (SEC 2) -------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
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


def point_mul(k, pt=G):
    out = None
    while k:
        if k & 1:
            out = point_add(out, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return out


def ser_p(pt):  # compressed SEC1
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


# --- BIP39 / BIP32 ------------------------------------------------------------------------------
def bip39_seed(mnemonic, passphrase):
    m = unicodedata.normalize("NFKD", mnemonic).encode()
    s = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", m, s, 2048, 64)


def master(seed, key):
    i = hmac.new(key, seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    assert 0 < k < N
    return k, i[32:]


def ckd_priv(k, c, index):
    if index & H:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ser_p(point_mul(k)) + index.to_bytes(4, "big")
    i = hmac.new(c, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    assert il < N
    child = (il + k) % N
    assert child != 0
    return child, i[32:]


def derive(seed, hmac_key, path):
    k, c = master(seed, hmac_key)
    for index in path:
        k, c = ckd_priv(k, c, index)
    return k


# --- encodings ----------------------------------------------------------------------------------
def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST, BECH32M_CONST = 1, 0x2BC830A3


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def convertbits(data, frombits, tobits):
    acc = bits = 0
    out = []
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & ((1 << tobits) - 1))
    if bits:
        out.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
    return out


def segwit_address(version, program):
    data = [version] + convertbits(program, 8, 5)
    const = BECH32_CONST if version == 0 else BECH32M_CONST
    hrp_exp = [ord(x) >> 5 for x in HRP] + [0] + [ord(x) & 31 for x in HRP]
    pm = polymod(hrp_exp + data + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return HRP + "1" + "".join(CHARSET[d] for d in data + checksum)


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def taproot_output_x(k):
    pt = point_mul(k)
    if pt[1] & 1:            # BIP340: the internal key is the even-y point with this x
        pt = (pt[0], P - pt[1])
    t = int.from_bytes(tagged_hash("TapTweak", pt[0].to_bytes(32, "big")), "big")
    assert t < N
    q = point_add(pt, point_mul(t))
    return q[0].to_bytes(32, "big")


# --- the vectors ----------------------------------------------------------------------------------
def main():
    passphrase = sys.argv[1] if len(sys.argv) > 1 else PASSPHRASE
    seed = bip39_seed(MNEMONIC, passphrase)
    print("# DigiByte wallet derivation vectors. Generated by vectors/derivation/generate.py, an")
    print("# implementation independent of the core (Python standard library only). Do not edit.")
    print("# mnemonic: " + MNEMONIC)
    print("# passphrase: " + (passphrase if passphrase else "(empty)"))
    print("# bip39 seed: " + seed.hex())
    print("# columns: derivation format chain index address")
    rows = [
        ("bip84", "p2wpkh", b"Bitcoin seed", [84 | H, 20 | H, 0 | H]),
        ("bip86", "p2tr", b"Bitcoin seed", [86 | H, 20 | H, 0 | H]),
        ("legacy", "p2pkh", b"DigiByte seed", [0 | H]),
        ("legacy", "p2wpkh", b"DigiByte seed", [0 | H]),
    ]
    for name, fmt, key, account in rows:
        for chain in (0, 1):
            for index in range(COUNT):
                k = derive(seed, key, account + [chain, index])
                if fmt == "p2tr":
                    addr = segwit_address(1, taproot_output_x(k))
                else:
                    h = hash160(ser_p(point_mul(k)))
                    addr = segwit_address(0, h) if fmt == "p2wpkh" else base58check(bytes([P2PKH_VERSION]) + h)
                print(f"{name} {fmt} {chain} {index} {addr}")


if __name__ == "__main__":
    main()
