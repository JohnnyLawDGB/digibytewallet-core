#!/usr/bin/env python3
"""Shared fixtures for the reconcile-backend answers both platforms parse.

Writes bodies/<kind>-<id>.body (the exact bytes of each answer) and expected.txt (the rows a correct
parser produces from each, or `unreadable`). README.md states the rules; this file is the corpus.

Every expectation below is written by hand. reference_rows() is an independent strict normaliser of
the README's rules, and the generator refuses to write (or, with --check, fails) when it disagrees
with any hand-written expectation. The normaliser is a generator aid only: nothing ships it, and each
platform keeps its own JSON parser (transport). It is not a model of either platform's parser.

    python3 -I generate.py            # write bodies/ and expected.txt
    python3 -I generate.py --check    # verify they are current; exit 1 otherwise

Python 3.8+, standard library only.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Body caps (bytes), Android's DgbNodeClient: RECONCILE_BODY_BYTES, HISTORY_BODY_BYTES,
# EXPLORER_BODY_BYTES. A body of exactly the cap is read; one byte over is unreadable.
CAPS = {
    "reconcile": 32 * 1024 * 1024,
    "history": 16 * 1024 * 1024,
    "raw-tx": 8 * 1024 * 1024,
    "tx-raw": 8 * 1024 * 1024,
    "tx-confirmation": 8 * 1024 * 1024,
    "block": 8 * 1024 * 1024,
}
MAX_DEPTH = 64
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1
UINT32_MAX = (1 << 32) - 1
HEXDIGITS = set("0123456789abcdefABCDEF")

# ---- the reference normaliser ---------------------------------------------------------------------


class Unreadable(Exception):
    pass


class _Float:
    """A JSON number with a fraction or exponent: never an integer field's value."""


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Unreadable("duplicate key %r" % k)
        d[k] = v
    return d


def _bad_constant(name):
    raise Unreadable("non-JSON constant %s" % name)


def _check_outside_strings(text):
    """Outside strings JSON is ASCII; nesting stays within MAX_DEPTH."""
    depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ord(ch) > 0x7F:
            raise Unreadable("non-ASCII outside a string")
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise Unreadable("nesting deeper than %d" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1


def _check_strings(v):
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise Unreadable("lone surrogate")
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_strings(k)
            _check_strings(x)
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)


def parse_json(body, cap):
    if len(body) > cap:
        raise Unreadable("over the cap")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable("not UTF-8")
    if text.startswith("﻿"):
        raise Unreadable("byte order mark")
    _check_outside_strings(text)
    try:
        v = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant,
                       parse_float=lambda s: _Float())
    except Unreadable:
        raise
    except (ValueError, RecursionError):
        raise Unreadable("not JSON")
    _check_strings(v)
    return v


_ABSENT = object()


def _get(obj, key):
    return obj.get(key, _ABSENT)


def int_field(obj, key, required, lo=INT64_MIN, hi=INT64_MAX, default=0):
    v = _get(obj, key)
    if v is _ABSENT or v is None:
        if required:
            raise Unreadable("%s missing" % key)
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise Unreadable("%s not an integer" % key)
    if not lo <= v <= hi:
        raise Unreadable("%s out of range" % key)
    return v


def is_hex(s):
    return all(c in HEXDIGITS for c in s)


def txid_value(v, what):
    if not isinstance(v, str) or len(v) != 64 or not is_hex(v):
        raise Unreadable("%s not 64 hex digits" % what)
    return v.lower()


def hex_bytes_value(v, what):
    if not isinstance(v, str) or not v or len(v) % 2 or not is_hex(v):
        raise Unreadable("%s not hex bytes" % what)
    return v.lower()


def optional_string(obj, key):
    """None for absent, null or ""; the string otherwise; Unreadable for any other type."""
    v = _get(obj, key)
    if v is _ABSENT or v is None or v == "":
        return None
    if not isinstance(v, str):
        raise Unreadable("%s not a string" % key)
    return v


def address_value(v):
    if not isinstance(v, str) or not 1 <= len(v) <= 128 or any(not 0x21 <= ord(c) <= 0x7E for c in v):
        raise Unreadable("address not 1-128 printable ASCII")
    return v


def time_field(obj):
    if _get(obj, "blocktime") not in (_ABSENT, None):
        return int_field(obj, "blocktime", True)
    return int_field(obj, "time", False)


def rows_reconcile(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    utxos = _get(root, "utxos")
    if not isinstance(utxos, list):
        raise Unreadable("utxos")
    raw = _get(root, "rawTxs")
    if raw is _ABSENT or raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise Unreadable("rawTxs")
    out = ["chain-height %d" % int_field(root, "height", False)]
    for u in utxos:
        if not isinstance(u, dict):
            raise Unreadable("utxo")
        txid = txid_value(_get(u, "txid"), "txid")
        vout = int_field(u, "vout", True, 0, UINT32_MAX)
        amount = int_field(u, "amountSatoshi", True)
        address = address_value(_get(u, "address"))
        height = int_field(u, "height", True)
        script = optional_string(u, "scriptPubKey")
        script = "-" if script is None else hex_bytes_value(script, "scriptPubKey")
        out.append("utxo %s %d %d %d %s %s" % (txid, vout, amount, height, address, script))
    seen = {}
    for k, e in raw.items():
        txid = txid_value(k, "rawTxs key")
        if txid in seen:
            raise Unreadable("rawTxs key twice")
        if not isinstance(e, dict):
            raise Unreadable("rawTxs entry")
        seen[txid] = "rawtx %s %d %d %s" % (txid, int_field(e, "height", True), int_field(e, "time", True),
                                           hex_bytes_value(_get(e, "hex"), "hex"))
    out += [seen[t] for t in sorted(seen)]
    return out


def rows_history(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    txs = _get(root, "transactions")
    if txs is _ABSENT or txs is None:
        return []
    if not isinstance(txs, list):
        raise Unreadable("transactions")
    out = []
    for t in txs:
        if not isinstance(t, dict):
            raise Unreadable("entry")
        txid = optional_string(t, "txid")
        height = int_field(t, "height", False)
        if txid is None:
            continue
        out.append("tx %s %d" % (txid_value(txid, "txid"), height))
    return out


def rows_raw_tx(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    h = optional_string(root, "hex")
    if h is None:
        raise Unreadable("no hex")
    return ["rawtx %s %d" % (hex_bytes_value(h, "hex"), time_field(root))]


def rows_tx_raw(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    h = optional_string(root, "hex")
    if h is None:
        h = optional_string(root, "rawtx")
    if h is None:
        raise Unreadable("no hex")
    return ["raw %s" % hex_bytes_value(h, "hex")]


def rows_tx_confirmation(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    bh = optional_string(root, "blockhash")
    bh = "-" if bh is None else txid_value(bh, "blockhash")
    return ["txconf %s %d %d" % (bh, int_field(root, "confirmations", False), time_field(root))]


def rows_block(root):
    if not isinstance(root, dict):
        raise Unreadable("root")
    return ["block %d" % int_field(root, "height", False)]


KINDS = {
    "reconcile": rows_reconcile,
    "history": rows_history,
    "raw-tx": rows_raw_tx,
    "tx-raw": rows_tx_raw,
    "tx-confirmation": rows_tx_confirmation,
    "block": rows_block,
}


def reference_rows(kind, body):
    try:
        return KINDS[kind](parse_json(body, CAPS[kind]))
    except Unreadable:
        return ["unreadable"]


# ---- the corpus ------------------------------------------------------------------------------------
# (kind, id, body bytes, pad-to or None, expected rows). A body with pad-to is padded with ASCII
# spaces to exactly that many bytes before it is parsed.

T1 = "8096148944b5c4d136d62d6521ae7f85283dce1656de991a77b8faf1b2973a63"   # AddressHistoryParseTest
T2 = "b42c76de310f5b3fee6d115bcaf2410c844a665d7c5eb2d7f0ecc31a22511636"   # AddressHistoryParseTest
DUP = "6bd35c442896c27f" + "0" * 48   # DuplicateUtxoTest's outpoint; its test txid is a 16-digit prefix
OTH = "ac3cbb77c252e78d" + "0" * 48
BH = "00044c37" + "ab" * 28
P2PKH = "76a914" + "11" * 20 + "88ac"
P2TR = "5120" + "22" * 32
ADDR = "DCrAZfrumyKz36cDfE8YCL2fJc5eU7Ffxk"
TADDR = "dgb1pexampletaprootaddress"
U = ["unreadable"]


def b(s):
    return s.encode("utf-8")


def utxo_json(txid=DUP, vout="0", amount="6000", addr=ADDR, height="24106618", script=P2PKH, extra=""):
    s = '{"txid":"%s","vout":%s,"amountSatoshi":%s,"address":"%s","height":%s' % (txid, vout, amount, addr, height)
    if script is not None:
        s += ',"scriptPubKey":"%s"' % script
    return s + extra + "}"


def reconcile_json(utxos, raw=None, height="24106700"):
    s = '{"utxos":[%s]' % ",".join(utxos)
    if raw is not None:
        s += ',"rawTxs":%s' % raw
    if height is not None:
        s += ',"height":%s' % height
    return s + "}"


def urow(txid=DUP, vout=0, amount=6000, height=24106618, addr=ADDR, script=P2PKH):
    return "utxo %s %d %d %d %s %s" % (txid, vout, amount, height, addr, script)


CH = "chain-height 24106700"


def one(amount="6000", **kw):
    """A reconcile body with one UTXO whose amountSatoshi token is `amount`."""
    return b(reconcile_json([utxo_json(amount=amount, **kw)]))


CASES = []


def case(kind, cid, body, expect, pad_to=None):
    CASES.append((kind, cid, body, pad_to, expect))


# reconcile: POST {endpoint}/wallet/reconcile
case("reconcile", "observed-duplicate",
     b(reconcile_json([utxo_json(), utxo_json(height="0"),
                       utxo_json(txid=OTH, amount="500000000", height="0")])),
     [CH, urow(), urow(height=0), urow(txid=OTH, amount=500000000, height=0)])
case("reconcile", "typical",
     b(reconcile_json([utxo_json(txid=T1, vout="1", amount="424797024", height="23877512"),
                       utxo_json(txid=T2, amount="100000", addr=TADDR, height="23874652", script=P2TR)],
                      raw='{"%s":{"hex":"0100aabb","height":23877512,"time":1784416468},'
                          '"%s":{"hex":"0200CCDD","height":23874652,"time":1784400000}}' % (T2, T1))),
     [CH, urow(T1, 1, 424797024, 23877512), urow(T2, 0, 100000, 23874652, TADDR, P2TR),
      "rawtx %s 23874652 1784400000 0200ccdd" % T1, "rawtx %s 23877512 1784416468 0100aabb" % T2])
case("reconcile", "no-rawtxs-no-height", b(reconcile_json([utxo_json()], height=None)),
     ["chain-height 0", urow()])
case("reconcile", "rawtxs-null", b(reconcile_json([utxo_json()], raw="null")), [CH, urow()])
case("reconcile", "empty-utxos", b('{"utxos":[],"height":5}'), ["chain-height 5"])
case("reconcile", "height-null", b('{"utxos":[],"height":null}'), ["chain-height 0"])
case("reconcile", "unknown-fields-ignored",
     b(reconcile_json([utxo_json(extra=',"confirmations":3,"coinbase":false,"x":{"y":[1,2.5,"z"]}')])[:-1]
       + ',"server":"9.26.7","took_ms":12.5}'),
     [CH, urow()])
case("reconcile", "whitespace-around", b(" \t\r\n" + reconcile_json([utxo_json()]) + "\n\n"), [CH, urow()])
case("reconcile", "missing-utxos", b('{"height":1}'), U)
case("reconcile", "utxos-null", b('{"utxos":null}'), U)
case("reconcile", "utxos-object", b('{"utxos":{}}'), U)
case("reconcile", "utxo-not-object", b('{"utxos":[1]}'), U)
case("reconcile", "script-absent", one(script=None), [CH, urow(script="-")])
case("reconcile", "script-empty", one(script=""), [CH, urow(script="-")])
case("reconcile", "script-null", b(reconcile_json([utxo_json(script=None, extra=',"scriptPubKey":null')])),
     [CH, urow(script="-")])
case("reconcile", "script-number", b(reconcile_json([utxo_json(script=None, extra=',"scriptPubKey":5120')])), U)
case("reconcile", "script-odd-length", one(script=P2PKH + "a"), U)
case("reconcile", "script-not-hex", one(script="76a9zz"), U)
case("reconcile", "uppercase-hex-lowercased", one(txid=DUP.upper(), script=P2PKH.upper()), [CH, urow()])
case("reconcile", "escaped-txid", one(txid="\\u0036" + DUP[1:]), [CH, urow()])
case("reconcile", "zero-amount", one(amount="0", addr=TADDR, script=P2TR), [CH, urow(amount=0, addr=TADDR, script=P2TR)])
case("reconcile", "negative-amount", one(amount="-1"), [CH, urow(amount=-1)])
case("reconcile", "negative-height", one(height="-1"), [CH, urow(height=-1)])
case("reconcile", "negative-zero-amount", one(amount="-0"), [CH, urow(amount=0)])
case("reconcile", "amount-int64-max", one(amount=str(INT64_MAX)), [CH, urow(amount=INT64_MAX)])
case("reconcile", "amount-int64-min", one(amount=str(INT64_MIN)), [CH, urow(amount=INT64_MIN)])
case("reconcile", "amount-int64-max-plus-one", one(amount=str(INT64_MAX + 1)), U)
case("reconcile", "amount-int64-min-minus-one", one(amount=str(INT64_MIN - 1)), U)
case("reconcile", "amount-huge", one(amount="1" + "0" * 40), U)
case("reconcile", "amount-exponent", one(amount="6e3"), U)
case("reconcile", "amount-fraction", one(amount="6000.0"), U)
case("reconcile", "amount-string", one(amount='"6000"'), U)
case("reconcile", "amount-bool", one(amount="true"), U)
case("reconcile", "amount-null", one(amount="null"), U)
case("reconcile", "amount-missing",
     b('{"utxos":[{"txid":"%s","vout":0,"address":"%s","height":1}]}' % (DUP, ADDR)), U)
case("reconcile", "amount-leading-zero", one(amount="06000"), U)
case("reconcile", "amount-plus-sign", one(amount="+6000"), U)
case("reconcile", "amount-arabic-indic-digits", one(amount="٦٠٠٠"), U)
case("reconcile", "amount-fullwidth-digits", one(amount="６０００"), U)
case("reconcile", "amount-arabic-indic-in-string", one(amount='"٦٠٠٠"'), U)
case("reconcile", "vout-negative", one(vout="-1"), U)
case("reconcile", "vout-uint32-max", one(vout=str(UINT32_MAX)), [CH, urow(vout=UINT32_MAX)])
case("reconcile", "vout-over-uint32", one(vout=str(UINT32_MAX + 1)), U)
case("reconcile", "vout-fraction", one(vout="0.0"), U)
case("reconcile", "height-huge", one(height="9" * 30), U)
case("reconcile", "height-string", one(height='"24106618"'), U)
case("reconcile", "txid-short", one(txid=DUP[:16]), U)
case("reconcile", "txid-65", one(txid=DUP + "0"), U)
case("reconcile", "txid-not-hex", one(txid="g" + DUP[1:]), U)
case("reconcile", "txid-fullwidth-hex", one(txid="６" + DUP[1:]), U)
case("reconcile", "txid-arabic-indic-digit", one(txid="٦" + DUP[1:]), U)
case("reconcile", "txid-number", b(reconcile_json(['{"txid":6,"vout":0,"amountSatoshi":1,"address":"%s","height":1}' % ADDR])), U)
case("reconcile", "address-empty", one(addr=""), U)
case("reconcile", "address-non-ascii", one(addr="Déadbeef"), U)
case("reconcile", "address-space", one(addr="D a"), U)
case("reconcile", "address-number",
     b('{"utxos":[{"txid":"%s","vout":0,"amountSatoshi":1,"address":5,"height":1}]}' % DUP), U)
case("reconcile", "duplicate-key-in-utxo", b(reconcile_json([utxo_json(extra=',"amountSatoshi":12000')])), U)
case("reconcile", "duplicate-key-in-root", b('{"utxos":[],"utxos":[]}'), U)
case("reconcile", "rawtxs-array", b(reconcile_json([utxo_json()], raw="[]")), U)
case("reconcile", "rawtx-key-not-txid", b(reconcile_json([], raw='{"abc":{"hex":"00","height":1,"time":1}}')), U)
case("reconcile", "rawtx-hex-odd", b(reconcile_json([], raw='{"%s":{"hex":"001","height":1,"time":1}}' % T1)), U)
case("reconcile", "rawtx-hex-empty", b(reconcile_json([], raw='{"%s":{"hex":"","height":1,"time":1}}' % T1)), U)
case("reconcile", "rawtx-missing-time", b(reconcile_json([], raw='{"%s":{"hex":"00","height":1}}' % T1)), U)
case("reconcile", "rawtx-entry-not-object", b(reconcile_json([], raw='{"%s":"00"}' % T1)), U)
case("reconcile", "rawtx-key-twice-by-case",
     b(reconcile_json([], raw='{"%s":{"hex":"00","height":1,"time":1},"%s":{"hex":"00","height":1,"time":1}}'
                      % (T1, T1.upper()))), U)
case("reconcile", "malformed-truncated", b(reconcile_json([utxo_json()]))[:-7], U)
case("reconcile", "malformed-trailing-comma", b('{"utxos":[],}'), U)
case("reconcile", "malformed-trailing-garbage", b('{"utxos":[]} x'), U)
case("reconcile", "malformed-two-documents", b('{"utxos":[]}{"utxos":[]}'), U)
case("reconcile", "malformed-single-quotes", b("{'utxos':[]}"), U)
case("reconcile", "malformed-comment", b('{"utxos":[] /* none */}'), U)
case("reconcile", "malformed-nan", b('{"utxos":[],"height":NaN}'), U)
case("reconcile", "malformed-infinity", b('{"utxos":[],"height":-Infinity}'), U)
case("reconcile", "malformed-bom", b("﻿" + '{"utxos":[]}'), U)
case("reconcile", "malformed-invalid-utf8", b('{"utxos":[],"note":"') + b"\xc3\x28" + b('"}'), U)
case("reconcile", "malformed-lone-surrogate", b('{"utxos":[],"note":"\\ud800"}'), U)
case("reconcile", "malformed-control-char", b('{"utxos":[],"note":"a\tb"}'), U)
case("reconcile", "malformed-nbsp-whitespace", b('{"utxos":[], "height":1}'), U)
case("reconcile", "root-array", b("[]"), U)
case("reconcile", "root-string", b('"utxos"'), U)
case("reconcile", "root-null", b("null"), U)
case("reconcile", "empty-body", b(""), U)
case("reconcile", "whitespace-only", b("   "), U)
case("reconcile", "depth-at-limit", b('{"utxos":[],"x":' + "[" * (MAX_DEPTH - 1) + "]" * (MAX_DEPTH - 1) + "}"),
     ["chain-height 0"])
case("reconcile", "depth-over-limit", b('{"utxos":[],"x":' + "[" * MAX_DEPTH + "]" * MAX_DEPTH + "}"), U)
case("reconcile", "depth-deep", b('{"utxos":[],"x":' + "[" * 10000 + "]" * 10000 + "}"), U)
case("reconcile", "size-at-cap", b(reconcile_json([utxo_json()])), [CH, urow()], pad_to=CAPS["reconcile"])
case("reconcile", "size-over-cap", b(reconcile_json([utxo_json()])), U, pad_to=CAPS["reconcile"] + 1)

# history: GET {endpoint}/rpc/address-history/:address, POST {endpoint}/rpc/address-history
case("history", "typical",
     b('{"address":"dgb1plr8","txCount":2,"transactions":[\n'
       '  {"txid":"%s","height":23877512,"confirmations":2919},\n'
       '  {"txid":"%s","height":23874652,"confirmations":5779}\n]}' % (T1, T2)),
     ["tx %s 23877512" % T1, "tx %s 23874652" % T2])
case("history", "missing-transactions", b('{"address":"x","txCount":0}'), [])
case("history", "transactions-null", b('{"transactions":null}'), [])
case("history", "transactions-empty", b('{"transactions":[]}'), [])
case("history", "transactions-object", b('{"transactions":{}}'), U)
case("history", "transactions-string", b('{"transactions":"none"}'), U)
case("history", "blank-txid-skipped",
     b('{"transactions":[{"txid":"","height":1},{"txid":"%s","height":2},{"height":3},{"txid":null,"height":4}]}' % T1),
     ["tx %s 2" % T1])
case("history", "skipped-entry-height-still-checked", b('{"transactions":[{"txid":"","height":"1"}]}'), U)
case("history", "whitespace-txid", b('{"transactions":[{"txid":" ","height":1}]}'), U)
case("history", "txid-short", b('{"transactions":[{"txid":"aa","height":2}]}'), U)
case("history", "txid-uppercase", b('{"transactions":[{"txid":"%s","height":2}]}' % T1.upper()), ["tx %s 2" % T1])
case("history", "txid-fullwidth", b('{"transactions":[{"txid":"%s","height":2}]}' % ("８" + T1[1:])), U)
case("history", "height-missing", b('{"transactions":[{"txid":"%s"}]}' % T1), ["tx %s 0" % T1])
case("history", "height-null", b('{"transactions":[{"txid":"%s","height":null}]}' % T1), ["tx %s 0" % T1])
case("history", "height-negative", b('{"transactions":[{"txid":"%s","height":-1}]}' % T1), ["tx %s -1" % T1])
case("history", "height-int64-max", b('{"transactions":[{"txid":"%s","height":%d}]}' % (T1, INT64_MAX)),
     ["tx %s %d" % (T1, INT64_MAX)])
case("history", "height-huge", b('{"transactions":[{"txid":"%s","height":%d}]}' % (T1, INT64_MAX + 1)), U)
case("history", "height-string", b('{"transactions":[{"txid":"%s","height":"2"}]}' % T1), U)
case("history", "height-fraction", b('{"transactions":[{"txid":"%s","height":2.0}]}' % T1), U)
case("history", "height-exponent", b('{"transactions":[{"txid":"%s","height":2e7}]}' % T1), U)
case("history", "height-arabic-indic", b('{"transactions":[{"txid":"%s","height":٢}]}' % T1), U)
case("history", "entry-not-object", b('{"transactions":[{"txid":"%s","height":2},7]}' % T1), U)
case("history", "repeated-txid-kept",
     b('{"transactions":[{"txid":"%s","height":0},{"txid":"%s","height":99}]}' % (T1, T1)),
     ["tx %s 0" % T1, "tx %s 99" % T1])
case("history", "duplicate-key", b('{"transactions":[{"txid":"%s","txid":"%s","height":2}]}' % (T1, T2)), U)
case("history", "root-array", b('[{"txid":"%s","height":2}]' % T1), U)
case("history", "malformed-truncated", b('{"transactions":[{"txid":"%s","height":2}' % T1), U)
case("history", "size-at-cap", b('{"transactions":[{"txid":"%s","height":2}]}' % T1), ["tx %s 2" % T1],
     pad_to=CAPS["history"])
case("history", "size-over-cap", b('{"transactions":[{"txid":"%s","height":2}]}' % T1), U,
     pad_to=CAPS["history"] + 1)

# raw-tx: GET {endpoint}/explorer/tx/:txid, read for its hex and block time (fetchRawTx)
EXPLORER_TX = b('{"txid":"%s","hex":"07700001aabb","blocktime":1784416468,"confirmations":2919,"blockhash":"%s"}'
                % (T1, BH))
MEMPOOL_TX = b('{"txid":"%s","hex":"07700001aabb","time":1784416000,"confirmations":0}' % T1)
case("raw-tx", "typical", EXPLORER_TX, ["rawtx 07700001aabb 1784416468"])
case("raw-tx", "time-fallback", b('{"hex":"aa","time":123}'), ["rawtx aa 123"])
case("raw-tx", "blocktime-null-falls-back", b('{"hex":"aa","blocktime":null,"time":123}'), ["rawtx aa 123"])
case("raw-tx", "blocktime-over-time", b('{"hex":"aa","blocktime":5,"time":123}'), ["rawtx aa 5"])
case("raw-tx", "no-time", b('{"hex":"aa"}'), ["rawtx aa 0"])
case("raw-tx", "mempool", MEMPOOL_TX, ["rawtx 07700001aabb 1784416000"])
case("raw-tx", "negative-time", b('{"hex":"aa","blocktime":-1}'), ["rawtx aa -1"])
case("raw-tx", "hex-uppercase", b('{"hex":"AABB"}'), ["rawtx aabb 0"])
case("raw-tx", "hex-absent", b('{"txid":"x"}'), U)
case("raw-tx", "hex-empty", b('{"hex":""}'), U)
case("raw-tx", "hex-null", b('{"hex":null}'), U)
case("raw-tx", "hex-number", b('{"hex":1234}'), U)
case("raw-tx", "hex-odd", b('{"hex":"aab"}'), U)
case("raw-tx", "hex-not-hex", b('{"hex":"zz"}'), U)
case("raw-tx", "hex-fullwidth", b('{"hex":"ａａ"}'), U)
case("raw-tx", "hex-arabic-indic", b('{"hex":"١٢"}'), U)
case("raw-tx", "blocktime-string", b('{"hex":"aa","blocktime":"1784416468"}'), U)
case("raw-tx", "time-wrong-type-unread-when-blocktime", b('{"hex":"aa","blocktime":7,"time":"x"}'), ["rawtx aa 7"])
case("raw-tx", "time-wrong-type", b('{"hex":"aa","time":"x"}'), U)
case("raw-tx", "blocktime-huge", b('{"hex":"aa","blocktime":%s}' % ("9" * 25)), U)
case("raw-tx", "root-array", b('["aa"]'), U)
case("raw-tx", "size-at-cap", b('{"hex":"aa","time":1}'), ["rawtx aa 1"], pad_to=CAPS["raw-tx"])
case("raw-tx", "size-over-cap", b('{"hex":"aa","time":1}'), U, pad_to=CAPS["raw-tx"] + 1)

# tx-raw: GET {endpoint}/tx/raw/:txid (fetchRawTransaction)
case("tx-raw", "hex", b('{"hex":"0100aabb"}'), ["raw 0100aabb"])
case("tx-raw", "rawtx-fallback", b('{"rawtx":"0100aabb"}'), ["raw 0100aabb"])
case("tx-raw", "hex-empty-falls-back", b('{"hex":"","rawtx":"0100aabb"}'), ["raw 0100aabb"])
case("tx-raw", "hex-null-falls-back", b('{"hex":null,"rawtx":"0100aabb"}'), ["raw 0100aabb"])
case("tx-raw", "hex-wins", b('{"hex":"01","rawtx":"02"}'), ["raw 01"])
case("tx-raw", "bad-hex-does-not-fall-back", b('{"hex":"0g","rawtx":"02"}'), U)
case("tx-raw", "neither", b('{"txid":"x"}'), U)
case("tx-raw", "hex-odd", b('{"hex":"010"}'), U)
case("tx-raw", "hex-arabic-indic", b('{"hex":"٠١"}'), U)
case("tx-raw", "hex-fullwidth", b('{"hex":"０１"}'), U)
case("tx-raw", "hex-devanagari", b('{"hex":"०१"}'), U)
case("tx-raw", "hex-number", b('{"hex":101}'), U)
case("tx-raw", "rawtx-wrong-type", b('{"rawtx":["01"]}'), U)
case("tx-raw", "size-at-cap", b('{"hex":"01"}'), ["raw 01"], pad_to=CAPS["tx-raw"])
case("tx-raw", "size-over-cap", b('{"hex":"01"}'), U, pad_to=CAPS["tx-raw"] + 1)

# tx-confirmation: GET {endpoint}/explorer/tx/:txid, read for blockhash, confirmations, block time
case("tx-confirmation", "confirmed", EXPLORER_TX, ["txconf %s 2919 1784416468" % BH])
case("tx-confirmation", "mempool", MEMPOOL_TX, ["txconf - 0 1784416000"])
case("tx-confirmation", "blockhash-empty", b('{"blockhash":"","confirmations":3,"time":9}'), ["txconf - 3 9"])
case("tx-confirmation", "blockhash-uppercase", b('{"blockhash":"%s","confirmations":1}' % BH.upper()),
     ["txconf %s 1 0" % BH])
case("tx-confirmation", "confirmations-negative", b('{"blockhash":"%s","confirmations":-1,"blocktime":5}' % BH),
     ["txconf %s -1 5" % BH])
case("tx-confirmation", "confirmations-missing", b('{"blockhash":"%s"}' % BH), ["txconf %s 0 0" % BH])
case("tx-confirmation", "confirmations-string", b('{"blockhash":"%s","confirmations":"1"}' % BH), U)
case("tx-confirmation", "confirmations-huge", b('{"blockhash":"%s","confirmations":%s}' % (BH, "1" * 20)), U)
case("tx-confirmation", "confirmations-fraction", b('{"blockhash":"%s","confirmations":1.5}' % BH), U)
case("tx-confirmation", "blockhash-path", b('{"blockhash":"../block/x","confirmations":1}'), U)
case("tx-confirmation", "blockhash-short", b('{"blockhash":"00044c37","confirmations":1}'), U)
case("tx-confirmation", "blockhash-number", b('{"blockhash":0,"confirmations":1}'), U)
case("tx-confirmation", "hex-not-read", b('{"hex":"zz","blockhash":"%s","confirmations":1}' % BH),
     ["txconf %s 1 0" % BH])
case("tx-confirmation", "root-array", b("[]"), U)
case("tx-confirmation", "size-over-cap", EXPLORER_TX, U, pad_to=CAPS["tx-confirmation"] + 1)

# block: GET {endpoint}/explorer/block/:hash
case("block", "typical", b('{"hash":"%s","height":23877512,"time":1784416468}' % BH), ["block 23877512"])
case("block", "height-missing", b('{"hash":"%s"}' % BH), ["block 0"])
case("block", "height-zero", b('{"height":0}'), ["block 0"])
case("block", "height-negative", b('{"height":-5}'), ["block -5"])
case("block", "height-string", b('{"height":"23877512"}'), U)
case("block", "height-fraction", b('{"height":23877512.0}'), U)
case("block", "height-huge", b('{"height":%d}' % (INT64_MAX + 1)), U)
case("block", "height-arabic-indic", b('{"height":٢٣}'), U)
case("block", "root-array", b("[23877512]"), U)
case("block", "malformed", b('{"height":'), U)
case("block", "size-at-cap", b('{"height":1}'), ["block 1"], pad_to=CAPS["block"])
case("block", "size-over-cap", b('{"height":1}'), U, pad_to=CAPS["block"] + 1)


# ---- writing ---------------------------------------------------------------------------------------

HEADER = """\
# Reconcile-backend answers and the rows a correct parser produces from each. Generated by
# vectors/reconcile-response/generate.py; do not edit (recovery_utxo_kat checks it is current).
# README.md states the rules and the row formats.
#
# case <kind> <id> <body file> <pad-to>     pad-to: - , or the size in bytes the body is padded to
#                                           with ASCII spaces (0x20) before it is parsed
# <row>...                                  the rows, in order; none for an answer with nothing in it
# end
#
# Rows:  chain-height <n>                                         reconcile, always first
#        utxo <txid> <vout> <amount> <height> <address> <script|->  reconcile, in the answer's order
#        rawtx <txid> <height> <time> <hex>                       reconcile, by txid ascending
#        tx <txid> <height>                                       history, in the answer's order
#        rawtx <hex> <time>                                       raw-tx
#        raw <hex>                                                tx-raw
#        txconf <blockhash|-> <confirmations> <time>              tx-confirmation
#        block <height>                                           block
#        unreadable                                               the whole answer, any kind
"""


def build():
    ids = set()
    bodies = {}
    out = [HEADER]
    problems = []
    for kind, cid, body, pad_to, expect in CASES:
        name = "%s-%s.body" % (kind, cid)
        if name in ids:
            problems.append("duplicate case %s" % name)
        ids.add(name)
        bodies[name] = body
        parsed = body if pad_to is None else body + b" " * (pad_to - len(body))
        if pad_to is not None and pad_to < len(body):
            problems.append("%s: pad-to below the body's size" % name)
        got = reference_rows(kind, parsed)
        if got != expect:
            problems.append("%s: hand-written %r, reference normaliser %r" % (name, expect, got))
        out.append("case %s %s bodies/%s %s\n" % (kind, cid, name, "-" if pad_to is None else pad_to))
        out.extend(r + "\n" for r in expect)
        out.append("end\n")
    return "".join(out), bodies, problems


def main():
    check = "--check" in sys.argv[1:]
    text, bodies, problems = build()
    if problems:
        for p in problems:
            print("DISAGREE: " + p)
        return 1
    bdir = os.path.join(HERE, "bodies")
    exp = os.path.join(HERE, "expected.txt")
    if check:
        stale = []
        try:
            with open(exp, "rb") as f:
                if f.read() != text.encode("utf-8"):
                    stale.append("expected.txt")
        except OSError:
            stale.append("expected.txt (missing)")
        present = set(os.listdir(bdir)) if os.path.isdir(bdir) else set()
        for name, body in bodies.items():
            try:
                with open(os.path.join(bdir, name), "rb") as f:
                    if f.read() != body:
                        stale.append(name)
            except OSError:
                stale.append(name + " (missing)")
        stale += ["%s (not in the corpus)" % n for n in sorted(present - set(bodies))]
        if stale:
            print("STALE: " + ", ".join(stale[:10]) + (" ..." if len(stale) > 10 else ""))
            return 1
        print("%d cases current; each hand-written expectation agrees with the reference normaliser" % len(CASES))
        return 0
    os.makedirs(bdir, exist_ok=True)
    for n in os.listdir(bdir):
        if n not in bodies:
            os.remove(os.path.join(bdir, n))
    for name, body in bodies.items():
        with open(os.path.join(bdir, name), "wb") as f:
            f.write(body)
    with open(exp, "wb") as f:
        f.write(text.encode("utf-8"))
    print("wrote %d cases" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
