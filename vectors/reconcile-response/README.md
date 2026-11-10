# reconcile-response fixtures

The answers of the reconcile backend (`api.digiscope.me/api`, or a user's own endpoint) that both
wallets parse, each with the rows a correct parser produces from it. JSON parsing stays each
platform's own (it is transport); these fixtures bind the two parsers, so a quoted balance, a sweep's
inputs and a confirmation come out the same from the same bytes. The rows then feed the core's rules
(`BRRecoveryUtxo.h` for a recovery scan's UTXOs).

- `bodies/<kind>-<id>.body`: the exact bytes of one answer (some are deliberately not JSON, or not UTF-8).
- `expected.txt`: for each case, its kind, body, padding and expected rows. Its header repeats the row formats.
- `generate.py`: the corpus. Every expectation in it is hand-written; the generator also runs a strict
  reference normaliser of the rules below and refuses to write when the two disagree. Regenerate with
  `python3 -I generate.py`; `--check` verifies the files are current (the host KAT
  `recovery_utxo_kat` in digibytewallet-android runs it). The normaliser is a generator aid, not a
  shipped parser.

A binding test reads `expected.txt`, feeds each body (padded with ASCII spaces to `pad-to` bytes when
one is given) to its platform's parser for that kind, writes the parser's answer as rows in the format
below, and compares the text.

## Kinds

| kind | request | Android today |
|---|---|---|
| `reconcile` | `POST {endpoint}/wallet/reconcile` `{"addresses":[...]}` | `DgbNodeClient.parseReconcileResponse` |
| `history` | `GET {endpoint}/rpc/address-history/:address`, `POST {endpoint}/rpc/address-history` | `parseAddressHistory` |
| `raw-tx` | `GET {endpoint}/explorer/tx/:txid`, read for its transaction | `parseRawTxResponse` (`fetchRawTx`) |
| `tx-raw` | `GET {endpoint}/tx/raw/:txid` | `fetchRawTransaction` |
| `tx-confirmation` | `GET {endpoint}/explorer/tx/:txid`, read for its confirmation | `txConfirmation`, first request |
| `block` | `GET {endpoint}/explorer/block/:hash` | `txConfirmation`, second request |

`raw-tx` and `tx-confirmation` read the same answer for different fields; each reads only its own, so a
bad `hex` does not spoil a confirmation, nor a bad `blockhash` a transaction.

## The rules

**Unreadable.** Any failure makes the whole answer `unreadable`: the same outcome as an unreachable
backend, never a partial answer. A parser never drops one bad row and keeps the rest, because a list
missing a row looks complete.

**The document.**
- At most the kind's cap: `reconcile` 33,554,432 bytes (32 MiB), `history` 16,777,216 (16 MiB), every
  explorer kind 8,388,608 (8 MiB). Exactly the cap is read; one byte over is unreadable.
- UTF-8, no byte order mark, strict RFC 8259 JSON: no comments, single quotes, trailing commas, `NaN` or
  `Infinity`, leading zeros or `+`; one value, then only JSON whitespace (space, tab, LF, CR).
- No object has the same name twice. No string holds a lone surrogate (`\ud800`). Nesting is at most
  64 deep (the root object is depth 1).
- The root is an object. Names a kind does not read are ignored, but must still be valid JSON.

**Fields.** "Absent" means the name is missing or its value is `null`.
- Integer: a JSON number with no fraction and no exponent (`6000`; not `6000.0`, `6e3` or `"6000"`), in
  the signed 64-bit range. `-0` is 0. Digits are ASCII `0`-`9` only (JSON's grammar); any other digit
  (Arabic-Indic, fullwidth, ...) makes the document invalid.
- The parser checks only that a value is representable. Zero and negative amounts, heights, times and
  confirmations are passed through as they came; what they mean is the core's rule (a non-positive
  amount refuses a sweep, a height of 0 or below is unconfirmed). The one range it does check is
  `vout`, an output index: 0 to 4,294,967,295.
- Hex: a string of ASCII `0-9a-fA-F`, written lowercase in rows. A txid or blockhash is exactly 64 hex
  digits; transaction or script hex is a non-empty, even number of them.
- A string field holding a number (or a number field holding a string) is unreadable, not converted.

**reconcile.** `{"utxos":[...], "rawTxs":{...}, "height":n}`
- `height` (the chain height): integer, absent = 0.
- `utxos`: required, an array (empty is fine). Each element is an object with `txid` (64 hex), `vout`
  (0..2^32-1), `amountSatoshi` (integer), `address` (a string of 1-128 printable ASCII characters,
  0x21-0x7E) and `height` (integer), all required, and `scriptPubKey`: absent or `""` is none (`-`),
  otherwise hex.
- Rows keep the answer's order and every row: a repeated outpoint is two rows. Collapsing it is the
  core's rule (`BRRecoveryUtxoDedup`), not the parser's.
- `rawTxs`: absent = none; otherwise an object whose names are txids (64 hex; two names that are the
  same txid in different case are a repeated name) and whose values are objects with `hex` (hex),
  `height` and `time` (integers), all required. Rows are by txid ascending.

**history.** `{"transactions":[{"txid":...,"height":n}, ...]}`
- `transactions` absent = no entries; otherwise an array of objects.
- An entry whose `txid` is absent or `""` is skipped (its `height`, when present, must still be an
  integer); any other `txid` is 64 hex. `height` is an integer, absent = 0.
- Rows keep the answer's order, repeats included (planning the import is `BRReconcilePlan`'s).

**raw-tx.** `hex`: absent or `""` is unreadable, otherwise hex. The time is `blocktime` when present,
else `time` when present, else 0 (integers; the one not used is not read). The height is the caller's,
from the history entry, so it is not in the row.

**tx-raw.** `hex` when present and not `""`, otherwise `rawtx`; neither is unreadable. A bad `hex` is
unreadable: it does not fall back to `rawtx`.

**tx-confirmation.** `blockhash`: absent or `""` is none (`-`), otherwise 64 hex. `confirmations`:
integer, absent = 0. The time as for raw-tx. A transaction is confirmed at block height H and that
time when its blockhash is not `-`, its confirmations are above 0, and the `block` answer for that
blockhash gives H above 0. Otherwise it is not confirmed (yet).

**block.** `height`: integer, absent = 0.

## Rows

```
chain-height <n>                                           reconcile: always the first row
utxo <txid> <vout> <amount> <height> <address> <script|->  reconcile: one per element, in order
rawtx <txid> <height> <time> <hex>                         reconcile: one per rawTxs entry, by txid
tx <txid> <height>                                         history: in order
rawtx <hex> <time>                                         raw-tx
raw <hex>                                                  tx-raw
txconf <blockhash|-> <confirmations> <time>                tx-confirmation
block <height>                                             block
unreadable                                                 any kind: the whole answer
```

Numbers are decimal, with `-` for negatives. Hex is lowercase. A case with no rows between `case` and
`end` is an answer with nothing in it (for example a history with no transactions), which is not the
same as `unreadable`.

## Where Android's parser differs today

These come from reading `DgbNodeClient.kt` on android `develop` (2026-11-10). A binding test will confirm
or correct them; each is a change to the Kotlin parser, not to these fixtures.

- **A JSON `null` read through `optString` (the largest difference on a device).** Android's own
  org.json returns the string `"null"` from `optString(name, fallback)` when the value is JSON null,
  not the fallback; the JVM `org.json:json` artifact the unit tests run against returns the fallback.
  So on a device: `scriptPubKey: null` becomes the script `"null"`; a history `txid: null` becomes the
  txid `"null"` instead of being skipped; a raw-tx `hex: null` passes the `isBlank` check; and a
  `blockhash: null` passes the empty check and requests `/explorer/block/null`. The unit tests and the
  device disagree on all four. Here every one of them is absent (`script-null`, `history`
  `blank-txid-skipped`, `raw-tx` `hex-null`, `tx-raw` `hex-null-falls-back`).
- org.json is lenient: it accepts some non-RFC syntax (single quotes, unquoted names, comments), and its
  `getLong`/`optLong`/`getInt` convert numeric strings and truncate fractions. How it treats repeated
  names and integers beyond 64 bits differs between the reference and Android's org.json.
- Hex and txids are kept as given: not checked, not lowercased.
- `reconcile`: a `rawTxs` of the wrong type reads as none.
- `history`: a non-object entry, or a whitespace-only txid, is skipped; a `transactions` of the wrong
  type reads as no entries.
- `tx-raw`: the hex is decoded with `Char.digitToInt(16)`, which also accepts non-ASCII decimal digits
  and fullwidth letters.
- `tx-confirmation`: the blockhash is used to build the block request without being checked.
- `reconcile`: `vout` is read with `getInt`, which truncates a value above 2,147,483,647 (INT32_MAX)
  instead of refusing it; here a `vout` is 0 to 4,294,967,295 and anything else is unreadable.
- No nesting limit.

Android unit tests that change when its parser is bound to these fixtures:
- `AddressHistoryParseTest.blank_txid_entries_skipped` keeps the entry with the toy txid `"aa"`; here a
  txid is 64 hex digits, so that body is unreadable.
- `AddressHistoryParseTest.parses_raw_tx_hex_and_time_with_supplied_height` uses the 8-digit blockhash
  `"00044c37"` (and txid `"8096"`); read as a `tx-confirmation`, that body is unreadable here (the
  fixtures' `raw-tx`/`tx-confirmation` bodies use a 64-digit blockhash beginning `00044c37`).
