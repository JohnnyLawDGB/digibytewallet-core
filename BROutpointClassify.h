//
//  BROutpointClassify.h
//
//  Where the wallet's own balance computation puts each outpoint of a list that came from elsewhere
//  (the node a reconcile scan asked), and which of the wallet's spendable outputs that list does not
//  name. Until 2026-11 this lived only in Android's JNI bridge (jni_wallet.c: classifyOutpoints and
//  spendableNotListed, behind NativeBridge.classifyOutpoints / NativeBridge.spendableNotListed). It
//  moves here unchanged so both platforms read the same answer from the same wallet; the bridge's
//  behaviour is the specification, and the host KAT outpoint_classify_kat drives the bridge and this
//  header through the same wallets and lists and requires the same answers.
//
//  INPUT. One line per outpoint, "<txid hex, 64 characters, display order>|<output index, decimal>".
//  A line is read exactly as the bridge reads it (BROutpointLineParse): longer than 65 bytes with '|'
//  at byte 64; the 64 bytes before it are the txid (uint256(), then reversed into the wallet's byte
//  order); the rest is read by strtoul(..., 10), which must consume at least one character and every
//  character to the end of the line, with a value no greater than UINT32_MAX. Anything else, and a
//  NULL line, is UNREADABLE.
//    CALLERS MUST pass a txid of exactly [0-9a-fA-F]{64}. The 64 bytes are NOT checked here: uint256()
//    is the core's own hex reader, a byte outside that set is undefined behaviour in it (a shift of a
//    negative value), and in practice such a byte reads as F, so "...zz" and "...ff" name the same
//    outpoint. A node that lists one outpoint under two spellings is then counted twice.
//    The index is read as leniently as strtoul reads: leading white space, a sign and leading zeros
//    are accepted (" 7", "+7", "007" and, by unsigned wrap, some negative spellings all read as an
//    index), and where long is 32 bits an out-of-range index reads as UINT32_MAX (NOT_HELD) rather
//    than UNREADABLE. So one outpoint has many spellings: a caller formats the index from a uint32,
//    builds each line from a validated txid and that index rather than from the node's own strings
//    (which also keeps an embedded NUL out of the line), and removes duplicates on the parsed BRUTXO,
//    never on the text.
//
//  THE CODES (BRWalletClassifyOutpoints), one per line, in order, first match wins:
//    -3 UNREADABLE    the line did not parse.
//    -1 NOT_HELD      the wallet does not hold the transaction, or it has no such output.
//    -2 CONFLICTED    the wallet holds the transaction but considers it invalid
//                     (BRWalletTransactionIsValid).
//     1 SPENDABLE     in the spendable set (BRWalletUTXOs) -- what the DGB balance sums.
//     3 DIGIDOLLAR    a DigiDollar token output (BRWalletDigiDollarUTXOs).
//     0 SPENT         the wallet holds a transaction spending the outpoint (BRWalletOutpointSpent).
//     6 PENDING       the wallet holds the transaction as pending (BRWalletTransactionIsPending).
//     5 NOT_CREDITED  the output does not pay one of the wallet's derived addresses (a watched-only
//                     pin, a foreign address, or a script with no address).
//     4 IMMATURE      a coin-generation transaction's output (one input, null prevout) to a derived
//                     address that is not in the spendable set.
//     2 HELD          an owned, valid, unspent output kept out of the spendable set (it carries
//                     DigiAsset units, explicitly or registered by the asset layer).
//    The partition arrays are private to BRWallet.c and only the spendable and DigiDollar sets have
//    locked copy accessors, so HELD is answered by elimination from the same rule the wallet's balance
//    update applies to an owned output of a valid, credited transaction: DigiDollar, else asset, else
//    spendable (immature coinbase aside). "Owned" is "derived" -- the derived prefix of one
//    BRWalletCopyAllAddrs snapshot -- because the wallet credits only derived addresses.
//
//  NOT LISTED (BRWalletSpendableNotListed). How many of the wallet's spendable outputs (BRWalletUTXOs)
//  no readable line names, and their total value (each output's amount from the wallet's copy of its
//  transaction; an output whose transaction the wallet no longer holds is counted with no value).
//  Unreadable lines name nothing. A non-zero answer means the wallet counts something the list does
//  not report.
//
//  SNAPSHOTS AND LOCKING. Exactly the bridge's sequence of calls: one address snapshot
//  (BRWalletCopyAllAddrs), one spendable-set and one DigiDollar-set copy per call (each sized by one
//  call and filled by another), then per line a transaction copy (BRWalletCopyTransactionForHash) and
//  the wallet's own predicates. Every wallet function called takes the wallet's lock itself and
//  releases it before returning; no wallet pointer is kept past one of them. The wallet's lock is not
//  recursive: the caller must NOT hold it. A platform that can free its wallet while another thread
//  reads it keeps its own guard around the call (Android: WALLET_READ_GUARD).
//    A build with assertions on (no NDEBUG) aborts when a line names an output of a coin-generation
//    transaction the wallet holds: the transaction copy adds its null-prevout input, which
//    BRTransactionAddInput asserts against. The bridge does the same. Shipped builds define NDEBUG.
//
//  COST. As the bridge: each line is checked against the spendable and DigiDollar copies by a linear
//  scan, and each spendable output against the readable lines by a linear scan, so both functions take
//  time proportional to (lines x outputs). Derived addresses are sorted once and searched by bisection.
//  The number of lines is the node's choice, and every readable line takes a full copy of its
//  transaction under the wallet's lock (and, when unconfirmed, a validity walk): a caller that cannot
//  trust the node bounds the list before calling.
//
//  RETURNS 1 with every answer written; 0 (nothing written) when the wallet is NULL, when count > 0 and
//  lines or an output pointer is NULL, or when an allocation fails -- the cases the bridge answers with
//  a null array. A count of 0 answers 1: no code is written, and NOT LISTED counts every spendable output.
//
//  Allocation: the snapshots above (malloc, freed before returning). No I/O. Header-only, static inline.
//
//  Test seams (host KAT outpoint_classify_kat in the Android repo): OUTPOINT_CLASSIFY_UNFIXED, tested by
//  VALUE as a set of bits; each comparison arm sets one bit, and the KAT requires it to differ from the
//  bridge in exactly its own cases. Unset or =0 is what ships.
//    1   OUTPOINT_CLASSIFY_RED_HELD_SPENDABLE     an owned held output answered SPENDABLE.
//    2   OUTPOINT_CLASSIFY_RED_COINBASE_HELD      the coin-generation test skipped (IMMATURE reads HELD).
//    4   OUTPOINT_CLASSIFY_RED_VALIDITY_SKIPPED   the validity test skipped (CONFLICTED never answered).
//    8   OUTPOINT_CLASSIFY_RED_DD_SKIPPED         the DigiDollar set not consulted.
//    16  OUTPOINT_CLASSIFY_RED_DERIVED_SKIPPED    every address read as derived (NOT_CREDITED never answered).
//    32  OUTPOINT_CLASSIFY_RED_TRAILING_ACCEPTED  characters after the output index accepted.
//    64  OUTPOINT_CLASSIFY_RED_LISTED_IGNORED     NOT LISTED counts every spendable output.
//    128 OUTPOINT_CLASSIFY_RED_SPENT_SKIPPED      the spent test skipped.
//    256 OUTPOINT_CLASSIFY_RED_PENDING_SKIPPED    the pending test skipped.
//

#ifndef BROutpointClassify_h
#define BROutpointClassify_h

#include "BRWallet.h"        // BRWallet, BRUTXO, BRWalletUTXOs, BRWalletCopyAllAddrs, the predicates
#include "BRTransaction.h"   // BRTransaction, BRTransactionFree
#include "BRAddress.h"       // BRAddress, BR_ADDRESS_NONE
#include "BRInt.h"           // UInt256, uint256, UInt256Reverse, UInt256Eq, UInt256IsZero
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OUTPOINT_CLASSIFY_UNFIXED
#define OUTPOINT_CLASSIFY_UNFIXED 0
#endif

#define OUTPOINT_CLASSIFY_RED_HELD_SPENDABLE     1
#define OUTPOINT_CLASSIFY_RED_COINBASE_HELD      2
#define OUTPOINT_CLASSIFY_RED_VALIDITY_SKIPPED   4
#define OUTPOINT_CLASSIFY_RED_DD_SKIPPED         8
#define OUTPOINT_CLASSIFY_RED_DERIVED_SKIPPED    16
#define OUTPOINT_CLASSIFY_RED_TRAILING_ACCEPTED  32
#define OUTPOINT_CLASSIFY_RED_LISTED_IGNORED     64
#define OUTPOINT_CLASSIFY_RED_SPENT_SKIPPED      128
#define OUTPOINT_CLASSIFY_RED_PENDING_SKIPPED    256

// The codes, as the bridge returns them (Android: WalletOutpointCode).
typedef enum {
    BR_OUTPOINT_UNREADABLE   = -3,
    BR_OUTPOINT_CONFLICTED   = -2,
    BR_OUTPOINT_NOT_HELD     = -1,
    BR_OUTPOINT_SPENT        = 0,
    BR_OUTPOINT_SPENDABLE    = 1,
    BR_OUTPOINT_HELD         = 2,
    BR_OUTPOINT_DIGIDOLLAR   = 3,
    BR_OUTPOINT_IMMATURE     = 4,
    BR_OUTPOINT_NOT_CREDITED = 5,
    BR_OUTPOINT_PENDING      = 6
} BROutpointCode;

// Reads one "txidHex|vout" line. Returns 1 and sets *hash (wallet byte order) and *n, or 0 (nothing set).
static inline int BROutpointLineParse(const char *s, UInt256 *hash, uint32_t *n)
{
    if (! (s && strlen(s) > 65 && s[64] == '|')) return 0;
    char hex[65];
    char *end = NULL;
    memcpy(hex, s, 64);
    hex[64] = '\0';
    unsigned long v = strtoul(s + 65, &end, 10);
#if OUTPOINT_CLASSIFY_UNFIXED & OUTPOINT_CLASSIFY_RED_TRAILING_ACCEPTED
    if (! (end && end != s + 65 && v <= UINT32_MAX)) return 0;
#else
    if (! (end && *end == '\0' && end != s + 65 && v <= UINT32_MAX)) return 0;
#endif
    if (hash) *hash = UInt256Reverse(uint256(hex));   // display order -> the wallet's byte order
    if (n) *n = (uint32_t)v;
    return 1;
}

static inline int _BROutpointAddrCompare(const void *a, const void *b)
{
    return strcmp(((const BRAddress *)a)->s, ((const BRAddress *)b)->s);
}

static inline int _BROutpointListHas(const BRUTXO *list, size_t n, UInt256 hash, uint32_t idx)
{
    for (size_t i = 0; i < n; i++) if (list[i].n == idx && UInt256Eq(list[i].hash, hash)) return 1;
    return 0;
}

// One line's code against one call's snapshots.
static inline int32_t _BROutpointCodeOf(BRWallet *wallet, const char *s, const BRAddress *addrs, size_t nDerived,
                                        const BRUTXO *utxos, size_t nUtxo, const BRUTXO *dds, size_t nDd)
{
    int32_t code = BR_OUTPOINT_UNREADABLE;
    UInt256 hash;
    uint32_t n;

    if (BROutpointLineParse(s, &hash, &n)) {
        // a copy taken under the wallet lock: no wallet pointer is kept past it
        BRTransaction *tx = BRWalletCopyTransactionForHash(wallet, hash);
#if OUTPOINT_CLASSIFY_UNFIXED
        const int red = OUTPOINT_CLASSIFY_UNFIXED;
        if (! tx || n >= tx->outCount) code = BR_OUTPOINT_NOT_HELD;
        else if (! (red & OUTPOINT_CLASSIFY_RED_VALIDITY_SKIPPED) && ! BRWalletTransactionIsValid(wallet, tx))
            code = BR_OUTPOINT_CONFLICTED;
        else if (_BROutpointListHas(utxos, nUtxo, hash, n)) code = BR_OUTPOINT_SPENDABLE;
        else if (! (red & OUTPOINT_CLASSIFY_RED_DD_SKIPPED) && _BROutpointListHas(dds, nDd, hash, n))
            code = BR_OUTPOINT_DIGIDOLLAR;
        else if (! (red & OUTPOINT_CLASSIFY_RED_SPENT_SKIPPED) && BRWalletOutpointSpent(wallet, hash, n))
            code = BR_OUTPOINT_SPENT;
        else if (! (red & OUTPOINT_CLASSIFY_RED_PENDING_SKIPPED) && BRWalletTransactionIsPending(wallet, tx))
            code = BR_OUTPOINT_PENDING;
        else {
            BRAddress key = BR_ADDRESS_NONE;
            strncpy(key.s, tx->outputs[n].address, sizeof(key.s) - 1);
            int derived = (red & OUTPOINT_CLASSIFY_RED_DERIVED_SKIPPED) ||
                          (key.s[0] != '\0' && nDerived > 0 &&
                           bsearch(&key, addrs, nDerived, sizeof(*addrs), _BROutpointAddrCompare) != NULL);
            int coinbase = ! (red & OUTPOINT_CLASSIFY_RED_COINBASE_HELD) &&
                           tx->inCount == 1 && UInt256IsZero(tx->inputs[0].txHash) &&
                           tx->inputs[0].index == UINT32_MAX;
            if (! derived) code = BR_OUTPOINT_NOT_CREDITED;
            else if (coinbase) code = BR_OUTPOINT_IMMATURE;
            else code = (red & OUTPOINT_CLASSIFY_RED_HELD_SPENDABLE) ? BR_OUTPOINT_SPENDABLE : BR_OUTPOINT_HELD;
        }
#else
        if (! tx || n >= tx->outCount) code = BR_OUTPOINT_NOT_HELD;
        else if (! BRWalletTransactionIsValid(wallet, tx)) code = BR_OUTPOINT_CONFLICTED;
        else if (_BROutpointListHas(utxos, nUtxo, hash, n)) code = BR_OUTPOINT_SPENDABLE;
        else if (_BROutpointListHas(dds, nDd, hash, n)) code = BR_OUTPOINT_DIGIDOLLAR;
        else if (BRWalletOutpointSpent(wallet, hash, n)) code = BR_OUTPOINT_SPENT;
        else if (BRWalletTransactionIsPending(wallet, tx)) code = BR_OUTPOINT_PENDING;
        else {
            BRAddress key = BR_ADDRESS_NONE;
            strncpy(key.s, tx->outputs[n].address, sizeof(key.s) - 1);
            int derived = key.s[0] != '\0' && nDerived > 0 &&
                          bsearch(&key, addrs, nDerived, sizeof(*addrs), _BROutpointAddrCompare) != NULL;
            int coinbase = tx->inCount == 1 && UInt256IsZero(tx->inputs[0].txHash) &&
                           tx->inputs[0].index == UINT32_MAX;
            if (! derived) code = BR_OUTPOINT_NOT_CREDITED;
            else if (coinbase) code = BR_OUTPOINT_IMMATURE;
            else code = BR_OUTPOINT_HELD;
        }
#endif
        if (tx) BRTransactionFree(tx);
    }
    return code;
}

// Writes one BROutpointCode per line to codes[0..count). See the header comment for the codes and RETURNS.
static inline int BRWalletClassifyOutpoints(BRWallet *wallet, const char *const lines[], size_t count,
                                            int32_t codes[])
{
    if (! wallet || (count > 0 && (! lines || ! codes))) return 0;

    // One snapshot of each set for the whole call.
    size_t nAddr = 0;
    BRWalletAddrOrigins origins = { 0, 0 };
    BRAddress *addrs = BRWalletCopyAllAddrs(wallet, &nAddr, &origins);
    size_t nDerived = addrs ? origins.derived : 0;
    if (addrs && nDerived > 1) qsort(addrs, nDerived, sizeof(*addrs), _BROutpointAddrCompare);

    size_t nUtxo = BRWalletUTXOs(wallet, NULL, 0);
    BRUTXO *utxos = (BRUTXO *)malloc((nUtxo ? nUtxo : 1) * sizeof(BRUTXO));
    size_t nDd = BRWalletDigiDollarUTXOs(wallet, NULL, 0);
    BRUTXO *dds = (BRUTXO *)malloc((nDd ? nDd : 1) * sizeof(BRUTXO));
    if (! utxos || ! dds || (nAddr > 0 && ! addrs)) {
        free(addrs); free(utxos); free(dds);
        return 0;
    }
    nUtxo = BRWalletUTXOs(wallet, utxos, nUtxo);
    nDd = BRWalletDigiDollarUTXOs(wallet, dds, nDd);

    for (size_t k = 0; k < count; k++)
        codes[k] = _BROutpointCodeOf(wallet, lines[k], addrs, nDerived, utxos, nUtxo, dds, nDd);

    free(addrs); free(utxos); free(dds);
    return 1;
}

// The wallet's spendable outputs no readable line names: their number in *notListedCount and their total
// value in *notListedSat. See the header comment for NOT LISTED and RETURNS.
static inline int BRWalletSpendableNotListed(BRWallet *wallet, const char *const lines[], size_t count,
                                             int64_t *notListedCount, int64_t *notListedSat)
{
    if (! wallet || ! notListedCount || ! notListedSat || (count > 0 && ! lines)) return 0;
    BRUTXO *listed = (BRUTXO *)calloc(count > 0 ? count : 1, sizeof(BRUTXO));
    if (! listed) return 0;
    size_t nListed = 0;
    for (size_t k = 0; k < count; k++) {
        if (BROutpointLineParse(lines[k], &listed[nListed].hash, &listed[nListed].n)) nListed++;
    }

    size_t nUtxo = BRWalletUTXOs(wallet, NULL, 0);
    BRUTXO *utxos = (BRUTXO *)malloc((nUtxo ? nUtxo : 1) * sizeof(BRUTXO));
    if (! utxos) { free(listed); return 0; }
    nUtxo = BRWalletUTXOs(wallet, utxos, nUtxo);

    int64_t out[2] = { 0, 0 };
    for (size_t i = 0; i < nUtxo; i++) {
#if OUTPOINT_CLASSIFY_UNFIXED & OUTPOINT_CLASSIFY_RED_LISTED_IGNORED
        (void)nListed;
#else
        if (_BROutpointListHas(listed, nListed, utxos[i].hash, utxos[i].n)) continue;
#endif
        BRTransaction *tx = BRWalletCopyTransactionForHash(wallet, utxos[i].hash);   // under the lock
        out[0]++;
        if (tx && utxos[i].n < tx->outCount) out[1] += (int64_t)tx->outputs[utxos[i].n].amount;
        if (tx) BRTransactionFree(tx);
    }
    free(listed); free(utxos);

    *notListedCount = out[0];
    *notListedSat = out[1];
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BROutpointClassify_h
