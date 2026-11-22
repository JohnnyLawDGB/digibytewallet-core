// The reader of vectors/asset-tx-amount's lines, shared by generate.c and the host KAT asset_tx_amount_kat
// (Android repo) so the two build each case the same way. A test helper, not a core header: it prints nothing
// and allocates only each case's transaction (txaFree releases it), and nothing that ships includes it.
//
// THE LINE (fields separated by one space):
//
//   amount <name> <send> <outputs> <ownership> <rows> [-> <status> <units> <assetId>]
//
//   <send>       1 a send (the row amount is below zero), 0 a receive
//   <outputs>    - : no transaction (the wallet has none); otherwise its outputs in order, comma-separated,
//                each <script hex>:<o|f|d>, o one of the wallet's own, f someone else's, d a data output (read
//                as f). The transaction is version 1 with one input (00..01:0) and the txid's hash; every
//                output's value is 600 satoshis, a data output's 0.
//   <ownership>  all: the owned set is the scripts marked o; none: the owned set is empty
//   <rows>       - : none; otherwise comma-separated, each <t|x>/<credit>/<quantity>/<spent>/<isAsset>/<id|->[/<vout>],
//                t the transaction's txid, x another's; credit U B V M (UNCHECKED BACKED VERIFIED MIXED); the
//                row's vout is <vout> when given (0 or above), otherwise its place in the list
//   the answer   OK|NONE|REFUSED, the units, the asset id or -
//
// The transaction's txid is TXA_TXID, the other TXA_OTHER, both display order.

#ifndef asset_tx_amount_read_h
#define asset_tx_amount_read_h

#include "BRAssetTxAmount.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define TXA_TXID  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define TXA_OTHER "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define TXA_MAX_OUTPUTS 16
#define TXA_MAX_ROWS 8
#define TXA_MAX_SCRIPT 80

typedef struct {
    char name[64];
    int send;
    BRTransaction *tx;                                 // NULL: none
    uint8_t scripts[TXA_MAX_OUTPUTS][TXA_MAX_SCRIPT];
    BRAssetScript owned[TXA_MAX_OUTPUTS];
    size_t ownedCount;
    BRAssetRow rows[TXA_MAX_ROWS];
    char ids[TXA_MAX_ROWS][80];
    size_t rowCount;
    int hasAnswer;                                     // the line carried "-> ..."
    BRAssetTxAmountStatus status;
    int64_t units;
    char assetId[80];                                  // "" for -
} TxaCase;

static int _txaHex(const char *s, size_t n, uint8_t *out, size_t cap, size_t *len)
{
    size_t i;

    if (n % 2 || n / 2 > cap) return 0;
    for (i = 0; i < n / 2; i++) {
        unsigned v;
        char b[3] = { s[2 * i], s[2 * i + 1], 0 };

        if (sscanf(b, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 1;
}

// Reads `line` into c (c->tx allocated; txaFree releases it). 1 on success.
static int txaRead(const char *line, TxaCase *c)
{
    char buf[2048], *fields[10], *save = NULL, *f;
    size_t nf = 0, i;
    UInt256 prev;

    memset(c, 0, sizeof(*c));
    if (strlen(line) >= sizeof(buf)) return 0;
    strcpy(buf, line);
    buf[strcspn(buf, "\r\n")] = 0;
    for (f = strtok_r(buf, " ", &save); f && nf < 10; f = strtok_r(NULL, " ", &save)) fields[nf++] = f;
    if ((nf != 6 && nf != 10) || strcmp(fields[0], "amount") != 0 || strlen(fields[1]) >= sizeof(c->name)) return 0;
    strcpy(c->name, fields[1]);
    c->send = strcmp(fields[2], "1") == 0;

    if (strcmp(fields[3], "-") != 0) {
        char *o, *osave = NULL;
        size_t n = 0;

        c->tx = BRTransactionNew();
        c->tx->version = 1;
        memset(&prev, 0, sizeof(prev));
        prev.u8[0] = 1;
        BRTransactionAddInput(c->tx, prev, 0, 0, NULL, 0, NULL, 0, NULL, 0, TXIN_SEQUENCE);
        for (o = strtok_r(fields[3], ",", &osave); o; o = strtok_r(NULL, ",", &osave)) {
            char *colon = strrchr(o, ':');
            size_t len = 0;

            if (! colon || n >= TXA_MAX_OUTPUTS || ! _txaHex(o, (size_t)(colon - o), c->scripts[n], TXA_MAX_SCRIPT, &len)) return 0;
            BRTransactionAddOutput(c->tx, colon[1] == 'd' ? 0 : 600, c->scripts[n], len);
            if (colon[1] == 'o' && strcmp(fields[4], "all") == 0) {
                c->owned[c->ownedCount].bytes = c->scripts[n];
                c->owned[c->ownedCount].len = len;
                c->ownedCount++;
            }
            n++;
        }
        // the txid's hash, display order reversed
        for (i = 0; i < 32; i++) c->tx->txHash.u8[i] = 0xcc;
    }

    if (strcmp(fields[5], "-") != 0) {
        char *r, *rsave = NULL;

        for (r = strtok_r(fields[5], ",", &rsave); r; r = strtok_r(NULL, ",", &rsave)) {
            char *p[7], *psave = NULL, *q, *end = NULL;
            size_t np = 0;
            BRAssetRow *row;

            if (c->rowCount >= TXA_MAX_ROWS) return 0;
            for (q = strtok_r(r, "/", &psave); q && np < 7; q = strtok_r(NULL, "/", &psave)) p[np++] = q;
            if (q || (np != 6 && np != 7) || strlen(p[5]) >= sizeof(c->ids[0])) return 0;
            row = &c->rows[c->rowCount];
            row->txid = p[0][0] == 't' ? TXA_TXID : TXA_OTHER;
            row->vout = (int32_t)c->rowCount;
            if (np == 7) {
                long v = strtol(p[6], &end, 10);

                if (end == p[6] || *end != 0 || v < 0 || v > INT32_MAX) return 0;
                row->vout = (int32_t)v;
            }
            row->credit = p[1][0] == 'B' ? BR_ASSET_CREDIT_BACKED : p[1][0] == 'V' ? BR_ASSET_CREDIT_VERIFIED :
                          p[1][0] == 'M' ? BR_ASSET_CREDIT_MIXED : BR_ASSET_CREDIT_UNCHECKED;
            row->assetQuantity = strtoll(p[2], NULL, 10);
            row->spent = strcmp(p[3], "1") == 0;
            row->isAsset = strcmp(p[4], "1") == 0;
            row->source = BR_ASSET_SOURCE_NATIVE;
            if (strcmp(p[5], "-") != 0) {
                strcpy(c->ids[c->rowCount], p[5]);
                row->assetId = c->ids[c->rowCount];
            }
            c->rowCount++;
        }
    }

    if (nf == 10) {
        if (strcmp(fields[6], "->") != 0 || strlen(fields[9]) >= sizeof(c->assetId)) return 0;
        c->hasAnswer = 1;
        c->status = strcmp(fields[7], "OK") == 0 ? BR_ASSET_TX_AMOUNT_OK : strcmp(fields[7], "NONE") == 0 ?
                    BR_ASSET_TX_AMOUNT_NONE : BR_ASSET_TX_AMOUNT_REFUSED;
        c->units = strtoll(fields[8], NULL, 10);
        if (strcmp(fields[9], "-") != 0) strcpy(c->assetId, fields[9]);
    }
    return 1;
}

static BRAssetTxAmount txaRun(const TxaCase *c)
{
    return BRAssetTxActivityAmount(TXA_TXID, c->send, c->rows, c->rowCount, c->tx, c->owned, c->ownedCount);
}

static const char *txaStatusName(BRAssetTxAmountStatus s)
{
    return s == BR_ASSET_TX_AMOUNT_OK ? "OK" : s == BR_ASSET_TX_AMOUNT_NONE ? "NONE" : "REFUSED";
}

static void txaFree(TxaCase *c)
{
    if (c->tx) BRTransactionFree(c->tx);
    c->tx = NULL;
}

#endif
