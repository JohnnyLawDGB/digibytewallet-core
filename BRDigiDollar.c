//
//  BRDigiDollar.c
//
//  DigiDollar (DD) SHOW decoder implementation. See BRDigiDollar.h for the
//  public API contract and docs/superpowers/specs/2026-07-04-digidollar-wire-format.md
//  for the pinned wire format.
//
//  Task 1 (.superpowers/sdd/task-1-brief.md) implements only the tx-version
//  classifier, BRDigiDollarTxType. BRDigiDollarDecodeAmounts and
//  BRDigiDollarOutputAmount are stubbed here and implemented in later tasks.
//

#include "BRDigiDollar.h"

int BRDigiDollarTxType(const BRTransaction *tx)
{
    if (! tx) return 0;
    if ((tx->version & 0xFFFFu) != DD_VERSION_MARKER) return 0;
    int type = (int)((tx->version >> 24) & 0xFFu);
    if (type == DD_TYPE_MINT || type == DD_TYPE_TRANSFER || type == DD_TYPE_REDEEM) return type;
    return 0;
}

// stubs (implemented in later tasks)
int BRDigiDollarDecodeAmounts(const BRTransaction *tx, int64_t *amounts, size_t maxAmounts) { return -1; }
int64_t BRDigiDollarOutputAmount(const BRTransaction *tx, size_t voutIndex) { return -1; }
