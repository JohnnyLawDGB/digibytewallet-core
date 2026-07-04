//
//  BRDigiDollar.h
//
//  DigiDollar (DD) SHOW decoder: pure, read-only classification and amount
//  extraction for DigiDollar transactions. No wallet/balance/JNI/UI wiring
//  here -- this module only answers "is this a DD tx, and what are its
//  per-output cent amounts." See docs/superpowers/specs/2026-07-04-digidollar-wire-format.md
//  for the pinned wire format this implements.
//
//  Created for DigiDollar SHOW decoder Task 1 (.superpowers/sdd/task-1-brief.md).
//

#ifndef BRDigiDollar_h
#define BRDigiDollar_h

#include "BRTransaction.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DD_VERSION_MARKER 0x0770u   // (tx->version & 0xFFFF) for any DigiDollar tx
#define DD_TYPE_MINT      1
#define DD_TYPE_TRANSFER  2
#define DD_TYPE_REDEEM    3

// Returns the DigiDollar tx type (1=MINT, 2=TRANSFER, 3=REDEEM), or 0 if `tx` is
// not a DigiDollar transaction (marker absent or type out of {1,2,3}).
int BRDigiDollarTxType(const BRTransaction *tx);

// Decodes the DD OP_RETURN cent-amount list into `amounts` (up to `maxAmounts`
// entries). Type-aware: TRANSFER -> all remaining pushes, MINT/REDEEM -> first push
// only. Returns the number of amounts written (>= 0), or -1 if `tx` is not a DD tx
// or the OP_RETURN is malformed / non-minimally-encoded / overflows `maxAmounts`.
int BRDigiDollarDecodeAmounts(const BRTransaction *tx, int64_t *amounts, size_t maxAmounts);

// Returns the DD cent amount bound to output `voutIndex` by DD-output ordinal
// (spec §3.2 Phase B), or -1 if that output is not a DD token output (OP_RETURN,
// nonzero value, or not a 34-byte OP_1 P2TR) or if no amount slot binds to it.
int64_t BRDigiDollarOutputAmount(const BRTransaction *tx, size_t voutIndex);

#ifdef __cplusplus
}
#endif

#endif // BRDigiDollar_h
