//
//  BRDigiDollarTransferLayout.h
//
//  The consensus-significant shape of a DigiDollar TRANSFER, for a caller that assembles one outside the
//  wallet's own builder. Until 2026-11 this lived in Android's JNI bridge
//  (native/src/main/jni/bridge/digidollar_transfer_layout.h), where the recovery transfer -- the dollars
//  of another seed moved to this wallet -- is assembled. Moved unchanged. Getting any of it wrong
//  destroys dollars, and the interesting parts -- the nVersion marker, the OP_RETURN bytes, the order of
//  the outputs -- are cheap to check on a host and expensive to discover on a device holding someone's
//  money.
//
//  Every value here is mirrored from BRWalletCreateDigiDollarTransfer (BRWallet.c), the builder the
//  wallet's own send uses, whose copies are private to that file (DD_MIN_FEE, DD_MIN_OUTPUT_CENTS,
//  DD_MAX_OUTPUT_CENTS, the 0x02000770 version), and cross-checked against a real mainnet DigiDollar
//  transaction (40a78f1306123354...) whose marker reads 6a 02 'DD' 01 02 01 64 -- $1.00. The host KAT
//  holds the two copies together.
//
//  THE ORDERING RULE. That builder carries the comment "NO shuffle (output order is
//  consensus-significant)". The order is: recipient P2TR at value 0, then optional DD change, then
//  optional DGB change, and the OP_RETURN LAST. A transfer whose outputs are rearranged is not the same
//  transfer.
//
//    BRDigiDollarRecipientScript  the P2TR scriptPubKey that pays a taproot output key: OP_1 <push32>
//                                 X(Q). Always 34 bytes. The key is used verbatim -- a DigiDollar
//                                 recipient key is already tweaked, and re-tweaking it would pay an
//                                 address nobody holds. key32 and out must not be NULL.
//    BRDigiDollarOpReturnScript   the DigiDollar OP_RETURN: 6a 02 'D' 'D' 01 02 <push cents>
//                                 [<push ddChange>]. The second push exists only when ddChangeCents > 0.
//                                 Returns the bytes written, or 0 when out is NULL, outLen is under 8, or
//                                 they would not fit: never a truncated marker.
//    BRDigiDollarCentsInRange     whether a cent amount is inside the per-output consensus range.
//
//  Header-only, static inline; no I/O, no clock, no locking, no allocation. No test seam: the host KAT
//  (digidollar_transfer_layout_core_kat in the Android repo) pins the values.
//

#ifndef BRDigiDollarTransferLayout_h
#define BRDigiDollarTransferLayout_h

#include "BRDigiDollar.h"   // BRDigiDollarWriteScriptNum
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// nVersion of a DD TRANSFER: 0x0770 marker in the low 16 bits, type 2 in the top byte.
#define BR_DIGIDOLLAR_TX_VERSION_TRANSFER 0x02000770u

// The fee floor of a DigiDollar transaction: 0.1 DGB. Not an estimate -- below this the transfer is not
// accepted however well-formed.
#define BR_DIGIDOLLAR_MIN_FEE 10000000ULL

// Per-output consensus bounds, in cents.
#define BR_DIGIDOLLAR_MIN_OUTPUT_CENTS 100LL        // $1.00
#define BR_DIGIDOLLAR_MAX_OUTPUT_CENTS 10000000LL   // $100,000

// Writes the P2TR scriptPubKey that pays a taproot output key: OP_1 <push32> X(Q). Always 34 bytes.
static inline size_t BRDigiDollarRecipientScript(const uint8_t key32[32], uint8_t out[34])
{
    out[0] = 0x51;  // OP_1
    out[1] = 0x20;  // push 32
    memcpy(out + 2, key32, 32);
    return 34;
}

// Writes the DigiDollar OP_RETURN: 6a 02 'D' 'D' 01 02 <push cents> [<push ddChange>]. ddChangeCents is
// 0 for no change output. Returns the bytes written, or 0 if they would not fit.
static inline size_t BRDigiDollarOpReturnScript(int64_t cents, int64_t ddChangeCents, uint8_t *out, size_t outLen)
{
    if (!out || outLen < 8) return 0;
    size_t ol = 0;
    out[ol++] = 0x6a;                                       // OP_RETURN
    out[ol++] = 0x02; out[ol++] = 0x44; out[ol++] = 0x44;   // push2 "DD"
    out[ol++] = 0x01; out[ol++] = 0x02;                     // push1 type = 2 (TRANSFER)

    uint8_t enc[9];
    size_t el = BRDigiDollarWriteScriptNum(cents, enc);
    if (el == 0 || ol + 1 + el > outLen) return 0;
    out[ol++] = (uint8_t)el; memcpy(out + ol, enc, el); ol += el;

    if (ddChangeCents > 0) {
        el = BRDigiDollarWriteScriptNum(ddChangeCents, enc);
        if (el == 0 || ol + 1 + el > outLen) return 0;
        out[ol++] = (uint8_t)el; memcpy(out + ol, enc, el); ol += el;
    }
    return ol;
}

// Whether a cent amount is inside the per-output consensus range.
static inline int BRDigiDollarCentsInRange(int64_t cents)
{
    return cents >= BR_DIGIDOLLAR_MIN_OUTPUT_CENTS && cents <= BR_DIGIDOLLAR_MAX_OUTPUT_CENTS;
}

#ifdef __cplusplus
}
#endif

#endif // BRDigiDollarTransferLayout_h
