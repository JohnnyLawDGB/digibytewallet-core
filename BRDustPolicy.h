//
//  BRDustPolicy.h
//
//  The smallest output the network relays, by output script, as DigiByte Core 9.26 decides it.
//  A payment below its line is built, signed and broadcast, and then refused by every node, so a
//  send is refused before anything is built, and every output of the built transaction is held to
//  the same line before it is signed. Until 2026-10 this lived in Kotlin (DustPolicy.kt).
//
//  The rule is Core's GetDustThreshold / IsDust (src/policy/policy.cpp) at Core's dust relay fee,
//  DUST_RELAY_TX_FEE = 30,000 sat/kvB (src/policy/policy.h), ten times Bitcoin's:
//    line = 30,000 x (the serialized output + the input that would spend it) / 1,000, rounded up,
//  where that input is a P2WPKH spend (67 vbytes, its witness discounted) for a witness program and
//  a P2PKH spend (148 bytes) for any other script. An unspendable output (a script starting
//  OP_RETURN, or one over 10,000 bytes) has no line.
//
//      output                  serialized   + spend   line (sat)
//      legacy P2PKH (D...)             34       148        5,460
//      script hash P2SH (S...)         32       148        5,400
//      native segwit P2WPKH            31        67        2,940
//      P2WSH, Taproot P2TR             43        67        3,300
//      unspendable (data)               -         -            0
//
//  DigiDollar token outputs carry no DGB by protocol. Core relays them below the line: a
//  zero-value output whose script is 34 bytes starting OP_1, inside a transaction that carries the
//  DigiDollar version marker with a type Core knows (IsDigiDollarDustExemptOutput, IsStandardTx).
//  Every other output of a DigiDollar transaction keeps its line. This exemption is a SEND rule
//  only: it decides whether an output this wallet is about to sign would be refused. It says
//  nothing about what the wallet credits (BRDigiDollarOutputAmount decides that, by its own,
//  stricter shape). Whether a transaction is a DigiDollar transaction is BRDigiDollarTxType
//  (BRDigiDollar.h) != 0, the same rule as DustPolicy.isDigiDollarTransaction; it is not
//  restated here.
//
//  Not TX_MIN_OUTPUT_AMOUNT (BRTransaction.h): 54,600 sat for every script (3 x TX_FEE_PER_KB over
//  a 34-byte output and a 148-byte input), the floor the wallet's builder folds change under and
//  its pending check holds an unconfirmed transaction's outputs to. It is ten times this rule's
//  P2PKH line and is not the relay rule; the two are not reconciled here.
//
//  Differences from the Kotlin: a NULL script is read as an empty one (Kotlin cannot pass one).
//  Amounts are int64_t, as Kotlin's Long: a negative amount is below every line, and an amount
//  above INT64_MAX (none is valid, MAX_MONEY is far below it) reads as negative and is dust.
//
//  Host KAT: digibytewallet-android native/src/test/host/dust_policy_kat/.
//  Header-only, static inline, no state.
//

#ifndef BRDustPolicy_h
#define BRDustPolicy_h

#include "BRAddress.h"   // OP_0, OP_1, OP_16, OP_RETURN, BRVarIntSize
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// DigiByte Core's dust relay fee, sat/kvB (DUST_RELAY_TX_FEE).
#define BR_DUST_RELAY_FEE_PER_KB      30000
// Core's MAX_SCRIPT_SIZE: a longer script is unspendable.
#define BR_DUST_MAX_SCRIPT_SIZE       10000
// The input that would spend an output, in bytes: a P2PKH spend, 32 + 4 + 1 + 107 + 4 ...
#define BR_DUST_SPEND_SIZE            148
// ... or, for a witness program, a P2WPKH spend with its witness discounted: 32 + 4 + 1 + 107/4 + 4.
#define BR_DUST_WITNESS_SPEND_SIZE    67
// A DigiDollar token output's script length: OP_1 and a 32-byte push.
#define BR_DUST_DD_TOKEN_SCRIPT_SIZE  34

// The lines of the standard scripts, in satoshis. Plain literals, so Swift's C importer sees them
// (it skips expression macros); each is checked against the rule at compile time below.
#define BR_DUST_P2PKH_SATS            5460   // 25-byte script
#define BR_DUST_P2SH_SATS             5400   // 23-byte script
#define BR_DUST_P2WPKH_SATS           2940   // 22-byte script
#define BR_DUST_P2WSH_SATS            3300   // 34-byte script
#define BR_DUST_P2TR_SATS             3300   // 34-byte script

#define _BR_DUST_LINE(scriptLen, spend) \
    ((BR_DUST_RELAY_FEE_PER_KB * (8 + 1 + (scriptLen) + (spend)) + 999) / 1000)
typedef char _BRDustSpendIsP2PKHInput[(BR_DUST_SPEND_SIZE == 32 + 4 + 1 + 107 + 4) ? 1 : -1];
typedef char _BRDustWitnessSpendIsP2WPKHInput[(BR_DUST_WITNESS_SPEND_SIZE == 32 + 4 + 1 + 107 / 4 + 4) ? 1 : -1];
typedef char _BRDustP2PKHLine[(BR_DUST_P2PKH_SATS == _BR_DUST_LINE(25, BR_DUST_SPEND_SIZE)) ? 1 : -1];
typedef char _BRDustP2SHLine[(BR_DUST_P2SH_SATS == _BR_DUST_LINE(23, BR_DUST_SPEND_SIZE)) ? 1 : -1];
typedef char _BRDustP2WPKHLine[(BR_DUST_P2WPKH_SATS == _BR_DUST_LINE(22, BR_DUST_WITNESS_SPEND_SIZE)) ? 1 : -1];
typedef char _BRDustP2WSHLine[(BR_DUST_P2WSH_SATS == _BR_DUST_LINE(34, BR_DUST_WITNESS_SPEND_SIZE)) ? 1 : -1];
typedef char _BRDustP2TRLine[(BR_DUST_P2TR_SATS == _BR_DUST_LINE(34, BR_DUST_WITNESS_SPEND_SIZE)) ? 1 : -1];
#undef _BR_DUST_LINE

// Core's CScript::IsUnspendable: a data output (OP_RETURN first), or a script over
// BR_DUST_MAX_SCRIPT_SIZE.
static inline int BRDustScriptIsUnspendable(const uint8_t *script, size_t scriptLen)
{
    if (! script) scriptLen = 0;
    return (scriptLen > 0 && script[0] == OP_RETURN) || scriptLen > BR_DUST_MAX_SCRIPT_SIZE;
}

// Core's CScript::IsWitnessProgram: a version opcode (OP_0, or OP_1 to OP_16), then one push of
// 2 to 40 bytes that is the whole rest of the script.
static inline int BRDustScriptIsWitnessProgram(const uint8_t *script, size_t scriptLen)
{
    if (! script || scriptLen < 4 || scriptLen > 42) return 0;
    if (script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16)) return 0;
    return (size_t)script[1] + 2 == scriptLen;
}

// The dust line for an output paying script, in satoshis (Core's GetDustThreshold): 0 for an
// unspendable script, else between 2,400 and 304,770.
static inline int64_t BRDustThreshold(const uint8_t *script, size_t scriptLen)
{
    int64_t size;

    if (! script) scriptLen = 0;
    if (BRDustScriptIsUnspendable(script, scriptLen)) return 0;
    size = 8 + (int64_t)BRVarIntSize(scriptLen) + (int64_t)scriptLen;
    size += BRDustScriptIsWitnessProgram(script, scriptLen) ? BR_DUST_WITNESS_SPEND_SIZE : BR_DUST_SPEND_SIZE;
#ifdef DUST_POLICY_RED_RATE
    // RED ARM SEAM (dust_policy_kat): Bitcoin's dust relay fee, 3,000 sat/kvB (a 546-sat P2PKH line).
    return (3000 * size + 999) / 1000;
#else
    return (BR_DUST_RELAY_FEE_PER_KB * size + 999) / 1000;   // CFeeRate::GetFee, rounded up
#endif
}

// True for a DigiDollar token output, which Core relays below the line inside a DigiDollar
// transaction. txIsDigiDollar: BRDigiDollarTxType(tx) != 0 for the transaction the output is in.
static inline int BRDustIsDigiDollarExempt(int64_t amount, const uint8_t *script, size_t scriptLen,
                                           int txIsDigiDollar)
{
#if defined(DUST_POLICY_RED_NO_EXEMPTION)
    // RED ARM SEAM (dust_policy_kat): no exemption; every DigiDollar send is refused.
    (void)amount; (void)script; (void)scriptLen; (void)txIsDigiDollar;
    return 0;
#elif defined(DUST_POLICY_RED_ANY_ZERO)
    // RED ARM SEAM (dust_policy_kat): any zero-value output is exempt, in any transaction.
    (void)script; (void)scriptLen; (void)txIsDigiDollar;
    return amount == 0;
#else
    return txIsDigiDollar && amount == 0 && script && scriptLen == BR_DUST_DD_TOKEN_SCRIPT_SIZE &&
           script[0] == OP_1;
#endif
}

// True when an output of amount satoshis paying script is below its line and not exempt: every
// node would refuse the transaction that carries it.
static inline int BRDustIsDust(int64_t amount, const uint8_t *script, size_t scriptLen, int txIsDigiDollar)
{
    return amount < BRDustThreshold(script, scriptLen) &&
           ! BRDustIsDigiDollarExempt(amount, script, scriptLen, txIsDigiDollar);
}

#ifdef __cplusplus
}
#endif

#endif // BRDustPolicy_h
