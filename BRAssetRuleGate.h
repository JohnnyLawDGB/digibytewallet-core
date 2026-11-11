//
//  BRAssetRuleGate.h
//
//  Whether a DigiAsset may move by a plain transfer, from what the wallet knows of its issuance and what
//  the asset proxy said about its transfer rules. Until 2026-11 this lived only in Android's Kotlin
//  (core/.../asset/rules/TransferRuleState.kt, AssetTransferRuleGate.stateOf, and in AssetManager.kt the
//  identity check of verifyTransferRules). It moves here unchanged: every input the Kotlin answers gets
//  the same answer here.
//
//  WHY IT REFUSES. DigiAsset Core re-checks an asset's transfer rules (royalty, deflation, signers, vote,
//  KYC, expiry) on every indexer. A transfer that breaks one has the assets on EVERY output cleared and
//  its inputs spent, so the sender's whole input holding is destroyed while a wallet that builds no rule
//  outputs reports success. Only NONE may move; anything the wallet cannot prove is UNKNOWN.
//
//  THE RULES:
//    - THE STATE (BRAssetRuleStateOf), from the issuance opcode the provenance walk recorded (or none),
//      that issuance's locked flag (or none) and the proxy's answer (a rules object, none, or no answer),
//      in this order:
//        an opcode of 3 or 4 (an issuance that carries rules)   -> BOUND, whatever else is known;
//        the proxy returned a rules object                      -> BOUND;
//        an opcode of 1, 2 or 5 AND the issuance is locked      -> NONE;
//        anything else                                          -> UNKNOWN.
//      An unlocked rule-free issuance is UNKNOWN: a later reissuance of an unlocked asset can attach
//      rules to an asset first issued without them. The proxy's answer can only tighten the verdict: an
//      answer without a rules object never turns UNKNOWN into NONE. No opcode is UNKNOWN unless the proxy
//      says BOUND. An opcode outside the issuance set is UNKNOWN. The proxy's answer is "a rules object"
//      when it returned a `rules` key whose object has at least one member (DigiAsset Core emits the key
//      only for non-empty rules); reading that from the JSON is the platform's.
//    - THE ASSET ASKED ABOUT (BRAssetRuleStateForAsset). A verdict is about the asset whose facts it was
//      computed from. It is the answer for the asset asked about only when those facts name that asset
//      (the same id, byte for byte); facts for another asset, or no facts at all, are UNKNOWN. A row the
//      walk has not yet named carries a placeholder id, and the walk's answer names the derived id, so a
//      placeholder never takes the derived asset's verdict.
//    - SENDING (BRAssetRuleAllowsSend): only NONE. A value this header does not define does not.
//
//  THE ENUM is BRSweepRuleState (BRSweepPartition.h): one enum for one meaning, Android's TransferRuleState
//  in its order (NONE 0, BOUND 1, UNKNOWN 2), so the recovery sweep's rule lookup (BRSweepRuleStateRead)
//  and the send gate read the same values. UNKNOWN and BOUND both mean "do not move this asset".
//
//  Kotlin's nullable inputs (Int?, Boolean?) are has/value pairs here: `has` zero is null, and the value is
//  then not read. A Boolean value is true when nonzero.
//
//  No allocation, no wallet, no network, no clock, no I/O. Header-only, static inline; its includes are
//  libc and BRSweepPartition.h (BRSweepRuleState), which this header uses and does not redefine. It reads
//  no build-time policy macro. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_provenance_rules_kat in the Android repo): ASSET_RULE_GATE_UNFIXED, tested
//  by VALUE as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0
//  is what ships.
//    1   ASSET_RULE_GATE_RED_API_LOOSENS     a proxy answer without rules stands in for the lock.
//    2   ASSET_RULE_GATE_RED_UNLOCKED_FINAL  a rule-free opcode is NONE whether or not it is locked.
//    4   ASSET_RULE_GATE_RED_API_IGNORED     the proxy's rules object is not read.
//    8   ASSET_RULE_GATE_RED_OPCODE_4_FREE   only opcode 3 is read as carrying rules.
//    16  ASSET_RULE_GATE_RED_ANY_OPCODE_FREE a locked issuance of any opcode but 3 and 4 is NONE.
//    32  ASSET_RULE_GATE_RED_OTHER_ASSET     the verdict for the facts' asset is taken for the one asked.
//    64  ASSET_RULE_GATE_RED_UNKNOWN_SENDS   UNKNOWN allows a send.
//

#ifndef BRAssetRuleGate_h
#define BRAssetRuleGate_h

#include "BRSweepPartition.h"   // BRSweepRuleState: BR_SWEEP_RULE_NONE / _BOUND / _UNKNOWN
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_RULE_GATE_UNFIXED
#define ASSET_RULE_GATE_UNFIXED 0
#endif

#define ASSET_RULE_GATE_RED_API_LOOSENS      1
#define ASSET_RULE_GATE_RED_UNLOCKED_FINAL   2
#define ASSET_RULE_GATE_RED_API_IGNORED      4
#define ASSET_RULE_GATE_RED_OPCODE_4_FREE    8
#define ASSET_RULE_GATE_RED_ANY_OPCODE_FREE  16
#define ASSET_RULE_GATE_RED_OTHER_ASSET      32
#define ASSET_RULE_GATE_RED_UNKNOWN_SENDS    64

// Does the issuance opcode carry a rules block (3, 4)?
static inline int _BRAssetRuleOpcodeBound(int32_t opcode)
{
#if (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_OPCODE_4_FREE)
    return opcode == 3;
#else
    return opcode == 3 || opcode == 4;
#endif
}

// Is the issuance opcode one of the rule-free issuances (1, 2, 5)?
static inline int _BRAssetRuleOpcodeFree(int32_t opcode)
{
#if (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_ANY_OPCODE_FREE)
    return ! _BRAssetRuleOpcodeBound(opcode);
#else
    return opcode == 1 || opcode == 2 || opcode == 5;
#endif
}

// The state (see THE RULES). hasOpcode/opcode: the issuance opcode the walk recorded; hasLocked/locked: its
// locked flag; hasApiRules/apiRules: the proxy answered (has) with a rules object (apiRules nonzero) or
// without one (zero).
static inline BRSweepRuleState BRAssetRuleStateOf(int hasOpcode, int32_t opcode, int hasLocked, int locked,
                                                  int hasApiRules, int apiRules)
{
    if (hasOpcode && _BRAssetRuleOpcodeBound(opcode)) return BR_SWEEP_RULE_BOUND;
#if ! (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_API_IGNORED)
    if (hasApiRules && apiRules) return BR_SWEEP_RULE_BOUND;
#else
    (void)hasApiRules; (void)apiRules;
#endif
#if (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_UNLOCKED_FINAL)
    (void)hasLocked; (void)locked;
    if (hasOpcode && _BRAssetRuleOpcodeFree(opcode)) return BR_SWEEP_RULE_NONE;
#elif (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_API_LOOSENS)
    if (hasOpcode && _BRAssetRuleOpcodeFree(opcode) && ((hasLocked && locked) || (hasApiRules && ! apiRules)))
        return BR_SWEEP_RULE_NONE;
#else
    if (hasOpcode && _BRAssetRuleOpcodeFree(opcode) && hasLocked && locked) return BR_SWEEP_RULE_NONE;
#endif
    return BR_SWEEP_RULE_UNKNOWN;
}

// The state for the asset askedAssetId (see THE ASSET ASKED ABOUT). factsAssetId is the id the facts name,
// NULL when there are none; the other arguments are BRAssetRuleStateOf's, read from those facts and the
// proxy's answer for that id. UNKNOWN when askedAssetId is NULL.
static inline BRSweepRuleState BRAssetRuleStateForAsset(const char *askedAssetId, const char *factsAssetId,
                                                        int hasOpcode, int32_t opcode, int hasLocked, int locked,
                                                        int hasApiRules, int apiRules)
{
    if (! askedAssetId || ! factsAssetId) return BR_SWEEP_RULE_UNKNOWN;
#if ! (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_OTHER_ASSET)
    if (strcmp(askedAssetId, factsAssetId) != 0) return BR_SWEEP_RULE_UNKNOWN;
#endif
    return BRAssetRuleStateOf(hasOpcode, opcode, hasLocked, locked, hasApiRules, apiRules);
}

// May an asset in this state be sent? 1 only for NONE.
static inline int BRAssetRuleAllowsSend(BRSweepRuleState state)
{
#if (ASSET_RULE_GATE_UNFIXED & ASSET_RULE_GATE_RED_UNKNOWN_SENDS)
    return state == BR_SWEEP_RULE_NONE || state == BR_SWEEP_RULE_UNKNOWN;
#else
    return state == BR_SWEEP_RULE_NONE;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetRuleGate_h
