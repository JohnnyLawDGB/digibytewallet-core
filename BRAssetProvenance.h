//
//  BRAssetProvenance.h
//
//  How a wallet names the asset a DigiAsset transfer carries: by walking the transfer back, first input
//  by first input, to the issuance that created the asset. A transfer's OP_RETURN carries no asset
//  identity, only an issuance does. Until 2026-11 this lived only in Android's Kotlin
//  (core/.../asset/AssetProvenanceWalker.kt; in AssetManager.kt classifyProvenanceHopFrom and
//  factsForNamedAsset). It moves here unchanged: every input the Kotlin answers gets the same answer here
//  (a hop on the transaction the core's parser reads from bytes that are exactly it), and the platform
//  executing it makes the same store reads and writes and asks for the same hops in the same order.
//
//  A SPECIFICATION, NOT AN EXECUTOR. The walk reads a store and fetches transactions, and both stay the
//  platform's. The header owns the decisions: the platform asks it what is needed next (BRAssetWalkStep,
//  BRAssetFactsForNamedAsset), does that one thing, and hands back what it found. The header never calls
//  out, never waits and never fetches.
//
//  THE RULES:
//    - ONE HOP (BRAssetHopClassify): what one transaction is to the walk, from the transaction the
//      platform fetched by its id. The platform passes whether it got bytes at all, and the transaction
//      the core's parser (BRTransactionParseSigned) read from them, or NULL when they do not parse. The
//      platform takes the wallet's own copy of the transaction first; bytes from anywhere else are
//      accepted only when they hash to the id asked for (BRRawTxId, BRRawTxBinding.h), and are otherwise
//      no bytes.
//        no bytes                                                     -> UNAVAILABLE (weather: retry);
//        then the transaction's FIRST output whose script begins OP_RETURN (0x6a) is decoded
//        (BRAssetDecodeHeader); no such output, bytes that do not parse, a script that is not a
//        carrier, and a tagged carrier that cannot be classified     -> DEAD END;
//        an ISSUANCE that is not locked                               -> DEAD END (its id is computed
//                                                                        from a script this is not given);
//        an ISSUANCE with no first input, or whose id is refused
//        (BRAssetIdForIssuance, BRAssetId.h)                          -> DEAD END;
//        an ISSUANCE                                                  -> ISSUANCE, with its facts: the
//          derived id, the amount issued, the divisibility, the metadata CID (BRAssetMetadataCid) when it
//          has one, the opcode, and locked;
//        a TRANSFER with no first input                               -> DEAD END;
//        a TRANSFER                                                   -> TRANSFER to the transaction its
//          first input spends (display-order hex, lower case);
//        a BURN                                                       -> DEAD END.
//      The first input is the parser's inputs[0]: its txid in display order and its output index read as
//      a signed 32-bit number.
//    - THE WALK (BRAssetWalkBegin, BRAssetWalkStep), from startTxid, with forceToIssuance and a budget of
//      maxHops hops per attempt:
//        1. Unless forced, the store's facts for startTxid answer at once (no write).
//        2. The store's frontier for startTxid, if it has one, says where to resume (resumeTxid) and how
//           many hops earlier attempts walked (hopsWalked); otherwise the walk starts at startTxid with 0.
//        3. Then, at most maxHops times, for the current txid:
//             seen before in THIS attempt (a cycle)        -> clear the frontier; no answer;
//             unless forced, the store has facts for it    -> memoise them for the PATH; clear the
//                                                             frontier; answer them;
//             its hop is ISSUANCE                          -> memoise the facts for the PATH and the
//                                                             current txid; clear the frontier; answer;
//             TRANSFER                                     -> the current txid joins the PATH; walk on to
//                                                             the parent;
//             UNAVAILABLE                                  -> put the frontier (startTxid, the current
//                                                             txid, hopsWalked + the hops this attempt);
//                                                             no answer;
//             DEAD END                                     -> clear the frontier; no answer.
//        4. Out of budget: put the frontier (startTxid, the current txid, hopsWalked + maxHops); no answer.
//      The PATH is startTxid and every transfer this attempt walked through, in order, each once. A
//      walk that ends writes at most two things, in this order: the path's facts, then the frontier. The
//      budget bounds work, not reach: an attempt that runs out keeps its place and the next one goes on.
//      Hop counts are added modulo 2^32 and read as a signed 32-bit number.
//      maxHops of 0 or less walks no hop and puts the frontier where the walk would have started.
//    - THE NAMED ASSET (BRAssetFactsForNamedAssetBegin, BRAssetFactsForNamedAsset). Facts for assetId:
//      the store's issuance facts for it (the platform answers none when the walk is forced), then the
//      walk from startTxid, then the walk from each transaction the other inputs of startTxid spend
//      (asked for only then; repeats and startTxid itself skipped, the rest in order). An answer is
//      taken only when it names assetId itself: the id is derived from its issuance, so a walk that
//      reaches that issuance from any input yields that asset's own facts, while the asset another
//      input's lineage reaches says nothing about this one. None when no answer names it.
//    - ISSUANCE FACTS (BRAssetIssuanceFactsMatch): a store's answer for "the issuance facts of an asset"
//      is a row naming that asset that recorded the issuance opcode. A row written without the opcode
//      does not answer.
//
//  TXIDS are NUL-terminated strings of at most BR_ASSET_TXID_LENGTH characters, compared byte for byte;
//  a longer one is refused. Facts' ids are at most BR_ASSET_ID_LENGTH characters. Kotlin nullables are
//  has/value pairs (`has` zero: null, the value not read). The walk copies every txid it keeps into the
//  caller's slots (BR_ASSET_WALK_SLOTS(maxHops), or BRAssetWalkSlots(maxHops), of them; fewer is refused,
//  CAPACITY); the named search keeps the caller's pointers (assetId, startTxid, the parent list), which
//  the caller keeps alive until it is done. A walk or a search that is REFUSED (an argument, a fed value
//  it cannot hold, too few slots) has no answer and writes nothing; every enum here has REFUSED or
//  UNAVAILABLE at 0, so a struct nobody filled reads as no answer.
//
//  No allocation, no wallet, no network, no clock, no I/O. Header-only, static inline; its includes are
//  libc, BRTransaction.h (BRTransaction, read only, no function of it called), BRAssetDecode.h
//  (BRAssetDecodeHeader, BRAssetMetadataCid) and BRAssetId.h (BRAssetIdForIssuance, so a program that
//  calls BRAssetHopClassify links BRCrypto.c and BRBase58.c), which this header uses and does not
//  redefine. It reads no build-time policy macro. Nothing in the core calls it yet.
//
//  Test seams (host KAT asset_provenance_rules_kat in the Android repo): ASSET_PROVENANCE_UNFIXED, tested
//  by VALUE as a set of bits; each comparison arm sets one bit and fails only its own cases. Unset or =0
//  is what ships.
//    1      ASSET_PROVENANCE_RED_NO_RESUME          the frontier is not read: every attempt starts over.
//    2      ASSET_PROVENANCE_RED_UNAVAILABLE_CLEARS a transaction that could not be fetched clears the frontier.
//    4      ASSET_PROVENANCE_RED_DEAD_END_KEEPS     a dead end puts a frontier.
//    8      ASSET_PROVENANCE_RED_NO_CYCLE_CHECK     a txid seen before in the attempt is walked again.
//    16     ASSET_PROVENANCE_RED_ANCESTOR_IGNORED   only the start txid's facts are read from the store.
//    32     ASSET_PROVENANCE_RED_FORCE_READS_CACHE  a forced walk answers from the store.
//    64     ASSET_PROVENANCE_RED_PATH_START_ONLY    only the start txid is memoised.
//    128    ASSET_PROVENANCE_RED_HOPS_NOT_CARRIED   a frontier counts this attempt's hops only.
//    256    ASSET_PROVENANCE_RED_UNLOCKED_NAMED     an unlocked issuance is given the locked id.
//    512    ASSET_PROVENANCE_RED_NO_BYTES_DEAD_END  no bytes is a dead end.
//    1024   ASSET_PROVENANCE_RED_BURN_WALKS         a burn is walked through to its first input.
//    2048   ASSET_PROVENANCE_RED_OTHER_ASSET        a walk's answer for another asset is taken.
//    4096   ASSET_PROVENANCE_RED_PARENTS_NOT_TRIED  the other inputs' transactions are not walked.
//    8192   ASSET_PROVENANCE_RED_PARENTS_REPEATED   a repeated parent, and the start txid, are walked again.
//    16384  ASSET_PROVENANCE_RED_ISSUANCE_ANY_ROW   a row without the issuance opcode answers for the issuance.
//    32768  ASSET_PROVENANCE_RED_KNOWN_UNCHECKED    the store's issuance facts are taken without the id check.
//

#ifndef BRAssetProvenance_h
#define BRAssetProvenance_h

#include "BRTransaction.h"   // BRTransaction, BRTxInput, BRTxOutput (read only)
#include "BRAssetDecode.h"   // BRAssetDecodeHeader, BRAssetMetadataCid, BRAssetHeader
#include "BRAssetId.h"       // BRAssetIdForIssuance, BR_ASSET_ID_BUFFER
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASSET_PROVENANCE_UNFIXED
#define ASSET_PROVENANCE_UNFIXED 0
#endif

#define ASSET_PROVENANCE_RED_NO_RESUME          1
#define ASSET_PROVENANCE_RED_UNAVAILABLE_CLEARS 2
#define ASSET_PROVENANCE_RED_DEAD_END_KEEPS     4
#define ASSET_PROVENANCE_RED_NO_CYCLE_CHECK     8
#define ASSET_PROVENANCE_RED_ANCESTOR_IGNORED   16
#define ASSET_PROVENANCE_RED_FORCE_READS_CACHE  32
#define ASSET_PROVENANCE_RED_PATH_START_ONLY    64
#define ASSET_PROVENANCE_RED_HOPS_NOT_CARRIED   128
#define ASSET_PROVENANCE_RED_UNLOCKED_NAMED     256
#define ASSET_PROVENANCE_RED_NO_BYTES_DEAD_END  512
#define ASSET_PROVENANCE_RED_BURN_WALKS         1024
#define ASSET_PROVENANCE_RED_OTHER_ASSET        2048
#define ASSET_PROVENANCE_RED_PARENTS_NOT_TRIED  4096
#define ASSET_PROVENANCE_RED_PARENTS_REPEATED   8192
#define ASSET_PROVENANCE_RED_ISSUANCE_ANY_ROW   16384
#define ASSET_PROVENANCE_RED_KNOWN_UNCHECKED    32768

// A txid's length in characters (display-order hex), and the bytes that hold it with the NUL after it.
#define BR_ASSET_TXID_LENGTH 64
#define BR_ASSET_TXID_BUFFER 65

// Hops per attempt (Android: AssetProvenanceWalker.DEFAULT_MAX_HOPS_PER_ATTEMPT).
#define BR_ASSET_WALK_DEFAULT_MAX_HOPS 50

// The slots a walk with this budget needs: one per hop and one for the start txid. A plain macro over the
// caller's value, so C can size an array with it; for the default budget, 51.
#define BR_ASSET_WALK_SLOTS(maxHops) ((size_t)((maxHops) > 0 ? (maxHops) : 0) + 1)

// The same count as a function, for callers that cannot use a function-like macro (Swift imports none).
static inline size_t BRAssetWalkSlots(int32_t maxHops)
{
    return BR_ASSET_WALK_SLOTS(maxHops);
}

// ---- the types -----------------------------------------------------------------------------------

// On-chain facts about an asset, from its issuance header (Android: ResolvedAssetFacts).
typedef struct {
    char assetId[BR_ASSET_ID_BUFFER];        // NUL-terminated
    int64_t totalSupply;
    int32_t divisibility;
    int hasMetadataCid;
    char metadataCid[BR_ASSET_CID_BUFFER];   // NUL-terminated; read only when hasMetadataCid
    int hasIssuanceOpcode;                   // a row written before the opcode was kept has none
    int32_t issuanceOpcode;                  // 1..5
    int hasIssuanceLocked;                   // none when hasIssuanceOpcode is
    int issuanceLocked;
} BRAssetResolvedFacts;

// What one transaction is to the walk (Android: AssetProvenanceWalker.Hop). UNAVAILABLE is 0.
typedef enum {
    BR_ASSET_HOP_UNAVAILABLE = 0,   // temporarily unreadable: the walk keeps its progress
    BR_ASSET_HOP_DEAD_END = 1,      // terminally unresolvable: the walk drops its progress
    BR_ASSET_HOP_TRANSFER = 2,      // a transfer: the asset came from parentTxid
    BR_ASSET_HOP_ISSUANCE = 3       // the issuance: the walk's destination, with its facts
} BRAssetHopKind;

typedef struct {
    BRAssetHopKind kind;
    char parentTxid[BR_ASSET_TXID_BUFFER];   // TRANSFER: display-order hex, lower case
    BRAssetResolvedFacts facts;              // ISSUANCE
} BRAssetHop;

// A txid the walk keeps, in the caller's buffer.
typedef struct {
    char txid[BR_ASSET_TXID_BUFFER];
} BRAssetTxidSlot;

// What the walk needs next. REFUSED is 0.
typedef enum {
    BR_ASSET_WALK_REFUSED = 0,        // nothing more: no answer, nothing to write (see `why`)
    BR_ASSET_WALK_NEEDS_KNOWN = 1,    // the store's facts for `ask` (feed.has, feed.facts)
    BR_ASSET_WALK_NEEDS_FRONTIER = 2, // the store's frontier for `ask`, the start txid (feed.has,
                                      // feed.resumeTxid, feed.hopsWalked)
    BR_ASSET_WALK_NEEDS_HOP = 3,      // BRAssetHopClassify of the transaction `ask` (feed.hop)
    BR_ASSET_WALK_DONE = 4            // write what the walk says, in order; take its answer
} BRAssetWalkNeed;

typedef enum {
    BR_ASSET_WALK_WHY_NONE = 0,
    BR_ASSET_WALK_WHY_ARGUMENT = 1,   // a NULL walk, txid or slot buffer
    BR_ASSET_WALK_WHY_TXID = 2,       // a txid longer than BR_ASSET_TXID_LENGTH, given or fed
    BR_ASSET_WALK_WHY_CAPACITY = 3,   // fewer slots than BR_ASSET_WALK_SLOTS(maxHops)
    BR_ASSET_WALK_WHY_FEED = 4        // fed facts whose text does not end in its buffer, or a hop kind
                                      // this header does not define
} BRAssetWalkWhy;

// What a finished walk does to the frontier.
typedef enum {
    BR_ASSET_FRONTIER_KEEP = 0,       // nothing
    BR_ASSET_FRONTIER_CLEAR = 1,      // clear the start txid's frontier
    BR_ASSET_FRONTIER_PUT = 2         // put (start txid, frontierResume, frontierHops)
} BRAssetFrontierWrite;

// What the platform found, for the need the walk asked about. Only that need's fields are read.
typedef struct {
    int has;                          // NEEDS_KNOWN, NEEDS_FRONTIER: the store holds one
    BRAssetResolvedFacts facts;       // NEEDS_KNOWN
    const char *resumeTxid;           // NEEDS_FRONTIER
    int32_t hopsWalked;               // NEEDS_FRONTIER
    BRAssetHop hop;                   // NEEDS_HOP
} BRAssetWalkFeed;

// One walk (Android: one AssetProvenanceWalker.resolve). Read `need`, `ask` and, once DONE, the answer and
// the writes; every other field is the walk's own.
typedef struct {
    BRAssetWalkNeed need;
    BRAssetWalkWhy why;                           // REFUSED: the reason
    char ask[BR_ASSET_TXID_BUFFER];               // the txid NEEDS_KNOWN / NEEDS_FRONTIER / NEEDS_HOP asks about

    // DONE:
    int hasAnswer;
    BRAssetResolvedFacts answer;
    size_t pathCount;                             // > 0: memoise `answer` for slots[0, pathCount) first
    BRAssetFrontierWrite frontier;                // then this
    char frontierResume[BR_ASSET_TXID_BUFFER];    // PUT
    int32_t frontierHops;                         // PUT

    // the walk's own:
    BRAssetTxidSlot *slots;
    size_t slotCap;
    size_t seen;                                  // slots[1, 1 + seen): the txids visited this attempt
    char start[BR_ASSET_TXID_BUFFER];
    char current[BR_ASSET_TXID_BUFFER];
    int force;
    int32_t maxHops;
    int32_t priorHops;
    int32_t step;
    int stage;
} BRAssetWalk;

// What the named search needs next. REFUSED is 0.
typedef enum {
    BR_ASSET_NAMED_REFUSED = 0,       // bad arguments or a fed value it cannot read: no answer
    BR_ASSET_NAMED_NEEDS_KNOWN = 1,   // the store's issuance facts for the asset (feed.facts, NULL none);
                                      // none when the walk is forced
    BR_ASSET_NAMED_NEEDS_RESOLVE = 2, // the answer of a whole walk from `ask` (feed.facts, NULL none)
    BR_ASSET_NAMED_NEEDS_PARENTS = 3, // the transactions the other inputs of the start txid spend
                                      // (feed.parents[0, feed.parentCount))
    BR_ASSET_NAMED_DONE = 4           // hasAnswer, answer
} BRAssetNamedNeed;

typedef struct {
    const BRAssetResolvedFacts *facts;
    const char *const *parents;
    size_t parentCount;
} BRAssetNamedFeed;

// One search (Android: one factsForNamedAsset). Read `need`, `ask` and, once DONE, the answer.
typedef struct {
    BRAssetNamedNeed need;
    const char *ask;                  // NEEDS_RESOLVE: the txid to walk from (the caller's pointer)
    int hasAnswer;
    BRAssetResolvedFacts answer;

    // the search's own:
    const char *assetId;
    const char *startTxid;
    const char *const *parents;
    size_t parentCount;
    size_t next;
    int stage;
} BRAssetNamedSearch;

// ---- small helpers -------------------------------------------------------------------------------

// Copies `src` into dst[BR_ASSET_TXID_BUFFER]: 1, or 0 (and nothing copied) when it is NULL or longer than
// BR_ASSET_TXID_LENGTH.
static inline int _BRAssetTxidCopy(char *dst, const char *src)
{
    size_t n = 0;

    if (! src) return 0;
    while (n <= BR_ASSET_TXID_LENGTH && src[n] != '\0') n++;
    if (n > BR_ASSET_TXID_LENGTH) return 0;
    memcpy(dst, src, n + 1);
    return 1;
}

static inline int _BRAssetTextEnds(const char *text, size_t cap)
{
    return memchr(text, '\0', cap) != NULL;
}

// Facts whose texts end in their buffers.
static inline int _BRAssetFactsWellFormed(const BRAssetResolvedFacts *f)
{
    return f && _BRAssetTextEnds(f->assetId, sizeof(f->assetId)) &&
           (! f->hasMetadataCid || _BRAssetTextEnds(f->metadataCid, sizeof(f->metadataCid)));
}

// Does this store row answer "the issuance facts of assetId" (see ISSUANCE FACTS)? 1 or 0; 0 for NULL
// arguments and for facts whose id does not end in its buffer.
static inline int BRAssetIssuanceFactsMatch(const BRAssetResolvedFacts *facts, const char *assetId)
{
    if (! facts || ! assetId || ! _BRAssetTextEnds(facts->assetId, sizeof(facts->assetId))) return 0;
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_ISSUANCE_ANY_ROW)
    return strcmp(facts->assetId, assetId) == 0;
#else
    return strcmp(facts->assetId, assetId) == 0 && facts->hasIssuanceOpcode;
#endif
}

// ---- one hop -------------------------------------------------------------------------------------

static inline BRAssetHop _BRAssetHopOf(BRAssetHopKind kind)
{
    BRAssetHop hop;

    memset(&hop, 0, sizeof(hop));
    hop.kind = kind;
    return hop;
}

// The first input's txid in display order, lower-case hex, into out[BR_ASSET_TXID_BUFFER].
static inline void _BRAssetHopTxidHex(const UInt256 *txHash, char *out)
{
    static const char digits[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 32; i++) {
        uint8_t b = txHash->u8[31 - i];

        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 0x0f];
    }
    out[64] = '\0';
}

// What the transaction is to the walk (see ONE HOP). fetched: the platform got bytes for it. tx: the core
// parser's reading of them, NULL when they do not parse (read only when fetched).
static inline BRAssetHop BRAssetHopClassify(int fetched, const BRTransaction *tx)
{
    const uint8_t *script = NULL;
    size_t i, scriptLen = 0;
    BRAssetHeader header;
    BRAssetHop hop;
    char firstTxid[BR_ASSET_TXID_BUFFER] = { 0 };

    if (! fetched) {
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_NO_BYTES_DEAD_END)
        return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
#else
        return _BRAssetHopOf(BR_ASSET_HOP_UNAVAILABLE);
#endif
    }
    if (! tx) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);

    for (i = 0; tx->outputs && i < tx->outCount; i++) {
        const BRTxOutput *out = &tx->outputs[i];

        if (out->scriptLen > 0 && out->script != NULL && out->script[0] == 0x6a) {
            script = out->script;
            scriptLen = out->scriptLen;
            break;
        }
    }
    if (! script) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
    if (BRAssetDecodeHeader(script, scriptLen, &header) != BR_ASSET_SCRIPT_ASSET) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);

    switch (header.operation) {
    case DA_ISSUANCE:
#if ! (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_UNLOCKED_NAMED)
        if (! header.locked) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
#endif
        if (! tx->inputs || tx->inCount < 1) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
        hop = _BRAssetHopOf(BR_ASSET_HOP_ISSUANCE);
        _BRAssetHopTxidHex(&tx->inputs[0].txHash, firstTxid);
        if (! BRAssetIdForIssuance(firstTxid, (int32_t)tx->inputs[0].index, 1, header.aggregation, header.divisibility,
                                   hop.facts.assetId, sizeof(hop.facts.assetId)))
            return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
        hop.facts.totalSupply = header.hasTotalQuantity ? header.totalQuantity : 0;
        hop.facts.divisibility = header.divisibility;
        hop.facts.hasMetadataCid = BRAssetMetadataCid(&header, hop.facts.metadataCid, sizeof(hop.facts.metadataCid)) > 0;
        hop.facts.hasIssuanceOpcode = 1;
        hop.facts.issuanceOpcode = header.opcode;
        hop.facts.hasIssuanceLocked = 1;
        hop.facts.issuanceLocked = header.locked ? 1 : 0;
        return hop;

    case DA_TRANSFER:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_BURN_WALKS)
    case DA_BURN:
#endif
        if (! tx->inputs || tx->inCount < 1) return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
        hop = _BRAssetHopOf(BR_ASSET_HOP_TRANSFER);
        _BRAssetHopTxidHex(&tx->inputs[0].txHash, hop.parentTxid);
        return hop;

    default:   // DA_BURN, and an operation this header does not know
        return _BRAssetHopOf(BR_ASSET_HOP_DEAD_END);
    }
}

// ---- the walk ------------------------------------------------------------------------------------

enum {
    _BR_ASSET_WALK_START_KNOWN = 1,   // asked the store for the start txid's facts
    _BR_ASSET_WALK_FRONTIER = 2,      // asked for the frontier
    _BR_ASSET_WALK_LOOP_KNOWN = 3,    // asked the store for the current txid's facts
    _BR_ASSET_WALK_HOP = 4,           // asked for the current txid's hop
    _BR_ASSET_WALK_OVER = 5           // done or refused
};

// a + b modulo 2^32, read as a signed 32-bit number.
static inline int32_t _BRAssetWalkAddHops(int32_t a, int32_t b)
{
    int64_t s = (int64_t)a + (int64_t)b;

    if (s > INT32_MAX) s -= (int64_t)4294967296LL;
    else if (s < INT32_MIN) s += (int64_t)4294967296LL;
    return (int32_t)s;
}

static inline BRAssetWalkNeed _BRAssetWalkRefuse(BRAssetWalk *w, BRAssetWalkWhy why)
{
    w->need = BR_ASSET_WALK_REFUSED;
    w->why = why;
    w->stage = _BR_ASSET_WALK_OVER;
    w->hasAnswer = 0;
    w->pathCount = 0;
    w->frontier = BR_ASSET_FRONTIER_KEEP;
    w->ask[0] = '\0';
    return w->need;
}

// Ends the walk. withPath: memoise `answer` for the path, and when withCurrent, the current txid too.
static inline BRAssetWalkNeed _BRAssetWalkDone(BRAssetWalk *w, const BRAssetResolvedFacts *answer, int withPath,
                                               int withCurrent, BRAssetFrontierWrite frontier, int32_t hops)
{
    size_t i, n = 0, last;

    w->need = BR_ASSET_WALK_DONE;
    w->stage = _BR_ASSET_WALK_OVER;
    w->ask[0] = '\0';
    w->hasAnswer = answer != NULL;
    if (answer) w->answer = *answer;
    w->pathCount = 0;
    if (withPath) {
        // slots[0] is the start txid; slots[1, 1 + seen) the txids visited, the last one the current.
        // The path is the start and every visited txid but the current (and it too when withCurrent),
        // each once: a visited txid equal to the start is not listed again.
        last = (withCurrent || w->seen == 0) ? w->seen : w->seen - 1;
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_PATH_START_ONLY)
        last = 0;
#endif
        n = 1;
        for (i = 1; i <= last; i++) {
            if (strcmp(w->slots[i].txid, w->start) == 0) continue;
            if (n != i) memcpy(w->slots[n].txid, w->slots[i].txid, sizeof(w->slots[n].txid));
            n++;
        }
        w->pathCount = n;
    }
    w->frontier = frontier;
    w->frontierResume[0] = '\0';
    w->frontierHops = 0;
    if (frontier == BR_ASSET_FRONTIER_PUT) {
        memcpy(w->frontierResume, w->current, sizeof(w->frontierResume));
        w->frontierHops = hops;
    }
    return w->need;
}

static inline BRAssetWalkNeed _BRAssetWalkAsk(BRAssetWalk *w, BRAssetWalkNeed need, int stage, const char *txid)
{
    w->need = need;
    w->stage = stage;
    memcpy(w->ask, txid, sizeof(w->ask));
    return need;
}

// The head of one hop of the loop: the budget, the cycle check, then the store or the hop.
static inline BRAssetWalkNeed _BRAssetWalkLoop(BRAssetWalk *w)
{
    size_t i;

    if (w->step >= w->maxHops)
        return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_PUT, _BRAssetWalkAddHops(w->priorHops, w->maxHops));

#if ! (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_NO_CYCLE_CHECK)
    for (i = 1; i <= w->seen; i++) {
        if (strcmp(w->slots[i].txid, w->current) == 0) return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_CLEAR, 0);
    }
#else
    (void)i;
#endif
    if (1 + w->seen >= w->slotCap) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_CAPACITY);   // not reached: Begin checks
    memcpy(w->slots[1 + w->seen].txid, w->current, sizeof(w->slots[0].txid));
    w->seen++;

#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_FORCE_READS_CACHE)
    if (1) {
#else
    if (! w->force) {
#endif
#if ! (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_ANCESTOR_IGNORED)
        return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_KNOWN, _BR_ASSET_WALK_LOOP_KNOWN, w->current);
#endif
    }
    return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_HOP, _BR_ASSET_WALK_HOP, w->current);
}

// Starts a walk from startTxid (see THE WALK). slots[0, slotCap) is the caller's, kept alive until the walk
// is over; BR_ASSET_WALK_SLOTS(maxHops) always suffice. Returns the first need: NEEDS_KNOWN for the start
// txid, or NEEDS_FRONTIER when forceToIssuance is set; REFUSED for a NULL argument, a start txid longer
// than BR_ASSET_TXID_LENGTH, or too few slots.
static inline BRAssetWalkNeed BRAssetWalkBegin(BRAssetWalk *w, const char *startTxid, int forceToIssuance,
                                               int32_t maxHops, BRAssetTxidSlot *slots, size_t slotCap)
{
    if (! w) return BR_ASSET_WALK_REFUSED;
    memset(w, 0, sizeof(*w));
    if (! startTxid || ! slots) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_ARGUMENT);
    if (! _BRAssetTxidCopy(w->start, startTxid)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_TXID);
    if (slotCap < BR_ASSET_WALK_SLOTS(maxHops)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_CAPACITY);

    w->slots = slots;
    w->slotCap = slotCap;
    w->force = forceToIssuance ? 1 : 0;
    w->maxHops = maxHops;
    memcpy(w->slots[0].txid, w->start, sizeof(w->start));
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_FORCE_READS_CACHE)
    if (1)
#else
    if (! w->force)
#endif
        return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_KNOWN, _BR_ASSET_WALK_START_KNOWN, w->start);
    return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_FRONTIER, _BR_ASSET_WALK_FRONTIER, w->start);
}

// One step: `feed` is what the platform found for the need the walk last returned (see BRAssetWalkFeed).
// Returns the next need. Once DONE or REFUSED, the walk stays there and `feed` is not read. A NULL feed,
// fed facts whose texts do not end in their buffers, a resume txid or a hop's parent txid that does not
// fit, or a hop kind this header does not define, is REFUSED.
static inline BRAssetWalkNeed BRAssetWalkStep(BRAssetWalk *w, const BRAssetWalkFeed *feed)
{
    if (! w) return BR_ASSET_WALK_REFUSED;
    if (w->stage == _BR_ASSET_WALK_OVER || w->stage == 0) return w->need;
    if (! feed) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_ARGUMENT);

    switch (w->stage) {
    case _BR_ASSET_WALK_START_KNOWN:
        if (feed->has) {
            if (! _BRAssetFactsWellFormed(&feed->facts)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_FEED);
            return _BRAssetWalkDone(w, &feed->facts, 0, 0, BR_ASSET_FRONTIER_KEEP, 0);
        }
        return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_FRONTIER, _BR_ASSET_WALK_FRONTIER, w->start);

    case _BR_ASSET_WALK_FRONTIER:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_NO_RESUME)
        if (0) {
#else
        if (feed->has) {
#endif
            if (! _BRAssetTxidCopy(w->current, feed->resumeTxid)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_TXID);
            w->priorHops = feed->hopsWalked;
        }
        else {
            memcpy(w->current, w->start, sizeof(w->current));
            w->priorHops = 0;
        }
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_HOPS_NOT_CARRIED)
        w->priorHops = 0;
#endif
        w->seen = 0;
        w->step = 0;
        return _BRAssetWalkLoop(w);

    case _BR_ASSET_WALK_LOOP_KNOWN:
        if (feed->has) {
            if (! _BRAssetFactsWellFormed(&feed->facts)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_FEED);
            return _BRAssetWalkDone(w, &feed->facts, 1, 0, BR_ASSET_FRONTIER_CLEAR, 0);
        }
        return _BRAssetWalkAsk(w, BR_ASSET_WALK_NEEDS_HOP, _BR_ASSET_WALK_HOP, w->current);

    case _BR_ASSET_WALK_HOP:
        switch (feed->hop.kind) {
        case BR_ASSET_HOP_ISSUANCE:
            if (! _BRAssetFactsWellFormed(&feed->hop.facts)) return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_FEED);
            return _BRAssetWalkDone(w, &feed->hop.facts, 1, 1, BR_ASSET_FRONTIER_CLEAR, 0);
        case BR_ASSET_HOP_TRANSFER:
            if (! _BRAssetTextEnds(feed->hop.parentTxid, sizeof(feed->hop.parentTxid)) ||
                ! _BRAssetTxidCopy(w->current, feed->hop.parentTxid))
                return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_TXID);
            w->step++;
            return _BRAssetWalkLoop(w);
        case BR_ASSET_HOP_UNAVAILABLE:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_UNAVAILABLE_CLEARS)
            return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_CLEAR, 0);
#else
            return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_PUT, _BRAssetWalkAddHops(w->priorHops, w->step));
#endif
        case BR_ASSET_HOP_DEAD_END:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_DEAD_END_KEEPS)
            return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_PUT, _BRAssetWalkAddHops(w->priorHops, w->step));
#else
            return _BRAssetWalkDone(w, NULL, 0, 0, BR_ASSET_FRONTIER_CLEAR, 0);
#endif
        default:
            return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_FEED);
        }

    default:
        return _BRAssetWalkRefuse(w, BR_ASSET_WALK_WHY_ARGUMENT);
    }
}

// ---- the named asset -----------------------------------------------------------------------------

enum {
    _BR_ASSET_NAMED_KNOWN = 1,
    _BR_ASSET_NAMED_START = 2,
    _BR_ASSET_NAMED_PARENTS = 3,
    _BR_ASSET_NAMED_PARENT = 4,
    _BR_ASSET_NAMED_OVER = 5
};

static inline BRAssetNamedNeed _BRAssetNamedEnd(BRAssetNamedSearch *s, BRAssetNamedNeed need,
                                                const BRAssetResolvedFacts *answer)
{
    s->need = need;
    s->stage = _BR_ASSET_NAMED_OVER;
    s->ask = NULL;
    s->hasAnswer = answer != NULL;
    if (answer) s->answer = *answer;
    return need;
}

// Does a fed answer name the asset searched for? A NULL answer does not; facts whose texts do not end in
// their buffers are -1 (refused).
static inline int _BRAssetNamedNames(const BRAssetNamedSearch *s, const BRAssetResolvedFacts *f, int checked)
{
    if (! f) return 0;
    if (! _BRAssetFactsWellFormed(f)) return -1;
    if (! checked) return 1;
    return strcmp(f->assetId, s->assetId) == 0;
}

// The next parent to walk from, from s->next on: repeats and the start txid skipped.
static inline BRAssetNamedNeed _BRAssetNamedNextParent(BRAssetNamedSearch *s)
{
    size_t i, j;

    for (i = s->next; i < s->parentCount; i++) {
        int skip = 0;
#if ! (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_PARENTS_REPEATED)
        for (j = 0; j < i && ! skip; j++) skip = strcmp(s->parents[j], s->parents[i]) == 0;
        if (strcmp(s->parents[i], s->startTxid) == 0) skip = 1;
#else
        (void)j;
#endif
        if (skip) continue;
        s->next = i + 1;
        s->need = BR_ASSET_NAMED_NEEDS_RESOLVE;
        s->stage = _BR_ASSET_NAMED_PARENT;
        s->ask = s->parents[i];
        return s->need;
    }
    return _BRAssetNamedEnd(s, BR_ASSET_NAMED_DONE, NULL);
}

// Starts a search for assetId's facts from startTxid (see THE NAMED ASSET). Both are the caller's, kept
// alive until the search is over. Returns NEEDS_KNOWN, or REFUSED for a NULL argument.
static inline BRAssetNamedNeed BRAssetFactsForNamedAssetBegin(BRAssetNamedSearch *s, const char *assetId,
                                                              const char *startTxid)
{
    if (! s) return BR_ASSET_NAMED_REFUSED;
    memset(s, 0, sizeof(*s));
    if (! assetId || ! startTxid) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
    s->assetId = assetId;
    s->startTxid = startTxid;
    s->need = BR_ASSET_NAMED_NEEDS_KNOWN;
    s->stage = _BR_ASSET_NAMED_KNOWN;
    return s->need;
}

// One step: `feed` is what the platform found for the need the search last returned. Returns the next need;
// once DONE or REFUSED the search stays there. The parent list (feed->parents, kept alive by the caller
// until the search is over) is read only for NEEDS_PARENTS; a NULL list with a nonzero count, or a NULL
// entry, is REFUSED, as are fed facts whose texts do not end in their buffers.
static inline BRAssetNamedNeed BRAssetFactsForNamedAsset(BRAssetNamedSearch *s, const BRAssetNamedFeed *feed)
{
    size_t i;
    int names;

    if (! s) return BR_ASSET_NAMED_REFUSED;
    if (s->stage == _BR_ASSET_NAMED_OVER || s->stage == 0) return s->need;
    if (! feed) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);

    switch (s->stage) {
    case _BR_ASSET_NAMED_KNOWN:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_KNOWN_UNCHECKED)
        names = _BRAssetNamedNames(s, feed->facts, 0);
#else
        names = _BRAssetNamedNames(s, feed->facts, 1);
#endif
        if (names < 0) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
        if (names) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_DONE, feed->facts);
        s->need = BR_ASSET_NAMED_NEEDS_RESOLVE;
        s->stage = _BR_ASSET_NAMED_START;
        s->ask = s->startTxid;
        return s->need;

    case _BR_ASSET_NAMED_START:
    case _BR_ASSET_NAMED_PARENT:
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_OTHER_ASSET)
        names = _BRAssetNamedNames(s, feed->facts, 0);
#else
        names = _BRAssetNamedNames(s, feed->facts, 1);
#endif
        if (names < 0) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
        if (names) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_DONE, feed->facts);
        if (s->stage == _BR_ASSET_NAMED_PARENT) return _BRAssetNamedNextParent(s);
#if (ASSET_PROVENANCE_UNFIXED & ASSET_PROVENANCE_RED_PARENTS_NOT_TRIED)
        return _BRAssetNamedEnd(s, BR_ASSET_NAMED_DONE, NULL);
#else
        s->need = BR_ASSET_NAMED_NEEDS_PARENTS;
        s->stage = _BR_ASSET_NAMED_PARENTS;
        s->ask = NULL;
        return s->need;
#endif

    case _BR_ASSET_NAMED_PARENTS:
        if (feed->parentCount > 0 && ! feed->parents) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
        for (i = 0; i < feed->parentCount; i++) {
            if (! feed->parents[i]) return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
        }
        s->parents = feed->parents;
        s->parentCount = feed->parentCount;
        s->next = 0;
        return _BRAssetNamedNextParent(s);

    default:
        return _BRAssetNamedEnd(s, BR_ASSET_NAMED_REFUSED, NULL);
    }
}

#ifdef __cplusplus
}
#endif

#endif // BRAssetProvenance_h
