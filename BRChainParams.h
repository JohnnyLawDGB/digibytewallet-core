//
//  BRChainParams.h
//
//  Created by Aaron Voisine on 1/10/18.
//  Copyright (c) 2019 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRChainParams_h
#define BRChainParams_h

#include "BRMerkleBlock.h"
#include "BRCrypto.h"
#include <assert.h>
#include <string.h>

typedef struct {
    uint32_t height;
    UInt256 hash;
    uint32_t timestamp;
    uint32_t target;
} BRCheckPoint;

// DIFFICULTY CONTEXT AT A CHECKPOINT. A run of real, consecutive block headers that ENDS AT a checkpoint: the last
// row is the checkpoint's own header, each row before it is its parent. A wallet's resident chain starts at a
// checkpoint stub, which carries a hash, a height, a timestamp and a target but no ancestors. MultiShield V4
// (BRDifficultyV4Target) reads the timestamps of the averaging window below a header and the target of the last block
// of the header's own algorithm, so without this run the first headers above a starting checkpoint could not be
// judged, and every later header would be judged only against those first ones. With it, the manager judges the very
// first header above the checkpoint against the real chain (_BRPeerManagerDiffV4ExpectedLocked).
//
// The rows are written by scripts/gen_block_checkpoints.sh with the checkpoint table, for its newest checkpoints, and
// are self-verifying: BRCheckPointContextVerify accepts a run only if every row links to the one before it by
// double-SHA256 and the last row hashes to the checkpoint at `height`, with that checkpoint's timestamp and target.
// A run that does not verify is not used. checkpoint_staleness_kat requires one that verifies at the newest mainnet
// checkpoint.
typedef struct {
    uint32_t height;               // the checkpoint the run ends at
    size_t count;                  // rows
    const char *const *headers;    // 80-byte serialized headers as hex (wire byte order), oldest first
} BRCheckPointContext;

// the least number of rows a context needs: the averaging window and both median-time-past spans, ending at the
// checkpoint (mainnet and testnet26 averagingInterval 10; the generator also extends the run until it holds a block
// of every algorithm allowed above the checkpoint)
#define BR_CHECKPOINT_CONTEXT_MIN_ROWS (BR_DIFF_V4_NUM_ALGOS*10 + BR_DIFF_V4_MEDIAN_SPAN)

// row `fromTop` of a context (0 = the checkpoint's own header, 1 = its parent, ...) as 80 header bytes;
// returns 0 if there is no such row or it is not 160 hex digits
static inline int BRCheckPointContextRow(const BRCheckPointContext *ctx, size_t fromTop, uint8_t hdr[80])
{
    if (! ctx || ! ctx->headers || fromTop >= ctx->count) return 0;

    const char *h = ctx->headers[ctx->count - 1 - fromTop];

    if (! h || strlen(h) != 160) return 0;

    for (size_t i = 0; i < 160; i++) {
        char c = h[i];
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;

        if (v < 0) return 0;
        if (i % 2 == 0) hdr[i/2] = (uint8_t)(v << 4);
        else hdr[i/2] |= (uint8_t)v;
    }

    return 1;
}

// 1 if `ctx` is a valid run for the checkpoint table `checkpoints` (see BRCheckPointContext): at least
// BR_CHECKPOINT_CONTEXT_MIN_ROWS rows, each row's prevBlock is the double-SHA256 of the row before it, and the last
// row is the checkpoint at ctx->height (its hash, timestamp and target). Writes that checkpoint's block hash (internal
// byte order, as a resident block's blockHash) to *hash if non-NULL.
static inline int BRCheckPointContextVerify(const BRCheckPoint *checkpoints, size_t checkpointsCount,
                                            const BRCheckPointContext *ctx, UInt256 *hash)
{
    const BRCheckPoint *cp = NULL;
    uint8_t hdr[80];
    UInt256 below = UINT256_ZERO, h = UINT256_ZERO;

    if (! ctx || ctx->count < BR_CHECKPOINT_CONTEXT_MIN_ROWS) return 0;

    for (size_t i = 0; i < checkpointsCount; i++) {
        if (checkpoints[i].height == ctx->height) cp = &checkpoints[i];
    }

    if (! cp || ctx->height < ctx->count - 1) return 0;

    for (size_t fromTop = ctx->count; fromTop > 0; fromTop--) {   // oldest row first
        if (! BRCheckPointContextRow(ctx, fromTop - 1, hdr)) return 0;
        if (fromTop < ctx->count && ! UInt256Eq(UInt256Get(&hdr[4]), below)) return 0;   // not the next block
        BRSHA256_2(&h, hdr, sizeof(hdr));
        below = h;
    }

    // the last row (hdr, h) is the checkpoint: its hash (the table holds the display hex), timestamp and target
    if (! UInt256Eq(h, UInt256Reverse(cp->hash)) || UInt32GetLE(&hdr[68]) != cp->timestamp ||
        UInt32GetLE(&hdr[72]) != cp->target) return 0;
    if (hash) *hash = h;
    return 1;
}

typedef struct {
    const char * const *dnsSeeds; // NULL terminated array of dns seeds
    uint16_t standardPort;
    uint32_t magicNumber;
    uint64_t services;
    int (*verifyDifficulty)(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime);
    const BRCheckPoint *checkpoints;
    size_t checkpointsCount;

    // Which proof-of-work algorithms a header at a given height may name (BRChainParamsAlgoAllowed).
    // Heights below are BLOCK heights h; the reference client keys the same rule on the previous
    // block's height (h - 1), which is how the values below were derived from its chainparams.
    uint32_t multiAlgoHeight;       // last height that is scrypt-only (Core multiAlgoDiffChangeTarget: prev < T <=> h <= T)
    uint32_t odoHeight;             // first height whose set is {sha256d, scrypt, skein, qubit, odo} rather than
                                    // {sha256d, scrypt, groestl, skein, qubit}; Core: max(algoSwapChangeTarget + 1, OdoHeight)
    uint32_t algoLockHeight;        // first height at which the set above is enforced; below it, from odoHeight up,
                                    // any of the six is accepted (Core enforced nothing there: min(AlgoLockHeight,
                                    // nGroestlDeactivationHeight))
    uint32_t odoShapechangeInterval; // Odocrypt key interval in seconds (Core nOdoShapechangeInterval)

    // MultiShield V4 difficulty-target parameters (BRDifficultyV4Target), copied per network from the reference
    // client's kernel/chainparams.cpp
    BRDifficultyV4Params diffV4;

    // Difficulty context at the newest checkpoints (BRCheckPointContext), so that a resident chain starting at one of
    // them judges its first headers against the real chain. NULL/0 on a network that carries none.
    const BRCheckPointContext *checkpointContexts;
    size_t checkpointContextsCount;
} BRChainParams;

// true if a header at block height `height` may name proof-of-work algorithm `algo` (a value from BRMerkleBlockAlgo)
// mirrors the reference client's IsAlgoActive(prev, algo) with prev = height - 1, gated as ContextualCheckBlockHeader
// gates it; an unknown algorithm is never allowed
static inline int BRChainParamsAlgoAllowed(const BRChainParams *params, uint32_t height, int algo)
{
    if (algo == BLOCK_ALGO_UNKNOWN) return 0;
    if (height <= params->multiAlgoHeight) return algo == BLOCK_VERSION_SCRYPT;

    if (height < params->odoHeight) {
        return algo == BLOCK_VERSION_SHA256D || algo == BLOCK_VERSION_SCRYPT || algo == BLOCK_VERSION_GROESTL ||
               algo == BLOCK_VERSION_SKEIN || algo == BLOCK_VERSION_QUBIT;
    }

    if (height < params->algoLockHeight) {
        return algo == BLOCK_VERSION_SHA256D || algo == BLOCK_VERSION_SCRYPT || algo == BLOCK_VERSION_GROESTL ||
               algo == BLOCK_VERSION_SKEIN || algo == BLOCK_VERSION_QUBIT || algo == BLOCK_VERSION_ODO;
    }

    return algo == BLOCK_VERSION_SHA256D || algo == BLOCK_VERSION_SCRYPT || algo == BLOCK_VERSION_SKEIN ||
           algo == BLOCK_VERSION_QUBIT || algo == BLOCK_VERSION_ODO;
}

static const char *BRMainNetDNSSeeds[] = {
        /* Bloom-filter-enabled nodes (priority — tried first by C core) */
        "digiscope.me",               // DigiScope SPV node (peerbloomfilters=1)
        /* Active DNS seeders (verified resolving, ordered by address count) */
        "seed.diginode.tools",        // Olly Stedall @saltedlolly (25 addrs)
        "seed.digibyte.link",         // Bastian Driessen @bastiandriessen (25 addrs)
        "seed.quakeguy.com",          // Paul Morgan @SnKQuaKe (25 addrs)
        "seed.aroundtheblock.app",    // Mark McNiel @JohnnyLawDGB (24 addrs)
        "seed.digibyte.io",           // Jared Tate @JaredTate (1 addr)
        /* Dead/unresponsive seeders removed 2026-03-30:
         *   seed.digibyteblockchain.org (0 addrs)
         *   eu.digibyteseed.com (0 addrs)
         *   seed.digibyte.services (0 addrs)
         */
        NULL
};

static const char *BRTestNetDNSSeeds[] = {
    "testnetseed.digibyte.io", "testnetseed.digibyte.link", "testnetseed.digibyte.services", NULL
};

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they must be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
// AUTO-GENERATED by scripts/gen_block_checkpoints.sh — DO NOT HAND-EDIT.
// 522 checkpoints: genesis + every previously-shipped height + a uniform
// 50000-block grid, from an operator full node. Hashes are the RPC display hex
// VERBATIM (UInt256Reverse is applied at READ time, BRPeerManager.c:2331/:4755)
// — NOT pre-reversed like BRCompactFilterCheckpoints.h.
//
// The NEWEST entry sets a fresh wallet's BIP158 scan floor, so a stale table
// silently becomes a multi-hundred-thousand-filter scan. checkpoint_staleness_kat
// fails the build when this ages out; rerun the generator to clear it.
// newest: height 24550000 @ 2026-11-12 UTC (chain tip was 24603868 at generation)
static const BRCheckPoint BRMainNetCheckpoints[] = {
        {        0, uint256("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496"), 1389388394, 0x1e0ffff0 },
        {     5000, uint256("95753d284404118788a799ac754a3fdb5d817f5bd73a78697dfe40985c085596"), 1389701913, 0x1c32a753 },
        {    10000, uint256("12f90b8744f3b965e107ad9fd8b33ba6d95a91882fbc4b5f8588d70d494bed88"), 1389996580, 0x1c1557fc },
        {    12000, uint256("a1266acba91dc3d5737d9e8c6e21b7a91901f7f4c48082ce3d84dd394a13e415"), 1390115182, 0x1c0d748e },
        {    14300, uint256("24f665d71b0c6c88f6f72a863e9f1ba8e835cc52d13ad895dc5426021c7d2c48"), 1390258861, 0x1c1409e7 },
        {    30000, uint256("17c69ef6b403571b1bd333c91fbe116e451ba8281be12aa6bafb0486764bb315"), 1391206674, 0x1c0e8ff5 },
        {    50000, uint256("e77a35893a5611c4154cc71f7a7f949e074143e66b05cac2bd8c1db1c752c2f8"), 1392476904, 0x1c0dca73 },
        {    60000, uint256("57b2c612b60462a3d6c388c8b30a68cb6f7e2034eea962b12b7ef506454fa2c1"), 1393183580, 0x1c16beae },
        {   100000, uint256("236eb6c24599c6a6a2a3f2263086e1e67b2fe29a37bec19be89bf24b33f12cc9"), 1396702366, 0x1c276339 },
        {   110000, uint256("ab2da24656493015f2fd288994661e1cc657d90aa34c755514af044aaaf1569d"), 1397850930, 0x1c198d98 },
        {   141100, uint256("145c2cb5239a4e019c730ce8468d927a3955529c2bae077850783da97ddbca05"), 1407018505, 0x1c01722c },
        {   141656, uint256("683d27720429f28bcfa22d8385b7a06f307c8fd918d49215148fbd41a0dda595"), 1408033242, 0x1c0185fc },
        {   150000, uint256("c652b775c9678167a1a0088c1e3624875d226dfa62a10128bf550dff904b4111"), 1409760287, 0x1c0a2457 },
        {   200000, uint256("0000000000000e8acbba6f1d21394c5df111dd836a17b750f29150f72be02802"), 1411630778, 0x1a14c0d4 },
        {   245000, uint256("852c475c605e1f20bbe60219c811abaeef08bf0d4ff87eef59200fd7a7567fa7"), 1413145109, 0x1c028e59 },
        {   250000, uint256("301cb89611709f47bddf383aeac2d3fb03d1ab187f695e6b56bd62d1681c3330"), 1413310441, 0x1b0e8269 },
        {   300000, uint256("701771ab8095e412122d1b7d49c60b0ef871751bc26a7d2a9a68d59dcff5edef"), 1414931706, 0x1c068533 },
        {   302000, uint256("fb6d14ac5e0208f00d941db1fcbfe050f093cfd0c05ed151c809e4428bc14286"), 1414988281, 0x1b0fb02e },
        {   331000, uint256("bd1a1d002750e1648746eb29c78d30fa1043c8b6f89d82924c4488be06fa3d19"), 1415917252, 0x1c07e8f8 },
        {   350000, uint256("23ffa9e21a1f8275f13976ae33463cc375a2ad1a9c0d5581bccc76d018f29c74"), 1416542523, 0x1c02138f },
        {   360000, uint256("8fee7e3f6c38dccd3047a3e4667c63406f835c2890024030a2ab2dc6dba7c912"), 1416891634, 0x1b2c1714 },
        {   400000, uint256("596eeb60dab06afccb354f63abbd684e11fd46339977c7943528e4aa34ed0400"), 1418230305, 0x1c02d464 },
        {   400100, uint256("82325a97cd97ac14b0a57408f881b1a9fc40174f8430a4580429499ac5d153c8"), 1418232367, 0x1c020a1c },
        {   450000, uint256("ee9e1b718a21cd8d380093d3c999b1221a7fdde4b229ddbffa88e89210881fe8"), 1419735702, 0x1b28315e },
        {   500000, uint256("745137430c905f1a82a59cd733832c543724043fb2fd60e532bac21b21256bb3"), 1421241373, 0x1c012abb },
        {   521000, uint256("d23fd1e1f994c0586d761b71bb3530e9ab45bd0fabda3a5a2e394f3dc4d9bb04"), 1421875139, 0x1c04531c },
        {   550000, uint256("bde46ef12a48ad06bb5b4cb77e445ec5283417d8f47c0857e05354e256eefa56"), 1422748270, 0x1c00bcc9 },
        {   600000, uint256("292bee9bd10c2d02ebebc2a366f8828f79a8f2369c842fb090f8537e87b73487"), 1424252210, 0x1c0099bd },
        {   650000, uint256("22ebf3a32ab8f9792ac560143988d4cec3838be49727ba8be1a2f2b73e024170"), 1425756900, 0x1c01cbc1 },
        {   700000, uint256("c68e02db2c1ef531d37158b2528bf57f6e1c8596d383e221a8ba4529bd02c087"), 1427262932, 0x1c017e07 },
        {   750000, uint256("e4f248c31f690b4ede6d08821e551f4dd728a71942f9b6096c914f877188409b"), 1428768638, 0x1c01e48a },
        {   800000, uint256("cbd4702a5eb54723edbae45659871449b300b3da9a30e5e4c6824fac80cae3e7"), 1430273819, 0x1c022a73 },
        {   850000, uint256("8a201d591f08294da50ff96d9935e29c73f1b682c400955ffdcc39f0a6e38a96"), 1431778202, 0x1b1a6277 },
        {   900000, uint256("11a7336b91bf2994321b8bcd49ab2fcbe45afa6399b406b59620915db0e11a11"), 1433284012, 0x1b34274f },
        {   950000, uint256("7daa0be3b5cde264c65a8967a6c48f89c9286fa33cead08d078716cded4ea4ab"), 1434789330, 0x1c00b507 },
        {  1000000, uint256("b85849392739f50e1fc7568b16eeb1bf37f36c144d7ec46340a4c8a202253ade"), 1436296106, 0x1c01534a },
        {  1050000, uint256("1114bac1d986fa60fdd79de041a31cbd1777bc5726115a3a32159042eb17e92e"), 1437798906, 0x1b5fba52 },
        {  1100000, uint256("b4b6536e012cf7f80a6e46d8801a5deec3106c8988272be8907f726e94c38407"), 1439302795, 0x1c019647 },
        {  1150000, uint256("a9a663e9c678f88f7bd1026a31c006cf33f597bd24478af85b56ac902c5c85f1"), 1440808195, 0x1c00dabe },
        {  1200000, uint256("000000000000083784693fa8994f64417fb2feb608bb2d0c93b60afeffdd48e3"), 1442313491, 0x1a136683 },
        {  1250000, uint256("00000000000002500502de1406b15d13d09d8f1e8bd14527af81f6ac9d7960ad"), 1443818604, 0x1a06fde7 },
        {  1300000, uint256("0000000000000020ff988770a99cf91c9ddabf97122329a9cedc8c5d4d774a12"), 1445323288, 0x1a050a35 },
        {  1350000, uint256("1a80ff7a8585ee7c2f11ed497106ef7701dd38c716bb9d6c829199063d42f25a"), 1446827836, 0x1c00a2be },
        {  1380000, uint256("00000000000001969b1e5836dd8bf6a001d96f4a16d336e09405b62b29feead6"), 1447731080, 0x1a02e03e },
        {  1400000, uint256("1cdc20a5e53a84c427d903eb7f748be09a0d3a9d8faf46ed6603857c0f424840"), 1448333015, 0x1b2006aa },
        {  1435000, uint256("f78cc9c2791c8a23720e2efcdaf46584046ee5db8f050e21a3a15a13f5c68da0"), 1449312651, 0x1c1f3df6 },
        {  1450000, uint256("2fa7e991ca9f696e100f44ad18691dc8cd2099efdb24718a12140f35cde8dde1"), 1449537655, 0x1c042159 },
        {  1500000, uint256("af353af43bb01a5168f7d344681de8389c44d2e431841a1943a1467f8d851a8b"), 1450284942, 0x1b3cf8f7 },
        {  1550000, uint256("8570af3d63bc57a24e4e36a6ae8458bb5462d170bd95e87450c0a2d35d6ec8e6"), 1451033507, 0x1b2c2acc },
        {  1600000, uint256("98efd15a6deec563359366dad7dc180f4b8041aa42f9a7e5fd907152648131e3"), 1451781348, 0x1c034519 },
        {  1650000, uint256("afd2bac9cabbff200a007da085631e20b4bb7eb1d870e1a219a354754b7a1221"), 1452530545, 0x1b2d9bb5 },
        {  1700000, uint256("000000000000069834ceddccc356b743970fdd07a7596a8d7bd3b30fcb11ba32"), 1453279105, 0x1a092f75 },
        {  1750000, uint256("5967f952a7336c4f7d7e92dc51daffb132c12fbbfde2b912ab8e43a20a82603f"), 1454026766, 0x1c00c70e },
        {  1800000, uint256("72f46e1fff56518dce7e540b407260ea827cb1c4652f24eb1d1917f54b95d65a"), 1454769372, 0x1c021355 },
        {  1850000, uint256("d0b4e5be68bdc1a1509aeb4188810dc38da3edc1c1e9cb2a19521cdab7137fa0"), 1455516731, 0x1c05dd21 },
        {  1900000, uint256("66d74c12a3b939fdec4f6f6bbe30a74a93bf5171989c264e19da00785b05eb8b"), 1456264104, 0x1c039900 },
        {  1950000, uint256("1037a1cab7e8222780afabc32e37b127a7e8171ef981f40ab300c66ab7a82d2f"), 1457009776, 0x1c009b63 },
        {  2000000, uint256("10f522ec60d8af2e2cbd9e2268260c33fb8bbf9cd9f176b4fddcae7493c6791d"), 1457756932, 0x1c021bb1 },
        {  2050000, uint256("25eeb421e039f2efa39b8a8d4f36f6e8e0dce7ef07effbf23b1fe4f6002a1ab5"), 1458503513, 0x1b597e8b },
        {  2100000, uint256("f73ad3dd4ad9fe97d244758b9d564fe6a631c5bfd5e99b54b854c8a60ca93b03"), 1459253310, 0x1b5ddeab },
        {  2150000, uint256("20b67adbe0f1b4ab49afb4c06d0369d29b4acfc5fbb3754a248db8257ef40fd7"), 1460002707, 0x1c01511c },
        {  2200000, uint256("f2cda55b21320d1d896cfbcd27f803bbcc682f671cc28ed45cf1e835f4f8c722"), 1460750607, 0x1b7a05a8 },
        {  2250000, uint256("2695ee013263d21c30f51fae0126c22c20d8d459dcd553100f370fbba6b9fd27"), 1461497674, 0x1b4f152c },
        {  2300000, uint256("6048af620731d1bc6c38cfd85df2d5b194af25acc3b109d2fc572b6460219922"), 1462244590, 0x1c04fbc4 },
        {  2350000, uint256("1ace0a0f8b8c547c0cecf4539c737ac4e491168495d12226c7b51e2e1a2e4b8e"), 1462991969, 0x1b1a4b10 },
        {  2400000, uint256("ed5569553f6966c7b6b75e78734a7499eb8b3ef619230262c374ef25e903328a"), 1463739886, 0x1c022843 },
        {  2450000, uint256("09cf9232ad44e6afc6f000cb536ad920a744d030587faab8ada220435b7aff8a"), 1464487458, 0x1c00ae68 },
        {  2500000, uint256("239a6e786001523e8ba4485b4fc1665e911a5b9b093260d194bb9c9b394d244a"), 1465231670, 0x1b31fb33 },
        {  2550000, uint256("67cbab6817a8f3d125e90bfebcda2360880796817be570aa06727953d62d3106"), 1465972191, 0x1c01322d },
        {  2600000, uint256("e4cd35742ba676ec33782cd022c66f96db2b93001de073c5fa07f76831517f65"), 1466712143, 0x1c01f8f2 },
        {  2650000, uint256("b0c380fd6253bd2a42a5652e027fd8a39d9bf68c1fd3da1e67cb4a132977ffa8"), 1467456024, 0x1c00eb6e },
        {  2700000, uint256("b6f5ad74dc4d013f9d2729341cd559d2141352aa25566b7f0951553487455a1c"), 1468202296, 0x1c02b16a },
        {  2750000, uint256("c362bd2b66b3ce34981404b456301ab75412b79f22600b17709c278ffc261b3f"), 1468949293, 0x1b34a098 },
        {  2800000, uint256("99b08a2bb086a355af00782dffc2a94f56e225426426b3748063e4c703444a45"), 1469694406, 0x1c012dd8 },
        {  2850000, uint256("d8620d49c69a66da02ff610f5e274cc421e2ba948e93f994b3631940f046be90"), 1470439650, 0x1c01c286 },
        {  2900000, uint256("9888c9f637e68fae64a3e6381872394124351611e65dabd77997652c33c3d2f9"), 1471182829, 0x1c01aae4 },
        {  2950000, uint256("bf6733af34ab247411e57a3a23b67be9df327024cb4cb72b1e673f51478200cf"), 1471926449, 0x1c01445a },
        {  3000000, uint256("c9b034e634cb78f16385ba5cd166f91a5b448af84d6b20c0a924bc2f4409effd"), 1472667779, 0x1b24a10a },
        {  3050000, uint256("5bb11bc8c889c61cd26ca5442731ca2bb00a213e27ac4d8a322d41884c54ad0a"), 1473408753, 0x1c00cf3d },
        {  3100000, uint256("db8d0280c6fc40196cf214e094fe87930fb6cd19d430fede2012539648ffb881"), 1474150945, 0x1b211c4d },
        {  3150000, uint256("4960e8c5ca38471c4f7564da8173a28bc6715589d21fe36c6eb7948d5183797f"), 1474892389, 0x1c00bc68 },
        {  3200000, uint256("5dcc21cebabb27e1e4376f6018169bfbeda345ace052e4e4f8be363150016858"), 1475633073, 0x1c0222f9 },
        {  3250000, uint256("50dc8dbd206cf429bebfb502c23bbba9b126b539bec23ec697e057e1c1351ef7"), 1476371756, 0x1c018251 },
        {  3300000, uint256("0bceb218f7d8ed33dfba60a4c6866798367a6d76883ff01cc3194b8f68fa261e"), 1477115210, 0x1b2acf68 },
        {  3350000, uint256("47cc0a4379416a08c1f25ebe755a73bc30dee5c3b2883b1f40a9261c770a38fe"), 1477856734, 0x1b49698c },
        {  3400000, uint256("00000000000002656bb99809312027f25a4436ca6d4161b379046a6291566b12"), 1478602085, 0x1a039159 },
        {  3450000, uint256("8518e020bf1f67a487b764379f8d18d897d737ad87ef1b42b20df063ab78a9b7"), 1479347727, 0x1c0219f6 },
        {  3500000, uint256("bece76f2a3f53637e2ea84837a45a6ffdc0c86372ab4701c3146094f65832c80"), 1480092130, 0x1b7b644f },
        {  3550000, uint256("fe31d298cc57de6bee1ec41db0e45202a0500e7bf12c2169c474b6645a41a58b"), 1480834234, 0x1c0143ff },
        {  3600000, uint256("520931769d7ec1fcade7ae754943d844b27adb7c09e7dece6ac40320bf135c09"), 1481580190, 0x1b47b360 },
        {  3650000, uint256("7f2d41cb76ee0736276ddaf830e4d251c2ce0ef1096f62a3bc7afcdd7d0ca6f9"), 1482326978, 0x1c01fbe1 },
        {  3700000, uint256("9e6aa6a32b00f8919fb06bade175ec7e78a1d6cd3cac66095d2f6a2e7cfd7adb"), 1483072077, 0x1b4e278d },
        {  3750000, uint256("8e7ddd9b53b791759f6e617a0316c5d24bbb663b2c24387b9c21bd23dd514f7c"), 1483817416, 0x1c00aebe },
        {  3800000, uint256("45dc73e94f35017464da16e7a703e5559f7f2e79585a7cbfb048bcaa56eaab67"), 1484564146, 0x1c017123 },
        {  3850000, uint256("87f49bdeae840ddc9110f43d8297f831895971912c6f12296083c1452e7a784e"), 1485311193, 0x1c0175e8 },
        {  3900000, uint256("7f63bbf0296697374e046392c60388af7bb3b05861eba66bfa226a8c4e666375"), 1486057313, 0x1c0152c1 },
        {  3950000, uint256("cac5d14ba768bbc4957e4c2bccb20e9497a6e855fdaa248f42bb525cd73aaf12"), 1486803527, 0x1b7146e5 },
        {  4000000, uint256("000000000000009d41478ed798aa84f059430efe0b493c2eedd6a17a6afde1cc"), 1487547939, 0x1a028efe },
        {  4050000, uint256("9ad3f147bb7e8858629a39aad1d0d94672d156c0fd28a550d151f6b1b87fa33c"), 1488291746, 0x1b436f3f },
        {  4100000, uint256("4a4a01554dca8f252dca0dbc166e2f16e22108d3d76afc1ba4718c8b048da355"), 1489032605, 0x1c014dbf },
        {  4150000, uint256("2595d5a161a31fac3bed58070c6d0a8602dc5dfe9bdbfac079709d7cd99883fc"), 1489771916, 0x1c043ad7 },
        {  4200000, uint256("140ea726d95fdaf39f9a4920ba2346b4165c24a7839c78b7cd9728678c9f42d9"), 1490509666, 0x1b30aae4 },
        {  4250000, uint256("056d9b639a13e6de7c362047032e8c9152cefb7f6ae94f7ad7463064d4b5cc37"), 1491247365, 0x1c01c787 },
        {  4255555, uint256("23f72e760542bf021ec76d04231ad7cf80142069a79ba702028e074b726f86ef"), 1491329321, 0x1b26a4c3 },
        {  4300000, uint256("6076bbd15d330f1acaf70a6f3e6c74c71c53616fe83835527910859df68fe302"), 1491988302, 0x1b2342f8 },
        {  4350000, uint256("993bca4358ce47816aa81eac81c3d24d52eef8e3c4a175ca8a191d7d14902fd7"), 1492730478, 0x1b123933 },
        {  4400000, uint256("aeb94a76714dc6577077d02bd048f05f0b1f6d52336674830d692be52f345b0f"), 1493473023, 0x1c00c8f3 },
        {  4450000, uint256("6808d89d62bda67f9a004f3f82e8a32bb7802a49eaede86905d9177dd0d4d4a5"), 1494215104, 0x1c00a81d },
        {  4500000, uint256("000000000000006027d9f6aec51709c4b9e8bc4a0dba1e881847c30e3bf427f4"), 1494959767, 0x19678fdc },
        {  4550000, uint256("9c31f364937c8ba28df451b2efd6f7e9599a44ad9b6bd0b125dc86ee144d7469"), 1495708620, 0x1b175c97 },
        {  4600000, uint256("c17a42929bf68ca3a0fef128b2d2097b32f8bc64025cd0e00494e97ecc031389"), 1496457052, 0x1b076bb9 },
        {  4650000, uint256("6d73aabacfe73242a911d015fea9a87e9a083ce5f5754247de742e07f76d9fc7"), 1497208012, 0x1b01bcf7 },
        {  4700000, uint256("b208ab3e67343b03e0ed0b86c1847137edf52255abc0c502dfd6dae730d87bc7"), 1497955077, 0x1b00efb4 },
        {  4750000, uint256("1b10b9bd9bcd388ddc3d8bfc07d2eb65302f325e80c793fdaef4c15fd08d051f"), 1498703073, 0x1b019338 },
        {  4800000, uint256("baac90bad8948257c3fcd11986e83ef58d21b5cb9b542bfd97fa07f74cbd4f07"), 1499452526, 0x1b03dec5 },
        {  4850000, uint256("42c8c8911e8cd9b4b2736fd97b99159d4cd03948f722e99ccbd4823460df4f34"), 1500200227, 0x1b02c53a },
        {  4900000, uint256("dbdd7a7c0e97e7c9f863a3388e503853572251b67cc5f5a7d019029901f5d910"), 1500947128, 0x1b1afbbe },
        {  4950000, uint256("8e4a13f40f61e8b69d640ed8d2bf850587bf12a1ad40215ea2efdc7e5732c55d"), 1501694806, 0x1b00c656 },
        {  5000000, uint256("1dd2fdf6416343688eed463a7bc70b298a4f872e941e36f85cda0915d6488e25"), 1502441966, 0x1b00b26f },
        {  5050000, uint256("82efffb23780ff82cec83bb390635a0944baafc4a5ee93fd645167b66c90de9c"), 1503189199, 0x1b1b051f },
        {  5100000, uint256("000000000000001fa2a2aa5ea1486bb95aa94359db9051f2a58f7ebba7581648"), 1503937345, 0x1922ce4e },
        {  5150000, uint256("79f9c317ee465c72fac4a12b7561760b51b53fd3cf34821cecb13a97a65ecd4d"), 1504687735, 0x1b00a912 },
        {  5200000, uint256("e219eaa86c4b6d8446f746ed50299829c864100b43c430070639f051922ef98a"), 1505436889, 0x1b1722f0 },
        {  5250000, uint256("fd5a39fec0c7f72ec1bd2bb3ade1043fc3811eaa82b9bb263ca065533b40ccb9"), 1506185090, 0x1b01eb6b },
        {  5300000, uint256("8603ca6b0a3e586cb9bb4d3d8c55659a41e2200228ed5f2994a3b648cbdba63b"), 1506931685, 0x1b0083bb },
        {  5350000, uint256("000000000000001759372124b51cb7fbdc17d472e30c4518ad317915a494feda"), 1507676575, 0x191e672a },
        {  5400000, uint256("8925d8f745f1e0bae5381e4a998c2b77e27faacdac6e8c39ab5e9a1ad4283775"), 1508422648, 0x1b018cec },
        {  5450000, uint256("daeb177277fdb63e1c7e390145a6fca0f3931d25f4c0bf67b745901c190409c6"), 1509163993, 0x1b0e33fd },
        {  5500000, uint256("e77792fd9f4cfaf3987078d6f70755e13f9c47a8cf854180405598c59daca031"), 1509904472, 0x1b08af3f },
        {  5550000, uint256("0ecee3818c0db8fd51ad72e697fa6c1140aef9becbc2b842fb9d5b5bdda8283c"), 1510645799, 0x1b01f116 },
        {  5600000, uint256("a9cc9e925cf3b65185b255fa00911fb5008ccc4125ca3cd7fda8028d8cdefd62"), 1511389763, 0x1b021203 },
        {  5650000, uint256("e101049d26da36a8b6ccde0f04a3efedacacfd3b8a32409ea2afaea7199b2c74"), 1512133627, 0x1b017bab },
        {  5700000, uint256("832ccb9f8ddb429dfedf8fa560eb3f5b1de4731630172d3ce18fe7504beaa15c"), 1512878119, 0x1b0777a7 },
        {  5712333, uint256("0000000000000003363ff6207a99a175e8b5adff71c77817a92f127fcefe936e"), 1513061829, 0x1924bd79 },
        {  5750000, uint256("1e55ca632656c24b2749f7017676af9f934b234a4f348d174169cf92ca8c4d55"), 1513625120, 0x1b00ca45 },
        {  5782400, uint256("b1005c34a3f4fbc0d99f2fe521490b63abd2ff2029fef80df72dd22ac2c735ec"), 1514109544, 0x1a5b24c0 },
        {  5800000, uint256("80687f64052f45c64cf62e92615732f80fc18b1ee1b47c699a192141699676f0"), 1514372292, 0x1b008d50 },
        {  5822077, uint256("27d9687ef5f34d2b451c2c0d9c4a6612e7b4bbdc083d03bbdf2d2adbef08e5b1"), 1514700120, 0x1b023a6c },
        {  5850000, uint256("e26154fa671076d815cb387547477ac7112266f0717bf89a4adcde63b5ba7a49"), 1515115947, 0x1a5686ce },
        {  5862666, uint256("0000000000000000b06d70ff1a3424a933b7743dc44ed08422cbc6b3fef8422c"), 1515304798, 0x1906cff8 },
        {  5900000, uint256("b35ef100b062ecaff14f1a82f31548ca1da18290648ce4125737c99b4741b41f"), 1515860731, 0x1a55a7b0 },
        {  5950000, uint256("8a3e1b412ccf52ca48d2889140a1f62318b0e50a9219bdc3d24ed103cad6f28c"), 1516605641, 0x1a4e2136 },
        {  6000000, uint256("6495a84f8f83981a435a6cbf9e6dd4bf0f38618c8325213ca6ef6add40c0ddd8"), 1517351271, 0x1a6af73c },
        {  6050000, uint256("0000000000000001157f6326ae4fc9ad4bdb2eb48b1ae647e4733d7bc37a3b78"), 1518098456, 0x1904cc1f },
        {  6100000, uint256("000000000000000140aad8cbf12752aae2fbc8d835ce1a75b658a45be134456a"), 1518844452, 0x1905a25c },
        {  6121330, uint256("819f22e8aee4fabfc36d12bac142852697b438fda5e5b3545102faa624b354e1"), 1519162626, 0x1b02f1a7 },
        {  6150000, uint256("cdace1ef5171a13e6b9aa6b353c515b8b49cf94eb40c152fb2f19786bb704886"), 1519589216, 0x1b043243 },
        {  6200000, uint256("f3dac63c3b0b83f8dc5776312ffce138612b4339df4738990858a876c290f7a2"), 1520332524, 0x1a5a77d2 },
        {  6227953, uint256("04a2e7f5ed5017dc45ee0627c1ed446f5331c290dc43e2febaa30e81fa280888"), 1520747973, 0x1a621a03 },
        {  6250000, uint256("56493d52069b79e905aa6f426f3074441e9a16b966db9574c85096df57d15d94"), 1521075728, 0x1a670819 },
        {  6256573, uint256("2b3d16a3a14eadcbaa977b8e8c41fc56140fee024c70047bfc18bef2d1ffa756"), 1521172890, 0x1a662f3c },
        {  6268500, uint256("00000000000000068c5b2c3515cf1fee4ff0fba92426cc6dad28e6ed9298f36a"), 1521349185, 0x190b32a3 },
        {  6300000, uint256("6980190f2e7b5a2a76f1a825570ac229bdcbf819ee244bff2f70f78b52823aca"), 1521816935, 0x1b02ab8c },
        {  6309234, uint256("86f360c347d61a1015e901ffcc54a0692af7267e06b64191aa21be988368673d"), 1521953988, 0x1a2bb5ea },
        {  6350000, uint256("c60a957fd50ed898956173b6f081edcfe2e86efd4994287f31c1fa98dc7d04ba"), 1522560852, 0x1a4befbb },
        {  6400000, uint256("ec40a9adc7f44de66f04c3c8abb26f58f5714960f1f8506904e621cd9666896c"), 1523306095, 0x1b01509f },
        {  6450000, uint256("f6e9c2c0f0b2a25656dce9c00cf78b6d94695b792d63263d1a483433cae88859"), 1524048723, 0x1a376fc0 },
        {  6500000, uint256("b168b7f70cbfd2e5fea07da55d9fa90dc7c65599ceb2700efe04ee6c45692e52"), 1524793379, 0x1b00ad31 },
        {  6550000, uint256("2ecd4323176f5879a8d57c3d38655fe124f82a2e9e8db9585ba89a804609e981"), 1525536334, 0x1a38550c },
        {  6600000, uint256("fb0fdab30d2fe283d92149e959a14f7cb63eaddf6077797de8922e34e4a5233e"), 1526279792, 0x1a46f3d6 },
        {  6650000, uint256("c4798a881ebec2232871bccc674c42435605e00079bdabf040762e6b211eb5aa"), 1527024755, 0x1a44ca19 },
        {  6700000, uint256("34f0e2229e32ebdc0f4b1642f4737bfab072410906557107003e2b773ac915c0"), 1527769952, 0x1a2b51b7 },
        {  6750000, uint256("aea50e8f468b4bdcff90207605a93f5d42eeb5164a39d54e88edf23f7e691669"), 1528514444, 0x1b00ecb0 },
        {  6800000, uint256("9e931416e834b8b3da0f9a4bc7e7650683de6cb9d2220f5d716f3eadba785751"), 1529260140, 0x1b00b1e4 },
        {  6850000, uint256("049a01f170a3c27f21bbef4323f37bed00a5b3e98a912989796316f4a00ca804"), 1530002453, 0x1a353e72 },
        {  6900000, uint256("31c160cbae37afcacd351597c162661951806861f4b7afa3b2a5050dcec1f82c"), 1530745968, 0x1a5cabc8 },
        {  6950000, uint256("73c1494cf527b042f6863261e89e3de105f86ba3ee3af821d59be213a37b1d84"), 1531491517, 0x1a370a53 },
        {  7000000, uint256("03c6664b250c3e3b688f5779ce791384b35acaa38c4461f0458a4674bd762f63"), 1532239864, 0x1a117058 },
        {  7050000, uint256("e7b90166dcd45571088103d611abd82fc52af6087e250f15a342a9cd178aeb82"), 1532985379, 0x1b0086b2 },
        {  7100000, uint256("f7485dd054e59567e5ceb8dbe52ff3aef4f8745e5e08a52979fac01748b8572a"), 1533731002, 0x1a379a99 },
        {  7150000, uint256("a07454250fe44306da823747d3bce8d7e4eac7c3c7c56cb10e71356805cc3a61"), 1534476501, 0x1a0e780f },
        {  7200000, uint256("8ddd0ef75cb09f84b2d78a128425276e4aa3e52155a19c076c1e697f792cc9ab"), 1535223292, 0x1a3aa1ef },
        {  7250000, uint256("c1f27248a417505c5d6fdb71c3dac7a66927bd512552b7419390ec4a71c605cc"), 1535973727, 0x1a156b46 },
        {  7300000, uint256("7dd0e9e988f475db6c9542895629e3ce7a51febc3dca08c0e663672661ffa50b"), 1536719749, 0x1a15befd },
        {  7350000, uint256("c21b2ea26a4853e0846cb854af35fec9623691fec7bda992ba80c7fa76ea5206"), 1537465005, 0x1a1093d5 },
        {  7400000, uint256("00000000000000002376f94b6c7cc3e1c8b76c20f57d9df152b456096793fcb6"), 1538210379, 0x1902a755 },
        {  7450000, uint256("ab57a95012b6ba12b9991e170ac89c4de86808a03f66c5a9161ed5500c91b6f2"), 1538956286, 0x1a225620 },
        {  7500000, uint256("bd10f5ebedd8d09b352d9e95c96af62ae0a0a7e3f698c6c82c151bc770c6a831"), 1539702577, 0x1a13f52e },
        {  7550000, uint256("f689833c01183997204d61adfbc4a7800fa9c2f8e23ef051fd29e11063da1c92"), 1540449078, 0x1a174a30 },
        {  7600000, uint256("0faf84b6789cc109e36c2d546904897df9adfa76e45a7d9b4e6fca0985905a4d"), 1541194636, 0x1a19d68f },
        {  7650000, uint256("9007dd0e3766520e35daa36b349f574d3b24762af2bbfd3e2de9d15897966f32"), 1541941045, 0x1a13f27d },
        {  7700000, uint256("13447b2e8d708b83114f00a717f8c64d9a1ab508e8121dd14dee95747776b6d8"), 1542685226, 0x1a0ddd21 },
        {  7750000, uint256("0000000000000002d48ca2cf37fe0b2c39e256ced08ab8aaf5d98d32e607b9f5"), 1543432036, 0x190416c3 },
        {  7800000, uint256("88e4802635239b3b87ee26e660e68de46d29aa13515e337f056e612030ef02e8"), 1544178361, 0x1a225409 },
        {  7850000, uint256("d5d97c2ac920aac82d69eba4f108340bddb1702e4a537b2ed53eb1f604287a44"), 1544922785, 0x1b01d614 },
        {  7900000, uint256("757958c8be093dcb4c4b225305e27849a9bb01d64258793b400339a570a7f100"), 1545666929, 0x1b016423 },
        {  7950000, uint256("dfdaaf2414ef3a116bb9d775be66c4b2e812c383b24fa55fd89b3181ead8a043"), 1546411267, 0x1a157973 },
        {  8000000, uint256("1af919cb004bb05c369a862cb5ded70aaa123d0eac2432ceec859f6f42880660"), 1547155779, 0x1b01d883 },
        {  8050000, uint256("e9aacc0addf91e1a0954ee516a27d7f8c302870718365f98caf39df03aeafe26"), 1547899006, 0x1a234fab },
        {  8100000, uint256("00000000000000059722b0f86997bdad4e0384740eb7620b1071d48528400b49"), 1548640019, 0x19060536 },
        {  8150000, uint256("bb3c95c47649addca966ccf0679fbb9348cf4502d72a99b86d2cecbe91f09839"), 1549383257, 0x1a17ba9c },
        {  8200000, uint256("c048b60f03f23188806956dd8d368c94749fc6d8fe2c5751d63a0301ccfcff3b"), 1550129416, 0x1b01cb87 },
        {  8250000, uint256("9903512b07167251e061bbdc0556940177dea9cae0de0fe91644a3e99c46afdd"), 1550875246, 0x1a0e63cc },
        {  8300000, uint256("c61c84b023ad4b5b16a6e365fa2d632368986fffc1cf9777420cd5d73807c715"), 1551621307, 0x1a1155df },
        {  8350000, uint256("4f7247b1e941c8791767d1adfc3f40052eef80743af48d21798557e03d49ef6c"), 1552368523, 0x1a09aa80 },
        {  8400000, uint256("0000000000000000126a30d5179f6c11674cc861c038dd79eef3146dcd416911"), 1553115313, 0x19056313 },
        {  8450000, uint256("0000000000000000b66358e70bcccd2f26d50a05663c20b5ec87258a8156e1aa"), 1553863448, 0x1905bbb9 },
        {  8500000, uint256("98d5d78c95c762778d6b3e62dfab1c8a212287628ee43aff337ee45ef3ec250b"), 1554609926, 0x1a0cfce6 },
        {  8550000, uint256("000000000000000016cfbc59f9508d59558ef60bc17963eabb23790eb74e0014"), 1555357262, 0x19055bb8 },
        {  8600000, uint256("24a1b9c95d84cc6a2e4ef1282f4e29bc1eb797c6a3788e9a5c601783b0bdcf77"), 1556105747, 0x1a0d6d71 },
        {  8650000, uint256("cd7e370cffde4387fbdab0f2b88371329f062bec13baf480f4b52e838850d907"), 1556853501, 0x1a07d842 },
        {  8700000, uint256("ca0d3e0572902706a1ec13225fe6597ca6db73a6d04da736526bf1c059f04f51"), 1557599728, 0x1a06be2e },
        {  8750000, uint256("2233eb15bd6bc5edac0aebe13e1a937b3e2b3f0cb48dbf81073896e81309eaf2"), 1558347035, 0x1b01a5ae },
        {  8800000, uint256("647fa4a4fcb981300019f2808096e31e7d46bc3463b51ddb11cec3e908252c52"), 1559093681, 0x1a086599 },
        {  8850000, uint256("e57125cb77938b03b9f4d6ed3ce0550a8c88a3524d38a44daed79ad8afd7bc1e"), 1559839414, 0x1a148939 },
        {  8900000, uint256("ef459b7767eae0588ca1544a36968ec07259cb048599c8414d5310b77ec43898"), 1560585602, 0x1a082531 },
        {  8950000, uint256("6fa6cc3db457e39d7ba8cf3e929a5d38629e1439a8bc74a022c8f08d90c4a0e3"), 1561331963, 0x1a095d90 },
        {  9000000, uint256("942b62f60ae25478d6ee41ec498daefc306cf6f93ff500435a12aa6fe3750220"), 1562079462, 0x1a07d618 },
        {  9050000, uint256("550c166d4d9c05362770e5fe54104adb4f223db7e034b140f3d58ba8e3dba3b8"), 1562826543, 0x1a03f8c6 },
        {  9100000, uint256("0000000000000002a481e71184e9922cb0b23b3c0aa38276d406cd19b371d6d0"), 1563573031, 0x1908bf58 },
        {  9150000, uint256("7b10edf845b0fc4001f9b2f01ba3b9fe8131783358a45950ea513a9cde6e75ec"), 1564320466, 0x1b00d8fd },
        {  9200000, uint256("ff44d27cfaa33cb449bcac144d4a920144fece73ff635ac465788194df7dc8b3"), 1565068697, 0x1a0eea1d },
        {  9250000, uint256("6c83e1e5b11b0ef2e41029311f74f2638b6a035320e1b1388fde6b2a8ede84e7"), 1565817595, 0x1b008c29 },
        {  9300000, uint256("a0f214790be2a6c51401fabe7166536f27f396993394c0522a7ba076b94abe59"), 1566566810, 0x1a04bb98 },
        {  9350000, uint256("c12977fdfd2c9c250f88873ad0be36693bc39f7224249bfcb82e5d2db0d9fc74"), 1567315172, 0x1a096e01 },
        {  9400000, uint256("231815644a71807ce4eab21bd010eb4933f15c55f67956825dfe37ce95af02f7"), 1568062134, 0x1a0df027 },
        {  9450000, uint256("bff6229b913068fc1fa0952989760ca6c0b02bd8930500f00b22f1302da7b17b"), 1568810765, 0x1a0aa664 },
        {  9500000, uint256("5b0351361414e520e9132ba6c5c4926d6f9ee55c41b77fffce3a16ea15d4a1be"), 1569559943, 0x1b018c00 },
        {  9550000, uint256("0000000000000002741a99c624306c1de65cf04050047289c68629c83bc90b22"), 1570308568, 0x1906de34 },
        {  9600000, uint256("00000000000000002b2ff20c6168d24e7722a3ec9e36b69f2f365d4ec5fc51dc"), 1571058346, 0x190751ca },
        {  9650000, uint256("4fdfedc0ae41db09ceeca9461095ac4d219b0bd5cf522619c38e55bcefdbddb8"), 1571807398, 0x1b014cf8 },
        {  9700000, uint256("86a47c07e9b931339e2c2006d1be14cbb43fd5fb446c5cf9d3838d6c2ac44ee0"), 1572554343, 0x1b00b6bb },
        {  9750000, uint256("7065543ff8e78a54ff79d5fa38abc67e5a55d13ff52430bd52e542788a028b56"), 1573302939, 0x1b01fbf4 },
        {  9800000, uint256("0e52a46580927e519789868f0f033c8cc7c2e67a5878ab3bc79d7d87e68d4c9d"), 1574050280, 0x1a07a35b },
        {  9850000, uint256("9123d6e8a2183895d1cfd10a5b4a5698b3a22341349145605f1f64607b00f23a"), 1574799303, 0x1a0c67bd },
        {  9900000, uint256("00000000000000008c8789cf584524433adc107a4c5e2747216a739e7b767f69"), 1575547984, 0x1909044e },
        {  9950000, uint256("688ce80f9b07ace66ff72caac9bba2e7786b91b7ea7b7f4189f033ec821494b1"), 1576296624, 0x1b029036 },
        { 10000000, uint256("9e382e2ae1909a4f20c40f38bc7b9f5d0222d5f92ed8be9c04238209c88d55b7"), 1577042521, 0x1b00eb79 },
        { 10050000, uint256("a835f36411460a843ba4f9c77330afb5b0f0d42a82dac54cd74b308692971253"), 1577789728, 0x1b011b28 },
        { 10100000, uint256("a79d5e1dbf2d4a72791c8941c7bc946198d09ab8a1f82bdcfa7eaa1c741baaac"), 1578538315, 0x1b01994f },
        { 10150000, uint256("00000000000000076a83682d7683cafb357273fafe308c2261797f131965da98"), 1579285154, 0x19084d7f },
        { 10200000, uint256("e14c037f86661f6a7f886e8b658ed7d612ea94ab7202076f14fed723ca8abc12"), 1580030347, 0x1b030f46 },
        { 10250000, uint256("a49cb7e90d27ccaf2253f2262ae5f859b45c2309e8ade9430067244a572cc0fd"), 1580776653, 0x1b0083f7 },
        { 10300000, uint256("cf879988b014d1ad51493ed4392273dead9ff950db7cf9d528f302441a6baa4f"), 1581521658, 0x1b03bb8e },
        { 10350000, uint256("75fdefe4cbbd58c437517b55a2b0daf2853791a7f5c767090f8e2c0d6ce3fe0c"), 1582267987, 0x1a02aae8 },
        { 10400000, uint256("ffd5406c454fc3c7483fe5f3fa124e3a0d0a25570719c0fd8cfd39bee4f78687"), 1583015648, 0x1b00affc },
        { 10450000, uint256("000000000000000124fd48501e984162762c52c72c8fd38439671bce25bff731"), 1583762719, 0x1907d9d5 },
        { 10500000, uint256("2e7c794d328830995cded5b6a37a238159ea8f9553665d4e77eb4f13d10794b3"), 1584508664, 0x1b03c104 },
        { 10550000, uint256("e1284718270e249804b62bc8566faf1a9f5c71867578a452475a00c8c696e288"), 1585254092, 0x1a015e63 },
        { 10600000, uint256("28a97f6a1b2bfeab7a60c265e38957c6f2c7e3db4dc61cb83e681b23f3544075"), 1585999283, 0x1b008dc3 },
        { 10650000, uint256("ecac6494b4f9a856ff2540c1bebc1a2641e42e6e2c1dd519ccbde8feaaad932e"), 1586745512, 0x1b0109ad },
        { 10700000, uint256("43c7ce1278e9fc1706bec51029af1a379f8a68e32b1d9eef4562ffd24c42a9a8"), 1587492755, 0x1a09bc75 },
        { 10750000, uint256("6640076fbaecceb3f383571719314fef3b9c90317c7583b2b47876dd36e3e959"), 1588239121, 0x1a3c9c94 },
        { 10800000, uint256("13347801d7d0fdb856b150a766e06bb2d4115f1b279f1225e66da0da95aaac91"), 1588986740, 0x1a0aa335 },
        { 10850000, uint256("9a287ba179e78c60571a132b955b3185b28e43f0731588238d7210a903f77858"), 1589734074, 0x1b00c77f },
        { 10900000, uint256("6ab645a1d1827ead16d1b6ff084af1949bc293815b82e68c79aeaaf164faf156"), 1590481464, 0x1a6fa343 },
        { 10950000, uint256("257005bc8e646dae3c43683b5c3f09b5177db15ec1153e7a82de8dda22b6bf17"), 1591228117, 0x1a02643b },
        { 11000000, uint256("0f4ad10ae49b504246c0175f6cbab9b0f91b6568a88931e6341a83a731701054"), 1591976167, 0x1b008be8 },
        { 11050000, uint256("93b0e277fc75b043f5786016a2eb456f3ae94f65fe0241f210cf56322f4e122e"), 1592724625, 0x1a76efcc },
        { 11100000, uint256("000000000000000142cc4591c0c1b31d95781b947067ea5dd4ca448b63d29bbf"), 1593473754, 0x1901a4bd },
        { 11150000, uint256("427504a26d3fc356ec4e915cd7163f1e076f795bdbc911bffb56846ef5dab2bd"), 1594222683, 0x1a477685 },
        { 11200000, uint256("8392bf656466bcbe5b409b9878aa2628a43e1657fccc4ad4900b97df33b71b94"), 1594970624, 0x1a0209bf },
        { 11250000, uint256("9c484b3f2f160ec11fa181cff1838e0c3e164538f710992de2a6b0aac0eb7a99"), 1595720125, 0x1a03200a },
        { 11300000, uint256("34c6b8378598f1fef010308a444be81dcf84b042b7af01f6d00400f2b4012659"), 1596468086, 0x1a112712 },
        { 11350000, uint256("00000000000000011ef7ca57c9f00c2ec2d1a805cb0a5af83f007eeaeba52c4d"), 1597217270, 0x19012f32 },
        { 11400000, uint256("e3be134d99a37e9d920ed7fa57e0c2b2a6654100272549d084bed7886dd5237f"), 1597967557, 0x1a011383 },
        { 11450000, uint256("ffbbd81450f3089cc6a30578518603661ead1a1628cff274f90a5b727127cade"), 1598716679, 0x1a01c388 },
        { 11500000, uint256("e2551bbb9ab12a7e7404c8711bba362a24a937167e2ad34661b3109fb1b004b1"), 1599465484, 0x1a62fbfa },
        { 11550000, uint256("f3015138b0b7ee28da36fb22eabd10960e79a1ec5ecb927bb3fef6e692b8cec0"), 1600214739, 0x1a50d47a },
        { 11600000, uint256("c35e7b9a276e75443f1c3e22b7faf5cf5e2daa011ef0b15dd412cae42d91655f"), 1600964366, 0x1a37033a },
        { 11650000, uint256("00000000000000005f0590c8e470ba8cb7673f95a7b68f7de2a986a8bddf7afa"), 1601713616, 0x19013f9e },
        { 11700000, uint256("37d5be1045d7497fb23e7e4df4c1228015366e78a85c96c53d61c0970ac42aeb"), 1602461629, 0x1a01d4fb },
        { 11750000, uint256("0000000000000000cf25cbfd66e6486ea27873ddd9ce9b6171a13ed9c9d81270"), 1603210303, 0x19018f5f },
        { 11800000, uint256("af19af6a174ea7f9fe8a43c3cdb10482736d4162e2afe820efd78bfc1b3fe633"), 1603959136, 0x1a4dae8b },
        { 11850000, uint256("3a5b843b7d214ca2e80bd65b7c4168becf76329a90641b89ad9a5e15e45e3b61"), 1604706696, 0x1a01276a },
        { 11900000, uint256("1494d8b6deca1b05cb5ba99b294282a1403c566848ba02cb33020d4e205fdf28"), 1605454297, 0x1a02feb6 },
        { 11950000, uint256("0000000000000000c300737d1fca353855acd64ae6bcf0ebe30c4cfd9794a49c"), 1606201644, 0x1903f0b0 },
        { 12000000, uint256("0000000000000000e231d6676909d4d54296d640d996453b6778cc8081239c1f"), 1606947788, 0x19029b4f },
        { 12050000, uint256("00000000000000013326cbcd87c05bad2606fbe1ded5af54dc4fd3b935a63a5d"), 1607694526, 0x1902af57 },
        { 12100000, uint256("000000000000000044a4355bf9dc119b0939e94a815955ea4d433dbb0946d26f"), 1608441294, 0x19031fb8 },
        { 12150000, uint256("000000000000000305b63f516520bd481fe757ab13521040b6d1437b8a99fa6f"), 1609188263, 0x190376c8 },
        { 12200000, uint256("195207cd4a1f89f25b84e3dc84747518d97c6e6346e245e6a47d7a3e999c42d1"), 1609934221, 0x1a06c765 },
        { 12250000, uint256("0000000000000001608faf373934446a7621c22915c01263b9f8e22e77020a04"), 1610679791, 0x1902c0ce },
        { 12300000, uint256("1d448397102e6240ac0bf8b308cf56a89f79d371b29981e16056fb03090ac2c5"), 1611426703, 0x1a0db273 },
        { 12350000, uint256("67a03283d675ba1f0e494a69995abb598bb657fd29e988e2571ba8748311c534"), 1612173541, 0x1a129a55 },
        { 12400000, uint256("3ce0e96dc4c7c9d7d9e61287b28c2a6118e89fd2af67fe006d69c8782029af85"), 1612918917, 0x1a091508 },
        { 12450000, uint256("ed6e4a370a1484c00d5a537ccaa55db7383c9e47647e8f5863ee0bc246a0cfac"), 1613666253, 0x1a0a83c7 },
        { 12500000, uint256("697a015b62140c9549fbc8d8b3c1d027626b2f94d337db32115e429fbf233ed7"), 1614413344, 0x1a1bf3ef },
        { 12550000, uint256("886166ee98132df67b7a1b0dbef16535a448ec87ebd1024f400374ad0d5a44c4"), 1615159533, 0x1a034105 },
        { 12600000, uint256("606ef518e1b5aa44f0fb28b7ecbdd3addbb1bd3df319a800c347fd4576515b3a"), 1615905940, 0x1a03bc9a },
        { 12650000, uint256("2f16d3003836a5cb34ad213ae8cacd7e3ad9ad6e1202a58c554441908a3175b3"), 1616652701, 0x1a026943 },
        { 12700000, uint256("0000000000000001d9a62dc7633d12f24fe21a897b9b5edfdfe26716ed168983"), 1617399450, 0x19021eec },
        { 12750000, uint256("06d9bd004cf41d93984ffcf0384e220ffd8c7ba9955264c77e4a103d5633cb33"), 1618147039, 0x1b0088a5 },
        { 12800000, uint256("268de5f9f6d37348aad63cf8409b0301d0df8307cfb3a4e13c4165ec2e4c109d"), 1618894542, 0x1a7ebcd0 },
        { 12850000, uint256("863c4b6a9fc4df29cf80a25618c1782512958370cbc44390b08524c4f5213e4d"), 1619641605, 0x1a065c7e },
        { 12900000, uint256("00000000000000010faffecc0d433ab35cabcf1f4090689a494e90e83ef99ad1"), 1620389417, 0x19016b3d },
        { 12950000, uint256("a035f09d9473d7415af170590b07dece4f252d264d2959afcbe5e3529e1e0773"), 1621136258, 0x1b009314 },
        { 13000000, uint256("a4c1069938986237270340fa9118e839e9a4b614fddf57b3d51e988ab357c13f"), 1621883565, 0x1a09f428 },
        { 13050000, uint256("000000000000000086d381046a6e96b23fa8921db18c9d94ae899731475465a9"), 1622631361, 0x1901df21 },
        { 13100000, uint256("0bd1228f102da924732c6374e46832c32ef813e97dac9fb9ae4ab5f0e89e136f"), 1623378591, 0x1a2d21a3 },
        { 13150000, uint256("3c2dc58ba6f77b02298709cdd845328fbf0d3249bf1730d82ad5dd1b02492269"), 1624127015, 0x1a00bdaf },
        { 13200000, uint256("4ad52098ab0fceb56ae67aa93316c998d255a391fc5129134cb711d993c42a13"), 1624875489, 0x1a2e4fbc },
        { 13250000, uint256("00000000000000005104f3a44932bd4140075c2d64b6ff4b9dce4e71cb3ed87c"), 1625623965, 0x1903aa70 },
        { 13300000, uint256("67b755de4c92aba6c7e07310d95e099c3da79ea92f055cb1aa83391a0db30d48"), 1626372558, 0x1a462265 },
        { 13350000, uint256("3dd11bf6f47a176d5b40207f9aa662185f4344cacb776dfaa619779aa31d1da9"), 1627120023, 0x1a01175d },
        { 13400000, uint256("0000000000000001d7a3a43d6794f501906fc230ebc5aa7d8601f000b725005a"), 1627867452, 0x1903daab },
        { 13450000, uint256("fe9136e1cbe8d1ece54946fcec7084dde670a841988300d18f923e5a7203f263"), 1628614819, 0x1a06cb43 },
        { 13500000, uint256("0000000000000001ea6f8617d63f25376f69468503513e80c2f9a9f963040582"), 1629361886, 0x1902a09a },
        { 13510000, uint256("e41f3bbb0668b4db50682506e131d4f6c31fbf66be58d03d35a5dc30fed5432a"), 1629510979, 0x1a24afff },
        { 13550000, uint256("da5b6c5ef2eb17d15332263d75f4919d944b9fa2192855f3cd36a2310c220be2"), 1630109487, 0x1a350468 },
        { 13600000, uint256("000000000000000083789a5e4c9a8f55d1f904a62af1654826cec88cd7db8d55"), 1630856230, 0x19027c2e },
        { 13650000, uint256("51ad6fe0ca4f79480e554583942db36cc4d49d6f4d2ee724f73c2709e7255715"), 1631601941, 0x1a380ebe },
        { 13700000, uint256("9f7a8f1f8cd2200516f62a6dfbb2977dc60b463680d95839eb683d239818a9da"), 1632348034, 0x1b00861a },
        { 13750000, uint256("031224c98da837a1dc594bc5077f52cfa69bd0498d82d26b0bcca4d0c81f88b3"), 1633095377, 0x1b00b946 },
        { 13800000, uint256("d3e642c388a9dfed9bf4368f4c7fe3a897d9bdeb9aac9f712dc236209423994b"), 1633842968, 0x1b00be2d },
        { 13850000, uint256("0000000000000003489f7c8b32bb6f451ea6b2733fdf371a2351ee041e0512c6"), 1634590131, 0x1903d392 },
        { 13900000, uint256("0dcb664ead7c83f1162e5d4635ea615ddf17be98dbfd0073055258fbe10e90fd"), 1635335774, 0x1a22180c },
        { 13950000, uint256("c1465267597207a13accedc5a7547478e31b5bad408d2a21c14a79e4db6b17e3"), 1636081611, 0x1a01c860 },
        { 14000000, uint256("a33861c857eed46191cf6cdaf81693e0dfcd00b3a11133821b0c73fe1d7769d9"), 1636828206, 0x1b00ad8c },
        { 14050000, uint256("0a1be5504a6dd66f84eb6b0d214a60603810feded6cca50b22756cd55ac07daf"), 1637573825, 0x1a05a5d7 },
        { 14100000, uint256("4253bc80de076890d52d3970c0a3d326cae5586306faaeda905d55b97eebb0cd"), 1638320290, 0x1a443191 },
        { 14150000, uint256("868f81bd43bd7c88d169f356dc89fccaec52b4f5fe9c7d7e60c1b2e71dde398e"), 1639068380, 0x1a01ca97 },
        { 14200000, uint256("a5d0580b1fe26232a447e2aa0b6bc4b732d77dec80fa4380bbc3016829ea7e83"), 1639815110, 0x1a0322dc },
        { 14250000, uint256("007ee9607956e785e2b411d201c1f243df1c39f072f40370d837663e0606d358"), 1640562527, 0x1b00cca2 },
        { 14300000, uint256("91ec0b5d55fed273a2ad616e9b22858aef447181746212b22d6f2e65a5a7a861"), 1641310332, 0x1a20e51d },
        { 14350000, uint256("8315a96dd50cf1ae4ede556a71cb207e0452a39f0be6248d57a0377fb80d0ad5"), 1642058765, 0x1a2594b7 },
        { 14400000, uint256("7d774fd884477e56491434d1678b861cbb8969f6e0fc5072571ce74ffb82a1e0"), 1642806863, 0x1a073907 },
        { 14450000, uint256("0000000000000000f1fdd61f6b85a872940c258d75dd65a1988b21828e440bba"), 1643554075, 0x19036f6f },
        { 14500000, uint256("7de279fee9a88b3cedac3b0fead7af3ba89411545076a42c836ec1d6ba0d1d46"), 1644302520, 0x1a19ae92 },
        { 14550000, uint256("e0bd1aa0ede1da4a7fd9ec67b024ec78e5bbab5bfdf29d9a287370b9d3595efe"), 1645050017, 0x1a061021 },
        { 14600000, uint256("000000000000000321752bb738dffdc2713deb28d50d1d555f44a142bba6970d"), 1645798335, 0x1904d082 },
        { 14650000, uint256("a57d9ff31de9009280b3091eed7761144a0f64ae3504a022c2f5caeb71e91228"), 1646545485, 0x1b00f912 },
        { 14700000, uint256("ca4e9edd91d9b94fb5ab3e48708cccd8b76b51d82b6bd8231528f4db5ad8b976"), 1647292224, 0x1a02747d },
        { 14750000, uint256("47b15beb19539fd10444c6a695a90a2709997544521bf4dc225c89b5fbc82b43"), 1648038209, 0x1a086841 },
        { 14800000, uint256("0000000000000001c51fd4fb8cbcca3015aa4380ff612299ec0b71b0ec9c1ae9"), 1648783918, 0x1903ea16 },
        { 14850000, uint256("8c714b2c56403d7f4de3980cfc8f0e074ffa2c8d29f5a91c19930919ad19a327"), 1649530799, 0x1a07a175 },
        { 14900000, uint256("19617a17dab381144f77eafc8a70b8f4f7e608d35c4d10d1cf84811153fdc445"), 1650277728, 0x1a0603ff },
        { 14950000, uint256("d0618581aa087ee7e8cfe074b8a634c99934605ebb5e42c726b8238476dc9c90"), 1651024949, 0x1a1f1b7d },
        { 15000000, uint256("57debd1dd4427be41f9b0d59beb26ca482255c18b2a01979a64bb70b173a537c"), 1651770202, 0x1a017ed3 },
        { 15050000, uint256("c70dc5e1fbbe7c29874e102973644d4e1745f77bedfcc6fa532dd9aab60e6d37"), 1652517671, 0x1a1546c4 },
        { 15100000, uint256("a55e0a6d1aca93843cc84713367788be3d9aee2118723f0cc45d6d168abf64e0"), 1653265037, 0x1b00b21c },
        { 15150000, uint256("ade8ff62c635d2a322bcd5cb940c31f5275b608cc4e99c4e5d6e2ce884cb8bb6"), 1654011452, 0x1a043914 },
        { 15200000, uint256("37d2d4cf3aa67c6c190153a3c7d13630ce873e08719e73a98ab9b07d8bae4873"), 1654758546, 0x1a21e65c },
        { 15250000, uint256("000000000000000419cd4c1f40f943e5dd11a5f89d67d353eda7f8558d2548cc"), 1655505331, 0x19054cb1 },
        { 15300000, uint256("57a5ecc0aebf7355b4eee06bbb3702a33ec9cb083bd2971f3a12387a5f6b5025"), 1656252413, 0x1a01f215 },
        { 15350000, uint256("36787aa1a2e46014b6c9bf8c4fc628ab37ac7c86c5f5db75a5e3a6cad62f1a3b"), 1657000004, 0x1a1f4512 },
        { 15400000, uint256("7925f0f72836f06fca7e6ccbc6ffac1bafa77d23b72a9177993e290974997d59"), 1657747961, 0x1a26aaf8 },
        { 15450000, uint256("752a0c0a384f016c9d9e7ea5e1d1d6af1a0be90a1348f597e1c981b54e5fc7dd"), 1658496445, 0x1a11d6d0 },
        { 15500000, uint256("000000000000000439d5c66b2fb3ec50f50a68b65f5790d338150b63488de645"), 1659244610, 0x19049b92 },
        { 15550000, uint256("cb2ac2be83cd1ac89381c875c60de7f068e33b2d66975f536204cb51857d1bb2"), 1659993223, 0x1a462625 },
        { 15600000, uint256("00000000000000011f4fc83238b5a100f98103c5e3bd3bb2277b9c180648a4bd"), 1660740580, 0x19046212 },
        { 15650000, uint256("a045fab119c063a397e3883adc9ab69d04368478cd2a6ad0b3fd3cf7a24a750d"), 1661487678, 0x1a2a16da },
        { 15700000, uint256("82b7780efc7067d10ea03ba5fdaa3c72468dd3e3af8623539da4a0140f5a105b"), 1662235042, 0x1a08109f },
        { 15750000, uint256("6ea4cb0d5e9f41a9f4463ab409f6ac8e578bfc66e9e1d1a42ba4e5cae724f55a"), 1662982521, 0x1b00bedf },
        { 15800000, uint256("5760dcba84f74428de9ee0a46dbc36cd6a9bf2e8d1470e844701b8d402d385c7"), 1663729608, 0x1a0bbb04 },
        { 15850000, uint256("0c5548e45e615b97f3aa2fd6711f427dcada91fef386f969f9e267cc92b6e5fe"), 1664476834, 0x1a2ab84b },
        { 15900000, uint256("83c418ac7ff48ce7678f0ccd9cb8633e24551bb3c3129c01a1131b8aa7d168dd"), 1665224997, 0x1a60cdc2 },
        { 15950000, uint256("1054d20f53e2d95e70e9f173a41f769335a57f05f02d94fd551023efcafd1512"), 1665972369, 0x1a06c5ff },
        { 16000000, uint256("5c0c7d7baecc5e13c69f06eb90534ab2db8ff0cc98a1ac8d8797f11dc16ea0ad"), 1666719839, 0x1b00dfbe },
        { 16050000, uint256("d532eee5cde3ac860c6ee7c69e7db39b562509511bca90ad61534e6329c9c2d5"), 1667466186, 0x1a169c2b },
        { 16100000, uint256("f53199127025b17f5f5933af931d371f42f2e225428962d64ed09841f254af3b"), 1668213754, 0x1b0137a1 },
        { 16150000, uint256("23a2cbd5d29a0ce653ec37b4c4bb9d7f12a3e8bde00ee327d7a05f8ed0eeb12e"), 1668961826, 0x1a1376f8 },
        { 16200000, uint256("076d2eaf71c2b346362a94865bec5458f30a17021275a2294b5a1b77594b8efc"), 1669710050, 0x1a0e2f14 },
        { 16250000, uint256("a57c56f443044af19781073c6220d3ba9e83ca7214a615a5d52959b5cbdf0302"), 1670458521, 0x1a069598 },
        { 16300000, uint256("f24b31bc64952526ecd6fee5b9dc681f1347e879bf8ee04fc77ddf152a8b8d60"), 1671206839, 0x1b0136a7 },
        { 16350000, uint256("00000000000000004001d2facfca5744a2bfb23b9b69b19c48e73e1066136895"), 1671953436, 0x1904ed92 },
        { 16400000, uint256("f070908abaeaa2cf7a04ad53e499631ec923a3f61aac2acb9ad9dcbeeea6903d"), 1672701648, 0x1a03bf14 },
        { 16450000, uint256("ea446043605bd5df288a9961e382f755f327b3da12e5b4a176f06fc59bf04284"), 1673448782, 0x1a09ad79 },
        { 16500000, uint256("0f08ad160c196da58d855e505aca4237d8527788c917b8e85593ca33444e549d"), 1674196649, 0x1b009f8e },
        { 16550000, uint256("f88ab856d86c38877ea4f5c91c188050723a241279807e88a841deaddd209832"), 1674944034, 0x1a04f7d6 },
        { 16600000, uint256("0000000000000003ba372da47af524347f62ee7c82a333fda757e73ff45050ca"), 1675692182, 0x19047844 },
        { 16650000, uint256("e5ee90cc4d3a60e3e5aa9cc711a1019afb61476330c2f70349ecf00824b438d1"), 1676439888, 0x1b00eeff },
        { 16700000, uint256("0000000000000002562429aa5488874a0b71e41fe4d1b5e203ffacb577db0a75"), 1677188328, 0x1903c7b5 },
        { 16750000, uint256("0e954244e4d5ee093535ab2967d8c3ff66814e992e46d3260835d102bb414a5e"), 1677936603, 0x1a63763c },
        { 16800000, uint256("0000000000000003a1088d27d85adeda173f0db69c7ef0ec65e853ade2a67aea"), 1678684834, 0x19043723 },
        { 16850000, uint256("aa22b6d47a569c53733595e2c2271a515c12539a9c7ee5b796b72ce09bf47e84"), 1679432863, 0x1b00cc55 },
        { 16900000, uint256("5e8c21505290cf2faa7cc9c20659abae9898fcf8627bf50d9221ae308c0c9901"), 1680180874, 0x1a08f718 },
        { 16950000, uint256("467efa8b08e3dacd5179fbcbd07c917d209823a92c63ce39621c98768adb69bc"), 1680929061, 0x1b00ece8 },
        { 17000000, uint256("f167688cc0102743b135499ed9f9eff9c5bad096203150e438be0a6e783d5587"), 1681676982, 0x1a10412f },
        { 17050000, uint256("b4439dcc0dea59689e3e3a69e155396d2c4b62afb85b9e3f01bd684c29942050"), 1682424244, 0x1b00e855 },
        { 17100000, uint256("7fd2a2a67a80d8ba61535784de932f43076c59a38875b7725a64b772cbbc7769"), 1683172619, 0x1a08af51 },
        { 17150000, uint256("c2a89b8e876d120e647654d60d840b70bddb0aef6276c547133a4fc0b558f1ab"), 1683921817, 0x1b01b3f3 },
        { 17200000, uint256("3e7686de60ebca4f8f6531669a9a69d97c49f832b9f9994fd64008a6ba4d31ab"), 1684670123, 0x1a0b5921 },
        { 17250000, uint256("0000000000000000b832b801270da9c4eb4aea4ab28fc94f29392b76c682337a"), 1685416850, 0x19059dfc },
        { 17300000, uint256("f21546be1101e60de2546bc628c88aa1f02dcc56ff9b537f31f454102a9c2370"), 1686164610, 0x1b00ec32 },
        { 17350000, uint256("00000000000000013c41f8b933b558a241d7b59e44ebd83153551fc7ea7fc7ab"), 1686912613, 0x1903077a },
        { 17400000, uint256("a3cc4d8b631a39d7fa94b718090da09a136ca1641ef2cd7491bfdc323b072ce4"), 1687659575, 0x1a032311 },
        { 17450000, uint256("b30b65f5d25106c07335dfcbf160186b9e4737ee0b91a3bd783fe00f8108d533"), 1688406575, 0x1a0ecb01 },
        { 17500000, uint256("31838212ab7cb0eb24f0b7100b2a688f92c8d0109878ce8360586b26cdc1da68"), 1689155057, 0x1a0a5772 },
        { 17550000, uint256("e43730c4d3d5e72cee8b003840c211e723e2c3b73619893adefbc5bdc71f6cf6"), 1689902729, 0x1b010756 },
        { 17600000, uint256("d2ec07c94dc053a4e474bdc905db574f6f2dcb5a92dbbba405cf66e862a08eba"), 1690650527, 0x1a57348d },
        { 17650000, uint256("3131e9146007f898467b10fba80b269ed05fa066c13ad3130cdad05040e3bf4a"), 1691398386, 0x1a0dc9da },
        { 17700000, uint256("0000000000000004d65cca5df8c44830e0a20ff58881e3dfd317528f6635a77c"), 1692147015, 0x1905edee },
        { 17750000, uint256("16793b8f82356594bbd9f403b553942f917729272a5e50bb3049a876a5986108"), 1692894614, 0x1a02df57 },
        { 17800000, uint256("f0d9bf94b82133a3fe2e7c532cd4e16a785a4f5c48160d275d0ab1f55f867c48"), 1693641853, 0x1b00d79a },
        { 17850000, uint256("0000000000000003b6e6f9bf1b318cecdee7ae2e80f78431ed631c7537db6db8"), 1694390015, 0x1905b186 },
        { 17900000, uint256("a2b9e2468cfea96746ed54e901886e834b1994a7c06ffd4268823147e3324831"), 1695138165, 0x1a07df6d },
        { 17950000, uint256("2857c6e072ec2eba09803e08459349ae734a855f1c81df6171eeeafc1c904b47"), 1695885371, 0x1a636ee1 },
        { 18000000, uint256("c71cc4929af6adb6b501f59a5b60b2638e0fd1cbe631b6ce40aacb21b46ca7b0"), 1696633305, 0x1a047f1d },
        { 18050000, uint256("00000000000000043af521a8e3917cba03400df9b826fe1db683b9c0b2c5b053"), 1697381628, 0x190bc865 },
        { 18100000, uint256("277cb19a74321f4eb8d90a87cc21ba680a539672d2f16a0eadf5c98f03e6e902"), 1698130156, 0x1a045f50 },
        { 18150000, uint256("286091e930b4d516c81869d952075d9d8ff59abae282d7a5da6670f333fd7a8a"), 1698878037, 0x1b008802 },
        { 18200000, uint256("0000000000000001fff0b3182374e6d8e192537515c12979b8ea23f88ce28d59"), 1699625438, 0x19068bd2 },
        { 18250000, uint256("00000000000000055c3668e47cab579fc6203c5e19b9b3d7700c7ee91999dd9e"), 1700374675, 0x1905f521 },
        { 18300000, uint256("303750f4f54459b6021df26a6bde07bb31d917096ba98be400506c009079fbf3"), 1701121548, 0x1b00dd0b },
        { 18350000, uint256("9b09c7748a5b9f7db3f7153494231f2aaee237ff58592a0ffcd8dc425aa616a9"), 1701868950, 0x1a613b3f },
        { 18400000, uint256("76f4a2fd2f164d2450a542f2b6a9e3a1d69c369a9a06d584a9747c6f6d08729b"), 1702615693, 0x1a137afa },
        { 18450000, uint256("97eb40ffc9dbe9c8368480501caba92a3b55f58bf091f3dfbf5af336126822bd"), 1703363239, 0x1a14667b },
        { 18500000, uint256("745dc7b89208de482071a3a8d13eb5596d55bedc4f5ba2fa74cbea9ecf91169e"), 1704110816, 0x1a5daab1 },
        { 18550000, uint256("d6bca8804ff2666ca22b2bc206414a1d84fa81fed981f1309dac58274dbd1b3d"), 1704856926, 0x1a688f3c },
        { 18600000, uint256("46d2a647f1b27fd528e2e67a9aa7019b62cc096542a3bbdf8982958a0efd517e"), 1705604816, 0x1a0eaf5c },
        { 18650000, uint256("1e122bae1e71928a285d3522e5520a06ec8f29b602c64b7fec7c13574594945b"), 1706353445, 0x1a631c68 },
        { 18700000, uint256("725af698bb6689b9a9ff43377f5724ff66c01ab0be696690e1a43615b8af67d9"), 1707101269, 0x1b012fa7 },
        { 18750000, uint256("000000000000000515c04ee70105ae02942834f3c78b4c0b2f0088e3d0ac34b8"), 1707848999, 0x190804b6 },
        { 18800000, uint256("e309521f9e741099e515c7fdcf3afa7628d7ce762c65bbb43b1a3d92f7c643fe"), 1708597390, 0x1a04605a },
        { 18850000, uint256("769171b5955b2e507661bd157a68f516659961f5ef1a4939661fb7ea316369cf"), 1709344679, 0x1a044f2c },
        { 18900000, uint256("5faa362c911d3c17cf5663d6ea73cf1b515bed236884aeeb60e62525ebb3a2c0"), 1710092058, 0x1a0f4d5a },
        { 18950000, uint256("731b4e8aa90f8e1ec83adaf78797ca0dffa8db25468bd40f1d2f106856e1c6f0"), 1710839260, 0x1a1457cd },
        { 19000000, uint256("67066a10cdb8f3d86a4b405209e06ccc77b908d464af04193ad47682c0b4da73"), 1711586649, 0x1a012a4d },
        { 19050000, uint256("d1d3a23168eb7f64a491f114c5d7148c9380b5117f7162e9c76db0dcf9b0dc22"), 1712335124, 0x1a43d183 },
        { 19100000, uint256("60269979b5aa26bdafa6020cc7ac87282fc309048259a5964d09c2767e955361"), 1713085436, 0x1a5386c5 },
        { 19150000, uint256("33e7179efbb71577189656470e7da4c7d25c0944601fef6a81b43349275cee2a"), 1713834790, 0x1b008e7c },
        { 19200000, uint256("000000000000000298612045c97be8f344df165704558943584e80385323f623"), 1714584311, 0x1902eadc },
        { 19250000, uint256("4d1f4dbd6f881c1500a78aa0089cb40afcba01c5af48a0cde69632bc937a0272"), 1715332831, 0x1a03e515 },
        { 19300000, uint256("531bb2dc1a9fd02a473d9bf4b3f3d5a75cc1c951ba319a95596d4eba6d936c44"), 1716081634, 0x1a0177f8 },
        { 19350000, uint256("0000000000000000168d4700c91e98c7fc3f6433e7d8572ca2f613033bfc96e0"), 1716831195, 0x1901e09d },
        { 19400000, uint256("000000000000000050369e58fcaca6abfa0fc0191df4b128dc258ca6fcd80161"), 1717579689, 0x19021d20 },
        { 19450000, uint256("d726d1170a1c7fca27a94e8f78f4592b2ec84ea409958a2737caa76ab39f0af7"), 1718328635, 0x1b008304 },
        { 19500000, uint256("c008cae8399ff9a4d9a5572f3f2ddc53e2db9754df1dda6f1f09424da8dab29f"), 1719078271, 0x1a219c86 },
        { 19550000, uint256("fbdc07f2cbf74428a6f72ac0ab871cf20c13a49ce5cf9038c23ff71aeb04861b"), 1719826219, 0x1a01b4c8 },
        { 19600000, uint256("b718184597349858e382c4084f6bb142690e941d52fd735d29058ac095a10e9f"), 1720574883, 0x1a013960 },
        { 19650000, uint256("5b1b4e51be273df6202a5af3091862dac2096fb48f7648b78e67c3ecdd3a89e6"), 1721322130, 0x1a0b1e5e },
        { 19700000, uint256("0b8f75c50bbc98b0a8134bebf311296cae935f6884ea06313e6484dd0630d85d"), 1722069795, 0x1a00e5e2 },
        { 19750000, uint256("44e4ef9c34b9575d028c508319b35b42592780fc5bf827db86889fd5ecabde9b"), 1722816008, 0x1b0082c3 },
        { 19800000, uint256("e6a9c51d1b737ccbd88f660002947757ce511e8cc4910cdf009494b853e09841"), 1723561532, 0x1b0113f4 },
        { 19850000, uint256("0000000000000004bf9838587eb82fb94934984291d008cb53d25453b4cf3b85"), 1724309324, 0x1905baf1 },
        { 19900000, uint256("ad6d4d705368b8cd770c437df4b7f546428e40b22d99e5589f747a5236e238dd"), 1725057241, 0x1a681f4f },
        { 19950000, uint256("000000000000000235c5ef4cc4aa5be608d58fb5238dc47ecc0702abb8cf7bae"), 1725804170, 0x19042f3e },
        { 20000000, uint256("f530a66ba6fe93e647f7d88a9b3f22bfe8c2c2ab1ec1b0286286f86b82d6a10f"), 1726553537, 0x1a08cd13 },
        { 20050000, uint256("000000000000000263d0116e93fd98dbf88354025cf75c9a920b0209e9225bac"), 1727301273, 0x19032878 },
        { 20100000, uint256("38b73497756508f9ed0420ec043e6480419cd6bc21c58b8d15afc4e56346f502"), 1728048860, 0x1a534034 },
        { 20150000, uint256("a8fd0ad76366582925179b469bb93a83c872f4e27127fc9a76bc34828064609f"), 1728796511, 0x1a057c26 },
        { 20200000, uint256("d97c59bc63c56fa67c64a633e91d4d1a0b3076cefbd972391ea4322fd6a6b8eb"), 1729544928, 0x1a00feb0 },
        { 20250000, uint256("c9b2b70394f54e15a79ff7566a3cf2a3e8ba568fad01a456680726185261dd5a"), 1730291973, 0x1b0114a5 },
        { 20300000, uint256("0000000000000006339dfe374ffa190439718bda67507806346950f06c11d617"), 1731040943, 0x19069ea9 },
        { 20350000, uint256("ed82159c414265ef88e72bd012403c6b61a444f7f722f219459146a41f4e3daf"), 1731789744, 0x1963e581 },
        { 20400000, uint256("00000000000000033d0d3379819773677c37369807e972f99cf7fe1cb3d4bd37"), 1732535229, 0x190385b9 },
        { 20450000, uint256("1532302a0a071a784227b60dfa4e3de68c1555f52bb9d4fda33623af4924167f"), 1733285282, 0x1a338bb5 },
        { 20500000, uint256("d39c147eb2faef374f1e5e0a9095558c5393d3a2ccee981de65dc4203845107e"), 1734032704, 0x1a00f3ee },
        { 20550000, uint256("0000000000000002a8a1871487ba64c9053cc9ff2442a69118c45bdf0b7def57"), 1734780440, 0x19043329 },
        { 20600000, uint256("e4d1bbecb16d36e62af8e65bf5e8a6f7e619524b196e4cd02b2df32169a838f9"), 1735527571, 0x1a30242a },
        { 20650000, uint256("00000000000000005b3c17c0236a21d87fe242e2a2ea3bf38560c6c1c52cf996"), 1736274856, 0x19035ca7 },
        { 20700000, uint256("61b3adeb781b47af6b9d018134bdb80014d074d8921c6f462a2c2f2da75be4d8"), 1737022573, 0x1a00fac0 },
        { 20750000, uint256("5756c0066dadc9beba7a5901f152fa81bb9409a579c09f59bbc42e161ab7a209"), 1737769708, 0x1b008cf8 },
        { 20800000, uint256("0000000000000000ba79e00bd88c25d5eb2e50571c0eb99fd819f4035f48a34c"), 1738516357, 0x190566b5 },
        { 20850000, uint256("54a0233fe47b1be1f61b04da0f97a62dc01dc87411c6b27352652559500d51d7"), 1739262819, 0x1a465d5c },
        { 20900000, uint256("a2b6267149b68ebb5fe2e38c6ae7bcba9c6598e628d51ce449a9c9cc637513a0"), 1740009360, 0x1a30dbb3 },
        { 20950000, uint256("5eb7ea1c1f812efd0c6dd568f32414b18ffeb1bb79cb427f10e6425fd5c24fb8"), 1740757473, 0x1a015576 },
        { 21000000, uint256("0000000000000001cb40d3be76bf601d98555a069669d963060d633ea3a140e8"), 1741505272, 0x19027f4c },
        { 21050000, uint256("39b5b310d35759d5ac078d81d2591bfcd02108a82a3db57ec5b9737f204aec30"), 1742253262, 0x1a105b42 },
        { 21100000, uint256("f8ca1c9a623b8bf33dae4e5935026638c528eb722da2d42825bb55a1d20438ec"), 1743000361, 0x1a56f5b0 },
        { 21150000, uint256("cbb1d764fdb34a608916b8f4cef7782e2d8be9e6e3942023648a180fa482e23c"), 1743748007, 0x1a05a058 },
        { 21200000, uint256("efc205c5e6f08292283de8bfb68d1b8d6232fb475230f79adc6a024e563cad82"), 1744497183, 0x1a0760a4 },
        { 21250000, uint256("00000000000000011f0fbc8d75bb84ca43b54abab8354af0dd0eabdeba93b07c"), 1745245670, 0x19033691 },
        { 21300000, uint256("f9b57fc0b881ce73ddd3b7666c00d87326a12ba871ae99d979ef02fedd1c4548"), 1745992698, 0x1a2b3791 },
        { 21350000, uint256("2da7fa4d4d0354f276f675c00927dd0caca7678a6bed001473039c77ef056535"), 1746739936, 0x1a1cfc42 },
        { 21400000, uint256("00000000000000016fa81ba4c87f311924e92701f4a316e194db9f398a64f2a2"), 1747487248, 0x190458af },
        { 21450000, uint256("0000000000000002ff12f21765513edc89eb22cca98044da8d5dccad3d8f1976"), 1748235035, 0x19049907 },
        { 21500000, uint256("00000000000000007cbe22612937832c2e6341ec867e881979e2246df44fa727"), 1748982571, 0x1903b647 },
        { 21550000, uint256("58698895113997dd838e079e592b473ef915e7bd7308f34dc72046a685f61802"), 1749729519, 0x1a440ef9 },
        { 21600000, uint256("45fe802cecb9bbb46281c51f1b00e6e50e148357ffc056743a9fab6ec2ada347"), 1750476448, 0x1a3ee20f },
        { 21650000, uint256("b32999d9bd76858f3bafaf60f506aaa85d945d7426cd7b94fad49d3aae603e31"), 1751225200, 0x1a3df31a },
        { 21700000, uint256("457f6864b52e5076a433afe3c28e3ae0bbeeaba9036a782ddb691242326fcb80"), 1751973911, 0x1a26d784 },
        { 21750000, uint256("68af4856b47ca42be356b49d54e674f2b1c65eb3bf94cf7b9c57b88db6491dc2"), 1752721665, 0x1a4574e1 },
        { 21800000, uint256("00000000000000018417bd479e1787240c92d7b391e7d4ee5e251f91c0c29839"), 1753469430, 0x190552a5 },
        { 21850000, uint256("000000000000000501175df991ff397c6571d13ed12172c06501544570fcfc3c"), 1754216183, 0x19054356 },
        { 21900000, uint256("00000000000000026de4066676271d923beeb62bf86f03621b45bb0ca63ecb25"), 1754963960, 0x19040a3a },
        { 21950000, uint256("0000000000000005e809390df83f603c31aaa663be22a45d7fe1bcbfa9cbfd1e"), 1755712233, 0x19098f97 },
        { 22000000, uint256("f8ee51070753b526000469277c2e73981d96f15852ae7c9b0ae5de0bdb8b9ee8"), 1756460375, 0x1a34dafd },
        { 22050000, uint256("b8e770c7bfc18df98bb06c71abe99a1274213e135f59007e6145d5514a7182a5"), 1757209014, 0x1a0a756e },
        { 22100000, uint256("12ff66184cdcb3022bd0b0eabba836e7e32271cb970e2d9485db914a83009d43"), 1757956783, 0x1a07c55a },
        { 22150000, uint256("1484bef2f73fb2d1342d13843b0ec35d2ef3fc77d321d12b7c02332f963c061d"), 1758705052, 0x1a6d0df0 },
        { 22200000, uint256("a142469226df9c63f2568f47b8f62e385696d0d02fd3ceffdb24e30f8f0e63a8"), 1759452243, 0x1a396b29 },
        { 22250000, uint256("4009bf894b04ef194c9896ca47713bdb12bffb28b3a38ed8080b949aaa1ad16b"), 1760200955, 0x1a08b1ee },
        { 22300000, uint256("eaaa5d56acbdb087e3863afb61acb9cf89c0ace4aaab7407977bf71995a5d54f"), 1760948893, 0x195a0181 },
        { 22350000, uint256("47ee7b3d4104bbd57ecaac9ed70c1cb31c8d5c4f5f8a2642bcea4b56a5366d41"), 1761697587, 0x1956916f },
        { 22400000, uint256("6f1b8bd68d1c934640daeb536737a4e8d3fa3114c57b3ba79e0ea3cffdd31068"), 1762445465, 0x1a0df021 },
        { 22450000, uint256("887a6e3231018faf6545f48c92154cc05d3dadd6c6bb138e1c0ae3afce58939e"), 1763193250, 0x1a09ca7c },
        { 22500000, uint256("e9e740eef2cd62cbf4321e11b26703acc1f0506c726cb2a61f7c886974d1bc7d"), 1763941298, 0x1a2aca28 },
        { 22550000, uint256("547063a41e8a12475ebac0e28bbeda0cc1f60d5199280923d84de92050cfe1ab"), 1764689956, 0x1b008011 },
        { 22600000, uint256("a24c25146b10df09be9e67872eea342604ed310279a0bdf95015bf64f102d612"), 1765437489, 0x1a08a125 },
        { 22650000, uint256("00000000000000035d2e0345b1e8e510a9b38ba77624f471176c8e3591b3271b"), 1766185463, 0x190582be },
        { 22700000, uint256("71e864b0d4bc76bf6bd5b452e04fcfd15c67076d926af6ff390a6f6c38febf8f"), 1766932854, 0x1a4aab34 },
        { 22750000, uint256("e7c18ffd186e3360f5e4fff27255966926ed4ac85523dd108218685563009799"), 1767681371, 0x1a213d3f },
        { 22800000, uint256("17e5a64c96243a729d9bf4fdd81f2612007cc5cba5061b8707a341b494f67b60"), 1768430409, 0x1a3c4a87 },
        { 22850000, uint256("e8c110a2c85c2a46fd457ace1b7fad8c5fc56bde26badfea9cdb58b098041bdf"), 1769178768, 0x1a0137ea },
        { 22900000, uint256("7603677c26c2e602be6d96881b5e7adfc513ca14d655013f8eb7c501042d2893"), 1769928015, 0x1a37eb28 },
        { 22950000, uint256("47f1f921317173527afa2adfcaf6fba84001d046b99b0054310888a5d1d70fac"), 1770676119, 0x1a009c43 },
        { 23000000, uint256("a805aa0c3c4e01abee1ce0edbc7ea7a4dd2fbf920681ced7333e20b35f95a97e"), 1771424588, 0x1a0b9a5c },
        { 23050000, uint256("00000000000000005f024df2e7fcd04fc57922afe307dfcc63dccfc02bd1864d"), 1772171620, 0x19051eaf },
        { 23100000, uint256("00000000000000027f0b39b6119e71b533ab7200c918e341de8556d5a774221b"), 1772920591, 0x19030694 },
        { 23150000, uint256("0000000000000003cca7ec6d5ff3e44ac0cc6938195afaa91f8aa488fa5a104b"), 1773668666, 0x1907c9e5 },
        { 23187000, uint256("0000000000000005611e332000cc21f5ab13da2a753b8e3901a683fe8418de15"), 1774221766, 0x19074103 },
        { 23200000, uint256("bd4678ec1d409217ac43cf881a39be8774e71b5dadcf09b86e47f18756cef8ca"), 1774416260, 0x1a780579 },
        { 23250000, uint256("45e0fdabdd9fcd1939b13a4fc3f43d00806fd928eec6d7fb3027acb44bce27db"), 1775165600, 0x1a104f83 },
        { 23300000, uint256("69df2c94f0a7cfba3f8207658f8c6150be007e4a3df057881fd5e543292c6a81"), 1775913372, 0x1a17f1ea },
        { 23350000, uint256("c4043ba5bfbebf4c5170c778e68d4ad100b78b759460c10821ccd89bf3b50129"), 1776661770, 0x1a50db3e },
        { 23400000, uint256("423d7e97e6fe8574e9b7b0a445418c8672c9ba62ccc66c9bce44672b741feb1c"), 1777409393, 0x1a0167b8 },
        { 23450000, uint256("0000000000000006179a7a495286c620f72db202e739ca513104f3da18910422"), 1778158254, 0x190a6784 },
        { 23500000, uint256("ade47d5ccbb92cb1d965b97a187bdbf65bf74be6a3709cb6a01339f8c2856deb"), 1778906996, 0x1a0e8757 },
        { 23550000, uint256("6fa429ae324b04e2060f6cbd7ede6a5ecee3d24d9ae0b6d365e417c529fac0f7"), 1779654230, 0x1a19c854 },
        { 23600000, uint256("00000000000000029da9da8e4427fbd7adb0665a0090375d1337018428885765"), 1780403050, 0x1904b9b8 },
        { 23650000, uint256("70c79c60e3089f3e67273b2753a3274d1d4601c74b1e011dc3fc053b73c1fffe"), 1781151846, 0x1a609015 },
        { 23660000, uint256("53cbf7222ccc0d5c81d8427f4bb63cf7b1af07f21b9a33ad95db9a75262d88dd"), 1781301527, 0x1a6d8294 },
        { 23700000, uint256("8e18a4f0bd8d5e376e446fc87545ee9588975407e5ede1dd3d2a8a5f7e75f9bc"), 1781900018, 0x1a20c1c5 },
        { 23750000, uint256("305d9d65d674040ab7e9e830c6d0e0d98e8f3a11a189f15c9e398c14574d2eff"), 1782648446, 0x1a01a127 },
        { 23800000, uint256("71062ebe3a704b1c4efdb403c6569d2dd44363326641d02cd06034b3ad01a929"), 1783276211, 0x1a575af8 },
        { 23850000, uint256("544d7bca0b7b91ce9c53d380d946975ee3cbd794f6aad1d8c9e2497158595c80"), 1784006076, 0x1a6451ea },
        { 23900000, uint256("d442acc09fe4b002ad2f1d238a38c185e4a41db69b6e86070d8b2300a8ce9450"), 1784752331, 0x1a18e940 },
        { 23950000, uint256("a508ecb0e88b2aae387aacc028a3ac24b5c7d084dd9d22b352268db151f4db79"), 1785500949, 0x1a4de6a8 },
        { 24000000, uint256("82fa126e82a287b121ba57b7d008624750b0d456e398746e9c0e8fe6f760eb72"), 1786248414, 0x1a138787 },
        { 24050000, uint256("5fca091d2bdd7e90b5a165895013ca975cd9a41ac59ad30a41d4e1640106c3db"), 1786994995, 0x1a526f72 },
        { 24100000, uint256("0000000000000001962842657e2332fdd354855c6878e057015d97f742cf3337"), 1787743826, 0x1906a5c3 },
        { 24150000, uint256("00000000000000008dc1c9f77a7f63835f06a3954d206d6ebac210aa550c942f"), 1788492815, 0x190780f9 },
        { 24200000, uint256("b80c50feb09f0fe1cbc2e7a97fb93e8f329e83af62471b6d78a99bce1d14cefd"), 1789242339, 0x1a745399 },
        { 24250000, uint256("c549fcd7bc054db8b74961bb9a45b1b2e8cd993be69946ac12a67e04cbbff92c"), 1789990939, 0x1a22194e },
        { 24300000, uint256("cecd79410bac9567f867b2b90f88e7f84b4314ea787052fcbc464ca896789b4e"), 1790739764, 0x1a50e745 },
        { 24350000, uint256("90ae85097f503f57deb712198b94a864e0bbfed5fa5e863fdc080cfcfd7536eb"), 1791488624, 0x1a2381d6 },
        { 24400000, uint256("706ca888c103f2a5d65afc39b9b40dfc4473da1af1565114a0e9fbe62117892e"), 1792236585, 0x1a019d50 },
        { 24450000, uint256("6354bf0c6d0b308c00b20b9e70e3555041439f94288fe05b7277b30cd4c59b2a"), 1792984767, 0x1a5180fd },
        { 24500000, uint256("2a73146e6f0557518534c09a76d21be144fb1aa27db51c91eed20bd1ddeefb51"), 1793733201, 0x1a2b361a },
        { 24550000, uint256("9f2a0848a0b014ae2e6e3b55e29bb0716cfb4bae34af37b76cd8d8ee6f0af8bd"), 1794482687, 0x1a026b0f }

};

// BEGIN checkpoint difficulty context -- AUTO-GENERATED by scripts/gen_block_checkpoints.sh, DO NOT HAND-EDIT.
// Real headers ending AT each of the newest 2 checkpoints (BRCheckPointContext), oldest first; the last
// row is the checkpoint's own header. Verified at generation and again by the core at start-up
// (BRCheckPointContextVerify).
static const char *const BRMainNetCheckpointContext24500000[] = {
    "020e0020d57a7c166ab0b468219f63b78c51d413d92badeebd9ced67b74d059555ce519c2d0fbbc76621fb2aee8127081b5b5d9507342d5e94609d0081f3ca52602cf6b6ba2fea6a94f6631a1111ff88"   /* 24499940 */,
    "020000206b075c122a225b0f15fc0a5452162652c1b10014791b13c31de1ceba00f1c083f8142597bb44037e595060b004fa238d219ec0bbb98f4d418e2d79d3273f6a31c12fea6ae528661a1d314e45"   /* 24499941 */,
    "0208002003678ff65dba98915282894572b066a07459c25ae63b068f01741d8adf31e6de8019cd71c28371cb898ad5551f24b5a621e4e5ae195370e4ca4d1fb22104c0d4c42fea6a5cf1321acbdb2108"   /* 24499942 */,
    "02000020e98e902cba18000704f8ab1d617ce572bdce47e5488147afa7df4b170fb1a40d9c0bdfd56ca605b6a02e5bf710828f59d859726aedc8b13ed1d075889ef7d9a2c52fea6ad2d85d1a10222248"   /* 24499943 */,
    "02e2ff3fe0a6dd358da9bba0e98790d6b7679cda3218832af5596239c1c9def703a7c42b5a7b918d9379d31387e5f0dad3aaf1ef39507a0292ab4ecffa25f2c3c788ed2acd2fea6a359f0a196063b17b"   /* 24499944 */,
    "02000020775a630acf76241485512c7eda05bbab21fa971b635510e80700000000000000d6abfa224bb0f8158eb31a63bf9e6eab7a09312aee2a69d31c0003661446ddfbcb2fea6a2ee0541a3e8837f3"   /* 24499945 */,
    "02000020614dc1d8644cd58b1809627cf53511e8955a678aa13d4c4855754164f8e9cc840f7079f65ff4b7329bff3ec3a4c207f41f12febca7bf7822c95ad84d1f8c9595d22fea6a386c491a0f22103f"   /* 24499946 */,
    "020800203cb3e31f024e0ffedce21d3cdd11e123a93e0322920b6619ca26e366cec0212cb571ce0ed063ebe0b8d30f0f7ab6d36055442466a73a7e2f1c5c6e5b013ee067f02fea6a146b331a389a1b4b"   /* 24499947 */,
    "02080020150a68a67c14e41ae09defd1c170796df582e0c24941262e7af22fb02de67f7ae53a630cc621cc7d1d822b8ea0cd21d6b7de4b66e7112552c1577f542a3ad57a0d30ea6adf6b2c1a5a4d3605"   /* 24499948 */,
    "020600202d6e5ed1b7eaea91e3130694adc44e425cad3b521b16c4661502a1d8f6776e2f940a644ad07c6f529e7cfbba9f3bdbada457a9d1877fffc2400d269d0564d0776430ea6ac144021af1258894"   /* 24499949 */,
    "02080020ed1626e8b56780fee48e21ebfe4c1f3ac6be9c3e930524695e6571de1943172dd2b0c36532d3ec79cd9a966f688f1edf49410794bddbc79b311c0e6db0bff5b01830ea6a47e9261abf8ef616"   /* 24499950 */,
    "02e2c620939b71976e8c24ee3c5f8fb7424bd025157097aafd5bc211df415a171cd4ada83869f6874eb64cfe1a3dd192fab9e6e58d7f7702e2864d4869c22b425bd0d2b41a30ea6a094e0b197ef874d0"   /* 24499951 */,
    "020e002078a863226575cbfb4a075e24be85c6882f91aaa65192132c01000000000000003a7d9cb9281d078e8a50caeea2b26bd70381e528313cec37d31971fadb1491562030ea6a9d81001bcb551a81"   /* 24499952 */,
    "020e0020aba4922fb2b2ee374d440a0bac3870656bae11f651232f26cc3d334447ce921ed4eec0b072085db3b6447d80b278cf4a0a05585f366af7f4c9a304978806864a3930ea6ace596e1a6bd8d40b"   /* 24499953 */,
    "0202ff3f5a16d07a3ad12f79c4c4a7e4792220068b4dd86984fc8e43f26f4a520bf382e6817263994153170bff4d69429d67b1a984b99a39b75615350a27c24274ff720b5630ea6ab2730a1961b0e10a"   /* 24499954 */,
    "0206002086022cb0ed88613c776b4a545f1c24bf7757c718fbeb01b1020000000000000040858ba50e9f8141afb2875f8e36094b6de3b0d5ee96c2a2a7bf28ba50f017181831ea6aca5c021adbea3bf4"   /* 24499955 */,
    "0200002061ff81ece253caa64c78f8ae12a51a76f5272b411054812e95c4709c7063e90a38da2048d0c2c0b3098fb9c8de9a899c690a17b7f15412350f824cf9e3d8ceef4f30ea6a7491591ae77907cc"   /* 24499956 */,
    "020000202741f892099716b021f11297f084da84671adcc2b25ceeff787d738cc434439bc0b926bc81eee20c200a19f29376ead94a390f07a04f15e6a1f3537fed4dfe9c5630ea6a97de4c1a6b9939d4"   /* 24499957 */,
    "020e0020be368eb4d12357617f421ed212b7b62b700dc920c23387b85ba0377c514466de283c72ec440cde3657ffa7038bc471e0ae06051a0b25c88f72478141bd19487b6630ea6a22876f1aeff525a2"   /* 24499958 */,
    "02080020cf75b3065ca63caec12fb83e6e55af0cfccc92d6611fa9671bc6fb4798fd74d5285bcc162cffae85c0a2f9ca119b7cf31707aa2447f3cc6acbb47c419ca428ad6f30ea6a96012e1a397d1803"   /* 24499959 */,
    "02a208204bbe50cabea668a13ef7b94efd8d2a2ffff001a6a248c17a6a8e21b43f96c0ef5b4deacc7ddae770e75b17e27e4108172acb3e0907aa8f42b6c6adf7198af1717030ea6a67fc0a191f38e088"   /* 24499960 */,
    "02080020d3564826fdcff5e45cb4760d586e1cec304da9ff4783f8590400000000000000dd1b7f470221984d5be130f811e22859be656d06730904dc05f019a9a3f0a1f37330ea6ae955291a0b22e532"   /* 24499961 */,
    "02060020c82ec7f301f9e34fcc6154ee44a25e29997782c3ddae593fcdddcf79dd6b38273d4a4f0a3d7efda970a3df88c4ff420d790c4d1353d859f50995f23d3a392c33be30ea6a3e94021a3f7ee805"   /* 24499962 */,
    "02000020ebc0a7165fd83bcc0bc2217d837ca6b7b51cb44e7fdea8303a4f137556d882fac43d7989ca255c3433d157526e671ad040e35a2644fc5caf2673563040f26e287730ea6a014e4f1a7c08f74a"   /* 24499963 */,
    "022200206fa6acc1901d8de55f978fb6f07f937057f2f1f45a9e1ce2627ccff44874fe6730f9358d436ca142e7e00147dac592ef3b910fd7ea69ccf5a966ae76c2805df97c30ea6afe760a19a8998922"   /* 24499964 */,
    "020e002027bed12d758836554c21b820108978419b5714d23260974c03000000000000007fd7ddaca3f93e008b9d1fbcf0b2dc7c4dbddcb897bd08dae0e1880443f2b8207f30ea6a552e771abadcd8c1"   /* 24499965 */,
    "02080020ac15994ead2314dbf19fcb222ec624beeba0618e8a9f03ac401b62e3d4da428a4084111a26efc2dff45278a859701b8744de26e7ddd857142694b47b2e45c8808e30ea6a09e5281ae2bcb187"   /* 24499966 */,
    "02080020557ff3b88bf518143f2a4c46a1a7c7e3621c70f5e893ae187285dac4e6aa1fe6ce8951cb0e31015ae84fbe37206ec7d3a34f4dffb03cfe53c4b352dd54b855dac630ea6a212a221a280d427a"   /* 24499967 */,
    "02000020884fce7987bf1035ec68e48f578d0695338de25e365ec5b2fb0d0914c30e23990322f49e5495b14c7a217ba6d98907f2134e82e7a624b54eeeb2610a5b60d9ccd130ea6aaf4b4d1a12c6750e"   /* 24499968 */,
    "02060020f31ca066d08246a904c79736208c93c93a6a89fe1682d35aa2957336fb5ed3e9fc4affc6d57544c7ae1aa0cd2762a211e989a690174983ce6641c0c56aa983fcaf31ea6afab8021ace51cd6e"   /* 24499969 */,
    "02a2a82082a4d455616c66f73736c4ce11a2cb59865c3882eea002430d9749930c2c2a5d5ebb144facfb1ddebe0d15359cb6a913ede12502946d2042c57755a709b78451d630ea6ada970a1949e5e1b3"   /* 24499970 */,
    "02060020fbd887928bcafb20c74dd0d69facf8bcc7f4c8c8c66e951a0500000000000000bb380ceeccb2f0bca38ac424aea24dd9c686450c767952d56211f300bac009ae3b31ea6aff51021ac8c9e50f"   /* 24499971 */,
    "020e0020d72b7e1b455405d3b639625f11a625cf77b18e7e8816070513053431ead7d0428331aeb2ff2dc45f49a0d85f0e8460f35ee47afe82119d6940db3210ca021563f030ea6af90f7b1aa3f99990"   /* 24499972 */,
    "02060020a49ce4c55cd394c70afe7b4ef8806529270b60702d8e4048f08d1107796390a8f3eee201c653e3ee05e0857d51d5bfaf32a0e6bfbc8b9bc9b771c8eafcc9557e0e31ea6ac8f1011a46ab06c4"   /* 24499973 */,
    "020e0020c76f790a7eaa4b454ae93ebfdebed1df7a0cb5e3ef0b5d918b18de7c52337231601f3f3e86bf302c6805e55efc3b2e3efebd339917d93e715b1fad00b249d8340a31ea6aca1b661a91056e1c"   /* 24499974 */,
    "020000208e2ef9d16cc66e85440e5f899c1a5e6320ae807be3819b75d9009b9e27efd39dd77d6b2ed8c0318ffb6a5a3ecb2505fc080e083e9626884971027099e1a858520d31ea6ab4064d1a14ae1d49"   /* 24499975 */,
    "020800201706929877da967e5dd72b60587e8d0f7247c66db4543a3e84663b5101f7600307604829267cde8b4e37731c782559684cdbd5576ab1bb3db519adf28c07b0482131ea6ac3fb241a45c06b53"   /* 24499976 */,
    "02020020f7df9a22dc54f1c416a752daf79e5fb4b664a8a5f3658a3e9170d02ed77bbe2f97b7c4f454f780678d319a3f72be6e3992b0c08a924a551f70eb808269fa76754131ea6ac6a90a1905c96077"   /* 24499977 */,
    "020600202b75790a9c5f408c0965fefe6b719d8db6322bcf9017dee50900000000000000f35767193d6af1134b71d26be354963771defaaf2a6bc2b9544e91504eb78b8cca31ea6aeecf011a1109a0c0"   /* 24499978 */,
    "0208002097c141eef907398eba0a6f5c165f815069d3766fb8d16d8a2b18f9e4d6c5fa8adff054a06778fc89e302a662ae7cc3ba9aabbc716fb7e2612f84ae2dac52dcd24331ea6ade801f1aeebab08d"   /* 24499979 */,
    "02060020f8c069c59e0fcafa57c6f0c84f38bed702fa8ebe12e4303bc5782fe9882310bf3333da214105fee594533c8a1b5ab46ee56776d6dc305e41116916b1758850654e31ea6a897c011a5b6ae738"   /* 24499980 */,
    "020e002021dc75076aa0b38e9660825c9cf51495343b0b1ac9ce382df347eec9485b0e200c7bee1de0dece1beee09901fdb47538a3987884eee8bb2f27d2bf231153ed785731ea6af89a651a31f578ae"   /* 24499981 */,
    "02623c309fdbf8728a319e4df54c46be54578802a3e0baef210c0d06bcfb4dae020f1d7d45662b67dfd9183f55ca97af2c943d180119be5c61df0c9d8333685f00dbd6c76631ea6a97e10919725ed758"   /* 24499982 */,
    "020000200ead0e3ab2ed86ecda8e213b57f629d2ff8fd7ce5f96fc8a0900000000000000391949689b5968b7bad5ff78df572029bea3d3f78fe74998d1bfaccd38faf9d98531ea6a6985501a094e1c07"   /* 24499983 */,
    "020e00205e39e61c1fcaa567942911587939f8bf6a41ec09e1b2c28250b01a575dc3b1069630195eb032c5960cca7a30d27ace1c9b54a4980bafccd553f58925604abff78d31ea6a2b4d571a71863103"   /* 24499984 */,
    "02080020f4707a8d4cb20bb49976087778334301e96cbd4edf784ec6c1e56a83b2f47cdd3861e612c9aeb0c8ea0927428aae0c2de28d0567d790ac5e1dd9def401cd552a9331ea6a1d891e1a9f64d14a"   /* 24499985 */,
    "020e0020544a38d981891ac5cd92ab9081294c35d0c79881df6e9157bffe9584ec958b40317a579635ba3ecbcc5c6d481dbf04fad49bdd8cc1a13ea0ce7a58423036746e9531ea6adc66471a4e5193a8"   /* 24499986 */,
    "020e00208a7acff9d529c02d2c84e9efc17da8fc46ec579d8f65540670b6dc3022226f673597ab67e3871fc2ee89d6389642bb8074ff952535b30be7ad9b53c4fb0592c89a31ea6adb26381a8b1275a1"   /* 24499987 */,
    "02628225209f2565b452b30381cca8a7eff86b331db2eca5ecbb2ab47cbd3e430054f0be9cd40d2df768cc81f9d2ab73dc1c60f939a59d3444c6e6228da91cc0a583f42c9d31ea6a578209194580e78b"   /* 24499988 */,
    "026200209914f084d1715139ecdec2bbf8b9d5e1633c27ae985e605600000000000000000d832a3d643b6b27a9e7469f713ad50a6d350b0d380646a19b0102528ca36a32cc31ea6a0f8b0719dcde410e"   /* 24499989 */,
    "02000020c6bea6a0c87431155c0c3078122dc153281c3a36e38681490600000000000000674106d58e2c635e8837f5accb8a2529de14d0d7110e7a9899b11fcc70608fb5d831ea6a30d2501a224a1c14"   /* 24499990 */,
    "02e2ff3f0063c39b918dc6b7b99f0e767144a0fbeaaa67cd2dfbe5b4df86cf672bb62c0d657ff9a905204355c96e5974e2cb783f0d01bdbdd7b4c98efd9dac3545808ceae431ea6acf36061957bfca10"   /* 24499991 */,
    "020600202aa9d13a6ab0a007e509208cbb837ee0d80434cc24ac872002000000000000001765208eaa4554524b86b4d885b81ee81e916c4b2085956e621ad42a2bc053430733ea6a5dcd011aa9141f8f"   /* 24499992 */,
    "020e0020fef1d49190bb3181c7b9146fcb929d987169ea82abbdfc69876f20e6f59ff75faba40888de3fd19b34c18e76898d7fd1ecd5a8c9482c0d729cf57716184268591532ea6adcb9351a91cc172c"   /* 24499993 */,
    "0202002052b1b19faeb9e350e842d5bccd20cf83a8cd9ad8509a1f84fbe0589c557c25ea2d96e9896d974d23bfc3f5284e2eb293e52d045410d58dafd4d10e094946602e2632ea6a2049051940175334"   /* 24499994 */,
    "0206002062a0f941dd629369dfe998fa69ddbc7c80ea8601026a82ea0200000000000000dfa22d088d576fbe3decc514f63aabdd1c515d7b98c992e560c29624fe27a49e7233ea6a418f011a20bd042b"   /* 24499995 */,
    "02000020a05dc4aa52d3f0ce33b8389bd9a0c6079dc91d8861ad41355c04a3d42ca00397b8dd451b58025bcd9a0f913497092dbd70473aac8a5e03e90352cc9fcac754803532ea6ae5394e1a637e5ab0"   /* 24499996 */,
    "0202582088aa787de1c07bcd77a20eb0fd9245e9e9e55e63cbe773c7fbc866eefa2ca01b7161cf7fe03471ac39a70ec51cea42bfe69492c29557ea82c74eaa7bc0cbc0dc3c32ea6aa38f04194a80d524"   /* 24499997 */,
    "020600204a40e4d590277af1e4c756af3b9a44d3fca499f86f7b618e0100000000000000149beebc62efa3c8022be7ed39ee01f2b9a89169fdb1181c8a5f4ccf3223e7017932ea6af05d011a5782618e"   /* 24499998 */,
    "020e002034ec13125f1d6a63d2288d0fe58f2f9e4b9d5d137b3779676aef91cb4d38ec17c0266a880e40df66f3145d9bab4aa4280f54244f1ab220cc7e18d4fffae3d2884b32ea6a7e44351a45dc2801"   /* 24499999 */,
    "0208002042bf073371b7a60d9a24e493dabccf0253c66351479bb1154706361c40397d6d5d9a842572eb94997703cba57b29af91f508b376da6d3e7bfd8a471b9c47721b5132ea6a1a362b1a4ca38e9d"   /* 24500000 */
};
static const char *const BRMainNetCheckpointContext24550000[] = {
    "02000020f2fea8db06b1d97e1b0d34b352326f8008a298f22ca11bfed86b3a83bb3142c26d5cab75140cb9b4acc261338a30f2348002aca48df0be8b39218d0c8314e840b19ef56ab84c5e1a0bac0aa6"   /* 24549940 */,
    "0202042043679eb882ba1d72aa6cb93ab53e3cc62588311a7625af8be78048cf1f0388e4cb314dea9c4434a2ba1542bfaa85ba7b82ae784ea8a51b44d96c8ef006f644cac79ef56adf230819d7b02495"   /* 24549941 */,
    "02000020a5a37acb998dee71086a989e7b469cb03969775b0cb17d4a0500000000000000dfbace839454bf821d716635026ea8e0b2bbca17f7a5f0b253464eab7c359009c59ef56a884a561a3f249651"   /* 24549942 */,
    "0208002008f7229573cddd8f9b97f5de51aea9c40f4b2bccbd17860a3231893eccf2e9b5f5ebad727c94bf6ddc4d5de424de78ffd404da5a6a66253e8857569ee52cc3efc79ef56adcb6261a62cd145d"   /* 24549943 */,
    "0208002044fc7a713f1fab363adb7ddf873f76bf59629ce72b5c3dc2c627f23c5b3e4e1566b9d75943c3204edbb02eb19eb7d9cb60732dceffc46275fda46e0ebfbc02c8ca9ef56af126221a5b395625"   /* 24549944 */,
    "028214207a98d47fd289e06624c94f7e0c195a27a1e9adc03284695a0eddc47692d2ef4d7716bade37a9487f3657742d6a637e64540e0cf5760214ffe1e449d7c1429c3cd09ef56a923608197611052d"   /* 24549945 */,
    "020e0020974be35c16ca1a06bb829db6642a4aa176a294fc1edb32fb000000000000000049fa802fbe780881e9d65f8f5b93aa5d3d0df0d2b09dffa7d011c39cda431957e09ef56a06a25a1ae82cbc11"   /* 24549946 */,
    "02080020437d95f4cbcc873acc61115ddbf7b2cdd2bd78bca99759ef7c7bc0ad763b7206529860bf1f08effa2573426c3038a62b51ae6a9b0d9839fed4598531a2393b11e89ef56a7342211a30889148"   /* 24549947 */,
    "020000208a29b8636aaf10f6092ddc35505f1bb9d6011e0e82ab7eab88a0302e8e25e6d8727b70339c7638a09e78ef7294056057db113040733891c8b678650b30ce5522ea9ef56a70875e1a36c22ca4"   /* 24549948 */,
    "020e00204e7a567b2268fa8cbff039674e4b7221337161620aade2d81696d4704d2df44b48a3f2e5e67bd44fa3b767a0b42002d00a3fe9e5901ae205b41e60de73b7466bed9ef56a0e27581aafa31120"   /* 24549949 */,
    "02000020bed38293071d4260665c9a587a7c56852f2adb1392757c49be3ed29c2a1b29c8d2e8e72b2bbb068688056a8dd3596c6c264754cc2a6ad8b8ef0cd9c89145d251f19ef56a364b581a33066b3c"   /* 24549950 */,
    "020000202a1d672d8550686fb64cac5e3ffb2b55c7f121129b3b9add76ed4793fc08fb7c2a2506bf072b6b5151cf86187351e6bdfb135f04f15014e0eb518588c88f1cb8fd9ef56a444c4f1a280e9d73"   /* 24549951 */,
    "02a2ea245454e9159517827bbac189b0f74930b63a091709da51cc299881366ea27107bf383bcc4f1e461d18b5793f3f0f44fe5023462e8a4a8934cc21994ecb29d7e54e049ff56a755e09198140b644"   /* 24549952 */,
    "0200002019e9752823fa2a919be76eef49fcf294e786ec920edfab790300000000000000501b6ba485a6e54ced69b9a836000a161cfbf97a9879d057aed7ca191a68de342d9ff56a6c594a1a132c2449"   /* 24549953 */,
    "020e00205293c0a9c8e1b47795b35d0fdf54584bc8f3fec5bda1ef1c3ab8a188c1e27c539cc5bb7ab7ce84b30a7f984a957e2368258101829a27c0ff97ca3ec0424753146b9ff56a8abc5c1ab00bd007"   /* 24549954 */,
    "020e00204ecffbfa3c17f89a103eb27b959c892aebf8eb8ceb59f62ede04702ac4cc04e7b38e614ea53ed7a1b1b5bd52f36c59ca8b4d62798e08dda312d26375a9116f46889ff56ab749531a26f2f984"   /* 24549955 */,
    "020600204c7d7f9b3df4d03f4118bbfa52e43c3677d7e4cc3825d4d4cfa03f958182971418383b8f43f453b2c94174cc157667d5f1d8d11635b537050a89dd819a39770c919ff56a80ed011abca84942"   /* 24549956 */,
    "02000020d1a5505cc881c207293ecc520deb98e011daab849b17d4facf55dddc082aa24aac392c90a1ccd08caa22074a54d28214c97ecc5cdf241a966659605069ab7677969ff56ad7654b1a4d840d1e"   /* 24549957 */,
    "02e2052054e4e3724e1124660538d0debf9019a661132e116e52fc1562329885f9ebbe27e00b77b8cf922f51dd8bfb7b978ed5d2fa4ec0b2a07b21136dd026519abd07119f9ff56a684d0a19392d3726"   /* 24549958 */,
    "02420020dbf50928561a5217371d664fd6603d1e413b14e5d6918da00400000000000000b27dba53299ef6dfbf539392bc6182849073636718ce8a0d768b3248ca6d9046be9ff56ac86d091924c2f7bd"   /* 24549959 */,
    "02020036f77a967f28101d205e5fd3a244862b68d2176e2c2c8bda690100000000000000938387bcf718e5419d5e84767896053f155659c8baf4875d3eebf67c00ad9226c19ff56ae0b90819fd1a14be"   /* 24549960 */,
    "020000204defcfffe50bab763ff65aa51cc3fd47a2b0386bba3fb9690500000000000000de817d02aec2cdea36c5e4e573050c60a3b688df23f502787e88e8de8e0921f4cd9ff56ab57d4e1a11c0a94b"   /* 24549961 */,
    "02000020f34dda402a74c314f5b6b962e69d550966bfe6d1d742ff8a7ea1fde503a57eadbec5b98ae69648b11ac807dea246457b51841549cbf73aff35117f41a997cbc9e89ff56a11bf471a5fd25dae"   /* 24549962 */,
    "020e0020634c0487303fd71fcc768a81c51fa43761157fc8de3a210a556d4b79e90bfc9dd50828250e0c8a79c1fef3a9020d9008d78d52c049c17fb148b70a7f9b78c1c1ea9ff56aec2e641ae336682b"   /* 24549963 */,
    "02e2ff3fb0188ea5ca01fcf1ffc1ce9e9aa914596b35097d3c5620254d06b7667c8aeb6704525ff2c6234f4f518dee672e07ec8025287420a953c3ed9192fd462e0e8397f59ff56a8fea0819c94aa55b"   /* 24549964 */,
    "020800202539cc5c1976d81507640378b4f10e38fbc6b2eb8caa2c8701000000000000000b6d6f5e4359b86723beab4238131bbad676c4d74d3749510861526aec459db2f09ff56a22383b1ac7c8db18"   /* 24549965 */,
    "02080020aef9f16f1c0ad9ed57236ae087c9855697bae834dc685bdc22114d0c55dc5fe902e0c29b4b4f3c077894eed81f06b3306e9f8e439188d0da5acd27825dbace45f99ff56acf40351a19ad374d"   /* 24549966 */,
    "02080020b2aca64ce99740afdce779e8b604396090915195ad837dc32f59a4525f0afcfc00268b476f790d8b103cceb786f22b0c5f5a3a0ccf21d5dceadcb82f64724b2906a0f56a21862f1af3a63944"   /* 24549967 */,
    "020000200480b7051461eebe7b4523a135b899dce479cf6592a6137d21c89d41b6d42533476cda1f69b7cc42a9961fdd9a0caec10b57e5584e2867a061fc0e467abddccd08a0f56a0a7f4e1a16a81533"   /* 24549968 */,
    "020600208a72d3115fcc9a12b57d0892b88e1e68a4d2c7cc3773a19e479084c02d4721a9d168bf8defdf972439235bd222cf0e6e1fefed966175a8a0006afcb4915c031144a1f56ab5c4021a3f1c369f"   /* 24549969 */,
    "020e0020a347f50b1c2f002c318b40e86888bae3b8ca1faa59c9bb60803e4e18a1c2a81c357257fd7542a841add04026ce274daad3d1991ebdac8391972c5a1d90c3bbaa23a0f56a4cb1701aa47b9b84"   /* 24549970 */,
    "02c21121beac8c274aef7c2393e7fced8e50b324ca934d1ba30499d8eb0d6e93e30a357975b96d85b8ab08d466dac74ba6063d3c84adf41754d425a3bd5a2c9c153396162aa0f56ab1fd0919df00cdf0"   /* 24549971 */,
    "02000020703f49bb779582120abd3ab3e588f4ab8fec2b9c15b98d7e0500000000000000eb32a9046073f7d5f53d3e0e859e28871e19cc648c347f8ef75e94e8e6a5221437a0f56a2c974d1a227578de"   /* 24549972 */,
    "02080020d8d1775fd0ea839decddfe5d2dd8ac22e38b2692396c60c88bd71abc6cfd46fb96901e92b02007d3bbb4cf4947cf64af638df3dd9b8a5a4dc28273ed4f42a07a38a0f56aa901331a3cf55179"   /* 24549973 */,
    "02080020bf2a0a875eb565497a706f849163b51f464dc2a8785ec8b042a8feecd8c7490c9bfcaf61ef74ea8e46fbb608b9b0b19911b0e0811dea6ab092e8dd5feef98f163ba0f56a81b72b1ae65af189"   /* 24549974 */,
    "02060020ce529522b425b0c21160e50d807b20f919fb82b4cf134970be64608f076db32454e93683fdf9fb96ae743074b6bfe7acc142dc10e52348bb6d60f43e474177b367a0f56ae6e9021a13e3ec22"   /* 24549975 */,
    "020600209b7d1b24a8cd254f0a82ef027944d3e20d8cdf47296ec5ebc4ee9119760b8318365bddd8e0c71fcc8cfcf4ac7a8756ae834c4ecc7c8272c9536bf6394d72161a66a1f56a8c83021a36d2d4d7"   /* 24549976 */,
    "02080020136217f2be412493226d8dc935a4a3a91a222ba62640437fe97e58abd863cd10a646c523ebd543f2b603bb548fa5d7c80a685f6f62c00f82399ac22e311782f376a0f56af3bd281a2127f820"   /* 24549977 */,
    "02020420b7f0503e783ef8e9d98432bbdff42fe138497cf1acc209b611dbdaf7bd5b97e57f0936254c3bba8d0b223f1762efafcf1ee7ebb132aadbfc44b4a678d7eaddb47ca0f56a94b40a19d028fb07"   /* 24549978 */,
    "0208002002424962b91568cc02127a66c5b32318ac001477ccbf556a08000000000000003fab4fb6fb95f240a14096dd5d75372d64dc0b6ebcea4271c86ce756c022ebf57da0f56aa759231aa4f52820"   /* 24549979 */,
    "020e0020e4f752616f87c9fde268c9e53b6887b3dc4bd3e033b8a3702cf760e87c29b734f90d2cc6dfc72c970b49e7b0eef1d39f76603835fb975608ffc81071f2a25fc77ea0f56ad185001be69e681b"   /* 24549980 */,
    "020e0020fe1ef3cc92526ffae4f02e06e4b6d0878b4f9843bf4b88ea8ba2c578914033d9da46c8a539b3dee9f1deed0c1f996c675c23f4cf0cad40308db5ca3ca747dcd781a0f56a03e16e1aa64bb98c"   /* 24549981 */,
    "020e0020985ad07121c8dc4e8893fda67f7cc27151c5cd7b24f355050dd7082f123e7ec82c47aebcc20753c75bbdd9abe3a774c5ba5e3e88f50559460b76b8ea9bb620178da0f56a3e205c1ac1d3b52e"   /* 24549982 */,
    "0262af2a0b0000a8b3efc10fddd3ec189d36ac86131241817baa995d24a0d1a6578c85bc706d08124960b1943b554333ceb85df47756b865c5e6c89dbaa71b89690ac4f293a0f56a88600a191006f38b"   /* 24549983 */,
    "02a23025398dee9848141a3135deac4f2472f79da1d0df6b2b61ce390a00000000000000e57c8bc46cd50f5753c2f118c36aa7c59f2c09a9eef7d138fd4b8cbceb65dad19ea0f56a17900819ba3c6649"   /* 24549984 */,
    "0208002099f545aafaac6c94204fa6e4aa2e5cf5acef8d6dd3969b170600000000000000cc675bfda6b5869e3339a6cb4e5fd725d78cf6473114cb9d27082796fdde11c3a8a0f56ad170231ac3c48514"   /* 24549985 */,
    "02820220d7dc36fcccaac29aa019f05b2a4241126743a26160119602de0fc1f33b78531c5535dcb56f7d093d8b2ca5648a255222cc5fb1ff1850eca8259adc3d7ff01978afa0f56a3359071943463a31"   /* 24549986 */,
    "02000020cfd005bd6de462380fabb5a30dfdbcbed42c7de844ef3892030000000000000007ae8ed7b10d7047a56777b3c7d5e11d4376a226001a85d5fccf919a509a4962bba0f56a10df6e1a63907731"   /* 24549987 */,
    "02060020b6e5ec510b9beef7213a837e3235995827571201ce6574a5248a310f13f5f442204ee2b3c910db27df170d9aa3bed4e13258218f7db07fe7bf8b783fd8a1a7efcea0f56a8131031a1d43a54d"   /* 24549988 */,
    "02060020d8ddcbb3f4e96c96c841be5f6c3b8e91107a7ad84395a540f1229d47914fc224ab3e3999e19bf50f2104e52ffdadbd3e933b44f9f7b8603fd41750f58ab39883d1a1f56ab7a0021ae38adf52"   /* 24549989 */,
    "020e002006f455834f1b3ad7050de441ab9c9a20f950733f4d486bcb01ea6b1e68a948be67ea28afed0a29c7c267ea3e3c160917144291a190bfda810a1c680dbc465d83e5a0f56a4c84621a8875930b"   /* 24549990 */,
    "0208002035990273d73950ba3d4f4a541bdbaafdabc9ff14009dde948ad37856611b2140a465caf21db3202ec09d63a3a48566cb240f7e196239e4dcf0b1ee51ef8f4223f1a0f56a12f1221ab4a3707e"   /* 24549991 */,
    "02000020a2c8855a13645bc2d75d3b66de703104b2bb97d8bada18cca34bce7055636a440094f1187c1badd435e9c5ae327b90c354af3eb31efa9619f6d2e8d8fde08acef5a0f56a9ca9681a815a8a88"   /* 24549992 */,
    "020600204ac76c5305565f08d8f6123301900a5575ed1fd938a6dc13641d5e7571f77f1d3cc512172e14e276e1f0a6a3854209977d9a3b406ff006d02e4c22daf99e3837fba0f56ac161021afc0eb886"   /* 24549993 */,
    "0208002070260479704e1310e6c7820be71e1494ab8792fbc91342b2378a8db237b59ab23bd09228bbd67103622d4116b92bd1ecbc0d3e2feafdc56561f743f1b71e06ec04a1f56a2ba01e1a85e70b33"   /* 24549994 */,
    "02000020ab5f241ffff6f7c2454d6da1e39a21700e09022e65ea2aab6a8987d8a874d3ac7ce133a0a1304ccc634263ca2eeb1bdedf0f9cddff973076239bb6eb098de43406a1f56ad6d45a1a66983093"   /* 24549995 */,
    "020e00207633c165c33eb6eb4a16ee74589d9720e1d97779fd8fc6c094489b4ef0a2dea2c9f8c6d7e3ef9a6961d92c34244ba4cce1cc171d368330db1be295e27482c06409a1f56a72e65f1a82edaf82"   /* 24549996 */,
    "020800200e5201786c472c1aace25a2fe32d00df2fbf25110967d24db192e585d24edc175ca66c3c2e81b19220b496dfa63b9f0d865ebf4d623e9ff7d9eb7bc1cb4d7f340ea1f56ac2801a1aed4d1965"   /* 24549997 */,
    "020e0020357a25dbbfe9c1227de959f49501e04df063fdaa3b5350ea9554190a5d152ae07bf3230732bcc10edc6d1236aff704d191ceac739ed7e6a022d4833e4caffec912a1f56aa406501a8314e2c7"   /* 24549998 */,
    "02080020df6375b0e672c0640c891c4e8f90bdf1d65fcc373e4a46e8b996932aab3eb29942122108a2272c566cc22b558688d31f912f91a32b650f8a9ec7907504d3645d1ca1f56aba25161af6036d8f"   /* 24549999 */,
    "020600208676f3f3e1ec8525907009a774c2223f1b33f45786d7d92801e3997f468fa37ff2f781189d03775dea0020f52470158936827f8f24f081fb247b8ab69cfe2cf3ffa1f56a0f6b021a1b6a4eb3"   /* 24550000 */
};
static const BRCheckPointContext BRMainNetCheckpointContexts[] = {
    { 24500000, sizeof(BRMainNetCheckpointContext24500000)/sizeof(*BRMainNetCheckpointContext24500000), BRMainNetCheckpointContext24500000 },
    { 24550000, sizeof(BRMainNetCheckpointContext24550000)/sizeof(*BRMainNetCheckpointContext24550000), BRMainNetCheckpointContext24550000 }
};
// END checkpoint difficulty context

static const BRCheckPoint BRTestNetCheckpoints[] = {
    {     0, uint256("0c9af936f28f7bd0e90c8f6235399063a026ed267bb53da398313b5d7aa55d82"), 1780156800, 0x1e0ffff0 },
    { 80000, uint256("66b32adec9b7eeecfae28899679a64e5994aee5babe75fc881d0ef07c0e16f85"), 1783178076, 0x1e020dd4 }
};

static int BRTestNetVerifyDifficulty(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime)
{
    int r = 1;
    
    assert(block != NULL);
    
    if (! previous || !UInt256Eq(block->prevBlock, previous->blockHash) || block->height != previous->height + 1)
        r = 0;
    
    return r;
}

static const BRChainParams BRMainNetParams = {
    BRMainNetDNSSeeds,
    12024,       // standardPort
    0xdab6c3fa, // magicNumber
    0,          // services
    BRMerkleBlockVerifyDifficulty,
    BRMainNetCheckpoints,
    sizeof(BRMainNetCheckpoints)/sizeof(*BRMainNetCheckpoints),
    // reference client kernel/chainparams.cpp (mainnet): multiAlgoDiffChangeTarget 145000, algoSwapChangeTarget 9100000,
    // OdoHeight 9112320, nGroestlDeactivationHeight 23808000 (AlgoLockHeight 23869440 is later, so never governs),
    // nOdoShapechangeInterval 10 days
    145000,     // multiAlgoHeight: 145,000 is the last scrypt-only height; 145,001 is the first sha256d block
    9112320,    // odoHeight
    23808000,   // algoLockHeight: groestl exists on the chain through 23,807,995 and never at or after 23,808,000
    864000,     // odoShapechangeInterval
    // reference client kernel/chainparams.cpp (mainnet): workComputationChangeTarget 1430000, nAveragingInterval 10,
    // multiAlgoTargetSpacingV4 15*5 -> nAveragingTargetTimespanV4 750, nMaxAdjustUpV4 8 -> nMinActualTimespanV4
    // 750*92/100, nMaxAdjustDownV4 16 -> nMaxActualTimespanV4 750*116/100, nLocalTargetAdjustment 4,
    // powLimit ~0 >> 20, fPowAllowMinDifficultyBlocks false, nTargetSpacing 60
    { 1430000, 10, 750, 750*(100 - 8)/100, 750*(100 + 16)/100, 4, 20, 0, 60 },
    // difficulty context at the newest checkpoints (scripts/gen_block_checkpoints.sh)
    BRMainNetCheckpointContexts,
    sizeof(BRMainNetCheckpointContexts)/sizeof(*BRMainNetCheckpointContexts)
};

static const BRChainParams BRTestNetParams = {
    BRTestNetDNSSeeds,
    12033,      // standardPort
    0xe7b9c6fe, // magicNumber (testnet26; wire bytes fe c6 b9 e7, confirmed via live 9.26.3 handshake 2026-07-06)
    0,          // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints)/sizeof(*BRTestNetCheckpoints),
    // reference client kernel/chainparams.cpp (testnet26): multiAlgoDiffChangeTarget 0, algoSwapChangeTarget 500,
    // OdoHeight 500, AlgoLockHeight 0 (enforced from height 1), nOdoShapechangeInterval 1 day. With prev-height keying
    // the groestl set applies while prev < 500 or h < 500, i.e. through h = 500 (the chain has groestl at 500 and
    // its first Odo block at 519), so the first Odo-set height is 501.
    0,          // multiAlgoHeight: only the genesis block is scrypt-only
    501,        // odoHeight
    0,          // algoLockHeight: no grandfathered band
    86400,      // odoShapechangeInterval
    // reference client kernel/chainparams.cpp (testnet26): workComputationChangeTarget 400, nAveragingInterval 10,
    // nAveragingTargetTimespanV4 750, nMinActualTimespanV4 750*(100 - nMaxAdjustUpV4 8)/100, and
    // nMaxActualTimespanV4 750*(100 + nMaxAdjustUpV4 8)/100 -- testnet's maximum is built from nMaxAdjustUpV4, not
    // nMaxAdjustDownV4 as on mainnet -- nLocalTargetAdjustment 4, powLimit ~0 >> 20, fPowAllowMinDifficultyBlocks
    // false, nTargetSpacing 60
    { 400, 10, 750, 750*(100 - 8)/100, 750*(100 + 8)/100, 4, 20, 0, 60 },
    NULL,       // checkpointContexts: none (testnet26 is a dev network; its table is not refreshed at release cadence)
    0
};

#endif // BRChainParams_h
