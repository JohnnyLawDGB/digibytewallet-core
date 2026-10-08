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
// 516 checkpoints: genesis + every previously-shipped height + a uniform
// 50000-block grid, from an operator full node. Hashes are the RPC display hex
// VERBATIM (UInt256Reverse is applied at READ time, BRPeerManager.c:2331/:4755)
// — NOT pre-reversed like BRCompactFilterCheckpoints.h.
//
// The NEWEST entry sets a fresh wallet's BIP158 scan floor, so a stale table
// silently becomes a multi-hundred-thousand-filter scan. checkpoint_staleness_kat
// fails the build when this ages out; rerun the generator to clear it.
// newest: height 24250000 @ 2026-09-21 UTC (chain tip was 24347846 at generation)
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
        { 24250000, uint256("c549fcd7bc054db8b74961bb9a45b1b2e8cd993be69946ac12a67e04cbbff92c"), 1789990939, 0x1a22194e }

};

// BEGIN checkpoint difficulty context -- AUTO-GENERATED by scripts/gen_block_checkpoints.sh, DO NOT HAND-EDIT.
// Real headers ending AT each of the newest 2 checkpoints (BRCheckPointContext), oldest first; the last
// row is the checkpoint's own header. Verified at generation and again by the core at start-up
// (BRCheckPointContextVerify).
static const char *const BRMainNetCheckpointContext24200000[] = {
    "020e0020b1b5d8b1a9737f351f28abecea74904c47f9ed43076af74e63c99d15070e2a592cbd980c51e464cce0309b44a0162bd90b83f2585ff87d6ea458ed56c1c4f658eea7a56a6a8e001b69d1eb12"   /* 24199940 */,
    "02020120b9899b3ed2cc905ed5e73ab3a10994f5879f6b269511201c8a28f0ed68ae3a6acca1372ef224a0ed4461b08031369698c48f95307cbdc5241dcb4c0d59489341fea7a56ab20b08199baa8d73"   /* 24199941 */,
    "020600207aa6a3cf9d7c1b5bf36f856d7fca40a43d2c013bb5adaad106000000000000002a5f358ad54c554df56745cfddfb66addd439f39ae3db00c3c239ec65793611184a8a56aaca2011a7c991350"   /* 24199942 */,
    "02000020be5358b93ebacd33e753e33842497d6728683063e2510908efbed4f88c3ef612a2d70bd5d53c014e48bf6cafb3751ec79bdba64c6e2466b1e17cc20d23c78d681aa8a56a33c8541a7942aef0"   /* 24199943 */,
    "02060020d0a701c45e7cfc50dedec6f1d178b54d2d6ce3c68ec9700775040fa98727292932b45fe4199b1c3c6c9497a645381782dd627547bc16f043fed64769be97190f31a8a56a3473011a09290e58"   /* 24199944 */,
    "020800201c15ba64f57e516367cbdaef252e71fa3f21f46947fc2422d3210b81da55a3b24f0281ac7d3167c9cb5d8c50d929051df85c93ed9d32be7d29531da68836d94927a8a56a3046211a7502d53c"   /* 24199945 */,
    "020000208da6274af8ae1b097eb780dad29b9742fcb38deaa81f8961ba7b6220b877b4cf841555d3b001c428d708a38558d991d4755c9408d89d0706844c18627f3e68ed2ca8a56ae2304c1a59747195"   /* 24199946 */,
    "02080020b85e8101fb7480bae928ee981a19d46e3d88ed93da8120b4f10b429e4bc5c77b2f313378ef3f1a65064ea1a413dddff18c83d2dc97a1f3cb946431154755c3dc31a8a56a37981c1a13a75f18"   /* 24199947 */,
    "020e0020aeca50108b29b000c0d1883c148e3fa81cd5feae51d3abdf426f4a4fea6d34919f0712ebe972b8d2dac6bab9881d29cb2a48a65f7e2686eb5160ea00511eadef41a8a56aec9b001beebb2d09"   /* 24199948 */,
    "02e2462f07853104488c2aa3dc7273c14cd89cd5d916c089fb0687854829b6d80a82560264d4282880c56c8aa5c5ada1ae591fa48e1e7ff01b532f43b0e4bd81604338f548a8a56a2ed208196fe2657b"   /* 24199949 */,
    "02080020788cbec9d1c592f2e7c84209b5fcef1efd11052b6e4c30cf02000000000000009d0f12210eb42cc611f121437413e8e2d9bb52efb91bbfd7d80cfa1aa978c7a35fa8a56a72b2191a0dbcbd99"   /* 24199950 */,
    "02c2ef3499ee4b10307d932e8685997a3c83c78bc6f97dd1b02062364de8f4c689f82f903f92017f68eca24e06c955fd9b9b4ae79130bc5bfbd6945eb3c6f803cf018d106aa8a56afaa1071926dc5303"   /* 24199951 */,
    "020e0020d0ffe5fe96233c51607eb0b9d88ed26f817f9d5328bc317f01000000000000000f9fdb572f0af50f6cd328f57985ac59053d03ccfae3ef88956fccee4d47cb2285a8a56a8790001bb1f12d18"   /* 24199952 */,
    "020800205b2d98a3f8c751744a1db220cc0f44138f2224c11f5b4810f56900e8d8e74fc964b0ec94c132c79f91146d3744de3720527f44b11c45ead1e4e5a1dd4ed0c5e89fa8a56a13df161a210d322c"   /* 24199953 */,
    "0206002019ebb13f635cc5dfc0d6638250a8f86a9bd9bb2d1223f31d5eac8bbe24a6fc83317d2fba518e0e3137f02482a7102ed38055aad5b818c7819d93b13f2450aa5faaa8a56ac0af011a1272be8a"   /* 24199954 */,
    "020600200ebd9a95324c177bb99e93ed10d1e694297357337611887a2d9ce441ae5e0c68e4fdb34911d8a0f9615aa9c1b7a9b01382a90c6deb87b4f317ac2f9e3b298c7c2aa9a56a605d011a5ec582d4"   /* 24199955 */,
    "020200208b637b73db93cef60b887f86ac7e7de911cf8b308cf2000d9c13db542239672afc40430afc582f493dbc7ce6210f6d091640bb953d1433a04e53da4328ce2e3dbda8a56a9441071980e017e7"   /* 24199956 */,
    "020600208af9cf1afe8a17a91afbdafe82625678930986dbc613a5ed03000000000000001e4f271787ec7abafb30023899369858eeb74b2e3cb868cc9a965eb7b7e7f6afbfa8a56a0726011a6e65ba96"   /* 24199957 */,
    "020000203eeed1e4e6623e620ec94bfd45228e9a6f4d0b245122a3f91eeae77e62fa570636ff0f208ea9c84dccc3721ab19238e1af72da99c3e0ab582cf1830582195321cba8a56a13735f1a86ba7bbf"   /* 24199958 */,
    "020000204fb08937bb7761eda510aa6234d9c11e7bd0357a7f6e95026c60fdae7fce093c734685c9e7d5d65daf736158cf9388766ecad29179fb1958ebb0c5277a007b4ed7a8a56ab7534e1a11484491"   /* 24199959 */,
    "020000205c2c27d0484462ae55120f93f23e37586d027fbe23c0206a8df383c7093870e4f41d9e1f568933457fcbe51aa9e8681fc39501d68b7435ec8a8115467703ac25f9a8a56a885d401ab342de48"   /* 24199960 */,
    "020e002009e0f35d33cbf7089a8e9a7feaf1b8d0772d99bf2a3c334c4006d38a35cce1f37b8cd8152e3feab3e0dd02dc2c8f4662690460dc878f786168be662d08c7f3e600a9a56a70a3001b51b886ae"   /* 24199961 */,
    "0208002014ddf7b7c6243fea7c25bab3c12ad27129f31f42ee7dd9a122749899eb07a5ff6bb9904e0706c8f61e215d439bdcded3ba37f690931799e4111e9eb27001c9ba13a9a56ab16f191a446b5eb0"   /* 24199962 */,
    "020e00200f573829a57fea9e6dbebe5fe315e7ae0c1f28f3db5567b8d57504a88f88eaea54143f2d0187e6051fd326c0669c19e8bb7082442935eb56ab0d2c325b06dcb01ea9a56ab58a001bcca3cf02"   /* 24199963 */,
    "024289282b4b549e85d34818f2dee8791a938e10119bc9ad06ee78627ea480463885aeab872be47410a5e95f17c0dad9c20daf349bce0d13b05b4434065a95748342f1c424a9a56a02c807194bb9c24a"   /* 24199964 */,
    "020600206765813ffea7ecbdfdfaeda52216ccf53dbbbeebbb1c5a6d02000000000000002663e4f8df72e92abef08cb77a578036f1767069492c0ea49cfd49fb968c91e440a9a56ad53e011aef653150"   /* 24199965 */,
    "0206002061c5ad0a93600db2bc9e6ccabc85d42dd3beae8f732d9cdef6cc1a9f1c88d5eb65c4599d2079b58956d7aebc3359a613efb3c3a9e02278d31e7a74198c4db65aeaa9a56a7407011a07883c1d"   /* 24199966 */,
    "020e0020addefb0a51b07b4890feb7b5dd7894901d6c83b4e9de1d47ae91749d54897fe891ccd263b30874f38a27ca33bbbfe611405a57a57739ee3cacd0e2e099a2f91963a9a56af7807f1a2f8c6b99"   /* 24199967 */,
    "0202c02070af407ca2e4fa2079f8e66eb09d894d4134f9c514ebfc32a6061a176653a21c1d9c4af14e845ea60e76296c0e73160767a4a62170345a2c294cf3344e730b1a9fa9a56a382c07192b31a31a"   /* 24199968 */,
    "020600206a2d56eae2123d097a673cb00c4bf90400814e2ffe8d8d9904000000000000005c53580cdbb85271677e2e64b9b2b138f43973184cb4bdd6188e83674d4e6f2526aaa56a8fe7001a19900f1f"   /* 24199969 */,
    "020e00209262e2884dc92bbe9e3c3888ae48c5feb61a70499a2fe68d2a7f13ca251e086bcb4458a409abbfb327202f9dddc2e7e43e96baab4dc89efb9e56ef2a40571722dda9a56a3a7f6e1a2da6a389"   /* 24199970 */,
    "020210203e78b365b57c0ea269da963803f480d9913f9968cc621f355a6f327b988d70742d195bc9bf5f58088f92eab45041c29ebd357d24d8a4b67a3a420a6789176c0ce5a9a56afb2b0619428f7805"   /* 24199971 */,
    "0200002017cd4720d2c0f522461fcb2fc639c3d5585931d514b979a20400000000000000d6747c81f9d20cb6c44843b8478ee739b9f6efefbac76e7504c9991ba0a3793cf0a9a56a65814f1aa2662d5c"   /* 24199972 */,
    "02080020a40e19faecea8f4bc5e31ea7f43d0dd03c70e2b9cffaebbcdce783ac90df6a5f6d487d9b7d98c7eeccdba251b50c196525d9d83dd6f5b2bfdec499f593205d37f0a9a56aceda1e1a5c5f1d39"   /* 24199973 */,
    "0200002071b92f92719ea490d6cf37b52ea8cfc845eb3d460189f7d7192c9b39119ad842bcc281ed650f5753009d6091f4859b9b9ba1cf42884932c71fe991c3f1fcd2a5fba9a56a162c451a673c6f61"   /* 24199974 */,
    "02080020f8e33b3d0bb0c04d9ee77bf0272146d502884fad54484c1f28281f8bf443b526ee22b8370fe9819a4e2561aade927fe66942ec75529a7ca305919257a59279ce07aaa56aeeea1a1a888528b7"   /* 24199975 */,
    "0200002036a7c0caac322d939bcdecfb097f96dd3d03b405561867f6721e19aa9cbb95d0d760afce1a9e2f861ee9ba403e9d92a04c72d2def796e2563847fbde0218d6002caaa56a98193c1a9ac4ddc7"   /* 24199976 */,
    "020e002020ab0ba6bec55984699ed63ff81c775e20e41b12ff6e06a32418e62e0241809a337b0b5e45d3056eb84568b2401eb3a89839940c830373eab63125c83748ea133aaaa56a2ca5741a2a169f90"   /* 24199977 */,
    "02000020a7b24774559c20fce750e5c587bd7da2a1fb602deddcc65906ee42240ad732f1487e31e0c25cc2596b8544969e951353b1f36a25146d537950ad23c6992b7af060aaa56a3b13341a34860e19"   /* 24199978 */,
    "020000200950b49a1906a0167d2f933c89c990eedc94fc99f347d190d9cb1c2bc0564b928de1175518a65b94a5e1fd946882991a264722512d3ff94b37e14d17676e559b7caaa56a4a812b1a4642224f"   /* 24199979 */,
    "02227622dc4b6c47697f209ebaa23b1f7ff5558e4fb8a29b3df01341b038901ea0e7005f6c52db2e69d6912fb0042a88132969a0c5640829178aa5c423d214c0fc35be67c4aaa56a1007071922bb60be"   /* 24199980 */,
    "0200002029c454a6cbe8810e08fc3f53d6334b15e8e141e93cae948f0500000000000000d346d885ef7fe3bcf45dc3e9354e3167190e08fd248c39eb6dd2addecea4f1c4b4aaa56a607d251a6ace76cb"   /* 24199981 */,
    "020600205d9ddd63913b53692737603ee0994de680c0b7b4a21043f6a02ca3a8dc0bd8c03fcd46d51986cf6dd6422c738edfa6ccc6e64d78465177de8225266d39fdee1cd3aba56ab835011a5c2cc881"   /* 24199982 */,
    "0262d6243cb8e5d176cfbe5b456b26d31d41883d91ff18da71f6483b9e8f6ec022fc624f6105dc3a2746ff18489519375c748bd3978649fd1230a1037cab24736f73f25dc1aaa56afa52061917823fb3"   /* 24199983 */,
    "020e0020e97a3c84a4e4358b45a32988f558500774d1ab5ba8320d7602000000000000000737fe9f671eeb6473786fcf64ea438faca78c3746381061d7f29459b300c02bdbaaa56a24507c1aeab9f710"   /* 24199984 */,
    "0208002038bfc8298bfe4e250ea03ab8bdbc036461831527e6e57243f6977627636736108ee22669eea99fcf88df39c92c6360b6d83455a3b80ae59f952f31016f133fedf5aaa56a9e71201a7ebfff20"   /* 24199985 */,
    "020800206b5e53f023f1748f77b27b08a6a3557a4797c88cd4ef927b240b23a4fe3e3cf021ea0bdc04681eb26f2276b52ae4c134317476e06a6f801d9a4fe6115945951c01aba56a8ae11b1ae67e3e35"   /* 24199986 */,
    "020e0020c995665fd4383785f738571e5cf762b214e100434f178283cfa1d9cf47295ac77bfa2b9e4e7b6cc4cf9b21325a122343682f0f4b5b58c99e74b66910fcdb0a0f07aba56ad201741a64d8c60d"   /* 24199987 */,
    "020e00207128632f39fe69cc0dbe638eb8a04979a85a4c469dafc08ff4df58459ea597a25cc02492748a92cdf288e149b8c26d324cdb1eef8461195efae46476003765711faba56ac116641a8db53513"   /* 24199988 */,
    "020600209a0c9342fef43f70aa7c569ca70800848361de5622e14f1f201a92874d37a8bd689c55b06637ba3c8441bad145751f3da8bdd966c952e13bf8db91e969866ee13aaba56acc54011a69982f17"   /* 24199989 */,
    "0202022022d27ad7d5995998f0f8529f22efd7dbddccd64a2027a0f94f520a27b0f1bacbbaa011eda693c498bdd0a7105e9312cf640496a1dacff71e4e3dc44b1c17e4b53eaba56a6ff50619d7dd2297"   /* 24199990 */,
    "020600204542cc4b8a8afba814a69253d3ab6a10fd9fa7ec9c94608402000000000000004b48bcb6803bd42f01f22d74339c5245ac4c47738421243f3dd72d84a84bc4096caca56ad033011a7ca3c519"   /* 24199991 */,
    "02060020f82a25ada3adb7ea9f6b99e0f5c4eaba423520b7309cc545cd01a69bf13f89c6029f546cf24b869433a86201f44053ca446ad43a3204216869d0adba421b8f7668aba56a540b011ae046ff61"   /* 24199992 */,
    "0242e32172d3ca3294718d7e81c5ccf02bfa57a0df1a76880903f8630bf06f866b841036e4bf239a83d6edead809bbb6b99a9cfeae14b48a1f662d8752188f503631bee999aba56a90960619517835e3"   /* 24199993 */,
    "0208002029389c143a358e2b1e5e7e82443019276b59ff89df3181a70500000000000000b7323354676401871f59fb5ca30b882afecde9a6ac1e68588d7555ca58cb07bb9daba56a0a08201abe3c4484"   /* 24199994 */,
    "02080020c8aa9d306bf2c14849860110672d2058173ab2e7df0e3a74893b0711c8600e379d12e81bdc9a8a837218e769955c724c7931b5af4004727a8c52a8352c75d0a3adaba56aff121c1ad98dab48"   /* 24199995 */,
    "020e00209feb6319aede1731528cd746b9112d83f535590f38ff2b24926a5ff52241e8ae94a062859613ffe5cf43317ab03b767f68894d4eba58bea6b789c5cf178cfff2b0aba56a4670731af10ad67f"   /* 24199996 */,
    "02c23420221e83277b100c11fca8656b7692fcac13af9bcf1b0480077ab57a549ea9cedb22103641f2e7e555100a469cb2d80bf57d68542e1ccbe665091c8c89e57e6ee9b6aba56a8f960619df830310"   /* 24199997 */,
    "02060020e839169df299058c41f810447873b70674eb8fe3356e461d060000000000000089720cb78d2e242a3aedf0f3bc01ee88a63305b86c7319156823bde0fc678ce0d2aca56a5d23011acf5d710a"   /* 24199998 */,
    "020208205e2000ccd1e6e855e7e30d4fc46e1737a11176efd2633fd114119cebe143292a822c968bcfda7dc40a4844338411d88be9dc65ae686223300e398b51f1bcd875d4aba56a501f0619329d314a"   /* 24199999 */,
    "020e00209410e9b05410ba1c2c694d03a409f3189533d0678167f9cf0000000000000000be9291adaa16ecedfd36f14a9598170038b7d5510e5fdbf2737cc7cc22546740e3aba56a9953741a0128a529"   /* 24200000 */
};
static const char *const BRMainNetCheckpointContext24250000[] = {
    "0222eb20dc9f9c0e5fc20af5d5cda1b021a107445727074a980b043ed7648a6c152ab572474901d45dd7d3ea0c026519f57ff7f48dee2bb34420ad502cddedbbb1abfad24016b16aea8c091924f985bf"   /* 24249940 */,
    "02a200205d06b19b8edc77460b9d7391da47d0080e4a18610f5b40fe0200000000000000a5b181955fd8c54e2c1aab6b6ddc3875238922df8a9cf02bf1e31f4d41ecea265016b16a8bcb08199d0dcc9c"   /* 24249941 */,
    "020800209fb8dde2ad4c57a9f43be974aa0acc0579b3e6da5a9ca4180200000000000000869f4c59553598c6535da9499923c0e0955e61e44e6963e363b75bb4914bae395116b16ac94f481a0ff50389"   /* 24249942 */,
    "02060020e69d40b8d2ba8df7c7c2fdd5d789ef3d0d88027d0afc47f42602bb6b566f71bc03ed4429029389abb8ac0066a5b55eefe84a3fa3684977dfe985d4ace3d649984217b16a3b0f021aab9d196e"   /* 24249943 */,
    "020e0020d8a3925ac42f07bb01a5a0bb7001fdda603b92a17b1832e1696e8dd6ac9b5ab7eae7104d118830faa3c78d2eccdf24f9590f1d02f16b3546c884e7aee19a9d765f16b16af8c4001be521019f"   /* 24249944 */,
    "0206002058f34986799ff25c5c3d373277a3020079580ba3623c3bbd98a0783cec7e4a848363707c6d756cf650c2fc6bb517e90ce8f1a1e3b66e204ce4fa9e27ffbacf047b17b16ad4f0011a58fc7787"   /* 24249945 */,
    "02820120411f5566fd52a419ec1478c10ad7f1d1de03de658fde2e4e8536d69467675ed237e75c6dba36ff4865bdb05e7e6dadcc0f5f6b203afbfa8591f9bb98f7dc7dbc6816b16aa45b0919f91ebeb7"   /* 24249946 */,
    "020800205b2eecce1924ad0d70b01650b641529d16006f11f65df6bd070000000000000016292bd1767441e8520448002b178a70a2f34e0aeb2ae8e472444572dfb00bcd7316b16a65124c1a006ce03e"   /* 24249947 */,
    "020e0020034c022bd82d212098b2a2cea222c858e5cd380fb61595dbec32eef87c94f2f3ef18d01cb8a4ccce2d0220e0b78b49ce38b340c344d0a2dbbbb262679108f2117e16b16a3dc7001baa699116"   /* 24249948 */,
    "020600207dd0228c9f7c05fb7283ba8b8f3c4274bf16e0c957dc8b2630bf8a5bc53f9377e9a06f695b5d7e2fc7475ea1a84235c97addd2e0f816147ce3d5e5fcb1a649438416b16abbeb011a2e94d995"   /* 24249949 */,
    "02220720b86e6ba2412a12f4e920dcf3863e451e0369512de99d1df6366d32f41a04914f0436f8a8800e900a1db98b0a5a784f9920a09fcd49f41d005dd65b7ce3b583458316b16a922d0919476c25c7"   /* 24249950 */,
    "020800200f2a1bf42643b745733c59a1b5c0a881e900b59851d78ca1000000000000000009ffa75da32cd64bedc75a183b0b2e614ddcfbb75a7ac2ca8a58886606da90f78616b16aeb824a1ae60648a2"   /* 24249951 */,
    "02080020bdda5e0cfd90044004787234872bbcc3dc10328d9cf21202105698e87f47bad7362cb93a34abbf04972c21af0cde3235e7c8aa3c1a508f4f9aa2e10f08d9e27b8e16b16ac333401aad6d6073"   /* 24249952 */,
    "020e00206cebeb70a3531d1d422f0d455fb6b8cd85f3e9ff9d47d8e5ee2db7892da2852185b559324e054eea9ca78920d6ed171c95e5604b0a86bda5e9359436da347a0b9116b16ab4c6001b8fb42b83"   /* 24249953 */,
    "02000020a2b4e77504ec29a795182272738e728dad560a835f3f6c0b4554f250b5b9f715465040f9991108c57edf10b314047333c27df5a9397ac8b72db3feb22e2d0ea99216b16a18c7001b1a58baba"   /* 24249954 */,
    "02a277208bfb3cd8e33e80289e9f0ea25cead1999e843a8b27b533290c46af13f8f55a9c0b58ff560256a662c5598a1d25061ff8c4fdae20794299ff1a291c7531a0627b9316b16a821409192d65803c"   /* 24249955 */,
    "02e20b2ffc45c77fa81951e38cead9d4937b1f3027b493f592f04c8b00000000000000008e140e8691b7b3367ac8f25615a954f4cc20415fa054611d9d93a8c1aa8e5bf9a916b16a9c9807193244e236"   /* 24249956 */,
    "020e002052cd47c99da35b1b6e5ca5c916cb2ebca38d46255cb20f7d0600000000000000e75947c71ffa4d584e8adea057f8c4c7f54666afd08ab16181934000305fec8dae16b16ababa001b83f9b8a5"   /* 24249957 */,
    "02060020919c8a5976bf5bff7cedb42144724e9bb4c545e0d6c6fb2d04070545fca65db4b57163de41ad34bbe95a4bea4677a01a74b42305d402808c0e97f7e42a68295ebb17b16afb32021a98b97558"   /* 24249958 */,
    "02000020d24bb543da37d652721412347d94305873d8bd731695d570b0fd294cb24d5b44957be7ffa7e08582c8bad52e0bb39c5132c935ab41cf117465ce963b0152e8e7b416b16af6b7001b3aaa13e1"   /* 24249959 */,
    "02000020fffdd910a95e31d41f7ada4c1ceb20777d51f3894517268e23ae4b85b064ace4311ff42b741f7b4a92842a19cd735f0dd92d3829d2565fccd16bf8bc1f84fb84bd16b16aab90001b000864c2"   /* 24249960 */,
    "02425122947b88a1f93ea1fd502dce1abf0a49519fbcf219b8a036d983d407cf69a698a7b0c4aadf3edfd9e5abbc7f927ec6e28095d8c6df1d0f1e632db49d1192d2a7c4c416b16a0afd061969c2c140"   /* 24249961 */,
    "020e00208a94ca9deaba3eb256ba0800ee347a7f11d51245c7187acb0100000000000000fe98a9794a8b0a729a15a7d0870722dc60c2ef144a62a5af93689bb3b4806269c916b16ac9ab001b2c720387"   /* 24249962 */,
    "0200002048b3f783aa086adade9953fb15f35ec718327ae24e04672a3a80c608e608995f22addaceff179790aac53a7e50045d0512295caaae22376d6c447f6ef458697fcb16b16aaa0d7b1a8914cc32"   /* 24249963 */,
    "0206002009cf716e4e28b96d7769a26df74be6e5e8b86a0491325bf0ba594d31a48405b877a7a969f6fc65deadb5a4e23d7264fbf36cfd295ec9ad8f7ff641a96cd39089d016b16aa81a021ac1bb682e"   /* 24249964 */,
    "020800202d527cf5cef2667d4c0ba4a3125b240479bc2f9fc2eaf1ee75a71aa85cde00f2b7862a0f6f13e28fed573c98f14ad25c582302ed2e4f232ee894449e5b723d43d116b16affd5501a3b492c1c"   /* 24249965 */,
    "0202042059ad67eaafdc07af49bbe7cd22152f32e316c3c225e1bc7d8966b727bb2efc8ef7f4fb3802059c21c40d883b4286b542c1c5727e436ff25cf68557a73f28a822d716b16aea6d061979b8434b"   /* 24249966 */,
    "020600206c686525430d5b1feb374de033dc3b976d1dc67cfa1662cb0000000000000000045efead3a528eb921b7cd4e85cc9d795d0f4325898990d2c6d4be13a92ed78cdf16b16a2dca011aa9223e99"   /* 24249967 */,
    "02000020164201fe2b75eae9abc948d0d7b6527908262dba879c0405b77cb04ac566b751f566c29b6f9e28cdb075652fce71b09cdbe5bc01db84745297976ab47c094031e216b16a8735711a6b908dd6"   /* 24249968 */,
    "02000020a257031bafb690b9b1ac252f0414677e08a55c5289a723bbe33be5cff66d19c5be5e56870c89a8d8dc05e2f8516c8abe033929840d85c878c223d95e0785f0e6f016b16aa607591a4ea802db"   /* 24249969 */,
    "02000020a592ff8ac236d13791a1a6df78135a298a52a6a3586120ac9c6aefebdd9e47e41f52c41115e7a6dde81889b099f64f47b1a23184099ef2e406e22cc73f03efc1f716b16ace03461ad19d6378"   /* 24249970 */,
    "02060020cd46afbbbc6e684a5d5937cd94f9fd5c740499019a32210c97ee576fcd0b5a8d4559f33606d916196ce1c93b36fa56babf2bf48a4591b38ba11a060e451368b6d117b16a4f95011a431316d2"   /* 24249971 */,
    "02e2ff25b7631bcd220ce769982fc4e90a73cc39c1f2909a627fd984052980d6fcd37182fb5bd28d1036c6a8daf3a961dce33f9c86c66d959cb624e3693dd412c4ce3b481617b16acf26061930027821"   /* 24249972 */,
    "02060020198abe131daf51e6e9ad5ec701e5d28a94fc0177fddbcae803000000000000000791e8a8e795808823069eeb773f98ae6a5762d2621692869b8d7080ea6ef0347c17b16a7e4b011a6e221d10"   /* 24249973 */,
    "020800205d858a37c2b88c7368cd2b5c94806d1e0e7b2506bc466b0e5e6110b135bd94a1f3ecf5dc3072c9e79a7c921bb9a2d4eaf10bfa19cc70e4b1d997f3368bd696d12117b16a5300571af2102fa9"   /* 24249974 */,
    "020e00204108ea56f5e0f17e5fab7fde7c87799c9ba6712593dae231b34e2ae042610f3c85ff03f591ce352d4de2b8523ba93617c6b7abff3f5c8a84070d6fb0009573282d17b16a4ad8001b8dff2f2a"   /* 24249975 */,
    "02060020be7c8f820b92be49a916d40a2b18219e7df612cb253896ac7d6f6261889b8428219efc62f368e4a0748393e0f1ac16e4e93e31eddf6fb27c90ebc45712aa017b7d17b16af619011a8f41363d"   /* 24249976 */,
    "02000020df7f725e5cdf5307ece3b01aac5023237a1da681fd56b876b1fc2c2d2fc6a228fc0720abc09cb518fe4e178f1f3d64f623b921958386e972da2d351b73228c244817b16a79ab451a0f12970e"   /* 24249977 */,
    "020800208500cc53822786f9d8d002e73ab43cfe2f27be7b580e8e78f90bb02556a6c9bd155716eee9109887187da921c8b91509f92b930540a64de297177a5a9fd700dd5417b16a70f64c1ae3aeac65"   /* 24249978 */,
    "02000020de3f567f83662a4ae8cb210c53f1c285e058e27d2c8c5140951892e229206342fac22f583bf6207807bb07a90bb85df6114dc5fbefc1db2d939d8900bdc75deb5a17b16a37fb381a0e348746"   /* 24249979 */,
    "020e0020c15bb463afa6ab457a0b341bf7b8470b3e198d5b7be8b31f3cc5182aa3c0ea267a82abf66cd8e0122a2cdaa380999904c75325592a52b87d68698c27d5540b3d5b17b16afcc6001b8bbfb00a"   /* 24249980 */,
    "02080020594d3fd2f7b51df78d64e2951eda3e610c76107a9ce9b2da9746571bddbe7e10aaefb4a65ed063b11e9a3ac6da4bbb6051ae9d91b5c813948a9413539de53a0d5d17b16aba76411a2eae757a"   /* 24249981 */,
    "0208002045dd744b9ec62abf6a4150696a582646a218b50ce8fa75138765a4954a96efc2de00039226d7c08949ad51b344094d5dc8cd07db2b9742c035e5ade3de4792356c17b16a657b331a81ed1811"   /* 24249982 */,
    "020800206a54df544af7baa5e7602d53d33d9f2d3c6207e0e7f1bf05ba081a3cb5ef050534b33cf71a063ce7c1f3ce8399ad4b430deb87054839a538abc34324802f40fa7517b16a897c281a1cba665d"   /* 24249983 */,
    "020800207f2265f47fcaf49f51676499c823267becb70010dba336526e65f82b4e22f022f897c217697f9fa6204b0c738dabefffebc54acfe0209cc9f404590ecdbbc8488417b16ae0d61f1a07fa2b8a"   /* 24249984 */,
    "020600201b7c66055bc1a55040d2ef64cb12680256d208c8f5ee6353ea455d284b5e5e9a4bab15ae193aa4db4bf6232b1a92a160979e9cf6b8f79665a96fc09359bcbc861718b16a772f011ace885aab"   /* 24249985 */,
    "020e00200e0d8877cd1f7d7fda06e5db264ea910ebf90c15936a436c4308dd7184fab00095524c5b7133aecc40da6149a38a501d925c7df839865715e188aab861bd82499317b16a63be001b0f0acb82"   /* 24249986 */,
    "02824c2de818e0187ea1430f273d84b59edc8bdff37d29d76515017aebbb96432ebc8633acd966b2f3b5769a9735fcb337b564e140266a7a7528eec1216949b7d956fd489a17b16a9d6008195719e059"   /* 24249987 */,
    "02000020c2b71cfbc1d5a18bb919e8f193fae709dbe77f33864fc8b5010000000000000002189fcd13ddc2755d20cd36c73cfdd2322f554b5aeb3bd5345415b03cf105be9b17b16ac7533d1a0f5a762d"   /* 24249988 */,
    "020e00201f7007a2caaf167a8e842fddf867c4342414e890c96edcd8647cbd967620d09f7220e5e41cf653459a611d7374868fca0d388144a29c9f42e429a8d045149ddb9d17b16af0a1001b65666693"   /* 24249989 */,
    "02060020bf58d866ad341387d1a7c6790d473d72a76ac2e872eb34b4f5e7acc4d697da870aaa8c2e5645c33e7acfffcfaeb8b4200b85d74325654eff9a23ae071f446aeab617b16a3017011a43bfb162"   /* 24249990 */,
    "020e00202a138f572c5a9b354b9f113c77a460676d8754f8887a0d7023894937f813f240251b6430570ccd633080ff92f7e93fd3b2dd982194572cb7330abc1368b93cfbb917b16a7184001b08cbac00"   /* 24249991 */,
    "02020c20cfc2917ceafeeb04090f9df5e1b51ac19112eaa80af77e2543a568271f45d4b936647f321bc64451b0284d56f063593029611dc947908f1ca77732e1c2b5630dbe17b16a0bb5071919e44926"   /* 24249992 */,
    "020800201a70f8336a1c23cb546e09231ca4a8853f1872447d713bb8000000000000000091dccad2728ad32012dbf3c52c060071d8c6adeae7de870360857ad8ee9d11b6c317b16a8a44221a67834d91"   /* 24249993 */,
    "020e00206d6207e9899eb6e98786d614c219749f85c938163a7e9ce967a2011a1d373579323ee4f04580e88dea655fa87a24b8253b075c76bf5b4876c420a866d0b62480dd17b16a4fa7701a6e4b0708"   /* 24249994 */,
    "024209200dbb26119b915697167d7707fae133dfdc51463ef8426989c11bcd4df4796a0cc3cc43acb17b3a6558a5605d27e0588b2679ab597a722ac8678298338863218be717b16a418e0619f1c541f1"   /* 24249995 */,
    "020e0020a29c844cc0d85ec304d88c1cecbf149a17be82e18c8d2a4801000000000000004a954aa8b7e5330e603809eef8e65b2d9356e7f76c8c98dd115a4f5b9fb154590218b16aff225c1aa900808b"   /* 24249996 */,
    "02060020ba1b35d808a2e5a2353540651cfd82ea3e206c8cab4fd2c0e8acb93379e11c21d43ba0b55b309ec5a56c333ef44f5342718c5caeddfdd7ca4b23264248dd4fb20e18b16acf15011aca5a9180"   /* 24249997 */,
    "02e22225b0c3eec3990167818b51612374e5901ba17e860b23c531e178e18039b6d64ee810815daa100646caa1c8c54e173bd82aaa402766ef9ee7f239ee4a5bc58bb9b40f18b16a829305194502405d"   /* 24249998 */,
    "020000204f159aec990099ed5b50d7b742d3d455cf1b1c7c238b8ad80000000000000000d4994c3098712091a3a72a82504c6ee0d2cc9211721906fb022432991c2038b41418b16a0264471a762c264a"   /* 24249999 */,
    "02080020d93b68d6f512f5a82a754a29b9d0f3110697a8b937cc2cb374fdabfc3284c49b5f1fc07dbc3a072f97ceee66ca562cfdf77bac9635734e6732f463ceffdb293c1b18b16a4e19221a5f825944"   /* 24250000 */
};
static const BRCheckPointContext BRMainNetCheckpointContexts[] = {
    { 24200000, sizeof(BRMainNetCheckpointContext24200000)/sizeof(*BRMainNetCheckpointContext24200000), BRMainNetCheckpointContext24200000 },
    { 24250000, sizeof(BRMainNetCheckpointContext24250000)/sizeof(*BRMainNetCheckpointContext24250000), BRMainNetCheckpointContext24250000 }
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
