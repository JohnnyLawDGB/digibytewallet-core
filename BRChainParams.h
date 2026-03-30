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
#include <assert.h>

typedef struct {
    uint32_t height;
    UInt256 hash;
    uint32_t timestamp;
    uint32_t target;
} BRCheckPoint;

typedef struct {
    const char * const *dnsSeeds; // NULL terminated array of dns seeds
    uint16_t standardPort;
    uint32_t magicNumber;
    uint64_t services;
    int (*verifyDifficulty)(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime);
    const BRCheckPoint *checkpoints;
    size_t checkpointsCount;
} BRChainParams;

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
        "testnet-1.us.digibyteservers.io",
        "testnetexplorer.digibyteservers.io", NULL
};

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they must be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const BRCheckPoint BRMainNetCheckpoints[] = {
        {       0, uint256("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496"), 1389388394, 0x1e0ffff0 },
        {    5000, uint256("95753d284404118788a799ac754a3fdb5d817f5bd73a78697dfe40985c085596"), 1389701913, 0x1c32a753 },
        {   10000, uint256("12f90b8744f3b965e107ad9fd8b33ba6d95a91882fbc4b5f8588d70d494bed88"), 1389996580, 0x1c1557fc },
        {   12000, uint256("a1266acba91dc3d5737d9e8c6e21b7a91901f7f4c48082ce3d84dd394a13e415"), 1390115182, 0x1c0d748e },
        {   14300, uint256("24f665d71b0c6c88f6f72a863e9f1ba8e835cc52d13ad895dc5426021c7d2c48"), 1390258861, 0x1c1409e7 },
        {   30000, uint256("17c69ef6b403571b1bd333c91fbe116e451ba8281be12aa6bafb0486764bb315"), 1391206674, 0x1c0e8ff5 },
        {   60000, uint256("57b2c612b60462a3d6c388c8b30a68cb6f7e2034eea962b12b7ef506454fa2c1"), 1393183580, 0x1c16beae },
        {  110000, uint256("ab2da24656493015f2fd288994661e1cc657d90aa34c755514af044aaaf1569d"), 1397850930, 0x1c198d98 },
        {  141100, uint256("145c2cb5239a4e019c730ce8468d927a3955529c2bae077850783da97ddbca05"), 1407018505, 0x1c01722c },
        {  141656, uint256("683d27720429f28bcfa22d8385b7a06f307c8fd918d49215148fbd41a0dda595"), 1408033242, 0x1c0185fc },
        {  245000, uint256("852c475c605e1f20bbe60219c811abaeef08bf0d4ff87eef59200fd7a7567fa7"), 1413145109, 0x1c028e59 },
        {  302000, uint256("fb6d14ac5e0208f00d941db1fcbfe050f093cfd0c05ed151c809e4428bc14286"), 1414988281, 0x1b0fb02e },
        {  331000, uint256("bd1a1d002750e1648746eb29c78d30fa1043c8b6f89d82924c4488be06fa3d19"), 1415917252, 0x1c07e8f8 },
        {  360000, uint256("8fee7e3f6c38dccd3047a3e4667c63406f835c2890024030a2ab2dc6dba7c912"), 1416891634, 0x1b2c1714 },
        {  400100, uint256("82325a97cd97ac14b0a57408f881b1a9fc40174f8430a4580429499ac5d153c8"), 1418232367, 0x1c020a1c },
        {  521000, uint256("d23fd1e1f994c0586d761b71bb3530e9ab45bd0fabda3a5a2e394f3dc4d9bb04"), 1421875139, 0x1c04531c },
        { 1380000, uint256("00000000000001969b1e5836dd8bf6a001d96f4a16d336e09405b62b29feead6"), 1447731080, 0x1a02e03e },
        { 1435000, uint256("f78cc9c2791c8a23720e2efcdaf46584046ee5db8f050e21a3a15a13f5c68da0"), 1449312651, 0x1c1f3df6 },
        { 3000000, uint256("c9b034e634cb78f16385ba5cd166f91a5b448af84d6b20c0a924bc2f4409effd"), 1472667779, 0x1b24a10a },
        { 4255555, uint256("23f72e760542bf021ec76d04231ad7cf80142069a79ba702028e074b726f86ef"), 1491329321, 0x1b26a4c3 },
        { 5712333, uint256("0000000000000003363ff6207a99a175e8b5adff71c77817a92f127fcefe936e"), 1513061829, 0x1924bd79 },
        { 5782400, uint256("b1005c34a3f4fbc0d99f2fe521490b63abd2ff2029fef80df72dd22ac2c735ec"), 1514109544, 0x1a5b24c0 },
        { 5822077, uint256("27d9687ef5f34d2b451c2c0d9c4a6612e7b4bbdc083d03bbdf2d2adbef08e5b1"), 1514700120, 0x1b023a6c },
        { 5862666, uint256("0000000000000000b06d70ff1a3424a933b7743dc44ed08422cbc6b3fef8422c"), 1515304798, 0x1906cff8 },
        { 6121330, uint256("819f22e8aee4fabfc36d12bac142852697b438fda5e5b3545102faa624b354e1"), 1519162626, 0x1b02f1a7 },
        { 6227953, uint256("04a2e7f5ed5017dc45ee0627c1ed446f5331c290dc43e2febaa30e81fa280888"), 1520747973, 0x1a621a03 },
        { 6256573, uint256("2b3d16a3a14eadcbaa977b8e8c41fc56140fee024c70047bfc18bef2d1ffa756"), 1521172890, 0x1a662f3c },
        { 6268500, uint256("00000000000000068c5b2c3515cf1fee4ff0fba92426cc6dad28e6ed9298f36a"), 1521349185, 0x190b32a3 },
        { 6309234, uint256("86f360c347d61a1015e901ffcc54a0692af7267e06b64191aa21be988368673d"), 1521953988, 0x1a2bb5ea },
        { 7000000, uint256("03c6664b250c3e3b688f5779ce791384b35acaa38c4461f0458a4674bd762f63"), 1532239864, 0x1a117058 },
        { 8000000, uint256("1af919cb004bb05c369a862cb5ded70aaa123d0eac2432ceec859f6f42880660"), 1547155779, 0x1b01d883 },
        { 9000000, uint256("942b62f60ae25478d6ee41ec498daefc306cf6f93ff500435a12aa6fe3750220"), 1562079462, 0x1a07d618 },
        { 10000000, uint256("9e382e2ae1909a4f20c40f38bc7b9f5d0222d5f92ed8be9c04238209c88d55b7"), 1577042521, 0x1b00eb79 },
        { 11000000, uint256("0f4ad10ae49b504246c0175f6cbab9b0f91b6568a88931e6341a83a731701054"), 1591976167, 0x1b008be8 },
        { 12000000, uint256("0000000000000000e231d6676909d4d54296d640d996453b6778cc8081239c1f"), 1606947788, 0x19029b4f },
        { 13000000, uint256("a4c1069938986237270340fa9118e839e9a4b614fddf57b3d51e988ab357c13f"), 1621883565, 0x1a09f428 },
        { 13510000, uint256("e41f3bbb0668b4db50682506e131d4f6c31fbf66be58d03d35a5dc30fed5432a"), 1629510979, 0x1a24afff },
        // Checkpoints added for DigiByte Core 8.26 compatibility — extracted from local mainnet node v8.26.2
        { 14000000, uint256("a33861c857eed46191cf6cdaf81693e0dfcd00b3a11133821b0c73fe1d7769d9"), 1636828206, 0x1b00ad8c },
        { 14500000, uint256("7de279fee9a88b3cedac3b0fead7af3ba89411545076a42c836ec1d6ba0d1d46"), 1644302520, 0x1a19ae92 },
        { 15000000, uint256("57debd1dd4427be41f9b0d59beb26ca482255c18b2a01979a64bb70b173a537c"), 1651770202, 0x1a017ed3 },
        { 15500000, uint256("000000000000000439d5c66b2fb3ec50f50a68b65f5790d338150b63488de645"), 1659244610, 0x19049b92 },
        { 16000000, uint256("5c0c7d7baecc5e13c69f06eb90534ab2db8ff0cc98a1ac8d8797f11dc16ea0ad"), 1666719839, 0x1b00dfbe },
        { 16500000, uint256("0f08ad160c196da58d855e505aca4237d8527788c917b8e85593ca33444e549d"), 1674196649, 0x1b009f8e },
        { 17000000, uint256("f167688cc0102743b135499ed9f9eff9c5bad096203150e438be0a6e783d5587"), 1681676982, 0x1a10412f },
        { 17500000, uint256("31838212ab7cb0eb24f0b7100b2a688f92c8d0109878ce8360586b26cdc1da68"), 1689155057, 0x1a0a5772 },
        { 18000000, uint256("c71cc4929af6adb6b501f59a5b60b2638e0fd1cbe631b6ce40aacb21b46ca7b0"), 1696633305, 0x1a047f1d },
        { 18500000, uint256("745dc7b89208de482071a3a8d13eb5596d55bedc4f5ba2fa74cbea9ecf91169e"), 1704110816, 0x1a5daab1 },
        { 19000000, uint256("67066a10cdb8f3d86a4b405209e06ccc77b908d464af04193ad47682c0b4da73"), 1711586649, 0x1a012a4d },
        { 19500000, uint256("c008cae8399ff9a4d9a5572f3f2ddc53e2db9754df1dda6f1f09424da8dab29f"), 1719078271, 0x1a219c86 },
        { 20000000, uint256("f530a66ba6fe93e647f7d88a9b3f22bfe8c2c2ab1ec1b0286286f86b82d6a10f"), 1726553537, 0x1a08cd13 },
        { 20500000, uint256("d39c147eb2faef374f1e5e0a9095558c5393d3a2ccee981de65dc4203845107e"), 1734032704, 0x1a00f3ee },
        { 21000000, uint256("0000000000000001cb40d3be76bf601d98555a069669d963060d633ea3a140e8"), 1741505272, 0x19027f4c },
        { 21500000, uint256("00000000000000007cbe22612937832c2e6341ec867e881979e2246df44fa727"), 1748982571, 0x1903b647 },
        { 22000000, uint256("f8ee51070753b526000469277c2e73981d96f15852ae7c9b0ae5de0bdb8b9ee8"), 1756460375, 0x1a34dafd },
        { 22500000, uint256("e9e740eef2cd62cbf4321e11b26703acc1f0506c726cb2a61f7c886974d1bc7d"), 1763941298, 0x1a2aca28 },
        { 23000000, uint256("a805aa0c3c4e01abee1ce0edbc7ea7a4dd2fbf920681ced7333e20b35f95a97e"), 1771424588, 0x1a0b9a5c },
        { 23187000, uint256("0000000000000005611e332000cc21f5ab13da2a753b8e3901a683fe8418de15"), 1774221766, 0x19074103 }

};

static const BRCheckPoint BRTestNetCheckpoints[] = {
    {0, "2a0f89abc8b26dc42791b5945295788c21d58f46fb5854bea0ce2a0c42dc65e8", 1609556859, 549454338 }
        //   {     0, "852c475c605e1f20bbe60219c811abaeef08bf0d4ff87eef59200fd7a7567fa7", 1413145109, 0x1b336ce6 },
        // Sitt 2016-02-18 Use Checkpoint from the First day of digiwallet fork (from breadWallet)
//        {  145000, uint256("f8d650dda836d5e3809b928b8523f050891c3bb9fa2c201bb04824a8a2fe7df6"), 1409596362, 0x1c01f271},
//        { 1800000, uint256("72f46e1fff56518dce7e540b407260ea827cb1c4652f24eb1d1917f54b95d65a"), 1454769372, 0x1c021355},
//        { 2149922, uint256("557846763a5f1eb3205d175724bd26ba7123c17c49eaaadf20b67c7e20e3118a"), 1460001303, 0x1c012a26},
//        { 4444444, uint256("0000000000000114de2ba1462056d2a9bd9ccfbd406cd2dfedaaef2c12910659"), 1494132592, 0x1a01152f}
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
    sizeof(BRMainNetCheckpoints)/sizeof(*BRMainNetCheckpoints)
};

static const BRChainParams BRTestNetParams = {
    BRTestNetDNSSeeds,
    12026,      // standardPort
    0xeeb791d1, // magicNumber
    0,          // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints)/sizeof(*BRTestNetCheckpoints)
};

#endif // BRChainParams_h
