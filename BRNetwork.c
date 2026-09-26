#include "BRNetwork.h"
static int g_isTestnet = 0;
void BRSetNetwork(int isTestnet) { g_isTestnet = isTestnet ? 1 : 0; }
int  BRNetworkIsTestnet(void)    { return g_isTestnet; }
// See BRNetwork.h: the reference client's EarliestActivationFloor per network.
uint32_t BRNetworkDigiDollarActivationHeight(void)
{
    return g_isTestnet ? DD_ACTIVATION_HEIGHT_TESTNET : DD_ACTIVATION_HEIGHT_MAINNET;
}
