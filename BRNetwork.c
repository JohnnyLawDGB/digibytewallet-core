#include "BRNetwork.h"
static int g_isTestnet = 0;
void BRSetNetwork(int isTestnet) { g_isTestnet = isTestnet ? 1 : 0; }
int  BRNetworkIsTestnet(void)    { return g_isTestnet; }
