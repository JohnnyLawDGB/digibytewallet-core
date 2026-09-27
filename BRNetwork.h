#ifndef BRNetwork_h
#define BRNetwork_h
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Runtime network selection. Set ONCE at core init before any wallet/peer-manager creation.
// Defaults to mainnet (0) so mainnet builds are unchanged until BRSetNetwork is called.
void BRSetNetwork(int isTestnet);
int  BRNetworkIsTestnet(void);

// DigiDollar activation floor: the lowest block height at which a confirmed DigiDollar-shaped
// output is credited as DigiDollar. Mirrors the reference client's EarliestActivationFloor
// (consensus/digidollar.cpp) = min(nDDActivationHeight, DeploymentHeight(DIGIDOLLAR)), from
// kernel/chainparams.cpp: mainnet DigiDollarHeight 23,869,440 / nDDActivationHeight 23,627,520;
// testnet 600 / 600. Keyed on the COIN's height (CoinHeightMayCreateDigiDollar), so an output one
// block below the floor is ordinary history and one at the floor is credited.
#define DD_ACTIVATION_HEIGHT_MAINNET 23627520u
#define DD_ACTIVATION_HEIGHT_TESTNET 600u
uint32_t BRNetworkDigiDollarActivationHeight(void);
#ifdef __cplusplus
}
#endif
#endif
