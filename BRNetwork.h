#ifndef BRNetwork_h
#define BRNetwork_h
#ifdef __cplusplus
extern "C" {
#endif
// Runtime network selection. Set ONCE at core init before any wallet/peer-manager creation.
// Defaults to mainnet (0) so mainnet builds are unchanged until BRSetNetwork is called.
void BRSetNetwork(int isTestnet);
int  BRNetworkIsTestnet(void);
#ifdef __cplusplus
}
#endif
#endif
