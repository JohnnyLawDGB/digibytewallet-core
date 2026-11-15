//
//  BRDigiAsset.h
//  DigiByte
//
//  Created by Yoshi Jaeger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#ifndef BRDigiAsset_h
#define BRDigiAsset_h

#include "BRAssetData.h"
#include "BRTransaction.h"
#include <stdint.h>

/*
              DIGI-
      _                _
     /_\  ___ ___  ___| |_ ___
    //_\\/ __/ __|/ _ \ __/ __|
   /  _  \__ \__ \  __/ |_\__ \
   \_/ \_/___/___/\___|\__|___/
 */

// First word must be zero, second must not be zero
#define DA_IS_ISSUANCE(byte) ((~(byte) & 0xF0) && ((byte) & 0x0F))
// First word must be 1
#define DA_IS_TRANSFER(byte) ((byte) & 0x10)
// First word must be 2
#define DA_IS_BURN(byte)     ((byte) & 0x20)

#define DA_TYPE_SHA1_META_SHA256      0x01
#define DA_TYPE_SHA1_MS12_SHA256      0x02
#define DA_TYPE_SHA1_MS13_SHA256      0x03
#define DA_TYPE_SHA1_META             0x04
#define DA_TYPE_SHA1_NO_META_LOCKED   0x05
#define DA_TYPE_SHA1_NO_META_UNLOCKED 0x06

#define DA_ASSET_DUST_AMOUNT 700

uint8_t BRTXContainsAsset(BRTransaction *tx);

uint8_t BRContainsAsset(const BRTxOutput *outputs, size_t outCount);

uint8_t BROutpointIsAsset(const BRTxOutput* output);

uint8_t BRTxOutputIsAsset(const BRTransaction* transaction, const BRTxOutput* output);

/* DA-014-REF: what BRTxAssetCarrier answers (see BRDigiAsset.c). */
#define DA_TX_NONE      0
#define DA_TX_CARRIER   1
#define DA_TX_UNDECIDED 2

int BRTxAssetCarrier(const BRTransaction *transaction, size_t *carrierIdx);

#endif /* BRDigiAsset_h */
