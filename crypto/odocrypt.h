// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The DigiByte Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HASH_ODO
#define HASH_ODO

#include <stdlib.h>

// key shapechange interval per chain (the reference client's Consensus::Params::nOdoShapechangeInterval):
// mainnet 10 days (name kept as spelled for the existing callers), testnet 1 day
#define ODOCRYPT_CHAPECHANGE_INTERVAL         (10*24*60*60)
#define ODOCRYPT_SHAPECHANGE_INTERVAL_TESTNET (1*24*60*60)
#define ODOCRYPT_DIGEST_SIZE          (80)

// Number of rounds.
const static int ODOCRYPT_ROUNDS = 84;
// Odo utilizes two sbox sizes - 6-bit sboxes, which are ideally suited for
// FPGA logic elements, and 10-bit sboxes, which are ideally suited for FPGA
// RAM elements.
const static int ODOCRYPT_SMALL_SBOX_WIDTH = 6;
const static int ODOCRYPT_LARGE_SBOX_WIDTH = 10;
// The pboxes are constructed using 3 primitives, applied multiple times.
const static int ODOCRYPT_PBOX_SUBROUNDS = 6;
// This constant should be a generator for the multiplicative group of
// integers modulo STATE_SIZE (3 or 7 for a STATE_SIZE of 10).  It controls
// one part of the pbox step.
const static int ODOCRYPT_PBOX_M = 3;
// The multiplicative inverse of PBOX_M modulo STATE_SIZE
const static int ODOCRYPT_INV_PBOX_M = 7;
// This constant must be even.  It controls the number of rotations used in
// the linear mixing step.
const static int ODOCRYPT_ROTATION_COUNT = 6;
// Odo internally operates on 64-bit words.
const static int ODOCRYPT_WORD_BITS = 64;

const static int ODOCRYPT_DIGEST_BITS = 8 * ODOCRYPT_DIGEST_SIZE;
const static int ODOCRYPT_STATE_SIZE = ODOCRYPT_DIGEST_BITS / ODOCRYPT_WORD_BITS;
const static int ODOCRYPT_SMALL_SBOX_COUNT = ODOCRYPT_DIGEST_BITS / (ODOCRYPT_SMALL_SBOX_WIDTH + ODOCRYPT_LARGE_SBOX_WIDTH);
const static int ODOCRYPT_LARGE_SBOX_COUNT = ODOCRYPT_STATE_SIZE;

typedef struct {
    uint64_t mask[ODOCRYPT_PBOX_SUBROUNDS][ODOCRYPT_STATE_SIZE/2];
    int rotation[ODOCRYPT_PBOX_SUBROUNDS-1][ODOCRYPT_STATE_SIZE/2];
} Pbox;

typedef struct {
    uint32_t key;
    Pbox Permutation[2];
    uint8_t Sbox1[ODOCRYPT_SMALL_SBOX_COUNT][1 << ODOCRYPT_SMALL_SBOX_WIDTH];
    uint16_t Sbox2[ODOCRYPT_LARGE_SBOX_COUNT][1 << ODOCRYPT_LARGE_SBOX_WIDTH];
    int Rotations[ODOCRYPT_ROTATION_COUNT];
    uint16_t RoundKey[ODOCRYPT_ROUNDS];
} OdoStruct;

typedef struct {
    uint64_t current;
    uint64_t multiplicand;
    uint64_t addend;
} OdoRandom;

const static uint64_t BASE_MULTIPLICAND = 6364136223846793005ull;
const static uint64_t BASE_ADDEND = 1442695040888963407ull;

int Odocrypt_Hash(OdoStruct* odo, const char* pbegin, const char* pend, char* output);
void Odocrypt_Encrypt(OdoStruct* odo, char* cipher, const char* plain);
void Odocrypt_Init(OdoStruct* odo, uint32_t key);

#endif
