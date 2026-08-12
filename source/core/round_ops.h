// source/core/round_ops.h
// Implementation of Rounds for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef ROUND_OPS_H
#define ROUND_OPS_H

#include <stdint.h>
#include "sbox.h"

// xors the block with the round key — addroundkey step in aes.
// combines the state with key material to prevent reversal without the key.
void round_xor_with_key(uint8_t *block, const uint8_t *key);

// substitutes each byte using the forward s-box — subbytes step.
// provides non-linearity, the core defense against linear and differential attacks.
void round_apply_sbox(uint8_t *block);

// substitutes each byte using the inverse s-box — invsubbytes step (decryption).
void round_apply_inv_sbox(uint8_t *block);

// cyclically shifts rows of the state left — shiftrows step.
// mixes bytes across columns for diffusion.
void round_shift_rows(uint8_t *block);

// cyclically shifts rows right — invshiftrows step (decryption).
void round_inv_shift_rows(uint8_t *block);

// multiplies each column by the aes mixcolumns matrix over gf(2^8).
// provides diffusion within each column; omitted in the final round.
void round_mix(uint8_t *block);

// multiplies each column by the inverse mixcolumns matrix (decryption).
void round_inv_mix(uint8_t *block);

#endif