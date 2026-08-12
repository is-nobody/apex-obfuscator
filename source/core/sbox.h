// source/core/sbox.h
// Implementation of Sbox for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef SBOX_H
#define SBOX_H

#include <stdint.h>

// block size in bytes for aes-style operations (128 bits = 16 bytes).
#define BLOCK_SIZE 16

// forward aes s-box: 256-byte lookup table for non-linear byte substitution.
extern const uint8_t SBOX[256];

// inverse s-box: reverses the forward substitution during decryption.
// initialized once by sbox_init().
extern uint8_t INV_SBOX[256];

// hash-specific s-box variant: derived from sbox with offset and xor,
// used internally by the hash function for domain separation from cipher ops.
extern uint8_t HASH_SBOX[256];

// call once before any cipher or hash operations to populate inv_sbox and hash_sbox.
// safe to call multiple times — subsequent calls are no-ops.
void sbox_init(void);

#endif