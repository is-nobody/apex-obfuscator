// source/core/keygen.h
// Implementation of Key Generation for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "sbox.h"

// number of aes rounds: 14 for 256-bit keys (128-bit keys use 10, 192-bit use 12).
#define ROUNDS 14

// default key size in bytes: 32 bytes = 256 bits for aes-256.
#define DEFAULT_KEY_SIZE 32

// minimum acceptable key size: 32 bytes to enforce aes-256 security level.
// shorter keys trigger automatic hmac expansion with a user warning.
#define MIN_KEY_SIZE 32

// aes-256 constants for key expansion:
// nk = 8 words in the cipher key (256 bits / 32 bits per word)
// nr = 14 rounds (standard for 256-bit key)
// nb = 4 words per block (128-bit aes block size, always 4)
#define NK 8
#define NR 14
#define NB 4

// expands the master key into round keys for encryption/decryption.
// keys shorter than 32 bytes are automatically expanded to full strength via hmac.
// round_keys array must have dimensions [ROUNDS + 1][BLOCK_SIZE] (15 × 16 bytes).
void keygen_expand(const uint8_t *master_key, size_t key_len,
                   uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]);

// fills the 16-byte iv with cryptographically secure random bytes.
// uses os-level entropy sources; aborts on failure since iv security is critical.
void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]);

// fills the key buffer with cryptographically secure random bytes.
// aborts if the os rng fails — no secure fallback is possible.
void keygen_random_key(uint8_t *key, size_t len);

#endif