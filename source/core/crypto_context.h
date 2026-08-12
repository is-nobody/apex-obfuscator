// source/core/crypto_context.h
// Implementation of Crypto Context for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include <stdint.h>
#include <stddef.h>

// default key size: 32 bytes = 256 bits for aes-256.
// matches the aes key size and derived key size for consistency.
#define DEFAULT_KEY_SIZE 32

// global default key buffer: populated once at startup with a random key.
// extern so main.c and args.c can reference it directly if needed.
extern uint8_t default_key[DEFAULT_KEY_SIZE];

// initializes the default key with cryptographically secure random bytes.
// must be called once before any encryption/decryption operations.
// subsequent calls would overwrite the key (not done, but safe if it happened).
void crypto_init_default_key(void);

// copies the default key into the provided buffer.
// the caller is responsible for providing a buffer of at least default_key_size bytes.
void crypto_get_default_key(uint8_t key[DEFAULT_KEY_SIZE]);

#endif