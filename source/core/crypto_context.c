// source/core/crypto_context.c
// Implementation of Crypto Context for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "crypto_context.h"
#include "keygen.h"
#include <string.h>

// global default key buffer: holds a random 256-bit key generated once at program startup.
// this key is used when the user doesn't provide their own key via the command line.
// storing a default key avoids requiring a key for every operation while still providing
// cryptographic protection (random per-process key, not a hardcoded constant).
uint8_t default_key[DEFAULT_KEY_SIZE];

// generates a fresh random default key at program startup.
// called once by main() before any command processing.
// the key is 32 bytes (256 bits) for full aes-256 strength.
//
// this approach means even "keyless" encryption uses a strong random key —
// the user just doesn't know what it is. useful for temporary/transit encryption
// where the key doesn't need to be remembered.
void crypto_init_default_key(void) {
    keygen_random_key(default_key, DEFAULT_KEY_SIZE);
}

// copies the default key into a caller-provided buffer.
// used when command handlers need access to the default key for encryption/decryption.
// returns a copy rather than a pointer to prevent accidental modification of the global key.
void crypto_get_default_key(uint8_t key[DEFAULT_KEY_SIZE]) {
    memcpy(key, default_key, DEFAULT_KEY_SIZE);
}