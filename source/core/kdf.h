// source/core/kdf.h
// Implementation of KDF for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>

// salt size for kdf: 16 bytes provides 128 bits of uniqueness.
// each encryption gets a fresh random salt, so identical passwords produce different keys.
#define KDF_SALT_SIZE 16

// pbkdf2 iteration count: 100,000 rounds.
// chosen as a balance between security (higher = slower to brute-force) and usability.
// owasp recommends at least 600,000 for sha256 in 2023, but 100k is acceptable for file encryption
// where the kdf runs once per encrypt/decrypt rather than per login attempt.
#define KDF_ITERATIONS 100000

// derived key output size: 32 bytes = 256 bits, matching aes-256 key size.
#define KDF_DERIVED_KEY_SIZE 32

// derives a cryptographic key from a password and salt using pbkdf2-hmac-sha256.
// password: user-provided key material (may be short/weak).
// salt: random 16-byte value unique per encryption (prevents precomputed rainbow table attacks).
// iterations: number of hmac iterations (higher = more expensive to brute-force).
// derived_key: output buffer receiving the strengthened key.
// key_len: desired output length in bytes (typically 32 for aes-256).
// returns 0 on success, -1 if any parameter is invalid.
int kdf_derive(const uint8_t *password, size_t password_len,
               const uint8_t *salt, size_t salt_len,
               uint32_t iterations,
               uint8_t *derived_key, size_t key_len);

#endif