// source/core/hmac.h
// Implementation of HMAC for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

// hmac output size: 32 bytes = sha256 digest size.
// matches hash_digest_size for consistency with the underlying hash function.
#define HMAC_SIZE 32

// sha256 internal block size: 64 bytes.
// used for key padding in hmac (keys are normalized to this size before hashing).
#define HMAC_BLOCK_SIZE 64

// computes hmac-sha256(key, data) and writes the 32-byte result to digest.
// key: secret key material of arbitrary length (normalized internally).
// data: message to authenticate (ciphertext + header in encrypt-then-mac).
// digest: output buffer of exactly hmac_size bytes (32).
void hmac_compute(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SIZE]);

#endif