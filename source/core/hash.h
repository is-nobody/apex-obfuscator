// source/core/hash.h
// Implementation of Hash for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

// sha-256 internal block size: 64 bytes (512 bits).
// the compression function processes one block at a time.
#define HASH_BLOCK_SIZE 64

// sha-256 output digest size: 32 bytes (256 bits).
#define HASH_DIGEST_SIZE 32

// sha-256 context: holds the internal state and buffered data between updates.
// call hash_init once, hash_update zero or more times, then hash_final once.
typedef struct {
    uint8_t buffer[HASH_BLOCK_SIZE];  // accumulates data until a full block is ready
    uint32_t state[8];                // current hash state (eight 32-bit words)
    uint64_t count;                   // total bytes processed (used for length padding)
} HASH_CTX;

// initializes a sha-256 context with the standard initial hash values.
// must be called before any hash_update or hash_final on the context.
void hash_init(HASH_CTX *ctx);

// feeds data into the hash. can be called multiple times for streaming input.
// data is buffered and compressed in 64-byte blocks as they fill up.
void hash_update(HASH_CTX *ctx, const uint8_t *data, size_t len);

// finalizes the hash: applies padding, final compression, and writes the 32-byte digest.
// the context is consumed and should not be reused without re-initialization.
void hash_final(HASH_CTX *ctx, uint8_t digest[HASH_DIGEST_SIZE]);

#endif