// source/core/hash.c
// Implementation of Hash for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "hash.h"
#include "sbox.h"
#include <string.h>

// number of rounds in the sha-256 compression function.
// each round mixes the message schedule word into the working state.
#define HASH_ROUNDS 64

// sha-256 round constants: the first 32 bits of the fractional parts of the cube roots
// of the first 64 primes. these are "nothing-up-my-sleeve" numbers that provide
// asymmetric constants to break any potential symmetry in the compression function.
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// bitwise right rotation (circular shift).
// used extensively in sha-256 for diffusion within 32-bit words.
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// choice function: (x and y) xor (not x and z).
// selects bits from y where x is 1, from z where x is 0.
// this is the primary non-linear mixing function in sha-256.
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

// majority function: true when at least two of three inputs are true.
// (x and y) xor (x and z) xor (y and z) — symmetric and balanced.
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// big sigma 0: rotates and xors for diffusion in the upper state word path.
// operates on the a register to spread bits across word positions.
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

// big sigma 1: rotates and xors for diffusion in the lower state word path.
// operates on the e register.
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

// small sigma 0: message schedule word mixing for words 16..63.
// spreads bits from earlier message words into later schedule positions.
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))

// small sigma 1: message schedule word mixing for words 16..63.
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// sha-256 compression function: processes one 64-byte message block.
// mixes the block into the current hash state via 64 rounds of logical operations.
// state is updated in-place (added to, not replaced) for the merkle-damgård construction.
static void hash_mix(uint32_t *state, const uint8_t *block) {
    uint32_t W[64];  // message schedule array (64 words of 32 bits)
    uint32_t a, b, c, d, e, f, g, h, T1, T2;
    
    // prepare message schedule: first 16 words are the block itself (big-endian).
    for (int t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t * 4]     << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8)  |
               ((uint32_t)block[t * 4 + 3]);
    }
    
    // extend to 64 words: each remaining word mixes four earlier words with sigma functions.
    // this ensures every bit of the message affects many rounds of compression.
    for (int t = 16; t < 64; t++) {
        W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
    }
    
    // initialize working variables from current hash state.
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // 64 rounds of compression: each round mixes one schedule word and one constant.
    for (int t = 0; t < 64; t++) {
        T1 = h + EP1(e) + CH(e, f, g) + K[t] + W[t];
        T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;   // e feeds forward with t1 added
        d = c;
        c = b;
        b = a;
        a = T1 + T2;  // a gets sum of both intermediates
    }
    
    // add compressed block to state (davies-meyer construction: feed-forward).
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// wrapper around hash_mix that copies state, compresses, then updates.
// isolates the compression call for cleaner buffer management in hash_update.
static void hash_compress(HASH_CTX *ctx, const uint8_t *block) {
    uint32_t state[8];
    memcpy(state, ctx->state, 32);
    hash_mix(state, block);
    for (int i = 0; i < 8; i++) {
        ctx->state[i] = state[i];
    }
}

// initializes sha-256 context with the standard initial hash values.
// these are the first 32 bits of the fractional parts of the square roots
// of the first 8 primes — nothing-up-my-sleeve constants.
void hash_init(HASH_CTX *ctx) {
    ctx->count = 0;  // total bytes processed (used for length padding at finalization)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x9b05688c;
    ctx->state[5] = 0x1f83d9ab;
    ctx->state[6] = 0x5be0cd19;
    ctx->state[7] = 0xcbbb9d5d;
}

// feeds data incrementally into the hash context.
// data is buffered until a full 64-byte block is accumulated, then compressed.
// this allows hashing of arbitrarily large streams without loading everything into memory.
void hash_update(HASH_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    
    while (i < len) {
        // position within the internal buffer where new data should be placed.
        size_t buffer_index = (size_t)(ctx->count % HASH_BLOCK_SIZE);
        
        // how much space remains in the current buffer.
        size_t space = HASH_BLOCK_SIZE - buffer_index;
        
        // copy at most enough to fill the buffer.
        size_t chunk = (len - i < space) ? len - i : space;
        
        memcpy(ctx->buffer + buffer_index, data + i, chunk);
        ctx->count += chunk;
        i += chunk;
        
        // if buffer is full, compress it into the state and continue.
        if (ctx->count % HASH_BLOCK_SIZE == 0) {
            hash_compress(ctx, ctx->buffer);
        }
    }
}

// finalizes the hash: applies merkle-damgård padding (1 bit, zeros, 64-bit length)
// and performs the final compression(s). after this, the context is consumed.
void hash_final(HASH_CTX *ctx, uint8_t digest[HASH_DIGEST_SIZE]) {
    // current write position in the buffer.
    size_t buffer_index = (size_t)(ctx->count % HASH_BLOCK_SIZE);
    
    // append the mandatory 0x80 byte (single '1' bit followed by zeros).
    ctx->buffer[buffer_index++] = 0x80;
    
    // if there isn't enough room for the 8-byte length field at the end,
    // pad with zeros, compress this block, and start a new one.
    if (buffer_index > 56) {
        memset(ctx->buffer + buffer_index, 0, HASH_BLOCK_SIZE - buffer_index);
        hash_compress(ctx, ctx->buffer);
        buffer_index = 0;
    }
    
    // fill remaining bytes with zeros up to position 56 (64 - 8 for length).
    memset(ctx->buffer + buffer_index, 0, 56 - buffer_index);
    
    // append the total message length in bits as a 64-bit big-endian integer.
    // this ensures that messages of different lengths produce different hashes.
    uint64_t bits = ctx->count * 8;
    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }
    
    // final compression of the padded block.
    hash_compress(ctx, ctx->buffer);
    
    // extract the 32-byte digest from the final state (big-endian word order).
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}