// source/core/round_ops.c
// Implementation of Rounds for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <string.h>
#include "round_ops.h"

// galois field multiplication lookup tables for the mixcolumns step.
// precomputing these avoids expensive runtime gf(2^8) multiplications.
// each table holds the result of multiplying every byte 0..255 by a fixed constant.
static uint8_t gf_mul2[256];   // multiply by 2 (x)  — used in forward mixcolumns
static uint8_t gf_mul3[256];   // multiply by 3 (x+1) — used in forward mixcolumns
static uint8_t gf_mul9[256];   // multiply by 9       — used in inverse mixcolumns
static uint8_t gf_mul11[256];  // multiply by 11      — used in inverse mixcolumns
static uint8_t gf_mul13[256];  // multiply by 13      — used in inverse mixcolumns
static uint8_t gf_mul14[256];  // multiply by 14      — used in inverse mixcolumns

// flag to ensure gf tables are computed only once across all round operations.
static int gf_tables_initialized = 0;

// performs a single gf(2^8) multiplication using the standard aes irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
// only used during table initialization; runtime lookups use the precomputed tables for speed.
static uint8_t gf_mul_slow(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;          // if current bit of b is set, xor a into product
        uint8_t hi = a & 0x80;      // check if high bit will overflow after shift
        a <<= 1;                     // multiply a by x
        if (hi) a ^= 0x1B;          // reduce modulo x^8 + x^4 + x^3 + x + 1
        b >>= 1;                     // move to next bit of b
    }
    return p;
}

// precomputes all six gf multiplication tables.
// called lazily on first use to avoid startup cost if cipher is never used.
static void init_gf_tables(void) {
    if (gf_tables_initialized) return;
    
    for (int i = 0; i < 256; i++) {
        gf_mul2[i]  = gf_mul_slow(i, 2);
        gf_mul3[i]  = gf_mul_slow(i, 3);
        gf_mul9[i]  = gf_mul_slow(i, 9);
        gf_mul11[i] = gf_mul_slow(i, 11);
        gf_mul13[i] = gf_mul_slow(i, 13);
        gf_mul14[i] = gf_mul_slow(i, 14);
    }
    gf_tables_initialized = 1;
}

// xors the 16-byte block with the round key using 32-bit word operations.
// processing as words is faster than byte-by-byte xor on most platforms.
void round_xor_with_key(uint8_t *block, const uint8_t *key) {
    uint32_t b[4];
    uint32_t k[4];
    
    // copy block and key into word arrays — memcpy handles unaligned access safely.
    memcpy(b, block, 16);
    memcpy(k, key, 16);
    
    // xor corresponding 32-bit words together.
    b[0] ^= k[0];
    b[1] ^= k[1];
    b[2] ^= k[2];
    b[3] ^= k[3];
    
    memcpy(block, b, 16);
}

// applies the forward s-box substitution to every byte in the block.
// this is the primary source of non-linearity in aes, defeating linear cryptanalysis.
void round_apply_sbox(uint8_t *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = SBOX[block[i]];
    }
}

// applies the inverse s-box substitution during decryption.
// reverses the forward s-box transformation byte by byte.
void round_apply_inv_sbox(uint8_t *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = INV_SBOX[block[i]];
    }
}

// shifts rows of the 4x4 state matrix left by row index (row 0: 0, row 1: 1, row 2: 2, row 3: 3).
// this provides diffusion by moving bytes across column boundaries.
// state layout in the flat array: column-major (bytes 0-3 = column 0, 4-7 = column 1, etc.)
void round_shift_rows(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    
    // row 0: no shift — bytes stay at positions 0,4,8,12
    tmp[0]  = block[0];
    tmp[4]  = block[4];
    tmp[8]  = block[8];
    tmp[12] = block[12];
    
    // row 1: shift left by 1 — byte from col 1 moves to col 0, etc.
    tmp[1]  = block[5];   // was column 1, row 1 → now column 0, row 1
    tmp[5]  = block[9];   // was column 2, row 1 → now column 1, row 1
    tmp[9]  = block[13];  // was column 3, row 1 → now column 2, row 1
    tmp[13] = block[1];   // was column 0, row 1 → now column 3, row 1
    
    // row 2: shift left by 2 — each byte moves two columns left
    tmp[2]  = block[10];
    tmp[6]  = block[14];
    tmp[10] = block[2];
    tmp[14] = block[6];
    
    // row 3: shift left by 3 (or right by 1) — each byte moves three columns left
    tmp[3]  = block[15];
    tmp[7]  = block[3];
    tmp[11] = block[7];
    tmp[15] = block[11];
    
    memcpy(block, tmp, BLOCK_SIZE);
}

// reverses the shift rows operation during decryption.
// shifts rows right by row index instead of left.
void round_inv_shift_rows(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    
    // row 0: no shift
    tmp[0]  = block[0];
    tmp[4]  = block[4];
    tmp[8]  = block[8];
    tmp[12] = block[12];
    
    // row 1: shift right by 1 (reverse of left shift by 1)
    tmp[1]  = block[13];
    tmp[5]  = block[1];
    tmp[9]  = block[5];
    tmp[13] = block[9];
    
    // row 2: shift right by 2
    tmp[2]  = block[10];
    tmp[6]  = block[14];
    tmp[10] = block[2];
    tmp[14] = block[6];
    
    // row 3: shift right by 3 (equivalent to left shift by 1)
    tmp[3]  = block[7];
    tmp[7]  = block[11];
    tmp[11] = block[15];
    tmp[15] = block[3];
    
    memcpy(block, tmp, BLOCK_SIZE);
}

// forward mixcolumns: multiplies each column of the state by a fixed 4x4 matrix over gf(2^8).
// this provides diffusion within each column, spreading every input byte to all four output bytes.
// uses precomputed gf tables instead of runtime multiplication for performance.
static void mix_bytes(uint8_t *block) {
    init_gf_tables();  // ensure tables are ready (no-op after first call)
    
    // extract columns for clarity — block is column-major
    uint8_t a0 = block[0],  a1 = block[1],  a2 = block[2],  a3 = block[3];    // column 0
    uint8_t b0 = block[4],  b1 = block[5],  b2 = block[6],  b3 = block[7];    // column 1
    uint8_t c0 = block[8],  c1 = block[9],  c2 = block[10], c3 = block[11];   // column 2
    uint8_t d0 = block[12], d1 = block[13], d2 = block[14], d3 = block[15];   // column 3
    
    // matrix multiplication for column 0: [2 3 1 1] · [a0 a1 a2 a3]^T
    block[0]  = gf_mul2[a0] ^ gf_mul3[a1] ^ a2 ^ a3;
    block[1]  = a0 ^ gf_mul2[a1] ^ gf_mul3[a2] ^ a3;
    block[2]  = a0 ^ a1 ^ gf_mul2[a2] ^ gf_mul3[a3];
    block[3]  = gf_mul3[a0] ^ a1 ^ a2 ^ gf_mul2[a3];
    
    // column 1
    block[4]  = gf_mul2[b0] ^ gf_mul3[b1] ^ b2 ^ b3;
    block[5]  = b0 ^ gf_mul2[b1] ^ gf_mul3[b2] ^ b3;
    block[6]  = b0 ^ b1 ^ gf_mul2[b2] ^ gf_mul3[b3];
    block[7]  = gf_mul3[b0] ^ b1 ^ b2 ^ gf_mul2[b3];
    
    // column 2
    block[8]  = gf_mul2[c0] ^ gf_mul3[c1] ^ c2 ^ c3;
    block[9]  = c0 ^ gf_mul2[c1] ^ gf_mul3[c2] ^ c3;
    block[10] = c0 ^ c1 ^ gf_mul2[c2] ^ gf_mul3[c3];
    block[11] = gf_mul3[c0] ^ c1 ^ c2 ^ gf_mul2[c3];
    
    // column 3
    block[12] = gf_mul2[d0] ^ gf_mul3[d1] ^ d2 ^ d3;
    block[13] = d0 ^ gf_mul2[d1] ^ gf_mul3[d2] ^ d3;
    block[14] = d0 ^ d1 ^ gf_mul2[d2] ^ gf_mul3[d3];
    block[15] = gf_mul3[d0] ^ d1 ^ d2 ^ gf_mul2[d3];
}

// inverse mixcolumns: multiplies each column by the inverse matrix [14 11 13 9].
// reverses the diffusion applied by forward mixcolumns during decryption.
static void inv_mix_bytes(uint8_t *block) {
    init_gf_tables();
    
    uint8_t a0 = block[0],  a1 = block[1],  a2 = block[2],  a3 = block[3];
    uint8_t b0 = block[4],  b1 = block[5],  b2 = block[6],  b3 = block[7];
    uint8_t c0 = block[8],  c1 = block[9],  c2 = block[10], c3 = block[11];
    uint8_t d0 = block[12], d1 = block[13], d2 = block[14], d3 = block[15];
    
    // inverse matrix multiplication for column 0: [14 11 13 9] · [a0 a1 a2 a3]^T
    block[0]  = gf_mul14[a0] ^ gf_mul11[a1] ^ gf_mul13[a2] ^ gf_mul9[a3];
    block[1]  = gf_mul9[a0]  ^ gf_mul14[a1] ^ gf_mul11[a2] ^ gf_mul13[a3];
    block[2]  = gf_mul13[a0] ^ gf_mul9[a1]  ^ gf_mul14[a2] ^ gf_mul11[a3];
    block[3]  = gf_mul11[a0] ^ gf_mul13[a1] ^ gf_mul9[a2]  ^ gf_mul14[a3];
    
    // column 1
    block[4]  = gf_mul14[b0] ^ gf_mul11[b1] ^ gf_mul13[b2] ^ gf_mul9[b3];
    block[5]  = gf_mul9[b0]  ^ gf_mul14[b1] ^ gf_mul11[b2] ^ gf_mul13[b3];
    block[6]  = gf_mul13[b0] ^ gf_mul9[b1]  ^ gf_mul14[b2] ^ gf_mul11[b3];
    block[7]  = gf_mul11[b0] ^ gf_mul13[b1] ^ gf_mul9[b2]  ^ gf_mul14[b3];
    
    // column 2
    block[8]  = gf_mul14[c0] ^ gf_mul11[c1] ^ gf_mul13[c2] ^ gf_mul9[c3];
    block[9]  = gf_mul9[c0]  ^ gf_mul14[c1] ^ gf_mul11[c2] ^ gf_mul13[c3];
    block[10] = gf_mul13[c0] ^ gf_mul9[c1]  ^ gf_mul14[c2] ^ gf_mul11[c3];
    block[11] = gf_mul11[c0] ^ gf_mul13[c1] ^ gf_mul9[c2]  ^ gf_mul14[c3];
    
    // column 3
    block[12] = gf_mul14[d0] ^ gf_mul11[d1] ^ gf_mul13[d2] ^ gf_mul9[d3];
    block[13] = gf_mul9[d0]  ^ gf_mul14[d1] ^ gf_mul11[d2] ^ gf_mul13[d3];
    block[14] = gf_mul13[d0] ^ gf_mul9[d1]  ^ gf_mul14[d2] ^ gf_mul11[d3];
    block[15] = gf_mul11[d0] ^ gf_mul13[d1] ^ gf_mul9[d2]  ^ gf_mul14[d3];
}

// public wrapper for forward mixcolumns.
// separated from the static implementation for clarity in the calling code.
void round_mix(uint8_t *block) {
    mix_bytes(block);
}

// public wrapper for inverse mixcolumns.
void round_inv_mix(uint8_t *block) {
    inv_mix_bytes(block);
}