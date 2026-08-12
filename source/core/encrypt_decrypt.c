// source/core/encrypt_decrypt.c
// Implementation of Encrypt/Decrypt for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "encrypt_decrypt.h"
#include "round_ops.h"

// encrypts a single 16-byte block using the expanded round keys.
// follows the aes-256 structure: initial whitening, 13 full rounds, final round without mixcolumns.
//
// round_keys layout: 15 keys (index 0..14)
//   key[0]  = initial whitening key (xored before round 1)
//   key[1..13] = round keys for full rounds (sbox → shift → mix → xor)
//   key[14] = final round key (sbox → shift → xor, no mix)

void encrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    // initial whitening: xor with round key 0 before the first round.
    // this prevents an attacker from skipping the first round by starting with known plaintext.
    round_xor_with_key(block, round_keys[0]);
    
    // rounds 1 through 13: full rounds with mixcolumns for diffusion.
    // each round applies all four aes operations in order.
    for (int r = 1; r < ROUNDS; r++) {
        round_apply_sbox(block);                   // subbytes: non-linear substitution
        round_shift_rows(block);                   // shiftrows: cross-column diffusion
        round_mix(block);                          // mixcolumns: intra-column diffusion
        round_xor_with_key(block, round_keys[r]);  // addroundkey: key material mixing
    }
    
    // round 14 (final round): omits mixcolumns.
    // mixcolumns is skipped because it adds computational cost without security benefit
    // in the final round — the cipher is already fully diffused.
    round_apply_sbox(block);
    round_shift_rows(block);
    round_xor_with_key(block, round_keys[ROUNDS]);
}

// decrypts a single 16-byte block using the expanded round keys.
// applies the inverse operations in reverse order to recover the original plaintext.
//
// decryption structure: inverse of encryption, with round keys applied in reverse order.
void decrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    // reverse the final round (round 14): xor, then invshiftrows, then invsubbytes.
    round_xor_with_key(block, round_keys[ROUNDS]);
    round_inv_shift_rows(block);
    round_apply_inv_sbox(block);
    
    // rounds 13 down to 1: full inverse rounds with invmixcolumns.
    // operations are the inverse of encryption, applied in reverse order.
    for (int r = ROUNDS - 1; r >= 1; r--) {
        round_xor_with_key(block, round_keys[r]);  // reverse addroundkey
        round_inv_mix(block);                      // reverse mixcolumns
        round_inv_shift_rows(block);               // reverse shiftrows
        round_apply_inv_sbox(block);               // reverse subbytes
    }
    
    // reverse the initial whitening: xor with round key 0.
    // this is the final step that recovers the original plaintext.
    round_xor_with_key(block, round_keys[0]);
}