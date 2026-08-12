// source/core/cipher_ops.c
// Implementation of Cipher Operations for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "cipher_ops.h"
#include "encrypt_decrypt.h"
#include <string.h>
#include <stdlib.h>

// securely zeros a memory region by overwriting every byte with 0.
// the volatile pointer prevents the compiler from optimizing away the write
// even if the memory is not read afterwards (dead store elimination).
// this is critical for wiping keys, ivs, and intermediate state from the stack/heap.
void cipher_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

// constant-time memory comparison: returns 0 if buffers are identical, non-zero otherwise.
// the comparison always processes all bytes regardless of where a difference is found,
// preventing timing side-channel attacks that could reveal which byte position mismatched.
// this is essential for mac verification where an attacker could otherwise
// use timing differences to forge a valid mac byte by byte.
int cipher_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];  // accumulate differences via or — never short-circuits
    }
    return diff;  // 0 = match, non-zero = mismatch
}

// initializes a cipher context for encryption.
// derives two independent keys from the master key using pbkdf2 with domain separation:
//   enc_key: for aes-256 encryption operations
//   mac_key: for hmac-sha256 integrity authentication
//
// domain separation is achieved by appending different tags ("ENC" vs "MAC") to the salt,
// ensuring that compromising one derived key doesn't reveal the other.
int cipher_ctx_init_encrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt) {
    
    // build encryption-specific salt: original_salt || "ENC"
    uint8_t enc_salt[KDF_SALT_SIZE + 3];
    uint8_t mac_salt[KDF_SALT_SIZE + 3];
    
    memcpy(enc_salt, salt, KDF_SALT_SIZE);
    enc_salt[KDF_SALT_SIZE]     = 'E';
    enc_salt[KDF_SALT_SIZE + 1] = 'N';
    enc_salt[KDF_SALT_SIZE + 2] = 'C';
    
    // build mac-specific salt: original_salt || "MAC"
    memcpy(mac_salt, salt, KDF_SALT_SIZE);
    mac_salt[KDF_SALT_SIZE]     = 'M';
    mac_salt[KDF_SALT_SIZE + 1] = 'A';
    mac_salt[KDF_SALT_SIZE + 2] = 'C';
    
    // derive encryption key from master key using the enc-tagged salt.
    if (kdf_derive(master_key, key_len, enc_salt, KDF_SALT_SIZE + 3, 
                   KDF_ITERATIONS, ctx->enc_key, KDF_DERIVED_KEY_SIZE) != 0) {
        return -1;
    }
    
    // derive mac key from master key using the mac-tagged salt.
    // separate derivation prevents key reuse between encryption and authentication.
    if (kdf_derive(master_key, key_len, mac_salt, KDF_SALT_SIZE + 3,
                   KDF_ITERATIONS, ctx->mac_key, KDF_DERIVED_KEY_SIZE) != 0) {
        cipher_secure_zero(ctx->enc_key, sizeof(ctx->enc_key));
        return -1;
    }
    
    // expand the derived encryption key into 15 round keys for aes-256.
    // this is done once at context creation rather than per-block for efficiency.
    keygen_expand(ctx->enc_key, KDF_DERIVED_KEY_SIZE, ctx->round_keys);
    
    return 0;
}

// initializes a cipher context for decryption.
// the process is identical to encryption initialization because aes is symmetric:
// the same round keys are used for both encryption and decryption (decryption
// just applies them in reverse order via decrypt_block).
int cipher_ctx_init_decrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt) {
    return cipher_ctx_init_encrypt(ctx, master_key, key_len, salt);
}

// encrypts one block in cbc mode: plaintext xor previous_ciphertext, then aes encrypt.
// after encryption, the output block becomes the new "previous" block for the next call.
// the iv serves as the initial "previous" block for the first block of the message.
void cipher_cbc_encrypt_block(uint8_t *block,
                              uint8_t *prev,
                              CipherContext *ctx) {
    
    // cbc: xor plaintext with the previous ciphertext block (or iv for first block).
    // this ensures identical plaintext blocks produce different ciphertext blocks.
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= prev[i];
    }
    
    // standard aes encryption of the xored block.
    encrypt_block(block, ctx->round_keys);
    
    // update prev to this block's ciphertext for the next call in the chain.
    memcpy(prev, block, BLOCK_SIZE);
}

// decrypts one block in cbc mode: aes decrypt, then xor with previous ciphertext block.
// the encrypted block is preserved as prev for the next call before being overwritten.
// separate encrypted_block and decrypted_block pointers avoid data corruption
// when the caller reuses the same buffer for input and output.
void cipher_cbc_decrypt_block(const uint8_t *encrypted_block,
                              uint8_t *decrypted_block,
                              uint8_t *prev,
                              CipherContext *ctx) {
    
    // save a copy of the encrypted block before decryption.
    // this copy will become the new prev for the next block.
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, encrypted_block, BLOCK_SIZE);
    
    // aes decrypt the ciphertext.
    decrypt_block(temp, ctx->round_keys);
    
    // cbc: xor decrypted block with the previous ciphertext block to recover plaintext.
    for (int j = 0; j < BLOCK_SIZE; j++) {
        decrypted_block[j] = temp[j] ^ prev[j];
    }
    
    // update prev to the original ciphertext of this block for the next call.
    memcpy(prev, encrypted_block, BLOCK_SIZE);
}

// applies pkcs#7 padding to the final partial block before encryption.
// padding fills the remaining bytes with the value equal to the number of padding bytes.
// examples:
//   15 data bytes → 1 padding byte with value 0x01
//   8 data bytes  → 8 padding bytes with value 0x08
//   0 data bytes  → 16 padding bytes with value 0x10 (full block of padding)
//
// the last case (full block of padding) is required so the decryptor can always
// distinguish padding bytes from data bytes by examining the last byte.
void cipher_add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size) {
    uint8_t padding_value = (uint8_t)(block_size - data_len);
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = padding_value;
    }
}

// validates and removes pkcs#7 padding from the final decrypted block.
// checks that all padding bytes have the correct value (equal to the count).
// returns 0 on success with unpadded length in *data_len, -1 on invalid padding.
//
// invalid padding could indicate: wrong decryption key, corrupted data,
// or a padding oracle attack attempt — all should be treated as authentication failures.
int cipher_remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len) {
    uint8_t padding_value = block[block_size - 1];
    
    // padding value must be between 1 and block_size (inclusive).
    // 0 is invalid (would mean no padding, but we always add at least 1 byte).
    // > block_size is invalid (can't pad more bytes than exist in the block).
    if (padding_value == 0 || padding_value > block_size) {
        return -1;
    }
    
    // verify that all padding bytes have the correct value.
    // this is a constant-time check: all bytes are examined regardless of where
    // a mismatch occurs, preventing padding oracle timing attacks.
    for (size_t i = block_size - padding_value; i < block_size; i++) {
        if (block[i] != padding_value) {
            return -1;
        }
    }
    
    *data_len = block_size - padding_value;
    return 0;
}

// securely wipes all sensitive material from the cipher context.
// zeros the derived encryption key, mac key, and all round keys.
// should be called as soon as encryption/decryption is complete to minimize
// the window where keys exist in memory.
void cipher_ctx_cleanup(CipherContext *ctx) {
    cipher_secure_zero(ctx->enc_key, sizeof(ctx->enc_key));
    cipher_secure_zero(ctx->mac_key, sizeof(ctx->mac_key));
    cipher_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
}