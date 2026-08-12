// source/core/cipher_ops.h
// Implementation of Cipher Operations for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef CIPHER_OPS_H
#define CIPHER_OPS_H

#include <stdint.h>
#include <stddef.h>
#include "sbox.h"
#include "keygen.h"
#include "kdf.h"
#include "hmac.h"
#include "hash.h"

// cipher context: holds all key material needed for encryption/decryption of a single file.
// created once per file operation and securely wiped after use.
// contains two independently derived keys (encryption and mac) plus pre-expanded round keys.
typedef struct {
    uint8_t enc_key[KDF_DERIVED_KEY_SIZE];            // derived encryption key (32 bytes)
    uint8_t mac_key[KDF_DERIVED_KEY_SIZE];            // derived mac key (32 bytes)
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];       // pre-expanded aes-256 round keys (15 × 16 bytes)
} CipherContext;

// initializes a cipher context for encryption.
// derives enc_key and mac_key from master_key using pbkdf2 with domain-separated salts,
// then expands enc_key into round_keys for aes-256.
// returns 0 on success, -1 on kdf failure.
int cipher_ctx_init_encrypt(CipherContext *ctx, 
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt);

// initializes a cipher context for decryption.
// identical to encryption initialization — aes uses the same round keys for both directions.
int cipher_ctx_init_decrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt);

// encrypts one block in cbc mode: plaintext xor prev, aes encrypt, update prev.
// prev must start as the iv and is updated to the ciphertext after each call.
void cipher_cbc_encrypt_block(uint8_t *block,
                              uint8_t *prev,
                              CipherContext *ctx);

// decrypts one block in cbc mode: aes decrypt, xor prev, update prev.
// encrypted_block and decrypted_block may point to the same buffer.
void cipher_cbc_decrypt_block(const uint8_t *encrypted_block,
                              uint8_t *decrypted_block,
                              uint8_t *prev,
                              CipherContext *ctx);

// applies pkcs#7 padding: fills remaining bytes with the padding byte count value.
// used on the final partial block before encryption so all blocks are full size.
void cipher_add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size);

// validates and removes pkcs#7 padding from the final decrypted block.
// returns 0 with valid padding removed, -1 if padding is malformed.
// malformed padding is treated as an authentication failure.
int cipher_remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len);

// constant-time memory comparison: returns 0 if a and b are identical.
// always processes all len bytes to prevent timing side-channel attacks.
// used for mac verification where timing leaks could enable forgery.
int cipher_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

// securely zeros a memory region using a volatile pointer to prevent
// compiler optimization from eliminating the write.
// used for wiping keys, ivs, and intermediate state from memory.
void cipher_secure_zero(void *ptr, size_t len);

// securely wipes all key material from the cipher context.
// call after encryption/decryption is complete to minimize key exposure in memory.
void cipher_ctx_cleanup(CipherContext *ctx);

#endif