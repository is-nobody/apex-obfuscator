// source/core/cipher.h
// Implementation of Cipher for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// aes block size: 16 bytes (128 bits). all encryption/decryption operates on 16-byte blocks.
#define CIPHER_BLOCK_SIZE 16

// padding block size: same as cipher block size. used for pkcs#7 padding.
#define CIPHER_PADDING_BLOCK 16

// encrypts a file using aes-256-cbc with pbkdf2 key derivation and hmac-sha256 authentication.
//
// input_path: path to the plaintext file to encrypt.
// output_path: path where the encrypted file will be written (created or overwritten).
// key: master key material (may be a password of any length).
// key_len: length of the key in bytes.
// progress: optional callback for progress reporting (receives current/total bytes).
//           pass NULL if progress updates are not needed.
//
// returns 0 on success, -1 on i/o or memory error.
int cipher_encrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

// decrypts a file encrypted by cipher_encrypt_file.
// verifies hmac before decryption to detect tampering or wrong keys.
//
// input_path: path to the encrypted file.
// output_path: path where the decrypted file will be written.
// key: the same master key used during encryption.
// key_len: length of the key in bytes (must match encryption).
// progress: optional callback for progress reporting.
//
// returns 0 on success, -1 on any failure (wrong key, corrupted data, i/o error, etc.).
// all failures produce the same return code to prevent oracle attacks.
int cipher_decrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

#endif