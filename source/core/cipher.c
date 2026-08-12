// source/core/cipher.c
// Implementation of Cipher for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <string.h>
#include <stdlib.h>
#include "cipher.h"
#include "sbox.h"
#include "keygen.h"
#include "cipher_ops.h"

// chunk size for streaming file i/o: 64 kb.
// balances memory usage against system call overhead.
// larger chunks mean fewer fread/fwrite calls but more stack/heap memory per operation.
#define STREAM_CHUNK 65536

// encrypts a file using aes-256-cbc with encrypt-then-mac authentication.
//
// file format (written to output):
//   [8 bytes]  original file size (big-endian uint64) — needed for padding removal
//   [16 bytes] kdf salt — random, unique per encryption
//   [16 bytes] iv — random initialization vector for cbc mode
//   [n bytes]  encrypted data (pkcs#7 padded to block boundary)
//   [32 bytes] hmac-sha256 — authenticates header + ciphertext
//
// the mac covers everything before it: size, salt, iv, and ciphertext.
// this is encrypt-then-mac: verify authenticity before attempting decryption.

int cipher_encrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total)) {
    
    // open input file and determine its size.
    FILE *input = fopen(input_path, "rb");
    if (!input) return -1;
    
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);
    
    if (file_size <= 0) { fclose(input); return -1; }
    
    FILE *output = fopen(output_path, "wb");
    if (!output) { fclose(input); return -1; }
    
    // initialize s-box tables — safe to call multiple times (no-op after first).
    sbox_init();
    
    // store original file size as 8-byte big-endian integer in the header.
    // this is needed during decryption to know how many padding bytes to remove,
    // and it's authenticated by the hmac to prevent truncation attacks.
    uint64_t original_size = (uint64_t)file_size;
    uint8_t size_bytes[8];
    for (int i = 0; i < 8; i++) {
        size_bytes[i] = (uint8_t)(original_size >> (56 - i * 8));
    }

    if (fwrite(size_bytes, 1, sizeof(size_bytes), output) != sizeof(size_bytes)) {
        fclose(input);
        fclose(output);
        return -1;
    }

    // generate random kdf salt and write it to the header.
    // unique salt per encryption ensures identical keys produce different derived keys.
    uint8_t salt[KDF_SALT_SIZE];
    keygen_generate_iv(salt);
    
    if (fwrite(salt, 1, KDF_SALT_SIZE, output) != KDF_SALT_SIZE) {
        fclose(input);
        fclose(output);
        return -1;
    }
    
    // initialize cipher context: derive encryption and mac keys from master key + salt.
    // uses pbkdf2 with separate domain separation tags for enc and mac keys.
    CipherContext ctx;
    if (cipher_ctx_init_encrypt(&ctx, key, key_len, salt) != 0) {
        fclose(input);
        fclose(output);
        return -1;
    }
    
    // generate random iv for cbc mode and write it to the header.
    // random iv per encryption ensures identical plaintexts produce different ciphertexts,
    // even with the same key and salt.
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);

    if (fwrite(iv, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    
    // allocate buffer for the complete ciphertext in memory.
    // size = file_size + one extra block for pkcs#7 padding.
    // we store full ciphertext so we can compute hmac over it after encryption.
    size_t encrypted_capacity = (size_t)file_size + BLOCK_SIZE;
    uint8_t *encrypted_data = (uint8_t*)malloc(encrypted_capacity);
    if (!encrypted_data) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    size_t encrypted_len = 0;
    
    // cbc mode: each plaintext block is xored with the previous ciphertext block
    // before encryption. the iv serves as the "previous block" for the first block.
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    // streaming read buffer: reads input in chunks to avoid loading huge files into memory.
    uint8_t *buffer = (uint8_t*)malloc(STREAM_CHUNK);
    if (!buffer) { 
        cipher_ctx_cleanup(&ctx);
        free(encrypted_data);
        fclose(input); fclose(output); return -1; 
    }
    
    size_t total_read = 0;
    size_t bytes_read;
    
    // pending block buffer: handles partial blocks when stream chunks aren't aligned
    // to the 16-byte block boundary. accumulates bytes until a full block is ready.
    uint8_t pending_block[BLOCK_SIZE];
    size_t pending_len = 0;
    
    // main encryption loop: read stream chunks, encrypt full blocks, buffer partial blocks.
    while ((bytes_read = fread(buffer, 1, STREAM_CHUNK, input)) > 0) {
        total_read += bytes_read;
        size_t processed = 0;
        
        // first, try to complete a pending partial block from the previous iteration.
        if (pending_len > 0) {
            size_t to_copy = BLOCK_SIZE - pending_len;
            if (to_copy > bytes_read) to_copy = bytes_read;
            memcpy(pending_block + pending_len, buffer, to_copy);
            pending_len += to_copy;
            processed += to_copy;
            
            // if the pending block is now full, encrypt and write it.
            if (pending_len == BLOCK_SIZE) {
                cipher_cbc_encrypt_block(pending_block, prev, &ctx);
                memcpy(encrypted_data + encrypted_len, pending_block, BLOCK_SIZE);
                encrypted_len += BLOCK_SIZE;
                
                if (fwrite(pending_block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                    cipher_ctx_cleanup(&ctx);
                    free(encrypted_data);
                    free(buffer);
                    fclose(input);
                    fclose(output);
                    return -1;
                }
                pending_len = 0;
            }
        }
        
        // encrypt all complete 16-byte blocks remaining in the current chunk.
        while (processed + BLOCK_SIZE <= bytes_read) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, buffer + processed, BLOCK_SIZE);
            
            cipher_cbc_encrypt_block(block, prev, &ctx);
            memcpy(encrypted_data + encrypted_len, block, BLOCK_SIZE);
            encrypted_len += BLOCK_SIZE;
            
            if (fwrite(block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                cipher_ctx_cleanup(&ctx);
                free(encrypted_data);
                free(buffer);
                fclose(input);
                fclose(output);
                return -1;
            }
            processed += BLOCK_SIZE;
        }
        
        // save any leftover bytes as a pending partial block for the next iteration.
        if (processed < bytes_read) {
            size_t remaining = bytes_read - processed;
            memcpy(pending_block, buffer + processed, remaining);
            pending_len = remaining;
        }
        
        if (progress) progress(total_read, (size_t)file_size);
    }
    
    // handle the final partial block: apply pkcs#7 padding to fill a full block.
    // padding value = number of padding bytes added (e.g., 0x05 means 5 bytes of padding).
    uint8_t final_block[BLOCK_SIZE];
    memcpy(final_block, pending_block, pending_len);
    cipher_add_pkcs7_padding(final_block, pending_len, BLOCK_SIZE);
    
    // encrypt and write the padded final block.
    cipher_cbc_encrypt_block(final_block, prev, &ctx);
    memcpy(encrypted_data + encrypted_len, final_block, BLOCK_SIZE);
    encrypted_len += BLOCK_SIZE;

    if (fwrite(final_block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        cipher_secure_zero(prev, sizeof(prev));
        cipher_secure_zero(pending_block, sizeof(pending_block));
        free(encrypted_data);
        free(buffer);
        fclose(input);
        fclose(output);
        return -1;
    }
    
    // compute hmac over header + complete ciphertext for integrity verification.
    // header = size_bytes (8) + salt (16) + iv (16) = 40 bytes.
    // this authenticates the original file size, salt, iv, and all ciphertext.
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + encrypted_len;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (hmac_data) {
        memcpy(hmac_data, size_bytes, 8);
        memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
        memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
        memcpy(hmac_data + header_size, encrypted_data, encrypted_len);
        
        uint8_t mac[HMAC_SIZE];
        hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, mac);
        
        // write the 32-byte hmac as the final part of the file.
        fwrite(mac, 1, HMAC_SIZE, output);
        
        // wipe hmac data buffer — contains complete plaintext-derived ciphertext copy.
        cipher_secure_zero(hmac_data, hmac_data_size);
        free(hmac_data);
    }
    
    // cleanup: securely wipe all key material and sensitive intermediate state.
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    cipher_secure_zero(pending_block, sizeof(pending_block));
    cipher_secure_zero(final_block, sizeof(final_block));
    free(encrypted_data);
    free(buffer);
    fclose(input);
    fclose(output);
    return 0;
}

// decrypts a file encrypted by cipher_encrypt_file.
// performs hmac verification before decryption (encrypt-then-mac).
// all failure modes return -1 — no distinction between wrong key, corruption,
// or i/o errors. this prevents attackers from using return codes as oracles.
int cipher_decrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total)) {
    
    FILE *input = fopen(input_path, "rb");
    if (!input) return -1;
    
    // read and reconstruct original file size from the header.
    uint8_t size_bytes[8];
    if (fread(size_bytes, 1, sizeof(size_bytes), input) != sizeof(size_bytes)) {
        fclose(input);
        return -1;
    }
    uint64_t original_size = 0;
    for (int i = 0; i < 8; i++) {
        original_size = (original_size << 8) | size_bytes[i];
    }
    
    // read kdf salt from header.
    uint8_t salt[KDF_SALT_SIZE];
    if (fread(salt, 1, KDF_SALT_SIZE, input) != KDF_SALT_SIZE) {
        fclose(input);
        return -1;
    }
    
    // initialize cipher context with the same salt used during encryption.
    // this re-derives the identical encryption and mac keys from the master key.
    CipherContext ctx;
    if (cipher_ctx_init_decrypt(&ctx, key, key_len, salt) != 0) {
        fclose(input);
        return -1;
    }
    
    // read iv from header.
    uint8_t iv[BLOCK_SIZE];
    if (fread(iv, 1, BLOCK_SIZE, input) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        return -1;
    }
    
    // determine encrypted data size: total file minus header minus hmac.
    fseek(input, 0, SEEK_END);
    long total_size = ftell(input);
    long encrypted_size = total_size - sizeof(uint64_t) - KDF_SALT_SIZE - BLOCK_SIZE - HMAC_SIZE;
    
    // validate encrypted size: must be positive and block-aligned (pkcs#7 padded).
    if (encrypted_size <= 0 || encrypted_size % BLOCK_SIZE != 0) {
        cipher_ctx_cleanup(&ctx);
        fclose(input); 
        return -1; 
    }
    
    // read the stored hmac from the end of the file.
    uint8_t stored_mac[HMAC_SIZE];
    fseek(input, -(long)HMAC_SIZE, SEEK_END);
    if (fread(stored_mac, 1, HMAC_SIZE, input) != HMAC_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input); 
        return -1; 
    }
    
    // seek back to the beginning of ciphertext for reading and hmac verification.
    fseek(input, sizeof(uint64_t) + KDF_SALT_SIZE + BLOCK_SIZE, SEEK_SET);
    
    // streaming buffer for reading ciphertext chunks.
    uint8_t *chunk_buf = (uint8_t*)malloc(STREAM_CHUNK);
    if (!chunk_buf) { 
        cipher_ctx_cleanup(&ctx);
        fclose(input); return -1; 
    }
    
    // build the hmac verification data: header + ciphertext (same as during encryption).
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + (size_t)encrypted_size;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (!hmac_data) {
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf);
        fclose(input);
        return -1;
    }
    
    // copy header fields into the hmac verification buffer.
    memcpy(hmac_data, size_bytes, 8);
    memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
    memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
    
    // read ciphertext into hmac buffer in streaming chunks.
    size_t offset = header_size;
    long remaining = encrypted_size;
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        size_t read_now = fread(chunk_buf, 1, to_read, input);
        if (read_now == 0) break;
        memcpy(hmac_data + offset, chunk_buf, read_now);
        offset += read_now;
        remaining -= read_now;
    }
    
    // compute hmac over header + ciphertext and compare with stored mac.
    // uses constant-time comparison to prevent timing side-channel attacks.
    uint8_t computed_mac[HMAC_SIZE];
    hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, computed_mac);
    
    cipher_secure_zero(hmac_data, hmac_data_size);
    free(hmac_data);
    
    // verify mac before any decryption — prevents padding oracle and chosen-ciphertext attacks.
    // returns -1 (same as all other errors) to prevent distinguishing auth failure from other errors.
    if (cipher_ct_memcmp(computed_mac, stored_mac, HMAC_SIZE) != 0) {
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf);
        fclose(input);
        return -1;
    }
    
    // mac verified — begin decryption.
    FILE *output = fopen(output_path, "wb");
    if (!output) { 
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf); 
        fclose(input); 
        return -1; 
    }
    
    sbox_init();
    
    // initialize cbc chain with the iv from the header.
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    // seek back to ciphertext start for decryption pass.
    fseek(input, sizeof(uint64_t) + KDF_SALT_SIZE + BLOCK_SIZE, SEEK_SET);
    
    size_t total_written = 0;
    
    // decrypt all blocks except the last one (which contains padding).
    // the last block needs special handling to remove pkcs#7 padding.
    remaining = encrypted_size - BLOCK_SIZE;
    
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        size_t read_bytes = fread(chunk_buf, 1, to_read, input);
        if (read_bytes == 0) break;
        
        // decrypt each full 16-byte block in the chunk.
        for (size_t i = 0; i < read_bytes; i += BLOCK_SIZE) {
            if (i + BLOCK_SIZE > read_bytes) break;
            
            uint8_t decrypted[BLOCK_SIZE];
            cipher_cbc_decrypt_block(chunk_buf + i, decrypted, prev, &ctx);
            
            if (fwrite(decrypted, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                cipher_ctx_cleanup(&ctx);
                free(chunk_buf);
                fclose(input);
                fclose(output);
                return -1;
            }
            total_written += BLOCK_SIZE;
        }
        remaining -= read_bytes;
        if (progress) progress(total_written, original_size);
    }
    
    // decrypt the final block and remove pkcs#7 padding.
    uint8_t last_encrypted[BLOCK_SIZE];
    uint8_t last_decrypted[BLOCK_SIZE];
    if (fread(last_encrypted, 1, BLOCK_SIZE, input) == BLOCK_SIZE) {
        cipher_cbc_decrypt_block(last_encrypted, last_decrypted, prev, &ctx);
        
        size_t unpadded_len;
        if (cipher_remove_pkcs7_padding(last_decrypted, BLOCK_SIZE, &unpadded_len) != 0) {
            // padding validation failed — likely corrupted or tampered data.
            // return -1 same as all other errors to prevent oracle.
            cipher_ctx_cleanup(&ctx);
            free(chunk_buf);
            fclose(input);
            fclose(output);
            return -1;
        }
        
        // write only the actual data bytes (without padding) to match original file size.
        if (unpadded_len > 0) {
            // clamp to original_size to prevent any possibility of writing beyond expected length.
            size_t remaining_to_write = original_size - total_written;
            if (unpadded_len > remaining_to_write) unpadded_len = remaining_to_write;
            
            if (fwrite(last_decrypted, 1, unpadded_len, output) != unpadded_len) {
                cipher_ctx_cleanup(&ctx);
                free(chunk_buf);
                fclose(input);
                fclose(output);
                return -1;
            }
            total_written += unpadded_len;
        }
    }
    
    if (progress) progress(total_written, original_size);
    
    // final cleanup: wipe all sensitive material from memory.
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    cipher_secure_zero(last_encrypted, sizeof(last_encrypted));
    cipher_secure_zero(last_decrypted, sizeof(last_decrypted));
    free(chunk_buf);
    fclose(input);
    fclose(output);
    
    return 0;
}