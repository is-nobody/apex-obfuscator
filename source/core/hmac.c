// source/core/hmac.c
// Implementation of HMAC for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "hmac.h"
#include "hash.h"
#include <string.h>

// hmac-sha256 implementation (rfc 2104).
// computes a keyed-hash message authentication code for integrity and authenticity verification.
// hmac = h((key xor opad) || h((key xor ipad) || message))
//
// used in encrypt-then-mac: the mac covers ciphertext + header, so any tampering
// or corruption is detected before decryption is attempted.
void hmac_compute(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SIZE]) {
    
    // working buffers for the key padded to block size.
    // both ipad and opad are derived from the block-sized key.
    uint8_t key_block[HMAC_BLOCK_SIZE];  // normalized key (hashed if too long, padded if too short)
    uint8_t ipad[HMAC_BLOCK_SIZE];       // key xor 0x36 (inner padding constant)
    uint8_t opad[HMAC_BLOCK_SIZE];       // key xor 0x5c (outer padding constant)
    
    HASH_CTX ctx;
    uint8_t inner_hash[HASH_DIGEST_SIZE]; // h((key xor ipad) || message)
    
    // step 1: normalize the key to exactly block size bytes.
    // if key is longer than block size, hash it first to reduce length.
    // if key is shorter, pad with zeros on the right.
    if (key_len > HMAC_BLOCK_SIZE) {
        // hash long keys to fit within a single hash block.
        // this preserves full key entropy while meeting the block size constraint.
        hash_init(&ctx);
        hash_update(&ctx, key, key_len);
        hash_final(&ctx, key_block);
        
        // zero the remaining bytes after the hash digest.
        memset(key_block + HASH_DIGEST_SIZE, 0, HMAC_BLOCK_SIZE - HASH_DIGEST_SIZE);
    } else {
        // copy key and zero-pad to block size.
        memcpy(key_block, key, key_len);
        if (key_len < HMAC_BLOCK_SIZE) {
            memset(key_block + key_len, 0, HMAC_BLOCK_SIZE - key_len);
        }
    }
    
    // step 2: create inner and outer padded keys.
    // ipad = key xor 0x36, opad = key xor 0x5c.
    // the constants 0x36 and 0x5c are chosen to have maximum hamming distance,
    // making ipad and opad as different as possible for security.
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    
    // step 3: compute inner hash = h(ipad || message).
    hash_init(&ctx);
    hash_update(&ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&ctx, data, data_len);
    hash_final(&ctx, inner_hash);
    
    // step 4: compute outer hash = h(opad || inner_hash).
    hash_init(&ctx);
    hash_update(&ctx, opad, HMAC_BLOCK_SIZE);
    hash_update(&ctx, inner_hash, HASH_DIGEST_SIZE);
    hash_final(&ctx, digest);
}