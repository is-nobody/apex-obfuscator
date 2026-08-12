// source/core/kdf.c
// Implementation of KDF for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include "kdf.h"
#include "hmac.h"
#include <string.h>

// pbkdf2-hmac-sha256 implementation (rfc 2898, section 5.2).
// derives a cryptographic key from a password and salt by repeatedly applying hmac.
// the iteration count makes brute-force attacks computationally expensive:
// each guess requires 100,000 hmac computations instead of just one.
int kdf_derive(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations,
                uint8_t *derived_key, size_t key_len) {
    
    // validate inputs — null pointers or zero-length key would cause undefined behavior.
    if (!password || !salt || !derived_key || key_len == 0) {
        return -1;
    }
    
    // buffer for the xor-accumulated block (t_i in the pbkdf2 spec).
    uint8_t block[HMAC_SIZE];
    
    // buffer for each iteration's hmac output (u_j in the spec).
    uint8_t u[HMAC_SIZE];
    
    // number of hmac-sized blocks needed to fill the requested key length.
    // ceil division: (key_len + hmac_size - 1) / hmac_size.
    uint32_t blocks_needed = (key_len + HMAC_SIZE - 1) / HMAC_SIZE;
    
    // generate each block t_1, t_2, ... t_n independently.
    for (uint32_t block_num = 1; block_num <= blocks_needed; block_num++) {
        // build the salt concatenated with the block index as a 32-bit big-endian integer.
        // this ensures each block gets unique input, preventing identical derived blocks.
        uint8_t salt_block[128];
        size_t salt_block_len = 0;
        
        memcpy(salt_block, salt, salt_len);
        salt_block_len += salt_len;
        
        // append block number in big-endian (rfc 2898 requirement).
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 24);
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 16);
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 8);
        salt_block[salt_block_len++] = (uint8_t)(block_num);
        
        // u_1 = hmac(password, salt || block_num).
        hmac_compute(password, password_len, salt_block, salt_block_len, u);
        
        // t_i = u_1 (starting accumulator).
        memcpy(block, u, HMAC_SIZE);
        
        // u_j = hmac(password, u_{j-1}) for j = 2..iterations.
        // t_i = u_1 xor u_2 xor ... xor u_iterations.
        // xor chain prevents any single iteration from dominating the result.
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_compute(password, password_len, u, HMAC_SIZE, u);
            
            // xor each byte of u into the accumulator.
            for (size_t j = 0; j < HMAC_SIZE; j++) {
                block[j] ^= u[j];
            }
        }
        
        // copy the derived block into the output key.
        // for the last block, only copy the remaining bytes needed (key_len may not be a multiple of hmac_size).
        size_t copy_len = (block_num == blocks_needed && key_len % HMAC_SIZE != 0) 
                          ? key_len % HMAC_SIZE 
                          : HMAC_SIZE;
        memcpy(derived_key + (block_num - 1) * HMAC_SIZE, block, copy_len);
    }
    
    return 0;
}