// source/core/keygen.c
// Implementation of Key Generation for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "keygen.h"
#include "hmac.h"
#include "cipher_ops.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

#ifdef __linux__
#include <sys/random.h>
#include <errno.h>
#endif

// round constants for aes-256 key expansion.
// each constant is x^(round-1) in gf(2^8) modulo the aes polynomial.
// rcon[0] is unused padding; expansion starts at rcon[1].
static const uint8_t Rcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D
};

// substitutes each byte of a 32-bit word using the s-box.
// used in the key expansion g-function to add non-linearity to round keys.
static uint32_t SubWord(uint32_t word) {
    return ((uint32_t)SBOX[(word >> 24) & 0xFF] << 24) |
           ((uint32_t)SBOX[(word >> 16) & 0xFF] << 16) |
           ((uint32_t)SBOX[(word >> 8)  & 0xFF] << 8)  |
           ((uint32_t)SBOX[word & 0xFF]);
}

// rotates a 32-bit word left by 8 bits (bytewise rotation).
// used in the key expansion g-function to mix bytes across word boundaries.
static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// fills a buffer with cryptographically secure random bytes from the os.
// platform-specific implementations chosen for maximum entropy quality:
// windows: bcryptgenrandom (kernel-mode rng), linux: getrandom() (kernel entropy pool),
// fallback: /dev/urandom, macos/bsd: arc4random_buf.
static int secure_random(uint8_t *buf, size_t len) {
#ifdef _WIN32
    // bcryptgenrandom with system-preferred rng — direct kernel entropy, no userspace prng.
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;

#elif defined(__linux__)
    // getrandom() reads directly from kernel entropy pool, blocks only if insufficient entropy.
    ssize_t result = getrandom(buf, len, 0);
    if (result == (ssize_t)len) return 0;
    
    // if getrandom returned partial data (rare on modern kernels), top up from /dev/urandom.
    if (result > 0) {
        size_t bytes_read = (size_t)result;
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) return -1;
        while (bytes_read < len) {
            size_t r = fread(buf + bytes_read, 1, len - bytes_read, f);
            if (r == 0) { fclose(f); return -1; }
            bytes_read += r;
        }
        fclose(f);
        return 0;
    }
    
    // getrandom() failed entirely — fall back to /dev/urandom (older kernels).
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t bytes_read = 0;
    while (bytes_read < len) {
        size_t r = fread(buf + bytes_read, 1, len - bytes_read, f);
        if (r == 0) { fclose(f); return -1; }
        bytes_read += r;
    }
    fclose(f);
    return 0;

#else
    // macos, openbsd, freebsd: arc4random_buf is the standard csprng, seeded from kernel entropy.
    arc4random_buf(buf, len);
    return 0;
#endif
}

// expands the master key into 15 round keys (one initial whitening + 14 rounds).
// for aes-256: nk=8 (256-bit key), nr=14 rounds.
// keys shorter than 32 bytes are expanded to full strength via hmac before schedule generation.
void keygen_expand(const uint8_t *master_key, size_t key_len,
                   uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    
    uint8_t key256[32];
    
    // if key is already 32 bytes or longer, use directly (truncating to 32 if longer).
    // this preserves full entropy for properly-sized keys.
    if (key_len >= 32) {
        memcpy(key256, master_key, 32);
    } else {
        // short keys (<32 bytes) are expanded to 32 bytes via hmac with a fixed salt.
        // this prevents weak-key attacks from short user passwords while maintaining determinism.
        // the fixed salt ensures the same short key always produces the same expanded key.
        uint8_t salt[] = "apex-key-expansion-salt-v1";
        hmac_compute(master_key, key_len, salt, sizeof(salt) - 1, key256);
    }
    
    // word array for the key schedule: nb*(nr+1) = 4*15 = 60 words for aes-256.
    uint32_t W[NB * (NR + 1)];
    uint32_t temp;
    
    // copy the 256-bit (32-byte) cipher key into the first 8 words (nk=8 for aes-256).
    for (int i = 0; i < 8; i++) {
        W[i] = ((uint32_t)key256[4*i]   << 24) |
               ((uint32_t)key256[4*i+1] << 16) |
               ((uint32_t)key256[4*i+2] << 8)  |
               ((uint32_t)key256[4*i+3]);
    }
    
    // generate remaining words (w[8] through w[59]).
    // for aes-256, the schedule applies extra non-linearity every 8 words (nk=8),
    // with subword alone applied every 4 words in between.
    for (int i = 8; i < NB * (NR + 1); i++) {
        temp = W[i - 1];
        
        if (i % 8 == 0) {
            // every 8th word: full g-function — rotate, substitute, xor with rcon.
            temp = SubWord(RotWord(temp)) ^ ((uint32_t)Rcon[i/8] << 24);
        } else if (i % 8 == 4) {
            // every 4th word (between full g-functions): substitute only.
            // this is specific to aes-256 and provides additional non-linearity.
            temp = SubWord(temp);
        }
        
        // xor with the word 8 positions back (nk=8 for 256-bit key).
        W[i] = W[i - 8] ^ temp;
    }
    
    // unpack the word array into 15 round keys of 16 bytes each.
    // round_keys[0] = initial whitening key, round_keys[1..13] = round keys, round_keys[14] = final round key.
    for (int r = 0; r <= NR; r++) {
        for (int j = 0; j < 4; j++) {
            uint32_t word = W[r * 4 + j];
            round_keys[r][j*4]   = (uint8_t)(word >> 24);
            round_keys[r][j*4+1] = (uint8_t)(word >> 16);
            round_keys[r][j*4+2] = (uint8_t)(word >> 8);
            round_keys[r][j*4+3] = (uint8_t)(word);
        }
    }
    
    // securely wipe the expanded key schedule from the stack.
    // volatile pointer prevents compiler from optimizing away the zeroing.
    volatile uint32_t *vp = W;
    for (int i = 0; i < NB * (NR + 1); i++) vp[i] = 0;
    
    // wipe the temporary 256-bit key buffer — it may contain hmac-derived material.
    cipher_secure_zero(key256, sizeof(key256));
}

// generates a cryptographically random initialization vector (16 bytes).
// fresh iv per encryption ensures identical plaintexts produce different ciphertexts.
void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]) {
    if (secure_random(iv, BLOCK_SIZE) != 0) {
        // if random generation fails, the system is critically compromised — abort loudly.
        fprintf(stderr, "Failed to generate secure IV\n");
        abort();
    }
}

// generates a cryptographically random key of the requested length.
// used for the default random key when no user key is provided.
void keygen_random_key(uint8_t *key, size_t len) {
    if (secure_random(key, len) != 0) {
        fprintf(stderr, "Failed to generate secure key\n");
        abort();
    }
}