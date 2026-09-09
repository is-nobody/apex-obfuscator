// source/shred/shred.c
// Implementation of Secure File Deletion for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shred.h"
#include "keygen.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define unlink _unlink
#define fileno _fileno
#endif

#ifdef __linux__
#include <unistd.h>
#endif

// chunk size for secure overwrite operations: 64 kb.
// matches the streaming buffer size used by the cipher module.
// larger chunks reduce system call overhead during multiple passes.
#define SHRED_CHUNK 65536

// dod 5220.22-m ece overwrite patterns for passes 1-6.
// pass 7 uses cryptographically secure random data.
// these patterns are designed to eliminate residual magnetic signatures
// from different encoding schemes on traditional hard drives.
static const uint8_t SHRED_PATTERNS[SHRED_PASSES - 1] = {
    0x55,  // alternating ones and zeros
    0xAA,  // complement of 0x55
    0x92,  // pseudorandom pattern
    0x49,  // complement of 0x92
    0x24,  // quarter pattern
    0x6D   // mixed pattern
};

// overwrites a file with a single pass of the specified byte pattern.
// seeks to beginning before each pass to ensure complete coverage.
// flushes and syncs to disk to ensure data reaches physical media.
// returns 0 on success, -1 on write or seek error.
static int overwrite_pattern(FILE *file, size_t file_size, uint8_t pattern) {
    
    // seek to beginning of file — critical for multiple passes.
    if (fseek(file, 0, SEEK_SET) != 0) {
        return -1;
    }
    
    // allocate buffer for efficient chunked writes.
    uint8_t *buffer = (uint8_t *)malloc(SHRED_CHUNK);
    if (!buffer) return -1;
    
    // pre-fill the buffer with the pattern once, then reuse.
    memset(buffer, pattern, SHRED_CHUNK);
    
    size_t remaining = file_size;
    
    // write pattern in chunks until entire file is overwritten.
    while (remaining > 0) {
        size_t chunk_size = (remaining < SHRED_CHUNK) ? remaining : SHRED_CHUNK;
        
        // write the pre-filled pattern buffer to disk.
        if (fwrite(buffer, 1, chunk_size, file) != chunk_size) {
            // securely wipe buffer before freeing.
            volatile uint8_t *vp = buffer;
            for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
            free(buffer);
            return -1;
        }
        remaining -= chunk_size;
    }
    
    // force all buffered data to physical media before continuing.
    if (fflush(file) != 0) {
        // securely wipe buffer before freeing.
        volatile uint8_t *vp = buffer;
        for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
        free(buffer);
        return -1;
    }
    
    // ensure data reaches the actual storage device, not just os cache.
#ifdef _WIN32
    _commit(fileno(file));
#else
    fsync(fileno(file));
#endif
    
    // securely wipe the pattern buffer from memory.
    volatile uint8_t *vp = buffer;
    for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
    free(buffer);
    
    return 0;
}

// overwrites a file with cryptographically secure random data.
// used for the final pass to ensure maximum entropy on the media.
// returns 0 on success, -1 on write or seek error.
static int overwrite_random(FILE *file, size_t file_size) {
    
    // seek to beginning of file for the random pass.
    if (fseek(file, 0, SEEK_SET) != 0) {
        return -1;
    }
    
    // allocate buffer for random data generation.
    uint8_t *buffer = (uint8_t *)malloc(SHRED_CHUNK);
    if (!buffer) return -1;
    
    size_t remaining = file_size;
    
    // fill with fresh random data in chunks.
    while (remaining > 0) {
        size_t chunk_size = (remaining < SHRED_CHUNK) ? remaining : SHRED_CHUNK;
        
        // generate cryptographically secure random bytes.
        // keygen_random_key aborts on rng failure — no recovery possible.
        keygen_random_key(buffer, chunk_size);
        
        // write random data to disk.
        if (fwrite(buffer, 1, chunk_size, file) != chunk_size) {
            // securely wipe random buffer before freeing.
            volatile uint8_t *vp = buffer;
            for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
            free(buffer);
            return -1;
        }
        remaining -= chunk_size;
    }
    
    // force random data to physical media.
    if (fflush(file) != 0) {
        // securely wipe random buffer before freeing.
        volatile uint8_t *vp = buffer;
        for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
        free(buffer);
        return -1;
    }
    
    // ensure data reaches the actual storage device.
#ifdef _WIN32
    _commit(fileno(file));
#else
    fsync(fileno(file));
#endif
    
    // securely wipe the random data buffer from memory.
    volatile uint8_t *vp = buffer;
    for (size_t i = 0; i < SHRED_CHUNK; i++) vp[i] = 0;
    free(buffer);
    
    return 0;
}

// securely deletes a file using dod 5220.22-m ece 7-pass standard.
// performs 6 pattern passes followed by 1 random data pass,
// then truncates and unlinks the file from the filesystem.
//
// the 7-pass method provides excellent security for both traditional
// magnetic media and modern storage while remaining practical for
// files up to several gigabytes in size.
int shred_file(const char *filename) {
    
    // validate input parameter before opening the file.
    if (!filename) return -1;
    
    // open file for read/write without truncation — we need to overwrite
    // existing content, not create a new empty file.
    FILE *file = fopen(filename, "rb+");
    if (!file) return -1;
    
    // determine file size for complete coverage during overwrites.
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return -1;
    }
    
    // handle empty files: nothing to overwrite, just delete.
    if (file_size == 0) {
        fclose(file);
        if (unlink(filename) != 0) return -1;
        return 0;
    }
    
    // perform first 6 passes with fixed patterns.
    // each pattern is designed to eliminate different types of
    // residual magnetic signatures on storage media.
    for (int pass = 0; pass < SHRED_PASSES - 1; pass++) {
        if (overwrite_pattern(file, (size_t)file_size, SHRED_PATTERNS[pass]) != 0) {
            fclose(file);
            return -1;
        }
    }
    
    // final pass: cryptographically secure random data.
    // this ensures maximum entropy and makes forensic recovery
    // statistically impossible even with advanced techniques.
    if (overwrite_random(file, (size_t)file_size) != 0) {
        fclose(file);
        return -1;
    }
    
    // close file before truncation and deletion.
    fclose(file);
    
    // truncate file to zero length before final deletion.
    // this removes any residual directory entry information.
    file = fopen(filename, "wb");
    if (file) {
        fclose(file);
    }
    
    // final unlink — this is the point of no return.
    if (unlink(filename) != 0) return -1;
    
    return 0;
}