// source/cli/args.c
// Implementation of CLI Arguments for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "args.h"
#include "cipher.h"
#include "utils.h"
#include "keygen.h"
#include "shred.h"

// platform-specific includes for sleep function and timing.
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RESET "\033[0m"

// checks if a string consists entirely of hexadecimal digits (0-9, a-f, A-F).
// used to detect whether a user-provided key string is a hex-encoded byte sequence
// or a raw text password — they require different parsing strategies.
static int is_hex_string(const char *str) {
    if (!str || !*str) return 0;
    for (size_t i = 0; str[i]; i++) {
        if (!isxdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}

// converts a hex string (e.g., "6d796b6579") into raw bytes.
// called when the user provides a hex-encoded key instead of a text password.
// pairs of hex characters are parsed into single byte values.
static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t *len) {
    size_t hex_len = strlen(hex);
    *len = hex_len / 2;  // two hex chars per byte
    for (size_t i = 0; i < *len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        bytes[i] = (uint8_t)byte;
    }
}

// displays a progress indicator during file encryption/decryption.
// overwrites the current line with carriage return (\r) for a smooth updating display.
// this is called by the cipher engine as it processes chunks of data.
void show_progress(size_t current, size_t total) {
    float percent = (total > 0) ? (float)current / total * 100.0f : 0.0f;
    printf("\r" COLOR_CYAN "Progress: %.1f%% (%llu / %llu bytes)" COLOR_RESET, percent, (unsigned long long)current, (unsigned long long)total);
    fflush(stdout);  // flush immediately so user sees real-time updates
}

// prepares a key from the user-provided string (or generates a random one if NULL).
// handles three cases:
//   1. NULL key_str → generate a fresh random 32-byte key
//   2. hex string (even length, all hex chars) → parse as raw bytes
//   3. regular string → treat as password, use bytes directly (up to 64)
//
// warns the user if the key is shorter than MIN_KEY_SIZE (32 bytes) since
// short keys get expanded via hmac, which reduces effective entropy.
static void prepare_key(const char *key_str, uint8_t *key, size_t *key_len) {
    if (key_str) {
        // auto-detect hex-encoded keys: even length and all hex digits.
        // this allows users to provide keys as both "mykey123" and "6d796b6579".
        if (strlen(key_str) % 2 == 0 && is_hex_string(key_str)) {
            hex_to_bytes(key_str, key, key_len);
        } else {
            // treat as raw text password — copy bytes up to 64 char limit.
            *key_len = strlen(key_str);
            if (*key_len > 64) *key_len = 64;  // truncate excessively long keys
            memcpy(key, key_str, *key_len);
        }
        
        // warn about short keys: less than 32 bytes means the key will be
        // expanded via hmac rather than used directly for aes-256.
        if (*key_len < MIN_KEY_SIZE) {
            fprintf(stderr, COLOR_RED "Warning: Key is only %llu bytes. Use at least %d bytes.\n" COLOR_RESET, (unsigned long long)*key_len, MIN_KEY_SIZE);
            fprintf(stderr, COLOR_RED "Short keys will be expanded via HMAC, but this reduces entropy.\n" COLOR_RESET);
        }
        
        utils_show_key(key, *key_len);
    } else {
        // no key provided — generate a random 32-byte key for one-time use.
        keygen_random_key(key, DEFAULT_KEY_SIZE);
        *key_len = DEFAULT_KEY_SIZE;
        utils_show_key(key, *key_len);
    }
}

// constructs the output filename by replacing or appending an extension.
// examples: "document.txt" + ".enc" → "document.enc"
//           "archive" + ".enc"     → "archive.enc"
//           "path/to/file.txt" + ".dec" → "path/to/file.dec"
//
// finds the last dot after the last path separator so filenames with
// multiple dots (e.g., "archive.tar.gz") get the extension appended,
// not replaced in the middle.
static char* make_output_name(const char *filename, const char *ext) {
    char *output_name = (char*)malloc(1024);
    if (!output_name) return NULL;
    
    // copy filename with room for null terminator.
    strncpy(output_name, filename, 1024 - 5);
    output_name[1024 - 5] = '\0';
    
    // find the last dot that comes after the last path separator.
    // this ensures we replace the file extension, not a directory name with a dot.
    char *dot = strrchr(output_name, '.');
    char *slash = strrchr(output_name, '/');
    
#ifdef _WIN32
    // on windows, also check for backslash as a path separator.
    char *bslash = strrchr(output_name, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
    
    // if there's a dot after the last slash, strip the old extension.
    if (dot && (!slash || dot > slash)) *dot = '\0';
    
    // append the new extension.
    strcat(output_name, ext);
    return output_name;
}

// handles the "encode" command: encrypts a file with an optional user-provided key.
// if no key is given, a random key is generated and displayed to the user.
// the encrypted output is written to <filename>.enc.
int args_encrypt_file(const char *filename, const char *key_str) {
    // verify the input file exists and is non-empty before doing any work.
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);
    
    if (file_size <= 0) {
        printf(COLOR_RED "Error: File is empty\n" COLOR_RESET);
        return 1;
    }
    
    // prepare the key: parse user input or generate random.
    uint8_t key[64];
    size_t key_len;
    prepare_key(key_str, key, &key_len);
    
    // build output filename with .enc extension.
    char *output_name = make_output_name(filename, ".enc");
    if (!output_name) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    
    // perform the actual encryption with progress reporting.
    int result = cipher_encrypt_file(filename, output_name, key, key_len, show_progress);
    
    if (result == 0) {
        printf("\n" COLOR_GREEN "Successfully encrypted: %s\n" COLOR_RESET, output_name);
    } else {
        printf("\n" COLOR_RED "Error: Encryption failed\n" COLOR_RESET);
    }
    
    free(output_name);
    return result;
}

// handles the "decode" command: decrypts a file with a required key.
// the key is mandatory for decryption — there's no random fallback.
// the decrypted output is written to <filename>.dec.
// all failures produce the same return code to prevent oracle attacks.
int args_decrypt_file(const char *filename, const char *key_str) {
    // verify the encrypted file exists and is non-empty.
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);
    
    if (file_size <= 0) {
        printf(COLOR_RED "Error: File is empty\n" COLOR_RESET);
        return 1;
    }
    
    // parse the key (no random generation for decryption — key must match encryption).
    uint8_t key[64];
    size_t key_len;
    
    // same auto-detection logic as prepare_key but without the random fallback.
    if (strlen(key_str) % 2 == 0 && is_hex_string(key_str)) {
        hex_to_bytes(key_str, key, &key_len);
    } else {
        key_len = strlen(key_str);
        if (key_len > 64) key_len = 64;
        memcpy(key, key_str, key_len);
    }
    utils_show_key(key, key_len);
    
    // build output filename with .dec extension.
    char *output_name = make_output_name(filename, ".dec");
    if (!output_name) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    
    // perform decryption with progress reporting.
    // cipher_decrypt_file returns 0 on success, -1 on any failure (all failures
    // produce the same return code — no oracle leakage).
    int result = cipher_decrypt_file(filename, output_name, key, key_len, show_progress);
    
    if (result == 0) {
        printf("\n" COLOR_GREEN "Successfully decrypted: %s\n" COLOR_RESET, output_name);
    } else {
        printf("\n" COLOR_RED "Error: Decryption failed\n" COLOR_RESET);
    }
    
    free(output_name);
    return result;
}

// handles the "shred" command: securely deletes a file using
// dod 5220.22-m ece 7-pass standard (6 patterns + 1 random).
// the operation is irreversible and cannot be undone.
int args_shred_file(const char *filename) {
    // verify the file exists before attempting secure deletion.
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    fclose(f);
    
    // warn the user about the irreversibility of this operation.
    printf(COLOR_YELLOW "WARNING: Securely deleting '%s'.\n" COLOR_RESET, filename);
    printf(COLOR_YELLOW "This operation CANNOT be undone!\n" COLOR_RESET);
    printf("Press Ctrl+C within 3 seconds to cancel...\n");
    
    // give user a brief moment to abort before proceeding.
    // intentionally minimal delay — just enough for reflex cancellation.
#ifdef _WIN32
    Sleep(3000);
#else
    sleep(3);
#endif
    
    // perform the secure deletion.
    int result = shred_file(filename);
    
    if (result == 0) {
        printf(COLOR_GREEN "Successfully shredded: %s\n" COLOR_RESET, filename);
    } else {
        printf(COLOR_RED "Error: Secure deletion failed\n" COLOR_RESET);
    }
    
    return result;
}

// prints usage instructions showing the available commands and their syntax.
// called when the user provides no command or an unknown command.
void print_usage(const char *program_name) {
    printf("Apex Obfuscator v26.08\n\n");
    printf("Usage:\n");
    printf("  %s encode <file>        - Encrypt file with random key\n", program_name);
    printf("  %s encode <file> <key>  - Encrypt file with provided key\n", program_name);
    printf("  %s decode <file> <key>  - Decrypt file with key\n", program_name);
    printf("  %s shred <file>         - Securely delete file (7-pass DoD 5220.22-M ECE)\n", program_name);
    printf("\n");
}