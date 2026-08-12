// source/utils/utils.c
// Implementation of Utils for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "utils.h"

// prints raw binary data directly to stdout without any formatting.
// used for outputting decrypted content or binary results.
// fwrite is used instead of printf to handle null bytes and binary data safely —
// printf with %s would stop at the first 0x00 byte.
void utils_print_safe(const uint8_t *data, size_t len) {
    fwrite(data, 1, len, stdout);
}

// displays a key as a hex string followed by its byte length in parentheses.
// example output: "Key: 6d796b6579313233 (8 bytes)"
//
// this is shown to the user during both encryption and decryption so they can
// verify the key being used and spot obvious typos or truncation.
// hex display ensures all bytes are visible regardless of whether they're
// printable ascii characters or not.
void utils_show_key(const uint8_t *key, size_t key_len) {
    printf("Key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", key[i]);  // zero-padded two-digit hex for each byte
    }
    printf(" (%llu bytes)\n", (unsigned long long)key_len);
}