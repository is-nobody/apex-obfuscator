// source/utils/utils.h
// Implementation of Utils for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

// writes raw binary data to stdout safely (handles null bytes correctly).
// uses fwrite rather than printf with %s to avoid truncation at 0x00 bytes.
void utils_print_safe(const uint8_t *data, size_t len);

// prints a key in hexadecimal format followed by its byte length.
// used to display keys to the user for verification and transparency.
// format: "Key: <hex bytes> (<length> bytes)"
void utils_show_key(const uint8_t *key, size_t key_len);

#endif