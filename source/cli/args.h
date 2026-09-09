// source/cli/args.h
// Implementation of CLI Arguments for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef ARGS_H
#define ARGS_H

// handles the "encode" command: encrypts a file with an optional key.
// filename: path to the plaintext file to encrypt.
// key_str: user-provided key string (text password or hex-encoded bytes),
//          or NULL to generate a random key.
// returns 0 on success, non-zero on error.
int args_encrypt_file(const char *filename, const char *key_str);

// handles the "decode" command: decrypts a file with a required key.
// filename: path to the encrypted file to decrypt.
// key_str: the key used during encryption (text or hex, must match).
// returns 0 on success, non-zero on error.
// all failure modes return the same error code to prevent oracle attacks.
int args_decrypt_file(const char *filename, const char *key_str);

// handles the "shred" command: securely deletes a file.
// uses dod 5220.22-m ece 7-pass standard for secure deletion.
// filename: path to the file to securely delete.
// returns 0 on success, non-zero on error.
int args_shred_file(const char *filename);

// prints command-line usage instructions to stdout.
// program_name: typically argv[0] for accurate command name display.
void print_usage(const char *program_name);

#endif