// main.c
// Implementation of Main Entry Point for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#include <stdio.h>
#include <string.h>
#include "args.h"
#include "crypto_context.h"

#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

// entry point for the Apex Obfuscator command-line tool.
// supports two commands: encode (encrypt) and decode (decrypt).
//
// the default random key is generated once at startup via crypto_init_default_key()
// so that it's available if needed, but it's only used when the user omits a key
// during encryption (which triggers random key generation in prepare_key anyway).

int main(int argc, char *argv[]) {
    // generate a fresh random default key at process start.
    // this key is created regardless of whether it will be used —
    // it costs almost nothing and ensures the rng is warmed up.
    // actual random keys per encryption are generated in prepare_key() when needed.
    crypto_init_default_key();
    
    // no command provided — show usage and exit.
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    // handle "decode" command: requires exactly a filename and a key.
    // decryption never uses a random key — the key must match what was used for encryption.
    if (strcmp(command, "decode") == 0) {
        if (argc != 4) {
            printf(COLOR_RED "Error: decode requires file and key\n" COLOR_RESET);
            print_usage(argv[0]);
            return 1;
        }
        return args_decrypt_file(argv[2], argv[3]);
    }
    
    // handle "encode" command: requires at least a filename, optional key.
    // if no key is provided, args_encrypt_file will generate a random one
    // and display it to the user so they can save it for decryption.
    if (strcmp(command, "encode") == 0) {
        if (argc < 3) {
            printf(COLOR_RED "Error: encode requires at least file\n" COLOR_RESET);
            print_usage(argv[0]);
            return 1;
        }
        // pass the key as NULL if only filename was given (no key argument).
        const char *key = (argc > 3) ? argv[3] : NULL;
        return args_encrypt_file(argv[2], key);
    }
    
    // unknown command — show error and usage to guide the user.
    printf(COLOR_RED "Error: Unknown command '%s'\n" COLOR_RESET, command);
    print_usage(argv[0]);
    
    return 1;
}