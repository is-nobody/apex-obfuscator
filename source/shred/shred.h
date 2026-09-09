// source/shred/shred.h
// Implementation of Secure File Deletion for Apex Obfuscator
// https://github.com/is-nobody/apex-obfuscator
// MIT license

#ifndef SHRED_H
#define SHRED_H

#include <stdint.h>
#include <stddef.h>

// number of overwrite passes for secure deletion.
// 7 passes follows dod 5220.22-m ece standard:
// pass 1-2: fixed patterns (0x55, 0xaa)
// pass 3-6: additional patterns (0x92, 0x49, 0x24, 0x6d)
// pass 7: cryptographically random data
// this provides excellent security while remaining practical for large files.
#define SHRED_PASSES 7

// securely deletes a file by overwriting its contents 7 times
// with specific patterns before unlinking.
//
// filename: path to the file to securely delete.
//
// returns 0 on success, -1 on any error (file not found, permission denied, etc.).
// all failures return the same code to prevent information leakage about
// which stage of deletion failed.
int shred_file(const char *filename);

#endif