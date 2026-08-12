<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="resources/logo.png">
    <source media="(prefers-color-scheme: light)" srcset="resources/logo-dark.png">
    <img alt="Apex" src="resources/logo.png" width="75%">
  </picture>
</div>

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Apex Obfuscator Version](https://img.shields.io/badge/Apex_Cipher-26.08-blue)](https://github.com/is-nobody/apex-obfuscator)
![Available](https://img.shields.io/badge/Available-Windows%20%7C%20macOS%20%7C%20Linux-red)

This is the official repository for [Apex](https://github.com/is-nobody/apex-obfuscator) Cipher.

## Why Apex Obfuscator?
- **Minimal & Lightweight:** Pure C implementation with zero external dependencies and minimal codebase.

- **Authenticated Encryption:** HMAC-SHA256 integrity verification detects any tampering or corruption.

- **Streaming Support:** Encrypts and decrypts large files in chunks without loading everything into memory.

- **Memory Safe:** Secure zeroization wipes sensitive keys and data immediately after use.

## Quick Start
### Install Apex Obfuscator
1. Clone the repository:
```bash
git clone https://github.com/is-nobody/apex-obfuscator.git
cd apex-obfuscator
```

2. Build the project:
```bash
cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release
cmake --build build/ --parallel
```

### Testing the Cipher
Use the `encode` and `decode` arguments:

```bash
none@root:~$ apex-obfuscator encode main.c mykey123
Warning: Key is only 8 bytes. Use at least 32 bytes.
Short keys will be expanded via HMAC, but this reduces entropy.
Key: 6d796b6579313233 (8 bytes)
Progress: 100.0% (6123 / 6123 bytes)
Successfully encrypted: main.enc

none@root:~$ apex-obfuscator decode main.enc mykey123
Key: 6d796b6579313233 (8 bytes)
Progress: 100.0% (6123 / 6123 bytes)
Successfully decrypted: main.dec
```

## Security Features
- **Mathematical Foundation from AES-256:** 14 rounds of substitution, shifting, mixing, and key addition with 15 unique round keys per session.

- **CBC Mode with PKCS#7:** Semantic security — identical plaintext blocks produce different ciphertexts.

- **Encrypt-then-MAC (HMAC-SHA256):** Authenticity verified *before* decryption — eliminates padding oracle attacks entirely.

- **Random Salt & IV:** 16 bytes each, unique per encryption — prevents ciphertext reuse and rainbow tables.

- **PBKDF2-HMAC-SHA256:** 100,000 iterations with unique salt for key derivation from passwords.

- **Key Length Enforcement:** 32–64 bytes. Shorter keys are cryptographically expanded, never silently truncated.

| Attack | Mitigation |
|--------|------------|
| Padding Oracle (Vaudenay, POODLE, Lucky13) | Encrypt-then-MAC — verification before decryption |
| Timing Side-Channel | Constant-time `ct_memcmp` — full 32-byte scan, no early exit |
| Error Code Oracle | Uniform `-1` return for all failure modes |
| Truncation | Original file size in authenticated header |
| Ciphertext Manipulation | HMAC-SHA256 over header + entire ciphertext |
| Brute-Force / Dictionary | PBKDF2 with 100,000 iterations + 128-bit random salt |
| Key Reuse (ENC vs MAC) | Domain-separated derivation ("ENC" / "MAC" tags) |
| Weak User Key (<32 bytes) | HMAC-based expansion to full 256-bit strength |
| Memory Dump / Cold Boot | Secure zeroization via `volatile` pointers, keys wiped after use |

## Getting Help
See [Issues](https://github.com/is-nobody/apex-obfuscator/issues) for bug reports and feature requests.

## Contributing
Apex Obfuscator is created and maintained by one person, but contributions are welcome!

Please see [contributing](contributing.md) and remember about [Code of Conduct](code_of_conduct.md)

## License
Apex Obfuscator is distributed under the terms of the **MIT license**.

See [license](license) for details.