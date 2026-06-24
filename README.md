# DFEP — Deep File Encryption Protocol

DFEP is a small, single-file Python CLI that provides an experimental "Deep File Encryption Protocol" for encrypting and signing files into a portable .dfep package. It combines a custom AES implementation, RSA keypair signing, PBKDF2 key derivation, and a lightweight "double warp" obfuscation pass. This repository is intended for exploration and educational use — do NOT rely on it for production or sensitive data without an expert security review.

## Features
- AES-based block encryption in CBC mode (implemented in Python).
- RSA keypair generation and RSA/SHA-512 signatures for integrity.
- PBKDF2-HMAC-SHA512 key derivation (configurable iterations).
- "Double warp" reversible XOR obfuscation pass.
- Salt and IV handling, packaged into a JSON `.dfep` file.
- Simple CLI for encrypting and decrypting files.
- Minimal single-file implementation suitable for study and prototyping.

## Quick start

Requirements:
- Python 3.8+ (or newer)
- No external dependencies (script uses Python stdlib)

Clone and run:
```code
git clone https://github.com/The-Bounce-LLC/DFEP.git
cd DFEP
python3 dfep.py -e path/to/file           # encrypt (interactive password prompt)
python3 dfep.py -d path/to/file.dfep      # decrypt (interactive password prompt)
