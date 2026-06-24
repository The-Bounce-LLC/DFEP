# DFEP — Deep File Encryption Protocol

Transform files into a portable encrypted package (.dfep). DFEP is a Python-based command-line tool that demonstrates a self-contained file envelope: password-derived AES encryption, a reversible XOR-based "double warp" obfuscation, RSA signatures, and a small packaging format (optionally compressed). DFEP is primarily intended for study, experimentation, and prototyping — not for production use with high-value secrets without additional hardening.

## Key features
- Pure-Python AES implementation (FastAES) using T-tables and CBC-mode block processing.
- Password-based key derivation with a PBKDF2-HMAC-SHA512 implementation (configurable iterations).
- Per-file RSA keypair generation and a custom RSA/SHA-512 signing scheme.
- "Double warp" reversible XOR obfuscation pass (two-pass XOR).
- Salt and IV handling; packaged as JSON fields inside a `.dfep` payload. Optional zlib compression with a custom DFEP header.
- Multi-platform optimizations and an auto-optimizer that can produce an optimized launcher (`dfep_optimized.py`) and `.dfep_optimized.json`.
- Worker module (worker.py) for threaded / process-based parallelism; optional NumPy/Numba acceleration when available.
- Minimal external dependencies (most functionality implemented with the Python standard library).

## Important safety & cryptography notes (read first)
- This project implements cryptographic primitives by hand. Homegrown crypto is dangerous: the code contains non-standard/naive uses of RSA signing and padding, custom AES/CBC handling, and bespoke key storage. Do NOT use DFEP to protect high-value secrets without an expert security audit.
- The RSA signing uses a custom primitive (modular exponent of a SHA-512-derived integer) and signature verification extracts trailing bytes — this is not a standard signature scheme (PKCS#1 or PSS). It is not resistant to modern signature attacks.
- AES is implemented inside the repo (FastAES). While educational, using a vetted library (cryptography.io) is highly recommended for production.
- DFEP stores a small key file in the user's home (`~/.dfep_key`) containing a SHA-256 hash of the password and original extension. Treat this file carefully; storing password-derived information on disk introduces attack surface.
- Recommended hardening: use Argon2/scrypt for KDF, use AES-GCM or an AEAD for authenticated encryption, use standard RSA/PSS or ECDSA with proper padding and verification, and avoid storing password material on disk in plaintext or predictable formats.

## Quick start — requirements
- Python 3.8+.
- No strict external dependencies for basic usage. Optional: numpy, numba, psutil for performance and system info.
- Clone and run:
  ```bash
  git clone https://github.com/The-Bounce-LLC/DFEP.git
  cd DFEP
  python3 dfep.py -e path/to/file          # Encrypt
  python3 dfep.py -d path/to/file.dfep     # Decrypt