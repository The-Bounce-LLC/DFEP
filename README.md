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
  ```

## CLI / Usage
- Encrypt: python3 dfep.py -e <file_path>
  - Prompts for a dfepk password (entered twice for confirmation).
  - Generates an RSA keypair, derives AES key from password + salt, double-warps the plaintext, AES-CBC encrypts, signs with RSA, then packages fields into JSON (optionally zlib-compressed with a DFEP header).
  - Output file: original-filename.dfep
- Decrypt: python3 dfep.py -d <file_path.dfep>
  - Prompts for the dfepk password, verifies a locally stored key hash (`~/.dfep_key`), verifies RSA signature, decrypts AES, un-warps and writes back original file extension.

## File format (implementation details)
When saved without compression, the package is a JSON object with compact field names:
- `s` — base64(signature)
- `k` — public key short form: {'n': hex(public_n), 'e': public_e}
- `i` — base64(iv)
- `a` — base64(salt)
- `e` — base64(encrypted_data)

When compression is used, DFEP writes a binary header:
- 4 bytes: ASCII 'DFEP'
- 1 byte: version (e.g. 1)
- 4 bytes: big-endian original JSON length
- remainder: zlib-compressed JSON bytes

## Project layout (top-level files)
- dfep.py — CLI entrypoint and user interaction (prompts, system info, calls into engine).
- engine.py — High-level encrypt/decrypt flow: PBKDF2, warping, AES-CBC loop, RSA sign/verify, packaging, compression.
- class.py — FastAES implementation and a custom RSA implementation, including key generation and sign/verify.
- worker.py — Parallel worker module (thread and process management, chunked AES and warp helpers, NumPy/Numba accelerated paths, Android/Termux fallbacks).
- optimize.py — Auto-optimizer that detects system capabilities, writes `.dfep_optimized.json`, patches worker.py, and creates `dfep_optimized.py`.
- progress.py — ProgressBar and Spinner utilities used throughout the CLI.
- helper.py — small utility (clear_screen).
- README.md — (this file).
  
## How it fits together (runtime shape)
- dfep.py instantiates the OptimizedDFEP engine and drives the user flow (password prompt, mode selection).
- engine.py uses FastAES and RSA from class.py (dynamically imported) to perform cryptographic operations, and uses ProgressBar/Spinner for UX.
- worker.py provides parallel chunked processing for warping, AES encrypt/decrypt, and PBKDF2 blocks; optimize.py can patch worker settings and generates an optimized launcher.

## Performance & platform notes
- The code includes optional NumPy / Numba acceleration for large data paths (worker.py) if not running on Android/Termux.
- SystemOptimizer and optimize.py attempt to detect CPU, memory, and environment (Android/Termux/WSL/Containers) to pick a reasonable default: chunk sizes, number of workers, and whether to use processes or threads.
- On Android, DFEP favors threads and smaller worker counts to be compatible with Termux and mobile constraints.

## Security recommendations and migration tips
- Do not rely on DFEP for highly sensitive data in its current form. Replace homegrown crypto with libraries such as:
  - cryptography (AES-GCM, HMAC, RSA with PSS) or libsodium (XChaCha20-Poly1305).
  - use Argon2 or scrypt for password-based key derivation.
- Replace the custom RSA signature scheme with a standard signing scheme with robust padding and constant-time verification.
- Consider adopting an AEAD (authenticated encryption) so integrity is enforced by the encryption primitive itself rather than a separate signature step.
- If you must keep the current structure: increase PBKDF2 iterations, protect `~/.dfep_key` (permissions and secure storage), and avoid reusing passwords.

## Testing & development
- To run simple module checks:
  ```bash
  python3 worker.py         # prints worker info
  python3 optimize.py       # creates an optimized launcher and config
  ```
- To run the full CLI:
  ```bash
  python3 dfep.py -e myfile.txt
  python3 dfep.py -d myfile.dfep
  ```

## Suggested improvements (short list)
- Migrate to cryptography or libsodium for AES, KDF, and signatures.
- Use AES-GCM or XChaCha20-Poly1305 for authenticated encryption.
- Replace custom RSA key generation with bindings to OpenSSL / cryptography primitives or switch to ECDSA/Ed25519.
- Remove on-disk password artifacts or encrypt them with OS keyrings.
- Add automated unit tests and CI to validate encryption/decryption round-trips and signature semantics.

## Contribution & license
Contributions welcome. Open an issue or PR with focused changes (security fixes or tests prioritized). Include tests and a short design note for nontrivial cryptographic changes.

License: `Non-Commercial Use License` — please add a LICENSE file to the repository.
