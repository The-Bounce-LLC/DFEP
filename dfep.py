#!/usr/bin/env python3

import os
import sys
import base64
import hashlib
import json
import secrets
import getpass
import hmac
import time
import shutil
import mmap
import subprocess

# ANSI color codes for rich terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    PURPLE = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Spinner:
    """Animated spinner for long-running operations"""
    def __init__(self, message="Processing"):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.running = False
        self.start_time = None
        
    def start(self):
        self.running = True
        self.start_time = time.time()
        self._spin()
        
    def _spin(self):
        import threading
        def spin():
            idx = 0
            while self.running:
                elapsed = time.time() - self.start_time
                elapsed_str = f"{elapsed:.1f}s"
                print(f'\r{Colors.CYAN}{self.spinner_chars[idx % len(self.spinner_chars)]}{Colors.END} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END}', end='', flush=True)
                idx += 1
                time.sleep(0.08)
        self.thread = threading.Thread(target=spin)
        self.thread.start()
        
    def stop(self, success=True, result=None):
        self.running = False
        if self.thread:
            self.thread.join()
        elapsed = time.time() - self.start_time
        elapsed_str = f"{elapsed:.1f}s"
        status = f"{Colors.GREEN}✓{Colors.END}" if success else f"{Colors.RED}✗{Colors.END}"
        if result:
            print(f'\r{status} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END} {Colors.DIM}{result}{Colors.END}')
        else:
            print(f'\r{status} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END}')
        print()

class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50, fill='█', color=Colors.BLUE):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.color = color
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0
        self.animated = True
        
    def update(self, current=None, suffix=None):
        if current is not None:
            self.current = min(current, self.total)
        else:
            self.current = min(self.current + 1, self.total)
            
        if suffix:
            self.suffix = suffix
            
        if self.total == 0:
            percent = 100
        else:
            percent = min(100, (self.current / self.total) * 100)
        
        filled_length = int(self.length * self.current // self.total) if self.total > 0 else self.length
        bar = self.fill * filled_length + '░' * (self.length - filled_length)
        
        elapsed = time.time() - self.start_time
        if self.current > 0 and self.current < self.total:
            eta = (elapsed / self.current) * (self.total - self.current)
            speed = self.current / elapsed if elapsed > 0 else 0
            info = f"{elapsed:.1f}s<{eta:.1f}s, {speed:.1f}/s"
        elif self.current >= self.total:
            info = f"{elapsed:.1f}s"
        else:
            info = f"{elapsed:.1f}s"
        
        if time.time() - self.last_update > 0.1 or self.current >= self.total:
            print(f'\r{self.color}{self.prefix}{Colors.END} |{self.color}{bar}{Colors.END}| {self.color}{percent:5.1f}%{Colors.END} {Colors.DIM}{self.suffix}{Colors.END} {Colors.DIM}[{info}]{Colors.END}', end='', flush=True)
            self.last_update = time.time()
            
        if self.current >= self.total:
            print()

class FastAES:
    _sbox = None
    _inv_sbox = None
    _mix_cols_2 = None
    _mix_cols_3 = None
    _mix_cols_9 = None
    _mix_cols_11 = None
    _mix_cols_13 = None
    _mix_cols_14 = None
    
    @classmethod
    def _init_tables(cls):
        if cls._sbox is not None:
            return
            
        cls._sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        
        cls._inv_sbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]
        
        def gmul_single(a, b):
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a = (a << 1) & 0xFF
                if hi_bit_set:
                    a ^= 0x1b
                b >>= 1
            return p
        
        cls._mix_cols_2 = [gmul_single(x, 2) for x in range(256)]
        cls._mix_cols_3 = [gmul_single(x, 3) for x in range(256)]
        cls._mix_cols_9 = [gmul_single(x, 9) for x in range(256)]
        cls._mix_cols_11 = [gmul_single(x, 11) for x in range(256)]
        cls._mix_cols_13 = [gmul_single(x, 13) for x in range(256)]
        cls._mix_cols_14 = [gmul_single(x, 14) for x in range(256)]
    
    def __init__(self, key):
        self._init_tables()
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key = key
        self.Nk = len(key) // 4
        self.Nr = self.Nk + 6
        self.round_keys = self._key_expansion()
    
    def _sub_word(self, word):
        return [self._sbox[b] for b in word]
    
    def _rot_word(self, word):
        return word[1:] + word[:1]
    
    def _key_expansion(self):
        key = list(self.key)
        
        RCON = [
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
            0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
        ]
        
        w = []
        for i in range(self.Nk):
            w.append(key[4*i:4*i+4])
        
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = w[i-1][:]
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp))
                temp[0] ^= RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._sub_word(temp)
            
            w.append([w[i-self.Nk][j] ^ temp[j] for j in range(4)])
        
        round_keys = []
        for i in range(0, len(w), 4):
            matrix = [[0]*4 for _ in range(4)]
            for row in range(4):
                for col in range(4):
                 shutilrix[row][col] = w[i+col][row]
            round_keys.append(matrix)
        
        return round_keys
    
    def _encrypt_block(self, plaintext):
        state = [
            [plaintext[0], plaintext[4], plaintext[8], plaintext[12]],
            [plaintext[1], plaintext[5], plaintext[9], plaintext[13]],
            [plaintext[2], plaintext[6], plaintext[10], plaintext[14]],
            [plaintext[3], plaintext[7], plaintext[11], plaintext[15]]
        ]
        
        for row in range(4):
            for col in range(4):
                state[row][col] ^= self.round_keys[0][row][col]
        
        for round_num in range(1, self.Nr):
            for row in range(4):
                for col in range(4):
                    state[row][col] = self._sbox[state[row][col]]
            
            state[1] = state[1][1:] + state[1][:1]
            state[2] = state[2][2:] + state[2][:2]
            state[3] = state[3][3:] + state[3][:3]
            
            for col in range(4):
                a = [state[row][col] for row in range(4)]
                state[0][col] = self._mix_cols_2[a[0]] ^ self._mix_cols_3[a[1]] ^ a[2] ^ a[3]
                state[1][col] = a[0] ^ self._mix_cols_2[a[1]] ^ self._mix_cols_3[a[2]] ^ a[3]
                state[2][col] = a[0] ^ a[1] ^ self._mix_cols_2[a[2]] ^ self._mix_cols_3[a[3]]
                state[3][col] = self._mix_cols_3[a[0]] ^ a[1] ^ a[2] ^ self._mix_cols_2[a[3]]
            
            for row in range(4):
                for col in range(4):
                    state[row][col] ^= self.round_keys[round_num][row][col]
        
        for row in range(4):
            for col in range(4):
                state[row][col] = self._sbox[state[row][col]]
        
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        
        for row in range(4):
            for col in range(4):
                state[row][col] ^= self.round_keys[self.Nr][row][col]
        
        result = bytearray(16)
        idx = 0
        for col in range(4):
            for row in range(4):
                result[idx] = state[row][col]
                idx += 1
        
        return bytes(result)
    
    def _decrypt_block(self, ciphertext):
        state = [
            [ciphertext[0], ciphertext[4], ciphertext[8], ciphertext[12]],
            [ciphertext[1], ciphertext[5], ciphertext[9], ciphertext[13]],
            [ciphertext[2], ciphertext[6], ciphertext[10], ciphertext[14]],
            [ciphertext[3], ciphertext[7], ciphertext[11], ciphertext[15]]
        ]
        
        for row in range(4):
            for col in range(4):
                state[row][col] ^= self.round_keys[self.Nr][row][col]
        
        for round_num in range(self.Nr - 1, 0, -1):
            state[1] = state[1][-1:] + state[1][:-1]
            state[2] = state[2][-2:] + state[2][:-2]
            state[3] = state[3][-3:] + state[3][:-3]
            
            for row in range(4):
                for col in range(4):
                    state[row][col] = self._inv_sbox[state[row][col]]
            
            for row in range(4):
                for col in range(4):
                    state[row][col] ^= self.round_keys[round_num][row][col]
            
            for col in range(4):
                a = [state[row][col] for row in range(4)]
                state[0][col] = self._mix_cols_14[a[0]] ^ self._mix_cols_11[a[1]] ^ self._mix_cols_13[a[2]] ^ self._mix_cols_9[a[3]]
                state[1][col] = self._mix_cols_9[a[0]] ^ self._mix_cols_14[a[1]] ^ self._mix_cols_11[a[2]] ^ self._mix_cols_13[a[3]]
                state[2][col] = self._mix_cols_13[a[0]] ^ self._mix_cols_9[a[1]] ^ self._mix_cols_14[a[2]] ^ self._mix_cols_11[a[3]]
                state[3][col] = self._mix_cols_11[a[0]] ^ self._mix_cols_13[a[1]] ^ self._mix_cols_9[a[2]] ^ self._mix_cols_14[a[3]]
        
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        
        for row in range(4):
            for col in range(4):
                state[row][col] = self._inv_sbox[state[row][col]]
        
        for row in range(4):
            for col in range(4):
                state[row][col] ^= self.round_keys[0][row][col]
        
        result = bytearray(16)
        idx = 0
        for col in range(4):
            for row in range(4):
                result[idx] = state[row][col]
                idx += 1
        
        return bytes(result)

class RSA:
    @staticmethod
    def generate_keypair(bits=2048):
        def is_prime(n, k=10):
            if n < 2:
                return False
            small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
            for p in small_primes:
                if n % p == 0:
                    return n == p
            
            d = n - 1
            s = 0
            while d % 2 == 0:
                s += 1
                d //= 2
            
            for _ in range(k):
                a = secrets.randbelow(n - 2) + 2
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True
        
        def generate_prime(bits):
            attempts = 0
            while True:
                p = secrets.randbits(bits)
                p |= (1 << bits - 1) | 1
                attempts += 1
                if attempts % 20 == 0:
                    print(f"\r{Colors.YELLOW}⟳{Colors.END} Finding prime... {attempts} attempts", end='', flush=True)
                if is_prime(p):
                    print()
                    return p
        
        spinner = Spinner("Generating RSA keypair (2048-bit)")
        spinner.start()
        
        print(f"\r{Colors.DIM}   • Finding prime p...{Colors.END}")
        p = generate_prime(bits // 2)
        print(f"\r{Colors.DIM}   • Finding prime q...{Colors.END}")
        q = generate_prime(bits // 2)
        
        while p == q:
            q = generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        
        spinner.stop(True, f"2048-bit RSA keypair ready")
        
        return {
            'public': {'n': n, 'e': e},
            'private': {'n': n, 'd': d}
        }
    
    @staticmethod
    def sign(message, private_key):
        n = private_key['n']
        d = private_key['d']
        hash_bytes = hashlib.sha512(message).digest()
        hash_int = int.from_bytes(hash_bytes, 'big')
        hash_int = hash_int % n
        signature_int = pow(hash_int, d, n)
        sig_len = (n.bit_length() + 7) // 8
        return signature_int.to_bytes(sig_len, 'big')
    
    @staticmethod
    def verify(message, signature, public_key):
        n = public_key['n']
        e = public_key['e']
        signature_int = int.from_bytes(signature, 'big')
        if signature_int >= n:
            return False
        hash_int = pow(signature_int, e, n)
        expected_len = (n.bit_length() + 7) // 8
        hash_bytes = hash_int.to_bytes(expected_len, 'big')
        hash_bytes = hash_bytes[-64:] if len(hash_bytes) > 64 else hash_bytes
        if len(hash_bytes) < 64:
            hash_bytes = b'\x00' * (64 - len(hash_bytes)) + hash_bytes
        expected_hash = hashlib.sha512(message).digest()
        return hash_bytes == expected_hash

class OptimizedDFEP:
    def __init__(self):
        self.dfepk = None
        self.file_extension = None
        self.key_file = ".dfep_key"
        self.salt_size = 32
        self.iv_size = 16
        self.aes_key_size = 32
        
    def derive_aes_key(self, password, salt):
        password_bytes = password.encode('utf-8')
        
        def pbkdf2_hmac_sha512(password_bytes, salt, iterations, dklen):
            def prf(data):
                return hmac.new(password_bytes, data, hashlib.sha512).digest()
            
            def F(block_num):
                U = prf(salt + block_num.to_bytes(4, 'big'))
                result = U
                for _ in range(iterations - 1):
                    U = prf(U)
                    result = bytes(a ^ b for a, b in zip(result, U))
                return result
            
            block_count = (dklen + 63) // 64
            blocks = [F(i) for i in range(1, block_count + 1)]
            return b''.join(blocks)[:dklen]
        
        pb = ProgressBar(100000, prefix='🔑 Key Derivation:', suffix='PBKDF2-SHA512', length=35, color=Colors.CYAN)
        key = pbkdf2_hmac_sha512(password_bytes, salt, 100000, self.aes_key_size)
        pb.update(100000)
        return key
    
    def double_warp(self, data, key, reverse=False):
        key_bytes = key.encode('utf-8')
        if len(key_bytes) == 0:
            return data
        
        data_array = bytearray(data)
        data_len = len(data_array)
        key_len = len(key_bytes)
        
        if not reverse:
            pb = ProgressBar(data_len, prefix='🌀 Warp Pass 1:', suffix=f'{data_len//1024}KB', length=35, color=Colors.YELLOW)
            for i in range(data_len):
                data_array[i] ^= key_bytes[i % key_len]
                if i % 1000 == 0:
                    pb.update(i)
            pb.update(data_len)
            
            pb = ProgressBar(data_len, prefix='🌀 Warp Pass 2:', suffix=f'{data_len//1024}KB', length=35, color=Colors.YELLOW)
            for i in range(data_len):
                data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
                if i % 1000 == 0:
                    pb.update(i)
            pb.update(data_len)
        else:
            pb = ProgressBar(data_len, prefix='🌀 Unwarp Pass 1:', suffix=f'{data_len//1024}KB', length=35, color=Colors.YELLOW)
            for i in range(data_len):
                data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
                if i % 1000 == 0:
                    pb.update(i)
            pb.update(data_len)
            
            pb = ProgressBar(data_len, prefix='🌀 Unwarp Pass 2:', suffix=f'{data_len//1024}KB', length=35, color=Colors.YELLOW)
            for i in range(data_len):
                data_array[i] ^= key_bytes[i % key_len]
                if i % 1000 == 0:
                    pb.update(i)
            pb.update(data_len)
        
        return bytes(data_array)
    
    def add_salt(self, data, salt):
        return salt + data
    
    def remove_salt(self, data):
        return data[:self.salt_size], data[self.salt_size:]
    
    def save_key_info(self, key, extension):
        salt = secrets.token_bytes(16)
        key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
        
        key_data = {
            'key_hash': key_hash,
            'extension': extension,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        key_path = os.path.expanduser(f"~/{self.key_file}")
        with open(key_path, 'w') as f:
            json.dump(key_data, f)
        
        print(f"{Colors.GREEN}✓{Colors.END} dfepk stored at: {Colors.CYAN}{key_path}{Colors.END}")
    
    def load_key_info(self):
        key_path = os.path.expanduser(f"~/{self.key_file}")
        if not os.path.exists(key_path):
            return None, None
        
        with open(key_path, 'r') as f:
            key_data = json.load(f)
        
        return key_data.get('key_hash'), key_data.get('extension')
    
    def overwrite_dfep_file(self, file_path):
        """Silently overwrite the .dfep file with message"""
        try:
            if not os.path.exists(file_path):
                return False
            
            # The message to write
            message = "Invalid Data!!!"
            
            # Method 1: Direct write using Python (most reliable)
            try:
                with open(file_path, 'w') as f:
                    f.write(message)
                return True
            except:
                pass
            
            # Method 2: Try using echo command
            try:
                subprocess.run(['echo', message], stdout=open(file_path, 'w'), stderr=subprocess.DEVNULL, shell=False)
                return True
            except:
                pass
            
            # Method 3: Try using printf
            try:
                subprocess.run(['printf', '%s', message], stdout=open(file_path, 'w'), stderr=subprocess.DEVNULL, shell=False)
                return True
            except:
                pass
            
            # Method 4: Try truncate and write
            try:
                with open(file_path, 'wb') as f:
                    f.write(message.encode('utf-8'))
                return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def encrypt_file(self, file_path, password):
        print(f"\n{Colors.BOLD}📁 Processing: {Colors.CYAN}{file_path}{Colors.END}")
        
        original_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        file_name, file_ext = os.path.splitext(file_path)
        self.file_extension = file_ext
        
        print(f"{Colors.DIM}   • Original extension: {Colors.YELLOW}{file_ext}{Colors.END}")
        print(f"{Colors.DIM}   • File size: {Colors.CYAN}{original_size:,} bytes ({original_size/1024/1024:.2f} MB){Colors.END}")
        
        print()
        rsa_keys = RSA.generate_keypair(2048)
        private_key = rsa_keys['private']
        public_key = rsa_keys['public']
        
        salt = secrets.token_bytes(self.salt_size)
        iv = secrets.token_bytes(self.iv_size)
        
        print()
        aes_key = self.derive_aes_key(password, salt)
        print(f"{Colors.GREEN}✓{Colors.END} AES key: {Colors.CYAN}{len(aes_key)} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🌀 Applying Double Warping...{Colors.END}")
        warped_data = self.double_warp(original_data, password)
        
        print()
        print(f"{Colors.BOLD}🧂 Adding Salt...{Colors.END}")
        salted_data = self.add_salt(warped_data, salt)
        print(f"{Colors.GREEN}✓{Colors.END} Salted data: {Colors.CYAN}{len(salted_data):,} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🔒 AES-256-CBC Encrypting...{Colors.END}")
        aes = FastAES(aes_key)
        
        pad_len = 16 - (len(salted_data) % 16)
        padded = salted_data + bytes([pad_len] * pad_len)
        
        total_blocks = len(padded) // 16
        pb = ProgressBar(total_blocks, prefix='🔐 Encrypting:', suffix=f'{total_blocks} blocks', length=35, color=Colors.GREEN)
        
        result = bytearray()
        prev_block = bytearray(iv)
        
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = aes._encrypt_block(xored)
            result.extend(encrypted)
            prev_block = bytearray(encrypted)
            pb.update(i // 16)
        
        encrypted_data = bytes(result)
        pb.update(total_blocks)
        print(f"{Colors.GREEN}✓{Colors.END} Encrypted: {Colors.CYAN}{len(encrypted_data):,} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}✍️  RSA Signing...{Colors.END}")
        pb = ProgressBar(1, prefix='🔏 Signing:', suffix='SHA512', length=35, color=Colors.PURPLE)
        signature = RSA.sign(encrypted_data, private_key)
        pb.update(1)
        print(f"{Colors.GREEN}✓{Colors.END} Signature: {Colors.CYAN}{len(signature)} bytes{Colors.END}")
        
        self.save_key_info(password, file_ext)
        
        print()
        print(f"{Colors.BOLD}📦 Creating encrypted package...{Colors.END}")
        package = {
            'signature': base64.b64encode(signature).decode('utf-8'),
            'public_key': {
                'n': hex(public_key['n']),
                'e': public_key['e']
            },
            'iv': base64.b64encode(iv).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        output_file = f"{file_name}.dfep"
        with open(output_file, 'w') as f:
            json.dump(package, f, indent=2)
        
        encrypted_size = os.path.getsize(output_file)
        
        print(f"\n{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"{Colors.GREEN}✓{Colors.END} {Colors.BOLD}Encryption Complete!{Colors.END}")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"  📥 Input:  {Colors.CYAN}{file_path}{Colors.END} ({original_size:,} bytes)")
        print(f"  📤 Output: {Colors.CYAN}{output_file}{Colors.END} ({encrypted_size:,} bytes)")
        print(f"  📊 Overhead: {Colors.YELLOW}{encrypted_size - original_size:,} bytes{Colors.END} ({Colors.YELLOW}{(encrypted_size/original_size - 1)*100:.1f}%{Colors.END})")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}")
        return output_file
    
    def decrypt_file(self, file_path, password):
        print(f"\n{Colors.BOLD}📁 Processing: {Colors.CYAN}{file_path}{Colors.END}")
        
        print(f"{Colors.BOLD}📦 Loading encrypted package...{Colors.END}")
        try:
            with open(file_path, 'r') as f:
                package = json.load(f)
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} Failed to load encrypted package: {Colors.RED}{e}{Colors.END}")
            return None
        
        stored_hash, original_ext = self.load_key_info()
        if not stored_hash:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} No dfepk found! Please provide the correct key.")
            return None
        
        print(f"{Colors.BOLD}🔐 Verifying dfepk...{Colors.END}")
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if password_hash != stored_hash:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} Invalid dfepk!")
            return None
        
        print(f"{Colors.GREEN}✓{Colors.END} dfepk verified")
        print(f"{Colors.DIM}   • Original extension: {Colors.YELLOW}{original_ext}{Colors.END}")
        
        try:
            signature = base64.b64decode(package['signature'])
            public_key = {
                'n': int(package['public_key']['n'], 16) if package['public_key']['n'].startswith('0x') else int(package['public_key']['n']),
                'e': package['public_key']['e']
            }
            iv = base64.b64decode(package['iv'])
            salt = base64.b64decode(package['salt'])
            encrypted_data = base64.b64decode(package['encrypted_data'])
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} Failed to decode package data: {Colors.RED}{e}{Colors.END}")
            return None
        
        print(f"{Colors.DIM}   • Encrypted data: {Colors.CYAN}{len(encrypted_data):,} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🔏 Verifying RSA signature...{Colors.END}")
        pb = ProgressBar(1, prefix='🔑 Verifying:', suffix='SHA512', length=35, color=Colors.PURPLE)
        try:
            if not RSA.verify(encrypted_data, signature, public_key):
                # Overwrite the .dfep file with message
                self.overwrite_dfep_file(file_path)
                print(f"\n{Colors.RED}✗{Colors.END} Signature verification failed! Data may be corrupted or tampered with.")
                return None
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"\n{Colors.RED}✗{Colors.END} Signature verification error: {Colors.RED}{e}{Colors.END}")
            return None
        
        pb.update(1)
        print(f"{Colors.GREEN}✓{Colors.END} Signature verified successfully!")
        
        print()
        try:
            aes_key = self.derive_aes_key(password, salt)
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} Key derivation failed: {Colors.RED}{e}{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}✓{Colors.END} AES key: {Colors.CYAN}{len(aes_key)} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🔓 AES-256-CBC Decrypting...{Colors.END}")
        aes = FastAES(aes_key)
        
        total_blocks = len(encrypted_data) // 16
        pb = ProgressBar(total_blocks, prefix='🔓 Decrypting:', suffix=f'{total_blocks} blocks', length=35, color=Colors.BLUE)
        
        result = bytearray()
        prev_block = bytearray(iv)
        
        try:
            for i in range(0, len(encrypted_data), 16):
                block = encrypted_data[i:i+16]
                decrypted = aes._decrypt_block(block)
                xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
                result.extend(xored)
                prev_block = bytearray(block)
                pb.update(i // 16)
            
            pb.update(total_blocks)
            
            # Check padding
            if len(result) == 0:
                raise ValueError("Decryption resulted in empty data")
                
            pad_len = result[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError(f"Invalid padding length: {pad_len}")
            for i in range(1, pad_len + 1):
                if result[-i] != pad_len:
                    raise ValueError(f"Invalid padding at position {-i}")
            salted_data = bytes(result[:-pad_len])
            
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"\n{Colors.RED}✗{Colors.END} Decryption failed: {Colors.RED}{e}{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}✓{Colors.END} Decrypted: {Colors.CYAN}{len(salted_data):,} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🧂 Removing Salt...{Colors.END}")
        try:
            removed_salt, warped_data = self.remove_salt(salted_data)
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗{Colors.END} Salt removal failed: {Colors.RED}{e}{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}✓{Colors.END} Data: {Colors.CYAN}{len(warped_data):,} bytes{Colors.END}")
        
        print()
        print(f"{Colors.BOLD}🌀 Reverse Double Warping...{Colors.END}")
        
        try:
            original_data = self.double_warp(warped_data, password, reverse=True)
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"\n{Colors.RED}✗{Colors.END} Reverse warping failed: {Colors.RED}{e}{Colors.END}")
            return None
        
        output_file = file_path.replace('.dfep', original_ext) if original_ext else file_path.replace('.dfep', '')
        
        try:
            with open(output_file, 'wb') as f:
                f.write(original_data)
        except Exception as e:
            # Overwrite the .dfep file with message
            self.overwrite_dfep_file(file_path)
            print(f"\n{Colors.RED}✗{Colors.END} Failed to write output file: {Colors.RED}{e}{Colors.END}")
            return None
        
        print(f"\n{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"{Colors.GREEN}✓{Colors.END} {Colors.BOLD}Decryption Complete!{Colors.END}")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"  📥 Input:  {Colors.CYAN}{file_path}{Colors.END} ({os.path.getsize(file_path):,} bytes)")
        print(f"  📤 Output: {Colors.CYAN}{output_file}{Colors.END} ({len(original_data):,} bytes)")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}")
        return output_file

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    # Get terminal width
    term_width = shutil.get_terminal_size().columns
    term_width = min(term_width, 80)
    
    print(f"\n{Colors.CYAN}{'═' * term_width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  🔒 DFEP - Deep File Encryption Protocol v1{Colors.END}")
    print(f"{Colors.DIM}  {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    print(f"{Colors.CYAN}{'═' * term_width}{Colors.END}")
    
    if len(sys.argv) < 2:
        print(f"\n{Colors.BOLD}Usage:{Colors.END}")
        print(f"  {Colors.CYAN}python dfep.py -e <file_path>{Colors.END}  {Colors.DIM}(Encrypt){Colors.END}")
        print(f"  {Colors.CYAN}python dfep.py -d <file_path>{Colors.END}  {Colors.DIM}(Decrypt){Colors.END}")
        print(f"\n{Colors.BOLD}Examples:{Colors.END}")
        print(f"  {Colors.DIM}python dfep.py -e document.txt{Colors.END}")
        print(f"  {Colors.DIM}python dfep.py -d document.dfep{Colors.END}")
        sys.exit(1)
    
    mode = sys.argv[1]
    if len(sys.argv) < 3:
        print(f"{Colors.RED}✗{Colors.END} Please specify file path")
        sys.exit(1)
    
    file_path = sys.argv[2]
    
    if not os.path.exists(file_path):
        print(f"{Colors.RED}✗{Colors.END} File not found: {Colors.CYAN}{file_path}{Colors.END}")
        sys.exit(1)
    
    dfep = OptimizedDFEP()
    start_time = time.time()
    
    if mode == '-e':
        print(f"\n{Colors.BOLD}🔐 Encryption Mode{Colors.END}")
        print(f"{Colors.DIM}{'─' * term_width}{Colors.END}")
        
        while True:
            password = getpass.getpass(f"{Colors.BOLD}Enter dfepk password:{Colors.END} ")
            confirm = getpass.getpass(f"{Colors.BOLD}Confirm password:{Colors.END} ")
            if password == confirm:
                break
            print(f"{Colors.RED}✗{Colors.END} Passwords don't match. Please try again.")
        
        if len(password) < 8:
            print(f"{Colors.YELLOW}⚠{Colors.END} Warning: Password should be at least 8 characters long.")
            if input(f"Continue anyway? {Colors.DIM}(y/n){Colors.END}: ").lower() != 'y':
                sys.exit(1)
        
        try:
            dfep.encrypt_file(file_path, password)
        except Exception as e:
            print(f"\n{Colors.RED}✗{Colors.END} Encryption failed: {Colors.RED}{e}{Colors.END}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    elif mode == '-d':
        print(f"\n{Colors.BOLD}🔓 Decryption Mode{Colors.END}")
        print(f"{Colors.DIM}{'─' * term_width}{Colors.END}")
        
        if not file_path.endswith('.dfep'):
            print(f"{Colors.RED}✗{Colors.END} This is not a .dfep file!")
            sys.exit(1)
        
        password = getpass.getpass(f"{Colors.BOLD}Enter dfepk password:{Colors.END} ")
        
        try:
            dfep.decrypt_file(file_path, password)
        except Exception as e:
            print(f"\n{Colors.RED}✗{Colors.END} Decryption failed: {Colors.RED}{e}{Colors.END}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    else:
        print(f"{Colors.RED}✗{Colors.END} Invalid mode. Use {Colors.CYAN}-e{Colors.END} for encrypt or {Colors.CYAN}-d{Colors.END} for decrypt.")
        sys.exit(1)
    
    elapsed = time.time() - start_time
    print(f"\n{Colors.DIM}⏱️  Total time: {elapsed:.2f} seconds{Colors.END}")
    print(f"{Colors.CYAN}{'═' * term_width}{Colors.END}\n")

if __name__ == "__main__":
    main()
