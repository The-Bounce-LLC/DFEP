#!/usr/bin/env python3

import hashlib
import secrets
import time
from progress import Colors, Spinner, ProgressBar

class FastAES:
    """Optimized AES with pre-computed T-tables for encryption"""
    _sbox = None
    _inv_sbox = None
    _mix_cols_2 = None
    _mix_cols_3 = None
    _mix_cols_9 = None
    _mix_cols_11 = None
    _mix_cols_13 = None
    _mix_cols_14 = None
    
    # Pre-computed T-tables for faster encryption rounds
    _T0 = None
    _T1 = None
    _T2 = None
    _T3 = None
    _Tin0 = None
    _Tin1 = None
    _Tin2 = None
    _Tin3 = None
    
    @classmethod
    def _init_tables(cls):
        if cls._sbox is not None:
            return
            
        # S-box
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
        
        # Inverse S-box
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
        
        # Galois field multiplication tables
        def gmul(a, b):
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xFF
                if hi: a ^= 0x1b
                b >>= 1
            return p
        
        cls._mix_cols_2 = [gmul(x, 2) for x in range(256)]
        cls._mix_cols_3 = [gmul(x, 3) for x in range(256)]
        cls._mix_cols_9 = [gmul(x, 9) for x in range(256)]
        cls._mix_cols_11 = [gmul(x, 11) for x in range(256)]
        cls._mix_cols_13 = [gmul(x, 13) for x in range(256)]
        cls._mix_cols_14 = [gmul(x, 14) for x in range(256)]
        
        # Pre-compute T-tables for encryption (4KB each = 16KB total)
        # T0[x] = [2*sbox[x], sbox[x], sbox[x], 3*sbox[x]]
        # T1[x] = [3*sbox[x], 2*sbox[x], sbox[x], sbox[x]]
        # etc.
        cls._T0 = [0] * 256
        cls._T1 = [0] * 256
        cls._T2 = [0] * 256
        cls._T3 = [0] * 256
        
        for i in range(256):
            s = cls._sbox[i]
            s2 = gmul(s, 2)
            s3 = gmul(s, 3)
            
            cls._T0[i] = (s2 << 24) | (s << 16) | (s << 8) | s3
            cls._T1[i] = (s3 << 24) | (s2 << 16) | (s << 8) | s
            cls._T2[i] = (s << 24) | (s3 << 16) | (s2 << 8) | s
            cls._T3[i] = (s << 24) | (s << 16) | (s3 << 8) | s2
        
        # Pre-compute inverse T-tables
        cls._Tin0 = [0] * 256
        cls._Tin1 = [0] * 256
        cls._Tin2 = [0] * 256
        cls._Tin3 = [0] * 256
        
        for i in range(256):
            s = cls._inv_sbox[i]
            s9 = gmul(s, 9)
            s11 = gmul(s, 11)
            s13 = gmul(s, 13)
            s14 = gmul(s, 14)
            
            cls._Tin0[i] = (s14 << 24) | (s9 << 16) | (s13 << 8) | s11
            cls._Tin1[i] = (s11 << 24) | (s14 << 16) | (s9 << 8) | s13
            cls._Tin2[i] = (s13 << 24) | (s11 << 16) | (s14 << 8) | s9
            cls._Tin3[i] = (s9 << 24) | (s13 << 16) | (s11 << 8) | s14
    
    def __init__(self, key):
        self._init_tables()
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key = key
        self.Nk = len(key) // 4
        self.Nr = self.Nk + 6
        self._expand_key()
    
    def _expand_key(self):
        """Key expansion - store as 32-bit words for faster access"""
        key = list(self.key)
        Nk = self.Nk
        Nr = self.Nr
        
        RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        
        # Create word array (each word is 4 bytes)
        w = []
        for i in range(Nk):
            w.append((key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3])
        
        for i in range(Nk, 4 * (Nr + 1)):
            temp = w[i-1]
            if i % Nk == 0:
                # RotWord
                temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
                # SubWord
                temp = (self._sbox[(temp >> 24) & 0xFF] << 24) | \
                       (self._sbox[(temp >> 16) & 0xFF] << 16) | \
                       (self._sbox[(temp >> 8) & 0xFF] << 8) | \
                       self._sbox[temp & 0xFF]
                # XOR with RCON
                temp ^= (RCON[i // Nk - 1] << 24)
            elif Nk > 6 and i % Nk == 4:
                temp = (self._sbox[(temp >> 24) & 0xFF] << 24) | \
                       (self._sbox[(temp >> 16) & 0xFF] << 16) | \
                       (self._sbox[(temp >> 8) & 0xFF] << 8) | \
                       self._sbox[temp & 0xFF]
            
            w.append(w[i-Nk] ^ temp)
        
        # Store as round keys (4 words per round)
        self._round_keys = []
        for i in range(0, len(w), 4):
            self._round_keys.append(w[i:i+4])
    
    def _encrypt_block(self, plaintext):
        """Encrypt using T-tables - much faster"""
        # Load state as 32-bit words
        s0 = (plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3]
        s1 = (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7]
        s2 = (plaintext[8] << 24) | (plaintext[9] << 16) | (plaintext[10] << 8) | plaintext[11]
        s3 = (plaintext[12] << 24) | (plaintext[13] << 16) | (plaintext[14] << 8) | plaintext[15]
        
        rk = self._round_keys
        
        # Initial round
        s0 ^= rk[0][0]
        s1 ^= rk[0][1]
        s2 ^= rk[0][2]
        s3 ^= rk[0][3]
        
        # Main rounds using T-tables
        for r in range(1, self.Nr):
            t0 = self._T0[(s0 >> 24) & 0xFF] ^ self._T1[(s1 >> 16) & 0xFF] ^ self._T2[(s2 >> 8) & 0xFF] ^ self._T3[s3 & 0xFF] ^ rk[r][0]
            t1 = self._T0[(s1 >> 24) & 0xFF] ^ self._T1[(s2 >> 16) & 0xFF] ^ self._T2[(s3 >> 8) & 0xFF] ^ self._T3[s0 & 0xFF] ^ rk[r][1]
            t2 = self._T0[(s2 >> 24) & 0xFF] ^ self._T1[(s3 >> 16) & 0xFF] ^ self._T2[(s0 >> 8) & 0xFF] ^ self._T3[s1 & 0xFF] ^ rk[r][2]
            t3 = self._T0[(s3 >> 24) & 0xFF] ^ self._T1[(s0 >> 16) & 0xFF] ^ self._T2[(s1 >> 8) & 0xFF] ^ self._T3[s2 & 0xFF] ^ rk[r][3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        
        # Final round (no MixColumns)
        s0 = (self._sbox[(s0 >> 24) & 0xFF] << 24) | (self._sbox[(s1 >> 16) & 0xFF] << 16) | (self._sbox[(s2 >> 8) & 0xFF] << 8) | self._sbox[s3 & 0xFF]
        s1 = (self._sbox[(s1 >> 24) & 0xFF] << 24) | (self._sbox[(s2 >> 16) & 0xFF] << 16) | (self._sbox[(s3 >> 8) & 0xFF] << 8) | self._sbox[s0 & 0xFF]
        s2 = (self._sbox[(s2 >> 24) & 0xFF] << 24) | (self._sbox[(s3 >> 16) & 0xFF] << 16) | (self._sbox[(s0 >> 8) & 0xFF] << 8) | self._sbox[s1 & 0xFF]
        s3 = (self._sbox[(s3 >> 24) & 0xFF] << 24) | (self._sbox[(s0 >> 16) & 0xFF] << 16) | (self._sbox[(s1 >> 8) & 0xFF] << 8) | self._sbox[s2 & 0xFF]
        
        s0 ^= rk[self.Nr][0]
        s1 ^= rk[self.Nr][1]
        s2 ^= rk[self.Nr][2]
        s3 ^= rk[self.Nr][3]
        
        return bytes([
            (s0 >> 24) & 0xFF, (s0 >> 16) & 0xFF, (s0 >> 8) & 0xFF, s0 & 0xFF,
            (s1 >> 24) & 0xFF, (s1 >> 16) & 0xFF, (s1 >> 8) & 0xFF, s1 & 0xFF,
            (s2 >> 24) & 0xFF, (s2 >> 16) & 0xFF, (s2 >> 8) & 0xFF, s2 & 0xFF,
            (s3 >> 24) & 0xFF, (s3 >> 16) & 0xFF, (s3 >> 8) & 0xFF, s3 & 0xFF,
        ])
    
    def _decrypt_block(self, ciphertext):
        """Decrypt using inverse T-tables"""
        s0 = (ciphertext[0] << 24) | (ciphertext[1] << 16) | (ciphertext[2] << 8) | ciphertext[3]
        s1 = (ciphertext[4] << 24) | (ciphertext[5] << 16) | (ciphertext[6] << 8) | ciphertext[7]
        s2 = (ciphertext[8] << 24) | (ciphertext[9] << 16) | (ciphertext[10] << 8) | ciphertext[11]
        s3 = (ciphertext[12] << 24) | (ciphertext[13] << 16) | (ciphertext[14] << 8) | ciphertext[15]
        
        rk = self._round_keys
        Nr = self.Nr
        
        # Initial round
        s0 ^= rk[Nr][0]
        s1 ^= rk[Nr][1]
        s2 ^= rk[Nr][2]
        s3 ^= rk[Nr][3]
        
        # Main rounds using inverse T-tables
        for r in range(Nr - 1, 0, -1):
            t0 = self._Tin0[(s0 >> 24) & 0xFF] ^ self._Tin1[(s3 >> 16) & 0xFF] ^ self._Tin2[(s2 >> 8) & 0xFF] ^ self._Tin3[s1 & 0xFF] ^ rk[r][0]
            t1 = self._Tin0[(s1 >> 24) & 0xFF] ^ self._Tin1[(s0 >> 16) & 0xFF] ^ self._Tin2[(s3 >> 8) & 0xFF] ^ self._Tin3[s2 & 0xFF] ^ rk[r][1]
            t2 = self._Tin0[(s2 >> 24) & 0xFF] ^ self._Tin1[(s1 >> 16) & 0xFF] ^ self._Tin2[(s0 >> 8) & 0xFF] ^ self._Tin3[s3 & 0xFF] ^ rk[r][2]
            t3 = self._Tin0[(s3 >> 24) & 0xFF] ^ self._Tin1[(s2 >> 16) & 0xFF] ^ self._Tin2[(s1 >> 8) & 0xFF] ^ self._Tin3[s0 & 0xFF] ^ rk[r][3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        
        # Final round
        s0 = (self._inv_sbox[(s0 >> 24) & 0xFF] << 24) | (self._inv_sbox[(s3 >> 16) & 0xFF] << 16) | (self._inv_sbox[(s2 >> 8) & 0xFF] << 8) | self._inv_sbox[s1 & 0xFF]
        s1 = (self._inv_sbox[(s1 >> 24) & 0xFF] << 24) | (self._inv_sbox[(s0 >> 16) & 0xFF] << 16) | (self._inv_sbox[(s3 >> 8) & 0xFF] << 8) | self._inv_sbox[s2 & 0xFF]
        s2 = (self._inv_sbox[(s2 >> 24) & 0xFF] << 24) | (self._inv_sbox[(s1 >> 16) & 0xFF] << 16) | (self._inv_sbox[(s0 >> 8) & 0xFF] << 8) | self._inv_sbox[s3 & 0xFF]
        s3 = (self._inv_sbox[(s3 >> 24) & 0xFF] << 24) | (self._inv_sbox[(s2 >> 16) & 0xFF] << 16) | (self._inv_sbox[(s1 >> 8) & 0xFF] << 8) | self._inv_sbox[s0 & 0xFF]
        
        s0 ^= rk[0][0]
        s1 ^= rk[0][1]
        s2 ^= rk[0][2]
        s3 ^= rk[0][3]
        
        return bytes([
            (s0 >> 24) & 0xFF, (s0 >> 16) & 0xFF, (s0 >> 8) & 0xFF, s0 & 0xFF,
            (s1 >> 24) & 0xFF, (s1 >> 16) & 0xFF, (s1 >> 8) & 0xFF, s1 & 0xFF,
            (s2 >> 24) & 0xFF, (s2 >> 16) & 0xFF, (s2 >> 8) & 0xFF, s2 & 0xFF,
            (s3 >> 24) & 0xFF, (s3 >> 16) & 0xFF, (s3 >> 8) & 0xFF, s3 & 0xFF,
        ])

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