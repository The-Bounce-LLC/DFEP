#!/usr/bin/env python3

import os
import base64
import hashlib
import json
import secrets
import hmac
import time
import subprocess
import sys
import importlib.util
import zlib
import struct
from progress import Colors, ProgressBar, Spinner

# Dynamic import for class.py
spec = importlib.util.spec_from_file_location("class_module", os.path.join(os.path.dirname(__file__), "class.py"))
class_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(class_module)
FastAES = class_module.FastAES
RSA = class_module.RSA

class SystemOptimizer:
    """Auto-detects and applies system optimizations"""
    
    @staticmethod
    def get_optimal_settings():
        """Get optimal settings for current system"""
        is_android = 'ANDROID_ROOT' in os.environ or 'TERMUX' in os.environ
        
        try:
            import multiprocessing as mp
            cpu_count = mp.cpu_count()
        except:
            cpu_count = 1
        
        # Simple settings that work everywhere
        return {
            'workers': min(4, cpu_count) if not is_android else 1,  # Single thread on Android
            'chunk_size': 65536,  # 64KB - optimal for most systems
            'is_android': is_android,
            'cpu_count': cpu_count,
            'memory_gb': 1.0,  # Default
        }

class OptimizedDFEP:
    def __init__(self):
        self.dfepk = None
        self.file_extension = None
        self.key_file = ".dfep_key"
        self.salt_size = 32
        self.iv_size = 16
        self.aes_key_size = 32
        self.opt = SystemOptimizer.get_optimal_settings()
        
    def derive_aes_key(self, password, salt):
        """Fast key derivation"""
        password_bytes = password.encode('utf-8')
        iterations = 50000 if self.opt['is_android'] else 100000
        
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
        
        pb = ProgressBar(iterations, prefix='Key:', suffix='PBKDF2', length=15)
        key = pbkdf2_hmac_sha512(password_bytes, salt, iterations, self.aes_key_size)
        pb.update(iterations)
        return key
    
    def double_warp(self, data, key, reverse=False):
        """Simple fast double warp"""
        key_bytes = key.encode('utf-8')
        if len(key_bytes) == 0:
            return data
        
        data_array = bytearray(data)
        data_len = len(data_array)
        key_len = len(key_bytes)
        chunk = self.opt['chunk_size']
        
        if not reverse:
            pb = ProgressBar(data_len, prefix='Warp:', suffix=f'{data_len//1024}KB', length=20, color=Colors.YELLOW)
            for start in range(0, data_len, chunk):
                end = min(start + chunk, data_len)
                for i in range(start, end):
                    data_array[i] ^= key_bytes[i % key_len]
                pb.update(end)
            
            for start in range(0, data_len, chunk):
                end = min(start + chunk, data_len)
                for i in range(start, end):
                    data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
                # Don't re-show progress for second pass
        else:
            pb = ProgressBar(data_len, prefix='Unwarp:', suffix=f'{data_len//1024}KB', length=20, color=Colors.YELLOW)
            for start in range(0, data_len, chunk):
                end = min(start + chunk, data_len)
                for i in range(start, end):
                    data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
                pb.update(end)
            
            for start in range(0, data_len, chunk):
                end = min(start + chunk, data_len)
                for i in range(start, end):
                    data_array[i] ^= key_bytes[i % key_len]
        
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
        
        print(f"{Colors.GREEN}✓{Colors.END} dfepk: {Colors.CYAN}{key_path}{Colors.END}")
    
    def load_key_info(self):
        key_path = os.path.expanduser(f"~/{self.key_file}")
        if not os.path.exists(key_path):
            return None, None
        
        with open(key_path, 'r') as f:
            key_data = json.load(f)
        
        return key_data.get('key_hash'), key_data.get('extension')
    
    def overwrite_dfep_file(self, file_path):
        """Silently overwrite the .dfep file"""
        try:
            if not os.path.exists(file_path):
                return False
            with open(file_path, 'wb') as f:
                f.write(b"Invalid Data!!!")
            return True
        except:
            return False
    
    def encrypt_file(self, file_path, password):
        print(f"\n{Colors.BOLD}📁 {Colors.CYAN}{file_path}{Colors.END}")
        
        original_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        file_name, file_ext = os.path.splitext(file_path)
        self.file_extension = file_ext
        
        print(f"{Colors.DIM}Ext: {Colors.YELLOW}{file_ext}{Colors.END}  Size: {Colors.CYAN}{original_size:,}{Colors.END}")
        
        # Generate keys
        rsa_keys = RSA.generate_keypair(2048)
        private_key = rsa_keys['private']
        public_key = rsa_keys['public']
        
        salt = secrets.token_bytes(self.salt_size)
        iv = secrets.token_bytes(self.iv_size)
        
        aes_key = self.derive_aes_key(password, salt)
        
        # Warp
        print(f"\n{Colors.BOLD}🌀 Warping...{Colors.END}")
        warped_data = self.double_warp(original_data, password)
        
        salted_data = self.add_salt(warped_data, salt)
        
        # Pad
        pad_len = 16 - (len(salted_data) % 16)
        padded = salted_data + bytes([pad_len] * pad_len)
        
        # AES Encrypt (simple, fast, with progress)
        print(f"\n{Colors.BOLD}🔒 Encrypting...{Colors.END}")
        aes = FastAES(aes_key)
        
        total = len(padded) // 16
        pb = ProgressBar(total, prefix='AES:', suffix='blocks', length=20, color=Colors.GREEN)
        
        result = bytearray()
        prev = bytearray(iv)
        
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev))
            encrypted = aes._encrypt_block(xored)
            result.extend(encrypted)
            prev = bytearray(encrypted)
            
            if i % 1024 == 0:  # Update every 1024 blocks
                pb.update(i // 16)
        
        encrypted_data = bytes(result)
        pb.update(total)
        
        # Sign
        print(f"\n{Colors.BOLD}✍️  Signing...{Colors.END}")
        signature = RSA.sign(encrypted_data, private_key)
        print(f"{Colors.GREEN}✓{Colors.END} Signed: {len(signature)}B")
        
        self.save_key_info(password, file_ext)
        
        # Build package with short keys
        package = {
            's': base64.b64encode(signature).decode('utf-8'),
            'k': {'n': hex(public_key['n']), 'e': public_key['e']},
            'i': base64.b64encode(iv).decode('utf-8'),
            'a': base64.b64encode(salt).decode('utf-8'),
            'e': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        # Save with compression
        output_file = f"{file_name}.dfep"
        json_str = json.dumps(package, separators=(',', ':'))
        json_bytes = json_str.encode('utf-8')
        
        # Try zlib compression
        try:
            compressed = zlib.compress(json_bytes, 6)
            if len(compressed) < len(json_bytes) - 100:  # Worth it
                with open(output_file, 'wb') as f:
                    f.write(b'DFEP')
                    f.write(struct.pack('B', 1))
                    f.write(struct.pack('>I', len(json_bytes)))
                    f.write(compressed)
                final_size = os.path.getsize(output_file)
                print(f"\n{Colors.GREEN}✓{Colors.END} Compressed: {len(json_bytes):,} → {final_size:,} bytes")
            else:
                with open(output_file, 'w') as f:
                    f.write(json_str)
                final_size = os.path.getsize(output_file)
        except:
            with open(output_file, 'w') as f:
                f.write(json_str)
            final_size = os.path.getsize(output_file)
        
        print(f"\n{Colors.GREEN}{'═' * 40}{Colors.END}")
        print(f"{Colors.GREEN}✓ Done!{Colors.END}")
        print(f"  Original: {original_size:,} bytes")
        print(f"  Encrypted: {final_size:,} bytes")
        
        overhead = final_size - original_size
        if overhead > 0:
            pct = (overhead / original_size) * 100
            print(f"  {Colors.DIM}Overhead: +{overhead:,} bytes ({pct:.1f}%){Colors.END}")
        
        print(f"{Colors.GREEN}{'═' * 40}{Colors.END}")
        return output_file
    
    def decrypt_file(self, file_path, password):
        print(f"\n{Colors.BOLD}📁 {Colors.CYAN}{file_path}{Colors.END}")
        
        # Read package (auto-detect format)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
            
            if header == b'DFEP':
                with open(file_path, 'rb') as f:
                    f.read(4)
                    f.read(1)  # version
                    original_size = struct.unpack('>I', f.read(4))[0]
                    compressed = f.read()
                json_bytes = zlib.decompress(compressed)
                package = json.loads(json_bytes.decode('utf-8'))
            else:
                with open(file_path, 'r') as f:
                    package = json.load(f)
        except Exception as e:
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗ Load failed: {e}{Colors.END}")
            return None
        
        # Verify password
        stored_hash, original_ext = self.load_key_info()
        if not stored_hash:
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗ No dfepk!{Colors.END}")
            return None
        
        if hashlib.sha256(password.encode('utf-8')).hexdigest() != stored_hash:
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗ Invalid dfepk!{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}✓{Colors.END} Key verified (ext: {Colors.YELLOW}{original_ext}{Colors.END})")
        
        # Parse package
        try:
            signature = base64.b64decode(package['s'])
            pk = package['k']
            public_key = {'n': int(pk['n'], 16), 'e': pk['e']}
            iv = base64.b64decode(package['i'])
            salt = base64.b64decode(package['a'])
            encrypted_data = base64.b64decode(package['e'])
        except:
            # Fallback to long keys
            try:
                signature = base64.b64decode(package.get('signature', ''))
                pk = package.get('public_key', {})
                public_key = {'n': int(pk['n'], 16) if pk['n'].startswith('0x') else int(pk['n']), 'e': pk['e']}
                iv = base64.b64decode(package.get('iv', ''))
                salt = base64.b64decode(package.get('salt', ''))
                encrypted_data = base64.b64decode(package.get('encrypted_data', ''))
            except Exception as e:
                self.overwrite_dfep_file(file_path)
                print(f"{Colors.RED}✗ Decode failed: {e}{Colors.END}")
                return None
        
        # Verify signature
        print(f"\n{Colors.BOLD}🔏 Verifying...{Colors.END}")
        if not RSA.verify(encrypted_data, signature, public_key):
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗ Bad signature!{Colors.END}")
            return None
        print(f"{Colors.GREEN}✓{Colors.END} Signature OK")
        
        # Derive key
        aes_key = self.derive_aes_key(password, salt)
        
        # Decrypt
        print(f"\n{Colors.BOLD}🔓 Decrypting...{Colors.END}")
        aes = FastAES(aes_key)
        
        total = len(encrypted_data) // 16
        pb = ProgressBar(total, prefix='AES:', suffix='blocks', length=20, color=Colors.BLUE)
        
        result = bytearray()
        prev = bytearray(iv)
        
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted = aes._decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev))
            result.extend(xored)
            prev = bytearray(block)
            
            if i % 1024 == 0:
                pb.update(i // 16)
        
        pb.update(total)
        
        # Remove padding
        try:
            pad_len = result[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError("Bad padding")
            salted_data = bytes(result[:-pad_len])
        except:
            self.overwrite_dfep_file(file_path)
            print(f"{Colors.RED}✗ Bad padding{Colors.END}")
            return None
        
        # Remove salt and unwarp
        _, warped_data = self.remove_salt(salted_data)
        
        print(f"\n{Colors.BOLD}🌀 Unwarping...{Colors.END}")
        original_data = self.double_warp(warped_data, password, reverse=True)
        
        # Save
        output_file = file_path.replace('.dfep', original_ext) if original_ext else file_path.replace('.dfep', '')
        with open(output_file, 'wb') as f:
            f.write(original_data)
        
        print(f"\n{Colors.GREEN}{'═' * 40}{Colors.END}")
        print(f"{Colors.GREEN}✓ Done!{Colors.END}  {os.path.getsize(file_path):,}B → {len(original_data):,}B")
        print(f"{Colors.GREEN}{'═' * 40}{Colors.END}")
        return output_file