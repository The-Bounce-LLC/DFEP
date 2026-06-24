#!/usr/bin/env python3
# worker.py - Parallel processing worker module for DFEP (Android Compatible)

import os
import sys
import multiprocessing as mp
from multiprocessing import Pool, Queue, Process
import threading
import queue
import time
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict, Any, Callable
import struct

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
        def spin():
            idx = 0
            while self.running:
                elapsed = time.time() - self.start_time
                elapsed_str = f"{elapsed:.1f}s"
                print(f'\r{Colors.CYAN}{self.spinner_chars[idx % len(self.spinner_chars)]}{Colors.END} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END}', end='', flush=True)
                idx += 1
                time.sleep(0.08)
        self.thread = threading.Thread(target=spin)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self, success=True, result=None):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
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

# Try to import for better performance
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import numba
    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False

# Check if we're on Android/Termux
IS_ANDROID = 'ANDROID_ROOT' in os.environ or 'TERMUX' in os.environ

# Global reference to FastAES class
_FAST_AES_CLASS = None

def set_fast_aes_class(fast_aes_class):
    """Set the FastAES class for use in worker functions"""
    global _FAST_AES_CLASS
    _FAST_AES_CLASS = fast_aes_class

def get_fast_aes():
    """Get the FastAES class"""
    global _FAST_AES_CLASS
    if _FAST_AES_CLASS is None:
        # Try to import from dfep
        try:
            from dfep import FastAES
            _FAST_AES_CLASS = FastAES
        except ImportError:
            try:
                from FastAES import FastAES
                _FAST_AES_CLASS = FastAES
            except ImportError:
                raise ImportError("FastAES module not found. Please ensure FastAES is available.")
    return _FAST_AES_CLASS

@dataclass
class WorkResult:
    """Result from a worker task"""
    success: bool
    data: Optional[bytes] = None
    error: Optional[str] = None
    worker_id: int = 0
    processed_bytes: int = 0

def double_warp_chunk(data: bytes, key: str, reverse: bool = False) -> bytes:
    """Double warp processing for a single chunk"""
    key_bytes = key.encode('utf-8')
    if len(key_bytes) == 0:
        return data
    
    data_array = bytearray(data)
    data_len = len(data_array)
    key_len = len(key_bytes)
    
    if not reverse:
        # Forward warp
        for i in range(data_len):
            data_array[i] ^= key_bytes[i % key_len]
        for i in range(data_len):
            data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
    else:
        # Reverse warp
        for i in range(data_len):
            data_array[i] ^= key_bytes[(data_len - i - 1) % key_len]
        for i in range(data_len):
            data_array[i] ^= key_bytes[i % key_len]
    
    return bytes(data_array)

def aes_encrypt_chunk(data: bytes, aes_key: bytes, iv: bytes, block_offset: int = 0) -> bytes:
    """AES encryption for a chunk (CBC mode with offset support)"""
    try:
        FastAES = get_fast_aes()
    except ImportError as e:
        raise ImportError(f"FastAES module not found: {e}")
    
    aes = FastAES(aes_key)
    
    # Pad the data
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    
    result = bytearray()
    
    # For CBC mode with offset, we need to handle the IV properly
    if block_offset > 0:
        prev_block = bytearray(iv)
        # Skip to the correct position
        for i in range(0, min(block_offset * 16, len(padded)), 16):
            block = padded[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = aes._encrypt_block(xored)
            prev_block = bytearray(encrypted)
        
        # Now process the actual chunk
        start_idx = block_offset * 16
        for i in range(start_idx, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = aes._encrypt_block(xored)
            result.extend(encrypted)
            prev_block = bytearray(encrypted)
    else:
        # Normal CBC mode
        prev_block = bytearray(iv)
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = aes._encrypt_block(xored)
            result.extend(encrypted)
            prev_block = bytearray(encrypted)
    
    return bytes(result)

def aes_decrypt_chunk(data: bytes, aes_key: bytes, iv: bytes, block_offset: int = 0) -> bytes:
    """AES decryption for a chunk (CBC mode with offset support)"""
    try:
        FastAES = get_fast_aes()
    except ImportError as e:
        raise ImportError(f"FastAES module not found: {e}")
    
    aes = FastAES(aes_key)
    
    result = bytearray()
    
    if block_offset > 0:
        prev_block = bytearray(iv)
        # Skip to the correct position
        for i in range(0, min(block_offset * 16, len(data)), 16):
            block = data[i:i+16]
            decrypted = aes._decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            prev_block = bytearray(block)
        
        # Now process the actual chunk
        start_idx = block_offset * 16
        for i in range(start_idx, len(data), 16):
            block = data[i:i+16]
            decrypted = aes._decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            result.extend(xored)
            prev_block = bytearray(block)
    else:
        # Normal CBC mode
        prev_block = bytearray(iv)
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            decrypted = aes._decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            result.extend(xored)
            prev_block = bytearray(block)
    
    return bytes(result)

def derive_key_chunk(data: bytes, password: str, salt: bytes, iterations: int) -> bytes:
    """Key derivation for a chunk (used for parallel processing)"""
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
    
    return pbkdf2_hmac_sha512(password_bytes, salt, iterations, 32)

# Optimized versions using NumPy if available and not on Android
if HAS_NUMPY and not IS_ANDROID:
    def double_warp_numpy(data: bytes, key: str, reverse: bool = False) -> bytes:
        """NumPy-optimized double warp"""
        if len(data) < 1024:
            return double_warp_chunk(data, key, reverse)
        
        key_bytes = key.encode('utf-8')
        if len(key_bytes) == 0:
            return data
        
        data_array = np.frombuffer(data, dtype=np.uint8)
        key_array = np.frombuffer(key_bytes * (len(data) // len(key_bytes) + 1), dtype=np.uint8)[:len(data)]
        
        if not reverse:
            # Forward warp
            data_array ^= key_array
            # Reverse warp
            key_reversed = key_array[::-1]
            data_array ^= key_reversed
        else:
            # Reverse warp (opposite order)
            key_reversed = key_array[::-1]
            data_array ^= key_reversed
            data_array ^= key_array
        
        return data_array.tobytes()

if HAS_NUMBA and not IS_ANDROID:
    @numba.jit(nopython=True)
    def double_warp_jit(data, key_bytes, reverse):
        """JIT-compiled double warp for speed"""
        data_len = len(data)
        key_len = len(key_bytes)
        
        if not reverse:
            # Forward warp
            for i in range(data_len):
                data[i] ^= key_bytes[i % key_len]
            for i in range(data_len):
                data[i] ^= key_bytes[(data_len - i - 1) % key_len]
        else:
            # Reverse warp
            for i in range(data_len):
                data[i] ^= key_bytes[(data_len - i - 1) % key_len]
            for i in range(data_len):
                data[i] ^= key_bytes[i % key_len]
        
        return data
    
    def double_warp_numba(data: bytes, key: str, reverse: bool = False) -> bytes:
        """Numba-optimized double warp"""
        key_bytes = key.encode('utf-8')
        if len(key_bytes) == 0:
            return data
        
        data_array = bytearray(data)
        result = double_warp_jit(data_array, key_bytes, reverse)
        return bytes(result)

# Fallback for Android - use threading instead of multiprocessing
class ThreadWorker:
    """Thread-based worker for Android compatibility"""
    
    def __init__(self, num_workers=None):
        if num_workers is None:
            self.num_workers = 2  # Limit threads on Android
        else:
            self.num_workers = num_workers
        self.chunk_size = 512 * 1024  # 512KB chunks for Android
    
    def process_parallel(self, data: bytes, process_func: Callable, *args, **kwargs) -> bytes:
        """Process data using threads (Android compatible)"""
        if len(data) < self.chunk_size * 2:
            return process_func(data, *args, **kwargs)
        
        # Calculate number of chunks
        num_chunks = (len(data) + self.chunk_size - 1) // self.chunk_size
        results = [None] * num_chunks
        threads = []
        
        def worker(chunk_idx, chunk_data, offset, func, *func_args):
            try:
                # For AES with offset, pass the offset
                if func.__name__ in ['aes_encrypt_chunk', 'aes_decrypt_chunk']:
                    block_offset = offset // 16
                    result = func(chunk_data, *func_args, block_offset)
                else:
                    result = func(chunk_data, *func_args)
                results[chunk_idx] = (chunk_idx, result)
            except Exception as e:
                results[chunk_idx] = (chunk_idx, None)
                print(f"{Colors.RED}✗{Colors.END} Thread {chunk_idx} failed: {e}")
        
        # Create and start threads
        for i in range(num_chunks):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(data))
            chunk_data = data[start:end]
            
            t = threading.Thread(
                target=worker,
                args=(i, chunk_data, start, process_func) + args
            )
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete with timeout
        for t in threads:
            t.join(timeout=30)  # 30 second timeout
        
        # Check for any failed threads
        for i, result in enumerate(results):
            if result is None:
                # If a thread failed, fall back to single-threaded
                print(f"{Colors.YELLOW}⚠{Colors.END} Thread {i} timed out, falling back to single-threaded")
                return process_func(data, *args, **kwargs)
        
        # Reassemble results
        result_data = bytearray()
        for _, chunk_result in sorted(results):
            if chunk_result is not None:
                result_data.extend(chunk_result)
        
        return bytes(result_data)

class WorkerManager:
    """Manages worker processes for the DFEP tool"""
    
    def __init__(self, num_workers: Optional[int] = None):
        if IS_ANDROID:
            # On Android, use threads instead of processes
            self.use_processes = False
            self.num_workers = 2
            self.chunk_size = 512 * 1024
            self.thread_worker = ThreadWorker(self.num_workers)
        else:
            self.use_processes = True
            if num_workers is None:
                try:
                    self.num_workers = min(mp.cpu_count(), 4)  # Limit to 4 workers
                except:
                    self.num_workers = 2
            else:
                self.num_workers = num_workers
            self.chunk_size = 1024 * 1024  # 1MB chunks
        
        self.batch_mode = False
        
    def process_data_parallel(self, data: bytes, process_func: Callable, *args, **kwargs) -> bytes:
        """Process data using parallel workers"""
        if not self.use_processes or len(data) < self.chunk_size * 2:
            # Use thread-based processing on Android or for small data
            return self.thread_worker.process_parallel(data, process_func, *args, **kwargs)
        
        try:
            # Try process-based parallelization
            chunks = []
            for i in range(0, len(data), self.chunk_size):
                chunk = data[i:i+self.chunk_size]
                chunks.append((i // self.chunk_size, chunk, i))
            
            # Create a pool
            with Pool(processes=self.num_workers) as pool:
                tasks = []
                for chunk_idx, chunk_data, offset in chunks:
                    if process_func.__name__ in ['aes_encrypt_chunk', 'aes_decrypt_chunk']:
                        block_offset = offset // 16
                        task = (chunk_data, chunk_idx, process_func.__name__, block_offset) + args
                    else:
                        task = (chunk_data, chunk_idx, process_func.__name__) + args
                    tasks.append(task)
                
                results = pool.map(process_func_with_metadata, tasks)
            
            # Reassemble data
            result_data = bytearray()
            for chunk_id, chunk_result in sorted(results):
                if chunk_result is not None:
                    result_data.extend(chunk_result)
            
            return bytes(result_data)
            
        except Exception as e:
            # Fallback to thread-based processing
            print(f"{Colors.YELLOW}⚠{Colors.END} Process-based parallelization failed: {e}")
            print(f"{Colors.DIM}   • Using thread-based processing{Colors.END}")
            return self.thread_worker.process_parallel(data, process_func, *args, **kwargs)
    
    def encrypt_parallel(self, data: bytes, aes_key: bytes, iv: bytes) -> bytes:
        """Parallel encryption"""
        return self.process_data_parallel(data, aes_encrypt_chunk, aes_key, iv)
    
    def decrypt_parallel(self, data: bytes, aes_key: bytes, iv: bytes) -> bytes:
        """Parallel decryption"""
        return self.process_data_parallel(data, aes_decrypt_chunk, aes_key, iv)
    
    def double_warp_parallel(self, data: bytes, key: str, reverse: bool = False) -> bytes:
        """Parallel double warping"""
        return self.process_data_parallel(data, double_warp_chunk, key, reverse)
    
    def derive_key_parallel(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Parallel key derivation using chunks"""
        # On Android, use single-threaded for key derivation
        if IS_ANDROID:
            return self._derive_key_single(password, salt, iterations)
        
        try:
            password_bytes = password.encode('utf-8')
            dklen = 32
            
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
                
                # Use processes for blocks if available
                if self.use_processes:
                    with Pool(processes=self.num_workers) as pool:
                        blocks = pool.map(F, range(1, block_count + 1))
                else:
                    blocks = [F(i) for i in range(1, block_count + 1)]
                
                return b''.join(blocks)[:dklen]
            
            return pbkdf2_hmac_sha512(password_bytes, salt, iterations, dklen)
        except:
            return self._derive_key_single(password, salt, iterations)
    
    def _derive_key_single(self, password: str, salt: bytes, iterations: int) -> bytes:
        """Single-threaded key derivation"""
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
        
        return pbkdf2_hmac_sha512(password_bytes, salt, iterations, 32)

def process_func_with_metadata(args) -> Tuple[int, bytes]:
    """Wrapper for processing functions with metadata"""
    chunk_data = args[0]
    chunk_id = args[1]
    func_name = args[2]
    extra_args = args[3:]
    
    if func_name == 'double_warp_chunk':
        key = extra_args[0]
        reverse = extra_args[1] if len(extra_args) > 1 else False
        result = double_warp_chunk(chunk_data, key, reverse)
    elif func_name == 'aes_encrypt_chunk':
        aes_key = extra_args[0]
        iv = extra_args[1]
        block_offset = extra_args[2] if len(extra_args) > 2 else 0
        result = aes_encrypt_chunk(chunk_data, aes_key, iv, block_offset)
    elif func_name == 'aes_decrypt_chunk':
        aes_key = extra_args[0]
        iv = extra_args[1]
        block_offset = extra_args[2] if len(extra_args) > 2 else 0
        result = aes_decrypt_chunk(chunk_data, aes_key, iv, block_offset)
    else:
        raise ValueError(f"Unknown function: {func_name}")
    
    return chunk_id, result

# Exported API for the main script
class WorkAPI:
    """Main API for the work module"""
    
    def __init__(self):
        self.manager = WorkerManager()
        self.use_numpy = HAS_NUMPY and not IS_ANDROID
        self.use_numba = HAS_NUMBA and not IS_ANDROID
        self.is_android = IS_ANDROID
        self.fast_aes_class = None
        
    def set_fast_aes_class(self, fast_aes_class):
        """Set the FastAES class for use in worker functions"""
        self.fast_aes_class = fast_aes_class
        set_fast_aes_class(fast_aes_class)
        
    def get_worker_info(self) -> Dict[str, Any]:
        """Get information about available workers and optimizations"""
        return {
            'num_workers': self.manager.num_workers,
            'chunk_size': self.manager.chunk_size,
            'use_numpy': self.use_numpy,
            'use_numba': self.use_numba,
            'is_android': self.is_android,
            'use_processes': self.manager.use_processes,
            'cpu_count': mp.cpu_count() if not IS_ANDROID else 1,
            'total_memory': self._get_total_memory()
        }
    
    def _get_total_memory(self) -> int:
        """Get total system memory in bytes"""
        try:
            import psutil
            return psutil.virtual_memory().total
        except:
            return 0
    
    def process_parallel(self, data: bytes, process_type: str, *args, **kwargs) -> bytes:
        """Main parallel processing interface"""
        if process_type == 'double_warp':
            key = args[0] if args else ''
            reverse = kwargs.get('reverse', False)
            
            # Use optimized version if available and not on Android
            if not self.is_android:
                if HAS_NUMBA and len(data) > 1024:
                    try:
                        return double_warp_numba(data, key, reverse)
                    except:
                        pass
                elif HAS_NUMPY and len(data) > 1024:
                    try:
                        return double_warp_numpy(data, key, reverse)
                    except:
                        pass
            
            # Fallback to parallel or single-threaded
            return self.manager.double_warp_parallel(data, key, reverse)
        
        elif process_type == 'aes_encrypt':
            aes_key = args[0] if args else b''
            iv = args[1] if len(args) > 1 else b'\x00' * 16
            return self.manager.encrypt_parallel(data, aes_key, iv)
        
        elif process_type == 'aes_decrypt':
            aes_key = args[0] if args else b''
            iv = args[1] if len(args) > 1 else b'\x00' * 16
            return self.manager.decrypt_parallel(data, aes_key, iv)
        
        elif process_type == 'derive_key':
            password = args[0] if args else ''
            salt = args[1] if len(args) > 1 else b''
            iterations = kwargs.get('iterations', 100000)
            return self.manager.derive_key_parallel(password, salt, iterations)
        
        else:
            raise ValueError(f"Unknown process type: {process_type}")
    
    def benchmark(self, data_size: int = 10 * 1024 * 1024) -> Dict[str, float]:
        """Benchmark the parallel processing performance"""
        import time
        
        # Generate test data
        test_data = secrets.token_bytes(data_size)
        key = "test_key_1234567890"
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        results = {}
        
        # Benchmark double warp
        start = time.time()
        self.process_parallel(test_data, 'double_warp', key)
        results['double_warp'] = time.time() - start
        
        # Benchmark AES encryption
        start = time.time()
        self.process_parallel(test_data, 'aes_encrypt', aes_key, iv)
        results['aes_encrypt'] = time.time() - start
        
        # Benchmark AES decryption
        start = time.time()
        self.process_parallel(test_data, 'aes_decrypt', aes_key, iv)
        results['aes_decrypt'] = time.time() - start
        
        return results

# Singleton instance
_work_api = None

def get_work_api() -> WorkAPI:
    """Get the singleton WorkAPI instance"""
    global _work_api
    if _work_api is None:
        _work_api = WorkAPI()
    return _work_api

def optimize_for_file_size(file_size: int) -> Dict[str, Any]:
    """Get optimization suggestions based on file size"""
    if IS_ANDROID:
        # Android optimized settings
        if file_size < 1024 * 1024:  # < 1MB
            return {
                'use_parallel': False,
                'chunk_size': 256 * 1024,
                'num_workers': 1,
                'suggestion': 'Single-threaded processing for small files (Android)'
            }
        elif file_size < 50 * 1024 * 1024:  # < 50MB
            return {
                'use_parallel': True,
                'chunk_size': 512 * 1024,
                'num_workers': 2,
                'suggestion': 'Thread-based processing for medium files (Android)'
            }
        else:  # > 50MB
            return {
                'use_parallel': True,
                'chunk_size': 1024 * 1024,
                'num_workers': 2,
                'suggestion': 'Thread-based processing for large files (Android)'
            }
    else:
        # Desktop optimized settings
        if file_size < 1024 * 1024:  # < 1MB
            return {
                'use_parallel': False,
                'chunk_size': 1024 * 1024,
                'num_workers': 1,
                'suggestion': 'Single-threaded processing for small files'
            }
        elif file_size < 100 * 1024 * 1024:  # < 100MB
            return {
                'use_parallel': True,
                'chunk_size': 1024 * 1024,
                'num_workers': min(mp.cpu_count(), 4),
                'suggestion': 'Moderate parallelism for medium files'
            }
        else:  # > 100MB
            return {
                'use_parallel': True,
                'chunk_size': 4 * 1024 * 1024,  # 4MB chunks
                'num_workers': min(mp.cpu_count(), 8),
                'suggestion': 'Aggressive parallelism for large files'
            }

# Export all necessary classes and functions
__all__ = [
    'Colors',
    'Spinner',
    'ProgressBar',
    'WorkAPI',
    'WorkerManager',
    'get_work_api',
    'optimize_for_file_size',
    'IS_ANDROID',
    'set_fast_aes_class',
    'get_fast_aes'
]

if __name__ == "__main__":
    # Test functionality
    print(f"{Colors.GREEN}DFEP Worker Module Initialized{Colors.END}")
    api = get_work_api()
    info = api.get_worker_info()
    print(f"Workers: {info['num_workers']}")
    print(f"NumPy: {info['use_numpy']}")
    print(f"Numba: {info['use_numba']}")
    print(f"Android: {info['is_android']}")
    print(f"Use Processes: {info['use_processes']}")