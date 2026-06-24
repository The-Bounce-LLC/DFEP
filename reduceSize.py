#!/usr/bin/env python3
# reduceSize.py - File size reduction for DFEP encrypted files

import os
import sys
import json
import base64
import zlib
import lzma
import bz2
import gzip
import time
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

# ANSI color codes for consistent output
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

class SizeReducer:
    """Handles size reduction for DFEP files through compression and optimization"""
    
    def __init__(self):
        self.compression_algorithms = {
            'zlib': {
                'compress': self._compress_zlib,
                'decompress': self._decompress_zlib,
                'extension': '.zlib',
                'name': 'ZLIB (Fast)'
            },
            'gzip': {
                'compress': self._compress_gzip,
                'decompress': self._decompress_gzip,
                'extension': '.gz',
                'name': 'GZIP (Balanced)'
            },
            'bz2': {
                'compress': self._compress_bz2,
                'decompress': self._decompress_bz2,
                'extension': '.bz2',
                'name': 'BZ2 (High)'
            },
            'lzma': {
                'compress': self._compress_lzma,
                'decompress': self._decompress_lzma,
                'extension': '.xz',
                'name': 'LZMA (Maximum)'
            }
        }
        
        self.optimization_levels = {
            'fast': {'level': 1, 'description': 'Fastest compression'},
            'balanced': {'level': 6, 'description': 'Balanced speed/compression'},
            'maximum': {'level': 9, 'description': 'Maximum compression'}
        }
    
    def _compress_zlib(self, data: bytes, level: int = 6) -> bytes:
        """Compress using zlib"""
        return zlib.compress(data, level)
    
    def _decompress_zlib(self, data: bytes) -> bytes:
        """Decompress using zlib"""
        return zlib.decompress(data)
    
    def _compress_gzip(self, data: bytes, level: int = 6) -> bytes:
        """Compress using gzip"""
        return gzip.compress(data, compresslevel=level)
    
    def _decompress_gzip(self, data: bytes) -> bytes:
        """Decompress using gzip"""
        return gzip.decompress(data)
    
    def _compress_bz2(self, data: bytes, level: int = 6) -> bytes:
        """Compress using bz2"""
        return bz2.compress(data, compresslevel=level)
    
    def _decompress_bz2(self, data: bytes) -> bytes:
        """Decompress using bz2"""
        return bz2.decompress(data)
    
    def _compress_lzma(self, data: bytes, level: int = 6) -> bytes:
        """Compress using LZMA"""
        return lzma.compress(data, preset=level)
    
    def _decompress_lzma(self, data: bytes) -> bytes:
        """Decompress using LZMA"""
        return lzma.decompress(data)
    
    def analyze_data(self, data: bytes) -> Dict[str, Any]:
        """Analyze data for best compression strategy"""
        # Calculate entropy
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        data_len = len(data)
        entropy = 0
        for count in byte_counts.values():
            prob = count / data_len
            entropy -= prob * (prob.bit_length() - 1 if prob > 0 else 0)
        
        # Check for patterns
        unique_bytes = len(byte_counts)
        diversity_ratio = unique_bytes / 256
        
        return {
            'size': data_len,
            'entropy': entropy,
            'unique_bytes': unique_bytes,
            'diversity_ratio': diversity_ratio,
            'compression_potential': 'High' if diversity_ratio < 0.5 else 'Medium' if diversity_ratio < 0.75 else 'Low'
        }
    
    def select_best_algorithm(self, data: bytes) -> Tuple[str, Dict[str, Any]]:
        """Select the best compression algorithm for the data"""
        analysis = self.analyze_data(data)
        
        # Test compression with small sample
        sample = data[:min(10240, len(data))]  # First 10KB sample
        
        results = {}
        for algo_name, algo_info in self.compression_algorithms.items():
            try:
                start = time.time()
                compressed = algo_info['compress'](sample)
                compression_time = time.time() - start
                
                compression_ratio = len(compressed) / len(sample) if len(sample) > 0 else 1
                
                results[algo_name] = {
                    'compression_ratio': compression_ratio,
                    'time': compression_time,
                    'size_reduction': (1 - compression_ratio) * 100
                }
            except Exception as e:
                results[algo_name] = {
                    'compression_ratio': 1,
                    'time': float('inf'),
                    'size_reduction': 0,
                    'error': str(e)
                }
        
        # Score algorithms based on ratio and time
        best_algo = None
        best_score = float('inf')
        
        for algo_name, result in results.items():
            if result['compression_ratio'] < 1:
                # Score = weighted combination of ratio and time
                score = (result['compression_ratio'] * 0.7) + (result['time'] * 0.3 / len(sample))
                if score < best_score:
                    best_score = score
                    best_algo = algo_name
        
        if best_algo is None:
            best_algo = 'zlib'  # Default fallback
        
        return best_algo, {
            'analysis': analysis,
            'sample_results': results,
            'selected': best_algo,
            'expected_ratio': results[best_algo]['compression_ratio']
        }
    
    def compress_dfep_file(self, file_path: str, algorithm: Optional[str] = None, 
                          level: str = 'balanced', keep_original: bool = True) -> Optional[str]:
        """
        Compress a DFEP file to reduce its size
        
        Args:
            file_path: Path to the .dfep file
            algorithm: Compression algorithm to use (None for auto-select)
            level: Compression level ('fast', 'balanced', 'maximum')
            keep_original: Keep the original file after compression
        
        Returns:
            Path to compressed file or None if failed
        """
        try:
            # Read the DFEP file
            with open(file_path, 'r') as f:
                dfep_data = json.load(f)
            
            file_size = os.path.getsize(file_path)
            print(f"\n{Colors.BOLD}📦 Analyzing: {Colors.CYAN}{file_path}{Colors.END}")
            print(f"{Colors.DIM}   • Original size: {file_size:,} bytes{Colors.END}")
            
            # Convert to JSON string for compression
            json_str = json.dumps(dfep_data, separators=(',', ':'))
            json_bytes = json_str.encode('utf-8')
            
            print(f"{Colors.DIM}   • JSON size: {len(json_bytes):,} bytes{Colors.END}")
            
            # Auto-select algorithm if not specified
            if algorithm is None:
                algorithm, analysis = self.select_best_algorithm(json_bytes)
                print(f"\n{Colors.BOLD}🔍 Analysis Results:{Colors.END}")
                print(f"{Colors.DIM}   • Entropy: {analysis['analysis']['entropy']:.2f}{Colors.END}")
                print(f"{Colors.DIM}   • Diversity: {analysis['analysis']['diversity_ratio']:.2%}{Colors.END}")
                print(f"{Colors.GREEN}   • Auto-selected: {self.compression_algorithms[algorithm]['name']}{Colors.END}")
            
            # Get compression function
            algo_info = self.compression_algorithms[algorithm]
            compress_func = algo_info['compress']
            
            # Compress
            opt_level = self.optimization_levels[level]['level']
            print(f"\n{Colors.BOLD}🗜️ Compressing...{Colors.END}")
            print(f"{Colors.DIM}   • Algorithm: {algo_info['name']}{Colors.END}")
            print(f"{Colors.DIM}   • Level: {self.optimization_levels[level]['description']}{Colors.END}")
            
            start_time = time.time()
            compressed = compress_func(json_bytes, opt_level)
            compression_time = time.time() - start_time
            
            compressed_size = len(compressed)
            ratio = (compressed_size / file_size) * 100
            saved = file_size - compressed_size
            saved_percent = (saved / file_size) * 100
            
            # Create compressed file structure
            compressed_package = {
                'version': 'dfep-compressed-v1',
                'algorithm': algorithm,
                'original_size': file_size,
                'compressed_data': base64.b64encode(compressed).decode('utf-8')
            }
            
            # Save compressed file
            output_path = file_path + algo_info['extension']
            with open(output_path, 'w') as f:
                json.dump(compressed_package, f, separators=(',', ':'))
            
            final_size = os.path.getsize(output_path)
            
            print(f"\n{Colors.GREEN}{'═' * 40}{Colors.END}")
            print(f"{Colors.GREEN}✓ Compression Complete!{Colors.END}")
            print(f"{Colors.DIM}   • Original: {file_size:,} bytes{Colors.END}")
            print(f"{Colors.DIM}   • Compressed data: {compressed_size:,} bytes{Colors.END}")
            print(f"{Colors.DIM}   • Final file: {final_size:,} bytes{Colors.END}")
            print(f"{Colors.GREEN}   • Saved: {saved:,} bytes ({saved_percent:.1f}%){Colors.END}")
            print(f"{Colors.DIM}   • Time: {compression_time:.2f}s{Colors.END}")
            print(f"{Colors.GREEN}{'═' * 40}{Colors.END}")
            
            if not keep_original:
                os.remove(file_path)
                print(f"{Colors.YELLOW}   • Original removed{Colors.END}")
            
            return output_path
            
        except Exception as e:
            print(f"{Colors.RED}✗ Compression failed: {e}{Colors.END}")
            return None
    
    def decompress_dfep_file(self, file_path: str, output_path: Optional[str] = None) -> Optional[str]:
        """
        Decompress a compressed DFEP file
        
        Args:
            file_path: Path to compressed file
            output_path: Output path (None for auto-generated)
        
        Returns:
            Path to decompressed file or None if failed
        """
        try:
            print(f"\n{Colors.BOLD}📦 Decompressing: {Colors.CYAN}{file_path}{Colors.END}")
            
            # Read compressed file
            with open(file_path, 'r') as f:
                compressed_package = json.load(f)
            
            # Extract data
            algorithm = compressed_package['algorithm']
            compressed_data = base64.b64decode(compressed_package['compressed_data'])
            
            # Decompress
            algo_info = self.compression_algorithms[algorithm]
            decompress_func = algo_info['decompress']
            
            print(f"{Colors.DIM}   • Algorithm: {algo_info['name']}{Colors.END}")
            
            start_time = time.time()
            decompressed = decompress_func(compressed_data)
            decompression_time = time.time() - start_time
            
            # Parse DFEP JSON
            dfep_data = json.loads(decompressed.decode('utf-8'))
            
            # Determine output path
            if output_path is None:
                output_path = file_path
                for ext in ['.gz', '.zlib', '.bz2', '.xz']:
                    if output_path.endswith(ext):
                        output_path = output_path[:-len(ext)]
                        break
            
            # Write decompressed file
            with open(output_path, 'w') as f:
                json.dump(dfep_data, f, indent=2)
            
            final_size = os.path.getsize(output_path)
            
            print(f"\n{Colors.GREEN}{'═' * 40}{Colors.END}")
            print(f"{Colors.GREEN}✓ Decompression Complete!{Colors.END}")
            print(f"{Colors.DIM}   • Output: {final_size:,} bytes{Colors.END}")
            print(f"{Colors.DIM}   • Time: {decompression_time:.2f}s{Colors.END}")
            print(f"{Colors.GREEN}{'═' * 40}{Colors.END}")
            
            return output_path
            
        except Exception as e:
            print(f"{Colors.RED}✗ Decompression failed: {e}{Colors.END}")
            return None
    
    def optimize_json(self, file_path: str, keep_original: bool = True) -> Optional[str]:
        """Optimize JSON structure without compression"""
        try:
            with open(file_path, 'r') as f:
                dfep_data = json.load(f)
            
            original_size = os.path.getsize(file_path)
            print(f"\n{Colors.BOLD}📦 Optimizing JSON: {Colors.CYAN}{file_path}{Colors.END}")
            print(f"{Colors.DIM}   • Original size: {original_size:,} bytes{Colors.END}")
            
            # Minify JSON
            minified = json.dumps(dfep_data, separators=(',', ':'))
            
            # Reformat with minimal indentation
            optimized = json.dumps(dfep_data, indent=1)
            
            output_path = file_path.replace('.dfep', '.opt.dfep') if keep_original else file_path
            
            with open(output_path, 'w') as f:
                f.write(optimized)
            
            new_size = os.path.getsize(output_path)
            saved = original_size - new_size
            saved_percent = (saved / original_size) * 100
            
            print(f"\n{Colors.GREEN}✓ Optimization Complete!{Colors.END}")
            print(f"{Colors.DIM}   • New size: {new_size:,} bytes{Colors.END}")
            print(f"{Colors.GREEN}   • Saved: {saved:,} bytes ({saved_percent:.1f}%){Colors.END}")
            
            return output_path
            
        except Exception as e:
            print(f"{Colors.RED}✗ Optimization failed: {e}{Colors.END}")
            return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='DFEP File Size Reducer')
    parser.add_argument('file', help='DFEP file to reduce')
    parser.add_argument('-a', '--algorithm', choices=['zlib', 'gzip', 'bz2', 'lzma'],
                       help='Compression algorithm (auto-select if not specified)')
    parser.add_argument('-l', '--level', choices=['fast', 'balanced', 'maximum'],
                       default='balanced', help='Compression level')
    parser.add_argument('-d', '--decompress', action='store_true',
                       help='Decompress a compressed file')
    parser.add_argument('-j', '--json-only', action='store_true',
                       help='Only optimize JSON without compression')
    parser.add_argument('-k', '--keep', action='store_true',
                       help='Keep original file')
    parser.add_argument('-i', '--info', action='store_true',
                       help='Show compression analysis only')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Colors.RED}✗ File not found: {args.file}{Colors.END}")
        sys.exit(1)
    
    reducer = SizeReducer()
    
    if args.info:
        with open(args.file, 'r') as f:
            dfep_data = json.load(f)
        json_str = json.dumps(dfep_data, separators=(',', ':'))
        json_bytes = json_str.encode('utf-8')
        
        algorithm, analysis = reducer.select_best_algorithm(json_bytes)
        
        print(f"\n{Colors.BOLD}🔍 Compression Analysis for: {Colors.CYAN}{args.file}{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        print(f"{Colors.DIM}   • File size: {os.path.getsize(args.file):,} bytes{Colors.END}")
        print(f"{Colors.DIM}   • Entropy: {analysis['analysis']['entropy']:.2f}{Colors.END}")
        print(f"{Colors.DIM}   • Unique bytes: {analysis['analysis']['unique_bytes']}{Colors.END}")
        print(f"{Colors.DIM}   • Compression potential: {analysis['analysis']['compression_potential']}{Colors.END}")
        print(f"\n{Colors.BOLD}Algorithm Comparison:{Colors.END}")
        
        for algo, result in analysis['sample_results'].items():
            if 'error' in result:
                print(f"{Colors.RED}   • {algo}: Error - {result['error']}{Colors.END}")
            else:
                reduction = result['size_reduction']
                color = Colors.GREEN if reduction > 30 else Colors.YELLOW if reduction > 10 else Colors.RED
                print(f"{color}   • {algo}: {reduction:.1f}% reduction ({result['compression_ratio']:.3f} ratio){Colors.END}")
        
        print(f"\n{Colors.GREEN}   ✓ Recommended: {reducer.compression_algorithms[algorithm]['name']}{Colors.END}")
        return
    
    if args.decompress:
        reducer.decompress_dfep_file(args.file)
    elif args.json_only:
        reducer.optimize_json(args.file, args.keep)
    else:
        reducer.compress_dfep_file(args.file, args.algorithm, args.level, args.keep)

if __name__ == "__main__":
    main()