#!/usr/bin/env python3

import os
import sys
import time
import getpass
import shutil
import signal
import platform
from progress import Colors
from engine import OptimizedDFEP, SystemOptimizer
from helper import clear_screen

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n\n{Colors.YELLOW}⚠ Interrupted by user{Colors.END}")
    print(f"{Colors.DIM}Cleaning up...{Colors.END}")
    sys.exit(0)

def show_system_info():
    """Show system optimization info"""
    opt = SystemOptimizer.get_optimal_settings()
    
    print(f"{Colors.DIM}  ⚡ System: {opt['cpu_count']} cores, {opt['memory_gb']:.1f}GB RAM{Colors.END}")
    
    if opt['is_android']:
        print(f"{Colors.DIM}  📱 Android mode: {opt['workers']} workers, {opt['chunk_size']//1024}KB chunks{Colors.END}")
    else:
        mode = 'Process' if opt['use_processes'] else 'Thread'
        print(f"{Colors.DIM}  💻 {mode} mode: {opt['workers']} workers, {opt['chunk_size']//1024}KB chunks{Colors.END}")
    
    # Show available optimizations (only check what exists)
    optimizations = []
    if opt.get('has_numpy'): 
        optimizations.append('NumPy')
    if opt.get('has_numba'): 
        optimizations.append('Numba')
    if optimizations:
        print(f"{Colors.DIM}  🚀 Using: {', '.join(optimizations)}{Colors.END}")

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Get terminal width
    term_width = shutil.get_terminal_size().columns
    term_width = min(term_width, 80)
    
    print(f"\n{Colors.CYAN}{'═' * term_width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  🔒 DFEP - Deep File Encryption Protocol v2{Colors.END}")
    print(f"{Colors.DIM}  {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    
    # Auto-show system optimization info
    show_system_info()
    
    print(f"{Colors.CYAN}{'═' * term_width}{Colors.END}")
    
    if len(sys.argv) < 2:
        print(f"\n{Colors.BOLD}Usage:{Colors.END}")
        print(f"  {Colors.CYAN}python dfep.py -e <file_path>{Colors.END}  {Colors.DIM}(Encrypt){Colors.END}")
        print(f"  {Colors.CYAN}python dfep.py -d <file_path>{Colors.END}  {Colors.DIM}(Decrypt){Colors.END}")
        print(f"\n{Colors.BOLD}Examples:{Colors.END}")
        print(f"  {Colors.DIM}python dfep.py -e document.txt{Colors.END}")
        print(f"  {Colors.DIM}python dfep.py -d document.dfep{Colors.END}")
        print(f"\n{Colors.DIM}✨ Auto-optimized for your system{Colors.END}")
        sys.exit(1)
    
    mode = sys.argv[1]
    if len(sys.argv) < 3:
        print(f"{Colors.RED}✗{Colors.END} Please specify file path")
        sys.exit(1)
    
    file_path = sys.argv[2]
    
    if not os.path.exists(file_path):
        print(f"{Colors.RED}✗{Colors.END} File not found: {Colors.CYAN}{file_path}{Colors.END}")
        sys.exit(1)
    
    # Create optimized DFEP instance
    dfep = OptimizedDFEP()
    start_time = time.time()
    
    try:
        if mode == '-e':
            print(f"\n{Colors.BOLD}🔐 Encryption Mode{Colors.END}")
            print(f"{Colors.DIM}{'─' * term_width}{Colors.END}")
            
            while True:
                try:
                    password = getpass.getpass(f"{Colors.BOLD}Enter dfepk password:{Colors.END} ")
                    confirm = getpass.getpass(f"{Colors.BOLD}Confirm password:{Colors.END} ")
                    if password == confirm:
                        break
                    print(f"{Colors.RED}✗{Colors.END} Passwords don't match. Please try again.")
                except KeyboardInterrupt:
                    print(f"\n\n{Colors.YELLOW}⚠ Cancelled{Colors.END}")
                    sys.exit(0)
            
            if len(password) < 8:
                print(f"{Colors.YELLOW}⚠{Colors.END} Short password - less secure")
            
            output_file = dfep.encrypt_file(file_path, password)
            if output_file is None:
                print(f"\n{Colors.RED}✗{Colors.END} Encryption failed")
                sys.exit(1)
        
        elif mode == '-d':
            print(f"\n{Colors.BOLD}🔓 Decryption Mode{Colors.END}")
            print(f"{Colors.DIM}{'─' * term_width}{Colors.END}")
            
            if not file_path.endswith('.dfep'):
                print(f"{Colors.RED}✗{Colors.END} This is not a .dfep file!")
                sys.exit(1)
            
            try:
                password = getpass.getpass(f"{Colors.BOLD}Enter dfepk password:{Colors.END} ")
            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}⚠ Cancelled{Colors.END}")
                sys.exit(0)
            
            output_file = dfep.decrypt_file(file_path, password)
            if output_file is None:
                print(f"\n{Colors.RED}✗{Colors.END} Decryption failed")
                sys.exit(1)
        
        else:
            print(f"{Colors.RED}✗{Colors.END} Invalid mode. Use {Colors.CYAN}-e{Colors.END} for encrypt or {Colors.CYAN}-d{Colors.END} for decrypt.")
            sys.exit(1)
        
        elapsed = time.time() - start_time
        print(f"\n{Colors.DIM}⏱️  Total time: {elapsed:.2f} seconds{Colors.END}")
        print(f"{Colors.CYAN}{'═' * term_width}{Colors.END}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Interrupted by user{Colors.END}")
        print(f"{Colors.DIM}Operation cancelled. No files were harmed.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}✗{Colors.END} Unexpected error: {Colors.RED}{e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()