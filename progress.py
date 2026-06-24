#!/usr/bin/env python3

import time
import threading
import sys
import re

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

def strip_ansi(text):
    """Remove ANSI escape codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

class Spinner:
    def __init__(self, message="Processing"):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.running = False
        self.start_time = None
        self.thread = None
        
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
                line = f'{Colors.CYAN}{self.spinner_chars[idx % len(self.spinner_chars)]}{Colors.END} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END}'
                sys.stderr.write(f'\r{line}')
                sys.stderr.flush()
                idx += 1
                time.sleep(0.08)
        self.thread = threading.Thread(target=spin)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self, success=True, result=None):
        self.running = False
        if self.thread:
            self.thread.join()
        elapsed = time.time() - self.start_time
        elapsed_str = f"{elapsed:.1f}s"
        status = f"{Colors.GREEN}✓{Colors.END}" if success else f"{Colors.RED}✗{Colors.END}"
        if result:
            sys.stderr.write(f'\r{status} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END} {Colors.DIM}{result}{Colors.END}\n')
        else:
            sys.stderr.write(f'\r{status} {self.message} {Colors.DIM}[{elapsed_str}]{Colors.END}\n')
        sys.stderr.flush()

class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=20, fill='█', color=Colors.BLUE):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.color = color
        self.current = 0
        self.start_time = time.time()
        self._last_line = ""
        
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
            info = f"{elapsed:.1f}s<{eta:.1f}s"
        else:
            info = f"{elapsed:.1f}s"
        
        # Build line with fixed format - no extra spaces, no padding
        line = f'{self.color}{self.prefix}{Colors.END}|{self.color}{bar}{Colors.END}|{percent:5.1f}%{Colors.DIM}{self.suffix}[{info}]{Colors.END}'
        
        # Write to stderr to avoid buffering issues
        sys.stderr.write(f'\r{line}')
        sys.stderr.flush()
        self._last_line = line
            
        if self.current >= self.total:
            sys.stderr.write('\n')
            sys.stderr.flush()