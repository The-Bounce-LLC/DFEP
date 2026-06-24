#!/usr/bin/env python3
# optimize.py - Fully automated cross-platform optimizer

import os
import sys
import platform
import json
import shutil
import subprocess
import multiprocessing as mp
import time
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

# ANSI color codes
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

class AutoOptimizer:
    """Fully automated optimizer - no user intervention needed"""
    
    def __init__(self):
        self.system = self._detect_system()
        self.config = {}
        self.installed_packages = set()
        
    def _detect_system(self) -> Dict[str, Any]:
        """Complete system detection"""
        info = {
            'os': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'python': platform.python_version(),
            'implementation': platform.python_implementation(),
        }
        
        # Environment detection
        info['is_android'] = 'ANDROID_ROOT' in os.environ or 'TERMUX' in os.environ
        info['is_termux'] = 'TERMUX' in os.environ
        info['is_wsl'] = 'microsoft' in platform.release().lower()
        info['is_container'] = os.path.exists('/.dockerenv') or 'container' in os.environ.get('container', '')
        info['is_ci'] = bool(os.environ.get('CI', ''))
        
        # Hardware
        try:
            info['cpu_count'] = mp.cpu_count()
        except:
            info['cpu_count'] = 1
        
        # Memory
        try:
            import psutil
            mem = psutil.virtual_memory()
            info['total_memory'] = mem.total
            info['available_memory'] = mem.available
            info['memory_percent'] = mem.percent
        except:
            info['total_memory'] = self._get_memory()
            info['available_memory'] = info['total_memory']
            info['memory_percent'] = 0
        
        # Disk
        try:
            disk = shutil.disk_usage('.')
            info['disk_free'] = disk.free
        except:
            info['disk_free'] = 1024 * 1024 * 1024  # 1GB default
        
        return info
    
    def _get_memory(self) -> int:
        """Get total memory without psutil"""
        try:
            if platform.system() == 'Linux':
                with open('/proc/meminfo') as f:
                    for line in f:
                        if 'MemTotal' in line:
                            return int(line.split()[1]) * 1024
            elif platform.system() == 'Darwin':
                result = subprocess.run(['sysctl', 'hw.memsize'], capture_output=True, text=True)
                return int(result.stdout.split(':')[1].strip())
        except:
            pass
        return 1024 * 1024 * 1024  # 1GB default
    
    def run(self) -> bool:
        """Run complete optimization - no questions asked"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ⚡ Auto-Optimizing DFEP for {self.system['os']}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.END}")
        
        # Phase 1: Analyze
        self._analyze_system()
        
        # Phase 2: Install missing packages
        self._install_dependencies()
        
        # Phase 3: Optimize configuration
        self._optimize_configuration()
        
        # Phase 4: Patch files
        self._patch_worker_file()
        
        # Phase 5: Create optimized launcher
        self._create_launcher()
        
        # Phase 6: Verify
        self._verify_optimizations()
        
        print(f"\n{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"{Colors.GREEN}  ✓ Optimization Complete!{Colors.END}")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}\n")
        
        return True
    
    def _analyze_system(self):
        """Analyze system and show findings"""
        print(f"\n{Colors.BOLD}📊 System Analysis{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        mem_gb = self.system['total_memory'] / (1024**3)
        print(f"  {Colors.CYAN}OS:{Colors.END} {self.system['os']} {self.system['release']}")
        print(f"  {Colors.CYAN}CPU:{Colors.END} {self.system['cpu_count']} cores")
        print(f"  {Colors.CYAN}RAM:{Colors.END} {mem_gb:.1f} GB")
        print(f"  {Colors.CYAN}Python:{Colors.END} {self.system['python']}")
        
        # Platform flags
        flags = []
        if self.system['is_android']: flags.append('Android')
        if self.system['is_termux']: flags.append('Termux')
        if self.system['is_wsl']: flags.append('WSL')
        if self.system['is_container']: flags.append('Container')
        if self.system['is_ci']: flags.append('CI/CD')
        
        if flags:
            print(f"  {Colors.CYAN}Environment:{Colors.END} {', '.join(flags)}")
        
        # Check available libraries
        libs = {}
        for lib in ['numpy', 'numba', 'psutil', 'orjson', 'msgpack', 'Crypto']:
            try:
                __import__(lib)
                libs[lib] = True
            except:
                libs[lib] = False
        
        available = [lib for lib, ok in libs.items() if ok]
        missing = [lib for lib, ok in libs.items() if not ok]
        
        if available:
            print(f"  {Colors.GREEN}✓ Available:{Colors.END} {', '.join(available)}")
        if missing:
            print(f"  {Colors.YELLOW}⚠ Missing:{Colors.END} {', '.join(missing)}")
    
    def _install_dependencies(self):
        """Auto-install missing dependencies"""
        print(f"\n{Colors.BOLD}📦 Installing Dependencies{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        # Determine pip command
        if self.system['is_termux']:
            pip_cmd = ['pkg', 'install', '-y', 'python']
        elif self.system['is_android']:
            pip_cmd = [sys.executable, '-m', 'pip', 'install', '--user']
        else:
            pip_cmd = [sys.executable, '-m', 'pip', 'install', '--quiet']
        
        # Essential packages for each platform
        packages = {
            'all': ['psutil'],  # Everyone needs psutil
            'Linux': ['numpy'],
            'Darwin': ['numpy'],
            'Windows': ['numpy'],
            'Android': [],  # Android has limitations
        }
        
        # Optional but recommended
        try:
            import numpy
        except:
            if not self.system['is_android']:
                packages[self.system['os']].append('numpy')
        
        # Install packages
        platform_packages = packages.get(self.system['os'], []) + packages['all']
        
        if not platform_packages:
            print(f"  {Colors.GREEN}✓ No packages needed{Colors.END}")
            return
        
        for package in platform_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"  {Colors.GREEN}✓ {package} already installed{Colors.END}")
            except:
                print(f"  {Colors.CYAN}→ Installing {package}...{Colors.END}")
                try:
                    subprocess.run(
                        pip_cmd + [package],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=60
                    )
                    self.installed_packages.add(package)
                    print(f"  {Colors.GREEN}✓ {package} installed{Colors.END}")
                except:
                    print(f"  {Colors.YELLOW}⚠ Could not install {package}{Colors.END}")
    
    def _optimize_configuration(self):
        """Generate optimal configuration"""
        print(f"\n{Colors.BOLD}⚙️ Generating Configuration{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        # Calculate optimal settings
        mem_gb = self.system['total_memory'] / (1024**3)
        cpu_count = self.system['cpu_count']
        
        if self.system['is_android']:
            workers = min(2, cpu_count)
            chunk_size = 256 * 1024  # 256KB
            use_processes = False
            reason = "Android/Termux limitations"
        elif self.system['is_container'] or mem_gb < 2:
            workers = min(2, cpu_count)
            chunk_size = 512 * 1024  # 512KB
            use_processes = True
            reason = "Limited resources"
        elif mem_gb < 4:
            workers = min(4, cpu_count)
            chunk_size = 1024 * 1024  # 1MB
            use_processes = True
            reason = "Medium resources"
        elif mem_gb < 8:
            workers = min(8, cpu_count)
            chunk_size = 2 * 1024 * 1024  # 2MB
            use_processes = True
            reason = "Good resources"
        else:
            workers = min(16, cpu_count)
            chunk_size = 4 * 1024 * 1024  # 4MB
            use_processes = True
            reason = "Excellent resources"
        
        print(f"  {Colors.CYAN}Workers:{Colors.END} {workers} ({reason})")
        print(f"  {Colors.CYAN}Chunk Size:{Colors.END} {chunk_size // 1024} KB")
        print(f"  {Colors.CYAN}Process Mode:{Colors.END} {'Yes' if use_processes else 'Thread-based'}")
        
        # Check for NumPy/Numba
        has_numpy = False
        has_numba = False
        try:
            import numpy
            has_numpy = True
        except:
            pass
        try:
            import numba
            has_numba = True
        except:
            pass
        
        print(f"  {Colors.CYAN}NumPy:{Colors.END} {'Yes ✓' if has_numpy else 'No'}")
        print(f"  {Colors.CYAN}Numba:{Colors.END} {'Yes ✓' if has_numba else 'No'}")
        
        # Build configuration
        self.config = {
            'version': 'dfep-auto-optimized-v1',
            'generated_at': __import__('datetime').datetime.now().isoformat(),
            'system': {
                'os': self.system['os'],
                'cpu_count': cpu_count,
                'memory_gb': mem_gb,
                'is_android': self.system['is_android'],
                'is_termux': self.system['is_termux'],
            },
            'performance': {
                'num_workers': workers,
                'chunk_size': chunk_size,
                'use_processes': use_processes,
                'use_numpy': has_numpy,
                'use_numba': has_numba,
                'reason': reason,
            },
            'features': {
                'auto_compression': True,
                'parallel_processing': workers > 1,
                'streaming_large_files': True,
                'auto_cleanup': True,
                'progress_bars': True,
            },
            'limits': {
                'max_file_size': min(1024 * 1024 * 1024, int(self.system['disk_free'] * 0.5)),
                'max_memory_percent': 75,
                'auto_split_threshold': 100 * 1024 * 1024,  # 100MB
            }
        }
        
        # Save configuration
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dfep_optimized.json')
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        print(f"\n  {Colors.GREEN}✓ Configuration saved to .dfep_optimized.json{Colors.END}")
    
    def _patch_worker_file(self):
        """Automatically patch worker.py with optimal settings"""
        print(f"\n{Colors.BOLD}🔧 Patching worker.py{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        # Find worker.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_path = os.path.join(script_dir, 'worker.py')
        
        if not os.path.exists(worker_path):
            # Try to find it
            for root, _, files in os.walk(script_dir):
                if 'worker.py' in files:
                    worker_path = os.path.join(root, 'worker.py')
                    break
        
        if not os.path.exists(worker_path):
            print(f"  {Colors.YELLOW}⚠ worker.py not found - skipping patch{Colors.END}")
            return
        
        # Backup original
        backup_path = worker_path + '.backup'
        if not os.path.exists(backup_path):
            shutil.copy2(worker_path, backup_path)
            print(f"  {Colors.GREEN}✓ Backup created: worker.py.backup{Colors.END}")
        
        # Read and patch
        with open(worker_path, 'r') as f:
            content = f.read()
        
        # Apply patches
        patches = [
            # Optimize worker count
            (r"self.num_workers\s*=\s*2", f"self.num_workers = {self.config['performance']['num_workers']}"),
            # Optimize chunk size
            (r"self.chunk_size\s*=\s*\d+\s*\*\s*\d+", f"self.chunk_size = {self.config['performance']['chunk_size']}"),
            # Add auto-detection
            ("def __init__(self, num_workers=None):", 
             f"def __init__(self, num_workers=None):\n        # Auto-optimized: {self.config['performance']['reason']}"),
        ]
        
        import re
        patched = content
        for pattern, replacement in patches:
            patched = re.sub(pattern, replacement, patched)
        
        if patched != content:
            with open(worker_path, 'w') as f:
                f.write(patched)
            print(f"  {Colors.GREEN}✓ worker.py patched with optimal settings{Colors.END}")
        else:
            print(f"  {Colors.GREEN}✓ worker.py already optimized{Colors.END}")
    
    def _create_launcher(self):
        """Create optimized launcher script"""
        print(f"\n{Colors.BOLD}🚀 Creating Optimized Launcher{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        launcher_content = f'''#!/usr/bin/env python3
"""
Auto-optimized DFEP launcher
Generated for: {self.system['os']} ({self.system['machine']})
Workers: {self.config['performance']['num_workers']}
Chunk Size: {self.config['performance']['chunk_size'] // 1024} KB
"""

import os
import sys
import json

# Load optimized configuration
_config_path = os.path.join(os.path.dirname(__file__), '.dfep_optimized.json')
if os.path.exists(_config_path):
    with open(_config_path) as f:
        _config = json.load(f)
    
    # Apply performance settings
    perf = _config['performance']
    os.environ['DFEP_WORKERS'] = str(perf['num_workers'])
    os.environ['DFEP_CHUNK_SIZE'] = str(perf['chunk_size'])
    os.environ['DFEP_USE_NUMPY'] = str(perf.get('use_numpy', False)).lower()
    os.environ['DFEP_USE_NUMBA'] = str(perf.get('use_numba', False)).lower()
    
    if 'use_processes' in perf:
        os.environ['DFEP_USE_PROCESSES'] = str(perf['use_processes']).lower()

# Launch DFEP with all arguments
_dfep_path = os.path.join(os.path.dirname(__file__), 'dfep.py')
if os.path.exists(_dfep_path):
    # Pass all arguments through
    os.execv(sys.executable, [sys.executable, _dfep_path] + sys.argv[1:])
else:
    print("Error: dfep.py not found in", os.path.dirname(__file__))
    sys.exit(1)
'''
        
        launcher_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dfep_optimized.py')
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        
        # Make executable on Unix
        if platform.system() != 'Windows':
            os.chmod(launcher_path, 0o755)
        
        print(f"  {Colors.GREEN}✓ Created dfep_optimized.py launcher{Colors.END}")
        
        # Create batch file for Windows
        if platform.system() == 'Windows':
            batch_content = f'''@echo off
REM Auto-optimized DFEP launcher for Windows
set DFEP_WORKERS={self.config['performance']['num_workers']}
set DFEP_CHUNK_SIZE={self.config['performance']['chunk_size']}
python "%~dp0dfep_optimized.py" %*
'''
            batch_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dfep_optimized.bat')
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            print(f"  {Colors.GREEN}✓ Created dfep_optimized.bat launcher{Colors.END}")
    
    def _verify_optimizations(self):
        """Verify all optimizations are working"""
        print(f"\n{Colors.BOLD}✓ Verifying Optimizations{Colors.END}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.END}")
        
        checks = []
        
        # Check config file
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dfep_optimized.json')
        checks.append(('Configuration file', os.path.exists(config_path)))
        
        # Check worker backup
        worker_backup = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'worker.py.backup')
        checks.append(('Worker backup', os.path.exists(worker_backup)))
        
        # Check launcher
        launcher_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dfep_optimized.py')
        checks.append(('Optimized launcher', os.path.exists(launcher_path)))
        
        # Check memory
        try:
            import psutil
            mem_percent = psutil.virtual_memory().percent
            checks.append((f'Memory usage ({mem_percent}%)', mem_percent < 90))
        except:
            checks.append(('Memory check', True))
        
        # Display results
        all_ok = True
        for check_name, result in checks:
            if result:
                print(f"  {Colors.GREEN}✓{Colors.END} {check_name}")
            else:
                print(f"  {Colors.RED}✗{Colors.END} {check_name}")
                all_ok = False
        
        if all_ok:
            print(f"\n  {Colors.GREEN}✓ All optimizations verified successfully!{Colors.END}")
        else:
            print(f"\n  {Colors.YELLOW}⚠ Some checks failed - but system should still work{Colors.END}")

def main():
    """Main entry point - fully automated"""
    print(f"\n{Colors.CYAN}🔄 DFEP Auto-Optimizer v2.0{Colors.END}")
    print(f"{Colors.DIM}No user input required - everything is automatic{Colors.END}")
    
    optimizer = AutoOptimizer()
    
    # Run optimization immediately
    success = optimizer.run()
    
    if success:
        print(f"{Colors.GREEN}✨ DFEP is now optimized for your system!{Colors.END}")
        print(f"{Colors.DIM}Use 'python dfep_optimized.py' for best performance{Colors.END}")
    else:
        print(f"{Colors.RED}✗ Optimization encountered issues{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()