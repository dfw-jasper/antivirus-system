#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import stat

def install_antivirus():
    """Install the antivirus system"""
    print("=== Antivirus System Installer ===\n")
    
    # Check Python version
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher required")
        return 1
        
    print("✓ Python version check passed")
    
    # Check required packages
    required_packages = ['cryptography']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} found")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package} missing")
            
    # Install missing packages
    if missing_packages:
        print(f"\nInstalling missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("✓ Packages installed successfully")
        except subprocess.CalledProcessError:
            print("✗ Failed to install packages")
            print("Please install manually: pip install " + " ".join(missing_packages))
            return 1
            
    # Create installation directory
    install_dir = os.path.expanduser("~/.antivirus")
    os.makedirs(install_dir, exist_ok=True)
    print(f"✓ Installation directory created: {install_dir}")
    
    # Copy files
    script_files = [
        'antivirus_cli.py',
        'enhanced_scanner.py',
        'quarantine_manager.py',
        'detection_algorithms.py',
        'network_monitor.py',
        'signature_database.py',
        'file_scanner.py'
    ]
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    for script_file in script_files:
        src_path = os.path.join(current_dir, script_file)
        dst_path = os.path.join(install_dir, script_file)
        
        if os.path.exists(src_path):
            shutil.copy2(src_path, dst_path)
            print(f"✓ Copied {script_file}")
        else:
            print(f"⚠ Warning: {script_file} not found")
            
    # Create executable wrapper
    wrapper_content = f"""#!/bin/bash
# Antivirus CLI wrapper
python3 "{install_dir}/antivirus_cli.py" "$@"
"""
    
    wrapper_path = "/usr/local/bin/antivirus"
    
    try:
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)
        os.chmod(wrapper_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"✓ Created executable: {wrapper_path}")
    except PermissionError:
        # Create in user's local bin if system-wide fails
        local_bin = os.path.expanduser("~/.local/bin")
        os.makedirs(local_bin, exist_ok=True)
        wrapper_path = os.path.join(local_bin, "antivirus")
        
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)
        os.chmod(wrapper_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"✓ Created executable: {wrapper_path}")
        print(f"⚠ Add {local_bin} to your PATH to use 'antivirus' command globally")
        
    # Initialize databases
    print("\nInitializing databases...")
    try:
        sys.path.insert(0, install_dir)
        from signature_database import SignatureDatabase
        from quarantine_manager import QuarantineManager
        
        # Initialize signature database
        db = SignatureDatabase()
        print("✓ Signature database initialized")
        
        # Initialize quarantine system
        qm = QuarantineManager()
        print("✓ Quarantine system initialized")
        
    except Exception as e:
        print(f"⚠ Warning: Database initialization failed: {e}")
        
    print("\n=== Installation Complete ===")
    print("Usage:")
    print("  antivirus scan /path/to/file")
    print("  antivirus monitor start")
    print("  antivirus quarantine list")
    print("  antivirus --help")
    print("\nFor more information, run: antivirus --help")
    
    return 0

if __name__ == "__main__":
    sys.exit(install_antivirus())
