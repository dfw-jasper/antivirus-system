import os
import hashlib
import mimetypes
import json
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime

class FileScanner:
    def __init__(self):
        self.scanned_files = []
        self.suspicious_files = []
        self.known_malware_hashes = set()
        self.suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', 
            '.js', '.jar', '.app', '.deb', '.pkg', '.dmg'
        }
        
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate hash of a file using specified algorithm"""
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except (IOError, OSError) as e:
            print(f"Error reading file {file_path}: {e}")
            return None
    
    def analyze_file_metadata(self, file_path: str) -> Dict:
        """Analyze file metadata for suspicious characteristics"""
        try:
            stat = os.stat(file_path)
            file_info = {
                'path': file_path,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': Path(file_path).suffix.lower(),
                'mime_type': mimetypes.guess_type(file_path)[0],
                'hash_sha256': self.calculate_file_hash(file_path),
                'suspicious_score': 0
            }
            
            # Calculate suspicion score
            if file_info['extension'] in self.suspicious_extensions:
                file_info['suspicious_score'] += 3
                
            if file_info['size'] > 100 * 1024 * 1024:  # Files > 100MB
                file_info['suspicious_score'] += 1
                
            if file_info['size'] < 1024:  # Very small executable files
                if file_info['extension'] in {'.exe', '.com'}:
                    file_info['suspicious_score'] += 2
            
            return file_info
            
        except (OSError, IOError) as e:
            print(f"Error analyzing {file_path}: {e}")
            return None
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """Scan directory for files and analyze them"""
        print(f"[SCANNER] Starting scan of directory: {directory}")
        scanned_files = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_info = self.analyze_file_metadata(file_path)
                        if file_info:
                            scanned_files.append(file_info)
                            if file_info['suspicious_score'] >= 3:
                                self.suspicious_files.append(file_info)
                                print(f"[WARNING] Suspicious file detected: {file_path}")
            else:
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    if os.path.isfile(item_path):
                        file_info = self.analyze_file_metadata(item_path)
                        if file_info:
                            scanned_files.append(file_info)
                            if file_info['suspicious_score'] >= 3:
                                self.suspicious_files.append(file_info)
                                print(f"[WARNING] Suspicious file detected: {item_path}")
        
        except PermissionError:
            print(f"[ERROR] Permission denied accessing: {directory}")
        except Exception as e:
            print(f"[ERROR] Unexpected error scanning {directory}: {e}")
        
        self.scanned_files.extend(scanned_files)
        print(f"[SCANNER] Scan complete. Found {len(scanned_files)} files, {len(self.suspicious_files)} suspicious")
        return scanned_files
    
    def check_against_signatures(self, file_hash: str) -> bool:
        """Check if file hash matches known malware signatures"""
        return file_hash in self.known_malware_hashes
    
    def load_malware_signatures(self, signatures_file: str):
        """Load known malware signatures from file"""
        try:
            with open(signatures_file, 'r') as f:
                signatures = json.load(f)
                self.known_malware_hashes.update(signatures.get('hashes', []))
                print(f"[SCANNER] Loaded {len(self.known_malware_hashes)} malware signatures")
        except FileNotFoundError:
            print(f"[WARNING] Signatures file not found: {signatures_file}")
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in signatures file: {signatures_file}")
    
    def generate_scan_report(self) -> Dict:
        """Generate comprehensive scan report"""
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_files_scanned': len(self.scanned_files),
            'suspicious_files_count': len(self.suspicious_files),
            'suspicious_files': self.suspicious_files,
            'scan_summary': {
                'clean_files': len(self.scanned_files) - len(self.suspicious_files),
                'threats_detected': len(self.suspicious_files),
                'files_by_extension': {}
            }
        }
        
        # Count files by extension
        for file_info in self.scanned_files:
            ext = file_info.get('extension', 'unknown')
            report['scan_summary']['files_by_extension'][ext] = \
                report['scan_summary']['files_by_extension'].get(ext, 0) + 1
        
        return report

# Demo usage
if __name__ == "__main__":
    scanner = FileScanner()
    
    # Create sample malware signatures file
    sample_signatures = {
        "hashes": [
            "d41d8cd98f00b204e9800998ecf8427e",  # Empty file hash (example)
            "5d41402abc4b2a76b9719d911017c592"   # "hello" hash (example)
        ]
    }
    
    with open('malware_signatures.json', 'w') as f:
        json.dump(sample_signatures, f)
    
    # Load signatures
    scanner.load_malware_signatures('malware_signatures.json')
    
    # Scan current directory (non-recursive for demo)
    print("=== ANTIVIRUS FILE SCANNER DEMO ===")
    scan_results = scanner.scan_directory('.', recursive=False)
    
    # Generate and display report
    report = scanner.generate_scan_report()
    print("\n=== SCAN REPORT ===")
    print(f"Files scanned: {report['total_files_scanned']}")
    print(f"Suspicious files: {report['suspicious_files_count']}")
    print(f"Clean files: {report['scan_summary']['clean_files']}")
    
    if report['suspicious_files']:
        print("\n=== SUSPICIOUS FILES ===")
        for file_info in report['suspicious_files']:
            print(f"File: {file_info['path']}")
            print(f"  Suspicion Score: {file_info['suspicious_score']}")
            print(f"  Size: {file_info['size']} bytes")
            print(f"  Extension: {file_info['extension']}")
            print()
