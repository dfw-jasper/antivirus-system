import os
import re
import math
import hashlib
import subprocess
import json
from collections import Counter
from datetime import datetime
import logging

class AdvancedDetectionEngine:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Suspicious patterns for heuristic analysis
        self.suspicious_patterns = {
            'registry_manipulation': [
                rb'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                rb'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                rb'RegCreateKey', rb'RegSetValue', rb'RegDeleteKey'
            ],
            'file_operations': [
                rb'CreateFile', rb'WriteFile', rb'DeleteFile', rb'MoveFile',
                rb'CopyFile', rb'SetFileAttributes'
            ],
            'network_activity': [
                rb'socket', rb'connect', rb'send', rb'recv', rb'WSAStartup',
                rb'InternetOpen', rb'HttpSendRequest', rb'URLDownloadToFile'
            ],
            'process_manipulation': [
                rb'CreateProcess', rb'TerminateProcess', rb'OpenProcess',
                rb'VirtualAlloc', rb'WriteProcessMemory', rb'CreateRemoteThread'
            ],
            'crypto_operations': [
                rb'CryptAcquireContext', rb'CryptCreateHash', rb'CryptEncrypt',
                rb'CryptDecrypt', rb'CryptGenKey'
            ],
            'anti_analysis': [
                rb'IsDebuggerPresent', rb'CheckRemoteDebuggerPresent',
                rb'GetTickCount', rb'Sleep', rb'VirtualProtect'
            ]
        }
        
        # Suspicious strings and indicators
        self.malware_indicators = [
            'backdoor', 'keylogger', 'trojan', 'virus', 'worm', 'rootkit',
            'botnet', 'ransomware', 'spyware', 'adware', 'malware',
            'exploit', 'payload', 'shellcode', 'injection', 'hooking'
        ]
        
        # File extensions commonly used by malware
        self.suspicious_extensions = {
            '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.js',
            '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg'
        }
        
    def analyze_file_entropy(self, file_path):
        """Calculate file entropy to detect packed/encrypted content"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if len(data) == 0:
                return 0.0
                
            # Calculate byte frequency
            byte_counts = Counter(data)
            file_size = len(data)
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / file_size
                if probability > 0:
                    entropy -= probability * math.log2(probability)
                    
            return entropy
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
            
    def heuristic_analysis(self, file_path):
        """Perform heuristic analysis on file content"""
        results = {
            'suspicious_patterns': [],
            'malware_indicators': [],
            'entropy': 0.0,
            'risk_score': 0
        }
        
        try:
            # Calculate entropy
            results['entropy'] = self.analyze_file_entropy(file_path)
            
            # High entropy might indicate packing/encryption
            if results['entropy'] > 7.5:
                results['suspicious_patterns'].append('High entropy (possibly packed/encrypted)')
                results['risk_score'] += 30
                
            # Read file content for pattern analysis
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Check for suspicious patterns
            for category, patterns in self.suspicious_patterns.items():
                matches = 0
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches += 1
                        
                if matches > 0:
                    results['suspicious_patterns'].append(f'{category}: {matches} matches')
                    results['risk_score'] += matches * 10
                    
            # Check for malware indicators in strings
            content_str = content.decode('utf-8', errors='ignore').lower()
            for indicator in self.malware_indicators:
                if indicator in content_str:
                    results['malware_indicators'].append(indicator)
                    results['risk_score'] += 15
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error in heuristic analysis for {file_path}: {e}")
            return results
            
    def behavioral_analysis(self, file_path):
        """Analyze file behavior patterns"""
        results = {
            'file_operations': [],
            'network_indicators': [],
            'persistence_mechanisms': [],
            'risk_score': 0
        }
        
        try:
            file_name = os.path.basename(file_path).lower()
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Check suspicious file characteristics
            if file_ext in self.suspicious_extensions:
                results['file_operations'].append(f'Suspicious extension: {file_ext}')
                results['risk_score'] += 20
                
            # Check for suspicious naming patterns
            suspicious_names = [
                'svchost', 'winlogon', 'explorer', 'system32', 'temp',
                'update', 'install', 'setup', 'crack', 'keygen', 'patch'
            ]
            
            for name in suspicious_names:
                if name in file_name:
                    results['file_operations'].append(f'Suspicious filename pattern: {name}')
                    results['risk_score'] += 15
                    
            # Check file size anomalies
            file_size = os.path.getsize(file_path)
            
            # Very small executables might be droppers
            if file_ext in ['.exe', '.com'] and file_size < 10000:
                results['file_operations'].append('Unusually small executable')
                results['risk_score'] += 25
                
            # Very large files might contain embedded payloads
            if file_size > 50 * 1024 * 1024:  # 50MB
                results['file_operations'].append('Unusually large file size')
                results['risk_score'] += 15
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error in behavioral analysis for {file_path}: {e}")
            return results
            
    def static_analysis(self, file_path):
        """Perform static analysis on executable files"""
        results = {
            'pe_analysis': {},
            'imports': [],
            'sections': [],
            'risk_score': 0
        }
        
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Only analyze PE files for now
            if file_ext not in ['.exe', '.dll', '.sys']:
                return results
                
            # Try to analyze PE structure (simplified)
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Check for PE signature
            if len(data) > 64:
                dos_header = data[:64]
                if dos_header[:2] == b'MZ':
                    results['pe_analysis']['has_dos_header'] = True
                    
                    # Look for PE signature
                    pe_offset = int.from_bytes(dos_header[60:64], 'little')
                    if pe_offset < len(data) - 4:
                        pe_sig = data[pe_offset:pe_offset+4]
                        if pe_sig == b'PE\x00\x00':
                            results['pe_analysis']['has_pe_header'] = True
                            results['risk_score'] += 10  # Valid PE structure
                            
            # Check for suspicious imports (simplified string search)
            suspicious_imports = [
                b'VirtualAlloc', b'VirtualProtect', b'WriteProcessMemory',
                b'CreateRemoteThread', b'SetWindowsHookEx', b'GetProcAddress',
                b'LoadLibrary', b'URLDownloadToFile', b'WinExec', b'ShellExecute'
            ]
            
            for imp in suspicious_imports:
                if imp in data:
                    results['imports'].append(imp.decode('ascii'))
                    results['risk_score'] += 20
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error in static analysis for {file_path}: {e}")
            return results
            
    def machine_learning_detection(self, file_path):
        """Simple ML-based detection using feature extraction"""
        results = {
            'features': {},
            'ml_score': 0,
            'classification': 'unknown'
        }
        
        try:
            # Extract basic features for ML analysis
            file_size = os.path.getsize(file_path)
            entropy = self.analyze_file_entropy(file_path)
            
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Feature extraction
            features = {
                'file_size': file_size,
                'entropy': entropy,
                'null_byte_ratio': content.count(b'\x00') / len(content) if content else 0,
                'printable_ratio': sum(1 for b in content if 32 <= b <= 126) / len(content) if content else 0,
                'unique_bytes': len(set(content)) if content else 0,
                'compression_ratio': len(content) / (len(set(content)) + 1) if content else 0
            }
            
            results['features'] = features
            
            # Simple rule-based ML simulation
            ml_score = 0
            
            # High entropy files are suspicious
            if entropy > 7.0:
                ml_score += 30
            elif entropy < 3.0:
                ml_score += 15  # Very low entropy also suspicious
                
            # Low printable ratio might indicate binary payload
            if features['printable_ratio'] < 0.1:
                ml_score += 20
                
            # High compression ratio might indicate packed content
            if features['compression_ratio'] > 100:
                ml_score += 25
                
            # Very few unique bytes might indicate simple encryption
            if features['unique_bytes'] < 50 and file_size > 1000:
                ml_score += 20
                
            results['ml_score'] = ml_score
            
            # Classification based on score
            if ml_score >= 70:
                results['classification'] = 'malicious'
            elif ml_score >= 40:
                results['classification'] = 'suspicious'
            else:
                results['classification'] = 'clean'
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error in ML detection for {file_path}: {e}")
            return results
            
    def comprehensive_analysis(self, file_path):
        """Perform comprehensive analysis using all detection methods"""
        print(f"\n=== Comprehensive Analysis: {file_path} ===")
        
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return None
            
        analysis_results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'analysis_time': datetime.now().isoformat(),
            'heuristic': {},
            'behavioral': {},
            'static': {},
            'ml_detection': {},
            'total_risk_score': 0,
            'final_classification': 'unknown'
        }
        
        try:
            # Perform all analysis types
            print("Running heuristic analysis...")
            analysis_results['heuristic'] = self.heuristic_analysis(file_path)
            
            print("Running behavioral analysis...")
            analysis_results['behavioral'] = self.behavioral_analysis(file_path)
            
            print("Running static analysis...")
            analysis_results['static'] = self.static_analysis(file_path)
            
            print("Running ML detection...")
            analysis_results['ml_detection'] = self.machine_learning_detection(file_path)
            
            # Calculate total risk score
            total_score = (
                analysis_results['heuristic']['risk_score'] +
                analysis_results['behavioral']['risk_score'] +
                analysis_results['static']['risk_score'] +
                analysis_results['ml_detection']['ml_score']
            )
            
            analysis_results['total_risk_score'] = total_score
            
            # Final classification
            if total_score >= 100:
                analysis_results['final_classification'] = 'high_risk'
            elif total_score >= 60:
                analysis_results['final_classification'] = 'medium_risk'
            elif total_score >= 30:
                analysis_results['final_classification'] = 'low_risk'
            else:
                analysis_results['final_classification'] = 'clean'
                
            # Display results
            self._display_analysis_results(analysis_results)
            
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis: {e}")
            return analysis_results
            
    def _display_analysis_results(self, results):
        """Display formatted analysis results"""
        print(f"\n--- Analysis Results ---")
        print(f"File: {results['file_path']}")
        print(f"Size: {results['file_size']} bytes")
        print(f"Total Risk Score: {results['total_risk_score']}")
        print(f"Classification: {results['final_classification'].upper()}")
        
        # Heuristic results
        heuristic = results['heuristic']
        print(f"\n🔍 Heuristic Analysis (Score: {heuristic['risk_score']}):")
        print(f"  Entropy: {heuristic['entropy']:.2f}")
        if heuristic['suspicious_patterns']:
            print(f"  Suspicious Patterns:")
            for pattern in heuristic['suspicious_patterns']:
                print(f"    - {pattern}")
        if heuristic['malware_indicators']:
            print(f"  Malware Indicators: {', '.join(heuristic['malware_indicators'])}")
            
        # Behavioral results
        behavioral = results['behavioral']
        print(f"\n🎯 Behavioral Analysis (Score: {behavioral['risk_score']}):")
        if behavioral['file_operations']:
            print(f"  File Operations:")
            for op in behavioral['file_operations']:
                print(f"    - {op}")
                
        # Static analysis results
        static = results['static']
        print(f"\n🔬 Static Analysis (Score: {static['risk_score']}):")
        if static['imports']:
            print(f"  Suspicious Imports: {', '.join(static['imports'])}")
        if static['pe_analysis']:
            print(f"  PE Analysis: {static['pe_analysis']}")
            
        # ML results
        ml = results['ml_detection']
        print(f"\n🤖 ML Detection (Score: {ml['ml_score']}):")
        print(f"  Classification: {ml['classification']}")
        print(f"  Key Features:")
        for feature, value in ml['features'].items():
            print(f"    {feature}: {value:.3f}")

def main():
    """Demo advanced detection algorithms"""
    print("=== Advanced Antivirus Detection Engine ===\n")
    
    detector = AdvancedDetectionEngine()
    
    # Create test files for analysis
    test_files = []
    
    # Create a suspicious executable-like file
    suspicious_file = "suspicious_test.exe"
    with open(suspicious_file, 'wb') as f:
        # Add PE-like header
        f.write(b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00')  # DOS header
        f.write(b'\x00' * 0x80)  # Padding to PE offset
        f.write(b'PE\x00\x00')  # PE signature
        
        # Add suspicious content
        suspicious_content = (
            b'VirtualAlloc' + b'CreateRemoteThread' + b'WriteProcessMemory' +
            b'keylogger' + b'backdoor' + b'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
        )
        f.write(suspicious_content)
        
        # Add some random data to increase entropy
        import random
        random_data = bytes([random.randint(0, 255) for _ in range(1000)])
        f.write(random_data)
        
    test_files.append(suspicious_file)
    
    # Create a clean text file
    clean_file = "clean_test.txt"
    with open(clean_file, 'w') as f:
        f.write("This is a clean text file with normal content.\n" * 50)
    test_files.append(clean_file)
    
    # Analyze each test file
    for test_file in test_files:
        analysis = detector.comprehensive_analysis(test_file)
        
        if analysis:
            # Save analysis results
            result_file = f"{test_file}_analysis.json"
            with open(result_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            print(f"Analysis saved to: {result_file}")
            
        print("\n" + "="*60)
        
    # Cleanup test files
    for test_file in test_files:
        if os.path.exists(test_file):
            os.remove(test_file)
            
    print("\n=== Detection Engine Demo Complete ===")

if __name__ == "__main__":
    main()
