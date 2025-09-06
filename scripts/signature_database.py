import sqlite3
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class SignatureDatabase:
    def __init__(self, db_path: str = "antivirus_signatures.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the signature database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create signatures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_type TEXT NOT NULL,
                signature_value TEXT NOT NULL UNIQUE,
                malware_name TEXT NOT NULL,
                threat_level INTEGER DEFAULT 5,
                description TEXT,
                source TEXT,
                created_date TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Create signature patterns table for advanced detection
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS signature_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name TEXT NOT NULL,
                pattern_regex TEXT NOT NULL,
                file_types TEXT,
                threat_level INTEGER DEFAULT 5,
                description TEXT,
                created_date TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Create scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                threat_detected BOOLEAN DEFAULT 0,
                signature_matched TEXT,
                action_taken TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[DATABASE] Initialized signature database at {self.db_path}")
    
    def add_signature(self, signature_type: str, signature_value: str, 
                     malware_name: str, threat_level: int = 5, 
                     description: str = "", source: str = "manual") -> bool:
        """Add a new signature to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            current_time = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO signatures 
                (signature_type, signature_value, malware_name, threat_level, 
                 description, source, created_date, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (signature_type, signature_value, malware_name, threat_level,
                  description, source, current_time, current_time))
            
            conn.commit()
            print(f"[DATABASE] Added signature: {malware_name} ({signature_type})")
            return True
            
        except sqlite3.IntegrityError:
            print(f"[WARNING] Signature already exists: {signature_value}")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to add signature: {e}")
            return False
        finally:
            conn.close()
    
    def check_signature(self, signature_value: str, signature_type: str = "hash") -> Optional[Dict]:
        """Check if a signature exists in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM signatures 
                WHERE signature_value = ? AND signature_type = ? AND is_active = 1
            ''', (signature_value, signature_type))
            
            result = cursor.fetchone()
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
            return None
            
        except Exception as e:
            print(f"[ERROR] Database query failed: {e}")
            return None
        finally:
            conn.close()
    
    def bulk_import_signatures(self, signatures_file: str) -> int:
        """Import signatures from JSON file"""
        try:
            with open(signatures_file, 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            
            # Import hash signatures
            if 'hashes' in data:
                for hash_sig in data['hashes']:
                    if isinstance(hash_sig, str):
                        # Simple hash string
                        if self.add_signature("hash", hash_sig, "Unknown Malware"):
                            imported_count += 1
                    elif isinstance(hash_sig, dict):
                        # Detailed hash object
                        if self.add_signature(
                            "hash", 
                            hash_sig.get('hash', ''),
                            hash_sig.get('name', 'Unknown Malware'),
                            hash_sig.get('threat_level', 5),
                            hash_sig.get('description', ''),
                            hash_sig.get('source', 'import')
                        ):
                            imported_count += 1
            
            # Import pattern signatures
            if 'patterns' in data:
                for pattern in data['patterns']:
                    self.add_pattern_signature(
                        pattern.get('name', 'Unknown Pattern'),
                        pattern.get('regex', ''),
                        pattern.get('file_types', ''),
                        pattern.get('threat_level', 5),
                        pattern.get('description', '')
                    )
                    imported_count += 1
            
            print(f"[DATABASE] Imported {imported_count} signatures")
            return imported_count
            
        except Exception as e:
            print(f"[ERROR] Failed to import signatures: {e}")
            return 0
    
    def add_pattern_signature(self, pattern_name: str, pattern_regex: str,
                            file_types: str = "", threat_level: int = 5,
                            description: str = "") -> bool:
        """Add a pattern-based signature for advanced detection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            current_time = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO signature_patterns 
                (pattern_name, pattern_regex, file_types, threat_level, description, created_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (pattern_name, pattern_regex, file_types, threat_level, description, current_time))
            
            conn.commit()
            print(f"[DATABASE] Added pattern signature: {pattern_name}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to add pattern signature: {e}")
            return False
        finally:
            conn.close()
    
    def log_scan_result(self, file_path: str, file_hash: str, 
                       threat_detected: bool = False, signature_matched: str = "",
                       action_taken: str = "none"):
        """Log scan results to history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            scan_date = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO scan_history 
                (file_path, file_hash, scan_date, threat_detected, signature_matched, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_path, file_hash, scan_date, threat_detected, signature_matched, action_taken))
            
            conn.commit()
            
        except Exception as e:
            print(f"[ERROR] Failed to log scan result: {e}")
        finally:
            conn.close()
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Count signatures by type
            cursor.execute('SELECT signature_type, COUNT(*) FROM signatures WHERE is_active = 1 GROUP BY signature_type')
            signature_counts = dict(cursor.fetchall())
            
            # Count total signatures
            cursor.execute('SELECT COUNT(*) FROM signatures WHERE is_active = 1')
            total_signatures = cursor.fetchone()[0]
            
            # Count pattern signatures
            cursor.execute('SELECT COUNT(*) FROM signature_patterns WHERE is_active = 1')
            pattern_signatures = cursor.fetchone()[0]
            
            # Recent scan statistics
            cursor.execute('SELECT COUNT(*) FROM scan_history WHERE scan_date > datetime("now", "-7 days")')
            recent_scans = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scan_history WHERE threat_detected = 1 AND scan_date > datetime("now", "-7 days")')
            recent_threats = cursor.fetchone()[0]
            
            return {
                'total_signatures': total_signatures,
                'signature_types': signature_counts,
                'pattern_signatures': pattern_signatures,
                'recent_scans_7days': recent_scans,
                'recent_threats_7days': recent_threats,
                'database_path': self.db_path
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get statistics: {e}")
            return {}
        finally:
            conn.close()
    
    def update_signature_database(self, update_source: str = "online"):
        """Update signature database from external source"""
        print(f"[DATABASE] Updating signatures from {update_source}...")
        
        # Simulate downloading new signatures
        new_signatures = {
            "hashes": [
                {
                    "hash": "a1b2c3d4e5f6789012345678901234567890abcdef",
                    "name": "Trojan.Generic.001",
                    "threat_level": 8,
                    "description": "Generic trojan detected by heuristic analysis",
                    "source": "threat_intel_feed"
                },
                {
                    "hash": "fedcba0987654321098765432109876543210fedcba",
                    "name": "Ransomware.Crypto.002", 
                    "threat_level": 10,
                    "description": "Crypto-ransomware variant",
                    "source": "threat_intel_feed"
                }
            ],
            "patterns": [
                {
                    "name": "Suspicious PowerShell",
                    "regex": r"powershell.*-encodedcommand",
                    "file_types": ".ps1,.bat,.cmd",
                    "threat_level": 6,
                    "description": "Encoded PowerShell commands often used by malware"
                }
            ]
        }
        
        # Save to temporary file and import
        temp_file = "temp_signatures.json"
        with open(temp_file, 'w') as f:
            json.dump(new_signatures, f)
        
        imported = self.bulk_import_signatures(temp_file)
        
        # Clean up
        Path(temp_file).unlink(missing_ok=True)
        
        print(f"[DATABASE] Update complete. Added {imported} new signatures.")
        return imported

# Demo usage and testing
if __name__ == "__main__":
    print("=== ANTIVIRUS SIGNATURE DATABASE DEMO ===")
    
    # Initialize database
    db = SignatureDatabase()
    
    # Add some sample signatures
    print("\n--- Adding Sample Signatures ---")
    db.add_signature("hash", "d41d8cd98f00b204e9800998ecf8427e", "Empty File Test", 1, "Test signature for empty files")
    db.add_signature("hash", "5d41402abc4b2a76b9719d911017c592", "Hello World Test", 2, "Test signature for 'hello' string")
    db.add_signature("hash", "malicious_hash_example_123456789", "Trojan.Example", 9, "Example trojan signature")
    
    # Add pattern signatures
    db.add_pattern_signature("Suspicious Executable", r"\.exe$", ".exe", 7, "Executable file pattern")
    
    # Test signature checking
    print("\n--- Testing Signature Lookup ---")
    result = db.check_signature("d41d8cd98f00b204e9800998ecf8427e", "hash")
    if result:
        print(f"Found signature: {result['malware_name']} (Threat Level: {result['threat_level']})")
    
    # Log some scan results
    print("\n--- Logging Scan Results ---")
    db.log_scan_result("/test/file1.exe", "d41d8cd98f00b204e9800998ecf8427e", True, "Empty File Test", "quarantined")
    db.log_scan_result("/test/file2.txt", "5d41402abc4b2a76b9719d911017c592", False, "", "none")
    
    # Update database
    print("\n--- Updating Signature Database ---")
    db.update_signature_database()
    
    # Show statistics
    print("\n--- Database Statistics ---")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n=== Database Demo Complete ===")
