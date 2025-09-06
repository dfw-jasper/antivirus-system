import os
import json
import shutil
import sqlite3
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
import logging

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine", db_path="quarantine.db"):
        self.quarantine_dir = quarantine_dir
        self.db_path = db_path
        self.key_file = os.path.join(quarantine_dir, ".qkey")
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize quarantine system
        self._setup_quarantine()
        self._setup_database()
        
    def _setup_quarantine(self):
        """Initialize quarantine directory and encryption key"""
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Generate or load encryption key
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Hide the key file on Windows
            if os.name == 'nt':
                os.system(f'attrib +h "{self.key_file}"')
                
        self.cipher = Fernet(key)
        
    def _setup_database(self):
        """Initialize quarantine database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                quarantine_date TEXT NOT NULL,
                threat_type TEXT,
                detection_method TEXT,
                restored BOOLEAN DEFAULT FALSE,
                restore_date TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def quarantine_file(self, file_path, threat_type="Unknown", detection_method="Scanner"):
        """Quarantine a suspicious file"""
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
                
            # Calculate file hash
            file_hash = self._calculate_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Generate quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{file_hash[:8]}.qfile"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Encrypt and move file
            with open(file_path, 'rb') as original_file:
                file_data = original_file.read()
                encrypted_data = self.cipher.encrypt(file_data)
                
            with open(quarantine_path, 'wb') as quarantine_file:
                quarantine_file.write(encrypted_data)
                
            # Remove original file
            os.remove(file_path)
            
            # Record in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quarantined_files 
                (original_path, quarantine_path, file_hash, file_size, 
                 quarantine_date, threat_type, detection_method)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_path, quarantine_path, file_hash, file_size,
                  datetime.now().isoformat(), threat_type, detection_method))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
            
    def restore_file(self, quarantine_id, restore_path=None):
        """Restore a quarantined file"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT original_path, quarantine_path, restored 
                FROM quarantined_files WHERE id = ?
            ''', (quarantine_id,))
            
            result = cursor.fetchone()
            if not result:
                self.logger.error(f"Quarantine record not found: {quarantine_id}")
                return False
                
            original_path, quarantine_path, restored = result
            
            if restored:
                self.logger.warning(f"File already restored: {quarantine_id}")
                return False
                
            if not os.path.exists(quarantine_path):
                self.logger.error(f"Quarantined file not found: {quarantine_path}")
                return False
                
            # Determine restore location
            target_path = restore_path or original_path
            
            # Create directory if needed
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            # Decrypt and restore file
            with open(quarantine_path, 'rb') as quarantine_file:
                encrypted_data = quarantine_file.read()
                decrypted_data = self.cipher.decrypt(encrypted_data)
                
            with open(target_path, 'wb') as restored_file:
                restored_file.write(decrypted_data)
                
            # Update database
            cursor.execute('''
                UPDATE quarantined_files 
                SET restored = TRUE, restore_date = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), quarantine_id))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"File restored: {quarantine_path} -> {target_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore file {quarantine_id}: {e}")
            return False
            
    def list_quarantined_files(self, show_restored=False):
        """List all quarantined files"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT id, original_path, file_size, quarantine_date, 
                   threat_type, detection_method, restored
            FROM quarantined_files
        '''
        
        if not show_restored:
            query += ' WHERE restored = FALSE'
            
        query += ' ORDER BY quarantine_date DESC'
        
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        return results
        
    def delete_quarantined_file(self, quarantine_id):
        """Permanently delete a quarantined file"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT quarantine_path FROM quarantined_files WHERE id = ?
            ''', (quarantine_id,))
            
            result = cursor.fetchone()
            if not result:
                self.logger.error(f"Quarantine record not found: {quarantine_id}")
                return False
                
            quarantine_path = result[0]
            
            # Delete encrypted file
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
                
            # Remove from database
            cursor.execute('DELETE FROM quarantined_files WHERE id = ?', (quarantine_id,))
            conn.commit()
            conn.close()
            
            self.logger.info(f"Quarantined file permanently deleted: {quarantine_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete quarantined file {quarantine_id}: {e}")
            return False
            
    def cleanup_old_files(self, days_old=30):
        """Clean up quarantined files older than specified days"""
        try:
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, quarantine_path FROM quarantined_files 
                WHERE quarantine_date < ? AND restored = FALSE
            ''', (cutoff_date.isoformat(),))
            
            old_files = cursor.fetchall()
            deleted_count = 0
            
            for file_id, quarantine_path in old_files:
                if self.delete_quarantined_file(file_id):
                    deleted_count += 1
                    
            conn.close()
            
            self.logger.info(f"Cleaned up {deleted_count} old quarantined files")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old files: {e}")
            return 0
            
    def get_quarantine_stats(self):
        """Get quarantine statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total quarantined files
        cursor.execute('SELECT COUNT(*) FROM quarantined_files')
        total_files = cursor.fetchone()[0]
        
        # Active quarantined files
        cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE restored = FALSE')
        active_files = cursor.fetchone()[0]
        
        # Restored files
        cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE restored = TRUE')
        restored_files = cursor.fetchone()[0]
        
        # Threat types
        cursor.execute('''
            SELECT threat_type, COUNT(*) FROM quarantined_files 
            WHERE restored = FALSE GROUP BY threat_type
        ''')
        threat_types = dict(cursor.fetchall())
        
        # Total size
        cursor.execute('''
            SELECT SUM(file_size) FROM quarantined_files WHERE restored = FALSE
        ''')
        total_size = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_files': total_files,
            'active_files': active_files,
            'restored_files': restored_files,
            'threat_types': threat_types,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2)
        }
        
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

def main():
    """Demo quarantine management functionality"""
    print("=== Antivirus Quarantine Manager ===\n")
    
    qm = QuarantineManager()
    
    # Create a test file to quarantine
    test_file = "test_malware.txt"
    with open(test_file, 'w') as f:
        f.write("This is a simulated malware file for testing purposes.")
    
    print(f"Created test file: {test_file}")
    
    # Quarantine the test file
    print(f"Quarantining {test_file}...")
    success = qm.quarantine_file(test_file, "Test Malware", "Manual Detection")
    
    if success:
        print("✓ File successfully quarantined")
    else:
        print("✗ Failed to quarantine file")
        return
    
    # List quarantined files
    print("\n--- Quarantined Files ---")
    quarantined = qm.list_quarantined_files()
    
    for file_info in quarantined:
        file_id, original_path, file_size, quarantine_date, threat_type, detection_method, restored = file_info
        print(f"ID: {file_id}")
        print(f"Original Path: {original_path}")
        print(f"Size: {file_size} bytes")
        print(f"Quarantined: {quarantine_date}")
        print(f"Threat Type: {threat_type}")
        print(f"Detection Method: {detection_method}")
        print(f"Restored: {restored}")
        print("-" * 40)
    
    # Show statistics
    print("\n--- Quarantine Statistics ---")
    stats = qm.get_quarantine_stats()
    print(f"Total Files: {stats['total_files']}")
    print(f"Active Files: {stats['active_files']}")
    print(f"Restored Files: {stats['restored_files']}")
    print(f"Total Size: {stats['total_size_mb']} MB")
    print(f"Threat Types: {stats['threat_types']}")
    
    # Demonstrate restore functionality
    if quarantined:
        file_id = quarantined[0][0]
        restore_path = f"restored_{test_file}"
        
        print(f"\nRestoring file ID {file_id} to {restore_path}...")
        success = qm.restore_file(file_id, restore_path)
        
        if success:
            print("✓ File successfully restored")
            print(f"Restored file exists: {os.path.exists(restore_path)}")
        else:
            print("✗ Failed to restore file")
    
    print("\n=== Quarantine Management Demo Complete ===")

if __name__ == "__main__":
    main()
