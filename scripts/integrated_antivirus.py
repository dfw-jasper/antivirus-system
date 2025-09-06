import os
import sys
import threading
import time
from datetime import datetime

# Import our antivirus components
from enhanced_scanner import EnhancedScanner
from quarantine_manager import QuarantineManager

class IntegratedAntivirus:
    def __init__(self):
        self.scanner = EnhancedScanner()
        self.quarantine = QuarantineManager()
        self.running = False
        self.scan_thread = None
        
    def start_protection(self):
        """Start real-time protection"""
        self.running = True
        print("🛡️  Antivirus protection started")
        print("Monitoring file system for threats...")
        
        # Start background scanning thread
        self.scan_thread = threading.Thread(target=self._background_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_protection(self):
        """Stop real-time protection"""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join()
        print("🛡️  Antivirus protection stopped")
        
    def _background_scan(self):
        """Background scanning process"""
        while self.running:
            try:
                # Scan common directories periodically
                scan_dirs = [
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    "/tmp" if os.name != 'nt' else os.environ.get('TEMP', 'C:\\temp')
                ]
                
                for scan_dir in scan_dirs:
                    if os.path.exists(scan_dir) and self.running:
                        self._scan_directory_for_threats(scan_dir)
                        
                # Wait before next scan cycle
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                print(f"Error in background scan: {e}")
                time.sleep(10)
                
    def _scan_directory_for_threats(self, directory):
        """Scan directory and quarantine threats"""
        try:
            results = self.scanner.scan_directory(directory, recursive=False)
            
            for result in results['files']:
                if result['threat_score'] >= 70:  # High threat threshold
                    file_path = result['file_path']
                    threat_indicators = result['threat_indicators']
                    
                    print(f"🚨 THREAT DETECTED: {file_path}")
                    print(f"   Threat Score: {result['threat_score']}")
                    print(f"   Indicators: {', '.join(threat_indicators)}")
                    
                    # Quarantine the file
                    threat_type = "High Risk File"
                    if "Known malware signature" in threat_indicators:
                        threat_type = "Known Malware"
                    elif "Suspicious executable" in threat_indicators:
                        threat_type = "Suspicious Executable"
                    
                    success = self.quarantine.quarantine_file(
                        file_path, 
                        threat_type, 
                        "Real-time Protection"
                    )
                    
                    if success:
                        print(f"   ✓ File quarantined successfully")
                    else:
                        print(f"   ✗ Failed to quarantine file")
                        
        except Exception as e:
            print(f"Error scanning directory {directory}: {e}")
            
    def manual_scan(self, path):
        """Perform manual scan of specified path"""
        print(f"🔍 Starting manual scan of: {path}")
        
        if os.path.isfile(path):
            results = self.scanner.scan_file(path)
            self._process_scan_results([results])
        elif os.path.isdir(path):
            results = self.scanner.scan_directory(path)
            self._process_scan_results(results['files'])
        else:
            print(f"❌ Path not found: {path}")
            
    def _process_scan_results(self, results):
        """Process and display scan results"""
        threats_found = 0
        
        for result in results:
            if isinstance(result, dict) and 'threat_score' in result:
                threat_score = result['threat_score']
                file_path = result['file_path']
                
                if threat_score >= 50:
                    threats_found += 1
                    status = "🚨 HIGH RISK" if threat_score >= 70 else "⚠️  MEDIUM RISK"
                    
                    print(f"{status}: {file_path}")
                    print(f"   Threat Score: {threat_score}")
                    print(f"   Indicators: {', '.join(result['threat_indicators'])}")
                    
                    if threat_score >= 70:
                        # Auto-quarantine high-risk files
                        response = input(f"   Quarantine this file? (y/N): ").lower()
                        if response == 'y':
                            success = self.quarantine.quarantine_file(
                                file_path, 
                                "Manual Scan Detection", 
                                "Manual Scan"
                            )
                            if success:
                                print(f"   ✓ File quarantined")
                            else:
                                print(f"   ✗ Failed to quarantine")
                                
        if threats_found == 0:
            print("✅ No threats detected")
        else:
            print(f"\n📊 Scan complete: {threats_found} threats found")
            
    def show_quarantine_status(self):
        """Display quarantine status"""
        print("\n=== Quarantine Status ===")
        
        stats = self.quarantine.get_quarantine_stats()
        print(f"Active Quarantined Files: {stats['active_files']}")
        print(f"Total Files Ever Quarantined: {stats['total_files']}")
        print(f"Files Restored: {stats['restored_files']}")
        print(f"Total Size: {stats['total_size_mb']} MB")
        
        if stats['threat_types']:
            print("\nThreat Types:")
            for threat_type, count in stats['threat_types'].items():
                print(f"  {threat_type}: {count}")
                
        # List recent quarantined files
        quarantined = self.quarantine.list_quarantined_files()
        if quarantined:
            print(f"\nRecent Quarantined Files:")
            for i, file_info in enumerate(quarantined[:5]):  # Show last 5
                file_id, original_path, file_size, quarantine_date, threat_type, detection_method, restored = file_info
                print(f"  {file_id}: {os.path.basename(original_path)} ({threat_type})")
                
    def interactive_mode(self):
        """Interactive command-line interface"""
        print("\n=== Integrated Antivirus System ===")
        print("Commands:")
        print("  1. start - Start real-time protection")
        print("  2. stop - Stop real-time protection") 
        print("  3. scan <path> - Manual scan")
        print("  4. quarantine - Show quarantine status")
        print("  5. restore <id> - Restore quarantined file")
        print("  6. delete <id> - Delete quarantined file")
        print("  7. cleanup - Clean old quarantined files")
        print("  8. quit - Exit")
        
        while True:
            try:
                command = input("\nantivirus> ").strip().split()
                
                if not command:
                    continue
                    
                cmd = command[0].lower()
                
                if cmd == "start":
                    if not self.running:
                        self.start_protection()
                    else:
                        print("Protection already running")
                        
                elif cmd == "stop":
                    if self.running:
                        self.stop_protection()
                    else:
                        print("Protection not running")
                        
                elif cmd == "scan":
                    if len(command) > 1:
                        path = " ".join(command[1:])
                        self.manual_scan(path)
                    else:
                        print("Usage: scan <path>")
                        
                elif cmd == "quarantine":
                    self.show_quarantine_status()
                    
                elif cmd == "restore":
                    if len(command) > 1:
                        try:
                            file_id = int(command[1])
                            success = self.quarantine.restore_file(file_id)
                            if success:
                                print("✓ File restored successfully")
                            else:
                                print("✗ Failed to restore file")
                        except ValueError:
                            print("Invalid file ID")
                    else:
                        print("Usage: restore <id>")
                        
                elif cmd == "delete":
                    if len(command) > 1:
                        try:
                            file_id = int(command[1])
                            success = self.quarantine.delete_quarantined_file(file_id)
                            if success:
                                print("✓ File deleted permanently")
                            else:
                                print("✗ Failed to delete file")
                        except ValueError:
                            print("Invalid file ID")
                    else:
                        print("Usage: delete <id>")
                        
                elif cmd == "cleanup":
                    deleted = self.quarantine.cleanup_old_files()
                    print(f"✓ Cleaned up {deleted} old files")
                    
                elif cmd in ["quit", "exit"]:
                    if self.running:
                        self.stop_protection()
                    print("Goodbye!")
                    break
                    
                else:
                    print("Unknown command. Type 'quit' to exit.")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                if self.running:
                    self.stop_protection()
                break
            except Exception as e:
                print(f"Error: {e}")

def main():
    """Main entry point"""
    antivirus = IntegratedAntivirus()
    
    # Check if running in interactive mode
    if len(sys.argv) > 1:
        if sys.argv[1] == "scan" and len(sys.argv) > 2:
            # Command line scan
            path = " ".join(sys.argv[2:])
            antivirus.manual_scan(path)
        elif sys.argv[1] == "protect":
            # Start protection and wait
            antivirus.start_protection()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                antivirus.stop_protection()
        else:
            print("Usage: python integrated_antivirus.py [scan <path>|protect]")
    else:
        # Interactive mode
        antivirus.interactive_mode()

if __name__ == "__main__":
    main()
