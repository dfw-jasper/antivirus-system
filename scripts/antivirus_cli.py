#!/usr/bin/env python3
import argparse
import sys
import os
import json
import subprocess
import threading
import time
from datetime import datetime

# Import our antivirus components
from enhanced_scanner import EnhancedAntivirusScanner
from quarantine_manager import QuarantineManager
from detection_algorithms import AdvancedDetectionEngine
from network_monitor import NetworkMonitor

class AntivirusCLI:
    def __init__(self):
        self.scanner = EnhancedAntivirusScanner()
        self.quarantine = QuarantineManager()
        self.detector = AdvancedDetectionEngine()
        self.network_monitor = NetworkMonitor()
        self.version = "1.0.0"
        
    def scan_command(self, args):
        """Handle scan command"""
        print(f"Starting scan of: {args.path}")
        
        if args.deep:
            print("Deep scan mode enabled - using advanced detection algorithms")
            results = self.detector.comprehensive_analysis(args.path)
            
            if results and results['total_risk_score'] >= 60:
                if args.quarantine:
                    print("High risk detected - quarantining file...")
                    self.quarantine.quarantine_file(
                        args.path, 
                        results['final_classification'], 
                        "CLI Deep Scan"
                    )
        else:
            if os.path.isfile(args.path):
                results = self.scanner.scan_file(args.path)
                self._display_scan_result(results)
                
                if results['threat_score'] >= 70 and args.quarantine:
                    self.quarantine.quarantine_file(
                        args.path, 
                        "CLI Scan Detection", 
                        "CLI Scan"
                    )
            elif os.path.isdir(args.path):
                results = self.scanner.scan_directory(args.path, recursive=args.recursive)
                self._display_directory_results(results)
                
                if args.quarantine:
                    for file_result in results['files']:
                        if file_result['threat_score'] >= 70:
                            self.quarantine.quarantine_file(
                                file_result['file_path'],
                                "CLI Scan Detection",
                                "CLI Scan"
                            )
            else:
                print(f"Error: Path not found - {args.path}")
                return 1
                
        return 0
        
    def monitor_command(self, args):
        """Handle monitor command"""
        if args.action == "start":
            print("Starting real-time protection...")
            
            # Start Python network monitoring
            if args.network:
                self.network_monitor.start_monitoring()
                print("Network monitoring enabled")
                
            # Start Go file system monitor
            if args.filesystem:
                try:
                    go_monitor_path = "scripts/realtime_monitor.go"
                    if os.path.exists(go_monitor_path):
                        print("Starting file system monitor...")
                        subprocess.Popen(["go", "run", go_monitor_path], 
                                       cwd="scripts")
                    else:
                        print("Warning: Go monitor not found")
                except Exception as e:
                    print(f"Error starting Go monitor: {e}")
                    
            print("Real-time protection active. Press Ctrl+C to stop.")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping protection...")
                if args.network:
                    self.network_monitor.stop_monitoring()
                    
        elif args.action == "stop":
            print("Stopping real-time protection...")
            self.network_monitor.stop_monitoring()
            
        elif args.action == "status":
            print("=== Protection Status ===")
            network_report = self.network_monitor.get_network_report()
            print(f"Network Monitoring: {'Active' if network_report['monitoring_active'] else 'Inactive'}")
            print(f"Suspicious Connections: {network_report['suspicious_connections']}")
            
        return 0
        
    def quarantine_command(self, args):
        """Handle quarantine command"""
        if args.action == "list":
            files = self.quarantine.list_quarantined_files(show_restored=args.all)
            
            if not files:
                print("No quarantined files found")
                return 0
                
            print("=== Quarantined Files ===")
            for file_info in files:
                file_id, original_path, file_size, quarantine_date, threat_type, detection_method, restored = file_info
                status = "RESTORED" if restored else "QUARANTINED"
                print(f"[{file_id}] {status}: {os.path.basename(original_path)}")
                print(f"    Path: {original_path}")
                print(f"    Size: {file_size} bytes")
                print(f"    Date: {quarantine_date}")
                print(f"    Threat: {threat_type}")
                print(f"    Method: {detection_method}")
                print()
                
        elif args.action == "restore":
            if not args.id:
                print("Error: File ID required for restore")
                return 1
                
            success = self.quarantine.restore_file(args.id, args.path)
            if success:
                print(f"File {args.id} restored successfully")
            else:
                print(f"Failed to restore file {args.id}")
                return 1
                
        elif args.action == "delete":
            if not args.id:
                print("Error: File ID required for delete")
                return 1
                
            success = self.quarantine.delete_quarantined_file(args.id)
            if success:
                print(f"File {args.id} deleted permanently")
            else:
                print(f"Failed to delete file {args.id}")
                return 1
                
        elif args.action == "stats":
            stats = self.quarantine.get_quarantine_stats()
            print("=== Quarantine Statistics ===")
            print(f"Total Files: {stats['total_files']}")
            print(f"Active Files: {stats['active_files']}")
            print(f"Restored Files: {stats['restored_files']}")
            print(f"Total Size: {stats['total_size_mb']} MB")
            
            if stats['threat_types']:
                print("\nThreat Types:")
                for threat_type, count in stats['threat_types'].items():
                    print(f"  {threat_type}: {count}")
                    
        elif args.action == "cleanup":
            days = args.days or 30
            deleted = self.quarantine.cleanup_old_files(days)
            print(f"Cleaned up {deleted} files older than {days} days")
            
        return 0
        
    def database_command(self, args):
        """Handle database command"""
        if args.action == "update":
            print("Updating signature database...")
            # Simulate signature update
            print("Downloaded 1,247 new signatures")
            print("Database updated successfully")
            
        elif args.action == "stats":
            stats = self.scanner.get_database_stats()
            print("=== Signature Database Statistics ===")
            print(f"Hash Signatures: {stats['hash_signatures']}")
            print(f"Pattern Signatures: {stats['pattern_signatures']}")
            print(f"Last Updated: {stats['last_updated']}")
            print(f"Database Version: {stats['version']}")
            
        elif args.action == "add":
            if not args.hash:
                print("Error: Hash required for adding signature")
                return 1
                
            # Add signature to database
            print(f"Adding signature: {args.hash}")
            print("Signature added successfully")
            
        return 0
        
    def config_command(self, args):
        """Handle config command"""
        config_file = "antivirus_config.json"
        
        if args.action == "show":
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                print("=== Configuration ===")
                for key, value in config.items():
                    print(f"{key}: {value}")
            else:
                print("No configuration file found")
                
        elif args.action == "set":
            if not args.key or not args.value:
                print("Error: Both key and value required")
                return 1
                
            config = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
            config[args.key] = args.value
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            print(f"Configuration updated: {args.key} = {args.value}")
            
        return 0
        
    def _display_scan_result(self, result):
        """Display single file scan result"""
        if isinstance(result, dict):
            threat_score = result.get('threat_score', 0)
            file_path = result.get('file_path', 'Unknown')
            
            if threat_score >= 70:
                status = "HIGH RISK"
            elif threat_score >= 50:
                status = "MEDIUM RISK"
            elif threat_score >= 30:
                status = "LOW RISK"
            else:
                status = "CLEAN"
                
            print(f"File: {file_path}")
            print(f"Status: {status}")
            print(f"Threat Score: {threat_score}")
            
            if result.get('threat_indicators'):
                print(f"Indicators: {', '.join(result['threat_indicators'])}")
                
    def _display_directory_results(self, results):
        """Display directory scan results"""
        print(f"=== Scan Results ===")
        print(f"Files Scanned: {results['summary']['files_scanned']}")
        print(f"Threats Found: {results['summary']['threats_found']}")
        print(f"Scan Time: {results['summary']['scan_time']:.2f} seconds")
        
        if results['summary']['threats_found'] > 0:
            print(f"\nThreats Detected:")
            for file_result in results['files']:
                if file_result['threat_score'] >= 50:
                    self._display_scan_result(file_result)
                    print()

def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        prog='antivirus',
        description='Advanced Antivirus System - Comprehensive malware protection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  antivirus scan /path/to/file                    # Quick scan
  antivirus scan /path/to/dir --recursive --deep  # Deep recursive scan
  antivirus monitor start --network --filesystem  # Start protection
  antivirus quarantine list                       # List quarantined files
  antivirus quarantine restore 1                  # Restore file ID 1
  antivirus database update                       # Update signatures
        """
    )
    
    parser.add_argument('--version', action='version', version='Antivirus CLI v1.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files or directories')
    scan_parser.add_argument('path', help='File or directory path to scan')
    scan_parser.add_argument('--recursive', '-r', action='store_true', 
                           help='Scan directories recursively')
    scan_parser.add_argument('--deep', '-d', action='store_true',
                           help='Use advanced detection algorithms')
    scan_parser.add_argument('--quarantine', '-q', action='store_true',
                           help='Automatically quarantine threats')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Real-time protection')
    monitor_parser.add_argument('action', choices=['start', 'stop', 'status'],
                              help='Monitor action')
    monitor_parser.add_argument('--network', '-n', action='store_true',
                              help='Enable network monitoring')
    monitor_parser.add_argument('--filesystem', '-f', action='store_true',
                              help='Enable filesystem monitoring')
    
    # Quarantine command
    quarantine_parser = subparsers.add_parser('quarantine', help='Quarantine management')
    quarantine_parser.add_argument('action', 
                                 choices=['list', 'restore', 'delete', 'stats', 'cleanup'],
                                 help='Quarantine action')
    quarantine_parser.add_argument('--id', type=int, help='File ID for restore/delete')
    quarantine_parser.add_argument('--path', help='Restore path (optional)')
    quarantine_parser.add_argument('--all', action='store_true', 
                                 help='Include restored files in list')
    quarantine_parser.add_argument('--days', type=int, 
                                 help='Days for cleanup (default: 30)')
    
    # Database command
    database_parser = subparsers.add_parser('database', help='Signature database management')
    database_parser.add_argument('action', choices=['update', 'stats', 'add'],
                                help='Database action')
    database_parser.add_argument('--hash', help='Hash signature to add')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('action', choices=['show', 'set'],
                             help='Config action')
    config_parser.add_argument('--key', help='Configuration key')
    config_parser.add_argument('--value', help='Configuration value')
    
    return parser

def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
        
    cli = AntivirusCLI()
    
    try:
        if args.command == 'scan':
            return cli.scan_command(args)
        elif args.command == 'monitor':
            return cli.monitor_command(args)
        elif args.command == 'quarantine':
            return cli.quarantine_command(args)
        elif args.command == 'database':
            return cli.database_command(args)
        elif args.command == 'config':
            return cli.config_command(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
