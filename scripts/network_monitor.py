import socket
import threading
import time
import json
from datetime import datetime
import logging

class NetworkMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.suspicious_connections = []
        
        # Known malicious IP ranges and domains (simplified examples)
        self.blacklisted_ips = {
            '192.168.1.100',  # Example suspicious IP
            '10.0.0.50',      # Example C&C server
        }
        
        self.suspicious_domains = {
            'malware-c2.com',
            'botnet-command.net',
            'suspicious-site.org'
        }
        
        # Suspicious ports commonly used by malware
        self.suspicious_ports = {
            1337, 31337, 4444, 5555, 6666, 7777, 8080, 9999,
            1234, 12345, 54321, 65534
        }
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.monitoring = True
        print("🌐 Network monitoring started")
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_connections, daemon=True).start()
        threading.Thread(target=self._monitor_dns_requests, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        print("🌐 Network monitoring stopped")
        
    def _monitor_connections(self):
        """Monitor network connections for suspicious activity"""
        while self.monitoring:
            try:
                # Simulate connection monitoring
                # In a real implementation, this would use netstat or similar
                self._check_active_connections()
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error monitoring connections: {e}")
                time.sleep(10)
                
    def _monitor_dns_requests(self):
        """Monitor DNS requests for suspicious domains"""
        while self.monitoring:
            try:
                # Simulate DNS monitoring
                # In a real implementation, this would intercept DNS queries
                self._check_dns_activity()
                time.sleep(3)
                
            except Exception as e:
                self.logger.error(f"Error monitoring DNS: {e}")
                time.sleep(10)
                
    def _check_active_connections(self):
        """Check for suspicious active connections"""
        try:
            # Simulate checking network connections
            # This would normally parse netstat output or use system APIs
            
            # Example suspicious connection detection
            suspicious_connection = {
                'timestamp': datetime.now().isoformat(),
                'local_port': 4444,
                'remote_ip': '192.168.1.100',
                'remote_port': 80,
                'protocol': 'TCP',
                'process': 'suspicious.exe',
                'threat_level': 'high'
            }
            
            # Check if connection matches suspicious patterns
            if (suspicious_connection['remote_ip'] in self.blacklisted_ips or
                suspicious_connection['local_port'] in self.suspicious_ports):
                
                self.suspicious_connections.append(suspicious_connection)
                self._alert_suspicious_connection(suspicious_connection)
                
        except Exception as e:
            self.logger.error(f"Error checking connections: {e}")
            
    def _check_dns_activity(self):
        """Check for suspicious DNS activity"""
        try:
            # Simulate DNS request monitoring
            # This would normally intercept actual DNS queries
            
            # Example suspicious DNS request
            dns_request = {
                'timestamp': datetime.now().isoformat(),
                'domain': 'malware-c2.com',
                'query_type': 'A',
                'process': 'suspicious.exe',
                'resolved_ip': '192.168.1.100'
            }
            
            # Check if domain is suspicious
            if dns_request['domain'] in self.suspicious_domains:
                self._alert_suspicious_dns(dns_request)
                
        except Exception as e:
            self.logger.error(f"Error checking DNS activity: {e}")
            
    def _alert_suspicious_connection(self, connection):
        """Alert on suspicious network connection"""
        print(f"🚨 SUSPICIOUS CONNECTION DETECTED!")
        print(f"   Remote IP: {connection['remote_ip']}")
        print(f"   Local Port: {connection['local_port']}")
        print(f"   Process: {connection['process']}")
        print(f"   Threat Level: {connection['threat_level']}")
        print(f"   Time: {connection['timestamp']}")
        
    def _alert_suspicious_dns(self, dns_request):
        """Alert on suspicious DNS request"""
        print(f"🚨 SUSPICIOUS DNS REQUEST!")
        print(f"   Domain: {dns_request['domain']}")
        print(f"   Process: {dns_request['process']}")
        print(f"   Resolved IP: {dns_request['resolved_ip']}")
        print(f"   Time: {dns_request['timestamp']}")
        
    def get_network_report(self):
        """Generate network activity report"""
        report = {
            'monitoring_active': self.monitoring,
            'suspicious_connections': len(self.suspicious_connections),
            'recent_alerts': self.suspicious_connections[-10:],  # Last 10
            'blacklisted_ips': list(self.blacklisted_ips),
            'suspicious_domains': list(self.suspicious_domains),
            'monitored_ports': list(self.suspicious_ports)
        }
        
        return report

def main():
    """Demo network monitoring functionality"""
    print("=== Network Security Monitor ===\n")
    
    monitor = NetworkMonitor()
    
    # Start monitoring
    monitor.start_monitoring()
    
    # Run for a short demo period
    print("Monitoring network activity for 15 seconds...")
    time.sleep(15)
    
    # Generate report
    report = monitor.get_network_report()
    print(f"\n--- Network Activity Report ---")
    print(f"Monitoring Active: {report['monitoring_active']}")
    print(f"Suspicious Connections: {report['suspicious_connections']}")
    print(f"Blacklisted IPs: {len(report['blacklisted_ips'])}")
    print(f"Suspicious Domains: {len(report['suspicious_domains'])}")
    
    if report['recent_alerts']:
        print(f"\nRecent Alerts:")
        for alert in report['recent_alerts']:
            print(f"  - {alert['timestamp']}: {alert.get('remote_ip', alert.get('domain'))}")
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    print("\n=== Network Monitor Demo Complete ===")

if __name__ == "__main__":
    main()
