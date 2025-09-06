import json
import subprocess
import time
from pathlib import Path

class MonitorIntegration:
    """Integration layer between Go monitor and Python scanner"""
    
    def __init__(self, monitor_log_path="antivirus_monitor.log"):
        self.monitor_log_path = monitor_log_path
        self.last_position = 0
    
    def parse_monitor_events(self):
        """Parse events from monitor log file"""
        events = []
        
        try:
            with open(self.monitor_log_path, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                for line in new_lines:
                    if 'THREAT' in line or 'ALERT' in line:
                        events.append({
                            'timestamp': line.split(']')[0][1:],
                            'level': line.split(']')[1].split(':')[0].strip(),
                            'message': ':'.join(line.split(':')[2:]).strip()
                        })
        
        except FileNotFoundError:
            pass
        
        return events
    
    def start_monitor_daemon(self):
        """Start the Go monitor as a background process"""
        try:
            # Compile Go program first
            compile_result = subprocess.run(['go', 'build', '-o', 'monitor', 'scripts/realtime_monitor.go'], 
                                          capture_output=True, text=True)
            
            if compile_result.returncode != 0:
                print(f"Failed to compile Go monitor: {compile_result.stderr}")
                return False
            
            # Start monitor process
            process = subprocess.Popen(['./monitor'], 
                                     stdin=subprocess.PIPE, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            # Send start command
            process.stdin.write("start\n")
            process.stdin.flush()
            
            print("Go monitor started successfully")
            return True
            
        except Exception as e:
            print(f"Failed to start monitor: {e}")
            return False
    
    def get_monitor_status(self):
        """Get current monitor status"""
        try:
            # Check if monitor log exists and is being updated
            log_path = Path(self.monitor_log_path)
            if log_path.exists():
                stat = log_path.stat()
                last_modified = time.time() - stat.st_mtime
                
                return {
                    'log_exists': True,
                    'last_activity': last_modified,
                    'active': last_modified < 60,  # Active if updated in last minute
                    'log_size': stat.st_size
                }
            else:
                return {
                    'log_exists': False,
                    'active': False
                }
        
        except Exception as e:
            return {'error': str(e), 'active': False}
    
    def create_test_threat(self):
        """Create a test file to trigger monitor detection"""
        test_file = "test_threat.bat"
        
        with open(test_file, 'w') as f:
            f.write('@echo off\n')
            f.write('powershell -encodedcommand SGVsbG8gV29ybGQ=\n')
            f.write('echo "This is a test threat file"\n')
        
        print(f"Created test threat file: {test_file}")
        return test_file
    
    def monitor_events_realtime(self, duration=30):
        """Monitor events in real-time for specified duration"""
        print(f"Monitoring events for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            events = self.parse_monitor_events()
            
            for event in events:
                print(f"[{event['timestamp']}] {event['level']}: {event['message']}")
            
            time.sleep(1)
        
        print("Monitoring complete")

# Demo usage
if __name__ == "__main__":
    print("=== MONITOR INTEGRATION DEMO ===")
    
    integration = MonitorIntegration()
    
    # Check monitor status
    status = integration.get_monitor_status()
    print(f"Monitor status: {status}")
    
    # Create test threat file
    test_file = integration.create_test_threat()
    
    print("\nMonitor integration ready!")
    print("To test:")
    print("1. Run 'go run scripts/realtime_monitor.go' in another terminal")
    print("2. Type 'start' to begin monitoring")
    print("3. The test threat file should be detected")
    
    # Monitor events for a short time
    integration.monitor_events_realtime(10)
    
    # Clean up test file
    try:
        Path(test_file).unlink()
        print(f"Cleaned up test file: {test_file}")
    except:
        pass
