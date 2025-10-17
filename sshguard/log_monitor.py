import re
import time
import subprocess
from typing import Optional, Dict, List
from collections import defaultdict, deque
from datetime import datetime

class SSHEvent:
    def __init__(self, timestamp: float, ip: str, username: str, event_type: str):
        """Initialize SSH event.
        
        Args:
            timestamp: Unix timestamp
            ip: Source IP address
            username: Attempted username
            event_type: Type of event (failed_auth, accepted_auth, invalid_user)
        """
        self.timestamp = timestamp
        self.ip = ip
        self.username = username
        self.event_type = event_type
    
    def __repr__(self):
        return f"SSHEvent({self.ip}, {self.username}, {self.event_type})"

class LogMonitor:
    """Monitor and parse SSH authentication logs."""
    
    # Regex patterns for SSH log parsing
    FAILED_PASSWORD = re.compile(
        r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
    )
    ACCEPTED_PASSWORD = re.compile(
        r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
    )
    INVALID_USER = re.compile(
        r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
    )
    AUTH_FAILURE = re.compile(
        r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\S+)'
    )
    TIMESTAMP = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w+\s+\d+\s+\d+:\d+:\d+)'
    )
    
    def __init__(self, log_file: str, window_size: int = 100):
        """Initialize log monitor.
        
        Args:
            log_file: Path to auth.log file
            window_size: Number of events to keep per IP
        """
        self.log_file = log_file
        self.window_size = window_size
        self.ip_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.tail_process: Optional[subprocess.Popen] = None
    
    def parse_line(self, line: str) -> Optional[SSHEvent]:
        """Parse a single log line.
        
        Args:
            line: Log line to parse
            
        Returns:
            SSHEvent if line contains SSH event, None otherwise
        """
        # Extract timestamp
        ts_match = self.TIMESTAMP.match(line)
        if not ts_match:
            return None
        
        timestamp = time.time()  # Use current time for simplicity
        
        # Check for failed password
        match = self.FAILED_PASSWORD.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'failed_auth')
        
        # Check for accepted password
        match = self.ACCEPTED_PASSWORD.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'accepted_auth')
        
        # Check for invalid user
        match = self.INVALID_USER.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'invalid_user')
        
        # Check for authentication failure (pam_unix format)
        match = self.AUTH_FAILURE.search(line)
        if match:
            ip, username = match.groups()
            return SSHEvent(timestamp, ip, username, 'failed_auth')
        
        return None
    
    def add_event(self, event: SSHEvent):
        """Add event to IP's event window.
        
        Args:
            event: SSH event to add
        """
        self.ip_windows[event.ip].append(event)
    
    def get_event_sequence(self, ip: str) -> List[SSHEvent]:
        """Get event sequence for an IP.
        
        Args:
            ip: IP address
            
        Returns:
            List of SSH events for the IP
        """
        return list(self.ip_windows[ip])
    
    def start_tail(self):
        """Start tailing the log file.
        
        Returns:
            Generator yielding log lines
        """
        try:
            # Use tail -F to follow log file (handles log rotation)
            self.tail_process = subprocess.Popen(
                ['tail', '-F', '-n', '0', self.log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in iter(self.tail_process.stdout.readline, ''):
                if line:
                    yield line.strip()
        except FileNotFoundError:
            # If tail command not found, fall back to Python implementation
            yield from self._python_tail()
    
    def _python_tail(self):
        """Python-based tail implementation (fallback).
        
        Returns:
            Generator yielding log lines
        """
        try:
            with open(self.log_file, 'r') as f:
                # Seek to end
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.1)
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file} not found")
            return
    
    def stop_tail(self):
        """Stop tailing the log file."""
        if self.tail_process:
            self.tail_process.terminate()
            self.tail_process.wait(timeout=5)
    
    def get_active_ips(self) -> List[str]:
        return list(self.ip_windows.keys())

