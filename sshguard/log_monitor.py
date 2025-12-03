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
            event_type: Type of event (failed_password, auth_failure, accepted_password, invalid_user)
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
    # Month name to number mapping
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
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
    
    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse timestamp string to Unix timestamp.
        
        Args:
            ts_str: Timestamp string (ISO format or syslog format)
            
        Returns:
            Unix timestamp (float)
        """
        try:
            # Try ISO format first: 2024-01-15T10:30:45
            if 'T' in ts_str:
                dt = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                return dt.timestamp()
            else:
                # Syslog format: Jan 15 10:30:45
                # Note: syslog format doesn't include year, assume current year
                parts = ts_str.split()
                if len(parts) >= 3:
                    month_name, day, time_str = parts[0], parts[1], parts[2]
                    month = self.MONTHS.get(month_name, 1)
                    current_year = datetime.now().year
                    dt = datetime.strptime(
                        f"{current_year}-{month:02d}-{day:02d} {time_str}",
                        '%Y-%m-%d %H:%M:%S'
                    )
                    return dt.timestamp()
        except (ValueError, KeyError) as e:
            # Fallback to current time if parsing fails
            return time.time()
        
        return time.time()
    
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
        
        # Parse actual timestamp from log
        timestamp = self._parse_timestamp(ts_match.group(1))
        
        # Check for failed password
        match = self.FAILED_PASSWORD.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'failed_password')
        
        # Check for accepted password
        match = self.ACCEPTED_PASSWORD.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'accepted_password')
        
        # Check for invalid user
        match = self.INVALID_USER.search(line)
        if match:
            username, ip = match.groups()
            return SSHEvent(timestamp, ip, username, 'invalid_user')
        
        # Check for authentication failure (pam_unix format)
        match = self.AUTH_FAILURE.search(line)
        if match:
            ip, username = match.groups()
            return SSHEvent(timestamp, ip, username, 'auth_failure')
        
        return None
    
    def add_event(self, event: SSHEvent):
        """Add event to IP's event window.
        
        Args:
            event: SSH event to add
        """
        self.ip_windows[event.ip].append(event)
    
    def get_event_sequence(self, ip: str, max_age_seconds: Optional[int] = None) -> List[SSHEvent]:
        """Get event sequence for an IP, optionally filtered by age.
        
        Args:
            ip: IP address
            max_age_seconds: If provided, only return events within this time window
            
        Returns:
            List of SSH events for the IP (optionally filtered by time)
        """
        events = list(self.ip_windows[ip])
        
        if max_age_seconds is not None:
            current_time = time.time()
            cutoff_time = current_time - max_age_seconds
            events = [e for e in events if e.timestamp >= cutoff_time]
        
        return events
    
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

