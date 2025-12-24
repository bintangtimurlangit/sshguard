import re
import time
import subprocess
from typing import Optional, Dict, List
from collections import defaultdict, deque
from datetime import datetime

class SSHEvent:
    def __init__(self, timestamp: float, ip: str, username: str, event_type: str, src_port: Optional[int] = None):
        self.timestamp = timestamp
        self.ip = ip
        self.username = username
        self.event_type = event_type
        self.src_port = src_port
    
    def __repr__(self):
        return f"SSHEvent({self.ip}, {self.username}, {self.event_type})"

class LogMonitor:
    FAILED_PASSWORD = re.compile(
        r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)(?:\s+port\s+(\d+))?'
    )
    ACCEPTED_PASSWORD = re.compile(
        r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)(?:\s+port\s+(\d+))?'
    )
    INVALID_USER = re.compile(
        r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)(?:\s+port\s+(\d+))?'
    )
    AUTH_FAILURE = re.compile(
        r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\S+)'
    )
    TIMESTAMP = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w+\s+\d+\s+\d+:\d+:\d+)'
    )
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def __init__(self, log_file: str, window_size: int = 100):
        self.log_file = log_file
        self.window_size = window_size
        self.ip_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.tail_process: Optional[subprocess.Popen] = None
    
    def _parse_timestamp(self, ts_str: str) -> float:
        try:
            if 'T' in ts_str:
                dt = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                return dt.timestamp()
            else:
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
            return time.time()
        
        return time.time()
    
    def parse_line(self, line: str) -> Optional[SSHEvent]:
        original_ts_match = None
        if 'replay:' in line:
            replay_ts_pattern = re.compile(r'replay:\s+(\w+\s+\d+\s+\d+:\d+:\d+)')
            original_ts_match = replay_ts_pattern.search(line)
        
        if original_ts_match:
            timestamp = self._parse_timestamp(original_ts_match.group(1))
        else:
            ts_match = self.TIMESTAMP.match(line)
            if not ts_match:
                return None
            timestamp = self._parse_timestamp(ts_match.group(1))
        
        match = self.FAILED_PASSWORD.search(line)
        if match:
            groups = match.groups()
            username, ip = groups[0], groups[1]
            src_port = int(groups[2]) if len(groups) > 2 and groups[2] else None
            return SSHEvent(timestamp, ip, username, 'failed_password', src_port)
        
        match = self.ACCEPTED_PASSWORD.search(line)
        if match:
            groups = match.groups()
            username, ip = groups[0], groups[1]
            src_port = int(groups[2]) if len(groups) > 2 and groups[2] else None
            return SSHEvent(timestamp, ip, username, 'accepted_password', src_port)
        
        match = self.INVALID_USER.search(line)
        if match:
            groups = match.groups()
            username, ip = groups[0], groups[1]
            src_port = int(groups[2]) if len(groups) > 2 and groups[2] else None
            return SSHEvent(timestamp, ip, username, 'invalid_user', src_port)
        
        match = self.AUTH_FAILURE.search(line)
        if match:
            ip, username = match.groups()
            return SSHEvent(timestamp, ip, username, 'auth_failure', None)
        
        return None
    
    def add_event(self, event: SSHEvent):
        self.ip_windows[event.ip].append(event)
    
    def get_event_sequence(self, ip: str, max_age_seconds: Optional[int] = None) -> List[SSHEvent]:
        events = list(self.ip_windows[ip])
        
        if max_age_seconds is not None:
            current_time = time.time()
            cutoff_time = current_time - max_age_seconds
            events = [e for e in events if e.timestamp >= cutoff_time]
        
        return events
    
    def start_tail(self):
        try:
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
            yield from self._python_tail()
    
    def _python_tail(self):
        try:
            with open(self.log_file, 'r') as f:
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
        if self.tail_process:
            self.tail_process.terminate()
            self.tail_process.wait(timeout=5)
    
    def get_active_ips(self) -> List[str]:
        return list(self.ip_windows.keys())
