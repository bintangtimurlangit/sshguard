import subprocess
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class FirewallManager:
    def __init__(self, chain_name: str = 'SSHGUARD', block_duration: int = 3600):
        self.chain_name = chain_name
        self.block_duration = block_duration
        self.blocked_ips: Dict[str, float] = {}
        self.logger = logging.getLogger(__name__)
        
        self._setup_chain()
    
    def _run_iptables(self, args: List[str]) -> bool:
        try:
            result = subprocess.run(
                ['iptables'] + args,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"iptables command failed: {e}")
            return False
    
    def _setup_chain(self):
        result = subprocess.run(
            ['iptables', '-L', self.chain_name, '-n'],
            capture_output=True
        )
        
        if result.returncode != 0:
            self._run_iptables(['-N', self.chain_name])
            self.logger.info(f"Created iptables chain: {self.chain_name}")
        
        check_result = subprocess.run(
            ['iptables', '-C', 'INPUT', '-j', self.chain_name],
            capture_output=True
        )
        
        if check_result.returncode != 0:
            self._run_iptables(['-I', 'INPUT', '-j', self.chain_name])
            self.logger.info(f"Added {self.chain_name} to INPUT chain")
    
    def block_ip(self, ip: str, reason: str = "SSH anomaly detected") -> bool:
        if ip in self.blocked_ips:
            self.logger.debug(f"IP {ip} already blocked")
            return True
        
        success = self._run_iptables([
            '-A', self.chain_name,
            '-s', ip,
            '-j', 'DROP',
            '-m', 'comment',
            '--comment', f'SSHGuard: {reason}'
        ])
        
        if success:
            self.blocked_ips[ip] = time.time()
            self.logger.warning(f"Blocked IP {ip}: {reason}")
            return True
        else:
            self.logger.error(f"Failed to block IP {ip}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            self.logger.debug(f"IP {ip} not in blocked list")
            return False
        
        success = self._run_iptables([
            '-D', self.chain_name,
            '-s', ip,
            '-j', 'DROP'
        ])
        
        if success:
            del self.blocked_ips[ip]
            self.logger.info(f"Unblocked IP {ip}")
            return True
        else:
            self.logger.error(f"Failed to unblock IP {ip}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def cleanup_expired(self) -> int:
        current_time = time.time()
        expired_ips = [
            ip for ip, block_time in self.blocked_ips.items()
            if current_time - block_time >= self.block_duration
        ]
        
        count = 0
        for ip in expired_ips:
            if self.unblock_ip(ip):
                count += 1
        
        if count > 0:
            self.logger.info(f"Unblocked {count} expired IPs")
        
        return count
    
    def list_blocked(self) -> List[Dict]:
        current_time = time.time()
        result = []
        
        for ip, block_time in self.blocked_ips.items():
            elapsed = current_time - block_time
            remaining = max(0, self.block_duration - elapsed)
            
            result.append({
                'ip': ip,
                'blocked_at': datetime.fromtimestamp(block_time).isoformat(),
                'elapsed_seconds': int(elapsed),
                'remaining_seconds': int(remaining)
            })
        
        return result
    
    def cleanup_chain(self):
        self._run_iptables(['-F', self.chain_name])
        self._run_iptables(['-D', 'INPUT', '-j', self.chain_name])
        self._run_iptables(['-X', self.chain_name])
        
        self.blocked_ips.clear()
        self.logger.info(f"Cleaned up iptables chain: {self.chain_name}")
    
    def get_stats(self) -> Dict:
        return {
            'total_blocked': len(self.blocked_ips),
            'chain_name': self.chain_name,
            'block_duration': self.block_duration,
            'blocked_ips': list(self.blocked_ips.keys())
        }
