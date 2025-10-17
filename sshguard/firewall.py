"""iptables firewall integration for IP blocking."""

import subprocess
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class FirewallManager:
    def __init__(self, chain_name: str = 'SSHGUARD', block_duration: int = 3600):
        """Initialize firewall manager.
        
        Args:
            chain_name: Name of iptables chain to create
            block_duration: How long to block IPs (seconds)
        """
        self.chain_name = chain_name
        self.block_duration = block_duration
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_timestamp
        self.logger = logging.getLogger(__name__)
        
        self._setup_chain()
    
    def _run_iptables(self, args: List[str]) -> bool:
        """Run iptables command.
        
        Args:
            args: Command arguments
            
        Returns:
            True if successful, False otherwise
        """
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
        """Create custom iptables chain."""
        # Check if chain exists
        result = subprocess.run(
            ['iptables', '-L', self.chain_name, '-n'],
            capture_output=True
        )
        
        if result.returncode != 0:
            # Create new chain
            self._run_iptables(['-N', self.chain_name])
            self.logger.info(f"Created iptables chain: {self.chain_name}")
        
        # Ensure chain is referenced in INPUT chain
        check_result = subprocess.run(
            ['iptables', '-C', 'INPUT', '-j', self.chain_name],
            capture_output=True
        )
        
        if check_result.returncode != 0:
            # Add jump rule to INPUT chain
            self._run_iptables(['-I', 'INPUT', '-j', self.chain_name])
            self.logger.info(f"Added {self.chain_name} to INPUT chain")
    
    def block_ip(self, ip: str, reason: str = "SSH anomaly detected") -> bool:
        """Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            
        Returns:
            True if successful, False otherwise
        """
        if ip in self.blocked_ips:
            self.logger.debug(f"IP {ip} already blocked")
            return True
        
        # Add iptables rule
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
        """Unblock an IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        if ip not in self.blocked_ips:
            self.logger.debug(f"IP {ip} not in blocked list")
            return False
        
        # Remove iptables rule
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
        """Check if an IP is blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        return ip in self.blocked_ips
    
    def cleanup_expired(self) -> int:
        """Remove expired IP blocks.
        
        Returns:
            Number of IPs unblocked
        """
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
        """Get list of blocked IPs with details.
        
        Returns:
            List of dictionaries with IP and block info
        """
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
        """Remove all rules and cleanup chain."""
        # Flush all rules in our chain
        self._run_iptables(['-F', self.chain_name])
        
        # Remove reference from INPUT chain
        self._run_iptables(['-D', 'INPUT', '-j', self.chain_name])
        
        # Delete the chain
        self._run_iptables(['-X', self.chain_name])
        
        self.blocked_ips.clear()
        self.logger.info(f"Cleaned up iptables chain: {self.chain_name}")
    
    def get_stats(self) -> Dict:
        """Get firewall statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'total_blocked': len(self.blocked_ips),
            'chain_name': self.chain_name,
            'block_duration': self.block_duration,
            'blocked_ips': list(self.blocked_ips.keys())
        }

