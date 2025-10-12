# SSHGuard

LSTM-based intrusion detection system for SSH authentication monitoring.

## Overview

SSHGuard monitors SSH authentication logs in real-time using a Bi-LSTM neural network to detect slow-rate brute force attacks that traditional threshold-based systems like fail2ban cannot catch effectively.

## How It Works

1. Monitors `/var/log/auth.log` for SSH authentication attempts
2. Analyzes authentication patterns using a trained LSTM model
3. Detects anomalous behavior indicative of slow-rate attacks
4. Automatically blocks suspicious IP addresses using iptables

## Installation

### From .deb Package

```bash
sudo dpkg -i sshguard_*.deb
sudo systemctl enable sshguard
sudo systemctl start sshguard
```

### From Source

```bash
python3 setup.py install
sudo cp systemd/sshguard.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sshguard
sudo systemctl start sshguard
```

## Configuration

Configuration file: `/etc/sshguard/sshguard.conf`

## Management

```bash
# Check status
sudo sshguard-ctl status

# View blocked IPs
sudo sshguard-ctl list

# Unblock an IP
sudo sshguard-ctl unblock <ip>
```

## Requirements

- Python 3.8+
- TensorFlow 2.x
- Root/sudo privileges for iptables management
- Systemd-based Linux distribution

## License

MIT License

