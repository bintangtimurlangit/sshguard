# SSHGuard

LSTM-based intrusion detection system for SSH authentication monitoring.

## Overview

SSHGuard monitors SSH authentication logs in real-time using an LSTM neural network to detect slow-rate brute force attacks that traditional threshold-based systems like fail2ban cannot catch effectively.

## How It Works

1. Monitors `/var/log/auth.log` for SSH authentication attempts
2. Analyzes authentication patterns using a trained LSTM model
3. Detects anomalous behavior indicative of slow-rate attacks
4. Automatically blocks suspicious IP addresses using iptables

## Installation

### Method 1 — Build and install .deb (recommended)

1) Clone repository
```bash
git clone https://github.com/bintangtimurlangit/sshguard.git
cd sshguard
```

2) Install build dependencies
```bash
sudo apt-get update
sudo apt-get install -y debhelper dh-python python3-all python3-setuptools python3-pip iptables
```

3) Build package
```bash
dpkg-buildpackage -us -uc -b
```

4) Install package and enable service
```bash
cd ..
sudo dpkg -i sshguard_1.0.0_all.deb
sudo systemctl daemon-reload
sudo systemctl enable sshguard
sudo systemctl start sshguard
```

### Method 2 — Install from source

1) Clone repository
```bash
git clone https://github.com/bintangtimurlangit/sshguard.git
cd sshguard
```

2) Install system dependencies
```bash
sudo apt-get update
sudo apt-get install -y python3-pip iptables
```

3) Install package and enable service
```bash
sudo pip3 install --break-system-packages -e .
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
sudo sshguard status

# View blocked IPs
sudo sshguard list

# Unblock an IP
sudo sshguard unblock <ip>

# Start/stop service
sudo sshguard start
sudo sshguard stop
sudo sshguard restart
```

## Monitoring

```bash
# Follow SSHGuard logs
sudo tail -f /var/log/sshguard.log

# Stream systemd logs
sudo journalctl -u sshguard -f

# Watch blocked IPs
watch -n 2 'sudo sshguard list'
```

## Requirements

- Python 3.8+
- TensorFlow 2.10+
- numpy 1.21+
- pandas 1.3+
- scikit-learn 1.0+
- Root/sudo privileges for iptables management
- Systemd-based Linux distribution

## License

MIT License
