# Build Instructions

## Building Debian Package

### Prerequisites

```bash
sudo apt-get install debhelper dh-python python3-all python3-setuptools
```

### Build Steps

1. Navigate to project directory:
```bash
cd sshguard
```

2. Build the package:
```bash
dpkg-buildpackage -us -uc -b
```

3. Install the generated .deb package:
```bash
# Preferred (resolves dependencies automatically)
sudo apt-get update
sudo apt-get install -y ../sshguard_1.0.0_all.deb

# If you already used dpkg -i and hit dependency errors
# (e.g., python3-numpy or python3-pip missing), run either:
sudo apt-get install -y python3-numpy python3-pip
# or let apt fix them for you:
sudo apt-get -f install -y
```

## Installing from Source

### Using setup.py

```bash
sudo python3 setup.py install
```

### Using pip

```bash
sudo pip3 install .
```

### Post-Installation

1. Copy the systemd service file:
```bash
sudo cp systemd/sshguard.service /lib/systemd/system/
sudo systemctl daemon-reload
```

2. Enable and start the service:
```bash
sudo systemctl enable sshguard
sudo systemctl start sshguard
```

## Troubleshooting

- Missing python dependencies after dpkg install:
  ```bash
  sudo apt-get install -y python3-numpy python3-pip
  sudo apt-get -f install -y
  ```
- Verify service status and logs:
  ```bash
  systemctl status sshguard --no-pager
  journalctl -u sshguard -e
  ```
- Allow iptables operations (run as root/sudo). On systems using `nftables`, ensure the compatibility layer is present.

## Configuration

Edit `/etc/sshguard/sshguard.conf` to customize settings:

- Detection threshold
- Log file path
- Block duration
- Model path

## Uninstallation

### If installed via .deb package:
```bash
sudo apt-get remove sshguard
```

### If installed via pip/setup.py:
```bash
sudo pip3 uninstall sshguard
```

