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
sudo dpkg -i ../sshguard_1.0.0_all.deb
sudo apt-get install -f  # Install dependencies if needed
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

