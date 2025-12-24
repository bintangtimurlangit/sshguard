import configparser
import os
from typing import Any, Optional


class Config:
    DEFAULT_CONFIG = {
        'general': {
            'log_file': '/var/log/auth.log',
            'model_path': '/usr/lib/sshguard/models/lstm_model.keras',
            'detection_threshold': '0.7',
            'window_size': '100',
            'window_seconds': '3600',
        },
        'firewall': {
            'enabled': 'true',
            'chain_name': 'SSHGUARD',
            'block_duration': '3600',
        },
        'logging': {
            'log_level': 'INFO',
            'log_path': '/var/log/sshguard.log',
        }
    }
    
    def __init__(self, config_path: str = '/etc/sshguard/sshguard.conf'):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._load()
    
    def _load(self):
        for section, values in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for key, value in values.items():
                self.config.set(section, key, value)
        
        if os.path.exists(self.config_path):
            self.config.read(self.config_path)
    
    def get(self, section: str, key: str, fallback: Optional[Any] = None) -> str:
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            if fallback is not None:
                return str(fallback)
            return self.DEFAULT_CONFIG.get(section, {}).get(key, '')
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback
    
    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        try:
            return self.config.getfloat(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback
    
    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback
