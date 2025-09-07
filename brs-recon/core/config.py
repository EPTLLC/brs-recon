"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from .utils import ensure_directory


@dataclass
class NetworkConfig:
    """Network scanning configuration"""
    default_timeout: int = 30
    max_concurrent_scans: int = 10
    default_ports: str = "22,80,443,8080,8443"
    ping_timeout: int = 3
    dns_servers: list = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = ["8.8.8.8", "1.1.1.1"]


@dataclass
class WebConfig:
    """Web scanning configuration"""
    user_agent: str = "BRS-RECON/0.0.1"
    request_timeout: int = 15
    max_redirects: int = 5
    verify_ssl: bool = True
    custom_headers: dict = None
    
    def __post_init__(self):
        if self.custom_headers is None:
            self.custom_headers = {}


@dataclass
class OutputConfig:
    """Output and results configuration"""
    results_dir: str = "results"
    default_format: str = "json"
    save_raw_output: bool = True
    timestamp_format: str = "%Y%m%d-%H%M%S"
    auto_cleanup_days: int = 30


@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_level: str = "INFO"
    log_to_file: bool = True
    log_file_max_size: str = "10MB"
    log_file_backup_count: int = 5
    console_output: bool = True


@dataclass
class SecurityConfig:
    """Security and safety configuration"""
    safe_mode: bool = True
    max_scan_depth: int = 3
    rate_limit_delay: float = 0.1
    respect_robots_txt: bool = True
    authorized_targets_only: bool = True


class BRSConfig:
    """Main configuration manager for BRS-RECON"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config_dir = Path(self.config_file).parent
        
        # Initialize default configurations
        self.network = NetworkConfig()
        self.web = WebConfig()
        self.output = OutputConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        
        # Load configuration if file exists
        self.load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        # Try user config directory first
        config_dir = Path.home() / ".config" / "brs-recon"
        
        # Fallback to project config directory
        if not config_dir.exists():
            config_dir = Path("config")
        
        ensure_directory(config_dir)
        return str(config_dir / "config.yaml")
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        config_path = Path(self.config_file)
        
        if not config_path.exists():
            # Create default config file
            self.save_config()
            return True
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}
            
            # Update configurations with loaded data
            if 'network' in config_data:
                self._update_config(self.network, config_data['network'])
            
            if 'web' in config_data:
                self._update_config(self.web, config_data['web'])
            
            if 'output' in config_data:
                self._update_config(self.output, config_data['output'])
            
            if 'logging' in config_data:
                self._update_config(self.logging, config_data['logging'])
            
            if 'security' in config_data:
                self._update_config(self.security, config_data['security'])
            
            return True
            
        except Exception as e:
            print(f"Error loading config: {e}")
            return False
    
    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            config_data = {
                'network': asdict(self.network),
                'web': asdict(self.web),
                'output': asdict(self.output),
                'logging': asdict(self.logging),
                'security': asdict(self.security)
            }
            
            # Ensure config directory exists
            ensure_directory(Path(self.config_file).parent)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def _update_config(self, config_obj, data: Dict[str, Any]):
        """Update configuration object with data"""
        for key, value in data.items():
            if hasattr(config_obj, key):
                setattr(config_obj, key, value)
    
    def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration as dictionary"""
        return {
            'network': asdict(self.network),
            'web': asdict(self.web),
            'output': asdict(self.output),
            'logging': asdict(self.logging),
            'security': asdict(self.security)
        }
    
    def update_config(self, section: str, updates: Dict[str, Any]) -> bool:
        """Update specific configuration section"""
        section_map = {
            'network': self.network,
            'web': self.web,
            'output': self.output,
            'logging': self.logging,
            'security': self.security
        }
        
        if section not in section_map:
            return False
        
        self._update_config(section_map[section], updates)
        return self.save_config()
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        self.network = NetworkConfig()
        self.web = WebConfig()
        self.output = OutputConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        
        return self.save_config()
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate current configuration"""
        issues = []
        warnings = []
        
        # Validate network config
        if self.network.default_timeout < 1:
            issues.append("Network timeout must be at least 1 second")
        
        if self.network.max_concurrent_scans < 1:
            issues.append("Max concurrent scans must be at least 1")
        
        # Validate web config
        if self.web.request_timeout < 1:
            issues.append("Web request timeout must be at least 1 second")
        
        # Validate output config
        if not self.output.results_dir:
            issues.append("Results directory cannot be empty")
        
        # Validate security config
        if not self.security.safe_mode:
            warnings.append("Safe mode is disabled - use with caution")
        
        if self.security.rate_limit_delay < 0:
            issues.append("Rate limit delay cannot be negative")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings
        }
    
    def get_env_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables"""
        overrides = {}
        
        # Network overrides
        if os.getenv('BRS_RECON_NETWORK_TIMEOUT'):
            overrides.setdefault('network', {})['default_timeout'] = int(os.getenv('BRS_RECON_NETWORK_TIMEOUT'))
        
        if os.getenv('BRS_RECON_MAX_CONCURRENT'):
            overrides.setdefault('network', {})['max_concurrent_scans'] = int(os.getenv('BRS_RECON_MAX_CONCURRENT'))
        
        # Web overrides
        if os.getenv('BRS_RECON_USER_AGENT'):
            overrides.setdefault('web', {})['user_agent'] = os.getenv('BRS_RECON_USER_AGENT')
        
        # Output overrides
        if os.getenv('BRS_RECON_RESULTS_DIR'):
            overrides.setdefault('output', {})['results_dir'] = os.getenv('BRS_RECON_RESULTS_DIR')
        
        if os.getenv('BRS_RECON_OUTPUT_FORMAT'):
            overrides.setdefault('output', {})['default_format'] = os.getenv('BRS_RECON_OUTPUT_FORMAT')
        
        # Security overrides
        if os.getenv('BRS_RECON_SAFE_MODE'):
            overrides.setdefault('security', {})['safe_mode'] = os.getenv('BRS_RECON_SAFE_MODE').lower() == 'true'
        
        return overrides
    
    def apply_env_overrides(self):
        """Apply environment variable overrides"""
        overrides = self.get_env_overrides()
        
        for section, updates in overrides.items():
            self.update_config(section, updates)


# Global configuration instance
_config_instance: Optional[BRSConfig] = None


def get_config(config_file: Optional[str] = None) -> BRSConfig:
    """Get or create global configuration instance"""
    global _config_instance
    
    if _config_instance is None:
        _config_instance = BRSConfig(config_file)
        _config_instance.apply_env_overrides()
    
    return _config_instance


def reload_config(config_file: Optional[str] = None) -> BRSConfig:
    """Reload configuration from file"""
    global _config_instance
    _config_instance = BRSConfig(config_file)
    _config_instance.apply_env_overrides()
    return _config_instance
