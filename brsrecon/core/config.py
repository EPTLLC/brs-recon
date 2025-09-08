"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 08 Sep 2025 09:36 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

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
        # Basic validation per tests
        if not isinstance(self.default_timeout, int) or self.default_timeout < 1:
            raise ValueError("default_timeout must be >= 1")
        if not isinstance(self.max_concurrent_scans, int) or not (
            1 <= self.max_concurrent_scans <= 1000
        ):
            raise ValueError("max_concurrent_scans must be between 1 and 1000")


@dataclass
class WebConfig:
    """Web scanning configuration"""

    user_agent: str = "BRS-RECON/0.0.2"
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
    # Fields expected by tests
    max_file_size: int = 100 * 1024 * 1024
    create_directories: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration"""

    # Fields expected by tests
    level: str = "INFO"
    format: str = "structured"
    max_file_size: int = 10 * 1024 * 1024
    backup_count: int = 5
    log_to_file: bool = True
    console_output: bool = True

    # Backward-compatible aliases expected by tests and commands
    @property
    def log_level(self) -> str:
        return self.level

    @log_level.setter
    def log_level(self, value: str) -> None:
        self.level = value

    @property
    def log_file_max_size(self) -> int:
        return self.max_file_size

    @property
    def log_file_backup_count(self) -> int:
        return self.backup_count


@dataclass
class SecurityConfig:
    """Security and safety configuration"""

    safe_mode: bool = True
    max_scan_depth: int = 3
    rate_limit_delay: float = 0.1
    respect_robots_txt: bool = True
    authorized_targets_only: bool = True
    # Fields expected by tests
    max_targets_per_scan: int = 100
    require_authorization: bool = True

    def __post_init__(self):
        if self.rate_limit_delay < 0:
            raise ValueError("rate_limit_delay cannot be negative")


class BRSConfig:
    """Main configuration manager for BRS-RECON"""

    def __init__(
        self,
        config_file: Optional[str] = None,
        network: Optional[NetworkConfig] = None,
        web: Optional[WebConfig] = None,
        output: Optional[OutputConfig] = None,
        logging: Optional[LoggingConfig] = None,
        security: Optional[SecurityConfig] = None,
    ):
        self._explicit_config = config_file is not None
        self.config_file = config_file or self._get_default_config_path()
        self.config_dir = Path(self.config_file).parent

        # Initialize default configurations or provided ones
        self.network = network or NetworkConfig()
        self.web = web or WebConfig()
        self.output = output or OutputConfig()
        self.logging = logging or LoggingConfig()
        self.security = security or SecurityConfig()

        # Track which sections were explicitly provided so we don't override them
        self._provided_sections = {
            "network": network is not None,
            "web": web is not None,
            "output": output is not None,
            "logging": logging is not None,
            "security": security is not None,
        }

        # Load configuration if file exists
        self.load_config()

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        # Use user config directory to keep library defaults stable in tests
        config_dir = Path.home() / ".config" / "brs-recon"

        ensure_directory(config_dir)
        return str(config_dir / "config.yaml")

    def load_config(self) -> bool:
        """Load configuration from file"""
        if not getattr(self, "_explicit_config", False):
            # Use in-memory defaults unless config file explicitly provided
            return True
        config_path = Path(self.config_file)

        if not config_path.exists():
            # Create default config file
            self.save_config()
            return True

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}

            # Update configurations with loaded data (skip explicitly provided sections)
            if "network" in config_data and not self._provided_sections.get("network"):
                self._update_config(self.network, config_data["network"])

            if "web" in config_data and not self._provided_sections.get("web"):
                self._update_config(self.web, config_data["web"])

            if "output" in config_data and not self._provided_sections.get("output"):
                self._update_config(self.output, config_data["output"])

            if "logging" in config_data and not self._provided_sections.get("logging"):
                self._update_config(self.logging, config_data["logging"])

            if "security" in config_data and not self._provided_sections.get(
                "security"
            ):
                self._update_config(self.security, config_data["security"])

            return True

        except Exception as e:
            print(f"Error loading config: {e}")
            return False

    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            config_data = {
                "network": asdict(self.network),
                "web": asdict(self.web),
                "output": asdict(self.output),
                "logging": asdict(self.logging),
                "security": asdict(self.security),
            }

            # Ensure config directory exists
            ensure_directory(Path(self.config_file).parent)

            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)

            return True

        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def _update_config(self, config_obj, data: Dict[str, Any]):
        """Update configuration object with data"""
        for key, value in data.items():
            # Accept legacy keys for LoggingConfig aliases first to avoid property setter issues
            if isinstance(config_obj, LoggingConfig) and key in {
                "log_level",
                "log_file_max_size",
                "log_file_backup_count",
            }:
                if key == "log_level":
                    config_obj.log_level = value
                elif key == "log_file_max_size":
                    # Accept string like "10MB"
                    if isinstance(value, str) and value.lower().endswith("mb"):
                        try:
                            mb = int(value[:-2])
                            config_obj.max_file_size = mb * 1024 * 1024
                        except Exception:
                            pass
                    elif isinstance(value, int):
                        config_obj.max_file_size = value
                elif key == "log_file_backup_count":
                    try:
                        config_obj.backup_count = int(value)
                    except Exception:
                        pass
                continue

            if hasattr(config_obj, key):
                setattr(config_obj, key, value)

    def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration as dictionary"""
        return {
            "network": asdict(self.network),
            "web": asdict(self.web),
            "output": asdict(self.output),
            "logging": asdict(self.logging),
            "security": asdict(self.security),
        }

    def update_config(self, section: str, updates: Dict[str, Any]) -> bool:
        """Update specific configuration section"""
        section_map = {
            "network": self.network,
            "web": self.web,
            "output": self.output,
            "logging": self.logging,
            "security": self.security,
        }

        if section not in section_map:
            return False

        self._update_config(section_map[section], updates)
        return self.save_config()

    # Methods required by tests
    def to_dict(self) -> Dict[str, Any]:
        return self.get_all_config()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BRSConfig":
        inst = cls()
        for section, updates in data.items():
            if hasattr(inst, section):
                inst._update_config(getattr(inst, section), updates)
        return inst

    def merge(self, override_data: Dict[str, Any]) -> "BRSConfig":
        # Create fresh defaults (without env overrides)
        merged = BRSConfig(
            network=NetworkConfig(),
            web=WebConfig(),
            output=OutputConfig(),
            logging=LoggingConfig(),
            security=SecurityConfig(),
        )
        # start from current dict then apply overrides
        current = self.get_all_config()
        for section, updates in current.items():
            inst_section = getattr(merged, section)
            merged._update_config(inst_section, updates)
        for section, updates in override_data.items():
            if hasattr(merged, section):
                merged._update_config(getattr(merged, section), updates)
        return merged

    # File loading helpers expected by tests
    @staticmethod
    def load_config_from_file(path: str) -> Dict[str, Any]:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(path))
        if p.suffix.lower() in (".yaml", ".yml"):
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        elif p.suffix.lower() == ".json":
            import json

            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            raise ValueError("Unsupported config file type")

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

        return {"valid": len(issues) == 0, "issues": issues, "warnings": warnings}

    def get_env_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables"""
        overrides = {}

        # Network overrides
        if os.getenv("BRS_RECON_NETWORK_TIMEOUT"):
            overrides.setdefault("network", {})["default_timeout"] = int(
                os.getenv("BRS_RECON_NETWORK_TIMEOUT")
            )

        if os.getenv("BRS_RECON_MAX_CONCURRENT"):
            overrides.setdefault("network", {})["max_concurrent_scans"] = int(
                os.getenv("BRS_RECON_MAX_CONCURRENT")
            )

        # Web overrides
        if os.getenv("BRS_RECON_USER_AGENT"):
            overrides.setdefault("web", {})["user_agent"] = os.getenv(
                "BRS_RECON_USER_AGENT"
            )

        # Output overrides
        if os.getenv("BRS_RECON_RESULTS_DIR"):
            overrides.setdefault("output", {})["results_dir"] = os.getenv(
                "BRS_RECON_RESULTS_DIR"
            )

        if os.getenv("BRS_RECON_OUTPUT_FORMAT"):
            overrides.setdefault("output", {})["default_format"] = os.getenv(
                "BRS_RECON_OUTPUT_FORMAT"
            )

        # Security overrides
        if os.getenv("BRS_RECON_SAFE_MODE"):
            overrides.setdefault("security", {})["safe_mode"] = (
                os.getenv("BRS_RECON_SAFE_MODE").lower() == "true"
            )

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
    # If caller provides a config file, always (re)create a fresh instance
    if config_file is not None:
        _config_instance = BRSConfig(config_file)
        _config_instance.apply_env_overrides()
        return _config_instance

    if _config_instance is None:
        _config_instance = BRSConfig()
    # Always apply env overrides to reflect current environment
    _config_instance.apply_env_overrides()
    return _config_instance


def reload_config(config_file: Optional[str] = None) -> BRSConfig:
    """Reload configuration from file"""
    global _config_instance
    _config_instance = BRSConfig(config_file)
    _config_instance.apply_env_overrides()
    return _config_instance


# Expose helper function for tests
def load_config_from_file(path: str) -> Dict[str, Any]:
    return BRSConfig.load_config_from_file(path)
