# BRS-RECON Configuration Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for configuration management."""

import os
import tempfile
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml

from brsrecon.core.config import (
    BRSConfig,
    LoggingConfig,
    NetworkConfig,
    OutputConfig,
    SecurityConfig,
    get_config,
)


class TestNetworkConfig:
    """Test NetworkConfig functionality."""

    def test_network_config_defaults(self):
        """Test default network configuration values."""
        config = NetworkConfig()

        assert config.default_timeout == 30
        assert config.max_concurrent_scans == 10
        assert config.default_ports == "22,80,443,8080,8443"
        assert config.ping_timeout == 3
        assert config.dns_servers == ["8.8.8.8", "1.1.1.1"]

    def test_network_config_custom_values(self):
        """Test NetworkConfig with custom values."""
        config = NetworkConfig(
            default_timeout=60,
            max_concurrent_scans=20,
            default_ports="80,443",
            ping_timeout=5,
            dns_servers=["1.1.1.1", "9.9.9.9"],
        )

        assert config.default_timeout == 60
        assert config.max_concurrent_scans == 20
        assert config.default_ports == "80,443"
        assert config.ping_timeout == 5
        assert config.dns_servers == ["1.1.1.1", "9.9.9.9"]

    def test_network_config_post_init(self):
        """Test NetworkConfig post_init method."""
        config = NetworkConfig(dns_servers=None)
        assert config.dns_servers == ["8.8.8.8", "1.1.1.1"]


class TestSecurityConfig:
    """Test SecurityConfig functionality."""

    def test_security_config_defaults(self):
        """Test default security configuration."""
        config = SecurityConfig()

        assert config.safe_mode is True
        assert config.max_scan_depth == 3
        assert config.rate_limit_delay == 0.1
        assert config.max_targets_per_scan == 100
        assert config.require_authorization is True

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        config = SecurityConfig(
            safe_mode=False,
            max_scan_depth=5,
            rate_limit_delay=0.2,
            max_targets_per_scan=500,
            require_authorization=False,
        )

        assert config.safe_mode is False
        assert config.max_scan_depth == 5
        assert config.rate_limit_delay == 0.2
        assert config.max_targets_per_scan == 500
        assert config.require_authorization is False


class TestOutputConfig:
    """Test OutputConfig functionality."""

    def test_output_config_defaults(self):
        """Test default output configuration."""
        config = OutputConfig()

        assert config.results_dir == "results"
        assert config.default_format == "json"
        assert config.timestamp_format == "%Y%m%d-%H%M%S"
        assert config.max_file_size == 100 * 1024 * 1024
        assert config.create_directories is True

    def test_output_config_custom_values(self):
        """Test OutputConfig with custom values."""
        config = OutputConfig(
            results_dir="/custom/results",
            default_format="sarif",
            timestamp_format="%Y-%m-%d_%H:%M:%S",
            max_file_size=50 * 1024 * 1024,
            create_directories=False,
        )

        assert config.results_dir == "/custom/results"
        assert config.default_format == "sarif"
        assert config.timestamp_format == "%Y-%m-%d_%H:%M:%S"
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.create_directories is False


class TestLoggingConfig:
    """Test LoggingConfig functionality."""

    def test_logging_config_defaults(self):
        """Test default logging configuration."""
        config = LoggingConfig()

        assert config.level == "INFO"
        assert config.format == "structured"
        assert config.max_file_size == 10 * 1024 * 1024
        assert config.backup_count == 5
        assert config.log_to_file is True

    def test_logging_config_custom_values(self):
        """Test LoggingConfig with custom values."""
        config = LoggingConfig(
            level="DEBUG",
            format="simple",
            max_file_size=5 * 1024 * 1024,
            backup_count=3,
            log_to_file=False,
        )

        assert config.level == "DEBUG"
        assert config.format == "simple"
        assert config.max_file_size == 5 * 1024 * 1024
        assert config.backup_count == 3
        assert config.log_to_file is False


class TestBRSConfig:
    """Test main BRSConfig functionality."""

    def test_brs_config_initialization(self):
        """Test BRSConfig initialization."""
        config = BRSConfig()

        assert isinstance(config.network, NetworkConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.logging, LoggingConfig)

    def test_brs_config_custom_components(self):
        """Test BRSConfig with custom component configurations."""
        network = NetworkConfig(default_timeout=45)
        security = SecurityConfig(safe_mode=False)

        config = BRSConfig(network=network, security=security)

        assert config.network.default_timeout == 45
        assert config.security.safe_mode is False
        assert isinstance(config.output, OutputConfig)  # Should use default
        assert isinstance(config.logging, LoggingConfig)  # Should use default

    def test_brs_config_to_dict(self):
        """Test BRSConfig serialization to dictionary."""
        config = BRSConfig()
        config_dict = config.to_dict()

        assert isinstance(config_dict, dict)
        assert "network" in config_dict
        assert "security" in config_dict
        assert "output" in config_dict
        assert "logging" in config_dict

        # Check nested structure
        assert isinstance(config_dict["network"], dict)
        assert "default_timeout" in config_dict["network"]
        assert config_dict["network"]["default_timeout"] == 30

    def test_brs_config_from_dict(self):
        """Test BRSConfig creation from dictionary."""
        config_dict = {
            "network": {"default_timeout": 90, "max_concurrent_scans": 25},
            "security": {"safe_mode": False, "rate_limit_delay": 0.3},
        }

        config = BRSConfig.from_dict(config_dict)

        assert config.network.default_timeout == 90
        assert config.network.max_concurrent_scans == 25
        assert config.security.safe_mode is False
        assert config.security.rate_limit_delay == 0.3

    def test_brs_config_merge(self):
        """Test configuration merging."""
        base_config = BRSConfig()

        override_data = {
            "network": {"default_timeout": 45},
            "security": {"safe_mode": False},
        }

        merged_config = base_config.merge(override_data)

        assert merged_config.network.default_timeout == 45
        assert merged_config.security.safe_mode is False
        # Non-overridden values should remain
        assert merged_config.network.max_concurrent_scans == 10


class TestConfigFileLoading:
    """Test configuration file loading functionality."""

    def test_load_config_yaml(self):
        """Test loading YAML configuration file."""
        config_data = {
            "network": {"default_timeout": 45, "dns_servers": ["8.8.8.8", "8.8.4.4"]},
            "security": {"safe_mode": False},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            loaded_config = load_config_from_file(config_path)

            assert loaded_config["network"]["default_timeout"] == 45
            assert loaded_config["network"]["dns_servers"] == ["8.8.8.8", "8.8.4.4"]
            assert loaded_config["security"]["safe_mode"] is False
        finally:
            os.unlink(config_path)

    def test_load_config_json(self):
        """Test loading JSON configuration file."""
        import json

        config_data = {
            "output": {"default_format": "sarif", "results_dir": "/custom/path"}
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            loaded_config = load_config_from_file(config_path)

            assert loaded_config["output"]["default_format"] == "sarif"
            assert loaded_config["output"]["results_dir"] == "/custom/path"
        finally:
            os.unlink(config_path)

    def test_load_config_nonexistent_file(self):
        """Test loading non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config_from_file("/nonexistent/config.yaml")

    def test_load_config_invalid_yaml(self):
        """Test loading invalid YAML file."""
        invalid_yaml = "invalid: yaml: content: ["

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(invalid_yaml)
            config_path = f.name

        try:
            with pytest.raises(yaml.YAMLError):
                load_config_from_file(config_path)
        finally:
            os.unlink(config_path)


class TestGetConfig:
    """Test get_config function."""

    @patch.dict(os.environ, {}, clear=True)
    def test_get_config_default(self):
        """Test get_config with default settings."""
        config = get_config()

        assert isinstance(config, BRSConfig)
        assert config.network.default_timeout == 30
        assert config.security.safe_mode is True

    @patch.dict(
        os.environ,
        {
            "BRS_RECON_NETWORK_TIMEOUT": "60",
            "BRS_RECON_MAX_CONCURRENT": "20",
            "BRS_RECON_SAFE_MODE": "false",
        },
    )
    def test_get_config_environment_variables(self):
        """Test get_config with environment variables."""
        config = get_config()

        assert config.network.default_timeout == 60
        assert config.network.max_concurrent_scans == 20
        assert config.security.safe_mode is False

    def test_get_config_with_file(self):
        """Test get_config with configuration file."""
        config_data = {
            "network": {"default_timeout": 90},
            "security": {"rate_limit_delay": 0.5},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            config = get_config(config_file=config_path)

            assert config.network.default_timeout == 90
            assert config.security.rate_limit_delay == 0.5
        finally:
            os.unlink(config_path)

    @patch.dict(os.environ, {"BRS_RECON_NETWORK_TIMEOUT": "120"})
    def test_get_config_precedence(self):
        """Test configuration precedence: env vars override file."""
        config_data = {"network": {"default_timeout": 90}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            config = get_config(config_file=config_path)

            # Environment variable should override file setting
            assert config.network.default_timeout == 120
        finally:
            os.unlink(config_path)


class TestConfigurationValidation:
    """Test configuration validation and error handling."""

    def test_invalid_timeout_values(self):
        """Test validation of timeout values."""
        with pytest.raises((ValueError, TypeError)):
            NetworkConfig(default_timeout=-1)

        with pytest.raises((ValueError, TypeError)):
            NetworkConfig(default_timeout=0)

    def test_invalid_concurrent_scans(self):
        """Test validation of concurrent scan limits."""
        with pytest.raises((ValueError, TypeError)):
            NetworkConfig(max_concurrent_scans=0)

        with pytest.raises((ValueError, TypeError)):
            NetworkConfig(max_concurrent_scans=1001)

    def test_invalid_rate_limit_delay(self):
        """Test validation of rate limiting configuration."""
        with pytest.raises((ValueError, TypeError)):
            SecurityConfig(rate_limit_delay=-0.1)

    def test_invalid_logging_level(self):
        """Test validation of logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            config = LoggingConfig(level=level)
            assert config.level == level
