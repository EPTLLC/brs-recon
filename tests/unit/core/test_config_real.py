# BRS-RECON Real Configuration Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for real configuration classes."""

import pytest

from brsrecon.core.config import (
    BRSConfig,
    LoggingConfig,
    NetworkConfig,
    OutputConfig,
    SecurityConfig,
    WebConfig,
    get_config,
)


class TestRealNetworkConfig:
    """Test real NetworkConfig functionality."""

    def test_network_config_creation(self):
        """Test NetworkConfig creation."""
        config = NetworkConfig()
        assert hasattr(config, "default_timeout")
        assert hasattr(config, "max_concurrent_scans")
        assert hasattr(config, "default_ports")

    def test_network_config_attributes(self):
        """Test NetworkConfig attributes."""
        config = NetworkConfig()
        assert isinstance(config.default_timeout, int)
        assert isinstance(config.max_concurrent_scans, int)
        assert isinstance(config.default_ports, str)


class TestRealWebConfig:
    """Test real WebConfig functionality."""

    def test_web_config_creation(self):
        """Test WebConfig creation."""
        config = WebConfig()
        assert hasattr(config, "user_agent")
        assert hasattr(config, "request_timeout")

    def test_web_config_attributes(self):
        """Test WebConfig attributes."""
        config = WebConfig()
        assert isinstance(config.user_agent, str)
        assert "BRS-RECON" in config.user_agent


class TestRealSecurityConfig:
    """Test real SecurityConfig functionality."""

    def test_security_config_creation(self):
        """Test SecurityConfig creation."""
        config = SecurityConfig()
        assert hasattr(config, "safe_mode")
        assert hasattr(config, "max_scan_depth")

    def test_security_config_safe_mode(self):
        """Test security config safe mode."""
        config = SecurityConfig()
        assert isinstance(config.safe_mode, bool)
        assert config.safe_mode is True  # Should default to safe


class TestRealOutputConfig:
    """Test real OutputConfig functionality."""

    def test_output_config_creation(self):
        """Test OutputConfig creation."""
        config = OutputConfig()
        assert hasattr(config, "results_dir")
        assert hasattr(config, "default_format")

    def test_output_config_attributes(self):
        """Test OutputConfig attributes."""
        config = OutputConfig()
        assert isinstance(config.results_dir, str)
        assert config.default_format in ["json", "html", "sarif", "xml", "csv"]


class TestRealLoggingConfig:
    """Test real LoggingConfig functionality."""

    def test_logging_config_creation(self):
        """Test LoggingConfig creation."""
        config = LoggingConfig()
        assert hasattr(config, "log_level")
        # Check what attributes actually exist
        assert hasattr(config, "log_level")

    def test_logging_config_attributes(self):
        """Test LoggingConfig attributes."""
        config = LoggingConfig()
        assert isinstance(config.log_level, str)
        assert config.log_level in ["DEBUG", "INFO", "WARNING", "ERROR"]


class TestRealBRSConfig:
    """Test real BRSConfig functionality."""

    def test_brs_config_creation(self):
        """Test BRSConfig creation."""
        config = BRSConfig()
        assert hasattr(config, "network")
        assert hasattr(config, "web")
        assert hasattr(config, "security")
        assert hasattr(config, "output")
        assert hasattr(config, "logging")

    def test_brs_config_components(self):
        """Test BRSConfig component types."""
        config = BRSConfig()
        assert isinstance(config.network, NetworkConfig)
        assert isinstance(config.web, WebConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.logging, LoggingConfig)


class TestRealGetConfig:
    """Test real get_config function."""

    def test_get_config_returns_brs_config(self):
        """Test get_config returns BRSConfig instance."""
        config = get_config()
        assert isinstance(config, BRSConfig)

    def test_get_config_has_all_components(self):
        """Test get_config returns config with all components."""
        config = get_config()
        assert hasattr(config, "network")
        assert hasattr(config, "web")
        assert hasattr(config, "security")
        assert hasattr(config, "output")
        assert hasattr(config, "logging")
