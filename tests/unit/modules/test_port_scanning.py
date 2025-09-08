# BRS-RECON Port Scanning Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Unit tests for port scanning module."""

import socket
import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest

from brsrecon.core.base import ScanConfig
from brsrecon.modules.port_scanning import PortScanning


class TestPortScanning:
    """Test PortScanning module functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = ScanConfig(timeout=10)
        self.port_scanner = PortScanning(config=self.config)

    def test_port_scanning_initialization(self):
        """Test PortScanning initialization."""
        assert self.port_scanner.name == "Port Scanning"
        assert self.port_scanner.config == self.config
        assert hasattr(self.port_scanner, "logger")
        assert hasattr(self.port_scanner, "results_manager")

    @patch("shutil.which")
    def test_validate_requirements_tools_available(self, mock_which):
        """Test requirements validation when tools are available."""
        mock_which.side_effect = lambda tool: (
            f"/usr/bin/{tool}" if tool in ["nmap", "masscan"] else None
        )

        result = self.port_scanner.validate_requirements()
        assert result is True

    @patch("shutil.which")
    def test_validate_requirements_nmap_only(self, mock_which):
        """Test requirements validation with only nmap available."""
        mock_which.side_effect = lambda tool: (
            "/usr/bin/nmap" if tool == "nmap" else None
        )

        result = self.port_scanner.validate_requirements()
        assert result is True

    def test_validate_requirements_interface(self):
        """Test requirements validation interface."""
        # Test that the method exists and returns a boolean
        result = self.port_scanner.validate_requirements()
        assert isinstance(result, bool)

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_basic_scan_functionality(self, mock_which, mock_run):
        """Test basic port scanning functionality."""
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = Mock(
            returncode=0, stdout="80/tcp open http\n443/tcp open https\n", stderr=""
        )

        result = self.port_scanner.scan("192.168.1.1", ports="80,443", scan_type="tcp")

        assert result is not None
        assert "target" in result

    def test_scan_invalid_scan_type(self):
        """Test scanning with invalid scan type."""
        with pytest.raises(ValueError):
            self.port_scanner.scan("192.168.1.1", ports="80", scan_type="invalid")

    def test_scan_invalid_target(self):
        """Test scanning with invalid target."""
        # Test that the method handles invalid targets gracefully
        result = self.port_scanner.scan("invalid..target", ports="80", scan_type="tcp")
        assert result is not None
