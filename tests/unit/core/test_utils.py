# BRS-RECON Utils Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for utility functions."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from brsrecon.core.utils import (
    ensure_directory,
    format_timestamp,
    parse_nmap_ports,
    run_command,
    sanitize_filename,
    validate_domain,
    validate_ip,
    validate_target,
)


class TestTimestampFormatting:
    """Test timestamp formatting utilities."""

    def test_format_timestamp_default(self):
        """Test default timestamp formatting."""
        dt = datetime(2025, 9, 7, 18, 45, 30)
        result = format_timestamp(dt)

        assert result == "20250907-184530"

    def test_format_timestamp_current_time(self):
        """Test formatting current time."""
        result = format_timestamp()

        assert isinstance(result, str)
        assert len(result) == 15  # YYYYMMDD-HHMMSS

        # Should be parseable back to datetime
        parsed = datetime.strptime(result, "%Y%m%d-%H%M%S")
        assert isinstance(parsed, datetime)


class TestIPValidation:
    """Test IP address validation."""

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("127.0.0.1", True),
            ("8.8.8.8", True),
            ("255.255.255.255", True),
            ("2001:db8::1", True),
            ("::1", True),
            ("fe80::1", True),
            ("256.1.1.1", False),
            ("192.168.1", False),
            ("not.an.ip", False),
            ("", False),
        ],
    )
    def test_validate_ip(self, ip, expected):
        """Test IP address validation."""
        result = validate_ip(ip)
        assert result == expected


class TestDomainValidation:
    """Test domain name validation."""

    @pytest.mark.parametrize(
        "domain,expected",
        [
            ("example.com", True),
            ("subdomain.example.com", True),
            ("test-domain.org", True),
            ("localhost", True),
            ("", False),
            (".", False),
            (".example.com", False),
            ("example..com", False),
            ("-example.com", False),
            ("example-.com", False),
            ("ex ample.com", False),
        ],
    )
    def test_validate_domain(self, domain, expected):
        """Test domain name validation."""
        result = validate_domain(domain)
        assert result == expected


class TestTargetValidation:
    """Test comprehensive target validation."""

    @pytest.mark.parametrize(
        "target,expected_valid,expected_type",
        [
            ("192.168.1.1", True, "ip"),
            ("example.com", True, "domain"),
            ("192.168.1.0/24", True, "network"),
            ("http://example.com", True, "url"),
            ("https://example.com", True, "url"),
            ("", False, None),
            ("invalid..domain", False, None),
            ("256.256.256.256", False, None),
        ],
    )
    def test_validate_target(self, target, expected_valid, expected_type):
        """Test target validation."""
        result = validate_target(target)

        assert result["valid"] == expected_valid
        if expected_valid:
            assert result["type"] == expected_type
        else:
            assert "error" in result


class TestFilenameUtilities:
    """Test filename sanitization utilities."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("normal_file.txt", "normal_file.txt"),
            ("file with spaces.txt", "file_with_spaces.txt"),
            ("file/with/slashes.txt", "file_with_slashes.txt"),
            ("file<>:|*?.txt", "file_______.txt"),
            ("", "unnamed"),
            ("   ", "unnamed"),
        ],
    )
    def test_sanitize_filename(self, filename, expected):
        """Test filename sanitization."""
        result = sanitize_filename(filename)
        assert result == expected

    def test_sanitize_filename_max_length(self):
        """Test filename length limits."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name, max_length=50)

        assert len(result) <= 50
        assert result.endswith(".txt")


class TestDirectoryUtilities:
    """Test directory management utilities."""

    def test_ensure_directory_creation(self):
        """Test directory creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "new" / "nested" / "directory"

            ensure_directory(test_path)

            assert test_path.exists()
            assert test_path.is_dir()

    def test_ensure_directory_existing(self):
        """Test ensure_directory with existing directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)

            # Should not raise error for existing directory
            ensure_directory(test_path)

            assert test_path.exists()


class TestSystemInfoUtilities:
    """Test system information utilities."""

    def test_system_utilities_interface(self):
        """Test system utilities interface."""
        # Test that basic functions exist and work
        timestamp = format_timestamp()
        assert isinstance(timestamp, str)

        # Test IP validation
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("invalid") is False


class TestCommandExecution:
    """Test safe command execution utilities."""

    @patch("subprocess.run")
    def test_run_command_safe_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value = Mock(returncode=0, stdout="success output", stderr="")

        result = run_command(["echo", "test"], timeout=10)

        assert result["success"] is True
        assert result["stdout"] == "success output"
        assert result["stderr"] == ""
        assert result["returncode"] == 0

    @patch("subprocess.run")
    def test_run_command_safe_failure(self, mock_run):
        """Test failed command execution."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="command failed")

        result = run_command(["false"], timeout=10)

        assert result["success"] is False
        assert result["stderr"] == "command failed"
        assert result["returncode"] == 1

    @patch("subprocess.run")
    def test_run_command_safe_timeout(self, mock_run):
        """Test command execution with timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("test", 1)

        result = run_command(["sleep", "10"], timeout=1)

        assert result["success"] is False
        assert "timeout" in result["error"].lower()


class TestXMLParsing:
    """Test XML parsing utilities."""

    def test_parse_nmap_xml_valid(self):
        """Test parsing valid nmap XML output."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="router.local" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack"/>
                <service name="ssh" product="OpenSSH" version="8.9p1"/>
            </port>
        </ports>
    </host>
</nmaprun>"""

        result = parse_nmap_ports(xml_content)

        assert isinstance(result, dict)
        assert "hosts" in result
        assert len(result["hosts"]) == 1

        host = result["hosts"][0]
        assert host["address"] == "192.168.1.1"
        assert host["hostname"] == "router.local"
        assert len(host["ports"]) == 1
        assert host["ports"][0]["port"] == 22
        assert host["ports"][0]["state"] == "open"

    def test_parse_nmap_xml_invalid(self):
        """Test parsing invalid XML."""
        invalid_xml = "not valid xml content"

        result = parse_nmap_ports(invalid_xml)

        assert result["success"] is False
        assert "error" in result


class TestErrorHandling:
    """Test error handling in utility functions."""

    def test_validate_target_with_none(self):
        """Test validate_target with None input."""
        result = validate_target(None)
        assert result["valid"] is False
        assert "error" in result

    def test_sanitize_filename_with_none(self):
        """Test sanitize_filename with None input."""
        result = sanitize_filename(None)
        assert result == "unnamed"

    def test_format_timestamp_with_invalid_input(self):
        """Test format_timestamp with invalid datetime."""
        with pytest.raises((ValueError, TypeError, AttributeError)):
            format_timestamp("not a datetime")


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple utilities."""

    def test_full_target_processing_workflow(self):
        """Test complete target processing workflow."""
        targets = [
            "example.com",
            "192.168.1.1",
            "https://secure.example.com",
            "192.168.1.0/24",
        ]

        for target in targets:
            validation = validate_target(target)
            assert validation["valid"] is True

            if validation["type"] in ["domain", "ip"]:
                filename = sanitize_filename(f"scan_{target}")
                assert len(filename) > 0

    def test_system_info_integration(self):
        """Test system information integration."""
        system_info = get_system_info()
        network_interfaces = get_network_interfaces()

        assert isinstance(system_info, dict)
        assert isinstance(network_interfaces, list)

        # Should have basic system information
        required_keys = ["hostname", "operating_system", "python_version"]
        for key in required_keys:
            assert key in system_info
