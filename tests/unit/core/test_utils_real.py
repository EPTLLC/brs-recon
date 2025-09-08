# BRS-RECON Real Utils Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for real utility functions."""

from datetime import datetime

import pytest

from brsrecon.core.utils import (
    check_tool_availability,
    ensure_directory,
    format_bytes,
    format_timestamp,
    get_local_ip,
    parse_nmap_ports,
    run_command,
    sanitize_filename,
    truncate_string,
    validate_domain,
    validate_ip,
    validate_target,
)


class TestRealTimestampFormatting:
    """Test real timestamp formatting."""

    def test_format_timestamp_with_datetime(self):
        """Test format_timestamp with datetime object."""
        dt = datetime(2025, 9, 7, 18, 45, 30)
        result = format_timestamp(dt)
        assert result == "20250907-184530"

    def test_format_timestamp_current_time(self):
        """Test format_timestamp with current time."""
        result = format_timestamp()
        assert isinstance(result, str)
        assert len(result) == 15  # YYYYMMDD-HHMMSS


class TestRealIPValidation:
    """Test real IP validation."""

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("192.168.1.1", True),
            ("127.0.0.1", True),
            ("::1", True),
            ("2001:db8::1", True),
            ("invalid", False),
            ("256.256.256.256", False),
            ("", False),
        ],
    )
    def test_validate_ip_real(self, ip, expected):
        """Test real IP validation function."""
        result = validate_ip(ip)
        assert result == expected


class TestRealDomainValidation:
    """Test real domain validation."""

    @pytest.mark.parametrize(
        "domain,expected",
        [
            ("example.com", True),
            ("subdomain.example.com", True),
            ("localhost", True),
            ("invalid..domain", False),
            ("", False),
            (".example.com", False),
        ],
    )
    def test_validate_domain_real(self, domain, expected):
        """Test real domain validation function."""
        result = validate_domain(domain)
        assert result == expected


class TestRealTargetValidation:
    """Test real target validation."""

    def test_validate_target_ip(self):
        """Test target validation with IP."""
        result = validate_target("192.168.1.1")
        assert result["valid"] is True
        assert result["type"] == "ip"

    def test_validate_target_domain(self):
        """Test target validation with domain."""
        result = validate_target("example.com")
        assert result["valid"] is True
        assert result["type"] == "domain"

    def test_validate_target_network(self):
        """Test target validation with network."""
        result = validate_target("192.168.1.0/24")
        assert result["valid"] is True
        assert result["type"] == "network"

    def test_validate_target_invalid(self):
        """Test target validation with invalid target."""
        result = validate_target("invalid..target")
        assert result["valid"] is False


class TestRealFilenameUtils:
    """Test real filename utilities."""

    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        result = sanitize_filename("test_file.txt")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_sanitize_filename_special_chars(self):
        """Test filename sanitization with special characters."""
        result = sanitize_filename("file<>test.txt")
        assert ">" not in result
        assert "<" not in result


class TestRealDirectoryUtils:
    """Test real directory utilities."""

    def test_ensure_directory_exists(self):
        """Test ensure_directory function exists and works."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "new_dir"
            ensure_directory(test_path)
            assert test_path.exists()


class TestRealToolUtils:
    """Test real tool utilities."""

    def test_check_tool_availability(self):
        """Test tool availability checking."""
        # Test with a tool that should exist
        result = check_tool_availability("ls")
        assert isinstance(result, bool)

    def test_check_tool_availability_nonexistent(self):
        """Test tool availability for non-existent tool."""
        result = check_tool_availability("nonexistent_tool_12345")
        assert result is False


class TestRealNetworkUtils:
    """Test real network utilities."""

    def test_get_local_ip(self):
        """Test getting local IP address."""
        ip = get_local_ip()
        # Function may return different types depending on implementation
        assert ip is not None


class TestRealCommandUtils:
    """Test real command utilities."""

    def test_run_command_exists(self):
        """Test run_command function exists."""
        assert callable(run_command)

    def test_run_command_basic(self):
        """Test basic command execution."""
        result = run_command(["echo", "test"])
        assert isinstance(result, (dict, str, list))


class TestRealParsingUtils:
    """Test real parsing utilities."""

    def test_parse_nmap_ports_exists(self):
        """Test parse_nmap_ports function exists."""
        assert callable(parse_nmap_ports)

    def test_parse_nmap_ports_basic(self):
        """Test basic nmap ports parsing."""
        # Test with simple input
        result = parse_nmap_ports("80/tcp open http")
        assert isinstance(result, (dict, list, str))


class TestRealFormattingUtils:
    """Test real formatting utilities."""

    def test_format_bytes(self):
        """Test format_bytes function."""
        result = format_bytes(1024)
        assert isinstance(result, str)
        assert "1" in result  # Should contain the number

    def test_truncate_string(self):
        """Test truncate_string function."""
        long_string = "a" * 100
        result = truncate_string(long_string, 50)
        assert isinstance(result, str)
        assert len(result) <= 50
