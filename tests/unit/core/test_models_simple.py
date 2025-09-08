# BRS-RECON Simple Models Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Simple unit tests for core data models."""

import pytest

from brsrecon.core.models import ScanResult


class TestScanResult:
    """Test ScanResult model."""
    
    def test_scan_result_creation(self):
        """Test basic scan result creation."""
        result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="192.168.1.0/24",
            scan_type="basic",
            status="completed",
            data={"hosts_found": 5},
            duration=60.0
        )
        
        assert result.timestamp == "2025-09-07T18:45:00Z"
        assert result.target == "192.168.1.0/24"
        assert result.scan_type == "basic"
        assert result.status == "completed"
        assert result.duration == 60.0
        assert result.data["hosts_found"] == 5
    
    def test_scan_result_with_error(self):
        """Test scan result with error."""
        result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="invalid.target",
            scan_type="basic",
            status="failed",
            data={},
            duration=5.0,
            error="Invalid target format"
        )
        
        assert result.status == "failed"
        assert result.error == "Invalid target format"
        assert result.duration == 5.0
    
    def test_scan_result_defaults(self):
        """Test scan result with default values."""
        result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="example.com",
            scan_type="comprehensive",
            status="completed",
            data={"ports_scanned": 1000}
        )
        
        assert result.duration == 0.0  # Default value
        assert result.error is None  # Default value
    
    def test_scan_result_data_types(self):
        """Test scan result with different data types."""
        result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="test.com",
            scan_type="basic",
            status="completed",
            data={
                "string_value": "test",
                "int_value": 42,
                "float_value": 3.14,
                "list_value": [1, 2, 3],
                "dict_value": {"nested": "data"}
            },
            duration=1.5
        )
        
        assert result.data["string_value"] == "test"
        assert result.data["int_value"] == 42
        assert result.data["float_value"] == 3.14
        assert result.data["list_value"] == [1, 2, 3]
        assert result.data["dict_value"]["nested"] == "data"
