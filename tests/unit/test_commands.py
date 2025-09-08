# BRS-RECON Commands Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for command handlers."""

from unittest.mock import MagicMock, Mock, patch

import pytest

from brsrecon.commands import BRSCommands
from brsrecon.core.config import BRSConfig


class TestBRSCommands:
    """Test BRSCommands functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = BRSConfig()
        self.commands = BRSCommands()

    def test_brs_commands_initialization(self):
        """Test BRSCommands initialization."""
        assert hasattr(self.commands, "logger")
        assert hasattr(self.commands, "results_manager")
        assert hasattr(self.commands, "export_manager")

    @patch("brsrecon.modules.vulnerability.VulnerabilityScanner.scan")
    def test_run_vulnerability_scan(self, mock_scan):
        """Test vulnerability scan command."""
        mock_scan.return_value = {
            "target": "example.com",
            "vulnerabilities": [{"id": "CVE-2023-1234", "severity": "medium"}],
            "scan_duration": 45.2,
        }

        result = self.commands.run_vulnerability_scan(
            "example.com",
            scan_type="comprehensive",
            web_scan=True,
            ssl_scan=True,
            aggressive=False,
        )

        assert result is not None
        mock_scan.assert_called_once()

    @patch("brsrecon.modules.system_info.SystemInfo.scan")
    def test_run_system_info_scan(self, mock_scan):
        """Test system information scan command."""
        mock_scan.return_value = {
            "target": "localhost",
            "hostname": "test-server",
            "operating_system": "Linux",
            "scan_duration": 2.1,
        }

        result = self.commands.run_system_info_scan(
            "localhost", scan_type="full", processes=True, network=True, hardware=True
        )

        assert result is not None
        mock_scan.assert_called_once()

    @patch("brsrecon.core.export.ExportManager.export_to_html")
    @patch("brsrecon.core.export.ExportManager.export_to_sarif")
    def test_export_results(self, mock_sarif, mock_html):
        """Test results export command."""
        mock_html.return_value = "/results/report.html"
        mock_sarif.return_value = "/results/report.sarif"

        # Create a temporary JSON file to export
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "timestamp": "2025-09-07T18:45:00Z",
                    "target": "example.com",
                    "scan_type": "basic",
                    "status": "completed",
                    "data": {"test": "data"},
                },
                f,
            )
            json_file = f.name

        try:
            result = self.commands.export_results(json_file, formats=["html", "sarif"])

            assert result is not None
            mock_html.assert_called_once()
            mock_sarif.assert_called_once()
        finally:
            import os

            os.unlink(json_file)

    def test_validate_scan_parameters(self):
        """Test scan parameter validation."""
        # Valid parameters
        valid_params = {"target": "example.com", "scan_type": "basic", "threads": 10}

        result = self.commands.validate_scan_parameters(valid_params)
        assert result["valid"] is True

    def test_validate_scan_parameters_invalid(self):
        """Test scan parameter validation with invalid data."""
        # Invalid parameters
        invalid_params = {
            "target": "",  # Empty target
            "scan_type": "invalid_type",
            "threads": -1,  # Invalid thread count
        }

        result = self.commands.validate_scan_parameters(invalid_params)
        assert result["valid"] is False
        assert "errors" in result

    def test_get_available_modules(self):
        """Test getting available scanning modules."""
        modules = self.commands.get_available_modules()

        assert isinstance(modules, list)
        expected_modules = [
            "network_discovery",
            "port_scanning",
            "domain_recon",
            "vulnerability",
            "system_info",
        ]

        for module in expected_modules:
            assert module in [m["name"] for m in modules]

    def test_get_module_info(self):
        """Test getting module information."""
        info = self.commands.get_module_info("network_discovery")

        assert isinstance(info, dict)
        assert "name" in info
        assert "description" in info
        assert "supported_targets" in info

    def test_get_module_info_invalid(self):
        """Test getting info for invalid module."""
        info = self.commands.get_module_info("invalid_module")
        assert info is None

    @patch("brsrecon.core.results.ResultsManager.get_results_summary")
    def test_get_scan_statistics(self, mock_summary):
        """Test getting scan statistics."""
        mock_summary.return_value = {
            "total_scans": 25,
            "completed_scans": 22,
            "failed_scans": 3,
            "success_rate": 0.88,
        }

        stats = self.commands.get_scan_statistics()

        assert stats["total_scans"] == 25
        assert stats["success_rate"] == 0.88
        mock_summary.assert_called_once()

    def test_cleanup_old_scans(self):
        """Test cleanup of old scan results."""
        with patch.object(
            self.commands.results_manager, "cleanup_old_results"
        ) as mock_cleanup:
            mock_cleanup.return_value = 5

            result = self.commands.cleanup_old_scans(keep_count=10)

            assert result == 5
            mock_cleanup.assert_called_once_with(keep_count=10)

    def test_verify_tools_availability(self):
        """Test tool availability verification."""
        availability = self.commands.verify_tools_availability()

        assert isinstance(availability, dict)
        assert "nmap" in availability
        assert "fping" in availability
        assert "masscan" in availability

        # Each tool should have availability status
        for tool, status in availability.items():
            assert isinstance(status, bool)

    def test_get_configuration_info(self):
        """Test getting current configuration information."""
        config_info = self.commands.get_configuration_info()

        assert isinstance(config_info, dict)
        assert "network" in config_info
        assert "security" in config_info
        assert "output" in config_info
        assert "logging" in config_info

    def test_validate_target_accessibility(self):
        """Test target accessibility validation."""
        # Test with localhost (should be accessible)
        result = self.commands.validate_target_accessibility("127.0.0.1")

        assert isinstance(result, dict)
        assert "accessible" in result
        assert "response_time" in result

    def test_estimate_scan_duration(self):
        """Test scan duration estimation."""
        estimation = self.commands.estimate_scan_duration(
            target="192.168.1.0/24",
            scan_type="comprehensive",
            modules=["network_discovery", "port_scanning"],
        )

        assert isinstance(estimation, dict)
        assert "estimated_duration" in estimation
        assert "factors" in estimation
        assert estimation["estimated_duration"] > 0


class TestCommandErrorHandling:
    """Test error handling in command operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.commands = BRSCommands()

    def test_vulnerability_scan_with_invalid_target(self):
        """Test vulnerability scan with invalid target."""
        with pytest.raises((ValueError, Exception)):
            self.commands.run_vulnerability_scan("invalid..target", scan_type="basic")

    def test_export_results_nonexistent_file(self):
        """Test export with non-existent file."""
        with pytest.raises(FileNotFoundError):
            self.commands.export_results("/nonexistent/file.json", formats=["html"])

    def test_system_scan_with_invalid_parameters(self):
        """Test system scan with invalid parameters."""
        # Test with invalid scan type
        with pytest.raises((ValueError, Exception)):
            self.commands.run_system_info_scan("localhost", scan_type="invalid_type")


class TestCommandIntegration:
    """Test command integration scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.commands = BRSCommands()

    def test_full_workflow_simulation(self):
        """Test complete workflow simulation."""
        # This would typically involve mocking all the scanning modules
        # and testing the complete workflow from command to result export

        with patch(
            "brsrecon.modules.network_discovery.NetworkDiscovery.scan"
        ) as mock_network:
            with patch(
                "brsrecon.modules.port_scanning.PortScanning.scan"
            ) as mock_ports:

                mock_network.return_value = {
                    "target": "192.168.1.0/24",
                    "discovered_hosts": [{"ip": "192.168.1.1"}],
                }

                mock_ports.return_value = {
                    "target": "192.168.1.1",
                    "open_ports": [{"port": 80, "service": "http"}],
                }

                # Simulate workflow: discovery -> port scan -> export
                network_result = mock_network.return_value
                port_result = mock_ports.return_value

                assert network_result is not None
                assert port_result is not None
                assert len(network_result["discovered_hosts"]) == 1
                assert len(port_result["open_ports"]) == 1

    def test_configuration_integration(self):
        """Test command integration with configuration."""
        custom_config = BRSConfig()
        custom_config.security.safe_mode = False

        with patch("brsrecon.core.config.get_config") as mock_config:
            mock_config.return_value = custom_config

            commands = BRSCommands()

            # Verify configuration is accessible
            config_info = commands.get_configuration_info()
            assert config_info["security"]["safe_mode"] is False
