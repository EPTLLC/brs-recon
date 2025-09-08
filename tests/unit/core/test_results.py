# BRS-RECON Results Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for results management."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from brsrecon.core.models import ScanResult
from brsrecon.core.results import ResultsManager


class TestResultsManager:
    """Test ResultsManager functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.results_dir = Path(self.temp_dir)
        self.results_manager = ResultsManager(results_dir=str(self.results_dir))

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_results_manager_initialization(self):
        """Test ResultsManager initialization."""
        assert self.results_manager.results_dir == str(self.results_dir)
        assert hasattr(self.results_manager, "logger")

    def test_save_results_json(self):
        """Test saving results in JSON format."""
        scan_result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="example.com",
            scan_type="basic",
            status="completed",
            data={"hosts_found": 5},
            duration=60.0,
        )

        saved_path = self.results_manager.save_results(scan_result, format="json")

        assert saved_path is not None
        assert Path(saved_path).exists()

        # Verify content
        with open(saved_path, "r") as f:
            data = json.load(f)

        assert data["target"] == "example.com"
        assert data["status"] == "completed"
        assert data["data"]["hosts_found"] == 5

    def test_save_results_multiple_formats(self):
        """Test saving results in multiple formats."""
        scan_result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="test.com",
            scan_type="comprehensive",
            status="completed",
            data={"test": "data"},
        )

        formats = ["json", "html"]
        saved_paths = []

        for fmt in formats:
            path = self.results_manager.save_results(scan_result, format=fmt)
            saved_paths.append(path)

        # All files should be created
        for path in saved_paths:
            assert Path(path).exists()

    def test_load_results(self):
        """Test loading results from file."""
        # First save a result
        scan_result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="load-test.com",
            scan_type="basic",
            status="completed",
            data={"loaded": True},
        )

        saved_path = self.results_manager.save_results(scan_result, format="json")

        # Then load it
        loaded_result = self.results_manager.load_results(saved_path)

        assert loaded_result is not None
        assert loaded_result["target"] == "load-test.com"
        assert loaded_result["data"]["loaded"] is True

    def test_list_results(self):
        """Test listing available results."""
        # Save multiple results
        for i in range(3):
            scan_result = ScanResult(
                timestamp=f"2025-09-07T18:4{i}:00Z",
                target=f"target{i}.com",
                scan_type="basic",
                status="completed",
                data={"index": i},
            )
            self.results_manager.save_results(scan_result, format="json")

        results_list = self.results_manager.list_results()

        assert isinstance(results_list, list)
        assert len(results_list) == 3

        # Should be sorted by timestamp (newest first)
        timestamps = [r["timestamp"] for r in results_list]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_get_latest_result(self):
        """Test getting latest result."""
        # Save multiple results with different timestamps
        timestamps = [
            "2025-09-07T18:45:00Z",
            "2025-09-07T18:46:00Z",
            "2025-09-07T18:44:00Z",
        ]

        for i, ts in enumerate(timestamps):
            scan_result = ScanResult(
                timestamp=ts,
                target=f"target{i}.com",
                scan_type="basic",
                status="completed",
                data={"index": i},
            )
            self.results_manager.save_results(scan_result, format="json")

        latest = self.results_manager.get_latest_result()

        assert latest is not None
        assert (
            latest["target"] == "target1.com"
        )  # Should be the one with latest timestamp

    def test_delete_result(self):
        """Test deleting a result."""
        scan_result = ScanResult(
            timestamp="2025-09-07T18:45:00Z",
            target="delete-test.com",
            scan_type="basic",
            status="completed",
            data={"delete": True},
        )

        saved_path = self.results_manager.save_results(scan_result, format="json")
        assert Path(saved_path).exists()

        # Delete the result
        success = self.results_manager.delete_result(saved_path)

        assert success is True
        assert not Path(saved_path).exists()

    def test_cleanup_old_results(self):
        """Test cleanup of old results."""
        # Save many results
        for i in range(10):
            scan_result = ScanResult(
                timestamp=f"2025-09-07T18:4{i:01d}:00Z",
                target=f"cleanup{i}.com",
                scan_type="basic",
                status="completed",
                data={"index": i},
            )
            self.results_manager.save_results(scan_result, format="json")

        # Keep only 5 latest
        cleaned_count = self.results_manager.cleanup_old_results(keep_count=5)

        assert cleaned_count == 5  # Should have deleted 5 files

        remaining = self.results_manager.list_results()
        assert len(remaining) == 5

    def test_get_results_summary(self):
        """Test getting results summary statistics."""
        # Save results with different statuses
        statuses = ["completed", "completed", "failed", "completed"]

        for i, status in enumerate(statuses):
            scan_result = ScanResult(
                timestamp=f"2025-09-07T18:4{i}:00Z",
                target=f"summary{i}.com",
                scan_type="basic",
                status=status,
                data={"index": i},
            )
            self.results_manager.save_results(scan_result, format="json")

        summary = self.results_manager.get_results_summary()

        assert summary["total_scans"] == 4
        assert summary["completed_scans"] == 3
        assert summary["failed_scans"] == 1
        assert summary["success_rate"] == 0.75

    def test_export_results_batch(self):
        """Test batch export of multiple results."""
        # Save multiple results
        for i in range(3):
            scan_result = ScanResult(
                timestamp=f"2025-09-07T18:4{i}:00Z",
                target=f"batch{i}.com",
                scan_type="basic",
                status="completed",
                data={"index": i},
            )
            self.results_manager.save_results(scan_result, format="json")

        # Export all as HTML
        exported_paths = self.results_manager.export_results_batch(format="html")

        assert isinstance(exported_paths, list)
        assert len(exported_paths) == 3

        for path in exported_paths:
            assert Path(path).exists()
            assert path.endswith(".html")

    def test_search_results(self):
        """Test searching results by criteria."""
        # Save results with different targets and statuses
        test_data = [
            ("example.com", "completed", {"ports": [80, 443]}),
            ("test.com", "failed", {"error": "timeout"}),
            ("example.org", "completed", {"ports": [22, 80]}),
        ]

        for target, status, data in test_data:
            scan_result = ScanResult(
                timestamp="2025-09-07T18:45:00Z",
                target=target,
                scan_type="basic",
                status=status,
                data=data,
            )
            self.results_manager.save_results(scan_result, format="json")

        # Search by target pattern
        example_results = self.results_manager.search_results(target_pattern="example")
        assert len(example_results) == 2

        # Search by status
        completed_results = self.results_manager.search_results(status="completed")
        assert len(completed_results) == 2

        # Search by scan type
        basic_results = self.results_manager.search_results(scan_type="basic")
        assert len(basic_results) == 3

