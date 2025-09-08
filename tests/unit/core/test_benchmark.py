# BRS-RECON Benchmark Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for benchmarking system."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from brsrecon.core.benchmark import BenchmarkResult, BenchmarkRunner, SystemInfo


class TestBenchmarkResult:
    """Test BenchmarkResult dataclass."""

    def test_benchmark_result_creation(self):
        """Test BenchmarkResult creation."""
        result = BenchmarkResult(
            name="test_benchmark",
            iterations=100,
            total_time=10.5,
            avg_time=0.105,
            min_time=0.08,
            max_time=0.15,
            median_time=0.1,
            std_dev=0.02,
            throughput=9.52,
            memory_peak=1024000,
            cpu_avg=25.5,
            success_rate=0.98,
            metadata={"test": "data"},
        )

        assert result.name == "test_benchmark"
        assert result.iterations == 100
        assert result.total_time == 10.5
        assert result.avg_time == 0.105
        assert result.throughput == 9.52
        assert result.success_rate == 0.98
        assert result.metadata["test"] == "data"

    def test_benchmark_result_to_dict(self):
        """Test BenchmarkResult serialization to dictionary."""
        result = BenchmarkResult(
            name="test_dict",
            iterations=50,
            total_time=5.0,
            avg_time=0.1,
            min_time=0.05,
            max_time=0.2,
            median_time=0.09,
            std_dev=0.03,
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["name"] == "test_dict"
        assert result_dict["iterations"] == 50
        assert result_dict["total_time"] == 5.0

    def test_benchmark_result_optional_fields(self):
        """Test BenchmarkResult with optional fields."""
        result = BenchmarkResult(
            name="minimal_test",
            iterations=10,
            total_time=1.0,
            avg_time=0.1,
            min_time=0.08,
            max_time=0.12,
            median_time=0.1,
            std_dev=0.01,
        )

        assert result.throughput is None
        assert result.memory_peak is None
        assert result.cpu_avg is None
        assert result.success_rate == 1.0
        assert result.metadata is None


class TestSystemInfo:
    """Test SystemInfo collection."""

    @patch("platform.platform")
    @patch("platform.python_version")
    @patch("psutil.cpu_count")
    @patch("psutil.cpu_freq")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.net_if_addrs")
    def test_system_info_collect(
        self,
        mock_net_if,
        mock_disk,
        mock_memory,
        mock_cpu_freq,
        mock_cpu_count,
        mock_python_ver,
        mock_platform,
    ):
        """Test SystemInfo collection."""
        mock_platform.return_value = "Linux-5.15.0-58-generic-x86_64"
        mock_python_ver.return_value = "3.10.6"
        mock_cpu_count.return_value = 8

        mock_freq = Mock()
        mock_freq.current = 2400.0
        mock_cpu_freq.return_value = mock_freq

        mock_mem = Mock()
        mock_mem.total = 16777216000
        mock_mem.available = 8388608000
        mock_memory.return_value = mock_mem

        mock_disk_info = Mock()
        mock_disk_info.total = 1000000000000
        mock_disk_info.used = 500000000000
        mock_disk_info.free = 500000000000
        mock_disk_info.percent = 50.0
        mock_disk.return_value = mock_disk_info

        mock_net_if.return_value = {
            "eth0": [
                Mock(
                    family=2,
                    address="192.168.1.100",
                    netmask="255.255.255.0",
                    broadcast="192.168.1.255",
                )
            ]
        }

        system_info = SystemInfo.collect()

        assert system_info.platform == "Linux-5.15.0-58-generic-x86_64"
        assert system_info.python_version == "3.10.6"
        assert system_info.cpu_count == 8
        assert system_info.cpu_freq == 2400.0
        assert system_info.memory_total == 16777216000
        assert system_info.disk_usage["percent"] == 50.0
        assert len(system_info.network_interfaces) == 1


class TestBenchmarkRunner:
    """Test BenchmarkRunner functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.results_dir = Path(self.temp_dir) / "benchmarks"
        self.runner = BenchmarkRunner(self.results_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_benchmark_runner_initialization(self):
        """Test BenchmarkRunner initialization."""
        assert self.runner.results_dir == self.results_dir
        assert self.results_dir.exists()
        assert len(self.runner.results) == 0

    def test_benchmark_function_basic(self):
        """Test basic function benchmarking."""

        def test_function(x, y=1):
            time.sleep(0.001)
            return x + y

        result = self.runner.benchmark_function(
            func=test_function,
            name="test_addition",
            iterations=10,
            warmup=2,
            args=(5,),
            kwargs={"y": 3},
        )

        assert isinstance(result, BenchmarkResult)
        assert result.name == "test_addition"
        assert result.iterations == 10
        assert result.total_time > 0
        assert result.success_rate == 1.0
        assert len(self.runner.results) == 1

    def test_benchmark_function_with_failures(self):
        """Test function benchmarking with some failures."""
        call_count = 0

        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count % 3 == 0:
                raise ValueError("Simulated failure")
            time.sleep(0.001)
            return "success"

        result = self.runner.benchmark_function(
            func=failing_function, name="failing_test", iterations=9, warmup=0
        )

        assert result.success_rate == 6 / 9
        assert result.iterations == 9

    def test_benchmark_module_performance(self):
        """Test module performance benchmarking."""
        results = self.runner.benchmark_module_performance()

        assert isinstance(results, dict)
        expected_modules = [
            "network_discovery",
            "port_scanning",
            "dns_lookup",
            "vulnerability_check",
        ]

        for module in expected_modules:
            assert module in results
            assert isinstance(results[module], BenchmarkResult)
            assert results[module].iterations > 0

    def test_save_results(self):
        """Test saving benchmark results."""

        def simple_function():
            return 42

        self.runner.benchmark_function(
            func=simple_function, name="save_test", iterations=5
        )

        saved_file = self.runner.save_results("test_results.json")

        assert saved_file.exists()
        assert saved_file.name == "test_results.json"

        with open(saved_file, "r") as f:
            data = json.load(f)

        assert "timestamp" in data
        assert "system_info" in data
        assert "results" in data
        assert len(data["results"]) == 1

    def test_generate_report(self):
        """Test report generation."""

        def test_function():
            time.sleep(0.001)
            return "test"

        self.runner.benchmark_function(test_function, "test_report", iterations=10)

        report = self.runner.generate_report()

        assert isinstance(report, str)
        assert "BRS-RECON Performance Benchmark Report" in report
        assert "test_report" in report
        assert "Average Time:" in report

