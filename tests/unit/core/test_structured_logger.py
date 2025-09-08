# BRS-RECON Structured Logger Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive tests for structured logging functionality."""

import json
import logging
import tempfile
import time
import uuid
from contextvars import copy_context
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from brsrecon.core.structured_logger import (
    BRSReconLogger,
    CorrelationIdFilter,
    LogContext,
    PerformanceLogger,
    PerformanceMetrics,
    StructuredFormatter,
    correlation_context,
    correlation_id,
    get_logger,
    operation_context,
)


class TestStructuredFormatter:
    """Test StructuredFormatter functionality."""

    def test_structured_formatter_basic(self):
        """Test basic structured formatting."""
        formatter = StructuredFormatter()

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.created = 1694098800.123456

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test_logger"
        assert parsed["message"] == "Test message"
        assert parsed["line"] == 42
        assert "timestamp" in parsed
        assert "thread" in parsed
        assert "process" in parsed

    def test_structured_formatter_with_correlation_id(self):
        """Test structured formatting with correlation ID."""
        formatter = StructuredFormatter()

        test_corr_id = "test-correlation-123"
        correlation_id.set(test_corr_id)

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        assert parsed["correlation_id"] == test_corr_id

        correlation_id.set(None)

    def test_structured_formatter_with_exception(self):
        """Test structured formatting with exception information."""
        formatter = StructuredFormatter()

        try:
            raise ValueError("Test exception")
        except ValueError:
            record = logging.LogRecord(
                name="test_logger",
                level=logging.ERROR,
                pathname="/test/path.py",
                lineno=42,
                msg="Error occurred",
                args=(),
                exc_info=True,
            )

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        assert "exception" in parsed
        assert parsed["exception"]["type"] == "ValueError"
        assert parsed["exception"]["message"] == "Test exception"
        assert "traceback" in parsed["exception"]

    def test_structured_formatter_with_extra_fields(self):
        """Test structured formatting with extra fields."""
        formatter = StructuredFormatter(include_extra=True)

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        record.scan_id = "scan-123"
        record.target = "example.com"
        record.duration = 5.5

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        assert "extra" in parsed
        assert parsed["extra"]["scan_id"] == "scan-123"
        assert parsed["extra"]["target"] == "example.com"
        assert parsed["extra"]["duration"] == 5.5


class TestCorrelationIdFilter:
    """Test CorrelationIdFilter functionality."""

    def test_correlation_id_filter_with_id(self):
        """Test filter with correlation ID set."""
        filter_obj = CorrelationIdFilter()

        test_corr_id = "test-filter-123"
        correlation_id.set(test_corr_id)

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)

        assert result is True
        assert hasattr(record, "correlation_id")
        assert record.correlation_id == test_corr_id

        correlation_id.set(None)

    def test_correlation_id_filter_without_id(self):
        """Test filter without correlation ID set."""
        filter_obj = CorrelationIdFilter()

        correlation_id.set(None)

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)

        assert result is True
        assert not hasattr(record, "correlation_id")


class TestPerformanceMetrics:
    """Test PerformanceMetrics dataclass."""

    def test_performance_metrics_creation(self):
        """Test PerformanceMetrics creation."""
        start_time = time.time()
        metrics = PerformanceMetrics(
            operation="test_operation", start_time=start_time, memory_start=1024000
        )

        assert metrics.operation == "test_operation"
        assert metrics.start_time == start_time
        assert metrics.memory_start == 1024000
        assert metrics.end_time is None
        assert metrics.duration is None

    def test_performance_metrics_finish(self):
        """Test PerformanceMetrics finish functionality."""
        start_time = time.time()
        metrics = PerformanceMetrics(operation="test_operation", start_time=start_time)

        time.sleep(0.01)
        metrics.finish()

        assert metrics.end_time is not None
        assert metrics.duration is not None
        assert metrics.duration >= 0.01
        assert metrics.end_time > metrics.start_time


class TestPerformanceLogger:
    """Test PerformanceLogger functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=logging.Logger)
        self.perf_logger = PerformanceLogger(self.mock_logger)

    def test_start_operation(self):
        """Test starting operation tracking."""
        operation_id = self.perf_logger.start_operation(
            "test_scan", target="example.com"
        )

        assert operation_id.startswith("test_scan_")
        assert len(operation_id) == len("test_scan_") + 8
        assert operation_id in self.perf_logger._operations

        self.mock_logger.info.assert_called_once()

    def test_finish_operation(self):
        """Test finishing operation tracking."""
        operation_id = self.perf_logger.start_operation("test_scan")

        time.sleep(0.01)

        metrics = self.perf_logger.finish_operation(operation_id)

        assert metrics is not None
        assert metrics.operation == "test_scan"
        assert metrics.duration > 0
        assert operation_id not in self.perf_logger._operations

        assert self.mock_logger.info.call_count == 2

    def test_finish_unknown_operation(self):
        """Test finishing unknown operation."""
        metrics = self.perf_logger.finish_operation("unknown-operation-123")

        assert metrics is None
        self.mock_logger.warning.assert_called_once()

    def test_log_benchmark(self):
        """Test benchmark logging."""
        self.perf_logger.log_benchmark(
            "network_scan", duration=5.5, hosts_scanned=256, hosts_found=12
        )

        self.mock_logger.info.assert_called_once()


class TestBRSReconLogger:
    """Test BRSReconLogger main class."""

    def test_brs_recon_logger_initialization(self):
        """Test BRSReconLogger initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"

            logger = BRSReconLogger(
                name="test_logger",
                level=logging.DEBUG,
                log_file=log_file,
                console_output=True,
                structured_format=True,
            )

            assert logger.name == "test_logger"
            assert logger.logger.level == logging.DEBUG
            assert isinstance(logger.performance, PerformanceLogger)
            assert len(logger.logger.handlers) == 2

    def test_correlation_id_management(self):
        """Test correlation ID management."""
        logger = BRSReconLogger()

        corr_id = logger.set_correlation_id("custom-id-123")
        assert corr_id == "custom-id-123"
        assert logger.get_correlation_id() == "custom-id-123"

        auto_corr_id = logger.set_correlation_id()
        assert auto_corr_id != "custom-id-123"
        assert len(auto_corr_id) == 36
        assert logger.get_correlation_id() == auto_corr_id

    def test_logger_adapter_creation(self):
        """Test logger adapter creation with context."""
        logger = BRSReconLogger()

        adapter = logger.with_context(scan_id="scan-123", target="example.com")

        assert isinstance(adapter, logging.LoggerAdapter)
        assert adapter.extra["scan_id"] == "scan-123"
        assert adapter.extra["target"] == "example.com"


class TestCorrelationContext:
    """Test correlation context manager."""

    def test_correlation_context_with_custom_id(self):
        """Test correlation context with custom ID."""
        custom_id = "custom-context-123"

        correlation_id.set(None)
        assert correlation_id.get() is None

        with correlation_context(custom_id) as context_id:
            assert context_id == custom_id
            assert correlation_id.get() == custom_id

        assert correlation_id.get() is None

    def test_correlation_context_auto_generated(self):
        """Test correlation context with auto-generated ID."""
        correlation_id.set(None)

        with correlation_context() as context_id:
            assert context_id is not None
            assert len(context_id) == 36
            assert correlation_id.get() == context_id

        assert correlation_id.get() is None

    def test_correlation_context_nested(self):
        """Test nested correlation contexts."""
        outer_id = "outer-context-123"
        inner_id = "inner-context-456"

        correlation_id.set(None)

        with correlation_context(outer_id):
            assert correlation_id.get() == outer_id

            with correlation_context(inner_id):
                assert correlation_id.get() == inner_id

            assert correlation_id.get() == outer_id

        assert correlation_id.get() is None


class TestOperationContext:
    """Test operation context manager."""

    def test_operation_context_basic(self):
        """Test basic operation context functionality."""
        mock_logger = Mock(spec=BRSReconLogger)
        mock_perf_logger = Mock(spec=PerformanceLogger)
        mock_logger.performance = mock_perf_logger

        mock_perf_logger.start_operation.return_value = "operation-123"
        mock_perf_logger.finish_operation.return_value = Mock()

        with operation_context(
            mock_logger, "test_operation", target="example.com"
        ) as op_id:
            assert op_id == "operation-123"

        mock_perf_logger.start_operation.assert_called_once_with(
            "test_operation", target="example.com"
        )
        mock_perf_logger.finish_operation.assert_called_once_with("operation-123")

    def test_operation_context_with_exception(self):
        """Test operation context when exception occurs."""
        mock_logger = Mock(spec=BRSReconLogger)
        mock_perf_logger = Mock(spec=PerformanceLogger)
        mock_logger.performance = mock_perf_logger

        mock_perf_logger.start_operation.return_value = "operation-123"
        mock_perf_logger.finish_operation.return_value = Mock()

        with pytest.raises(ValueError):
            with operation_context(mock_logger, "test_operation"):
                raise ValueError("Test exception")

        mock_perf_logger.finish_operation.assert_called_once_with("operation-123")


class TestGetLogger:
    """Test get_logger factory function."""

    def test_get_logger_defaults(self):
        """Test get_logger with default parameters."""
        logger = get_logger()

        assert isinstance(logger, BRSReconLogger)
        assert logger.name == "brs-recon"

    def test_get_logger_custom_parameters(self):
        """Test get_logger with custom parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "custom.log"

            logger = get_logger(
                name="custom_logger",
                level=logging.WARNING,
                log_file=log_file,
                console_output=False,
                structured_format=False,
            )

            assert logger.name == "custom_logger"
            assert logger.logger.level == logging.WARNING
            assert len(logger.logger.handlers) == 1


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""

    def test_full_logging_workflow(self):
        """Test complete logging workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "integration.log"

            logger = get_logger(
                name="integration_test", log_file=log_file, structured_format=True
            )

            corr_id = logger.set_correlation_id("integration-test-123")

            with operation_context(
                logger, "network_scan", target="example.com"
            ) as op_id:
                logger.info("Starting network scan", target="example.com")
                time.sleep(0.01)
                logger.info("Scan completed", hosts_found=5)

            assert log_file.exists()

            with open(log_file, "r") as f:
                log_lines = f.readlines()

            assert len(log_lines) >= 2

            first_entry = json.loads(log_lines[0])
            assert first_entry["correlation_id"] == corr_id

    def test_concurrent_logging_with_correlation(self):
        """Test concurrent logging with different correlation IDs."""
        import queue
        import threading

        results = queue.Queue()

        def worker(worker_id):
            logger = get_logger(name=f"worker_{worker_id}")

            with correlation_context(f"worker-{worker_id}-correlation"):
                corr_id = correlation_id.get()
                logger.info(f"Worker {worker_id} starting", worker_id=worker_id)

                with operation_context(logger, f"worker_{worker_id}_task"):
                    time.sleep(0.01)
                    logger.info(f"Worker {worker_id} completed")

                results.put((worker_id, corr_id))

        threads = []
        for i in range(3):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        collected_results = []
        while not results.empty():
            collected_results.append(results.get())

        assert len(collected_results) == 3

        correlation_ids = [result[1] for result in collected_results]
        assert len(set(correlation_ids)) == 3

