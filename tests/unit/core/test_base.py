# BRS-RECON Base Module Tests
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Unit tests for base module functionality."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from brsrecon.core.base import BaseModule, ScanConfig
from brsrecon.core.models import ScanResult


class MockModule(BaseModule):
    """Mock implementation of BaseModule for testing."""
    
    def __init__(self, name: str = "test_module", config: ScanConfig = None, fail_validation: bool = False):
        super().__init__(name, config)
        self.fail_validation = fail_validation
        self.scan_called = False
        self.validate_called = False
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Mock scan implementation."""
        self.scan_called = True
        time.sleep(0.01)  # Simulate scan time
        return {
            "target": target,
            "results": ["mock_result_1", "mock_result_2"],
            "kwargs": kwargs
        }
    
    def validate_requirements(self) -> bool:
        """Mock validation implementation."""
        self.validate_called = True
        return not self.fail_validation


class TestScanConfig:
    """Test ScanConfig dataclass."""
    
    def test_scan_config_defaults(self):
        """Test default ScanConfig values."""
        config = ScanConfig()
        
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.delay_between_requests == 0.1
        assert config.save_results is True
        assert config.output_format == "json"
    
    def test_scan_config_custom_values(self):
        """Test ScanConfig with custom values."""
        config = ScanConfig(
            timeout=60,
            max_retries=5,
            delay_between_requests=0.2,
            save_results=False,
            output_format="sarif"
        )
        
        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.delay_between_requests == 0.2
        assert config.save_results is False
        assert config.output_format == "sarif"


class TestBaseModule:
    """Test BaseModule abstract base class."""
    
    def test_base_module_initialization(self):
        """Test BaseModule initialization."""
        module = MockModule("test_scanner")
        
        assert module.name == "test_scanner"
        assert isinstance(module.config, ScanConfig)
        assert module.logger is not None
        assert module.results_manager is not None
        assert module._start_time == 0.0
        assert module._end_time == 0.0
    
    def test_base_module_with_custom_config(self):
        """Test BaseModule with custom configuration."""
        config = ScanConfig(timeout=45, max_retries=5)
        module = MockModule("custom_scanner", config)
        
        assert module.config.timeout == 45
        assert module.config.max_retries == 5
    
    def test_start_scan_valid_target(self):
        """Test _start_scan with valid target."""
        module = MockModule()
        
        result = module._start_scan("example.com")
        
        assert result is True
        assert module.validate_called is True
        assert module._start_time > 0
    
    def test_start_scan_invalid_target(self):
        """Test _start_scan with invalid target."""
        module = MockModule()
        
        result = module._start_scan("invalid..target")
        
        assert result is False
    
    def test_abstract_methods_implementation(self):
        """Test that abstract methods are properly implemented."""
        module = MockModule()
        
        # Test scan method
        result = module.scan("test.com", param1="value1")
        assert module.scan_called is True
        assert result["target"] == "test.com"
        assert result["kwargs"]["param1"] == "value1"
        
        # Test validate_requirements method
        validation_result = module.validate_requirements()
        assert module.validate_called is True
        assert validation_result is True
    
    def test_abstract_methods_not_implemented(self):
        """Test that BaseModule cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseModule("test")
    
    def test_full_scan_workflow(self):
        """Test complete scan workflow from start to finish."""
        module = MockModule()
        
        # Start scan
        start_result = module._start_scan("example.com")
        assert start_result is True
        
        # Perform scan
        scan_results = module.scan("example.com", threads=20, aggressive=True)
        assert scan_results["target"] == "example.com"
        assert scan_results["kwargs"]["threads"] == 20
        assert scan_results["kwargs"]["aggressive"] is True
        
        # End scan
        final_result = module._end_scan("example.com", scan_results)
        assert final_result.status == "completed"
        assert final_result.data == scan_results
        assert final_result.duration > 0