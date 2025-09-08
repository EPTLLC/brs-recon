# BRS-RECON Test Configuration
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Pytest configuration and fixtures for BRS-RECON tests."""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch
from typing import Dict, Any, Generator

# Import core modules for testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from brsrecon.core.base import ScanConfig
from brsrecon.core.models import ScanResult


@pytest.fixture
def temp_results_dir() -> Generator[Path, None, None]:
    """Create temporary results directory for tests."""
    temp_dir = tempfile.mkdtemp(prefix="brs_recon_test_")
    results_path = Path(temp_dir)
    
    # Create subdirectories
    for subdir in ["scans", "html", "json", "sarif", "xml", "csv", "logs"]:
        (results_path / subdir).mkdir(exist_ok=True)
    
    yield results_path
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_scan_config() -> ScanConfig:
    """Create mock scan configuration for tests."""
    return ScanConfig(
        target="test.example.com",
        scan_type="basic",
        threads=1,
        timeout=10,
        safe_mode=True,
        output_format="json"
    )


@pytest.fixture
def mock_target_info() -> dict:
    """Create mock target information for tests."""
    return {
        "target": "test.example.com",
        "ip_addresses": ["192.168.1.100"],
        "hostname": "test.example.com",
        "target_type": "domain"
    }


@pytest.fixture
def mock_scan_result() -> ScanResult:
    """Create mock scan result for tests."""
    return ScanResult(
        timestamp="2025-09-07T18:45:00Z",
        target="test.example.com",
        scan_type="basic",
        status="completed",
        data={"test": "data"},
        duration=60.0
    )


@pytest.fixture
def mock_subprocess():
    """Mock subprocess calls for external tools."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(
            returncode=0,
            stdout="mock output",
            stderr=""
        )
        yield mock_run


@pytest.fixture
def mock_network_tools():
    """Mock external network tools (nmap, fping, etc.)."""
    tools = {
        'nmap': Mock(return_value="mock nmap output"),
        'fping': Mock(return_value="mock fping output"),
        'masscan': Mock(return_value="mock masscan output"),
        'dig': Mock(return_value="mock dig output"),
        'whois': Mock(return_value="mock whois output"),
        'nikto': Mock(return_value="mock nikto output"),
        'sslscan': Mock(return_value="mock sslscan output"),
        'testssl.sh': Mock(return_value="mock testssl output"),
    }
    
    with patch.multiple('subprocess', **{f'run_{tool}': mock for tool, mock in tools.items()}):
        yield tools


@pytest.fixture(autouse=True)
def disable_network_calls():
    """Automatically disable real network calls in tests."""
    with patch('socket.socket'), \
         patch('requests.get'), \
         patch('requests.post'), \
         patch('aiohttp.ClientSession'):
        yield


@pytest.fixture
def sample_nmap_output() -> str:
    """Sample nmap XML output for testing."""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <hostnames>
            <hostname name="test.example.com" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack"/>
                <service name="http" product="nginx" version="1.18.0"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="nginx" version="1.18.0"/>
            </port>
        </ports>
    </host>
</nmaprun>'''


@pytest.fixture
def sample_domain_data() -> Dict[str, Any]:
    """Sample domain reconnaissance data."""
    return {
        "domain": "test.example.com",
        "dns_records": {
            "A": ["192.168.1.100"],
            "AAAA": ["2001:db8::1"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all"]
        },
        "subdomains": ["www.example.com", "mail.example.com"],
        "whois": {
            "registrar": "Test Registrar",
            "creation_date": "2020-01-01",
            "expiration_date": "2025-01-01"
        }
    }


# Pytest markers configuration
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "privileged: mark test as requiring elevated privileges"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    for item in items:
        # Mark integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark slow tests
        if "slow" in item.name or "comprehensive" in item.name:
            item.add_marker(pytest.mark.slow)
        
        # Mark network tests
        if any(keyword in str(item.fspath) for keyword in ["network", "domain", "port"]):
            item.add_marker(pytest.mark.network)
