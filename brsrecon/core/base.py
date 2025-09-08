"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .logger import get_logger
from .models import ScanResult
from .results import ResultsManager
from .utils import format_timestamp, validate_target


@dataclass
class ScanConfig:
    """Base scan configuration"""

    timeout: int = 30
    max_retries: int = 3
    delay_between_requests: float = 0.1
    save_results: bool = True
    output_format: str = "json"


class BaseModule(ABC):
    """Base class for all BRS reconnaissance modules"""

    def __init__(self, name: str, config: Optional[ScanConfig] = None):
        self.name = name
        self.config = config or ScanConfig()
        self.logger = get_logger()
        self.results_manager = ResultsManager()
        self._start_time = 0.0
        self._end_time = 0.0

    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform the scan on target"""
        pass

    @abstractmethod
    def validate_requirements(self) -> bool:
        """Validate that all required tools/dependencies are available"""
        pass

    def _start_scan(self, target: str) -> bool:
        """Initialize scan process"""
        # Validate target
        target_info = validate_target(target)
        if not target_info["valid"]:
            self.logger.error(f"Invalid target: {target}")
            return False

        # Check requirements
        if not self.validate_requirements():
            self.logger.error(f"Requirements not met for {self.name}")
            return False

        # Log scan start
        self.logger.scan_start(target, self.name)
        self._start_time = time.time()
        return True

    def _end_scan(
        self, target: str, results: Dict[str, Any], error: Optional[str] = None
    ) -> ScanResult:
        """Finalize scan process"""
        self._end_time = time.time()
        duration = self._end_time - self._start_time

        # Create scan result
        scan_result = ScanResult(
            timestamp=format_timestamp(),
            target=target,
            scan_type=self.name,
            status="completed" if error is None else "failed",
            data=results,
            duration=duration,
            error=error,
        )

        # Log completion
        if error is None:
            results_count = self._count_results(results)
            self.logger.scan_complete(target, self.name, duration, results_count)
        else:
            self.logger.scan_error(target, self.name, error)

        # Save results if configured
        if self.config.save_results:
            try:
                filepath = self.results_manager.save_scan_result(
                    scan_result, self.config.output_format
                )
                self.logger.info(f"Results saved to {filepath}")
            except Exception as e:
                self.logger.error(f"Failed to save results: {e}")

        return scan_result

    def _count_results(self, results: Dict[str, Any]) -> int:
        """Count results in scan data"""
        count = 0

        # For vulnerability scanner, count only actual vulnerabilities
        if self.name == "Vulnerability Scanner":
            vulnerabilities = results.get("vulnerabilities", [])
            return len(vulnerabilities)

        # For other modules, count relevant results
        for key, value in results.items():
            if key in [
                "live_hosts",
                "open_ports",
                "subdomains",
                "services",
                "vulnerabilities",
            ]:
                if isinstance(value, list):
                    count += len(value)
            elif isinstance(value, dict) and key in ["dns_records", "whois_info"]:
                count += len(value)

        return count

    def run_scan(self, target: str, **kwargs) -> ScanResult:
        """Main scan execution method"""
        if not self._start_scan(target):
            return ScanResult(
                timestamp=format_timestamp(),
                target=target,
                scan_type=self.name,
                status="failed",
                data={},
                error="Failed to initialize scan",
            )

        try:
            results = self.scan(target, **kwargs)
            return self._end_scan(target, results)
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.logger.error(error_msg)
            return self._end_scan(target, {}, error_msg)

    def get_info(self) -> Dict[str, Any]:
        """Get module information"""
        return {
            "name": self.name,
            "description": self.__doc__ or "No description available",
            "config": {
                "timeout": self.config.timeout,
                "max_retries": self.config.max_retries,
                "delay_between_requests": self.config.delay_between_requests,
                "save_results": self.config.save_results,
                "output_format": self.config.output_format,
            },
            "requirements_met": self.validate_requirements(),
        }


class NetworkModule(BaseModule):
    """Base class for network-related modules"""

    def __init__(self, name: str, config: Optional[ScanConfig] = None):
        super().__init__(name, config)

    def _check_network_tools(self, tools: List[str]) -> Dict[str, bool]:
        """Check availability of network tools"""
        from .utils import check_tool_availability

        tool_status = {}
        for tool in tools:
            available = check_tool_availability(tool)
            tool_status[tool] = available
            self.logger.tool_check(tool, available)

        return tool_status


class WebModule(BaseModule):
    """Base class for web-related modules"""

    def __init__(self, name: str, config: Optional[ScanConfig] = None):
        super().__init__(name, config)
        self.user_agent = "BRS-RECON/0.0.2 (Network Reconnaissance Tool)"

    def _get_headers(self) -> Dict[str, str]:
        """Get default HTTP headers"""
        return {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "close"}


class SystemModule(BaseModule):
    """Base class for system information modules"""

    def __init__(self, name: str, config: Optional[ScanConfig] = None):
        super().__init__(name, config)

    def _run_system_command(self, command: List[str]) -> Dict[str, Any]:
        """Run system command and return results"""
        from .utils import run_command

        result = run_command(command, timeout=self.config.timeout)
        return {
            "command": " ".join(command),
            "success": result["success"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "returncode": result["returncode"],
        }
