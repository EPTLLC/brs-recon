#!/usr/bin/env python3
# BRS-RECON Test Runner Script
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Comprehensive test runner script for BRS-RECON.

This script provides various test execution modes with proper reporting
and configuration management.
"""

import sys
import argparse
import subprocess
import os
from pathlib import Path
from typing import List, Optional, Dict, Any


class TestRunner:
    """Main test runner class."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.tests_dir = project_root / "tests"
        self.coverage_dir = project_root / "htmlcov"
        
    def run_unit_tests(self, verbose: bool = False, coverage: bool = True) -> int:
        """Run unit tests."""
        print("🧪 Running Unit Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "unit"),
            "-m", "unit or not (integration or slow or network or privileged)",
            "--tb=short"
        ]
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
            
        if coverage:
            cmd.extend([
                "--cov=brs_recon",
                "--cov-report=term-missing:skip-covered",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml"
            ])
            
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_integration_tests(self, verbose: bool = False, include_privileged: bool = False) -> int:
        """Run integration tests."""
        print("🔗 Running Integration Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "integration"),
            "-m", "integration"
        ]
        
        if not include_privileged:
            cmd.extend(["-m", "not privileged"])
            
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
            
        cmd.extend(["--tb=short", "--durations=10"])
        
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_all_tests(self, verbose: bool = False, include_slow: bool = False, 
                     include_privileged: bool = False) -> int:
        """Run all tests."""
        print("🚀 Running All Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir),
            "--cov=brs_recon",
            "--cov-report=term-missing:skip-covered",
            "--cov-report=html:htmlcov",
            "--cov-report=xml:coverage.xml",
            "--cov-fail-under=85"
        ]
        
        # Build marker expression
        markers = []
        if not include_slow:
            markers.append("not slow")
        if not include_privileged:
            markers.append("not privileged")
            
        if markers:
            cmd.extend(["-m", " and ".join(markers)])
            
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
            
        cmd.extend(["--tb=short", "--durations=20"])
        
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_specific_test(self, test_path: str, verbose: bool = True) -> int:
        """Run a specific test file or function."""
        print(f"🎯 Running Specific Test: {test_path}")
        
        cmd = [
            "python", "-m", "pytest",
            test_path,
            "--tb=long"
        ]
        
        if verbose:
            cmd.append("-v")
            
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_coverage_report(self) -> int:
        """Generate and display coverage report."""
        print("📊 Generating Coverage Report...")
        
        # Generate HTML report
        cmd = [
            "python", "-m", "pytest",
            "--cov=brs_recon",
            "--cov-report=html:htmlcov",
            "--cov-report=term-missing",
            "--cov-only"
        ]
        
        result = subprocess.run(cmd, cwd=self.project_root)
        
        if result.returncode == 0:
            print(f"✅ Coverage report generated: {self.coverage_dir}/index.html")
        
        return result.returncode
    
    def run_performance_tests(self, verbose: bool = False) -> int:
        """Run performance/benchmark tests."""
        print("⚡ Running Performance Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir),
            "-k", "benchmark or performance",
            "--tb=short"
        ]
        
        if verbose:
            cmd.append("-v")
            
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_security_tests(self, verbose: bool = False) -> int:
        """Run security-focused tests."""
        print("🔒 Running Security Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir),
            "-k", "security or auth or validation",
            "--tb=short"
        ]
        
        if verbose:
            cmd.append("-v")
            
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def run_parallel_tests(self, workers: int = 4, verbose: bool = False) -> int:
        """Run tests in parallel using pytest-xdist."""
        print(f"🔄 Running Tests in Parallel ({workers} workers)...")
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir),
            f"-n{workers}",
            "--cov=brs_recon",
            "--cov-report=term-missing:skip-covered",
            "--cov-report=html:htmlcov"
        ]
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
            
        return subprocess.run(cmd, cwd=self.project_root).returncode
    
    def check_test_environment(self) -> Dict[str, Any]:
        """Check test environment and dependencies."""
        print("🔍 Checking Test Environment...")
        
        env_status = {
            "python_version": sys.version,
            "pytest_available": False,
            "coverage_available": False,
            "external_tools": {},
            "test_dirs_exist": {}
        }
        
        # Check pytest
        try:
            import pytest
            env_status["pytest_available"] = True
            env_status["pytest_version"] = pytest.__version__
        except ImportError:
            pass
        
        # Check coverage
        try:
            import coverage
            env_status["coverage_available"] = True
            env_status["coverage_version"] = coverage.__version__
        except ImportError:
            pass
        
        # Check external tools
        tools = ["nmap", "fping", "masscan", "dig", "whois"]
        import shutil
        for tool in tools:
            env_status["external_tools"][tool] = shutil.which(tool) is not None
        
        # Check test directories
        test_dirs = ["unit", "integration"]
        for test_dir in test_dirs:
            dir_path = self.tests_dir / test_dir
            env_status["test_dirs_exist"][test_dir] = dir_path.exists()
        
        return env_status
    
    def print_environment_status(self, env_status: Dict[str, Any]) -> None:
        """Print environment status report."""
        print("\n📋 Test Environment Status:")
        print(f"Python: {env_status['python_version']}")
        
        if env_status["pytest_available"]:
            print(f"✅ pytest: {env_status.get('pytest_version', 'available')}")
        else:
            print("❌ pytest: not available")
        
        if env_status["coverage_available"]:
            print(f"✅ coverage: {env_status.get('coverage_version', 'available')}")
        else:
            print("❌ coverage: not available")
        
        print("\nExternal Tools:")
        for tool, available in env_status["external_tools"].items():
            status = "✅" if available else "❌"
            print(f"{status} {tool}: {'available' if available else 'not found'}")
        
        print("\nTest Directories:")
        for test_dir, exists in env_status["test_dirs_exist"].items():
            status = "✅" if exists else "❌"
            print(f"{status} {test_dir}: {'exists' if exists else 'missing'}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BRS-RECON Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/run_tests.py unit              # Run unit tests only
  python scripts/run_tests.py integration       # Run integration tests
  python scripts/run_tests.py all --verbose     # Run all tests with verbose output
  python scripts/run_tests.py specific tests/unit/core/test_base.py
  python scripts/run_tests.py coverage          # Generate coverage report
  python scripts/run_tests.py parallel -w 8     # Run tests in parallel with 8 workers
  python scripts/run_tests.py check             # Check test environment
        """
    )
    
    parser.add_argument(
        "test_type",
        choices=["unit", "integration", "all", "specific", "coverage", 
                "performance", "security", "parallel", "check"],
        help="Type of tests to run"
    )
    
    parser.add_argument(
        "test_path",
        nargs="?",
        help="Specific test path (for 'specific' test type)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Disable coverage reporting"
    )
    
    parser.add_argument(
        "--include-slow",
        action="store_true",
        help="Include slow tests"
    )
    
    parser.add_argument(
        "--include-privileged",
        action="store_true",
        help="Include tests requiring elevated privileges"
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=4,
        help="Number of parallel workers (for parallel tests)"
    )
    
    args = parser.parse_args()
    
    # Find project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    runner = TestRunner(project_root)
    
    # Handle different test types
    if args.test_type == "check":
        env_status = runner.check_test_environment()
        runner.print_environment_status(env_status)
        return 0
    
    elif args.test_type == "unit":
        return runner.run_unit_tests(
            verbose=args.verbose,
            coverage=not args.no_coverage
        )
    
    elif args.test_type == "integration":
        return runner.run_integration_tests(
            verbose=args.verbose,
            include_privileged=args.include_privileged
        )
    
    elif args.test_type == "all":
        return runner.run_all_tests(
            verbose=args.verbose,
            include_slow=args.include_slow,
            include_privileged=args.include_privileged
        )
    
    elif args.test_type == "specific":
        if not args.test_path:
            print("❌ Error: test_path required for 'specific' test type")
            return 1
        return runner.run_specific_test(args.test_path, verbose=args.verbose)
    
    elif args.test_type == "coverage":
        return runner.run_coverage_report()
    
    elif args.test_type == "performance":
        return runner.run_performance_tests(verbose=args.verbose)
    
    elif args.test_type == "security":
        return runner.run_security_tests(verbose=args.verbose)
    
    elif args.test_type == "parallel":
        return runner.run_parallel_tests(
            workers=args.workers,
            verbose=args.verbose
        )
    
    else:
        print(f"❌ Unknown test type: {args.test_type}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
