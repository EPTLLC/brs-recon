# BRS-RECON Benchmarking System
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Created
# Telegram: https://t.me/easyprotech

"""Comprehensive benchmarking and performance measurement system."""

import json
import platform
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

from .structured_logger import get_logger


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""

    name: str
    iterations: int
    total_time: float
    avg_time: float
    min_time: float
    max_time: float
    median_time: float
    std_dev: float
    throughput: Optional[float] = None
    memory_peak: Optional[int] = None
    cpu_avg: Optional[float] = None
    success_rate: float = 1.0
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class SystemInfo:
    """System information for benchmark context."""

    platform: str
    python_version: str
    cpu_count: int
    cpu_freq: Optional[float]
    memory_total: int
    memory_available: int
    disk_usage: Dict[str, Any]
    network_interfaces: List[Dict[str, Any]]

    @classmethod
    def collect(cls) -> "SystemInfo":
        """Collect current system information."""
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Network interfaces
        net_interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            interface = {"name": name, "addresses": []}
            for addr in addrs:
                interface["addresses"].append(
                    {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    }
                )
            net_interfaces.append(interface)

        return cls(
            platform=platform.platform(),
            python_version=platform.python_version(),
            cpu_count=psutil.cpu_count(),
            cpu_freq=cpu_freq.current if cpu_freq else None,
            memory_total=memory.total,
            memory_available=memory.available,
            disk_usage={
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent,
            },
            network_interfaces=net_interfaces,
        )


class BenchmarkRunner:
    """Main benchmarking system for BRS-RECON."""

    def __init__(self, results_dir: Path = Path("results/benchmarks")):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger("benchmark")
        self.results: List[BenchmarkResult] = []

    @contextmanager
    def measure_time(self):
        """Context manager for measuring execution time."""
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss

        yield

        end_time = time.perf_counter()
        end_memory = psutil.Process().memory_info().rss

        self.last_duration = end_time - start_time
        self.last_memory_delta = end_memory - start_memory

    def benchmark_function(
        self,
        func: Callable,
        name: str,
        iterations: int = 100,
        warmup: int = 10,
        args: tuple = (),
        kwargs: Dict[str, Any] = None,
        concurrent: bool = False,
        max_workers: int = 4,
    ) -> BenchmarkResult:
        """Benchmark a function with multiple iterations."""
        if kwargs is None:
            kwargs = {}

        self.logger.info(f"Starting benchmark: {name}", iterations=iterations)

        # Warmup runs
        for _ in range(warmup):
            try:
                func(*args, **kwargs)
            except Exception as e:
                self.logger.warning(f"Warmup failed: {e}")

        times = []
        successes = 0
        memory_peak = 0
        cpu_readings = []

        if concurrent:
            times, successes, memory_peak, cpu_readings = self._benchmark_concurrent(
                func, iterations, args, kwargs, max_workers
            )
        else:
            times, successes, memory_peak, cpu_readings = self._benchmark_sequential(
                func, iterations, args, kwargs
            )

        # Calculate statistics
        if times:
            total_time = sum(times)
            avg_time = statistics.mean(times)
            min_time = min(times)
            max_time = max(times)
            median_time = statistics.median(times)
            std_dev = statistics.stdev(times) if len(times) > 1 else 0.0
            throughput = iterations / total_time if total_time > 0 else None
        else:
            total_time = avg_time = min_time = max_time = median_time = std_dev = 0.0
            throughput = None

        success_rate = successes / iterations if iterations > 0 else 0.0
        cpu_avg = statistics.mean(cpu_readings) if cpu_readings else None

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            avg_time=avg_time,
            min_time=min_time,
            max_time=max_time,
            median_time=median_time,
            std_dev=std_dev,
            throughput=throughput,
            memory_peak=memory_peak,
            cpu_avg=cpu_avg,
            success_rate=success_rate,
            metadata={
                "concurrent": concurrent,
                "max_workers": max_workers if concurrent else 1,
                "warmup_iterations": warmup,
            },
        )

        self.results.append(result)
        self.logger.info(f"Benchmark completed: {name}", **result.to_dict())

        return result

    def _benchmark_sequential(
        self, func: Callable, iterations: int, args: tuple, kwargs: Dict[str, Any]
    ) -> tuple:
        """Run benchmark sequentially."""
        times = []
        successes = 0
        memory_peak = 0
        cpu_readings = []

        process = psutil.Process()

        for i in range(iterations):
            # Measure CPU before
            cpu_before = process.cpu_percent()

            start_time = time.perf_counter()
            start_memory = process.memory_info().rss

            try:
                func(*args, **kwargs)
                successes += 1
            except Exception as e:
                self.logger.debug(f"Iteration {i} failed: {e}")

            end_time = time.perf_counter()
            end_memory = process.memory_info().rss

            # Measure CPU after
            cpu_after = process.cpu_percent()
            cpu_readings.append((cpu_before + cpu_after) / 2)

            times.append(end_time - start_time)
            memory_peak = max(memory_peak, end_memory - start_memory)

        return times, successes, memory_peak, cpu_readings

    def _benchmark_concurrent(
        self,
        func: Callable,
        iterations: int,
        args: tuple,
        kwargs: Dict[str, Any],
        max_workers: int,
    ) -> tuple:
        """Run benchmark concurrently."""
        times = []
        successes = 0
        memory_peak = 0
        cpu_readings = []

        process = psutil.Process()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            futures = []
            for i in range(iterations):
                future = executor.submit(self._timed_execution, func, args, kwargs)
                futures.append(future)

            # Collect results
            for future in as_completed(futures):
                try:
                    duration, memory_delta, success = future.result()
                    times.append(duration)
                    memory_peak = max(memory_peak, memory_delta)
                    if success:
                        successes += 1

                    # Sample CPU usage
                    cpu_readings.append(process.cpu_percent())

                except Exception as e:
                    self.logger.debug(f"Concurrent task failed: {e}")

        return times, successes, memory_peak, cpu_readings

    def _timed_execution(
        self, func: Callable, args: tuple, kwargs: Dict[str, Any]
    ) -> tuple:
        """Execute function with timing measurement."""
        process = psutil.Process()

        start_time = time.perf_counter()
        start_memory = process.memory_info().rss
        success = False

        try:
            func(*args, **kwargs)
            success = True
        except Exception:
            pass

        end_time = time.perf_counter()
        end_memory = process.memory_info().rss

        return (end_time - start_time, end_memory - start_memory, success)

    def benchmark_module_performance(self) -> Dict[str, BenchmarkResult]:
        """Benchmark core BRS-RECON modules."""
        results = {}

        # Mock functions for different modules
        def mock_network_discovery():
            time.sleep(0.01)  # Simulate network operation
            return list(range(10))

        def mock_port_scan():
            time.sleep(0.005)  # Simulate port scanning
            return {"open_ports": [22, 80, 443]}

        def mock_dns_lookup():
            time.sleep(0.002)  # Simulate DNS lookup
            return {"A": ["192.168.1.1"], "MX": ["mail.example.com"]}

        def mock_vulnerability_check():
            time.sleep(0.02)  # Simulate vulnerability scanning
            return {"vulnerabilities": []}

        # Benchmark each module
        benchmarks = [
            ("network_discovery", mock_network_discovery, 50),
            ("port_scanning", mock_port_scan, 100),
            ("dns_lookup", mock_dns_lookup, 200),
            ("vulnerability_check", mock_vulnerability_check, 25),
        ]

        for name, func, iterations in benchmarks:
            result = self.benchmark_function(
                func=func, name=name, iterations=iterations, warmup=5
            )
            results[name] = result

        return results

    def save_results(self, filename: Optional[str] = None) -> Path:
        """Save benchmark results to JSON file."""
        if filename is None:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"benchmark_results_{timestamp}.json"

        filepath = self.results_dir / filename

        # Prepare data for serialization
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "system_info": asdict(SystemInfo.collect()),
            "results": [result.to_dict() for result in self.results],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"Benchmark results saved to: {filepath}")
        return filepath

    def generate_report(self) -> str:
        """Generate a human-readable benchmark report."""
        if not self.results:
            return "No benchmark results available."

        report_lines = [
            "BRS-RECON Performance Benchmark Report",
            "=" * 40,
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"System: {platform.platform()}",
            f"Python: {platform.python_version()}",
            f"CPU Cores: {psutil.cpu_count()}",
            f"Memory: {psutil.virtual_memory().total // (1024**3)} GB",
            "",
        ]

        for result in self.results:
            report_lines.extend(
                [
                    f"Benchmark: {result.name}",
                    f"  Iterations: {result.iterations}",
                    f"  Average Time: {result.avg_time:.4f}s",
                    f"  Min/Max Time: {result.min_time:.4f}s / {result.max_time:.4f}s",
                    f"  Standard Deviation: {result.std_dev:.4f}s",
                    (
                        f"  Throughput: {result.throughput:.2f} ops/sec"
                        if result.throughput
                        else "  Throughput: N/A"
                    ),
                    f"  Success Rate: {result.success_rate:.2%}",
                    (
                        f"  Memory Peak: {result.memory_peak // 1024} KB"
                        if result.memory_peak
                        else "  Memory Peak: N/A"
                    ),
                    (
                        f"  CPU Average: {result.cpu_avg:.1f}%"
                        if result.cpu_avg
                        else "  CPU Average: N/A"
                    ),
                    "",
                ]
            )

        return "\n".join(report_lines)


# CLI interface for benchmarking
def main():
    """Main CLI interface for benchmarking."""
    import argparse

    parser = argparse.ArgumentParser(description="BRS-RECON Benchmark Runner")
    parser.add_argument("--output", "-o", help="Output directory for results")
    parser.add_argument(
        "--iterations", "-i", type=int, default=100, help="Number of iterations"
    )
    parser.add_argument(
        "--concurrent", "-c", action="store_true", help="Run concurrent benchmarks"
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=4, help="Number of concurrent workers"
    )
    parser.add_argument(
        "--report", "-r", action="store_true", help="Generate text report"
    )

    args = parser.parse_args()

    # Setup benchmark runner
    results_dir = Path(args.output) if args.output else Path("results/benchmarks")
    runner = BenchmarkRunner(results_dir)

    print("Starting BRS-RECON performance benchmarks...")

    # Run module benchmarks
    runner.benchmark_module_performance()

    # Save results
    filepath = runner.save_results()
    print(f"Results saved to: {filepath}")

    # Generate report if requested
    if args.report:
        report = runner.generate_report()
        print("\n" + report)

        # Save report to file
        report_file = filepath.with_suffix(".txt")
        with open(report_file, "w") as f:
            f.write(report)
        print(f"Report saved to: {report_file}")


if __name__ == "__main__":
    main()
