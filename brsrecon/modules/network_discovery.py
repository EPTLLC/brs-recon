"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from ..core.base import NetworkModule, ScanConfig
from ..core.utils import run_command, validate_network
from .network_utils import NetworkUtils


class NetworkDiscovery(NetworkModule):
    """Network discovery and host enumeration module"""

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__("Network Discovery", config)
        self.discovered_hosts = []
        self.ping_results = {}
        self.arp_results = {}

    def validate_requirements(self) -> bool:
        """Check if required tools are available"""
        required_tools = ["nmap"]
        optional_tools = ["ping", "fping", "arp-scan"]

        status = self._check_network_tools(required_tools + optional_tools)
        for tool, available in status.items():
            self.logger.tool_check(tool, available)

        return status.get(
            "nmap", False
        )  # не блокируемся на отсутствии ping, если есть nmap

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform network discovery scan"""
        method = kwargs.get("method", "ping_sweep")
        threads = kwargs.get("threads", 50)

        results = {
            "target": target,
            "method": method,
            "discovered_hosts": [],
            "live_hosts": [],
            "scan_summary": {},
        }

        if method == "ping_sweep":
            part = self._ping_sweep(target, threads)
        elif method == "arp_scan":
            part = self._arp_scan(target)
        elif method == "nmap_discovery":
            part = self._nmap_discovery(target)
        elif method == "comprehensive":
            part = self._comprehensive_discovery(target, threads)
        else:
            raise ValueError(f"Unknown discovery method: {method}")

        results.update(part)

        # Aggregate discovered_hosts from all methods
        agg = set()
        for method_result in results.get("method_results", {}).values():
            for host in method_result.get("live_hosts", method_result.get("hosts", [])):
                if isinstance(host, str):
                    agg.add(host)
                elif isinstance(host, dict) and "ip" in host:
                    agg.add(host["ip"])

        # Sort by IP address
        discovered = [x for x in agg if x]
        try:
            results["discovered_hosts"] = sorted(
                discovered, key=lambda x: ipaddress.ip_address(x)
            )
        except Exception:
            results["discovered_hosts"] = sorted(discovered)

        return results

    def _ping_sweep(self, target: str, threads: int) -> Dict[str, Any]:
        """Fast ping sweep with fping optimization"""
        self.logger.info(f"Starting ping sweep on {target}")
        hosts = NetworkUtils.generate_host_list(target, self.logger)
        live_hosts: List[str] = []

        # Fast path with fping
        if hosts and self._check_network_tools(["fping"]).get("fping", False):
            if validate_network(target):
                cmd = ["fping", "-a", "-A", "-q", "-g", target, "-r", "0", "-t", "200"]
            else:
                cmd = ["fping", "-a", "-A", "-q"] + hosts + ["-r", "0", "-t", "200"]

            result = run_command(cmd, timeout=60)
            if result["success"]:
                live_hosts = [
                    line.strip()
                    for line in result["stdout"].splitlines()
                    if line.strip()
                ]
            else:
                self.logger.debug(f"fping failed: {result['stderr']}")

        # Fallback - parallel ping/TCP
        if not live_hosts:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futs = {executor.submit(NetworkUtils.probe_host, h): h for h in hosts}
                for future in as_completed(futs):
                    host = futs[future]
                    try:
                        if future.result():
                            live_hosts.append(host)
                            self.logger.info(f"Host {host} is alive")
                    except Exception as e:
                        self.logger.debug(f"Error probing {host}: {e}")

        return {
            "method_results": {
                "ping_sweep": {
                    "total_hosts_scanned": len(hosts),
                    "live_hosts_found": len(live_hosts),
                    "live_hosts": live_hosts,
                }
            },
            "live_hosts": live_hosts,
            "scan_summary": {
                "total_scanned": len(hosts),
                "live_found": len(live_hosts),
                "success_rate": (
                    f"{(len(live_hosts)/len(hosts)*100):.1f}%" if hosts else "0%"
                ),
            },
        }

    def _arp_scan(self, target: str) -> Dict[str, Any]:
        """ARP scan with proper local network discovery"""
        self.logger.info(f"Starting ARP scan on {target}")
        hosts = []

        if self._check_network_tools(["arp-scan"]).get("arp-scan", False):
            # Correct usage - local network
            result = run_command(["arp-scan", "--localnet", "--quiet"], timeout=30)
            if result["success"]:
                hosts = NetworkUtils.parse_arp_scan_output(result["stdout"])

        if not hosts:
            hosts = NetworkUtils.get_arp_table()

        return {
            "method_results": {
                "arp_scan": {
                    "hosts_found": len(hosts),
                    "hosts": hosts,
                    "live_hosts": [h["ip"] for h in hosts],
                }
            },
            "live_hosts": [h["ip"] for h in hosts],
            "scan_summary": {"total_found": len(hosts), "method": "arp_scan"},
        }

    def _nmap_discovery(self, target: str) -> Dict[str, Any]:
        """Nmap discovery with grepable output parsing"""
        self.logger.info(f"Starting nmap discovery on {target}")

        cmd = [
            "nmap",
            "-sn",
            "-PE",
            "-PP",
            "-PS80,443",
            "-PA80,443",
            "-oG",
            "-",
            target,
        ]
        result = run_command(cmd, timeout=180)

        hosts = (
            NetworkUtils.parse_nmap_grepable(result["stdout"])
            if result["success"]
            else []
        )

        return {
            "method_results": {
                "nmap_discovery": {
                    "command": " ".join(cmd),
                    "hosts_found": len(hosts),
                    "hosts": [{"ip": h, "hostname": "", "status": "up"} for h in hosts],
                    "live_hosts": hosts,
                    "raw_output": (
                        result["stdout"] if result["success"] else result["stderr"]
                    ),
                }
            },
            "live_hosts": hosts,
            "scan_summary": {"total_found": len(hosts), "method": "nmap_discovery"},
        }

    def _comprehensive_discovery(self, target: str, threads: int) -> Dict[str, Any]:
        """Perform comprehensive discovery using multiple methods"""
        self.logger.info(f"Starting comprehensive discovery on {target}")

        all_hosts = set()
        results = {"method_results": {}}

        # Run ping sweep
        ping_results = self._ping_sweep(target, threads)
        results["method_results"]["ping_sweep"] = ping_results["method_results"][
            "ping_sweep"
        ]
        all_hosts.update(ping_results["live_hosts"])

        # Run ARP scan
        arp_results = self._arp_scan(target)
        results["method_results"]["arp_scan"] = arp_results["method_results"][
            "arp_scan"
        ]
        all_hosts.update(arp_results["live_hosts"])

        # Run nmap discovery
        nmap_results = self._nmap_discovery(target)
        results["method_results"]["nmap_discovery"] = nmap_results["method_results"][
            "nmap_discovery"
        ]
        all_hosts.update(nmap_results["live_hosts"])

        live_hosts = sorted(list(all_hosts), key=lambda x: ipaddress.ip_address(x))

        results.update(
            {
                "live_hosts": live_hosts,
                "scan_summary": {
                    "total_unique_hosts": len(live_hosts),
                    "methods_used": ["ping_sweep", "arp_scan", "nmap_discovery"],
                    "comprehensive": True,
                },
            }
        )

        return results
