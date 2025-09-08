"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import platform
from typing import Any, Dict, Optional

import psutil

from ..core.base import ScanConfig, SystemModule
from ..core.utils import format_bytes, run_command
from .system_utils import SystemUtils


class SystemInfo(SystemModule):
    """System information gathering and analysis module"""

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__("System Information", config)

    def validate_requirements(self) -> bool:
        """Check if required tools are available"""
        # System info module uses built-in Python modules primarily
        return True

    def scan(self, target: str = "localhost", **kwargs) -> Dict[str, Any]:
        """Gather system information"""
        scan_type = kwargs.get("scan_type", "basic")
        include_processes = kwargs.get("processes", False)
        include_network = kwargs.get("network", True)
        include_hardware = kwargs.get("hardware", True)

        results = {
            "target": target,
            "scan_type": scan_type,
            "system_info": {},
            "hardware_info": {},
            "network_info": {},
            "services": [],
            "processes": [],
            "scan_summary": {},
        }

        if scan_type == "basic":
            results.update(self._basic_system_scan(include_network, include_hardware))
        elif scan_type == "full":
            results.update(
                self._full_system_scan(
                    include_processes, include_network, include_hardware
                )
            )
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

        return results

    def _basic_system_scan(
        self, include_network: bool, include_hardware: bool
    ) -> Dict[str, Any]:
        """Perform basic system information gathering"""
        self.logger.info("Gathering basic system information")

        results = {}

        # Basic system information
        system_info = self._get_system_info()
        results["system_info"] = system_info

        # Hardware information
        if include_hardware:
            hardware_info = self._get_hardware_info()
            results["hardware_info"] = hardware_info

        # Network information
        if include_network:
            network_info = self._get_network_info()
            results["network_info"] = network_info

        # Running services
        services = SystemUtils.parse_systemctl_output("")
        if platform.system() == "Linux" and SystemUtils.has_tool("systemctl"):
            systemctl_result = run_command(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                    "--all",
                    "--full",
                ],
                timeout=30,
            )
            if systemctl_result["success"]:
                services = SystemUtils.parse_systemctl_output(
                    systemctl_result["stdout"]
                )

        results["services"] = services

        results["scan_summary"] = {
            "scan_type": "basic",
            "services_found": len(services),
            "network_interfaces": len(
                results.get("network_info", {}).get("interfaces", [])
            ),
            "include_hardware": include_hardware,
            "include_network": include_network,
        }

        return results

    def _full_system_scan(
        self, include_processes: bool, include_network: bool, include_hardware: bool
    ) -> Dict[str, Any]:
        """Perform comprehensive system information gathering"""
        self.logger.info("Gathering comprehensive system information")

        # Start with basic scan
        results = self._basic_system_scan(include_network, include_hardware)

        # Additional information for full scan
        if include_processes:
            processes = SystemUtils.get_process_list_with_cpu()
            results["processes"] = processes

        # Connected devices
        connected_devices = SystemUtils.get_connected_devices()
        results["connected_devices"] = connected_devices

        # Disk usage
        disk_usage = SystemUtils.get_filtered_disk_usage()
        results["disk_usage"] = disk_usage

        # Environment variables (filtered)
        env_vars = SystemUtils.get_safe_environment_variables()
        results["environment"] = env_vars

        results["scan_summary"].update(
            {
                "scan_type": "full",
                "processes_found": len(results.get("processes", [])),
                "connected_devices": len(connected_devices),
                "disk_partitions": len(disk_usage),
            }
        )

        return results

    def _get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        info = {
            "hostname": platform.node(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "uptime": SystemUtils.get_uptime(),
        }

        # Additional Linux-specific information
        if platform.system() == "Linux":
            try:
                with open("/etc/os-release", "r") as f:
                    os_release = {}
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            os_release[key] = value.strip('"')
                    info["linux_distribution"] = os_release.get("NAME", "Unknown")
                    info["linux_version"] = os_release.get("VERSION", "Unknown")
            except Exception:
                pass

        return info

    def _get_hardware_info(self) -> Dict[str, Any]:
        """Get hardware information"""
        info = {
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "cpu_freq": dict(psutil.cpu_freq()._asdict()) if psutil.cpu_freq() else {},
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent,
                "used": psutil.virtual_memory().used,
                "free": psutil.virtual_memory().free,
            },
            "swap": {
                "total": psutil.swap_memory().total,
                "used": psutil.swap_memory().used,
                "free": psutil.swap_memory().free,
                "percent": psutil.swap_memory().percent,
            },
        }

        # Format memory sizes
        for key in ["total", "available", "used", "free"]:
            if key in info["memory"]:
                info["memory"][f"{key}_formatted"] = format_bytes(info["memory"][key])

        for key in ["total", "used", "free"]:
            if key in info["swap"]:
                info["swap"][f"{key}_formatted"] = format_bytes(info["swap"][key])

        return info

    def _get_network_info(self) -> Dict[str, Any]:
        """Get network information with normalized addresses"""
        info = {"interfaces": [], "connections": [], "stats": {}}

        # Network interfaces with proper address normalization
        for ifname, addrs in psutil.net_if_addrs().items():
            iface = {"name": ifname, "addresses": []}
            for addr in addrs:
                iface["addresses"].append(
                    {
                        "family": SystemUtils.fam_name(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "prefixlen": SystemUtils.prefix_len(addr.address, addr.netmask),
                        "broadcast": addr.broadcast,
                    }
                )
            info["interfaces"].append(iface)

        # Per-interface statistics + totals
        try:
            per_interface = psutil.net_io_counters(pernic=True)
            total_stats = psutil.net_io_counters()

            info["stats"]["total"] = {
                "bytes_sent": total_stats.bytes_sent,
                "bytes_recv": total_stats.bytes_recv,
                "packets_sent": total_stats.packets_sent,
                "packets_recv": total_stats.packets_recv,
                "bytes_sent_formatted": format_bytes(total_stats.bytes_sent),
                "bytes_recv_formatted": format_bytes(total_stats.bytes_recv),
            }

            info["stats"]["per_interface"] = {
                k: {
                    "bytes_sent": v.bytes_sent,
                    "bytes_recv": v.bytes_recv,
                    "packets_sent": v.packets_sent,
                    "packets_recv": v.packets_recv,
                }
                for k, v in per_interface.items()
            }
        except Exception:
            pass

        # Active connections (limited to 50)
        try:
            connections = psutil.net_connections(kind="inet")[:50]
            for conn in connections:
                info["connections"].append(
                    {
                        "family": SystemUtils.fam_name(conn.family),
                        "type": str(conn.type),
                        "local_address": (
                            f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                        ),
                        "remote_address": (
                            f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                        ),
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
        except Exception:
            pass

        return info
