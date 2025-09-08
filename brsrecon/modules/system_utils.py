"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import ipaddress
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from ..core.utils import format_bytes, run_command


class SystemUtils:
    """System information utility functions"""

    @staticmethod
    def get_uptime() -> Dict[str, Any]:
        """Get system uptime with proper time handling"""
        try:
            boot_ts = psutil.boot_time()
            now = time.time()
            up = max(0, now - boot_ts)
            days = int(up // 86400)
            hours = int((up % 86400) // 3600)
            minutes = int((up % 3600) // 60)

            return {
                "boot_time_epoch": boot_ts,
                "boot_time_iso": datetime.fromtimestamp(
                    boot_ts, tz=timezone.utc
                ).isoformat(),
                "uptime_seconds": up,
                "uptime_formatted": f"{days}d {hours}h {minutes}m",
            }
        except Exception:
            return {}

    @staticmethod
    def fam_name(fam) -> str:
        """Get human-readable family name"""
        if fam == socket.AF_INET:
            return "IPv4"
        if fam == socket.AF_INET6:
            return "IPv6"
        try:
            if fam == psutil.AF_LINK:
                return "MAC"
        except Exception:
            pass
        return str(fam)

    @staticmethod
    def prefix_len(addr: str, netmask: Optional[str]) -> Optional[int]:
        """Calculate prefix length from netmask"""
        try:
            if not netmask:
                return None
            net = ipaddress.ip_network(f"{addr}/{netmask}", strict=False)
            return net.prefixlen
        except Exception:
            return None

    @staticmethod
    def has_tool(tool: str) -> bool:
        """Check if tool is available"""
        try:
            return run_command(["which", tool], timeout=2)["returncode"] == 0
        except Exception:
            return False

    @staticmethod
    def get_process_list_with_cpu() -> List[Dict[str, Any]]:
        """Get process list with proper CPU percent calculation"""
        processes: List[Dict[str, Any]] = []

        try:
            # Warm up cpu_percent (first call always returns 0.0)
            for proc in psutil.process_iter(["pid", "name", "username"]):
                try:
                    proc.cpu_percent(None)
                except Exception:
                    pass

            # Small delay for accurate CPU measurement
            time.sleep(0.1)

            # Get actual CPU percentages
            for proc in psutil.process_iter(
                ["pid", "name", "username", "memory_percent"]
            ):
                try:
                    processes.append(
                        {
                            "pid": proc.pid,
                            "name": proc.info["name"],
                            "username": proc.info.get("username") or "",
                            "cpu_percent": proc.cpu_percent(None),
                            "memory_percent": proc.info.get("memory_percent") or 0.0,
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Sort by CPU usage and limit to top 50
            processes.sort(key=lambda x: x["cpu_percent"] or 0, reverse=True)
            return processes[:50]

        except Exception:
            return processes

    @staticmethod
    def get_filtered_disk_usage() -> List[Dict[str, Any]]:
        """Get disk usage filtering out pseudo-filesystems and loops"""
        disk_usage = []
        skip_fstypes = {
            "tmpfs",
            "devtmpfs",
            "proc",
            "sysfs",
            "cgroup2",
            "overlay",
            "squashfs",
            "autofs",
            "nsfs",
            "tracefs",
            "debugfs",
            "fusectl",
        }

        try:
            for partition in psutil.disk_partitions(all=False):
                if not partition.fstype or partition.fstype in skip_fstypes:
                    continue
                if partition.mountpoint.startswith(("/snap", "/run")):
                    continue

                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage.append(
                        {
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total": usage.total,
                            "used": usage.used,
                            "free": usage.free,
                            "percent": (
                                (usage.used / usage.total * 100) if usage.total else 0
                            ),
                            "total_formatted": format_bytes(usage.total),
                            "used_formatted": format_bytes(usage.used),
                            "free_formatted": format_bytes(usage.free),
                        }
                    )
                except PermissionError:
                    continue
        except Exception:
            pass

        return disk_usage

    @staticmethod
    def get_safe_environment_variables() -> Dict[str, str]:
        """Get filtered environment variables"""
        safe_vars = [
            "PATH",
            "HOME",
            "USER",
            "SHELL",
            "TERM",
            "LANG",
            "LC_ALL",
            "PWD",
            "HOSTNAME",
            "XDG_RUNTIME_DIR",
        ]

        import os

        return {var: os.environ[var] for var in safe_vars if var in os.environ}

    @staticmethod
    def parse_systemctl_output(output: str) -> List[Dict[str, Any]]:
        """Parse systemctl list-units output with robust parsing"""
        services = []

        for line in output.splitlines():
            line = line.strip()
            if not line or ".service" not in line:
                continue

            # UNIT LOAD ACTIVE SUB DESCRIPTION
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append(
                    {
                        "name": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4] if len(parts) == 5 else "",
                        "type": "systemd_service",
                    }
                )

        return services

    @staticmethod
    def get_connected_devices() -> List[Dict[str, Any]]:
        """Get information about connected devices (only if tools available)"""
        devices: List[Dict[str, Any]] = []

        if platform.system() == "Linux":
            if SystemUtils.has_tool("lsusb"):
                result = run_command(["lsusb"], timeout=10)
                if result["success"]:
                    devices += [
                        {"type": "usb", "info": line.strip()}
                        for line in result["stdout"].splitlines()
                        if line.strip()
                    ]

            if SystemUtils.has_tool("lspci"):
                result = run_command(["lspci"], timeout=10)
                if result["success"]:
                    devices += [
                        {"type": "pci", "info": line.strip()}
                        for line in result["stdout"].splitlines()[:20]
                        if line.strip()
                    ]

        return devices
