"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import ipaddress
import json
import re
import socket
from typing import Dict, List

from ..core.utils import run_command


class NetworkUtils:
    """Network discovery utility functions"""

    @staticmethod
    def parse_nmap_grepable(output: str) -> List[str]:
        """Parse nmap grepable output for live hosts"""
        live = []
        for line in output.splitlines():
            if line.startswith("Host:") and "Status: Up" in line:
                match = re.search(r"Host:\s+([0-9a-fA-F\.:]+)", line)
                if match:
                    live.append(match.group(1))
        return live

    @staticmethod
    def parse_arp_scan_output(output: str) -> List[Dict[str, str]]:
        """Parse arp-scan output"""
        hosts = []
        for line in output.split("\n"):
            if "\t" in line and not line.startswith("Interface:"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    hosts.append(
                        {
                            "ip": parts[0].strip(),
                            "mac": parts[1].strip(),
                            "vendor": parts[2].strip() if len(parts) > 2 else "",
                        }
                    )
        return hosts

    @staticmethod
    def get_arp_table() -> List[Dict[str, str]]:
        """Get system ARP table with ip neigh fallback"""
        hosts = []

        # Prefer ip neigh (modern)
        result = run_command(["ip", "-j", "neigh", "show"], timeout=5)
        if result["success"] and result["stdout"].strip():
            try:
                data = json.loads(result["stdout"])
                for entry in data:
                    if entry.get("state") in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                        if "lladdr" in entry and "dst" in entry:
                            hosts.append(
                                {
                                    "ip": entry["dst"],
                                    "mac": entry["lladdr"],
                                    "vendor": "",
                                }
                            )
            except Exception:
                pass

        if hosts:
            return hosts

        # Fallback to arp -a
        result = run_command(["arp", "-a"], timeout=5)
        if result["success"]:
            for line in result["stdout"].splitlines():
                if "(" in line and ")" in line:
                    try:
                        ip = line.split("(")[1].split(")")[0]
                        mac = line.split(" at ")[1].split()[0]
                        hosts.append({"ip": ip, "mac": mac, "vendor": ""})
                    except Exception:
                        continue

        return hosts

    @staticmethod
    def probe_host(host: str) -> bool:
        """Probe host with ICMP and TCP fallback (IPv4+IPv6 support)"""
        # ICMP ping
        try:
            ip = ipaddress.ip_address(host)
            ping_cmd = ["ping", "-n", "-c", "1", "-W", "1", host]
            if ip.version == 6:
                ping_cmd = ["ping", "-6", "-n", "-c", "1", "-W", "1", host]

            result = run_command(ping_cmd, timeout=3)
            if result["success"] and result["returncode"] == 0:
                return True
        except Exception:
            pass

        # TCP connect fallback on common ports
        for port in (80, 443, 22):
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return True
            except Exception:
                continue

        return False

    @staticmethod
    def generate_host_list(target: str, logger) -> List[str]:
        """Generate sorted list of hosts to scan with size limits"""
        from ..core.utils import validate_ip, validate_network

        hosts: List[str] = []

        if validate_ip(target):
            return [target]

        if validate_network(target):
            try:
                net = ipaddress.ip_network(target, strict=False)
                max_hosts = 4096

                if net.num_addresses > max_hosts:
                    logger.warning(
                        f"Network {target} is large ({net.num_addresses}). Limiting to first {max_hosts}."
                    )
                    hosts = [str(ip) for _, ip in zip(range(max_hosts), net.hosts())]
                else:
                    hosts = [str(ip) for ip in net.hosts()]
            except ValueError:
                logger.error(f"Invalid network: {target}")

        return hosts
