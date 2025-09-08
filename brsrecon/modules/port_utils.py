"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import errno
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

from ..core.utils import parse_nmap_ports


class PortUtils:
    """Port scanning utility functions"""

    @staticmethod
    def get_common_ports() -> List[int]:
        """Get list of common ports"""
        return [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            993,
            995,
            1723,
            3306,
            3389,
            5432,
            5900,
            8080,
        ]

    @staticmethod
    def get_top_ports(count: int) -> List[int]:
        """Get top N most common ports with dedup and sorting"""
        top = [
            80,
            443,
            22,
            21,
            25,
            23,
            53,
            110,
            139,
            445,
            135,
            143,
            993,
            995,
            3306,
            3389,
            5432,
            6379,
            27017,
            8080,
            8443,
            8000,
            8008,
            8081,
            111,
            2049,
            5900,
            5901,
            465,
            587,
            514,
            389,
            636,
            1521,
            1110,
            9100,
            10000,
            8888,
            123,
            161,
            162,
        ]
        # Dedup and sort
        return list(dict.fromkeys(top))[:count]

    @staticmethod
    def parse_port_specification(ports: str, logger) -> List[int]:
        """Parse port specification into list of ports"""
        if ports == "common":
            return PortUtils.get_common_ports()
        elif ports == "all":
            return list(range(1, 65536))
        elif ports == "top100":
            return PortUtils.get_top_ports(100)
        elif ports == "top1000":
            return PortUtils.get_top_ports(1000)
        else:
            # Try to parse as nmap-style port specification
            try:
                return parse_nmap_ports(ports)
            except Exception:
                logger.warning(
                    f"Invalid port specification: {ports}, using common ports"
                )
                return PortUtils.get_common_ports()

    @staticmethod
    def tcp_connect(
        host: str, port: int, timeout: float = 3.0
    ) -> Tuple[str, Optional[str]]:
        """Tri-state TCP connect with IPv6 support"""
        try:
            for fam, socktype, proto, _, sa in socket.getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            ):
                s = socket.socket(fam, socktype, proto)
                s.settimeout(timeout)
                try:
                    rc = s.connect_ex(sa)
                finally:
                    s.close()

                if rc == 0:
                    return "open", None
                if rc in (errno.ECONNREFUSED, 111, 61, 10061):
                    return "closed", None
                if rc in (errno.ETIMEDOUT, 110, 60, 10060):
                    return "filtered", "timeout"
                # Other errors - consider filtered
                return "filtered", str(rc)
        except socket.timeout:
            return "filtered", "timeout"
        except Exception as e:
            return "closed", str(e)

    @staticmethod
    def detect_service(host: str, port: int) -> Optional[Dict[str, str]]:
        """Enhanced service detection with TLS and HTTP HEAD"""
        info = {"port": port, "service": "unknown", "banner": ""}

        try:
            # TLS handshake for HTTPS ports
            if port in (443, 8443, 9443):
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), 3) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as ss:
                        cert = ss.getpeercert() or {}
                        info["service"] = "HTTPS"
                        info["tls_subject"] = dict(
                            x[0] for x in cert.get("subject", [])
                        ).get("commonName", "")
                        info["tls_issuer"] = dict(
                            x[0] for x in cert.get("issuer", [])
                        ).get("commonName", "")
                return info

            # HTTP HEAD request
            if port in (80, 8080, 8000, 8008, 8081):
                req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: BRS-RECON\r\n\r\n".encode()
                with socket.create_connection((host, port), 3) as s:
                    s.sendall(req)
                    data = s.recv(2048).decode("utf-8", "ignore")
                info["banner"] = data.split("\r\n\r\n", 1)[0]
                info["service"] = "HTTP"
                return info

            # Banner grabbing for other services
            with socket.create_connection((host, port), 3) as s:
                try:
                    s.sendall(b"\r\n")
                    data = s.recv(1024).decode("utf-8", "ignore").strip()
                except Exception:
                    data = ""

                info["banner"] = data
                if "SSH" in data:
                    info["service"] = "SSH"
                elif "FTP" in data:
                    info["service"] = "FTP"
                elif "SMTP" in data or "ESMTP" in data:
                    info["service"] = "SMTP"

                return info

        except Exception:
            return info

    @staticmethod
    def format_port_list(ports: List[int]) -> str:
        """Format ports as compact ranges without losing gaps"""
        if not ports:
            return ""

        xs = sorted(set(p for p in ports if 1 <= p <= 65535))
        ranges = []
        start = prev = xs[0]

        for p in xs[1:]:
            if p == prev + 1:
                prev = p
                continue
            ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
            start = prev = p

        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        return ",".join(ranges)

    @staticmethod
    def parse_nmap_output(output: str) -> Dict[str, Any]:
        """Parse nmap scan output"""
        results = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
        }

        for line in output.split("\n"):
            line = line.strip()

            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_info = parts[0]
                    state = parts[1]

                    try:
                        port = int(port_info.split("/")[0])

                        if state == "open":
                            results["open_ports"].append(port)

                            # Extract service info if available
                            if len(parts) >= 3:
                                service = parts[2] if parts[2] != "unknown" else ""
                                version = " ".join(parts[3:]) if len(parts) > 3 else ""

                                results["services"][port] = {
                                    "service": service,
                                    "version": version,
                                    "state": state,
                                }

                        elif state == "closed":
                            results["closed_ports"].append(port)
                        elif state == "filtered":
                            results["filtered_ports"].append(port)

                    except ValueError:
                        continue

        return results
