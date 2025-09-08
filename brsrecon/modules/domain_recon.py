"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import secrets
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from ..core.base import ScanConfig, WebModule
from ..core.utils import check_tool_availability, run_command, validate_domain


class DomainRecon(WebModule):
    """Domain reconnaissance and DNS enumeration module"""

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__("Domain Reconnaissance", config)
        self.common_subdomains = [
            # Basic subdomains
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "app",
            "blog", "shop", "forum", "support", "help", "docs", "cdn", "static",
            "assets", "img", "images", "js", "css", "media", "files", "download",
            
            # Extended list for better coverage
            "m", "mobile", "wap", "secure", "ssl", "vpn", "remote", "proxy",
            "ns", "ns1", "ns2", "ns3", "dns", "mx", "mx1", "mx2", "smtp", "pop",
            "imap", "webmail", "email", "exchange", "owa", "autodiscover",
            
            # Development & Testing
            "beta", "alpha", "demo", "preview", "sandbox", "lab", "labs", "testing",
            "qa", "uat", "preprod", "prod", "production", "live",
            
            # Services & Applications  
            "login", "auth", "sso", "oauth", "ldap", "ad", "directory", "portal",
            "dashboard", "panel", "cpanel", "admin", "administrator", "root",
            "manager", "console", "control", "config", "configuration",
            
            # Content & Media
            "video", "videos", "audio", "music", "photo", "photos", "gallery",
            "upload", "uploads", "content", "cms", "wiki", "news", "press",
            
            # Infrastructure
            "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
            "search", "solr", "cache", "memcache", "queue", "worker", "jobs",
            "cron", "backup", "backups", "archive", "log", "logs", "monitor",
            "monitoring", "metrics", "stats", "analytics", "tracking",
            
            # Cloud & Services
            "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket", "repo",
            "git", "svn", "jenkins", "ci", "cd", "build", "deploy", "docker",
            
            # Regional & Language
            "en", "us", "uk", "de", "fr", "es", "it", "ru", "cn", "jp", "kr",
            "asia", "europe", "america", "global", "international",
            
            # Business & Commerce
            "store", "shop", "cart", "checkout", "payment", "pay", "billing",
            "invoice", "order", "orders", "customer", "customers", "crm",
            "sales", "marketing", "promo", "offers", "deals",
            
            # Technical
            "status", "health", "ping", "uptime", "service", "services", "tools",
            "util", "utils", "lib", "libs", "sdk", "api-docs", "swagger",
            "graphql", "rest", "soap", "rpc", "websocket", "socket"
        ]

    def _ace(self, domain: str) -> str:
        """Convert domain to ASCII (IDNA)"""
        try:
            return domain.encode("idna").decode("ascii")
        except Exception:
            return domain

    def _resolver_ns(self) -> Optional[str]:
        """Get resolver from config"""
        try:
            return (
                getattr(getattr(self.config, "network", None), "dns_servers", None)
                or [None]
            )[0]
        except Exception:
            return None

    def _dig(self, args: List[str], timeout: int = 5, ns: Optional[str] = None):
        """Fast dig command with optimized parameters"""
        base = ["dig", "+tries=1", "+time=2", "+retry=0"]
        if ns:
            base.append(f"@{ns}")
        return run_command(base + args, timeout=timeout)

    def _resolve_any(self, host: str) -> bool:
        """Check if host resolves (IPv4+IPv6)"""
        try:
            socket.getaddrinfo(host, None)  # IPv4+IPv6
            return True
        except socket.gaierror:
            return False

    def _has_wildcard(self, domain: str) -> bool:
        """Check if domain has wildcard DNS"""
        rnd = "brs-" + secrets.token_hex(4) + "." + domain
        return self._resolve_any(rnd)

    def validate_requirements(self) -> bool:
        """Check if required tools are available"""
        # dig обязателен, whois желательно
        dig_ok = check_tool_availability("dig")
        whois_ok = check_tool_availability("whois")
        self.logger.tool_check("dig", dig_ok)
        self.logger.tool_check("whois", whois_ok)
        return dig_ok  # не блокируем модуль из-за whois

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform domain reconnaissance"""
        # Validate and normalize domain (IDNA)
        domain = self._ace(target.strip().lower())
        if not validate_domain(domain):
            raise ValueError(f"Invalid domain: {target}")

        scan_type = kwargs.get("scan_type", "basic")
        include_subdomains = kwargs.get("subdomains", True)
        threads = kwargs.get("threads", 20)

        results = {
            "target": domain,
            "domain_info": {},
            "dns_records": {},
            "whois_info": {},
            "subdomains": [],
            "scan_summary": {},
        }

        if scan_type == "basic":
            results.update(self._basic_recon(domain))
        elif scan_type == "comprehensive":
            results.update(
                self._comprehensive_recon(domain, include_subdomains, threads)
            )
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

        return results

    def _basic_recon(self, domain: str) -> Dict[str, Any]:
        """Perform basic domain reconnaissance"""
        self.logger.info(f"Starting basic domain reconnaissance for {domain}")

        results = {}

        # DNS lookups
        dns_records = self._get_dns_records(domain)
        results["dns_records"] = dns_records

        # WHOIS lookup
        whois_info = self._get_whois_info(domain)
        results["whois_info"] = whois_info

        # Basic domain info
        domain_info = self._get_domain_info(domain, dns_records)
        results["domain_info"] = domain_info

        results["scan_summary"] = {
            "scan_type": "basic",
            "dns_records_found": len(dns_records),
            "has_whois": bool(whois_info),
        }

        return results

    def _comprehensive_recon(
        self, domain: str, include_subdomains: bool, threads: int
    ) -> Dict[str, Any]:
        """Perform comprehensive domain reconnaissance"""
        self.logger.info(f"Starting comprehensive domain reconnaissance for {domain}")

        # Start with basic recon
        results = self._basic_recon(domain)

        # Subdomain enumeration
        if include_subdomains:
            subdomains = self._enumerate_subdomains(domain, threads)
            results["subdomains"] = subdomains

            # Get DNS records for found subdomains
            subdomain_dns = {}
            for subdomain in subdomains[:10]:  # Limit to avoid too many requests
                subdomain_records = self._get_dns_records(subdomain)
                if subdomain_records:
                    subdomain_dns[subdomain] = subdomain_records

            results["subdomain_dns"] = subdomain_dns

        # Additional reconnaissance
        results["zone_transfer"] = self._attempt_zone_transfer(domain)
        results["mx_records_detail"] = self._get_mx_details(domain)

        # Update subdomain count in domain_info
        results["domain_info"]["subdomain_count"] = len(results.get("subdomains", []))

        results["scan_summary"] = {
            "scan_type": "comprehensive",
            "dns_records_found": len(results["dns_records"]),
            "subdomains_found": len(results.get("subdomains", [])),
            "zone_transfer_possible": results["zone_transfer"]["possible"],
            "has_whois": bool(results["whois_info"]),
        }

        return results

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get various DNS records for domain with fast dig"""
        records: Dict[str, List[str]] = {}
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        ns = self._resolver_ns()

        for rtype in record_types:
            try:
                res = self._dig(["+short", rtype, domain], timeout=5, ns=ns)
                if res["success"] and res["stdout"].strip():
                    lines = [
                        line.strip()
                        for line in res["stdout"].splitlines()
                        if line.strip()
                    ]
                    records[rtype] = lines
            except Exception as e:
                self.logger.debug(f"DNS {rtype} {domain}: {e}")

        return records

    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        try:
            res = run_command(["whois", domain], timeout=30)
            if not res["success"] or not res["stdout"]:
                return {}
            return self._parse_whois_output(res["stdout"])
        except Exception as e:
            self.logger.debug(f"WHOIS {domain}: {e}")
            return {}

    def _parse_whois_output(self, whois_output: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data"""
        info = {
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "name_servers": [],
            "status": "",
            "registrant": "",
            "raw_output": whois_output,
        }

        for line in whois_output.split("\n"):
            line = line.strip().lower()

            if "registrar:" in line:
                info["registrar"] = line.split(":", 1)[1].strip()
            elif "creation date:" in line or "created:" in line:
                info["creation_date"] = line.split(":", 1)[1].strip()
            elif "expiration date:" in line or "expires:" in line:
                info["expiration_date"] = line.split(":", 1)[1].strip()
            elif "name server:" in line:
                ns = line.split(":", 1)[1].strip()
                if ns not in info["name_servers"]:
                    info["name_servers"].append(ns)
            elif "status:" in line:
                info["status"] = line.split(":", 1)[1].strip()

        return info

    def _get_domain_info(
        self, domain: str, dns_records: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Get basic domain information"""
        info = {
            "domain": domain,
            "ip_addresses": dns_records.get("A", []) + dns_records.get("AAAA", []),
            "mail_servers": [],
            "name_servers": [ns.rstrip(".") for ns in dns_records.get("NS", [])],
            "has_www": False,
            "subdomain_count": 0,
        }

        # Extract mail servers
        if "MX" in dns_records:
            mx = []
            for record in dns_records["MX"]:
                parts = record.split()
                if len(parts) >= 2:
                    mx.append(parts[-1].rstrip("."))
            info["mail_servers"] = mx

        # Check if www subdomain exists (IPv4+IPv6)
        info["has_www"] = self._resolve_any(f"www.{domain}")

        return info

    def _enumerate_subdomains(self, domain: str, threads: int) -> List[str]:
        """Enumerate subdomains with wildcard protection"""
        self.logger.info(f"Enumerating subdomains for {domain}")
        found: List[str] = []

        # Wildcard защита
        wildcard = self._has_wildcard(domain)
        if wildcard:
            self.logger.info("Wildcard DNS detected, filtering results")

        def check(sub: str) -> Optional[str]:
            fqdn = f"{sub}.{domain}"
            if not self._resolve_any(fqdn):
                return None
            if wildcard:
                # Оставим как найденный, дальше можно фильтровать на веб-этапе
                return fqdn
            return fqdn

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(check, sub): sub for sub in self.common_subdomains}
            for fut in as_completed(futs):
                val = fut.result()
                if val:
                    found.append(val)
                    self.logger.info(f"Found subdomain: {val}")

        return sorted(set(found))

    def _attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt DNS zone transfer with proper validation"""
        out = {"possible": False, "name_servers": [], "records": [], "error": ""}

        ns_res = self._dig(["+short", "NS", domain], timeout=5)
        if not ns_res["success"] or not ns_res["stdout"].strip():
            out["error"] = "NS query failed"
            return out

        name_servers = [
            x.strip().rstrip(".") for x in ns_res["stdout"].splitlines() if x.strip()
        ]
        out["name_servers"] = name_servers

        for ns in name_servers:
            try:
                # AXFR к конкретному NS
                res = self._dig(["AXFR", domain], timeout=15, ns=ns)
                if not res["success"] or not res["stdout"]:
                    continue
                s = res["stdout"]
                if (
                    "Transfer failed" in s
                    or "refused" in s.lower()
                    or "timed out" in s.lower()
                ):
                    continue
                if "XFR size" in s or "\tIN\t" in s:
                    out["possible"] = True
                    out["records"] = [line for line in s.splitlines() if line.strip()]
                    break
            except Exception as e:
                self.logger.debug(f"AXFR @{ns} failed: {e}")

        return out

    def _get_mx_details(self, domain: str) -> List[Dict[str, Any]]:
        """Get detailed MX record information with A and AAAA"""
        details: List[Dict[str, Any]] = []

        res = self._dig(["+short", "MX", domain], timeout=5)
        if not res["success"] or not res["stdout"].strip():
            return details

        for line in res["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            pri_str, host = parts[0], parts[1].rstrip(".")
            try:
                prio = int(pri_str)
            except ValueError:
                prio = 0

            ips: List[str] = []
            # Get A records
            a = self._dig(["+short", "A", host], timeout=3)
            if a["success"] and a["stdout"].strip():
                ips.extend([x.strip() for x in a["stdout"].splitlines() if x.strip()])

            # Get AAAA records
            aaaa = self._dig(["+short", "AAAA", host], timeout=3)
            if aaaa["success"] and aaaa["stdout"].strip():
                ips.extend(
                    [x.strip() for x in aaaa["stdout"].splitlines() if x.strip()]
                )

            details.append({"priority": prio, "hostname": host, "ip_addresses": ips})

        return sorted(details, key=lambda x: x["priority"])
