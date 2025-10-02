"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import argparse
import sys
from typing import Optional  # noqa: F401

from .commands import BRSCommands
from .core.config import get_config
from .core.logger import get_logger, setup_logging
from .modules.domain_recon import DomainRecon
from .modules.network_discovery import NetworkDiscovery
from .modules.port_scanning import PortScanning
from .modules.system_info import SystemInfo
from .modules.vulnerability import VulnerabilityScanner


class BRSRecon:
    """Main BRS-RECON application class"""

    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.commands = BRSCommands()
        self.modules = {
            "network": NetworkDiscovery(),
            "ports": PortScanning(),
            "domain": DomainRecon(),
            "vuln": VulnerabilityScanner(),
            "system": SystemInfo(),
        }

    def run_network_discovery(
        self, target: str, method: str = "ping_sweep", threads: int = 50
    ):
        """Run network discovery scan"""
        self.logger.banner("Network Discovery")

        module = self.modules["network"]
        result = module.run_scan(target, method=method, threads=threads)

        if result.status == "completed":
            live_hosts = result.data.get("live_hosts", [])
            self.logger.success(
                f"Network discovery completed - {len(live_hosts)} hosts found"
            )

            if live_hosts:
                self.logger.info("Live hosts:")
                for host in live_hosts[:10]:  # Show first 10
                    self.logger.info(f"  - {host}")
                if len(live_hosts) > 10:
                    self.logger.info(f"  ... and {len(live_hosts) - 10} more hosts")
        else:
            self.logger.error(f"Network discovery failed: {result.error}")

        return result

    def run_port_scan(
        self,
        target: str,
        ports: str = "common",
        scan_type: str = "tcp",
        threads: int = 100,
        service_detection: bool = False,
    ):
        """Run port scanning"""
        self.logger.banner("Port Scanning")

        module = self.modules["ports"]
        result = module.run_scan(
            target,
            ports=ports,
            scan_type=scan_type,
            threads=threads,
            service_detection=service_detection,
        )

        if result.status == "completed":
            open_ports = result.data.get("open_ports", [])
            self.logger.success(
                f"Port scan completed - {len(open_ports)} open ports found"
            )

            if open_ports:
                self.logger.info("Open ports:")
                for port in open_ports:
                    service_info = result.data.get("services", {}).get(port, {})
                    service = service_info.get("service", "unknown")
                    self.logger.info(f"  - {port}/tcp ({service})")
        else:
            self.logger.error(f"Port scan failed: {result.error}")

        return result

    def run_domain_recon(
        self,
        domain: str,
        scan_type: str = "basic",
        subdomains: bool = True,
        threads: int = 20,
    ):
        """Run domain reconnaissance"""
        self.logger.banner("Domain Reconnaissance")

        module = self.modules["domain"]
        result = module.run_scan(
            domain, scan_type=scan_type, subdomains=subdomains, threads=threads
        )

        if result.status == "completed":
            dns_records = result.data.get("dns_records", {})
            found_subdomains = result.data.get("subdomains", [])

            self.logger.success("Domain reconnaissance completed")
            self.logger.info(f"DNS records found: {len(dns_records)}")

            if found_subdomains:
                self.logger.info(f"Subdomains found: {len(found_subdomains)}")
                for subdomain in found_subdomains[:5]:
                    self.logger.info(f"  - {subdomain}")
                if len(found_subdomains) > 5:
                    self.logger.info(f"  ... and {len(found_subdomains) - 5} more")
        else:
            self.logger.error(f"Domain reconnaissance failed: {result.error}")

        return result

    def show_banner(self):
        """Show application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           BRS-RECON v0.0.2                                   ║
║                    Network Reconnaissance Tool                               ║
║                                                                              ║
║                        EasyProTech LLC                                       ║
║                   https://t.me/EasyProTech                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def show_help(self):
        """Show help information"""
        help_text = """
BRS-RECON - Network Reconnaissance Tool

USAGE:
    brs-recon <command> <target> [options]

COMMANDS:
    network     Network discovery and host enumeration
    ports       Port scanning and service detection
    domain      Domain reconnaissance and DNS enumeration

EXAMPLES:
    brs-recon network 192.168.1.0/24
    brs-recon ports 192.168.1.1 --ports common
    brs-recon domain example.com --subdomains

For detailed help on a specific command:
    brs-recon <command> --help
        """
        print(help_text)


def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="BRS-RECON - Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="BRS-RECON 0.0.2")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Network discovery command
    network_parser = subparsers.add_parser("network", help="Network discovery")
    network_parser.add_argument("target", help="Target network (e.g., 192.168.1.0/24)")
    network_parser.add_argument(
        "--method",
        choices=["ping_sweep", "arp_scan", "nmap_discovery", "comprehensive"],
        default="ping_sweep",
        help="Discovery method",
    )
    network_parser.add_argument(
        "--threads", type=int, default=50, help="Number of threads"
    )
    network_parser.add_argument(
        "--max-hosts", type=int, default=4096, help="Maximum hosts to scan"
    )

    # Port scanning command
    ports_parser = subparsers.add_parser("ports", help="Port scanning")
    ports_parser.add_argument("target", help="Target host or IP")
    ports_parser.add_argument(
        "--ports",
        default="common",
        help="Ports to scan (common, top100, top1000, all, or custom range)",
    )
    ports_parser.add_argument(
        "--scan-type",
        choices=["tcp", "udp", "syn", "comprehensive"],
        default="tcp",
        help="Scan type",
    )
    ports_parser.add_argument(
        "--threads", type=int, default=100, help="Number of threads"
    )
    ports_parser.add_argument(
        "--service-detection", action="store_true", help="Enable service detection"
    )
    ports_parser.add_argument(
        "--max-ports", type=int, default=65535, help="Maximum ports to scan"
    )
    ports_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL verification (WARNING: insecure)",
    )

    # Domain reconnaissance command
    domain_parser = subparsers.add_parser("domain", help="Domain reconnaissance")
    domain_parser.add_argument("target", help="Target domain")
    domain_parser.add_argument(
        "--scan-type",
        choices=["basic", "comprehensive"],
        default="basic",
        help="Scan type",
    )
    domain_parser.add_argument(
        "--no-subdomains", action="store_true", help="Disable subdomain enumeration"
    )
    domain_parser.add_argument(
        "--threads", type=int, default=20, help="Number of threads"
    )

    # Vulnerability scanning command
    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability assessment")
    vuln_parser.add_argument("target", help="Target host, IP, or URL")
    vuln_parser.add_argument(
        "--scan-type",
        choices=["basic", "comprehensive", "web_only"],
        default="basic",
        help="Scan type",
    )
    vuln_parser.add_argument(
        "--no-web", action="store_true", help="Disable web vulnerability scan"
    )
    vuln_parser.add_argument(
        "--no-ssl", action="store_true", help="Disable SSL vulnerability scan"
    )
    vuln_parser.add_argument(
        "--aggressive", action="store_true", help="Enable aggressive scanning"
    )

    # System information command
    system_parser = subparsers.add_parser("system", help="System information")
    system_parser.add_argument(
        "--target", default="localhost", help="Target system (default: localhost)"
    )
    system_parser.add_argument(
        "--scan-type", choices=["basic", "full"], default="basic", help="Scan type"
    )
    system_parser.add_argument(
        "--processes", action="store_true", help="Include process list"
    )
    system_parser.add_argument(
        "--no-network", action="store_true", help="Disable network info"
    )
    system_parser.add_argument(
        "--no-hardware", action="store_true", help="Disable hardware info"
    )

    # Export command
    export_parser = subparsers.add_parser(
        "export", help="Export results in multiple formats"
    )
    export_parser.add_argument("scan_file", help="Path to scan result JSON file")
    export_parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "html", "sarif", "xml", "csv"],
        default=["html"],
        help="Export formats",
    )

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)

    # Initialize application
    app = BRSRecon()

    if not args.command:
        app.show_banner()
        app.show_help()
        return 0

    try:
        if args.command == "network":
            app.run_network_discovery(
                args.target, method=args.method, threads=args.threads
            )

        elif args.command == "ports":
            app.run_port_scan(
                args.target,
                ports=args.ports,
                scan_type=args.scan_type,
                threads=args.threads,
                service_detection=args.service_detection,
            )

        elif args.command == "domain":
            app.run_domain_recon(
                args.target,
                scan_type=args.scan_type,
                subdomains=not args.no_subdomains,
                threads=args.threads,
            )

        elif args.command == "vuln":
            app.commands.run_vulnerability_scan(
                args.target,
                scan_type=args.scan_type,
                web_scan=not args.no_web,
                ssl_scan=not args.no_ssl,
                aggressive=args.aggressive,
            )

        elif args.command == "system":
            app.commands.run_system_info_scan(
                args.target,
                scan_type=args.scan_type,
                processes=args.processes,
                network=not args.no_network,
                hardware=not args.no_hardware,
            )

        elif args.command == "export":
            from .core.results import ResultsManager

            results_manager = ResultsManager()

            # Load scan result
            scan_result = results_manager.load_scan_result(args.scan_file)
            if scan_result:
                exported_files = results_manager.export_multi_format(
                    scan_result, args.formats
                )
                app.logger.success(f"Exported to {len(exported_files)} formats")
                for fmt, filepath in exported_files.items():
                    app.logger.info(f"{fmt.upper()}: {filepath}")
            else:
                app.logger.error(f"Could not load scan result from {args.scan_file}")

        return 0

    except KeyboardInterrupt:
        app.logger.warning("Scan interrupted by user")
        return 1
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
