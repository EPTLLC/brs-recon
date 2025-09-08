"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import Optional
from .core.logger import get_logger
from .modules.vulnerability import VulnerabilityScanner
from .modules.system_info import SystemInfo


class BRSCommands:
    """Additional commands for BRS-RECON"""
    
    def __init__(self):
        self.logger = get_logger()
        self.vuln_scanner = VulnerabilityScanner()
        self.system_info = SystemInfo()
    
    def run_vulnerability_scan(self, target: str, scan_type: str = "basic", 
                              web_scan: bool = True, ssl_scan: bool = True, 
                              aggressive: bool = False):
        """Run vulnerability assessment"""
        self.logger.banner("Vulnerability Assessment")
        
        # Validate requirements based on scan options
        if not self.vuln_scanner.validate_requirements(web_scan, ssl_scan):
            self.logger.error("Required tools not available for requested scan")
            return None
        
        result = self.vuln_scanner.run_scan(
            target,
            scan_type=scan_type,
            web_scan=web_scan,
            ssl_scan=ssl_scan,
            aggressive=aggressive
        )
        
        if result.status == "completed":
            vulnerabilities = result.data.get("vulnerabilities", [])
            nmap_vulns = result.data.get("nmap_vulns", [])
            web_vulns = result.data.get("web_vulnerabilities", [])
            ssl_issues = result.data.get("ssl_issues", [])
            
            total_vulns = len(vulnerabilities)
            self.logger.success(f"Vulnerability scan completed - {total_vulns} issues found")
            
            # Show breakdown by category
            if nmap_vulns:
                self.logger.info(f"Network vulnerabilities: {len(nmap_vulns)}")
            if web_vulns:
                self.logger.info(f"Web vulnerabilities: {len(web_vulns)}")
            if ssl_issues:
                self.logger.info(f"SSL/TLS issues: {len(ssl_issues)}")
            
            if vulnerabilities:
                self.logger.info("Found vulnerabilities:")
                for vuln in vulnerabilities[:5]:  # Show first 5
                    severity = vuln.get("severity", "unknown")
                    title = vuln.get("title", "Unknown vulnerability")
                    source = vuln.get("source", "unknown")
                    self.logger.info(f"  - [{severity.upper()}] [{source}] {title}")
                
                if len(vulnerabilities) > 5:
                    self.logger.info(f"  ... and {len(vulnerabilities) - 5} more vulnerabilities")
        else:
            self.logger.error(f"Vulnerability scan failed: {result.error}")
        
        return result
    
    def run_system_info_scan(self, target: str = "localhost", scan_type: str = "basic",
                            processes: bool = False, network: bool = True, 
                            hardware: bool = True):
        """Run system information gathering"""
        self.logger.banner("System Information")
        
        result = self.system_info.run_scan(
            target,
            scan_type=scan_type,
            processes=processes,
            network=network,
            hardware=hardware
        )
        
        if result.status == "completed":
            system_info = result.data.get("system_info", {})
            services = result.data.get("services", [])
            
            self.logger.success("System information gathered successfully")
            
            # Display key system info
            if system_info:
                hostname = system_info.get("hostname", "Unknown")
                os_name = system_info.get("operating_system", "Unknown")
                self.logger.info(f"Hostname: {hostname}")
                self.logger.info(f"Operating System: {os_name}")
            
            if services:
                self.logger.info(f"Running services: {len(services)}")
                for service in services[:5]:  # Show first 5
                    name = service.get("name", "Unknown")
                    self.logger.info(f"  - {name}")
                
                if len(services) > 5:
                    self.logger.info(f"  ... and {len(services) - 5} more services")
        else:
            self.logger.error(f"System information scan failed: {result.error}")
        
        return result
