"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

from ..core.base import NetworkModule, ScanConfig
from ..core.utils import run_command
from .port_utils import PortUtils


class PortScanning(NetworkModule):
    """Port scanning and service detection module"""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__("Port Scanning", config)
    
    def validate_requirements(self) -> bool:
        """Check if required tools are available"""
        required_tools = ["nmap"]
        optional_tools = ["masscan", "nc"]
        
        tool_status = self._check_network_tools(required_tools + optional_tools)
        return tool_status.get("nmap", False)
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform port scanning"""
        ports = kwargs.get("ports", "common")
        scan_type = kwargs.get("scan_type", "tcp")
        threads = kwargs.get("threads", 100)
        service_detection = kwargs.get("service_detection", False)
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "ports_scanned": [],
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "scan_summary": {}
        }
        
        # Parse port specification
        port_list = PortUtils.parse_port_specification(ports, self.logger)
        results["ports_scanned"] = port_list
        
        if scan_type == "tcp":
            results.update(self._tcp_scan(target, port_list, threads, service_detection))
        elif scan_type == "udp":
            results.update(self._udp_scan(target, port_list))
        elif scan_type == "syn":
            results.update(self._syn_scan(target, port_list))
        elif scan_type == "comprehensive":
            results.update(self._comprehensive_scan(target, port_list, threads, service_detection))
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
        
        return results
    
    def _tcp_scan(self, target: str, ports: List[int], threads: int, service_detection: bool) -> Dict[str, Any]:
        """TCP scan with tri-state detection (open/closed/filtered)"""
        self.logger.info(f"Starting TCP scan on {target} ({len(ports)} ports)")
        
        open_ports, closed_ports, filtered_ports, services = [], [], [], {}
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futs = {executor.submit(PortUtils.tcp_connect, target, p): p for p in ports}
            for fut in as_completed(futs):
                port = futs[fut]
                try:
                    state, _ = fut.result()
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
                    state = "closed"
                
                if state == "open":
                    open_ports.append(port)
                    if service_detection:
                        service_info = PortUtils.detect_service(target, port)
                        if service_info:
                            services[port] = service_info
                elif state == "filtered":
                    filtered_ports.append(port)
                else:
                    closed_ports.append(port)
        
        open_ports.sort()
        closed_ports.sort()
        filtered_ports.sort()
        
        return {
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "services": services,
            "scan_summary": {
                "total_ports": len(ports),
                "open_ports": len(open_ports),
                "closed_ports": len(closed_ports),
                "filtered_ports": len(filtered_ports),
                "scan_type": "tcp_connect"
            }
        }
    
    def _udp_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Perform UDP scan using nmap"""
        self.logger.info(f"Starting UDP scan on {target}")
        
        port_range = PortUtils.format_port_list(ports)
        cmd = ["nmap", "-Pn", "-T4", "-sU", "-p", port_range, target]
        
        result = run_command(cmd, timeout=300)  # UDP scans take longer
        
        if result["success"]:
            scan_results = PortUtils.parse_nmap_output(result["stdout"])
        else:
            scan_results = {"open_ports": [], "closed_ports": [], "filtered_ports": []}
        
        return {
            "open_ports": scan_results.get("open_ports", []),
            "closed_ports": scan_results.get("closed_ports", []),
            "filtered_ports": scan_results.get("filtered_ports", []),
            "services": scan_results.get("services", {}),
            "scan_summary": {
                "total_ports": len(ports),
                "scan_type": "udp",
                "command": " ".join(cmd),
                "raw_output": result["stdout"] if result["success"] else result["stderr"]
            }
        }
    
    def _syn_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Perform SYN scan using nmap"""
        self.logger.info(f"Starting SYN scan on {target}")
        
        port_range = PortUtils.format_port_list(ports)
        cmd = ["nmap", "-Pn", "-T4", "-sS", "-p", port_range, target]
        
        result = run_command(cmd, timeout=120)
        
        if result["success"]:
            scan_results = PortUtils.parse_nmap_output(result["stdout"])
        else:
            scan_results = {"open_ports": [], "closed_ports": [], "filtered_ports": []}
        
        return {
            "open_ports": scan_results.get("open_ports", []),
            "closed_ports": scan_results.get("closed_ports", []),
            "filtered_ports": scan_results.get("filtered_ports", []),
            "services": scan_results.get("services", {}),
            "scan_summary": {
                "total_ports": len(ports),
                "scan_type": "syn",
                "command": " ".join(cmd),
                "raw_output": result["stdout"] if result["success"] else result["stderr"]
            }
        }
    
    def _comprehensive_scan(self, target: str, ports: List[int], threads: int, service_detection: bool) -> Dict[str, Any]:
        """Comprehensive scan with masscan fast-path for large port lists"""
        self.logger.info(f"Starting comprehensive scan on {target}")
        
        # Fast-path for large port lists using masscan
        if len(ports) > 2000 and self._check_network_tools(["masscan"]).get("masscan", False):
            self.logger.info("Using masscan for discovery phase")
            port_range = PortUtils.format_port_list(ports)
            masscan_result = run_command(["masscan", target, "-p", port_range, "--rate", "5000", "--wait", "3", "-oL", "-"], timeout=180)
            
            found = []
            if masscan_result["success"]:
                for line in masscan_result["stdout"].splitlines():
                    if line.startswith("open"):
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == "open":
                            try:
                                found.append(int(parts[2]))
                            except:
                                pass
            
            found = sorted(set(found))
            services = {}
            
            if found and service_detection:
                self.logger.info(f"Running nmap service detection on {len(found)} ports")
                cmd = ["nmap", "-Pn", "-sV", "-p", PortUtils.format_port_list(found), target]
                nmap_result = run_command(cmd, timeout=180)
                if nmap_result["success"]:
                    services = PortUtils.parse_nmap_output(nmap_result["stdout"]).get("services", {})
            
            return {
                "open_ports": found,
                "closed_ports": [],
                "filtered_ports": [],
                "services": services,
                "scan_summary": {
                    "total_ports": len(ports),
                    "open_ports": len(found),
                    "scan_type": "comprehensive-masscan",
                    "service_detection": service_detection
                }
            }
        
        # Standard comprehensive scan
        tcp_results = self._tcp_scan(target, ports, threads, False)
        open_ports = tcp_results["open_ports"]
        services = {}
        
        if open_ports and service_detection:
            self.logger.info(f"Performing service detection on {len(open_ports)} open ports")
            port_range = PortUtils.format_port_list(open_ports)
            cmd = ["nmap", "-Pn", "-sV", "-p", port_range, target]
            
            result = run_command(cmd, timeout=180)
            if result["success"]:
                nmap_results = PortUtils.parse_nmap_output(result["stdout"])
                services = nmap_results.get("services", {})
        
        return {
            "open_ports": open_ports,
            "closed_ports": tcp_results["closed_ports"],
            "filtered_ports": tcp_results["filtered_ports"],
            "services": services,
            "scan_summary": {
                "total_ports": len(ports),
                "open_ports": len(open_ports),
                "scan_type": "comprehensive",
                "service_detection": service_detection
            }
        }
    
