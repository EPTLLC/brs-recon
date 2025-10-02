<!--
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-02 (UTC)
Status: Modified
Telegram: https://t.me/easyprotech
-->

# BRS-RECON

**Python Network Reconnaissance Toolkit**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.0.2-brightgreen?style=for-the-badge&logo=github&logoColor=white)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux&logoColor=white)](README.md)

[![GitHub Stars](https://img.shields.io/github/stars/EPTLLC/brs-recon?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EPTLLC/brs-recon/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/EPTLLC/brs-recon?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EPTLLC/brs-recon/network)
[![GitHub Issues](https://img.shields.io/github/issues/EPTLLC/brs-recon?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EPTLLC/brs-recon/issues)
[![GitHub Release](https://img.shields.io/github/v/release/EPTLLC/brs-recon?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EPTLLC/brs-recon/releases)

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-purple?style=for-the-badge&logo=security&logoColor=white)](https://docs.github.com/en/code-security/code-scanning)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![Security](https://img.shields.io/badge/Security-Enterprise-red?style=for-the-badge&logo=shield&logoColor=white)](SECURITY.md)
[![EasyProTech](https://img.shields.io/badge/EasyProTech-LLC-gold?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/EasyProTech)

**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Contact:** https://t.me/EasyProTech

BRS-RECON is a Python network reconnaissance and security assessment toolkit. It reimplements the original [BRS](https://github.com/EPTLLC/brs) with a modular architecture. Patterns align with [BRS-XSS](https://github.com/EPTLLC/brs-xss) for consistency and performance.

---

## Why BRS-RECON?

**Modular Architecture** - Clean separation of concerns with specialized modules for each reconnaissance discipline  
**High Performance** - Optimized algorithms with parallel execution and intelligent caching  
**Multi-Format Export** - SARIF, JSON, HTML, XML, CSV output for seamless tool integration  
**IPv6 Ready** - Full dual-stack support for modern network environments  
**Enterprise Grade** - Structured logging, deterministic outputs, reproducible runs

### Comparison Matrix

| Feature                 | BRS-RECON               | Original BRS       | nmap alone         | Custom Scripts       |
| ----------------------- | ----------------------- | ------------------ | ------------------ | -------------------- |
| **Modular Design**      | Yes (5 modules)         | Partial (monolithic) | No (single tool)   | Partial (ad-hoc)     |
| **Parallel Execution**  | Yes (async)             | No (sequential)    | No (sequential)    | Partial (manual)     |
| **Multi-Format Export** | Yes (JSON/HTML/SARIF/XML/CSV) | Partial (text only) | Partial (XML only) | No standard          |
| **IPv6 Support**        | Yes (native)            | Partial (limited)  | Yes (native)       | Partial (manual)     |
| **Error Handling**      | Structured              | Basic              | Basic              | Inconsistent         |
| **Result Management**   | Deterministic           | Minimal            | None               | Manual               |

---

## Quickstart (60 seconds)

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip nmap fping arp-scan masscan dnsutils whois nikto sslscan sqlmap dirb git unzip bsdextrautils

# Install testssl.sh (script + etc resources)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -sf "$PWD/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
sudo mkdir -p /usr/local/bin/etc && sudo cp -r testssl.sh/etc/* /usr/local/bin/etc/
export TESTSSL_INSTALL_DIR=/usr/local/bin
testssl.sh --version

# Set capabilities
sudo setcap cap_net_raw+ep "$(command -v fping)"
sudo setcap cap_net_admin,cap_net_raw+ep "$(command -v masscan)"
```

### Install Python Dependencies

```bash
pip install -r requirements/requirements.txt
```

### Quick Scans

```bash
# Network discovery
brs-recon network 192.168.1.0/24 --method comprehensive

# Port scanning with service detection
brs-recon ports target.com --ports top1000 --service-detection

# Domain reconnaissance
brs-recon domain example.com --scan-type comprehensive

# Vulnerability assessment
brs-recon vuln target.com --scan-type comprehensive --aggressive

# System information
brs-recon system --scan-type full --processes
```

### Docker Usage

```bash
# Build
docker build -t brs-recon .

# Run (capabilities required for raw sockets)
docker run --rm \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/results:/results \
  brs-recon network 10.0.0.0/24

docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v $(pwd)/results:/results brs-recon ports target.com --ports common
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v $(pwd)/results:/results brs-recon domain example.com

# Local network scanning
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host -v $(pwd)/results:/results brs-recon network 10.0.0.0/24

# Rootless (podman)
podman run --rm --cap-add=net_raw,net_admin -v $(pwd)/results:/results localhost/brs-recon network 10.0.0.0/24

# Environment variables
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e BRS_RECON_MAX_CONCURRENT=32 -v $(pwd)/results:/results brs-recon network 10.0.0.0/24

# testssl.sh installation path for runtime
export TESTSSL_INSTALL_DIR=/usr/local/bin
```

---

## Core Modules

### 1. Network Discovery

**High-speed host enumeration and network mapping**

Discovery Methods:
* **fping Sweep** - Ultra-fast ICMP discovery with IPv6 support
* **ARP Scanning** - Local network discovery with modern `ip neigh` integration
* **nmap Discovery** - Comprehensive host detection with greppable output parsing
* **TCP Connect Fallback** - Probing common ports when ICMP is filtered

Performance Enhancements:
* Parallel execution with configurable thread pools
* Intelligent network size limiting (4096 hosts max)
* IPv4/IPv6 dual-stack support
* Automatic tool availability detection

```bash
# Examples
brs-recon network 192.168.1.0/24 --method ping_sweep --threads 100
brs-recon network 10.0.0.0/16 --method comprehensive
brs-recon network target.com --method nmap_discovery
```

### 2. Port Scanning

**Advanced port scanning with service fingerprinting**

Scanning Techniques:
* **TCP Connect** - Tri-state detection (open/closed/filtered)
* **SYN Scanning** - Stealth scanning via nmap integration
* **UDP Scanning** - UDP service discovery
* **masscan Integration** - High-speed scanning for large port ranges

Service Detection:
* **TLS Handshake Analysis** - Certificate information extraction
* **HTTP Header Analysis** - Server fingerprinting via HEAD requests
* **Banner Grabbing** - Service identification for SSH, FTP, SMTP
* **IPv6 Support** - Dual-stack scanning capabilities

```bash
# Examples  
brs-recon ports target.com --ports top1000 --scan-type comprehensive
brs-recon ports 10.0.0.1 --ports "80,443,8080-8090" --service-detection
brs-recon ports target.com --scan-type syn --ports all
```

### 3. Domain Reconnaissance

**Comprehensive DNS intelligence gathering**

DNS Analysis:
* **IDNA Normalization** - International domain name support
* **Fast DNS Queries** - Optimized dig parameters (+tries=1 +time=2)
* **Wildcard Protection** - False positive prevention in subdomain enumeration
* **Zone Transfer Attempts** - AXFR testing with proper validation

Intelligence Gathering:
* **Subdomain Enumeration** - Threaded discovery with common wordlists
* **WHOIS Analysis** - Registration and ownership information
* **MX Record Analysis** - Mail server discovery with A/AAAA resolution
* **DNS Record Collection** - A, AAAA, CNAME, MX, NS, TXT, SOA records

```bash
# Examples
brs-recon domain example.com --scan-type comprehensive --threads 50
brs-recon domain target.com --scan-type basic --no-subdomains
brs-recon domain international-域名.com --scan-type comprehensive
```

### 4. Vulnerability Assessment

**Multi-vector security vulnerability scanning**

Scanning Vectors:
* **Network Vulnerabilities** - 2-phase nmap vulnerability script execution
* **Web Application Security** - nikto scanning with enhanced parsing
* **SSL/TLS Assessment** - sslscan and testssl.sh integration
* **SQL Injection Detection** - Enhanced sqlmap with smart crawling

Performance Features:
* **Parallel Execution** - Concurrent nmap/nikto/SSL scanning
* **Intelligent Targeting** - Port discovery before vulnerability scanning
* **Configurable Aggressiveness** - Safe defaults with aggressive options
* **Tool Availability Adaptation** - Graceful degradation when tools missing

```bash
# Examples
brs-recon vuln target.com --scan-type comprehensive --aggressive
brs-recon vuln https://app.example.com --scan-type web_only
brs-recon vuln target.com --no-web --scan-type basic
```

### 5. System Information

**Comprehensive system profiling and analysis**

Information Categories:
* **System Overview** - OS, architecture, uptime, Python environment
* **Hardware Profile** - CPU, memory, disk usage with filtering
* **Network Configuration** - Interfaces with IPv4/IPv6 normalization
* **Process Analysis** - Running processes with accurate CPU percentages
* **Service Enumeration** - systemd services and listening processes

Advanced Features:
* **Address Normalization** - Proper IPv4/IPv6/MAC address handling
* **Prefix Length Calculation** - Network mask to CIDR conversion
* **Pseudo-filesystem Filtering** - Clean disk usage without system mounts
* **Modern Tool Integration** - systemctl, ip neigh, JSON parsing

```bash
# Examples
brs-recon system --scan-type full --processes
brs-recon system --scan-type basic --no-network
brs-recon system --target remote-host --scan-type full
```

---

## Export and Reporting

### Multi-Format Export System

BRS-RECON provides comprehensive export capabilities matching enterprise security tool standards:

**Supported Formats:**
* **JSON** - Machine-readable structured data
* **HTML** - User-friendly reports with responsive design
* **SARIF** - Security Analysis Results Interchange Format (v2.1.0)
* **XML** - Structured data exchange format
* **CSV** - Spreadsheet-compatible tabular data

### Export Examples

```bash
# Export existing scan results
brs-recon export results/scans/scan_result.json --formats html sarif csv

# Direct export during scanning (future feature)
brs-recon vuln target.com --export-formats html sarif
```

### Results Directory Structure (Contract)

```
results/
├── scans/<timestamp>_<target>.json  # Raw scan results
├── html/<timestamp>.html            # User-friendly reports  
├── sarif/<timestamp>.sarif          # SARIF 2.1.0 format
├── json/<timestamp>.json            # Machine-readable export
├── csv/<timestamp>.csv              # Spreadsheet format
├── xml/<timestamp>.xml              # Structured XML
├── logs/<timestamp>.log             # Structured application logs
└── latest.* -> symlink              # Latest scan result
```

**File Naming Convention:**
- `brs-recon_{target}_{YYYYMMDD-HHMMSS}.{format}`
- Automatic sanitization of target names for filesystem compatibility
- Deterministic timestamps for result correlation

---

## Performance Benchmarks

**Testing Environment:** Ubuntu 22.04, Python 3.10, Real-world Testing

| Module              | Target Type    | Performance (v0.0.2) | Accuracy      |
| ------------------- | -------------- | -------------------- | ------------- |
| **Network Discovery** | Single host   | 0.27 seconds         | 100% detection |
| **Port Scanning**    | 10 ports + svc| 2.49 seconds         | Perfect service ID |
| **Domain Recon**     | Domain + subs  | 14.48 seconds        | Wildcard protected |
| **Vulnerability**    | Web + SSL      | 137 seconds basic    | Real findings |
| **System Info**      | Localhost      | 0.08 seconds full    | Complete profile |

### Scalability Testing (v0.0.2 Real Results)

- **Network Discovery:** Single host in 0.27 seconds (comprehensive mode)
- **Port Scanning:** 10 critical ports + service detection in 2.49 seconds
- **Subdomain Enum:** 100+ wordlist, 16 subdomains found on github.com in 47 seconds
- **Service Detection:** 30 ports with parallel identification in 6.53 seconds
- **Vulnerability Assessment:** 8 real findings in 137 seconds

---

## Configuration

### Default Configuration

BRS-RECON uses intelligent defaults optimized for speed and accuracy:

```yaml
# ~/.config/brs-recon/config.yaml
network:
  default_timeout: 30
  max_concurrent_scans: 10
  dns_servers: ["8.8.8.8", "1.1.1.1"]

web:
  user_agent: "BRS-RECON/0.0.1"
  request_timeout: 15
  verify_ssl: true

security:
  safe_mode: true
  max_scan_depth: 3
  rate_limit_delay: 0.1
```

### Environment Variables

```bash
export BRS_RECON_NETWORK_TIMEOUT=60
export BRS_RECON_MAX_CONCURRENT=20
export BRS_RECON_RESULTS_DIR="/custom/results"
export BRS_RECON_SAFE_MODE=true
```

---

## Advanced Usage

### Comprehensive Network Assessment

```bash
# Increase file descriptor limit for large scans
ulimit -n 65535

# Phase 1: Network Discovery
brs-recon network 10.0.0.0/24 --method comprehensive --threads 100 --max-hosts 2048

# Phase 2: Port Scanning (discovered hosts)
brs-recon ports discovered-host.com --ports top1000 --service-detection --max-ports 5000

# Phase 3: Vulnerability Assessment
brs-recon vuln discovered-host.com --scan-type comprehensive --aggressive

# Phase 4: Export Results
brs-recon export results/scans/latest-vuln-scan.json --formats html sarif
```

### Domain Intelligence Pipeline

```bash
# Comprehensive domain analysis
brs-recon domain target.com --scan-type comprehensive --threads 64

# Subdomain discovery only
brs-recon domain target.com --scan-type basic --subdomains

# Export for further analysis
brs-recon export results/scans/domain-scan.json --formats csv xml
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Reconnaissance
  run: |
    brs-recon vuln $(cat inputs/targets.txt) --scan-type basic
    brs-recon export results/scans/latest.json --formats sarif

- name: Upload Security Results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/sarif/security-scan.sarif
```

---

## Installation Options

### From Source (Recommended)

```bash
git clone https://github.com/EPTLLC/brs-recon.git
cd brs-recon

# Install dependencies via Makefile
make deps

# Install system dependencies (Ubuntu/Debian)
sudo apt install -y nmap fping arp-scan masscan dig whois nikto sslscan sqlmap dirb
```

### Build Targets

```bash
make deps    # Install Python dependencies
make lint    # Code quality checks (flake8, black)
make test    # Run test suite (pytest)
make docker  # Build Docker container
make clean   # Clean build artifacts
```

### Docker Container

```bash
# Build and run
docker build -t brs-recon .
docker run --rm -v $(pwd)/results:/results brs-recon network 192.168.1.0/24

# Pre-built image (future)
docker pull ghcr.io/eptllc/brs-recon:latest
```

### System Requirements

**Minimum:**
- Ubuntu 20.04+ or compatible Linux distribution
- Python 3.8+
- 2GB RAM
- 1GB free disk space

**Recommended:**
- Ubuntu 22.04 LTS
- Python 3.10+
- 8GB RAM
- 5GB free disk space
- Network interfaces for comprehensive testing

---

## Command Reference

### Network Discovery

```bash
# Basic ping sweep
brs-recon network 192.168.1.0/24

# ARP scan local network
brs-recon network 192.168.1.0/24 --method arp_scan

# Comprehensive multi-method discovery
brs-recon network 10.0.0.0/16 --method comprehensive --threads 200

# IPv6 network discovery
brs-recon network 2001:db8::/64 --method nmap_discovery
```

### Port Scanning

```bash
# Common ports with service detection
brs-recon ports target.com --ports common --service-detection

# Top 1000 ports comprehensive scan
brs-recon ports target.com --ports top1000 --scan-type comprehensive

# Custom port range
brs-recon ports target.com --ports "80,443,8000-8100" --scan-type tcp

# UDP scan
brs-recon ports target.com --ports "53,161,1194" --scan-type udp
```

### Domain Reconnaissance

```bash
# Basic domain analysis
brs-recon domain example.com --scan-type basic

# Comprehensive with subdomain enumeration
brs-recon domain target.com --scan-type comprehensive --threads 50

# International domains
brs-recon domain münchen.de --scan-type comprehensive
```

### Vulnerability Assessment

```bash
# Basic security assessment
brs-recon vuln target.com --scan-type basic

# Comprehensive web application testing
brs-recon vuln https://app.target.com --scan-type comprehensive --aggressive

# Network vulnerabilities only
brs-recon vuln target.com --no-web --no-ssl

# Web vulnerabilities only
brs-recon vuln target.com --scan-type web_only --aggressive
```

### System Information

```bash
# Basic system profile
brs-recon system --scan-type basic

# Comprehensive system analysis
brs-recon system --scan-type full --processes

# Network-focused analysis
brs-recon system --scan-type full --no-hardware
```

### Export and Reporting

```bash
# Export to multiple formats
brs-recon export results/scans/scan-result.json --formats html sarif csv xml

# HTML report only
brs-recon export results/scans/scan-result.json --formats html

# SARIF for security tools
brs-recon export results/scans/vuln-scan.json --formats sarif
```

---

## Architecture Overview

### Modular Design

```
brs-recon/
├── brs-recon/          # Core application package
│   ├── core/           # Framework components
│   │   ├── base.py     # Module base classes
│   │   ├── config.py   # Configuration management
│   │   ├── logger.py   # Professional logging
│   │   ├── models.py   # Data models
│   │   ├── results.py  # Result management
│   │   ├── export.py   # Multi-format export
│   │   └── utils.py    # Utility functions
│   ├── modules/        # Scanning modules
│   │   ├── network_discovery.py  # Host enumeration
│   │   ├── port_scanning.py      # Port analysis
│   │   ├── domain_recon.py       # DNS intelligence
│   │   ├── vulnerability.py      # Security assessment
│   │   ├── system_info.py        # System profiling
│   │   └── *_utils.py            # Module utilities
│   ├── commands.py     # Extended command handlers
│   └── main.py         # CLI interface and entry point
├── cli/                # CLI-specific components
├── config/             # Configuration templates
├── requirements/       # Dependency specifications
└── results/           # Multi-format output directory
```

### Data Flow

1. **Input Validation** - Target normalization and requirement checking
2. **Parallel Execution** - Concurrent module operation with thread pools
3. **Result Aggregation** - Structured data collection and validation
4. **Multi-Format Export** - SARIF, JSON, HTML, XML, CSV generation
5. **Professional Logging** - Timestamped logs with multiple output streams

---

## Security Considerations

### Safe Mode Defaults

BRS-RECON operates with production-safe defaults:

- **Rate limiting** to prevent service disruption
- **Timeout controls** to prevent hanging operations  
- **Resource limits** to prevent system overload
- **Authorization validation** before scanning operations

### Ethical Guidelines

- **Authorized testing only** - Explicit permission required
- **Responsible disclosure** - 90-day coordinated disclosure timeline
- **Minimal impact** - Designed to minimize disruption to target systems
- **Privacy protection** - Secure handling of discovered information

See [ETHICS.md](ETHICS.md) for complete ethical guidelines.

---

**AUTHORIZED USE ONLY - obtain explicit permission before scanning.**

## Legal Compliance

### BRS-RECON Dual License Structure

**Open Source (GPLv3):**
- Educational, research, and open-source projects
- Requires source code disclosure for derivative works
- Copyleft compliance mandatory

**Commercial License:**
- Commercial entities and proprietary projects  
- No copyleft restrictions
- Private use permitted
- Contact: https://t.me/EasyProTech

### Important Legal Notice

**AUTHORIZED USE ONLY**

This tool is designed for legitimate security testing with proper authorization. Unauthorized use may result in criminal prosecution under computer crime laws worldwide.

See [LEGAL.md](LEGAL.md) and [DISCLAIMER.md](DISCLAIMER.md) for complete terms.

---

## Contributing

### Development Standards

1. **Code Quality**
   - Maximum 300 lines per file
   - Type hints for all functions
   - Comprehensive error handling
   - English-only comments and documentation

2. **Testing Requirements**
   - Unit tests for all core functions
   - Integration tests for module interactions
   - Performance benchmarks for optimization validation

3. **Documentation Standards**
   - Docstrings for all public functions
   - Example usage in module documentation
   - Architecture decision records for significant changes

### Contribution Process

```bash
# Development setup
git clone https://github.com/EPTLLC/brs-recon.git
cd brs-recon
pip install -r requirements/requirements.txt

# Run tests
pytest tests/

# Code formatting
black brsrecon/
flake8 brsrecon/

# Submit changes
git checkout -b feature/amazing-enhancement
git commit -m "Add amazing enhancement"
git push origin feature/amazing-enhancement
```

---

## Troubleshooting

### Common Issues

**Permission Errors:**
```bash
sudo setcap cap_net_raw+ep "$(command -v fping)"
sudo setcap cap_net_admin,cap_net_raw+ep "$(command -v masscan)"
```

**Missing Tools:**
```bash
# Check tool availability
brs-recon vuln target.com --scan-type basic
# Install missing tools based on error messages
```

**Performance Issues:**
- Reduce thread count for resource-constrained systems
- Use targeted scanning instead of comprehensive modes
- Enable safe mode for production environments

### Debug Mode

```bash
brs-recon --log-level DEBUG network target.com
```

### Development

```bash
# Code quality
isort .
black .
flake8 .
```

---

## Roadmap

### Version 0.1.0 (Next Release)

- **Interactive TUI** - Menu-driven interface matching original BRS
- **Attack Tools Module** - Authorized penetration testing capabilities
- **Configuration UI** - Interactive configuration management
- **Result Aggregation** - Multi-scan analysis and trending

### Version 0.2.0 (Future)

- **REST API** - Programmatic access and integration
- **Web Dashboard** - Browser-based result visualization
- **Custom Wordlists** - User-defined enumeration dictionaries
- **Plugin Architecture** - Third-party module support

---

## Related Projects

### EasyProTech Security Suite

BRS-RECON is part of the comprehensive EasyProTech security toolkit:

- **[Brabus Recon Suite (BRS)](https://github.com/EPTLLC/brs)** - Original Bash-based reconnaissance toolkit
  - Professional Linux toolkit for network reconnaissance
  - Interactive TUI with menu-driven interface
  - Timestamped results and clean formatting
  - Multi-language support (7 languages)

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Specialized XSS vulnerability scanner
  - Context-aware XSS payload generation
  - WAF evasion techniques and ML-based risk scoring
  - SARIF 2.1.0 compliance for CI/CD integration
  - Async performance with 32 concurrent requests

### Integration Capabilities

BRS-RECON is designed for seamless integration with other EasyProTech tools:

```bash
# Comprehensive security assessment pipeline
brs-recon network 10.0.0.0/24 --method comprehensive
brs-recon ports discovered-hosts.txt --ports top1000
brs-recon vuln web-services.txt --scan-type comprehensive
brs-xss scan web-applications.txt --aggr --deep
```

---

## Support and Community

### Getting Help

- **Documentation:** This README and inline help (`--help`)
- **Community:** GitHub Discussions and Issues
- **Commercial Support:** https://t.me/EasyProTech

### Reporting Issues

1. **Security Vulnerabilities:** Private disclosure via Telegram
2. **Bug Reports:** GitHub Issues with reproduction steps
3. **Feature Requests:** GitHub Discussions with use case description

---

**BRS-RECON v0.0.2** | **EasyProTech LLC** | **https://t.me/EasyProTech**

_Python Evolution of [Brabus Recon Suite](https://github.com/EPTLLC/brs) with [BRS-XSS](https://github.com/EPTLLC/brs-xss) Architecture_
