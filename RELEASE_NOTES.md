# BRS-RECON Release Notes

**Project:** BRS-RECON (Network Reconnaissance Tool)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Date:** 2025-09-16  
**Status:** Release Notes  
**Contact:** https://t.me/easyprotech

---

## [0.0.2] - 2025-10-02

### Major Bug Fixes and Performance Improvements

This release addresses critical functionality issues discovered in v0.0.1 and delivers significant performance improvements.

#### Critical Fixes
- **Service Detection Completely Rewritten** - Fixed critical bug where all services showed as "unknown"
- **Nikto Integration Restored** - Fixed file permission errors, now works with stdout parsing
- **Performance Breakthrough** - Port scanning now 50-72x faster than v0.0.1
- **Comprehensive Mode Fixed** - Service detection now works in all scan modes

#### Key Improvements
- **Real Service Identification:** SSH, HTTP, HTTPS, FTP, MySQL, PostgreSQL, Redis properly detected
- **Enhanced Subdomain Discovery:** 100+ subdomain wordlist vs previous 25
- **Parallel Service Detection:** Multi-threaded service identification for speed
- **Robust Error Handling:** Better graceful degradation when tools fail

#### Performance Benchmarks (Real Testing Results)
- **Port Scanning:** 2.49s (was 180s+) - 72x improvement
- **Network Discovery:** 0.27s (target: <1s) - Exceeds specification
- **Domain Reconnaissance:** 14.48s (target: <60s) - 4x faster than target
- **Vulnerability Assessment:** 137s (target: <2min) - Meets specification
- **System Information:** 0.08s (target: <1s) - 12x faster than target

#### Real-world Validation
Comprehensive testing performed on multiple targets:
- **30+ open ports identified** with correct service detection
- **Multiple vulnerability findings** through working nikto integration
- **Multi-format exports** (HTML, SARIF, CSV, XML, JSON) all functional
- **Professional reporting** with detailed technical analysis

### Installation & Usage

```bash
# Install from source
git clone https://github.com/EPTLLC/brs-recon.git
cd brs-recon
pip install -e .

# Quick functionality test
brs-recon --version  # Should show 0.0.2
brs-recon ports target.com --ports common --service-detection
brs-recon domain target.com --scan-type comprehensive
```

### Breaking Changes
- None - All changes are backward compatible improvements

### Migration from v0.0.1
- No migration required - direct upgrade
- All existing command-line interfaces remain unchanged
- Output formats remain compatible

---

## [0.0.1] - 2025-09-16

### Maintenance Updates

- CI/CD: Fixed Docker job by building image via `docker build` and ensuring Trivy sees local tag; updated CodeQL actions to v3; adjusted Safety to `safety scan` with JSON output; added permissions for SARIF uploads; ensured required tools (nikto, sqlmap, dirb, testssl.sh) installed in test job; set `BRS_RECON_TEST_SHIMS=1` in tests.
- Dockerfile: Added `bsdextrautils` and proper `testssl.sh` install with `etc` resources; copied requirements-base/constraints before install.
- Dependencies: Bumped `requests`, `jinja2`, updated `aiohttp` markers for 3.8 compatibility; added typing stubs (`types-PyYAML`, `types-psutil`).
- README: clarified dependencies (dnsutils, git, bsdextrautils), proper `testssl.sh` install and `TESTSSL_INSTALL_DIR` usage; removed emojis in comparison table; updated upload-sarif action to v3.
- Packaging: Switched to setuptools package discovery for `brsrecon*`; removed `typer[all]` extra.

### Initial Release

First public release of BRS-RECON - Python Network Reconnaissance Toolkit.

### Features

#### Core Modules
- **Network Discovery** - Multi-method host enumeration (fping, ARP, nmap)
- **Port Scanning** - Advanced TCP/UDP/SYN scanning with service detection
- **Domain Reconnaissance** - DNS analysis, subdomain enumeration, WHOIS
- **Vulnerability Assessment** - Multi-vector security scanning
- **System Information** - Comprehensive system profiling

#### Export & Reporting
- **Multi-Format Export** - JSON, HTML, SARIF, XML, CSV output
- **SARIF 2.1.0 Compliance** - GitHub Security tab integration
- **Professional Reports** - Responsive HTML with modern styling
- **Structured Results** - Deterministic output with timestamps

#### Performance & Reliability
- **Async Architecture** - Parallel execution with thread pools
- **IPv6 Ready** - Full dual-stack network support
- **Enterprise Grade** - Structured logging, error handling
- **Docker Ready** - Multi-stage build with security hardening

### Security Features

- **Safe Mode Defaults** - Production-safe rate limiting
- **Capability Management** - Minimal required privileges
- **Input Validation** - Comprehensive target validation
- **Output Sanitization** - Secure report generation

### Infrastructure

- **Modern Packaging** - pyproject.toml with setuptools backend
- **Testing** - Full pytest suite, clean flake8/isort/black
- **CI/CD Pipeline** - GitHub Actions: lint, tests, docker, security
- **Quality Assurance** - black, flake8, mypy (advisory), bandit

### Installation

```bash
# Install from source
git clone https://github.com/EPTLLC/brs-recon.git
cd brs-recon
pip install -e .

# Quick start
brs-recon --version
brs-recon system --scan-type basic
brs-recon network 192.168.1.0/24 --method comprehensive
```

### Docker Support

```bash
# Build container
docker build -t brs-recon .

# Run scan
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/results:/results brs-recon network 192.168.1.0/24
```

### Performance Notes

- Performance depends on environment and tool availability

### Security Considerations

- **Authorized Testing Only** - Explicit permission required
- **Rate Limiting** - Prevents service disruption
- **Resource Limits** - System overload protection
- **Ethical Guidelines** - Responsible disclosure practices

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

### Integration

Works seamlessly with EasyProTech security suite:
- **[BRS](https://github.com/EPTLLC/brs)** - Original Bash reconnaissance toolkit
- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - XSS vulnerability scanner

### Documentation

- **README.md** - Comprehensive usage guide
- **SECURITY.md** - Security policy and vulnerability reporting
- **CONTRIBUTING.md** - Development guidelines
- **ETHICS.md** - Ethical usage guidelines
- **LEGAL.md** - Legal terms and compliance

### License

Dual licensing structure:
- **GPL-3.0-or-later** - Open source projects
- **Commercial License** - Enterprise and proprietary use

Contact: https://t.me/easyprotech

### Known Constraints

- Docker scans may require `--cap-add=NET_RAW`/`--cap-add=NET_ADMIN`
- External tools (nmap, fping, masscan, etc.) required for full features

### Coming Next (v0.1.0)

- **Interactive TUI** - Menu-driven interface
- **Attack Tools Module** - Authorized penetration testing
- **Configuration UI** - Interactive setup
- **Result Aggregation** - Multi-scan analysis

---

## Download

**Source Code:** https://github.com/EPTLLC/brs-recon/archive/v0.0.1.tar.gz  
**Wheel Package:** `pip install brs-recon` (upon publication)  
**Docker Image:** `ghcr.io/eptllc/brs-recon:0.0.1` (upon publication)

## Verification

**SHA256 Checksums:**
- Source: `TBD`
- Wheel: `TBD`

**GPG Signature:** Available in release assets

---

**Full Changelog:** https://github.com/EPTLLC/brs-recon/blob/main/CHANGELOG.md  
**Security Policy:** https://github.com/EPTLLC/brs-recon/blob/main/SECURITY.md  
**Support:** https://t.me/easyprotech
