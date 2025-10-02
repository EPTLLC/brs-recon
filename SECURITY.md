# Security Policy

**Project:** BRS-RECON (Network Reconnaissance Tool)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Date:** 2025-09-07  
**Status:** Created  
**Contact:** https://t.me/easyprotech

## Supported Versions

We actively support security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | :white_check_mark: |

## Reporting a Vulnerability

### Private Security Disclosure

For security vulnerabilities, please **DO NOT** create a public GitHub issue. Instead, report vulnerabilities privately through one of these channels:

#### Primary Channel: Telegram
- **Contact:** https://t.me/easyprotech
- **Subject:** `[SECURITY] BRS-RECON Vulnerability Report`
- **Response Time:** Within 24-48 hours

#### Alternative Channel: GitHub Security Advisory
- Use GitHub's private vulnerability reporting feature
- Navigate to: Security → Advisories → Report a vulnerability
- **Response Time:** Within 72 hours

### What to Include in Your Report

Please provide the following information to help us assess and fix the vulnerability quickly:

1. **Vulnerability Description**
   - Clear description of the security issue
   - Potential impact and severity assessment
   - Affected components/modules

2. **Reproduction Steps**
   - Step-by-step instructions to reproduce the issue
   - Minimal test case or proof-of-concept
   - Environment details (OS, Python version, dependencies)

3. **Technical Details**
   - Code snippets or patches if available
   - Stack traces or error messages
   - Network captures if relevant

4. **Suggested Mitigation**
   - Proposed fixes or workarounds
   - References to similar issues or CVEs

### Disclosure Timeline

We follow responsible disclosure practices:

| Timeline | Action |
|----------|--------|
| **Day 0** | Vulnerability reported |
| **Day 1-2** | Initial response and acknowledgment |
| **Day 3-7** | Vulnerability assessment and validation |
| **Day 7-30** | Development of fix and testing |
| **Day 30-90** | Coordinated disclosure and release |
| **Day 90+** | Public disclosure (if unresolved) |

### Severity Classification

We use the following severity levels based on CVSS v3.1:

| Severity | CVSS Score | Response Time | Disclosure Timeline |
|----------|------------|---------------|-------------------|
| **Critical** | 9.0-10.0 | 24 hours | 7-14 days |
| **High** | 7.0-8.9 | 48 hours | 30 days |
| **Medium** | 4.0-6.9 | 7 days | 60 days |
| **Low** | 0.1-3.9 | 14 days | 90 days |

### Security Considerations for BRS-RECON

#### High-Risk Areas

The following components require special security attention:

1. **External Tool Execution**
   - Command injection in subprocess calls
   - Path traversal in tool invocation
   - Privilege escalation through capabilities

2. **Network Operations**
   - Raw socket handling and capabilities
   - DNS resolution and cache poisoning
   - SSL/TLS certificate validation

3. **Input Validation**
   - Target parsing and validation
   - Configuration file processing
   - Command-line argument handling

4. **Output Generation**
   - File path traversal in results
   - Template injection in reports
   - XML/HTML injection in exports

5. **Dependency Management**
   - Third-party library vulnerabilities
   - Supply chain security
   - Outdated security patches

#### Security Best Practices

When reporting vulnerabilities, consider these common attack vectors:

- **Command Injection:** Malicious input in target specifications
- **Path Traversal:** Directory traversal in output paths
- **Privilege Escalation:** Abuse of network capabilities
- **Denial of Service:** Resource exhaustion attacks
- **Information Disclosure:** Sensitive data in logs/outputs

### Acknowledgments

We maintain a security hall of fame for researchers who responsibly disclose vulnerabilities:

- *No security researchers yet - be the first!*

### Security Updates

Security updates are distributed through:

1. **GitHub Releases** with security advisories
2. **PyPI Package Updates** with version bumps
3. **Docker Image Updates** with security patches
4. **Telegram Announcements** for critical issues

### Contact Information

- **Security Team:** https://t.me/easyprotech
- **General Contact:** contact@easypro.tech
- **GitHub Security:** Use private vulnerability reporting

---

**Remember:** This tool is designed for authorized security testing only. Unauthorized use may violate local laws and regulations. Always obtain explicit permission before testing systems you do not own.
 