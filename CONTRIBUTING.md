# Contributing to BRS-RECON

**Project:** BRS-RECON (Network Reconnaissance Tool)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Date:** 2025-09-07  
**Status:** Created  
**Contact:** https://t.me/easyprotech

Thank you for your interest in contributing to BRS-RECON! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Development Standards](#development-standards)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- **Be respectful** and inclusive in all interactions
- **Use English** for all code, comments, and documentation
- **Follow ethical guidelines** for security research
- **Respect intellectual property** and licensing terms
- **Maintain professional standards** in all communications

## Getting Started

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **Git** version control
- **Linux environment** (Ubuntu 20.04+ recommended)
- **Network tools** (nmap, fping, masscan, etc.)
- **Docker** (optional, for containerized development)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/EPTLLC/brs-recon.git
cd brs-recon

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Verify installation
brs-recon --version
```

## Development Setup

### Detailed Environment Setup

1. **System Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install -y python python-pip python-venv git
   sudo apt install -y nmap fping arp-scan masscan dig whois
   sudo apt install -y nikto sslscan sqlmap dirb
   
   # Set network capabilities
   sudo setcap cap_net_raw+ep "$(command -v fping)"
   sudo setcap cap_net_admin,cap_net_raw+ep "$(command -v masscan)"
   ```

2. **Python Environment**
   ```bash
   # Create virtual environment
   python -m venv .venv
   source .venv/bin/activate
   
   # Upgrade pip and install build tools
   pip install --upgrade pip setuptools wheel
   
   # Install project in development mode
   pip install -e .[dev,test,docs]
   ```

3. **Development Tools**
   ```bash
   # Install pre-commit hooks
   pre-commit install --install-hooks
   
   # Verify setup
   pre-commit run --all-files
   ```

### IDE Configuration

#### VS Code
```json
{
    "python.defaultInterpreterPath": "./.venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

#### PyCharm
- Set interpreter to `.venv/bin/python`
- Enable Black formatter
- Configure flake8 as external tool
- Set import optimization to isort

## Contributing Guidelines

### Types of Contributions

We welcome the following types of contributions:

1. **Bug Reports** - Help us identify and fix issues
2. **Feature Requests** - Suggest new functionality
3. **Code Contributions** - Implement features or bug fixes
4. **Documentation** - Improve guides and API documentation
5. **Testing** - Add test cases and improve coverage
6. **Security** - Report vulnerabilities responsibly

### Contribution Process

1. **Check existing issues** to avoid duplicates
2. **Create an issue** for discussion (for significant changes)
3. **Fork the repository** and create a feature branch
4. **Implement your changes** following our standards
5. **Add tests** for new functionality
6. **Update documentation** as needed
7. **Submit a pull request** with clear description

### Branch Naming Convention

Use descriptive branch names with prefixes:

- `feature/add-new-scanner` - New features
- `bugfix/fix-port-parsing` - Bug fixes
- `docs/update-readme` - Documentation updates
- `test/improve-coverage` - Test improvements
- `refactor/cleanup-models` - Code refactoring
- `security/fix-command-injection` - Security fixes

## Pull Request Process

### Before Submitting

1. **Sync with main branch**
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run quality checks**
   ```bash
   # Format code
   black brs-recon/
   isort brs-recon/
   
   # Run linting
   flake8 brs-recon/
   mypy brs-recon/
   
   # Run tests
   pytest tests/ -v
   
   # Security check
   bandit -r brs-recon/
   ```

3. **Update documentation**
   - Add docstrings to new functions
   - Update README if needed
   - Add changelog entry

### Pull Request Template

When submitting a PR, include:

- **Description** of changes made
- **Issue reference** (if applicable)
- **Testing** performed
- **Breaking changes** (if any)
- **Checklist** completion

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by maintainers
3. **Testing** in different environments
4. **Security review** for sensitive changes
5. **Documentation review** for user-facing changes

## Issue Reporting

### Bug Reports

Use the bug report template and include:

- **Environment details** (OS, Python version, dependencies)
- **Reproduction steps** with minimal example
- **Expected behavior** vs actual behavior
- **Error messages** and stack traces
- **Configuration** and command-line arguments used

### Feature Requests

Use the feature request template and include:

- **Use case** and problem description
- **Proposed solution** with examples
- **Alternatives considered**
- **Implementation suggestions** (if any)

### Security Issues

**DO NOT** create public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for private reporting channels.

## Development Standards

### Code Quality

1. **Maximum 300 lines per file**
2. **Type hints for all functions**
3. **Comprehensive error handling**
4. **English-only comments and documentation**
5. **PEP 8 compliance** with Black formatting
6. **Import sorting** with isort

### Documentation Standards

1. **Docstrings** for all public functions (Google style)
   ```python
   def scan_network(target: str, method: str = "ping") -> NetworkResult:
       """Perform network discovery scan.
       
       Args:
           target: Network range or hostname to scan
           method: Scanning method (ping, arp, nmap)
           
       Returns:
           NetworkResult object with discovered hosts
           
       Raises:
           ValueError: If target format is invalid
           NetworkError: If scanning fails
       """
   ```

2. **Module documentation** with examples
3. **README updates** for user-facing changes
4. **Changelog entries** for all changes

### Architecture Guidelines

1. **Modular design** with clear separation of concerns
2. **Base classes** for consistent interfaces
3. **Configuration management** through structured config
4. **Error handling** with custom exception classes
5. **Logging** with structured format and correlation IDs

## Testing Requirements

### Test Categories

1. **Unit Tests** - Test individual functions and classes
   ```python
   def test_parse_target_valid_ip():
       """Test target parsing with valid IP address."""
       result = parse_target("192.168.1.1")
       assert result.target_type == "ip"
       assert result.ip_addresses == ["192.168.1.1"]
   ```

2. **Integration Tests** - Test module interactions
   ```python
   @pytest.mark.integration
   def test_network_discovery_integration():
       """Test network discovery with real tools."""
       # Test with actual network tools
   ```

3. **Mock Tests** - Test external tool integration
   ```python
   @patch('subprocess.run')
   def test_nmap_scanner_mock(mock_run):
       """Test nmap scanner with mocked subprocess."""
       mock_run.return_value.stdout = sample_nmap_output
       # Test logic
   ```

### Test Coverage

- **Minimum 80% code coverage**
- **All public functions tested**
- **Error conditions covered**
- **Edge cases included**

### Running Tests

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests (requires tools)
pytest tests/integration/ -v

# All tests with coverage
pytest tests/ -v --cov=brs_recon --cov-report=html

# Specific test file
pytest tests/unit/core/test_models.py -v

# Specific test function
pytest tests/unit/core/test_models.py::TestScanResult::test_scan_result_creation -v
```

## Security Considerations

### Security Review Process

1. **Threat modeling** for new features
2. **Input validation** for all user inputs
3. **Output sanitization** for all exports
4. **Privilege analysis** for system operations
5. **Dependency scanning** for vulnerabilities

### Common Security Issues

1. **Command Injection**
   ```python
   # BAD
   subprocess.run(f"nmap {user_input}")
   
   # GOOD
   subprocess.run(["nmap", validated_target])
   ```

2. **Path Traversal**
   ```python
   # BAD
   open(f"results/{filename}")
   
   # GOOD
   safe_path = Path("results") / Path(filename).name
   open(safe_path)
   ```

3. **Privilege Escalation**
   ```python
   # Check capabilities before operations
   if not has_capability("CAP_NET_RAW"):
       raise PermissionError("Raw socket access required")
   ```

### Security Testing

```bash
# Security linting
bandit -r brs-recon/

# Dependency scanning
safety check

# Container scanning
docker run --rm -v $(pwd):/app aquasec/trivy fs /app
```

## Release Process

### Version Management

We use semantic versioning (SemVer):
- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
- **Major** - Breaking changes
- **Minor** - New features (backward compatible)
- **Patch** - Bug fixes (backward compatible)

### Release Checklist

1. **Update version** in pyproject.toml
2. **Update CHANGELOG.md** with new features and fixes
3. **Run full test suite** and security scans
4. **Create release branch** and PR
5. **Tag release** after merge
6. **Publish to PyPI** (maintainers only)
7. **Update Docker images** (automated)

## Community

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and ideas
- **Telegram** - Direct contact with maintainers
- **Pull Requests** - Code review and collaboration

### Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md** file
- **GitHub contributor stats**
- **Release notes** for significant contributions
- **Security hall of fame** for vulnerability reports

---

Thank you for contributing to BRS-RECON! Your contributions help make cybersecurity tools more accessible and reliable for the community.
