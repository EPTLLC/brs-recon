# BRS-RECON Examples

**Project:** BRS-RECON (Network Reconnaissance Tool)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Date:** 2025-09-07  
**Status:** Created  
**Contact:** https://t.me/easyprotech

This directory contains example outputs, schemas, and usage examples for BRS-RECON.

## Directory Structure

```
examples/
├── outputs/                    # Example output files
│   ├── network-discovery-example.json
│   ├── vulnerability-scan-example.sarif
│   └── scan-report-example.html
├── schemas/                    # JSON Schema files
│   ├── scan-result.schema.json
│   └── sarif-mapping.json
└── README.md                   # This file
```

## Example Outputs

### Network Discovery (`outputs/network-discovery-example.json`)
Complete example of network discovery scan results including:
- Discovered hosts with IP addresses and hostnames
- MAC addresses and vendor information
- Open ports and services
- Performance metrics and timing data
- Discovery method comparison (fping, ARP scan, nmap)

### Vulnerability Scan SARIF (`outputs/vulnerability-scan-example.sarif`)
SARIF 2.1.0 compliant vulnerability scan results featuring:
- Structured vulnerability findings
- CVSS scores and CWE mappings
- Multiple severity levels (high, medium, low)
- Tool metadata and run information
- Compliance with GitHub Security tab integration

### HTML Report (`outputs/scan-report-example.html`)
Professional HTML report template with:
- Responsive design and modern styling
- Interactive vulnerability details
- Network discovery results table
- Performance statistics dashboard
- Security warnings and compliance notices

## JSON Schemas

### Scan Result Schema (`schemas/scan-result.schema.json`)
Comprehensive JSON Schema for validating BRS-RECON scan results:
- Required and optional fields validation
- Data type constraints and formats
- Enum values for scan types and statuses
- Nested object validation for results and metadata

### SARIF Mapping (`schemas/sarif-mapping.json`)
Configuration schema for mapping BRS-RECON results to SARIF format:
- Tool information and metadata
- Rule definitions and mappings
- Severity level conversions
- Module-specific rule assignments

## Usage Examples

### Validating Output Files

```bash
# Validate JSON output against schema
python -c "
import json
import jsonschema

# Load schema and data
with open('examples/schemas/scan-result.schema.json') as f:
    schema = json.load(f)

with open('examples/outputs/network-discovery-example.json') as f:
    data = json.load(f)

# Validate
jsonschema.validate(data, schema)
print('✅ JSON validation passed!')
"

# Validate SARIF output
python -c "
import json

# Load and validate SARIF structure
with open('examples/outputs/vulnerability-scan-example.sarif') as f:
    sarif = json.load(f)

assert sarif['version'] == '2.1.0'
assert 'runs' in sarif
print('✅ SARIF validation passed!')
"
```

### Using Schemas in Your Code

```python
import json
import jsonschema
from pathlib import Path

# Load schema
schema_path = Path("examples/schemas/scan-result.schema.json")
with open(schema_path) as f:
    schema = json.load(f)

# Validate scan results
def validate_scan_result(result_data):
    try:
        jsonschema.validate(result_data, schema)
        return True
    except jsonschema.ValidationError as e:
        print(f"Validation error: {e}")
        return False

# Example usage
scan_result = {
    "scan_id": "test-123",
    "module": "network_discovery",
    "target": "192.168.1.0/24",
    "scan_type": "basic",
    "status": "completed",
    "start_time": "2025-09-07T18:45:00Z",
    "results": {"hosts_found": 5},
    "metadata": {"version": "0.0.1"}
}

if validate_scan_result(scan_result):
    print("✅ Scan result is valid!")
```

### Generating Custom Reports

```python
from jinja2 import Template
import json

# Load example data
with open('examples/outputs/network-discovery-example.json') as f:
    data = json.load(f)

# Simple report template
template = Template("""
# Network Discovery Report

**Target:** {{ data.target }}
**Scan Type:** {{ data.scan_type }}
**Duration:** {{ data.duration }}s
**Hosts Found:** {{ data.results.hosts_alive | length }}

## Discovered Hosts
{% for host in data.results.discovered_hosts %}
- **{{ host.ip_address }}** ({{ host.hostname or "Unknown" }})
  - MAC: {{ host.mac_address }}
  - Vendor: {{ host.vendor }}
  - Ports: {{ host.open_ports | join(", ") }}
{% endfor %}
""")

# Generate report
report = template.render(data=data)
print(report)
```

## Integration Examples

### GitHub Actions SARIF Upload

```yaml
- name: Run BRS-RECON Security Scan
  run: |
    brs-recon vuln ${{ matrix.target }} --scan-type comprehensive
    brs-recon export results/scans/latest.json --formats sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results/sarif/security-scan.sarif
```

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# ci-security-scan.sh

set -e

# Run comprehensive security assessment
brs-recon vuln "${TARGET_HOST}" \
    --scan-type comprehensive \
    --export-formats json sarif html

# Validate results
python -c "
import json
import sys

with open('results/scans/latest.json') as f:
    data = json.load(f)

if data['status'] != 'completed':
    print('❌ Scan did not complete successfully')
    sys.exit(1)

vuln_count = len(data.get('results', {}).get('vulnerabilities', []))
print(f'✅ Scan completed: {vuln_count} vulnerabilities found')
"

# Upload results to security dashboard
curl -X POST "${SECURITY_API_URL}/scans" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @results/json/security-scan.json
```

## Best Practices

### Schema Validation
- Always validate output data against schemas before processing
- Use schemas for API contract validation
- Implement schema versioning for backward compatibility

### Report Generation
- Use templates for consistent report formatting
- Include metadata and timestamps in all reports
- Implement responsive design for HTML reports

### SARIF Compliance
- Follow SARIF 2.1.0 specification strictly
- Include proper tool metadata and rule definitions
- Map vulnerability severity levels consistently

### Security Considerations
- Sanitize all output data to prevent injection attacks
- Validate file paths to prevent directory traversal
- Use secure templating engines with auto-escaping

## Contributing Examples

To contribute new examples:

1. **Follow naming conventions:** `{module}-{type}-example.{format}`
2. **Include comprehensive data:** Cover all major use cases
3. **Validate against schemas:** Ensure examples pass validation
4. **Add documentation:** Explain the example's purpose and usage
5. **Test integration:** Verify examples work in real scenarios

## Support

For questions about examples or schemas:
- Create an issue on GitHub
- Contact: https://t.me/easyprotech
- Check documentation: README.md
 