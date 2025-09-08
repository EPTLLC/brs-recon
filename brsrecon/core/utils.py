"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import re
import socket
import subprocess
from datetime import datetime
from typing import Optional, List, Union
from pathlib import Path
import ipaddress


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for file naming (YYYYMMDD-HHMMSS)"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y%m%d-%H%M%S")


def validate_ip(ip: str) -> bool:
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_network(network: str) -> bool:
    """Validate network CIDR notation"""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(domain)) and len(domain) <= 255


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> bool:
    """Validate port range (e.g., '80-443')"""
    if '-' not in port_range:
        return validate_port(port_range)
    
    try:
        start, end = port_range.split('-', 1)
        return validate_port(start) and validate_port(end) and int(start) <= int(end)
    except (ValueError, TypeError):
        return False


def validate_target(target: str) -> dict:
    """Validate and classify target type"""
    result = {
        'valid': False,
        'type': None,
        'target': target.strip()
    }
    
    target = target.strip()
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.hostname
            if domain and validate_domain(domain):
                result['valid'] = True
                result['type'] = 'url'
                result['domain'] = domain
                return result
        except:
            pass
    
    if validate_ip(target):
        result['valid'] = True
        result['type'] = 'ip'
    elif validate_network(target):
        result['valid'] = True
        result['type'] = 'network'
    elif validate_domain(target):
        result['valid'] = True
        result['type'] = 'domain'
    
    return result


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if port is open on host"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, socket.timeout):
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_local_ip() -> Optional[str]:
    """Get local IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def run_command(command: List[str], timeout: int = 30, capture_output: bool = True) -> dict:
    """Run system command with timeout"""
    result = {
        'success': False,
        'stdout': '',
        'stderr': '',
        'returncode': -1
    }
    
    try:
        process = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        
        result['success'] = process.returncode == 0
        result['stdout'] = process.stdout or ''
        result['stderr'] = process.stderr or ''
        result['returncode'] = process.returncode
        
    except subprocess.TimeoutExpired:
        result['stderr'] = f'Command timeout after {timeout} seconds'
    except subprocess.CalledProcessError as e:
        result['stderr'] = str(e)
    except Exception as e:
        result['stderr'] = f'Unexpected error: {str(e)}'
    
    return result


def check_tool_availability(tool: str) -> bool:
    """Check if external tool is available"""
    try:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure directory exists, create if not"""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    # Remove or replace problematic characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Limit length
    return filename[:255]


def parse_nmap_ports(port_string: str) -> List[int]:
    """Parse nmap-style port specification"""
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    return sorted(list(set(ports)))


def format_bytes(bytes_count: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"


def truncate_string(text: str, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate string to max length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix
