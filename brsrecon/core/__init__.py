"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

# Core components
from .base import BaseModule, ScanConfig
from .config import BRSConfig, get_config, load_config_from_file
from .export import ExportManager
from .logger import get_logger
from .models import ScanResult
from .results import ResultsManager
from .utils import format_timestamp, validate_target


def get_system_info():
    import platform

    return {
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "python_version": platform.python_version(),
    }


def get_network_interfaces():
    import psutil

    return list(psutil.net_if_addrs().keys())


__all__ = [
    "BaseModule",
    "ScanConfig",
    "BRSConfig",
    "get_config",
    "get_logger",
    "ScanResult",
    "ResultsManager",
    "ExportManager",
    "validate_target",
    "format_timestamp",
    "load_config_from_file",
]
