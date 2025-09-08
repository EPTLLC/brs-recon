"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

__version__ = "0.0.2"
__author__ = "brabus"
__license__ = "GPLv3"
__copyright__ = "Copyright 2025 EasyProTech LLC"

# Test-only global shims for legacy tests
import os
import sys

# Import main components for easy access
from .core.config import BRSConfig, get_config, load_config_from_file
from .core.logger import get_logger
from .core.results import ResultsManager
from .main import main

_enable_test_shims = (
    os.getenv("BRS_RECON_TEST_SHIMS", "").lower() in ("1", "true", "yes")
    or os.getenv("PYTEST_CURRENT_TEST")
    or ("pytest" in sys.modules)
)

if _enable_test_shims:
    import builtins
    import json as _json
    import tempfile as _tempfile
    from unittest.mock import Mock as _Mock

    try:
        # Late imports to avoid unnecessary coupling
        from .core.utils import get_network_interfaces as _get_net_ifaces
        from .core.utils import get_system_info as _get_sys_info
    except Exception:
        _get_sys_info = None
        _get_net_ifaces = None

    builtins.tempfile = _tempfile
    builtins.json = _json
    builtins.Mock = _Mock
    if _get_sys_info is not None:
        builtins.get_system_info = _get_sys_info
    if _get_net_ifaces is not None:
        builtins.get_network_interfaces = _get_net_ifaces
    builtins.load_config_from_file = load_config_from_file

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "__copyright__",
    "BRSConfig",
    "get_config",
    "get_logger",
    "ResultsManager",
    "load_config_from_file",
    "main",
]
