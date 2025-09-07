"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

__version__ = "0.0.1"
__author__ = "brabus"
__license__ = "GPLv3"
__copyright__ = "Copyright 2025 EasyProTech LLC"

# Import main components for easy access
from .core.config import BRSConfig, get_config
from .core.logger import get_logger
from .core.results import ResultsManager
from .main import main

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "__copyright__",
    "BRSConfig",
    "get_config",
    "get_logger", 
    "ResultsManager",
    "main",
]
