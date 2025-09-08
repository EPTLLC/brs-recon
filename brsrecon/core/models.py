"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ScanResult:
    """Base scan result structure"""

    timestamp: str
    target: str
    scan_type: str
    status: str
    data: Dict[str, Any]
    duration: float = 0.0
    error: Optional[str] = None
