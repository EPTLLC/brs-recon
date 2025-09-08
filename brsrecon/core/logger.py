"""
Project: BRS-RECON (Network Reconnaissance Tool)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 07 Sep 2025
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text


class BRSLogger:
    """Professional logging system for BRS-RECON"""

    def __init__(self, name: str = "brs-recon", log_level: str = "INFO"):
        self.name = name
        self.console = Console()
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Setup logging handlers"""
        # Rich console handler for beautiful output
        console_handler = RichHandler(
            console=self.console, show_time=True, show_path=False, rich_tracebacks=True
        )
        console_handler.setLevel(logging.INFO)

        # File handler for detailed logs
        log_dir = Path("results") / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = log_dir / f"brs-recon-{timestamp}.log"

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)

        # Formatters
        console_format = "%(message)s"
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        console_handler.setFormatter(logging.Formatter(console_format))
        file_handler.setFormatter(logging.Formatter(file_format))

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)

    def success(self, message: str, **kwargs):
        """Log success message"""
        text = Text(f"[SUCCESS] {message}", style="bold green")
        self.console.print(text)
        self.logger.info(f"SUCCESS: {message}", **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        text = Text(f"[WARNING] {message}", style="bold yellow")
        self.console.print(text)
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        text = Text(f"[ERROR] {message}", style="bold red")
        self.console.print(text)
        self.logger.error(message, **kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        text = Text(f"[CRITICAL] {message}", style="bold red on white")
        self.console.print(text)
        self.logger.critical(message, **kwargs)

    def scan_start(self, target: str, scan_type: str):
        """Log scan start"""
        text = Text(f"[SCAN] Starting {scan_type} scan on {target}", style="bold blue")
        self.console.print(text)
        self.logger.info(f"SCAN_START: {scan_type} on {target}")

    def scan_complete(
        self, target: str, scan_type: str, duration: float, results_count: int = 0
    ):
        """Log scan completion"""
        text = Text(
            f"[COMPLETE] {scan_type} scan completed on {target} "
            f"({duration:.2f}s, {results_count} results)",
            style="bold green",
        )
        self.console.print(text)
        self.logger.info(
            f"SCAN_COMPLETE: {scan_type} on {target} - {duration:.2f}s - {results_count} results"
        )

    def scan_error(self, target: str, scan_type: str, error: str):
        """Log scan error"""
        text = Text(
            f"[FAILED] {scan_type} scan failed on {target}: {error}", style="bold red"
        )
        self.console.print(text)
        self.logger.error(f"SCAN_ERROR: {scan_type} on {target} - {error}")

    def progress(self, message: str, current: int, total: int):
        """Log progress message"""
        percentage = (current / total) * 100 if total > 0 else 0
        text = Text(
            f"[PROGRESS] {message} ({current}/{total} - {percentage:.1f}%)",
            style="cyan",
        )
        self.console.print(text)
        self.logger.debug(f"PROGRESS: {message} - {current}/{total}")

    def tool_check(self, tool: str, available: bool):
        """Log tool availability check"""
        if available:
            text = Text(f"[TOOL] {tool} is available", style="green")
            self.logger.info(f"TOOL_CHECK: {tool} - available")
        else:
            text = Text(f"[TOOL] {tool} is not available", style="red")
            self.logger.warning(f"TOOL_CHECK: {tool} - not available")

        self.console.print(text)

    def result_saved(self, filename: str, result_type: str):
        """Log result file saved"""
        text = Text(
            f"[SAVED] {result_type} results saved to {filename}", style="bold cyan"
        )
        self.console.print(text)
        self.logger.info(f"RESULT_SAVED: {result_type} - {filename}")

    def banner(self, title: str):
        """Display banner"""
        self.console.rule(f"[bold blue]{title}[/bold blue]", style="blue")
        self.logger.info(f"BANNER: {title}")

    def separator(self):
        """Display separator"""
        self.console.print("─" * 80, style="dim")


# Global logger instance
_logger_instance: Optional[BRSLogger] = None


def get_logger(name: str = "brs-recon", log_level: str = "INFO") -> BRSLogger:
    """Get or create logger instance"""
    global _logger_instance

    if _logger_instance is None:
        _logger_instance = BRSLogger(name, log_level)

    return _logger_instance


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup logging configuration"""
    global _logger_instance
    _logger_instance = BRSLogger("brs-recon", log_level)
    return _logger_instance
