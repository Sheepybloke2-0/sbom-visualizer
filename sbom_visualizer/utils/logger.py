"""
Logging configuration for SBOM Visualizer.
"""

import logging
import sys
from typing import Optional


def setup_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    use_colors: bool = True,
) -> None:
    """
    Setup logging configuration for the application.

    Args:
        level: Logging level
        format_string: Custom format string
        use_colors: Whether to use colored output
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Create formatter
    if use_colors:
        formatter = ColoredFormatter(format_string)
    else:
        formatter = logging.Formatter(format_string)

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for different log levels."""

    # Color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Get the original formatted message
        formatted = super().format(record)

        # Add color if available for this level
        level_name = record.levelname
        if level_name in self.COLORS:
            formatted = f"{self.COLORS[level_name]}{formatted}{self.COLORS['RESET']}"

        return formatted
