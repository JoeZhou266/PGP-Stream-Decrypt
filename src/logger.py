"""Logging setup: rotating daily file handler + optional console output."""

import logging
import logging.handlers
from pathlib import Path


def setup_logger(
    log_dir: Path,
    level: str = "INFO",
    console: bool = True,
) -> logging.Logger:
    """Configure the root logger with a daily rotating file handler.

    Args:
        log_dir: Directory where log files are written.
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
        console: Whether to also emit to stdout.

    Returns:
        The configured root logger.
    """
    log_dir.mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove pre-existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    # Daily rotating file — keeps 30 days of logs
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_dir / "pgp_stream_decrypt.log",
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

    return root
