"""Entry point for PGP Stream Decrypt.

Usage:
    python src/main.py
    python src/main.py --config config.properties
    python src/main.py --workers 8 --log-level DEBUG
"""

import argparse
import logging
import sys
from pathlib import Path

# Allow running as `python src/main.py` from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config  # noqa: E402
from src.decryptor import PGPDecryptor  # noqa: E402
from src.logger import setup_logger  # noqa: E402
from src.watcher import FileWatcher  # noqa: E402
from src.worker_pool import WorkerPool  # noqa: E402

log = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch a directory and decrypt incoming PGP files."
    )
    parser.add_argument(
        "--config",
        default="config.properties",
        help="Path to the properties file (default: config.properties)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Override thread pool size from config",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override log level from config",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    cfg = Config(args.config)

    log_level = args.log_level or cfg.log_level
    setup_logger(cfg.log_dir, log_level)

    log.info("Starting PGP Stream Decrypt")
    log.info("Config: %s", args.config)

    try:
        decryptor = PGPDecryptor(cfg.private_key_path, cfg.passphrase)
    except Exception:
        log.exception("Failed to load private key from %s", cfg.private_key_path)
        sys.exit(1)

    workers = args.workers or cfg.workers

    with WorkerPool(
        decrypt_fn=decryptor.decrypt_file,
        output_dir=cfg.output_dir,
        processed_dir=cfg.processed_dir,
        error_dir=cfg.error_dir,
        workers=workers,
    ) as pool:
        watcher = FileWatcher(cfg.input_dir, pool)
        log.info("Pool size: %d workers", workers)
        log.info("Press Ctrl-C to stop")
        watcher.run_forever()

    log.info("PGP Stream Decrypt stopped")


if __name__ == "__main__":
    main()
