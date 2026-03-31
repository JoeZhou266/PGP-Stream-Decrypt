"""Thread pool that decrypts PGP files concurrently."""

import logging
import shutil
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)


class WorkerPool:
    """Manages a pool of worker threads that decrypt PGP files.

    Args:
        decrypt_fn: Callable(input_path, output_path) that performs decryption.
        output_dir: Directory where decrypted files are written.
        processed_dir: Successful originals are moved here.
        error_dir: Failed originals are moved here.
        workers: Number of concurrent threads.
    """

    def __init__(
        self,
        decrypt_fn: Callable[[Path, Path], None],
        output_dir: Path,
        processed_dir: Path,
        error_dir: Path,
        workers: int = 4,
    ) -> None:
        self._decrypt = decrypt_fn
        self._output_dir = output_dir
        self._processed_dir = processed_dir
        self._error_dir = error_dir
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pgp-worker")

    def submit(self, input_path: Path) -> Future:
        """Submit *input_path* for decryption.  Returns a Future."""
        log.debug("Submitting %s", input_path.name)
        return self._executor.submit(self._process, input_path)

    def _process(self, input_path: Path) -> None:
        """Worker task: decrypt then move the original to processed or error."""
        # Determine output path (strip .pgp / .gpg suffix if present)
        stem = input_path.stem if input_path.suffix.lower() in (".pgp", ".gpg") else input_path.name
        output_path = self._output_dir / stem

        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            self._decrypt(input_path, output_path)
            self._move(input_path, self._processed_dir)
            log.info("Processed: %s", input_path.name)
        except Exception:
            log.exception("Error processing %s", input_path.name)
            self._move(input_path, self._error_dir)

    def _move(self, src: Path, dest_dir: Path) -> None:
        """Move *src* into *dest_dir*, overwriting if a same-named file exists."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        try:
            shutil.move(str(src), str(dest))
        except Exception:
            log.exception("Failed to move %s → %s", src, dest)

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the thread pool gracefully."""
        log.info("Shutting down worker pool")
        self._executor.shutdown(wait=wait)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()
