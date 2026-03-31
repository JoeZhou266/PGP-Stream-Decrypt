"""File-system watcher that feeds PGP files from the input directory to the worker pool."""

import logging
import time
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger(__name__)

_PGP_EXTENSIONS = {".pgp", ".gpg", ".asc"}


class _PGPEventHandler(FileSystemEventHandler):
    """Handles file-created events and forwards PGP files to the pool."""

    def __init__(self, submit_fn) -> None:
        super().__init__()
        self._submit = submit_fn

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in _PGP_EXTENSIONS:
            log.info("Detected new file: %s", path.name)
            self._submit(path)


class FileWatcher:
    """Watches *watch_dir* for new PGP files and submits them to *pool*.

    Also performs a one-time scan of any files already in *watch_dir* at
    startup so that files dropped before the process starts are not missed.

    Args:
        watch_dir: Directory to monitor (pgps/input).
        pool: WorkerPool instance with a ``submit(path)`` method.
        poll_interval: Watchdog observer poll interval in seconds.
    """

    def __init__(self, watch_dir: Path, pool, poll_interval: float = 1.0) -> None:
        self._watch_dir = watch_dir
        self._pool = pool
        self._poll_interval = poll_interval
        self._observer = Observer()

    def start(self) -> None:
        """Start watching and process any pre-existing files."""
        self._watch_dir.mkdir(parents=True, exist_ok=True)

        # Process files already present in the input directory
        existing = [
            p for p in self._watch_dir.iterdir()
            if p.is_file() and p.suffix.lower() in _PGP_EXTENSIONS
        ]
        if existing:
            log.info("Found %d existing PGP file(s) in %s", len(existing), self._watch_dir)
            for path in existing:
                self._pool.submit(path)

        handler = _PGPEventHandler(self._pool.submit)
        self._observer.schedule(handler, str(self._watch_dir), recursive=False)
        self._observer.start()
        log.info("Watching %s for new PGP files", self._watch_dir)

    def stop(self) -> None:
        """Stop the file-system observer."""
        self._observer.stop()
        self._observer.join()
        log.info("File watcher stopped")

    def run_forever(self) -> None:
        """Block until interrupted (Ctrl-C / SIGTERM)."""
        self.start()
        try:
            while True:
                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
