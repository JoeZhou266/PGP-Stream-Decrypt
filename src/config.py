"""Application configuration loader from a .properties (INI) file."""

import configparser
from pathlib import Path


class Config:
    """Reads config.properties and exposes typed accessors with defaults."""

    _DEFAULTS = {
        "paths": {
            "input_dir": "pgps/input",
            "output_dir": "pgps/output",
            "processed_dir": "pgps/processed",
            "error_dir": "pgps/error",
        },
        "decryption": {
            "private_key_path": "",
            "passphrase": "",
        },
        "pool": {
            "workers": "4",
        },
        "logging": {
            "level": "INFO",
            "log_dir": "log",
        },
    }

    def __init__(self, config_path: str = "config.properties") -> None:
        self._parser = configparser.ConfigParser()
        # Populate defaults
        for section, values in self._DEFAULTS.items():
            self._parser[section] = values
        self._parser.read(config_path)

    # ── paths ──────────────────────────────────────────────────────────────

    @property
    def input_dir(self) -> Path:
        return Path(self._parser.get("paths", "input_dir"))

    @property
    def output_dir(self) -> Path:
        return Path(self._parser.get("paths", "output_dir"))

    @property
    def processed_dir(self) -> Path:
        return Path(self._parser.get("paths", "processed_dir"))

    @property
    def error_dir(self) -> Path:
        return Path(self._parser.get("paths", "error_dir"))

    # ── decryption ─────────────────────────────────────────────────────────

    @property
    def private_key_path(self) -> Path:
        return Path(self._parser.get("decryption", "private_key_path"))

    @property
    def passphrase(self) -> bytes:
        raw = self._parser.get("decryption", "passphrase").strip()
        return raw.encode() if raw else b""

    # ── pool ───────────────────────────────────────────────────────────────

    @property
    def workers(self) -> int:
        return self._parser.getint("pool", "workers")

    # ── logging ────────────────────────────────────────────────────────────

    @property
    def log_level(self) -> str:
        return self._parser.get("logging", "level").upper()

    @property
    def log_dir(self) -> Path:
        return Path(self._parser.get("logging", "log_dir"))
