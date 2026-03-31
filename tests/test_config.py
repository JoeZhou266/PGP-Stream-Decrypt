"""Tests for src/config.py."""

from pathlib import Path

from src.config import Config


class TestConfigDefaults:
    def test_default_input_dir(self, tmp_path):
        cfg = Config(str(tmp_path / "nonexistent.properties"))
        assert cfg.input_dir == Path("pgps/input")

    def test_default_workers(self, tmp_path):
        cfg = Config(str(tmp_path / "nonexistent.properties"))
        assert cfg.workers == 4

    def test_default_log_level(self, tmp_path):
        cfg = Config(str(tmp_path / "nonexistent.properties"))
        assert cfg.log_level == "INFO"


class TestConfigOverride:
    def _write(self, path: Path, content: str) -> str:
        path.write_text(content)
        return str(path)

    def test_workers_override(self, tmp_path):
        cfg_file = self._write(tmp_path / "c.properties", "[pool]\nworkers = 8\n")
        cfg = Config(cfg_file)
        assert cfg.workers == 8

    def test_log_level_override(self, tmp_path):
        cfg_file = self._write(tmp_path / "c.properties", "[logging]\nlevel = DEBUG\n")
        cfg = Config(cfg_file)
        assert cfg.log_level == "DEBUG"

    def test_passphrase_empty(self, tmp_path):
        cfg_file = self._write(tmp_path / "c.properties", "[decryption]\npassphrase =\n")
        cfg = Config(cfg_file)
        assert cfg.passphrase == b""

    def test_passphrase_set(self, tmp_path):
        cfg_file = self._write(tmp_path / "c.properties", "[decryption]\npassphrase = secret\n")
        cfg = Config(cfg_file)
        assert cfg.passphrase == b"secret"

    def test_path_properties_return_path_objects(self, tmp_path):
        cfg = Config(str(tmp_path / "nonexistent.properties"))
        assert isinstance(cfg.input_dir, Path)
        assert isinstance(cfg.output_dir, Path)
        assert isinstance(cfg.processed_dir, Path)
        assert isinstance(cfg.error_dir, Path)
        assert isinstance(cfg.log_dir, Path)
