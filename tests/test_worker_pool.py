"""Tests for src/worker_pool.py."""

from pathlib import Path

from src.worker_pool import WorkerPool


def _noop(_input_path: Path, _output_path: Path) -> None:
    """Decrypt function that does nothing (success)."""


def _fail(_input_path: Path, _output_path: Path) -> None:
    """Decrypt function that always raises."""
    raise RuntimeError("simulated decryption failure")


class TestWorkerPool:
    def test_success_moves_to_processed(self, tmp_path):
        input_dir = tmp_path / "input"
        processed_dir = tmp_path / "processed"
        error_dir = tmp_path / "error"
        output_dir = tmp_path / "output"

        input_dir.mkdir()
        pgp_file = input_dir / "test.pgp"
        pgp_file.write_bytes(b"fake pgp content")

        with WorkerPool(_noop, output_dir, processed_dir, error_dir, workers=1) as pool:
            future = pool.submit(pgp_file)
            future.result(timeout=5)

        assert (processed_dir / "test.pgp").exists()
        assert not pgp_file.exists()

    def test_failure_moves_to_error(self, tmp_path):
        input_dir = tmp_path / "input"
        processed_dir = tmp_path / "processed"
        error_dir = tmp_path / "error"
        output_dir = tmp_path / "output"

        input_dir.mkdir()
        pgp_file = input_dir / "test.pgp"
        pgp_file.write_bytes(b"fake pgp content")

        with WorkerPool(_fail, output_dir, processed_dir, error_dir, workers=1) as pool:
            future = pool.submit(pgp_file)
            future.result(timeout=5)

        assert (error_dir / "test.pgp").exists()
        assert not pgp_file.exists()

    def test_output_dir_created(self, tmp_path):
        output_dir = tmp_path / "output"
        processed_dir = tmp_path / "processed"
        error_dir = tmp_path / "error"

        pgp_file = tmp_path / "sample.pgp"
        pgp_file.write_bytes(b"x")

        with WorkerPool(_noop, output_dir, processed_dir, error_dir, workers=1) as pool:
            future = pool.submit(pgp_file)
            future.result(timeout=5)

        assert output_dir.exists()

    def test_concurrent_submissions(self, tmp_path):
        processed_dir = tmp_path / "processed"
        output_dir = tmp_path / "output"
        error_dir = tmp_path / "error"

        files = []
        for i in range(10):
            f = tmp_path / f"file_{i}.pgp"
            f.write_bytes(b"x")
            files.append(f)

        with WorkerPool(_noop, output_dir, processed_dir, error_dir, workers=4) as pool:
            futures = [pool.submit(f) for f in files]
            for fut in futures:
                fut.result(timeout=10)

        assert len(list(processed_dir.iterdir())) == 10
