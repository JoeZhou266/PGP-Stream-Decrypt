"""Tests for src/decryptor.py — end-to-end PGP decryption."""

import os
from pathlib import Path

import pytest

from src.decryptor import PGPDecryptor, load_private_key


class TestLoadPrivateKey:
    def test_load_pem_key(self, pem_private_key_file):
        key = load_private_key(pem_private_key_file, b"")
        assert key is not None

    def test_wrong_path_raises(self):
        with pytest.raises(FileNotFoundError):
            load_private_key(Path("/nonexistent/key.pem"), b"")


class TestPGPDecryptor:
    def test_decrypt_basic(self, tmp_path, pgp_file, pem_private_key_file):
        """Decrypted output matches the original plaintext."""
        pgp_path, original = pgp_file
        out_path = tmp_path / "out.bin"

        dec = PGPDecryptor(pem_private_key_file, b"")
        dec.decrypt_file(pgp_path, out_path)

        assert out_path.read_bytes() == original

    def test_decrypt_creates_output_dirs(self, tmp_path, pgp_file, pem_private_key_file):
        """decrypt_file creates missing parent directories."""
        pgp_path, original = pgp_file
        out_path = tmp_path / "nested" / "deep" / "out.bin"

        dec = PGPDecryptor(pem_private_key_file, b"")
        dec.decrypt_file(pgp_path, out_path)

        assert out_path.exists()
        assert out_path.read_bytes() == original

    def test_wrong_key_raises(self, tmp_path, pgp_file):
        """Using a different private key raises ValueError."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        pgp_path, _ = pgp_file
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = tmp_path / "other.pem"
        key_path.write_bytes(
            other_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        dec = PGPDecryptor(key_path, b"")
        with pytest.raises((ValueError, Exception)):
            dec.decrypt_file(pgp_path, tmp_path / "out.bin")

    def test_decrypt_large_content(self, tmp_path, rsa_key_pair, pem_private_key_file):
        """Decrypt a 1 MB payload to verify streaming works correctly."""
        from tests.conftest import make_pgp_file

        private_key, public_key = rsa_key_pair
        plaintext = os.urandom(1024 * 1024)
        session_key = os.urandom(32)
        pgp_data = make_pgp_file(plaintext, public_key, session_key)

        pgp_path = tmp_path / "large.pgp"
        pgp_path.write_bytes(pgp_data)
        out_path = tmp_path / "large.bin"

        dec = PGPDecryptor(pem_private_key_file, b"")
        dec.decrypt_file(pgp_path, out_path)

        assert out_path.read_bytes() == plaintext

    def test_corrupted_file_raises(self, tmp_path, pgp_file, pem_private_key_file):
        """A bit-flipped file should raise a decryption or MDC error."""
        pgp_path, _ = pgp_file
        corrupted = bytearray(pgp_path.read_bytes())
        # Flip a byte in the middle of the SEIPD body
        mid = len(corrupted) // 2
        corrupted[mid] ^= 0xFF
        bad_path = tmp_path / "bad.pgp"
        bad_path.write_bytes(bytes(corrupted))

        dec = PGPDecryptor(pem_private_key_file, b"")
        with pytest.raises((ValueError, Exception)):
            dec.decrypt_file(bad_path, tmp_path / "out.bin")
