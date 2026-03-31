"""Shared pytest fixtures.

Generates a fresh RSA key pair and a minimal PGP-encrypted test file for each
test session.  The encryption logic mirrors exactly what generate_test_data.py
produces, ensuring the decryptor is tested end-to-end.
"""

import hashlib
import os
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ── PGP encryption helpers (mirrors generate_test_data.py) ────────────────────

def _write_mpi(value: int) -> bytes:
    """Encode an integer as an OpenPGP MPI."""
    bit_len = value.bit_length()
    if bit_len == 0:
        bit_len = 1
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + value.to_bytes(byte_len, "big")


def _old_format_packet(tag: int, body: bytes) -> bytes:
    """Encode an old-format PGP packet with a 4-byte length."""
    header = bytes([(0x80 | (tag << 2) | 0x02)])
    header += struct.pack(">I", len(body))
    return header + body


def _new_format_packet(tag: int, body: bytes) -> bytes:
    """Encode a new-format PGP packet."""
    if len(body) < 192:
        length_bytes = bytes([len(body)])
    elif len(body) < 8384:
        n = len(body) - 192
        length_bytes = bytes([((n >> 8) + 192), n & 0xFF])
    else:
        length_bytes = bytes([0xFF]) + struct.pack(">I", len(body))
    return bytes([0xC0 | tag]) + length_bytes + body


def _build_pkesk(public_key, session_key: bytes, sym_algo: int) -> bytes:
    """Build a PKESK packet body (version 3, RSA, PKCS#1 v1.5)."""
    # Plaintext for PKESK: [sym_algo][session_key][checksum]
    checksum = sum(session_key) & 0xFFFF
    plaintext = bytes([sym_algo]) + session_key + struct.pack(">H", checksum)

    encrypted = public_key.encrypt(plaintext, asym_padding.PKCS1v15())
    enc_int = int.from_bytes(encrypted, "big")

    body = bytes([3])            # version
    body += b"\x00" * 8          # key ID (use zeros → wildcard)
    body += bytes([1])            # RSA algorithm
    body += _write_mpi(enc_int)
    return body


def _openpgp_cfb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* using OpenPGP CFB mode (RFC 4880 §13.9).

    Produces: [encrypted prefix (18 bytes)] + [encrypted data]
    """
    block_size = 16  # AES

    # Generate random prefix
    prefix = os.urandom(block_size)
    # Quick-check bytes: repeat last 2 bytes of prefix
    quick_check = prefix[-2:]

    # ── phase 1: encrypt prefix ──────────────────────────────────────────────
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv0 = bytes(block_size)

    # Manually encrypt prefix with OpenPGP CFB
    def ecb_encrypt(block):
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    fre = ecb_encrypt(iv0)
    enc_prefix = bytes(a ^ b for a, b in zip(prefix, fre))

    fr = bytes(list(enc_prefix))
    fre = ecb_encrypt(fr)
    enc_qc = bytes([quick_check[0] ^ fre[0], quick_check[1] ^ fre[1]])

    # Resync: IV2 = enc_prefix[2:18] (first 16 bytes of encrypted prefix, offset by 2)
    iv2 = (enc_prefix + enc_qc)[2:18]

    # ── phase 2: encrypt actual data with standard CFB ───────────────────────
    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv2)).encryptor()
    enc_data = encryptor.update(plaintext) + encryptor.finalize()

    return enc_prefix + enc_qc + enc_data


def _build_literal_packet(data: bytes, filename: str = "test.bin") -> bytes:
    """Build a Literal Data packet body."""
    fname = filename.encode()
    body = bytes([ord("b"), len(fname)]) + fname + struct.pack(">I", 0) + data
    return body


def _build_seipd(session_key: bytes, plaintext_inner: bytes) -> bytes:
    """Build a SEIPD packet (version 1) body."""
    # Inner: literal packet
    literal_body = _build_literal_packet(plaintext_inner)
    literal_pkt = _old_format_packet(11, literal_body)

    # Compute MDC: SHA-1 of (prefix_plain + data + 0xD3 0x14)
    # We need to encrypt first to know the prefix_plain; use a two-pass approach
    # ── encrypt ──────────────────────────────────────────────────────────────
    block_size = 16

    prefix = os.urandom(block_size)
    quick_check = prefix[-2:]
    inner_plain = literal_pkt

    def ecb_encrypt(block):
        enc = Cipher(algorithms.AES(session_key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    fre = ecb_encrypt(bytes(block_size))
    enc_prefix = bytes(a ^ b for a, b in zip(prefix, fre))
    fre2 = ecb_encrypt(enc_prefix)
    enc_qc = bytes([quick_check[0] ^ fre2[0], quick_check[1] ^ fre2[1]])
    iv2 = (enc_prefix + enc_qc)[2:18]

    # MDC input: prefix_plain (16 bytes) + quick_check (2 bytes) + inner packets + 0xD3 0x14
    mdc_input = prefix + quick_check + inner_plain + bytes([0xD3, 0x14])
    mdc_hash = hashlib.sha1(mdc_input).digest()
    mdc_packet = bytes([0xD3, 0x14]) + mdc_hash

    # Encrypt (inner_plain + mdc_packet) with phase-2 CFB
    enc = Cipher(algorithms.AES(session_key), modes.CFB(iv2)).encryptor()
    enc_body = enc.update(inner_plain + mdc_packet) + enc.finalize()

    seipd_body = bytes([1]) + enc_prefix + enc_qc + enc_body
    return seipd_body


def make_pgp_file(plaintext: bytes, public_key, session_key: bytes, sym_algo: int = 9) -> bytes:
    """Produce a minimal RFC 4880 binary PGP file (PKESK + SEIPD)."""
    pkesk_body = _build_pkesk(public_key, session_key, sym_algo)
    seipd_body = _build_seipd(session_key, plaintext)

    pkesk_pkt = _new_format_packet(1, pkesk_body)
    seipd_pkt = _new_format_packet(18, seipd_body)
    return pkesk_pkt + seipd_pkt


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate a 2048-bit RSA key pair for the test session."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(scope="session")
def pem_private_key_file(rsa_key_pair, tmp_path_factory):
    """Write the PEM private key to a temp file and return its Path."""
    private_key, _ = rsa_key_pair
    pem_dir = tmp_path_factory.mktemp("keys")
    key_path = pem_dir / "private_key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key_path


@pytest.fixture
def plaintext() -> bytes:
    return b"Hello, PGP Stream Decrypt!\nThis is a test message.\n"


@pytest.fixture
def pgp_file(tmp_path, rsa_key_pair, plaintext):
    """Return (pgp_path, plaintext) for a freshly encrypted test file."""
    private_key, public_key = rsa_key_pair
    session_key = os.urandom(32)  # AES-256
    pgp_data = make_pgp_file(plaintext, public_key, session_key, sym_algo=9)
    pgp_path = tmp_path / "test.pgp"
    pgp_path.write_bytes(pgp_data)
    return pgp_path, plaintext
