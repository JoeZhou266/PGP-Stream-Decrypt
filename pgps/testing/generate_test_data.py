"""Generate test PGP files for the development workflow.

Run from the project root:
    python pgps/testing/generate_test_data.py

Produces:
    pgps/testing/private_key.pem    — RSA-2048 private key (PEM, unprotected)
    pgps/testing/public_key.pem     — RSA-2048 public key (PEM)
    pgps/testing/sample.txt         — plaintext test file
    pgps/testing/sample.txt.pgp     — encrypted PGP file
    pgps/testing/large_sample.bin   — 5 MB random plaintext
    pgps/testing/large_sample.bin.pgp — encrypted large PGP file
"""

import hashlib
import os
import struct
import sys
from pathlib import Path

# Allow running from project root or from this directory
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TESTING_DIR = Path(__file__).parent
SYM_AES256 = 9


# ══════════════════════════════════════════════════════════════════════════════
# PGP packet builders (RFC 4880)
# ══════════════════════════════════════════════════════════════════════════════

def _write_mpi(value: int) -> bytes:
    bit_len = value.bit_length() or 1
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + value.to_bytes(byte_len, "big")


def _new_format_packet(tag: int, body: bytes) -> bytes:
    if len(body) < 192:
        length_bytes = bytes([len(body)])
    elif len(body) < 8384:
        n = len(body) - 192
        length_bytes = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        length_bytes = bytes([0xFF]) + struct.pack(">I", len(body))
    return bytes([0xC0 | tag]) + length_bytes + body


def _old_format_packet(tag: int, body: bytes) -> bytes:
    return bytes([0x80 | (tag << 2) | 0x02]) + struct.pack(">I", len(body)) + body


def _ecb_encrypt(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _build_pkesk(public_key, session_key: bytes, sym_algo: int) -> bytes:
    """PKESK v3, RSA / PKCS#1 v1.5."""
    checksum = sum(session_key) & 0xFFFF
    plaintext = bytes([sym_algo]) + session_key + struct.pack(">H", checksum)
    enc_int = int.from_bytes(
        public_key.encrypt(plaintext, asym_padding.PKCS1v15()), "big"
    )
    body = bytes([3]) + b"\x00" * 8 + bytes([1]) + _write_mpi(enc_int)
    return body


def _build_seipd(session_key: bytes, inner_plaintext: bytes) -> bytes:
    """SEIPD v1 with AES-256-CFB and MDC."""
    block_size = 16
    key = session_key

    # Random prefix + quick-check bytes
    prefix = os.urandom(block_size)
    quick_check = prefix[-2:]

    # Phase 1: encrypt prefix
    fre = _ecb_encrypt(key, bytes(block_size))
    enc_prefix = bytes(a ^ b for a, b in zip(prefix, fre))
    fre2 = _ecb_encrypt(key, enc_prefix)
    enc_qc = bytes([quick_check[0] ^ fre2[0], quick_check[1] ^ fre2[1]])

    # Phase 2 IV = enc_prefix[2:18]  (after enc_prefix + enc_qc are appended)
    iv2 = (enc_prefix + enc_qc)[2:18]

    # Compute MDC hash over plaintext
    mdc_header = bytes([0xD3, 0x14])
    mdc_input = prefix + quick_check + inner_plaintext + mdc_header
    mdc_hash = hashlib.sha1(mdc_input).digest()
    mdc_packet = mdc_header + mdc_hash

    # Encrypt inner plaintext + MDC with phase-2 CFB
    enc = Cipher(algorithms.AES(key), modes.CFB(iv2)).encryptor()
    enc_body = enc.update(inner_plaintext + mdc_packet) + enc.finalize()

    return bytes([1]) + enc_prefix + enc_qc + enc_body


def _build_literal_packet(data: bytes, filename: str) -> bytes:
    fname = filename.encode()
    return bytes([ord("b"), len(fname)]) + fname + struct.pack(">I", 0) + data


def encrypt_to_pgp(plaintext: bytes, public_key, filename: str = "data.bin") -> bytes:
    """Encrypt *plaintext* to a minimal binary PGP file."""
    session_key = os.urandom(32)  # AES-256

    literal_body = _build_literal_packet(plaintext, filename)
    literal_pkt = _old_format_packet(11, literal_body)

    pkesk_body = _build_pkesk(public_key, session_key, SYM_AES256)
    seipd_body = _build_seipd(session_key, literal_pkt)

    return _new_format_packet(1, pkesk_body) + _new_format_packet(18, seipd_body)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print("Generating RSA-2048 key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save keys
    priv_path = TESTING_DIR / "private_key.pem"
    pub_path = TESTING_DIR / "public_key.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"  Saved: {priv_path}")
    print(f"  Saved: {pub_path}")

    # Small plaintext file
    sample_text = (
        "Hello from PGP Stream Decrypt!\n"
        "This file was encrypted with RSA-2048 + AES-256.\n"
        "Line 3: testing 1, 2, 3...\n"
    ).encode()
    sample_path = TESTING_DIR / "sample.txt"
    sample_pgp_path = TESTING_DIR / "sample.txt.pgp"

    sample_path.write_bytes(sample_text)
    sample_pgp_path.write_bytes(encrypt_to_pgp(sample_text, public_key, "sample.txt"))
    print(f"  Saved: {sample_path}  ({len(sample_text)} bytes)")
    print(f"  Saved: {sample_pgp_path}")

    # Large binary file (5 MB)
    large_data = os.urandom(5 * 1024 * 1024)
    large_path = TESTING_DIR / "large_sample.bin"
    large_pgp_path = TESTING_DIR / "large_sample.bin.pgp"

    large_path.write_bytes(large_data)
    large_pgp_path.write_bytes(encrypt_to_pgp(large_data, public_key, "large_sample.bin"))
    print(f"  Saved: {large_path}  ({len(large_data) // 1024} KB)")
    print(f"  Saved: {large_pgp_path}")

    # Update config.properties to point to the generated private key
    config_path = project_root / "config.properties"
    if config_path.exists():
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(str(config_path))
        if not cfg.has_section("decryption"):
            cfg.add_section("decryption")
        cfg.set("decryption", "private_key_path", str(priv_path.relative_to(project_root)).replace("\\", "/"))
        cfg.set("decryption", "passphrase", "")
        with open(config_path, "w") as f:
            cfg.write(f)
        print(f"\nUpdated {config_path} with private_key_path.")

    print("\nDone.  Next steps:")
    print("  1. Copy pgps/testing/*.pgp to pgps/input/")
    print("  2. Run:  python src/main.py")
    print("  3. Check pgps/output/ and compare with pgps/testing/sample.txt etc.")


if __name__ == "__main__":
    main()
