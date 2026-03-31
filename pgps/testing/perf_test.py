"""Performance test: generate, encrypt, and decrypt a 1.5 GB PGP file.

Run from the project root:
    python pgps/testing/perf_test.py

Requirements:
  - pgps/testing/private_key.pem must exist (run generate_test_data.py first)
  - ~4.5 GB free disk space (plaintext + .pgp + decrypted output)

What this script does:
  1. Generates a 1.5 GB plaintext file using fast pseudo-random data.
  2. Stream-encrypts it to a .pgp file (RFC 4880: RSA-2048 + AES-256-CFB).
  3. Decrypts the .pgp file using PGPDecryptor.
  4. Verifies byte-for-byte correctness via streaming SHA-256 comparison.
  5. Reports throughput for both encryption and decryption.
"""

import hashlib
import os
import struct
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.decryptor import PGPDecryptor

TESTING_DIR = Path(__file__).parent
TARGET_SIZE = int(1.5 * 1024 * 1024 * 1024)  # 1.5 GiB
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB I/O chunks
SYM_AES256 = 9


# ══════════════════════════════════════════════════════════════════════════════
# Streaming PGP encryption helpers
# ══════════════════════════════════════════════════════════════════════════════

def _ecb_encrypt(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _write_mpi(value: int) -> bytes:
    bit_len = value.bit_length() or 1
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + value.to_bytes(byte_len, "big")


def _new_format_packet(tag: int, body: bytes) -> bytes:
    """Encode a small new-format packet (body fits in memory)."""
    n = len(body)
    if n < 192:
        lb = bytes([n])
    elif n < 8384:
        n2 = n - 192
        lb = bytes([(n2 >> 8) + 192, n2 & 0xFF])
    else:
        lb = bytes([0xFF]) + struct.pack(">I", n)
    return bytes([0xC0 | tag]) + lb + body


def _new_format_packet_header(tag: int, body_len: int) -> bytes:
    """Return only the packet header bytes (tag + length encoding)."""
    if body_len < 192:
        lb = bytes([body_len])
    elif body_len < 8384:
        n = body_len - 192
        lb = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        lb = bytes([0xFF]) + struct.pack(">I", body_len)
    return bytes([0xC0 | tag]) + lb


def _build_pkesk(public_key, session_key: bytes, sym_algo: int) -> bytes:
    """PKESK v3, RSA / PKCS#1 v1.5."""
    checksum = sum(session_key) & 0xFFFF
    plaintext = bytes([sym_algo]) + session_key + struct.pack(">H", checksum)
    enc_int = int.from_bytes(
        public_key.encrypt(plaintext, asym_padding.PKCS1v15()), "big"
    )
    return bytes([3]) + b"\x00" * 8 + bytes([1]) + _write_mpi(enc_int)


def stream_encrypt_to_pgp(
    plaintext_path: Path,
    pgp_path: Path,
    public_key,
    session_key: bytes,
) -> None:
    """Stream-encrypt *plaintext_path* into *pgp_path* (RFC 4880 PKESK + SEIPD).

    Never loads the full plaintext into memory — reads in CHUNK_SIZE increments.
    The encrypted output is streamed directly to disk as it is produced.
    """
    block_size = 16
    fname_bytes = plaintext_path.name[:255].encode()
    plaintext_size = plaintext_path.stat().st_size

    # Pre-compute packet sizes so we can write correct headers upfront
    lit_header_size = 1 + 1 + len(fname_bytes) + 4   # fmt + fnlen + fname + ts
    lit_body_size = lit_header_size + plaintext_size
    lit_pkt_size = 5 + lit_body_size                  # old-format tag(1) + len(4) + body

    mdc_size = 22                                     # 0xD3 0x14 + 20-byte SHA-1
    inner_size = lit_pkt_size + mdc_size              # content inside SEIPD encryption
    seipd_body_size = 1 + (block_size + 2) + inner_size  # version + prefix + enc data

    # ── write PKESK ──────────────────────────────────────────────────────────
    pkesk_body = _build_pkesk(public_key, session_key, SYM_AES256)
    pkesk_pkt = _new_format_packet(1, pkesk_body)

    with open(pgp_path, "wb") as out:
        out.write(pkesk_pkt)

        # ── SEIPD packet header + version byte ──────────────────────────────
        out.write(_new_format_packet_header(18, seipd_body_size))
        out.write(bytes([1]))  # SEIPD version 1

        # ── OpenPGP CFB prefix ───────────────────────────────────────────────
        prefix = os.urandom(block_size)
        quick_check = prefix[-2:]

        fre = _ecb_encrypt(session_key, bytes(block_size))
        enc_prefix = bytes(a ^ b for a, b in zip(prefix, fre))
        fre2 = _ecb_encrypt(session_key, enc_prefix)
        enc_qc = bytes([quick_check[0] ^ fre2[0], quick_check[1] ^ fre2[1]])

        out.write(enc_prefix)
        out.write(enc_qc)

        # Phase-2 IV: ciphertext bytes [2:18]
        iv2 = (enc_prefix + enc_qc)[2:18]
        encryptor = Cipher(algorithms.AES(session_key), modes.CFB(iv2)).encryptor()

        # ── Start SHA-1 for MDC ──────────────────────────────────────────────
        sha1 = hashlib.sha1()
        sha1.update(prefix + quick_check)  # prefix plaintext contributes to MDC

        # ── Literal Data packet header (old-format, 4-byte length) ──────────
        lit_pkt_hdr = (
            bytes([0x80 | (11 << 2) | 0x02])   # old-format tag 11, 4-byte len
            + struct.pack(">I", lit_body_size)
            + bytes([ord("b"), len(fname_bytes)])  # format='b', fname length
            + fname_bytes
            + struct.pack(">I", 0)               # timestamp = 0
        )
        sha1.update(lit_pkt_hdr)
        out.write(encryptor.update(lit_pkt_hdr))

        # ── Stream plaintext ─────────────────────────────────────────────────
        with open(plaintext_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha1.update(chunk)
                out.write(encryptor.update(chunk))

        # ── MDC packet ───────────────────────────────────────────────────────
        mdc_header = bytes([0xD3, 0x14])
        sha1.update(mdc_header)
        mdc_pkt = mdc_header + sha1.digest()
        out.write(encryptor.update(mdc_pkt))
        out.write(encryptor.finalize())


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def generate_plaintext(path: Path, size: int) -> None:
    """Write *size* bytes of fast pseudo-random data to *path*."""
    seed_block = os.urandom(CHUNK_SIZE)  # 4 MB random seed — repeated
    written = 0
    with open(path, "wb") as f:
        while written < size:
            remaining = size - written
            chunk = seed_block[:min(CHUNK_SIZE, remaining)]
            f.write(chunk)
            written += len(chunk)
            if written % (256 * 1024 * 1024) == 0 or written == size:
                pct = written * 100 // size
                print(f"\r  {pct:3d}% ({written // 1024 // 1024} MB / {size // 1024 // 1024} MB)", end="", flush=True)
    print()


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of *path* without loading it into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _fmt(size_bytes: int, elapsed: float) -> str:
    mb = size_bytes / 1024 / 1024
    return f"{mb:.1f} MB in {elapsed:.2f}s = {mb / elapsed:.1f} MB/s"


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    key_path = TESTING_DIR / "private_key.pem"
    plaintext_path = TESTING_DIR / "perf_1500MB.bin"
    pgp_path = TESTING_DIR / "perf_1500MB.bin.pgp"
    output_path = PROJECT_ROOT / "pgps" / "output" / "perf_1500MB.bin"

    # ── 0. Load / generate keys ───────────────────────────────────────────────
    if key_path.exists():
        print(f"Using existing private key: {key_path}")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(key_path.read_bytes(), password=None)
        public_key = private_key.public_key()
    else:
        print("Generating RSA-2048 key pair (run generate_test_data.py first)...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        print(f"  Saved: {key_path}")

    session_key = os.urandom(32)  # AES-256

    # ── 1. Generate plaintext ─────────────────────────────────────────────────
    if plaintext_path.exists():
        print(f"\nPlaintext already exists ({plaintext_path.stat().st_size // 1024 // 1024} MB), skipping generation.")
    else:
        size_mb = TARGET_SIZE // 1024 // 1024
        print(f"\n[1/4] Generating {size_mb} MB plaintext -> {plaintext_path.name}")
        t0 = time.perf_counter()
        generate_plaintext(plaintext_path, TARGET_SIZE)
        elapsed = time.perf_counter() - t0
        print(f"  Generated: {_fmt(TARGET_SIZE, elapsed)}")

    # ── 2. Encrypt ────────────────────────────────────────────────────────────
    print(f"\n[2/4] Encrypting -> {pgp_path.name}")
    t0 = time.perf_counter()
    stream_encrypt_to_pgp(plaintext_path, pgp_path, public_key, session_key)
    enc_elapsed = time.perf_counter() - t0
    pgp_size = pgp_path.stat().st_size
    print(f"  Encrypted: {_fmt(pgp_size, enc_elapsed)}")
    print(f"  PGP file size: {pgp_size / 1024 / 1024:.1f} MB")

    # ── 3. Decrypt ────────────────────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"\n[3/4] Decrypting -> {output_path.name}")
    decryptor = PGPDecryptor(key_path, b"")
    t0 = time.perf_counter()
    decryptor.decrypt_file(pgp_path, output_path)
    dec_elapsed = time.perf_counter() - t0
    out_size = output_path.stat().st_size
    print(f"  Decrypted: {_fmt(out_size, dec_elapsed)}")

    # ── 4. Verify ─────────────────────────────────────────────────────────────
    print(f"\n[4/4] Verifying SHA-256 (streaming)...")
    t0 = time.perf_counter()
    orig_hash = sha256_file(plaintext_path)
    out_hash = sha256_file(output_path)
    verify_elapsed = time.perf_counter() - t0

    if orig_hash == out_hash:
        print(f"  MATCH  sha256={orig_hash[:16]}...  ({verify_elapsed:.1f}s)")
    else:
        print(f"  MISMATCH!")
        print(f"  Original:  {orig_hash}")
        print(f"  Decrypted: {out_hash}")
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    size_mb = TARGET_SIZE / 1024 / 1024
    enc_mbs = pgp_size / 1024 / 1024 / enc_elapsed
    dec_mbs = out_size / 1024 / 1024 / dec_elapsed
    print("\n=== Performance Summary ===")
    print(f"  File size : {size_mb:.1f} MB")
    print(f"  Encrypt   : {enc_mbs:.1f} MB/s  ({enc_elapsed:.2f}s)")
    print(f"  Decrypt   : {dec_mbs:.1f} MB/s  ({dec_elapsed:.2f}s)")
    print(f"  Verify    : OK (SHA-256 match)")
    print("===========================")


if __name__ == "__main__":
    main()
