"""PGP file decryption conforming to OpenPGP (RFC 4880).

Streaming implementation using the `cryptography` library — no pgpy, no gnupg.

Supported:
  - RSA public-key encrypted session key  (PKESK, packet tag 1)
  - AES-128 / AES-192 / AES-256 symmetric cipher (SEIPD, packet tag 18)
  - Compressed data: ZLIB, ZIP, uncompressed (packet tag 8)
  - Literal data (packet tag 11)
  - PEM or PGP ASCII-armored private keys

OpenPGP CFB note (RFC 4880 §13.9):
  The first (block_size + 2) bytes of SEIPD plaintext form a "prefix" that
  acts as the IV randomisation.  After that prefix there is a resync step
  that shifts the feedback register by 2 bytes.  This is implemented as:
    Phase-1: decrypt the 18-byte prefix with AES-CFB(IV=0)
    Phase-2: re-key AES-CFB with IV = ciphertext[2:18] and decrypt the rest
"""

import base64
import hashlib
import io
import logging
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

log = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

# ── PGP packet tags ────────────────────────────────────────────────────────────
PKT_PKESK = 1
PKT_SKESK = 3
PKT_COMPRESSED = 8
PKT_LITERAL = 11
PKT_SEIPD = 18
PKT_MDC = 19

# ── Public-key algorithm IDs ───────────────────────────────────────────────────
PK_RSA = 1
PK_RSA_E = 2  # RSA encrypt-only (deprecated)

# ── Symmetric algorithm IDs ────────────────────────────────────────────────────
SYM_AES128, SYM_AES192, SYM_AES256 = 7, 8, 9
_SYM_KEY_SIZES = {SYM_AES128: 16, SYM_AES192: 24, SYM_AES256: 32}
_SYM_BLOCK_SIZES = {SYM_AES128: 16, SYM_AES192: 16, SYM_AES256: 16}

# ── Compression algorithm IDs ──────────────────────────────────────────────────
COMP_NONE, COMP_ZIP, COMP_ZLIB, COMP_BZIP2 = 0, 1, 2, 3

MDC_PACKET_LEN = 22  # 0xD3 0x14 + 20-byte SHA-1


# ══════════════════════════════════════════════════════════════════════════════
# Low-level helpers
# ══════════════════════════════════════════════════════════════════════════════

def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt exactly one AES block in ECB mode (used for manual CFB)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _parse_mpi(data: bytes, offset: int) -> Tuple[int, int]:
    """Parse one OpenPGP MPI from *data* starting at *offset*.

    Returns (integer_value, new_offset).
    """
    bit_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    byte_count = (bit_count + 7) // 8
    value = int.from_bytes(data[offset: offset + byte_count], "big")
    return value, offset + byte_count


# ══════════════════════════════════════════════════════════════════════════════
# Packet I/O
# ══════════════════════════════════════════════════════════════════════════════

def _read_packet(stream: io.RawIOBase) -> Optional[Tuple[int, bytes]]:
    """Read one PGP packet and return (tag, body_bytes), or None at EOF.

    Loads the full packet body into memory — suitable for small packets
    (PKESK, SKESK).  For large SEIPD packets use _read_packet_header +
    _stream_packet_body instead.
    """
    first = stream.read(1)
    if not first:
        return None
    b = first[0]
    if not (b & 0x80):
        raise ValueError(f"Not a PGP packet (byte=0x{b:02x})")

    if b & 0x40:  # new format
        tag = b & 0x3F
        body = _read_new_body(stream)
    else:  # old format
        tag = (b & 0x3C) >> 2
        body = _read_old_body(stream, b & 0x03)

    return tag, body


def _read_packet_header(stream: io.RawIOBase) -> Optional[Tuple[int, Optional[int], bool]]:
    """Read only the packet header.

    Returns (tag, body_length_or_None, is_new_format).
    body_length is None for old-format indeterminate packets.
    """
    first = stream.read(1)
    if not first:
        return None
    b = first[0]
    if not (b & 0x80):
        raise ValueError(f"Not a PGP packet (byte=0x{b:02x})")

    if b & 0x40:  # new format
        tag = b & 0x3F
        body_len = _read_new_format_length(stream)
        return tag, body_len, True
    else:  # old format
        tag = (b & 0x3C) >> 2
        length_type = b & 0x03
        if length_type == 0:
            body_len = stream.read(1)[0]
        elif length_type == 1:
            body_len = struct.unpack(">H", stream.read(2))[0]
        elif length_type == 2:
            body_len = struct.unpack(">I", stream.read(4))[0]
        else:
            body_len = None  # indeterminate
        return tag, body_len, False


def _read_new_format_length(stream: io.RawIOBase) -> int:
    """Read a new-format length field.  Partial bodies are concatenated."""
    lb = stream.read(1)[0]
    if lb < 192:
        return lb
    if lb < 224:
        second = stream.read(1)[0]
        return ((lb - 192) << 8) + second + 192
    if lb == 255:
        return struct.unpack(">I", stream.read(4))[0]
    # Partial body — not encountered in typical encrypted files but handle gracefully
    partial = 1 << (lb & 0x1F)
    rest = _read_new_format_length(stream)
    return partial + rest


def _read_new_body(stream: io.RawIOBase) -> bytes:
    lb = stream.read(1)[0]
    if lb < 192:
        return stream.read(lb)
    if lb < 224:
        second = stream.read(1)[0]
        length = ((lb - 192) << 8) + second + 192
        return stream.read(length)
    if lb == 255:
        length = struct.unpack(">I", stream.read(4))[0]
        return stream.read(length)
    # Partial body
    partial = 1 << (lb & 0x1F)
    data = stream.read(partial)
    return data + _read_new_body(stream)


def _read_old_body(stream: io.RawIOBase, length_type: int) -> bytes:
    if length_type == 0:
        return stream.read(stream.read(1)[0])
    if length_type == 1:
        return stream.read(struct.unpack(">H", stream.read(2))[0])
    if length_type == 2:
        return stream.read(struct.unpack(">I", stream.read(4))[0])
    # Indeterminate — read to end of stream
    return stream.read()


# ══════════════════════════════════════════════════════════════════════════════
# PKESK — Public-Key Encrypted Session Key (tag 1)
# ══════════════════════════════════════════════════════════════════════════════

def _decrypt_pkesk(body: bytes, private_key) -> Tuple[bytes, int]:
    """Decrypt a PKESK packet body and return (session_key, sym_algo_id).

    Args:
        body: Raw PKESK packet body bytes.
        private_key: RSA private key object from `cryptography`.

    Raises:
        ValueError: If the algorithm is unsupported or the checksum fails.
    """
    offset = 0
    version = body[offset]
    offset += 1
    if version != 3:
        raise ValueError(f"Unsupported PKESK version: {version}")

    offset += 8  # key ID (ignored — wildcard match)
    pk_algo = body[offset]
    offset += 1

    if pk_algo not in (PK_RSA, PK_RSA_E):
        raise ValueError(f"Unsupported public-key algorithm: {pk_algo}")

    encrypted_m, _ = _parse_mpi(body, offset)
    enc_bytes = encrypted_m.to_bytes((encrypted_m.bit_length() + 7) // 8, "big")

    # RFC 4880 §5.1: RSA uses PKCS#1 v1.5 (EME-PKCS1-v1_5)
    plaintext = private_key.decrypt(enc_bytes, asym_padding.PKCS1v15())

    # plaintext = [sym_algo 1B][session_key NB][checksum 2B]
    sym_algo = plaintext[0]
    if sym_algo not in _SYM_KEY_SIZES:
        raise ValueError(f"Unsupported symmetric algorithm: {sym_algo}")

    key_len = _SYM_KEY_SIZES[sym_algo]
    session_key = plaintext[1: 1 + key_len]
    checksum = struct.unpack_from(">H", plaintext, 1 + key_len)[0]
    expected = sum(session_key) & 0xFFFF
    if checksum != expected:
        raise ValueError("PKESK session key checksum mismatch — wrong private key?")

    return session_key, sym_algo


# ══════════════════════════════════════════════════════════════════════════════
# OpenPGP CFB decryption (RFC 4880 §13.9)
# ══════════════════════════════════════════════════════════════════════════════

def _openpgp_cfb_decrypt_prefix(key: bytes, block_size: int, prefix_enc: bytes) -> bytes:
    """Decrypt the (block_size + 2) prefix bytes using OpenPGP CFB with IV=0.

    Also performs the "quick check": the last two plaintext bytes of the
    prefix must equal the two bytes before them.

    Returns the decrypted prefix (block_size + 2 bytes).
    Raises ValueError if the quick check fails.
    """
    assert len(prefix_enc) == block_size + 2, "Prefix wrong length"

    # --- phase 1: encrypt IV=0 → decrypt first block_size bytes ---
    fr = bytes(block_size)
    fre = _aes_ecb_encrypt_block(key, fr)
    prefix_plain = bytearray()
    for i in range(block_size):
        prefix_plain.append(prefix_enc[i] ^ fre[i])

    # FR becomes the first block of ciphertext
    fr = prefix_enc[:block_size]
    fre = _aes_ecb_encrypt_block(key, fr)

    # Decrypt the two quick-check bytes
    qc0 = prefix_enc[block_size] ^ fre[0]
    qc1 = prefix_enc[block_size + 1] ^ fre[1]
    prefix_plain.append(qc0)
    prefix_plain.append(qc1)

    if qc0 != prefix_plain[block_size - 2] or qc1 != prefix_plain[block_size - 1]:
        raise ValueError(
            "OpenPGP quick-check failed — wrong private key or corrupted file"
        )

    return bytes(prefix_plain)


def _openpgp_cfb_phase2_iv(prefix_enc: bytes, block_size: int) -> bytes:
    """Return the IV for phase-2 decryption: ciphertext[2 : block_size+2]."""
    return prefix_enc[2: block_size + 2]


# ══════════════════════════════════════════════════════════════════════════════
# Inner-packet parsing (Literal + Compressed)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_literal_data(plain_stream: io.RawIOBase, out_stream: io.RawIOBase) -> None:
    """Read a Literal Data packet (tag 11) body from *plain_stream* and write
    the file content to *out_stream*, stripping the literal header."""
    fmt = plain_stream.read(1)
    if not fmt:
        raise ValueError("Truncated Literal Data header")
    fname_len = plain_stream.read(1)[0]
    _filename = plain_stream.read(fname_len)  # noqa: F841
    _timestamp = plain_stream.read(4)  # noqa: F841
    # Body: stream remainder to output
    while True:
        chunk = plain_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        out_stream.write(chunk)


def _parse_inner_packets(plain_stream: io.RawIOBase, out_stream: io.RawIOBase) -> None:
    """Parse the inner plaintext (after SEIPD prefix) and write literal data.

    Handles:
      - Literal Data directly (tag 11)
      - Compressed Data → Literal Data (tag 8 wrapping tag 11)
    """
    header = _read_packet_header(plain_stream)
    if header is None:
        raise ValueError("No inner packets found in SEIPD plaintext")

    tag, body_len, is_new_fmt = header

    if tag == PKT_COMPRESSED:
        # Read compressed body (can be large — stream to temp)
        compressed_data = plain_stream.read() if body_len is None else plain_stream.read(body_len)
        comp_algo = compressed_data[0]
        compressed_body = compressed_data[1:]

        if comp_algo == COMP_NONE:
            inner = io.BytesIO(compressed_body)
        elif comp_algo == COMP_ZIP:
            inner = io.BytesIO(zlib.decompress(compressed_body, -15))
        elif comp_algo == COMP_ZLIB:
            inner = io.BytesIO(zlib.decompress(compressed_body))
        elif comp_algo == COMP_BZIP2:
            import bz2
            inner = io.BytesIO(bz2.decompress(compressed_body))
        else:
            raise ValueError(f"Unsupported compression algorithm: {comp_algo}")

        _parse_inner_packets(inner, out_stream)

    elif tag == PKT_LITERAL:
        if body_len is not None:
            body_data = plain_stream.read(body_len)
            _extract_literal_data(io.BytesIO(body_data), out_stream)
        else:
            _extract_literal_data(plain_stream, out_stream)

    elif tag == PKT_MDC:
        pass  # MDC already consumed — nothing more to do

    else:
        log.warning("Unexpected inner packet tag %d — skipping", tag)


# ══════════════════════════════════════════════════════════════════════════════
# SEIPD decryption (tag 18)
# ══════════════════════════════════════════════════════════════════════════════

def _decrypt_seipd_stream(
    enc_stream: io.RawIOBase,
    seipd_len: Optional[int],
    session_key: bytes,
    sym_algo: int,
    out_stream: io.RawIOBase,
) -> None:
    """Decrypt a SEIPD packet body using streaming OpenPGP CFB.

    Strategy:
      1. Read & verify the (block_size + 2) prefix — manual OpenPGP CFB.
      2. Derive phase-2 IV from the first bytes of ciphertext.
      3. Stream-decrypt the remainder with AES-CFB (cryptography library).
      4. Write decrypted bytes into a temporary file for inner-packet parsing
         (avoids holding the full plaintext in RAM while still streaming AES).
      5. Strip the trailing MDC_PACKET_LEN bytes and verify the SHA-1 MDC.
      6. Parse inner packets from the temp file and write literal data.
    """
    block_size = _SYM_BLOCK_SIZES[sym_algo]
    key = session_key

    # ── step 1: read & decrypt prefix ──────────────────────────────────────
    prefix_enc = enc_stream.read(block_size + 2)
    if len(prefix_enc) < block_size + 2:
        raise ValueError("SEIPD data shorter than required prefix length")

    prefix_plain = _openpgp_cfb_decrypt_prefix(key, block_size, prefix_enc)

    # ── step 2: phase-2 CFB setup ──────────────────────────────────────────
    iv2 = _openpgp_cfb_phase2_iv(prefix_enc, block_size)
    decryptor = Cipher(algorithms.AES(key), modes.CFB(iv2)).decryptor()

    # ── step 3 & 4: stream-decrypt to temp file ────────────────────────────
    sha1 = hashlib.sha1()
    sha1.update(prefix_plain)  # MDC covers the prefix plaintext

    with tempfile.TemporaryFile() as tmp:
        bytes_remaining = seipd_len - (block_size + 2) if seipd_len else None

        while True:
            if bytes_remaining is not None:
                to_read = min(CHUNK_SIZE, bytes_remaining)
                if to_read == 0:
                    break
            else:
                to_read = CHUNK_SIZE

            chunk = enc_stream.read(to_read)
            if not chunk:
                break

            if bytes_remaining is not None:
                bytes_remaining -= len(chunk)

            plain_chunk = decryptor.update(chunk)
            tmp.write(plain_chunk)

        tmp.write(decryptor.finalize())
        tmp_size = tmp.tell()

        # ── step 5: verify MDC ─────────────────────────────────────────────
        if tmp_size < MDC_PACKET_LEN:
            raise ValueError("Decrypted SEIPD too short to contain MDC")

        # Read everything except the last MDC_PACKET_LEN bytes for SHA-1
        tmp.seek(0)
        data_len = tmp_size - MDC_PACKET_LEN
        bytes_read = 0
        while bytes_read < data_len:
            to_read = min(CHUNK_SIZE, data_len - bytes_read)
            chunk = tmp.read(to_read)
            if not chunk:
                break
            sha1.update(chunk)
            bytes_read += len(chunk)

        # Read MDC packet
        mdc_bytes = tmp.read(MDC_PACKET_LEN)
        if mdc_bytes[0] != 0xD3 or mdc_bytes[1] != 0x14:
            raise ValueError("MDC packet header invalid — file may be corrupted")

        # Include the two MDC header bytes in the SHA-1 before comparing
        sha1.update(mdc_bytes[:2])
        computed = sha1.digest()
        expected = mdc_bytes[2:]
        if computed != expected:
            raise ValueError("MDC SHA-1 mismatch — file corrupted or tampered")

        log.debug("MDC verified OK")

        # ── step 6: parse inner packets ────────────────────────────────────
        tmp.seek(0)
        plain_stream = _LimitedStream(tmp, data_len)
        _parse_inner_packets(plain_stream, out_stream)


class _LimitedStream:
    """Wraps a stream and limits reads to *limit* bytes."""

    def __init__(self, stream: io.RawIOBase, limit: int) -> None:
        self._stream = stream
        self._remaining = limit

    def read(self, n: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if n < 0 or n > self._remaining:
            n = self._remaining
        data = self._stream.read(n)
        self._remaining -= len(data)
        return data


# ══════════════════════════════════════════════════════════════════════════════
# Private key loading
# ══════════════════════════════════════════════════════════════════════════════

def _dearmor(armored: bytes) -> bytes:
    """Strip PGP / PEM ASCII armor and return raw binary data."""
    lines = armored.decode("ascii", errors="replace").splitlines()
    in_body = False
    b64_lines = []
    for line in lines:
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if in_body:
            if line.startswith("="):  # CRC24 line — stop
                break
            if line and not line.startswith("Version:") and ":" not in line:
                b64_lines.append(line)
    return base64.b64decode("".join(b64_lines))


def _load_pgp_armored_private_key(data: bytes, passphrase: bytes):
    """Load an RSA private key from a PGP ASCII-armored secret key block.

    Parses the PGP key packet (RFC 4880 §5.5.3) and reconstructs the RSA
    private key using the `cryptography` library.
    """
    raw = _dearmor(data)
    stream = io.BytesIO(raw)

    rsa_key = None
    while True:
        result = _read_packet(stream)
        if result is None:
            break
        tag, body = result
        # Tag 5 = Secret Key, Tag 7 = Secret Subkey
        if tag in (5, 7):
            try:
                rsa_key = _parse_secret_key_packet(body, passphrase)
                if rsa_key is not None:
                    # Prefer the encryption subkey (tag 7)
                    if tag == 7:
                        break
            except Exception as exc:
                log.debug("Skipping key packet (tag %d): %s", tag, exc)

    if rsa_key is None:
        raise ValueError("No usable RSA private key found in PGP key block")
    return rsa_key


def _parse_secret_key_packet(body: bytes, passphrase: bytes):
    """Parse one Secret-Key / Secret-Subkey packet body.

    Returns an RSA private key or None if the packet is not RSA.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateNumbers,
        RSAPublicNumbers,
    )

    offset = 0
    version = body[offset]
    offset += 1
    if version not in (3, 4):
        return None

    offset += 4  # creation timestamp
    if version == 3:
        offset += 2  # validity days

    pk_algo = body[offset]
    offset += 1
    if pk_algo not in (PK_RSA, PK_RSA_E, 3):  # 3 = RSA sign-only
        return None  # Skip non-RSA keys

    # RSA public key MPIs: n, e
    n, offset = _parse_mpi(body, offset)
    e, offset = _parse_mpi(body, offset)

    # S2K usage
    s2k_usage = body[offset]
    offset += 1

    if s2k_usage == 0:
        # Unprotected: secret MPIs follow directly
        secret_data = body[offset:]
        sym_algo_id = None
    elif s2k_usage in (254, 255):
        sym_algo_id = body[offset]
        offset += 1
        s2k_type = body[offset]
        offset += 1

        # Derive symmetric key from passphrase
        derived_key = _s2k_derive(body, offset, s2k_type, passphrase, sym_algo_id)
        # Advance offset past S2K specifier
        if s2k_type == 0:
            offset += 1  # hash algo
        elif s2k_type in (1, 3):
            offset += 1  # hash algo
            offset += 8  # salt
            if s2k_type == 3:
                offset += 1  # count byte

        # IV
        iv_size = _SYM_BLOCK_SIZES.get(sym_algo_id, 16)
        iv = body[offset: offset + iv_size]
        offset += iv_size

        # Decrypt secret key material
        encrypted_secret = body[offset:]
        secret_data = _decrypt_secret_key_material(
            encrypted_secret, derived_key, sym_algo_id, iv, s2k_usage
        )
    else:
        # Older usage byte encodes sym algo directly
        sym_algo_id = s2k_usage
        iv_size = _SYM_BLOCK_SIZES.get(sym_algo_id, 8)
        iv = body[offset: offset + iv_size]
        offset += iv_size
        # Simple CFB decrypt without S2K (RFC 4880 §3.7)
        if not passphrase:
            return None
        # Derive key as MD5(passphrase) repeated to key length
        key_size = _SYM_KEY_SIZES.get(sym_algo_id, 16)
        derived_key = _simple_s2k(passphrase, key_size)
        encrypted_secret = body[offset:]
        secret_data = _decrypt_secret_key_material(
            encrypted_secret, derived_key, sym_algo_id, iv, 255
        )

    # Parse RSA secret MPIs from secret_data
    sec_offset = 0
    d, sec_offset = _parse_mpi(secret_data, sec_offset)
    p, sec_offset = _parse_mpi(secret_data, sec_offset)
    q, sec_offset = _parse_mpi(secret_data, sec_offset)
    u, _ = _parse_mpi(secret_data, sec_offset)

    # Build cryptography RSA key
    pub = RSAPublicNumbers(e=e, n=n)
    priv = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(p, -1, q),
        public_numbers=pub,
    )
    return priv.private_key()


def _s2k_derive(
    body: bytes, offset: int, s2k_type: int, passphrase: bytes, sym_algo_id: int
) -> bytes:
    """Derive a symmetric key using the S2K specifier (RFC 4880 §3.7)."""
    key_size = _SYM_KEY_SIZES.get(sym_algo_id, 16)
    hash_algo = body[offset]
    hash_fn = {2: hashlib.sha1, 8: hashlib.sha256, 10: hashlib.sha512}.get(
        hash_algo, hashlib.sha1
    )

    if s2k_type == 0:  # Simple
        return _hash_to_key(hash_fn, b"", passphrase, 0, key_size)
    if s2k_type == 1:  # Salted
        salt = body[offset + 1: offset + 9]
        return _hash_to_key(hash_fn, salt, passphrase, 0, key_size)
    if s2k_type == 3:  # Iterated and Salted
        salt = body[offset + 1: offset + 9]
        count_byte = body[offset + 9]
        count = (16 + (count_byte & 15)) << ((count_byte >> 4) + 6)
        return _hash_to_key(hash_fn, salt, passphrase, count, key_size)
    raise ValueError(f"Unsupported S2K type: {s2k_type}")


def _hash_to_key(hash_fn, salt: bytes, passphrase: bytes, count: int, key_size: int) -> bytes:
    """Produce *key_size* bytes by hashing (salt + passphrase) repeatedly."""
    data = salt + passphrase
    result = b""
    prefix_zeros = 0
    while len(result) < key_size:
        h = hash_fn()
        h.update(b"\x00" * prefix_zeros)
        if count > 0:
            needed = count
            while needed > 0:
                chunk = data[: min(needed, len(data))]
                h.update(chunk)
                needed -= len(chunk)
        else:
            h.update(data)
        result += h.digest()
        prefix_zeros += 1
    return result[:key_size]


def _simple_s2k(passphrase: bytes, key_size: int) -> bytes:
    result = b""
    i = 0
    while len(result) < key_size:
        h = hashlib.md5(b"\x00" * i + passphrase).digest()
        result += h
        i += 1
    return result[:key_size]


def _decrypt_secret_key_material(
    encrypted: bytes, key: bytes, sym_algo: int, iv: bytes, s2k_usage: int
) -> bytes:
    """Decrypt the secret key MPI region of a PGP key packet."""
    if sym_algo not in _SYM_KEY_SIZES:
        raise ValueError(f"Unsupported symmetric algorithm for key encryption: {sym_algo}")

    dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    plain = dec.update(encrypted) + dec.finalize()

    if s2k_usage == 254:
        # Last 20 bytes = SHA-1 of key material
        key_material = plain[:-20]
        digest = plain[-20:]
        if hashlib.sha1(key_material).digest() != digest:
            raise ValueError("Secret key SHA-1 integrity check failed — wrong passphrase?")
        return key_material
    else:
        # Last 2 bytes = simple checksum
        key_material = plain[:-2]
        checksum = struct.unpack_from(">H", plain, len(plain) - 2)[0]
        expected = sum(key_material) & 0xFFFF
        if checksum != expected:
            raise ValueError("Secret key checksum mismatch — wrong passphrase?")
        return key_material


def load_private_key(key_path: Path, passphrase: bytes):
    """Load an RSA private key from *key_path*.

    Supports:
      - PEM files (PKCS#8 ``-----BEGIN PRIVATE KEY-----`` or
        PKCS#1 ``-----BEGIN RSA PRIVATE KEY-----``)
      - PGP ASCII-armored secret key blocks
        (``-----BEGIN PGP PRIVATE KEY BLOCK-----``)
    """
    data = key_path.read_bytes()
    passphrase_arg = passphrase if passphrase else None

    if b"BEGIN PGP PRIVATE KEY BLOCK" in data:
        return _load_pgp_armored_private_key(data, passphrase or b"")

    # PEM format
    return load_pem_private_key(data, password=passphrase_arg)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class PGPDecryptor:
    """Decrypts PGP files conforming to RFC 4880.

    Args:
        private_key_path: Path to the RSA private key (PEM or PGP armored).
        passphrase: Passphrase protecting the private key (empty bytes if none).
    """

    def __init__(self, private_key_path: Path, passphrase: bytes = b"") -> None:
        self._private_key = load_private_key(private_key_path, passphrase)
        log.info("Private key loaded from %s", private_key_path)

    def decrypt_file(self, input_path: Path, output_path: Path) -> None:
        """Decrypt *input_path* (a .pgp / .gpg file) to *output_path*.

        Raises:
            ValueError: On any PGP format error, wrong key, or MDC failure.
            OSError: On I/O errors.
        """
        log.info("Decrypting %s → %s", input_path, output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(input_path, "rb") as f:
            session_key, sym_algo = self._find_and_decrypt_pkesk(f)
            self._decrypt_seipd(f, session_key, sym_algo, output_path)

        log.info("Done: %s", output_path.name)

    def _find_and_decrypt_pkesk(self, stream) -> Tuple[bytes, int]:
        """Scan the stream for a PKESK packet and return (session_key, sym_algo)."""
        while True:
            result = _read_packet(stream)
            if result is None:
                raise ValueError("No PKESK packet found in PGP file")
            tag, body = result
            if tag == PKT_PKESK:
                return _decrypt_pkesk(body, self._private_key)
            if tag == PKT_SEIPD:
                raise ValueError("SEIPD found before PKESK — cannot decrypt")
            # Skip other packets (Marker, Signature, etc.)

    def _decrypt_seipd(
        self, stream, session_key: bytes, sym_algo: int, output_path: Path
    ) -> None:
        """Find the SEIPD packet and stream-decrypt it to *output_path*."""
        while True:
            header = _read_packet_header(stream)
            if header is None:
                raise ValueError("No SEIPD packet found in PGP file")
            tag, body_len, _ = header
            if tag == PKT_SEIPD:
                version = stream.read(1)[0]
                if version != 1:
                    raise ValueError(f"Unsupported SEIPD version: {version}")
                adjusted_len = (body_len - 1) if body_len is not None else None
                with open(output_path, "wb") as out:
                    _decrypt_seipd_stream(stream, adjusted_len, session_key, sym_algo, out)
                return
            # Skip this packet's body
            if body_len is not None:
                stream.read(body_len)
            else:
                stream.read()  # indeterminate — consume rest
