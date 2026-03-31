# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Project: PGP Stream Decrypt

Python application that watches a directory for incoming PGP-encrypted files and decrypts them concurrently using a thread pool.

## Tech Stack

- **Language:** Python 3.9.13
- **Environment:** venv
- **Testing:** pytest
- **PGP decryption:** Native OpenPGP (RFC 4880) — do NOT use `pgpy` (too slow for GB files) or `python-gnupg` (requires external GPG binary)

## Commands

```bash
# Setup
python -m venv venv
source venv/Scripts/activate   # Windows
pip install -r requirements.txt

# Run
python src/main.py                          # default config
python src/main.py --config config.properties
python src/main.py --workers 4 --log-level DEBUG

# Test
pytest tests/
pytest tests/test_decryptor.py             # single file
pytest tests/ -k "test_decrypt"            # single test by name

# Lint
flake8 src/ tests/
```

## Architecture

The application has three layers that pass work downstream:

```
[File Watcher Gateway]  →  [Thread Pool Workers]  →  [PGP Decryptor]
   watchdog/polling           concurrent.futures          RFC 4880
   pgps/input/                N threads (config)          private key +
   pgps/processed/                                        passphrase
   pgps/error/
```

**File Watcher Gateway** (`src/watcher.py`): Monitors `pgps/input/` for new `.pgp`/`.gpg` files using a polling or event-driven approach. On detection, submits the file path to the thread pool. On success, moves the file to `pgps/processed/`; on any exception, moves it to `pgps/error/`.

**Thread Pool** (`src/worker_pool.py`): `concurrent.futures.ThreadPoolExecutor` with pool size read from config. Accepts file tasks from the watcher and calls the decryptor.

**PGP Decryptor** (`src/decryptor.py`): Implements OpenPGP decryption per RFC 4880 as a streaming operation (memory-efficient for GB-scale files). Reads the private key path and passphrase from config.

**Configuration** (`config.properties`): Controls input/output/processed/error paths, thread pool size, log level, private key path, and passphrase.

**Logging** (`src/logger.py`): Rotating file handler writing to `log/`, rotates at least daily. Supports ERROR, INFO, DEBUG levels switchable via config.

## Directory Layout

```
pgps/input/       # drop PGP files here
pgps/output/      # decrypted output lands here
pgps/processed/   # originals moved here after success
pgps/error/       # originals moved here after failure
pgps/testing/     # demo encrypted files + private key for validation
log/              # rotating log files
src/              # application source
tests/            # pytest tests
config.properties # runtime configuration
requirements.txt  # dependencies
```

## Key Design Decisions

- Streaming decryption: read/decrypt/write in chunks to handle GB-sized files without loading into memory.
- Thread pool size is configurable; default should be documented in `config.properties`.
- Private key and passphrase are loaded once at startup and shared across worker threads (thread-safe reads).
- File moves (input → processed/error) must be atomic to avoid partial states visible to the watcher.

## Development Workflow

When source code and README.md are ready:

1. **Generate** demo encrypted PGP files and the private key/passphrase in `pgps/testing/`.
2. **Start** the file watching gateway.
3. **Validate:**
   - Copy PGP files from `pgps/testing/` to `pgps/input/`.
   - Wait for processing to complete.
   - Compare decrypted files in `pgps/output/` against the originals.
   - Stop the gateway.
4. **Fix** any mismatches and repeat from step 2.
5. **Update** README.md with final usage details.
6. **Generate** demo encrypted PGP files with 1.5 GB size and the private key/passphrase in `pgps/testing/` to test the performance of the application.

Do at least 2 comparison rounds. Only stop when the user says so or when no differences remain.
