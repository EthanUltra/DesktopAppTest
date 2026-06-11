# Desktop Apps — PySide6 Learning Projects

A small collection of Windows desktop applications built with **Python + PySide6**,
written to practice the patterns that real GUI software depends on: separating slow
work from the UI thread, input validation, file I/O, and packaging to a standalone
executable.

## Projects

### PortScout — TCP Port Scanner (`port_scanner.py`)
Scans a host for open TCP ports and lists them with their common service names.

- **Threading model:** the scan runs in a `QThread` worker that communicates with the
  UI only through signals, so the window stays fully responsive (and cancellable)
  during a scan.
- A **concurrent edition** (`port_scanner_concurrent.py`) refactors this to a
  `QThreadPool` of `QRunnable` jobs for much faster scans, with a `QMutex` guarding
  the shared progress counter to avoid a race condition.

> **Use responsibly:** only scan hosts you own or have explicit permission to test.
> The default target is `127.0.0.1` (your own machine).

### HashCheck — File Integrity Verifier (`hash_checker.py`)
Computes MD5, SHA-1, and SHA-256 for a chosen file (button or drag-and-drop) and
compares them against an expected hash to verify the file wasn't corrupted or
tampered with.

- **Chunked reading:** the file is read in 1 MB chunks and streamed to all three
  hashers in a single pass, so it handles multi-gigabyte files with minimal memory.
- **Off-thread hashing:** runs in a `QThread` worker with a live progress bar.
- Shows all three algorithms deliberately — SHA-256 is the one to trust for integrity;
  MD5 and SHA-1 are included for compatibility but are cryptographically weak.

## Why these patterns matter

The recurring lesson across both apps is the same: **the UI thread must never block.**
A port scan and a large-file hash are both slow, so each runs on a background thread
and reports progress back via Qt signals. Only the main thread touches widgets — a
hard rule in Qt. This is what keeps the apps responsive instead of freezing.

## Running

```bash
pip install PySide6
python hash_checker.py        # or port_scanner.py
```

## Building a standalone .exe

```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed hash_checker.py
```

The executable appears in `dist/`. (Note: a freshly built unsigned `.exe` may be
flagged by Windows SmartScreen — a common false positive for PyInstaller binaries.)

## Tech

Python 3.12 · PySide6 (Qt for Python) · PyInstaller