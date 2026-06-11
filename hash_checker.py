"""
HashCheck — a file hash / checksum verifier with a PySide6 GUI.

WHAT IT DOES
  Pick a file (button or drag-and-drop), and it computes the file's
  MD5, SHA-1, and SHA-256 hashes. You can paste an "expected" hash
  (e.g. the one a download page lists) and it tells you whether the
  file matches — i.e. whether it was tampered with or corrupted.

WHY THIS IS A GOOD PROJECT
  - No legal grey area at all: it only ever reads a local file you chose.
  - Same core lesson as a port scanner: hashing a big file is SLOW, so the
    work runs in a QThread and reports progress via signals. The UI never
    freezes. This is THE pattern for responsive desktop apps.
  - Real file I/O, read in chunks so even a multi-GB file uses little memory.
  - Genuinely useful + security-relevant: verifying downloads is a real task.

HOW HASHING IS USED FOR INTEGRITY
  A cryptographic hash maps any file to a fixed-length fingerprint. Change a
  single byte and the fingerprint changes completely. So if a download page
  publishes a SHA-256 and your computed SHA-256 matches, you know the file
  arrived intact and unmodified. (MD5 and SHA-1 are included for
  compatibility but are considered weak for security — SHA-256 is the one to
  trust. The app shows all three so you can learn the difference.)

Run it:
  pip install PySide6
  python hash_checker.py
"""

import hashlib
import os
import sys

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QProgressBar, QFileDialog, QFrame,
)

# Read the file in 1 MB chunks. This is why a huge file doesn't blow up
# memory: we never load the whole thing at once, we feed it to the hashers
# piece by piece.
CHUNK_SIZE = 1024 * 1024


class HashWorker(QObject):
    """
    Hashes a file off the UI thread. Reports progress as it reads, then
    emits the final hex digests. Talks to the UI only through signals.
    """
    progress = Signal(int)                 # percent 0..100
    finished = Signal(str, str, str)       # (md5, sha1, sha256)
    error = Signal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            total = os.path.getsize(self.path)
            read_so_far = 0

            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            with open(self.path, "rb") as f:
                while True:
                    if self._cancelled:
                        return
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    # Feed the same chunk to all three hashers in one pass —
                    # no need to read the file three separate times.
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)

                    read_so_far += len(chunk)
                    if total > 0:
                        self.progress.emit(int(read_so_far * 100 / total))

            self.finished.emit(md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())
        except OSError as e:
            self.error.emit(str(e))


class HashCheck(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
        self.current_path = None
        self.setAcceptDrops(True)   # enable drag-and-drop of a file
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle("HashCheck — File Integrity Verifier")
        self.resize(640, 380)

        # --- File chooser row + drop hint ---
        self.path_label = QLabel("No file selected")
        self.path_label.setFrameShape(QFrame.StyledPanel)
        self.path_label.setMinimumHeight(34)
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.browse_btn = QPushButton("Choose File\u2026")
        self.browse_btn.clicked.connect(self.choose_file)

        top_row = QHBoxLayout()
        top_row.addWidget(self.path_label, stretch=1)
        top_row.addWidget(self.browse_btn)

        drop_hint = QLabel("\u2026 or drag and drop a file onto this window")
        drop_hint.setAlignment(Qt.AlignCenter)
        drop_hint.setStyleSheet("color: gray;")

        # --- Progress bar ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        # --- Result fields (read-only, selectable so you can copy them) ---
        self.md5_field = self._make_result_field()
        self.sha1_field = self._make_result_field()
        self.sha256_field = self._make_result_field()

        results = QGridLayout()
        results.addWidget(QLabel("MD5:"), 0, 0)
        results.addWidget(self.md5_field, 0, 1)
        results.addWidget(QLabel("SHA-1:"), 1, 0)
        results.addWidget(self.sha1_field, 1, 1)
        results.addWidget(QLabel("SHA-256:"), 2, 0)
        results.addWidget(self.sha256_field, 2, 1)

        # --- Expected-hash comparison row ---
        self.expected_input = QLineEdit()
        self.expected_input.setPlaceholderText("Paste an expected hash to compare (any of the three)")
        self.expected_input.textChanged.connect(self.update_match)

        self.match_label = QLabel("")
        self.match_label.setAlignment(Qt.AlignCenter)
        self.match_label.setMinimumHeight(30)

        # --- Assemble ---
        layout = QVBoxLayout(self)
        layout.addLayout(top_row)
        layout.addWidget(drop_hint)
        layout.addWidget(self.progress_bar)
        layout.addLayout(results)
        layout.addWidget(self.expected_input)
        layout.addWidget(self.match_label)
        layout.addStretch(1)

    def _make_result_field(self):
        field = QLineEdit()
        field.setReadOnly(True)
        field.setPlaceholderText("\u2014")
        return field

    # --- Drag and drop support ---
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.start_hashing(path)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file")
        if path:
            self.start_hashing(path)

    def start_hashing(self, path: str):
        self.current_path = path
        self.path_label.setText(path)
        self.progress_bar.setValue(0)
        for f in (self.md5_field, self.sha1_field, self.sha256_field):
            f.clear()
        self.match_label.setText("")
        self.browse_btn.setEnabled(False)

        # Off-thread hashing — same QThread + worker pattern as before.
        self.thread = QThread()
        self.worker = HashWorker(path)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_finished(self, md5: str, sha1: str, sha256: str):
        self.md5_field.setText(md5)
        self.sha1_field.setText(sha1)
        self.sha256_field.setText(sha256)
        self.progress_bar.setValue(100)
        self.browse_btn.setEnabled(True)
        self.update_match()

    def on_error(self, message: str):
        self.path_label.setText(f"Error: {message}")
        self.browse_btn.setEnabled(True)

    def update_match(self):
        """Compare the pasted expected hash against all three computed ones."""
        expected = self.expected_input.text().strip().lower()
        if not expected:
            self.match_label.setText("")
            return

        computed = {
            self.md5_field.text().lower(),
            self.sha1_field.text().lower(),
            self.sha256_field.text().lower(),
        }
        computed.discard("")

        if not computed:
            self.match_label.setText("")
            return

        if expected in computed:
            self.match_label.setText("\u2713  MATCH — file integrity verified")
            self.match_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.match_label.setText("\u2717  NO MATCH — file differs from expected")
            self.match_label.setStyleSheet("color: red; font-weight: bold;")

def main():
    app = QApplication(sys.argv)
    window = HashCheck()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

def closeEvent(self, event):
    """Shut the scan down cleanly when the window is closed mid-scan."""
    if self.thread is not None and self.thread.isRunning():
        if self.worker is not None:
            self.worker.cancel()      # ask the loop to stop
        self.thread.quit()            # stop the thread's event loop
        self.thread.wait(2000)        # wait up to 2s for it to finish
    event.accept()