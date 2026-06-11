"""
PortScout — a simple TCP port scanner with a PySide6 GUI.

This is a learning scaffold. It demonstrates the patterns that matter in
real desktop apps:
  - Separating the UI (the main thread) from slow work (a worker thread).
    A port scan is slow, so if you ran it on the UI thread the whole window
    would freeze. Instead the scanning happens in a QThread and reports
    progress back to the UI via Qt signals.
  - Signals/slots: the worker EMITS signals (result found, progress, done)
    and the UI CONNECTS to them. The worker never touches widgets directly —
    that's a hard rule in Qt: only the main thread may modify the UI.
  - A clean, resizable layout using QVBoxLayout / QHBoxLayout.
  - Input validation and disabling controls while a scan runs.

IMPORTANT — use responsibly:
  Only scan hosts you own or have explicit permission to test. Port scanning
  machines you don't control can be against the law and against the policy of
  most networks. Default target below is 127.0.0.1 (your own machine), which
  is always safe.

Run it:
  pip install PySide6
  python port_scanner.py
"""

import socket
import sys

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QProgressBar,
    QVBoxLayout,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
)

# A small map of well-known ports so results are more readable than bare numbers.
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


class ScanWorker(QObject):
    """
    Does the actual scanning. Lives in its own thread.

    It communicates with the UI ONLY through these signals — never by
    touching widgets. That separation is what keeps the app responsive
    and is the core lesson of this whole project.
    """
    port_result = Signal(int, bool)   # (port, is_open)
    progress = Signal(int, int)       # (ports_done, total_ports)
    finished = Signal()

    def __init__(self, host: str, start_port: int, end_port: int, timeout: float = 0.5):
        super().__init__()
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self._cancelled = False

    def cancel(self):
        """Called from the UI thread to ask the scan to stop early."""
        self._cancelled = True

    def run(self):
        """Entry point once the thread starts. Scans each port in turn."""
        total = self.end_port - self.start_port + 1
        done = 0

        # Resolve the hostname once up front. If it fails, report and bail.
        try:
            resolved = socket.gethostbyname(self.host)
        except socket.gaierror:
            # Signal nothing found and finish; the UI shows zero open ports.
            self.finished.emit()
            return

        for port in range(self.start_port, self.end_port + 1):
            if self._cancelled:
                break

            # A connect_ex returning 0 means the TCP handshake succeeded,
            # i.e. the port is open and accepting connections.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                is_open = sock.connect_ex((resolved, port)) == 0

            self.port_result.emit(port, is_open)

            done += 1
            self.progress.emit(done, total)

        self.finished.emit()


class PortScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle("PortScout — TCP Port Scanner")
        self.resize(560, 480)

        # --- Input row: host + port range ---
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setPlaceholderText("Host or IP (e.g. 127.0.0.1)")

        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)

        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(1024)

        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Host:"))
        input_row.addWidget(self.host_input, stretch=1)
        input_row.addWidget(QLabel("From:"))
        input_row.addWidget(self.start_port)
        input_row.addWidget(QLabel("To:"))
        input_row.addWidget(self.end_port)

        # --- Control row: scan + cancel buttons ---
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.start_scan)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setEnabled(False)

        control_row = QHBoxLayout()
        control_row.addWidget(self.scan_btn)
        control_row.addWidget(self.cancel_btn)
        control_row.addStretch(1)

        # --- Progress bar ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        # --- Results table ---
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Open Port", "Service"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        # --- Status line ---
        self.status = QLabel("Ready. Only scan hosts you have permission to test.")
        self.status.setAlignment(Qt.AlignLeft)

        # --- Assemble the main vertical layout ---
        layout = QVBoxLayout(self)
        layout.addLayout(input_row)
        layout.addLayout(control_row)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.table, stretch=1)
        layout.addWidget(self.status)

    def start_scan(self):
        host = self.host_input.text().strip()
        start = self.start_port.value()
        end = self.end_port.value()

        # --- Validation: the kind of thing that separates real apps from toys ---
        if not host:
            QMessageBox.warning(self, "Invalid input", "Please enter a host or IP.")
            return
        if start > end:
            QMessageBox.warning(self, "Invalid range", "'From' port must not exceed 'To' port.")
            return

        # Reset UI state for a fresh scan.
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.status.setText(f"Scanning {host} ports {start}\u2013{end}\u2026")

        # --- Set up the worker + thread ---
        # The worker is moved INTO a QThread. When the thread starts, it calls
        # worker.run(). Signals from the worker are delivered safely to slots
        # on the main thread, so updating widgets from them is allowed.
        self.thread = QThread()
        self.worker = ScanWorker(host, start, end)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.port_result.connect(self.on_port_result)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)

        # Cleanup: when finished, quit the thread and schedule both for deletion.
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def cancel_scan(self):
        if self.worker:
            self.worker.cancel()
            self.status.setText("Cancelling\u2026")

    def on_port_result(self, port: int, is_open: bool):
        if not is_open:
            return
        service = COMMON_SERVICES.get(port, "unknown")
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.table.setItem(row, 1, QTableWidgetItem(service))

    def on_progress(self, done: int, total: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(done)

    def on_finished(self):
        open_count = self.table.rowCount()
        self.status.setText(f"Done. {open_count} open port(s) found.")
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.worker = None
        self.thread = None


def main():
    app = QApplication(sys.argv)
    window = PortScanner()
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