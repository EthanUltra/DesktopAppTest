"""
PortScout (concurrent edition) — a TCP port scanner with a PySide6 GUI.

WHAT CHANGED vs port_scanner.py, and WHY:

  The first version used ONE worker in ONE thread, checking ports one after
  another. Correct and responsive, but slow: each closed port costs up to
  `timeout` seconds, so scanning 1024 ports serially can take a long time.

  This version uses a THREAD POOL. Each port check is a tiny independent job
  (a QRunnable). We hand all the jobs to a QThreadPool, which runs several at
  once across a fixed number of threads. The UI thread stays free, exactly as
  before, but the scan finishes many times faster.

  Two different Qt threading tools, two different situations:
    - QThread + a worker object  -> ONE long-running task (the old version).
    - QThreadPool + QRunnable     -> MANY short independent tasks (this one).
  Knowing which to reach for is the actual skill.

A subtlety this version introduces: COORDINATION.
  With many jobs finishing in parallel, we need a thread-safe way to count how
  many have completed and to know when ALL are done. We use a QMutex to guard
  the shared counter. This is your first taste of why concurrency is hard:
  shared state needs protection, or two threads can corrupt it.

Use responsibly: only scan hosts you own or have permission to test.
Default target is 127.0.0.1 (your own machine), which is always safe.

Run it:
  pip install PySide6
  python port_scanner_concurrent.py
"""

import socket
import sys

from PySide6.QtCore import (
    QObject, QRunnable, QThreadPool, Signal, QMutex, QMutexLocker, Qt,
)
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QProgressBar, QVBoxLayout, QHBoxLayout,
    QHeaderView, QMessageBox,
)

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


class ScanSignals(QObject):
    """
    QRunnable can't emit signals itself (it's not a QObject), so each job
    carries a small signals object. All jobs share ONE instance here, so the
    UI only has to connect once.
    """
    port_result = Signal(int, bool)   # (port, is_open)
    progress = Signal(int, int)       # (ports_done, total)
    finished = Signal()               # emitted once, when the LAST job ends


class ScanState:
    """
    Shared, thread-safe coordination between all the parallel jobs.

    `done` is incremented by whichever thread finishes a port. Because many
    threads touch it at once, every read/modify/write is wrapped in a mutex
    lock. Without the lock, two threads could read the same value, both add
    one, and we'd lose a count — a classic race condition.
    """
    def __init__(self, total: int, signals: ScanSignals):
        self.total = total
        self.signals = signals
        self.done = 0
        self.cancelled = False
        self.mutex = QMutex()

    def mark_done(self):
        with QMutexLocker(self.mutex):
            self.done += 1
            current = self.done
        # Emit OUTSIDE the lock so we don't hold it longer than needed.
        self.signals.progress.emit(current, self.total)
        if current == self.total:
            self.signals.finished.emit()

    def is_cancelled(self) -> bool:
        with QMutexLocker(self.mutex):
            return self.cancelled

    def cancel(self):
        with QMutexLocker(self.mutex):
            self.cancelled = True


class PortCheck(QRunnable):
    """One job = check one port. The thread pool runs many of these at once."""
    def __init__(self, host: str, port: int, timeout: float, state: ScanState):
        super().__init__()
        self.host = host
        self.port = port
        self.timeout = timeout
        self.state = state

    def run(self):
        # If the user cancelled, still mark the job done so the counter
        # reaches `total` and the `finished` signal fires.
        if self.state.is_cancelled():
            self.state.mark_done()
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                is_open = sock.connect_ex((self.host, self.port)) == 0
        except OSError:
            is_open = False

        self.state.signals.port_result.emit(self.port, is_open)
        self.state.mark_done()


class PortScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.pool = QThreadPool.globalInstance()
        # Cap concurrency. Too many simultaneous sockets can exhaust system
        # resources or trip network defenses; 100 is a sane, polite ceiling.
        self.pool.setMaxThreadCount(100)
        self.state = None
        self.signals = None
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle("PortScout (concurrent) — TCP Port Scanner")
        self.resize(560, 480)

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

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.start_scan)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setEnabled(False)

        control_row = QHBoxLayout()
        control_row.addWidget(self.scan_btn)
        control_row.addWidget(self.cancel_btn)
        control_row.addStretch(1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Open Port", "Service"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.status = QLabel("Ready. Only scan hosts you have permission to test.")

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

        if not host:
            QMessageBox.warning(self, "Invalid input", "Please enter a host or IP.")
            return
        if start > end:
            QMessageBox.warning(self, "Invalid range", "'From' port must not exceed 'To' port.")
            return

        # Resolve the hostname ONCE on the UI thread before dispatching jobs,
        # rather than resolving in every one of hundreds of jobs.
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror:
            QMessageBox.warning(self, "Host not found", f"Could not resolve '{host}'.")
            return

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.status.setText(f"Scanning {host} ports {start}\u2013{end}\u2026")

        total = end - start + 1
        self.signals = ScanSignals()
        self.signals.port_result.connect(self.on_port_result)
        self.signals.progress.connect(self.on_progress)
        self.signals.finished.connect(self.on_finished)

        self.state = ScanState(total, self.signals)

        # Hand every port to the pool. It schedules them across its threads.
        for port in range(start, end + 1):
            self.pool.start(PortCheck(resolved, port, 0.5, self.state))

    def cancel_scan(self):
        if self.state:
            self.state.cancel()
            self.status.setText("Cancelling\u2026")

    def on_port_result(self, port: int, is_open: bool):
        if not is_open:
            return
        service = COMMON_SERVICES.get(port, "unknown")
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.table.setItem(row, 1, QTableWidgetItem(service))
        # Keep the open ports sorted by number for readability.
        self.table.sortItems(0, Qt.AscendingOrder)

    def on_progress(self, done: int, total: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(done)

    def on_finished(self):
        open_count = self.table.rowCount()
        self.status.setText(f"Done. {open_count} open port(s) found.")
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.state = None
        self.signals = None


def main():
    app = QApplication(sys.argv)
    window = PortScanner()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()