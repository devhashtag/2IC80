from PyQt6.QtCore import QThread, pyqtSignal
from .methods import scan_hosts

class HostScanner(QThread):
    scan_finished = pyqtSignal(list)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        hosts = scan_hosts(self.subnet)
        self.scan_finished.emit(hosts)