from PyQt6.QtCore import QThread, pyqtSignal
from .methods import get_interfaces

class InterfaceLoader(QThread):
    interfaces_loaded = pyqtSignal(list)

    def run(self):
        interfaces = get_interfaces()
        self.interfaces_loaded.emit(interfaces)