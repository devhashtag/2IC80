from widgets.host_widget import HostListWidget
from PyQt6.QtWidgets import (
    QVBoxLayout,
    QWidget
)

class ARPTab(QWidget):
    def __init__(self, interface, parent=None):
        super().__init__(parent)
 
        self.interface = interface
        self.setup()

    def setup(self):
        layout = QVBoxLayout(self)
        layout.addWidget(HostListWidget(self.interface))


class ARPAttack:
    def __init__(self, gateway=None, victims=[]):
        self.gateway = gateway
        self.victims = victims

    def start(self):
        pass

    def stop(self):
        pass