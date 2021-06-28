from entities import Host
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QPushButton,
    QWidget
)

class GatewayWidget(QWidget):
    on_gateway_click = pyqtSignal(Host)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.gateway = None
        self.widgets = { }
        self.setup()

    def setup(self):
        self.create_title()
        self.create_clear_button()
        self.create_gateway()
        self.create_layout()

    def create_title(self):
        self.widgets['title'] = QLabel('Gateway')
        self.widgets['title'].setAlignment(Qt.AlignmentFlag.AlignCenter)

    def create_gateway(self):
        self.widgets['gateway'] = QLineEdit()
        self.widgets['gateway'].setReadOnly(True)

    def create_clear_button(self):
        self.widgets['clear_button'] = QPushButton('Clear')
        self.widgets['clear_button'].setIcon(QIcon('assets/clear.svg'))
        self.widgets['clear_button'].clicked.connect(self.clear_gateway)

    def create_layout(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        for widget in self.widgets.values():
            layout.addWidget(widget)

    def clear_gateway(self):
        self.widgets['gateway'].clear()

    def set_gateway(self, gateway: Host):
        self.gateway = gateway
        self.widgets['gateway'].setText(gateway.ip_address)
