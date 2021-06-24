from .async_widget import AsyncWidget
from entities import Host
from util import HostScanner
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QPushButton
)

class HostListWidget(AsyncWidget):
    on_host_click = pyqtSignal(Host)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.setup()

    def setup(self):
        self.create_list()
        self.create_refresh_button()
        self.create_layout()
        self.reload_hosts()

    def create_list(self):
        self.host_list = QListWidget()
        self.host_list.itemDoubleClicked.connect(
            lambda item: self.on_host_click.emit(item.data(Qt.ItemDataRole.UserRole))
        )

    def create_refresh_button(self):
        self.refresh_button = QPushButton('Refresh')
        self.refresh_button.setIcon(QIcon('assets/refresh.svg'))
        self.refresh_button.clicked.connect(self.reload_hosts)

    def create_layout(self):
        layout = QVBoxLayout(self)
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.host_list)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def reload_hosts(self):
        self.host_list.clear()

        thread = HostScanner(self.interface.subnet)
        thread.scan_finished.connect(self.set_hosts)
        self.execute_thread(thread)

    def set_hosts(self, hosts):
        for host in hosts:
            item = QListWidgetItem(self.host_list)
            item.setData(Qt.ItemDataRole.DisplayRole, host.ip_address)
            item.setData(Qt.ItemDataRole.UserRole, host)
