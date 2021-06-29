from .async_widget import AsyncWidget
from entities import Host, Interface
from util import sort_hosts
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QPushButton
)

class VictimWidget(AsyncWidget):
    on_host_click = pyqtSignal(Host)

    def __init__(self, interface: Interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.list_elements = []
        self.setup()

    def setup(self):
        self.create_title()
        self.create_list()
        self.create_clear_button()
        self.create_layout()

    def create_title(self):
        self.title = QLabel('Victims')
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def create_list(self):
        self.host_list = QListWidget()
        self.host_list.itemDoubleClicked.connect(
            lambda item: self.on_host_click.emit(item.data(Qt.ItemDataRole.UserRole))
        )

    def create_clear_button(self):
        self.clear_button = QPushButton('Clear')
        self.clear_button.setIcon(QIcon('assets/clear.svg'))
        self.clear_button.clicked.connect(self.host_list.clear)
        self.clear_button.clicked.connect(lambda: self.list_elements.clear())

    def create_layout(self):
        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.host_list)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def update_list(self):
        # remove duplicates
        self.list_elements = list(set(self.list_elements))
        self.list_elements = sort_hosts(self.list_elements)
        self.host_list.clear()

        for host in self.list_elements:
            item = QListWidgetItem(self.host_list)
            item.setData(Qt.ItemDataRole.DisplayRole, host.ip_address)
            item.setData(Qt.ItemDataRole.UserRole, host)

    def get_hosts(self):
        return self.list_elements

    def set_hosts(self, hosts: list[Host]):
        self.list_elements = hosts
        self.update_list()

    def add_host(self, host: Host):
        self.list_elements.append(host)
        self.update_list()

    hosts = property(get_hosts, set_hosts)