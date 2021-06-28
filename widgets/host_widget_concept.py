from os import set_inheritable
from entities.interface import Interface
from .async_widget import AsyncWidget
from entities import Host
from util import HostScanner
from PyQt6.QtGui import QHoverEvent, QIcon
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLayout,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QPushButton,
    QWidget
)

class HostWidget(AsyncWidget):
    on_host_click = pyqtSignal(Host)

    def __init__(self,
            interface: Interface,
            title: str=None,
            buttons: list = [],
            parent=None):
        super().__init__(parent)

        self.interface = interface
        self.title = title
        self.buttons = []
        self.gui_elements = { }
        self.list_elements = []
        self.setup()

    def setup(self):
        # The widgets are shown in the same order as that they
        # are created, so order is important!
        if self.title is not None:
            self.create_title()
        self.create_buttons()
        self.create_list()
        self.create_layout()

    def create_title(self):
        if self.title is None:
            return

        title_widget = QLabel(self.title)
        title_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.gui_elements['title'] = title_widget

    def create_buttons(self):
        button_layout = QHBoxLayout()

        for button in self.buttons:
            button_layout.addWidget(button)

        self.gui_elements['buttons'] = button_layout

    def create_list(self):
        host_list = QListWidget()
        host_list.itemDoubleClicked.connect(
            lambda item: self.on_host_click.emit(item.data(Qt.ItemDataRole.UserRole))
        )
        self.gui_elements['host_list'] = host_list

    def create_layout(self):
        layout = QVBoxLayout(self)

        for element in self.gui_elements.values():
            if isinstance(element, QWidget):
                layout.addWidget(element)
            elif isinstance(element, QLayout):
                layout.addLayout(element)

    def update_host_list(self):
        list_widget = self.gui_elements['host_list']
        list_widget.clear()

        for host in self.list_elements:
            item = QListWidgetItem(list_widget)
            item.setData(Qt.ItemDataRole.DisplayRole, host.ip_address)
            item.setData(Qt.ItemDataRole.UserRole, host)

    def get_hosts(self):
        return self.list_elements

    def set_hosts(self, hosts: list[Host]):
        self.list_elements = hosts
        self.update_host_list()

    hosts = property(get_hosts, set_hosts)

class NetworkHostsWidget(HostWidget):
    def __init__(self, interface: Interface, parent=None, buttons=[], title: str='Host list'):
        super().__init__(interface, title, buttons, parent)

        self.reload_hosts()

    def reload_hosts(self):
        thread = HostScanner(self.interface.subnet)
        thread.scan_finished.connect(self.set_hosts)
        self.execute_thread(thread)
