from entities import Interface
from widgets import AsyncWidget
from util import InterfaceLoader
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QListWidget,
    QVBoxLayout,
    QListWidgetItem
)

class InterfaceScreen(AsyncWidget):
    onInterfaceChosen = pyqtSignal(Interface)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setup()

    def setup(self):
        self.set_screen_properties()
        self.create_interface_list()
        self.create_layout()

    def set_screen_properties(self):
        self.setWindowTitle('Choose interface')
        self.setFixedWidth(350)
        self.setFixedHeight(350)

    def create_interface_list(self):
        self.interface_list = QListWidget()
        self.interface_list.setFixedWidth(300)
        self.interface_list.setFixedHeight(300)
        self.interface_list.itemDoubleClicked.connect(
            lambda item: self.onInterfaceChosen.emit(item.data(Qt.ItemDataRole.UserRole))
        )
        self.load_interfaces()

    def load_interfaces(self):
        thread = InterfaceLoader()
        thread.interfaces_loaded.connect(self.set_interfaces)
        self.execute_thread(thread)

    def create_layout(self):
        layout = QVBoxLayout(self)
        layout.addWidget(self.interface_list)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_interfaces(self, interfaces):
        for interface in interfaces:
            item = QListWidgetItem(self.interface_list)
            item.setData(Qt.ItemDataRole.DisplayRole, interface.name)
            item.setData(Qt.ItemDataRole.UserRole, interface)
            item.setTextAlignment(Qt.AlignmentFlag.AlignHCenter)
