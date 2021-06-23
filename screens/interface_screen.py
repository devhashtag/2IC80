from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *

from util import get_interfaces

class InterfaceScreen(QWidget):
    onInterfaceChosen = QtCore.pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.create_layout()

    def create_layout(self):
        self.setWindowTitle('Choose interface')
        self.setFixedWidth(350)
        self.setFixedHeight(350)

        interface_list = self.create_interface_list()
        interface_list.setFixedWidth(300)
        interface_list.setFixedHeight(300)

        layout = QVBoxLayout(self)
        layout.addWidget(interface_list)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def create_interface_list(self):
        interface_list = QListWidget()
        interfaces = get_interfaces()

        for name in interfaces:
            item = QListWidgetItem(interface_list)
            item.setData(Qt.ItemDataRole.DisplayRole, name)
            item.setData(Qt.ItemDataRole.UserRole, interfaces[name])
            item.setTextAlignment(Qt.AlignmentFlag.AlignHCenter)

        interface_list.itemDoubleClicked.connect(
            lambda item: self.onInterfaceChosen.emit(item.data(Qt.ItemDataRole.UserRole))
        )

        return interface_list