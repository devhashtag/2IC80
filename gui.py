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

        layout = QVBoxLayout(self)
        layout.addWidget(self.create_interface_list())

    def create_interface_list(self):
        interface_list = QListWidget()
        interfaces = get_interfaces()

        for name in interfaces:
            item = QListWidgetItem(interface_list)
            item.setData(Qt.ItemDataRole.DisplayRole, name)
            item.setData(Qt.ItemDataRole.UserRole, interfaces[name])

        interface_list.itemDoubleClicked.connect(
            lambda item: self.onInterfaceChosen.emit(item.data(Qt.ItemDataRole.UserRole))
        )

        return interface_list

class MainScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('Test'))
        self.setWindowTitle('Happy hacking')

class Window(QMainWindow):
    """The Main window of the application
    """
    onInterfaceChosen = QtCore.pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._createMenubar()

        self.interface_widget = InterfaceScreen()
        self.main_widget = MainScreen()
        self.interface_widget.onInterfaceChosen.connect(self.on_interface_chosen)

        self.hideMenu()
        self.setScreen(self.interface_widget)

    def hideMenu(self):
        if self.menuBar() != None:
            self.menuBar().hide()

    def showMenu(self):
        if self.menuBar() != None:
            self.menuBar().show()

    def setScreen(self, screen):
        window_title = screen.windowTitle()

        self.setCentralWidget(screen)
        self.setWindowTitle(window_title)

    def on_interface_chosen(self, interface):
        self.setScreen(self.main_widget)
        self.showMenu()

    def _createMenubar(self):
        menubar = QMenuBar(self)
        self.setMenuBar(menubar)

        file_menu = QMenu('File', self)
        edit_menu = QMenu('Edit', self)
        help_menu = QMenu('Help', self)

        # TODO: add useful options

        menubar.addMenu(file_menu)
        menubar.addMenu(edit_menu)
        menubar.addMenu(help_menu)

app = QApplication([])

window = Window()
window.show()

app.exec()

