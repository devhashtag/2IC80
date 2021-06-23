from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *

from screens import InterfaceScreen, MainScreen

class Window(QMainWindow):
    """The Main window of the application
    """
    onInterfaceChosen = QtCore.pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._createMenubar()

        self.interface_screen = InterfaceScreen()
        self.main_screen = None
        self.interface_screen.onInterfaceChosen.connect(self.on_interface_chosen)

        self.hideMenu()
        self.setScreen(self.interface_screen)
        # self.setScreen(MainScreen({'subnet': '192.168.2.0/24'}))

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
        self.main_screen = MainScreen(interface)

        self.setScreen(self.main_screen)
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