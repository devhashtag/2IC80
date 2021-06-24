from tabs.arp import ARPTab
from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMainWindow

from screens import InterfaceScreen, MainScreen

class Window(QMainWindow):
    """The Main window of the application
    """
    onInterfaceChosen = QtCore.pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.interface_screen = InterfaceScreen()
        self.main_screen = None
        self.interface_screen.onInterfaceChosen.connect(self.on_interface_chosen)

        interface = {
            'subnet': '192.168.2.0/24'
        }

        # self.setScreen(self.interface_screen)
        main_screen = MainScreen(interface)
        main_screen.add_tab(ARPTab(interface), 'ARP Spoofing')
        self.setScreen(main_screen)

    def setScreen(self, screen):
        window_title = screen.windowTitle()

        self.setCentralWidget(screen)
        self.setWindowTitle(window_title)

    def on_interface_chosen(self, interface):
        self.main_screen = MainScreen(interface)

        self.setScreen(self.main_screen)
