from PyQt5.QtWidgets import QMainWindow
from tabs import ARPTab, DNSTab
from screens import InterfaceScreen, MainScreen

class Window(QMainWindow):
    """The Main window of the application
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.interface_screen = InterfaceScreen()
        self.interface_screen.onInterfaceChosen.connect(self.on_interface_chosen)

        self.setScreen(self.interface_screen)

    def setScreen(self, screen):
        window_title = screen.windowTitle()

        self.setCentralWidget(screen)
        self.setWindowTitle(window_title)

    def on_interface_chosen(self, interface):
        self.main_screen = MainScreen(interface)
        self.main_screen.add_tab(ARPTab(interface), 'ARP Spoofing')
        self.main_screen.add_tab(DNSTab(interface), 'DNS Spoofing')
        self.setScreen(self.main_screen)
