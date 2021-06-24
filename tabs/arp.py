from entities import Host, Interface
from widgets import HostListWidget
from PyQt6.QtWidgets import (
    QGridLayout,
    QVBoxLayout,
    QWidget
)

class ARPTab(QWidget):
    def __init__(self, interface: Interface, parent=None):
        super().__init__(parent)
 
        self.interface = interface
        self.setup()

    def setup(self):
        '''
        Layout should look roughly like this:
            +------+-----+   
            | 1    | 3   |   1: gateway
            +------+     |   2: victims
            | 2    |     |   3: host list
            |      |     |
            +------+-----+ 
        '''

        layout = QGridLayout(self)
        layout.addWidget(HostListWidget(self.interface), 0, 1)

class ARPAttack:
    def __init__(self,
            interface: Interface,
            gateway: Host = None,
            victims: list[Host] = []):
        self.interface = interface
        self.gateway = gateway
        self.victims = victims

    def start(self):
        pass

    def stop(self):
        pass