from attacks import ARPAttack
from entities import Interface
from widgets import HostListWidget, GatewayWidget, VictimWidget
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget
)

class ARPTab(QWidget):
    GATEWAY = 0
    VICTIM = 1

    def __init__(self, interface: Interface, parent=None):
        super().__init__(parent)
 
        self.interface = interface
        self.widgets = { }
        self.attack = None

        self.setup()

    def setup(self):
        self.create_widgets()
        self.connect_components()
        self.create_layout()

    def create_widgets(self):
        self.widgets['host list'] = HostListWidget(self.interface)
        self.widgets['gateway'] = GatewayWidget(self.interface)
        self.widgets['victims'] = VictimWidget(self.interface)

        self.widgets['select host type'] = QComboBox()
        self.widgets['select host type'].addItem('Gateway', self.GATEWAY)
        self.widgets['select host type'].addItem('Victim', self.VICTIM)

        self.widgets['select host label'] = QLabel('Select host as: ')
        self.widgets['select host label'].setAlignment(Qt.AlignmentFlag.AlignRight)

        self.widgets['start button'] = QPushButton('Start')
        self.widgets['stop button'] = QPushButton('Stop')

    def connect_components(self):
        self.widgets['host list'].on_host_click.connect(self.on_host_selected)
        self.widgets['start button'].released.connect(self.start)
        self.widgets['stop button'].released.connect(self.stop)

    def create_layout(self):
        sub_layout = QVBoxLayout()
        sub_layout.addWidget(self.widgets['gateway'])
        sub_layout.addWidget(self.widgets['victims'])

        layout = QGridLayout(self)
        layout.addWidget(self.widgets['select host label'], 0, 0)
        layout.addWidget(self.widgets['select host type'], 0, 1)
        layout.addLayout(sub_layout, 1, 0)
        layout.addWidget(self.widgets['host list'], 1, 1)
        layout.addWidget(self.widgets['start button'], 2, 0)
        layout.addWidget(self.widgets['stop button'], 2, 1)

    def on_host_selected(self, host):
        host_type = self.widgets['select host type'].currentData(Qt.ItemDataRole.UserRole)

        if host_type == self.GATEWAY:
            self.widgets['gateway'].set_gateway(host)
        elif host_type == self.VICTIM:
            self.widgets['victims'].add_host(host)

    def start(self):
        if self.attack is not None and self.attack.active:
            self.show_error('Cannot start ARP attack', 'There is already an ARP attack active')
            return
    
        try:
            self.attack = ARPAttack(
                self.interface,
                self.widgets['gateway'].gateway,
                self.widgets['victims'].hosts)
            self.attack.start()
        except ValueError as error:
            self.show_error('Cannot start ARP attack', error.args[0])

    def stop(self):
        if self.attack is None or not self.attack.active:
            self.show_error('Cannot stop ARP attack', 'There is no ARP attack active')
            return

        self.attack.stop()

    def show_error(self, title, message):
        error_message = QMessageBox(QMessageBox.Icon.Critical, title, message)
        error_message.show()
        error_message.exec()
