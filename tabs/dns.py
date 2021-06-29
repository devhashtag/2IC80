from attacks.dns_attack import DNSAttack
from entities import Interface
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget
)

class DNSTab(QWidget):
    def __init__(self, interface: Interface, parent=None):
        super().__init__(parent)

        self.interface = interface
        self.widgets = { }
        self.dns_table = { }
        self.attack = None
        self.setup()

    def setup(self):
        self.create_widgets()
        self.connect_components()
        self.create_layout()

    def create_widgets(self):
        self.widgets['hostname label'] = QLabel('Hostname')
        self.widgets['ip label'] = QLabel('IP Address')
        self.widgets['hostname label'].setAlignment(Qt.AlignmentFlag.AlignRight)
        self.widgets['ip label'].setAlignment(Qt.AlignmentFlag.AlignRight)
        self.widgets['hostname input'] = QLineEdit()
        self.widgets['ip input'] = QLineEdit()
        self.widgets['add button'] = QPushButton('Add')
        self.widgets['start button'] = QPushButton('Start')
        self.widgets['stop button'] = QPushButton('Stop')
        self.widgets['dns table'] = QTableWidget()
        self.widgets['dns table'].setColumnCount(2)
        self.widgets['dns table'].setHorizontalHeaderLabels(['Hostname', 'IP Address'])
        self.widgets['dns table'].setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.widgets['dns table'].setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

    def connect_components(self):
        self.widgets['add button'].released.connect(self.on_add)
        self.widgets['dns table'].cellDoubleClicked.connect(self.on_item_remove)
        self.widgets['start button'].released.connect(self.start)
        self.widgets['stop button'].released.connect(self.stop)

    def create_layout(self):
        sublayout = QGridLayout()
        sublayout.addWidget(self.widgets['hostname label'], 0, 0)
        sublayout.addWidget(self.widgets['ip label'], 1, 0)
        sublayout.addWidget(self.widgets['hostname input'], 0, 1)
        sublayout.addWidget(self.widgets['ip input'], 1, 1)
        sublayout.addWidget(self.widgets['add button'], 2, 1)
        sublayout.addWidget(self.widgets['start button'], 3, 0)
        sublayout.addWidget(self.widgets['stop button'], 3, 1)

        layout = QHBoxLayout(self)
        layout.addWidget(self.widgets['dns table'])
        layout.addLayout(sublayout)

    def on_add(self):
        hostname = self.widgets['hostname input'].text()
        ip_address = self.widgets['ip input'].text()

        if len(hostname) == 0 or len(ip_address) == 0:
            self.show_error('Error', 'Please provide both a hostname and an ip address')
            return

        if hostname in self.dns_table:
            self.show_error('Error', 'The given hostname is already in the table')
            return

        self.widgets['hostname input'].clear()
        self.widgets['ip input'].clear()

        self.dns_table[hostname] = ip_address
        self.update_table()

    def on_item_remove(self, row):
        table = self.widgets['dns table']
        hostname = table.itemAt(row, 0).text()

        del self.dns_table[hostname]
        self.update_table()

    def update_table(self):
        table = self.widgets['dns table']
        table.clearContents()
        table.setRowCount(len(self.dns_table))

        dns_records = list(self.dns_table.items())
        for i in range(len(dns_records)):
            hostname, ip = dns_records[i]
            table.setItem(i, 0, QTableWidgetItem(hostname))
            table.setItem(i, 1, QTableWidgetItem(ip))

    def start(self):
        if self.attack is not None and self.attack.active:
            self.show_error('Cannot start DNS attack', 'There is already a DNS attack active')
            return
    
        # We send a reference of self.dns_table instead of a copy so that any
        # changes will go in effect immediatly, without restarting the attack
        self.attack = DNSAttack(self.interface, self.dns_table)
        self.attack.start()

    def stop(self):
        if self.attack is None or not self.attack.active:
            self.show_error('Cannot stop DNS attack', 'There is no DNS attack active')
            return
     
        self.attack.stop()

    def show_error(self, title, message):
        error_message = QMessageBox(QMessageBox.Icon.Critical, title, message)
        error_message.show()
        error_message.exec()
        