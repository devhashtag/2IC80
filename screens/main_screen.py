from util import AddressFamily
from widgets.host_widget import HostWidget
from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import *

class AttackTabWidget(QWidget):
    def __init__(self, parent=None):
        super(QWidget, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()

        self.tabs.resize(300, 200)

        self.tabs.addTab(self.tab1, 'Tab 1')
        self.tabs.addTab(self.tab2, 'Tab 2')

        self.tab1.layout = QVBoxLayout(self)
        self.l = QLabel()
        self.l.setText('This is the first tab')
        self.tab1.layout.addWidget(self.l)
        self.tab1.setLayout(self.tab1.layout)

        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)


class MainScreen(QWidget):
    def __init__(self, interface, parent=None):
        super().__init__(parent)

        self.interface = interface
        self.setWindowTitle('Main screen')

        layout = QHBoxLayout(self)
        layout.addWidget(AttackTabWidget())

        # self.host_widget = HostWidget(interface)
        # self.host_widget.on_host_clicked.connect(self.on_target_add)

        # self.targets = []
        # self.target_widget = QTableWidget()
        # self.target_widget.setColumnCount(1)
        # self.target_widget.setHorizontalHeaderLabels(['IP Address'])
        # self.target_widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # self.target_widget.setFont(QFont('monospace'))
        # self.target_widget.verticalHeader().hide()
        # self.target_widget.cellDoubleClicked.connect(self.on_target_cell_clicked)

        # layout = QHBoxLayout(self)
        # layout.addWidget(self.host_widget)
        # layout.addWidget(self.target_widget)


    def update_target_widget(self):
        self.target_widget.clearContents()
        self.target_widget.setRowCount(len(self.targets))

        for index, target in enumerate(self.targets):
            item = QTableWidgetItem(target['ip_address'])
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            item.setData(Qt.ItemDataRole.UserRole, target)
            self.target_widget.setItem(index, 0, item)

        self.target_widget.update()

    def on_target_add(self, target):
        print(target)
        self.targets.append(target)
        self.update_target_widget()

    def on_target_remove(self, target):
        self.targets = [x for x in self.targets if x['ip_address'] != target['ip_address']]
        self.update_target_widget()

    def on_target_cell_clicked(self, x, y):
        cell = self.target_widget.item(x, y)
        target = cell.data(Qt.ItemDataRole.UserRole)

        self.on_target_remove(target)
