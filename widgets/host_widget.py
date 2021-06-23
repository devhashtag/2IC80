from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QFont

from util import scan_hosts

class HostWidget(QTableWidget):
    on_host_clicked = QtCore.pyqtSignal(dict)

    def __init__(self, interface, *args):
        QTableWidget.__init__(self, *args)

        self.interface = interface
        self.hosts = []

        self.refresh()

    def scan_hosts(self):
        subnet = self.interface['subnet']
        self.hosts = scan_hosts(subnet)

    def update_table(self):
        n_hosts = len(self.hosts)

        self.clearContents()
        self.setColumnCount(2)
        self.setHorizontalHeaderLabels(['IP Address', 'MAC Address'])
        self.setRowCount(n_hosts)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setFont(QFont('monospace'))
        self.font().setStyleHint(QFont.StyleHint.TypeWriter)
        self.verticalHeader().hide()

        self.cellDoubleClicked.connect(self.on_cell_clicked)

        for i in range(n_hosts):
            host = self.hosts[i]

            for j in range(len(host)):
                key = list(host.keys())[j]
                item = QTableWidgetItem(host[key])
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setData(Qt.ItemDataRole.UserRole, host)

                print(i)
                print(j)
                print(item.data(Qt.ItemDataRole.UserRole))
                self.setItem(i, j, item)

    def refresh(self):
        self.scan_hosts()
        self.update_table()

    def on_cell_clicked(self, row, column):
        cell = self.item(row, column)
        host = cell.data(Qt.ItemDataRole.UserRole)

        print(cell.data(Qt.ItemDataRole.DisplayRole))

        self.on_host_clicked.emit(host)
