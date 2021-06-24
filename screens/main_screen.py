from async_widget import AsyncWidget
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QTabWidget,
    QHBoxLayout,
)

class MainScreen(AsyncWidget):
    def __init__(self, interface, parent=None):
        super().__init__(parent)

        self.interface = interface
        self.setWindowTitle('Main screen')

        self.tab_widget = QTabWidget()

        layout = QHBoxLayout(self)
        layout.addWidget(self.tab_widget)

    @property
    def tabs(self):
        n_tabs = self.tab_widget.count()
        tabs = [self.tab_widget.widget(i) for i in range(n_tabs)]

        return tabs

    def add_tab(self, tab, name):
        self.tab_widget.addTab(tab, name)

    def remove_tab(self, tab):
        try:
            index = self.tabs.index(tab)
            self.tab_widget.removeTab(index)
        except ValueError:
            raise ValueError(f'{tab} is not in the list of tabs')

    # def update_target_widget(self):
    #     self.target_widget.clearContents()
    #     self.target_widget.setRowCount(len(self.targets))

    #     for index, target in enumerate(self.targets):
    #         item = QTableWidgetItem(target['ip_address'])
    #         item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    #         item.setData(Qt.ItemDataRole.UserRole, target)
    #         self.target_widget.setItem(index, 0, item)

    #     self.target_widget.update()

    # def on_target_add(self, target):
    #     print(target)
    #     self.targets.append(target)
    #     self.update_target_widget()

    # def on_target_remove(self, target):
    #     self.targets = [x for x in self.targets if x['ip_address'] != target['ip_address']]
    #     self.update_target_widget()

    # def on_target_cell_clicked(self, x, y):
    #     cell = self.target_widget.item(x, y)
    #     target = cell.data(Qt.ItemDataRole.UserRole)

    #     self.on_target_remove(target)
