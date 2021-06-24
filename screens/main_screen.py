from widgets import AsyncWidget
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
