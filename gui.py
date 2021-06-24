print('Importing modules...')

from PyQt6.QtWidgets import QApplication
from window import Window

print('Initializing application...')

app = QApplication([])
window = Window()
window.show()

print('Initialized!')

app.exec()