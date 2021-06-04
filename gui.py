from PyQt5.QtWidgets import *

app = QApplication([])

window = QWidget()

layout = QVBoxLayout()
listview = QListView()
layout.addWidget(listview)

def on_button_click():
    alert = QMessageBox()
    alert.setText('you clicked the button')
    alert.exec()

button = QPushButton('Click me')
button.clicked.connect(on_button_click)

layout_horizontal = QHBoxLayout()
layout_horizontal.addLayout(layout)
layout_horizontal.addWidget(button)

window.setLayout(layout_horizontal)
window.show()

app.exec()
