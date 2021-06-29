from PyQt5.QtWidgets import (
    QWidget
)

class AsyncWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.threads = []

    def execute_thread(self, thread):
        self.threads.append(thread)
        
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self.threads.remove(thread))
        thread.start()