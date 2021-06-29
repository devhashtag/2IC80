print('Importing modules...')

from PyQt6.QtWidgets import QApplication
from scapy.all import conf
from window import Window

print('Initializing application...')

# Disable promiscuous mode as we are not interested in packets
# not addressed to us
conf.sniff_promisc = False

app = QApplication([])
window = Window()
window.show()

print('Initialized!')

app.exec()