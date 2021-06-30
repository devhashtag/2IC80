print('Importing modules...')

from PyQt5.QtWidgets import QApplication
from scapy.all import conf, load_layer
from window import Window

print('Initializing application...')

# Disable promiscuous mode as we are not interested in packets
# not addressed to us
conf.sniff_promisc = False
# We will be using the http layer
load_layer('http')

app = QApplication([])
window = Window()
window.show()

print('Initialized!')

app.exec()