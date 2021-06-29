import socket
import psutil

class AddressFamily:
    # socket and psutil have different values
    # for AF_LINK, so we have to use the psutil one
    AF_LINK = psutil.AF_LINK
    AF_INET = socket.AF_INET