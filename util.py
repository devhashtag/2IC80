import socket
import psutil

def get_prefix_length(mask):
    """Returns the prefix length of a subnet mask
    """
    return sum([bin(int(x)).count('1') for x in mask.split('.')])

def apply_mask(ip, mask):
    ip = [int(x) for x in ip.split('.')]
    mask = [int(x) for x in mask.split('.')]

    return str.join('.', [str(a & b) for a,b in zip(ip, mask)])

class AddressFamily():
    # socket and psutil have different values
    # for AF_LINK, so we have to use the psutil
    AF_LINK = psutil.AF_LINK
    AF_INET = socket.AF_INET

class Dns():
    QUERY = 0
    RESPONSE = 1

    OPCODE_STANDARD_QUERY = 0
    OPCODE_INVERSE_QUERY = 1
    OPCODE_STATUS_REQUEST = 2