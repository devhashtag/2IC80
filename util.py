from entities import Interface, Host
import socket
import psutil
from scapy.all import ARP, Ether, srp, DNS, IP, UDP
from PyQt6.QtCore import QThread, pyqtSignal

def get_prefix_length(mask):
    """Returns the prefix length of a subnet mask
    """
    return sum([bin(int(x)).count('1') for x in mask.split('.')])

def apply_mask(ip, mask):
    ip = [int(x) for x in ip.split('.')]
    mask = [int(x) for x in mask.split('.')]

    return str.join('.', [str(a & b) for a,b in zip(ip, mask)])

class AddressFamily:
    # socket and psutil have different values
    # for AF_LINK, so we have to use the psutil one
    AF_LINK = psutil.AF_LINK
    AF_INET = socket.AF_INET

class Dns:
    QUERY = 0
    RESPONSE = 1

    OPCODE_STANDARD_QUERY = 0
    OPCODE_INVERSE_QUERY = 1
    OPCODE_STATUS_REQUEST = 2

def get_interfaces():
    """Returns a dictionary of the interfaces
    """
    interfaces = []

    for name, addresses in psutil.net_if_addrs().items():
        data = { 'name': name } 

        for address in addresses:
            if address.family == AddressFamily.AF_LINK:
                data['mac_address'] = address.address
            elif address.family == AddressFamily.AF_INET:
                data['ip_address'] = address.address
                data['netmask'] = address.netmask
                data['network_address'] = apply_mask(data['ip_address'], data['netmask'])
                data['prefix_length'] = get_prefix_length(data['netmask'])

        try:
            interfaces.append(Interface(
                data['name'],
                data['mac_address'],
                data['ip_address'],
                data['netmask'],
                data['network_address'],
                data['prefix_length']
            ))
        except KeyError as error:
            key = error.args[0]
            print(f"Skipping interface {name} because it has no value for '{key}'")

    return interfaces

def scan_hosts(subnet):
    """Scans the subnet (in cidr notation) and returns a list of hosts
    """
    packet = Ether() / ARP()
    packet[ARP].pdst = subnet
    packet[Ether].dst = 'ff:ff:ff:ff:ff:ff'

    answered_requests, unanswered_requests = srp(packet, timeout=10, verbose=0)
    hosts = [
        Host(response.psrc, response.hwsrc)
        for request, response in answered_requests
    ]

    return hosts

class InterfaceLoader(QThread):
    interfaces_loaded = pyqtSignal(list)

    def run(self):
        interfaces = get_interfaces()
        self.interfaces_loaded.emit(interfaces)

class HostScanner(QThread):
    scan_finished = pyqtSignal(list)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        hosts = scan_hosts(self.subnet)
        self.scan_finished.emit(hosts)
