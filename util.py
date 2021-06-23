import socket
import psutil
# from scapy.all import *
from scapy.all import ARP, Ether, srp, DNS, IP, UDP

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

def get_interfaces():
    """Returns a dictionary of the interfaces
    """
    interfaces = psutil.net_if_addrs()
    interfaces_data = {}

    # Iterate over the interfaces
    for name, addresses in interfaces.items():
        interface_data = { 'name': name }

        # Loop over the addresses of the different OSI layers
        # (we are only interested in the link and network layers)
        for address in addresses:
            if address.family == AddressFamily.AF_LINK:
                interface_data['mac_address'] = address.address
            elif address.family == AddressFamily.AF_INET:
                network_ip = apply_mask(address.address, address.netmask)
                prefix_length = get_prefix_length(address.netmask)

                interface_data['ip_address'] = address.address
                interface_data['netmask'] = address.netmask
                interface_data['subnet'] = f'{network_ip}/{prefix_length}'

        interfaces_data[name] = interface_data

    return interfaces_data

def scan_hosts(subnet):
    """Scans the subnet (in cidr notation) and returns a list of hosts
    """
    packet = Ether() / ARP()
    packet[ARP].pdst = subnet
    packet[Ether].dst = 'ff:ff:ff:ff:ff:ff'

    answered_requests, unanswered_requests = srp(packet, timeout=10, verbose=0)
    hosts = [{
        'ip_address': response.psrc,
        'mac_address': response.hwsrc
    } for request, response in answered_requests]

    return hosts