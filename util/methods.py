import socket
import psutil
from scapy.all import ARP, Ether, srp
from entities import Host, Interface
from .address_family import AddressFamily

def get_prefix_length(mask):
    """Returns the prefix length of a subnet mask
    """
    return sum([bin(int(x)).count('1') for x in mask.split('.')])

def apply_mask(ip, mask):
    ip = [int(x) for x in ip.split('.')]
    mask = [int(x) for x in mask.split('.')]

    return str.join('.', [str(a & b) for a,b in zip(ip, mask)])

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

    return sort_hosts(hosts)

def sort_hosts(hosts):
    return sorted(hosts, key=lambda host: socket.inet_aton(host.ip_address))

def get_interfaces():
    """Returns a dictionary of the interfaces
    """
    interfaces = []

    for name, addresses in psutil.net_if_addrs().items():
        data = { 'name': name } 

        for address in addresses:
            if address.family == AddressFamily.AF_LINK:
                data['mac_address'] = address.address.replace('-', ':')
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