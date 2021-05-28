
from scapy.all import *
from scapy.all import ARP, Ether, srp
from scapy.arch.windows import get_windows_if_list
from ipaddress import IPv4Network
import netifaces #type: ignore

# get interfaces, choose one to perfom the attack on
# interfaces = get_if_list()

iface = conf.iface
ipv4 = get_if_addr(iface)

subnet = IPv4Network('192.168.2.0/24')

ip = '192.168.2.13/24'
arp = ARP(pdst=ip)
ether = Ether(dst='ff:ff:ff:ff:ff:ff')
packet = ether/arp
result = srp(packet, timeout=3)[0]

for request, response in result:
    print(f'IP: {response.psrc} MAC: {response.hwsrc}')

# choose target 1
# choose target 2
# send ARP reply to target 1
# send ARP reply to target 2
# repeat ARP replies every X seconds