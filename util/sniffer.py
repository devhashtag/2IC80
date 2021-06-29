from scapy.sendrecv import sniff
from threading import Thread, Event
from entities import Interface
from typing import Callable

class Sniffer(Thread):
    def __init__(self, interface: Interface, process_packet: Callable):
        super().__init__()

        self.interface = interface
        self.process_packet = process_packet
        self.stop_sniffing = Event()

    def run(self):
        sniff(iface=self.interface.name, store=0, prn=self.handle_packet, stop_filter=self.should_stop_sniffing)

    def join(self, timeout=None):
        self.stop_sniffing.set()
        super().join(timeout)

    def should_stop_sniffing(self, _=None):
        return self.stop_sniffing.is_set()

    def handle_packet(self, packet):
        '''
        The stop_filter is only called once after each packet, which means
        that if the sniffer should stop, it still sniffs 1 packet. This method
        makes sure that the user-defined process_packet function will not be
        called with packets after the sniffer has stopped.
        '''
        if self.should_stop_sniffing():
            return

        self.process_packet(packet)