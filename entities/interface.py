from dataclasses import dataclass

@dataclass(unsafe_hash=True)
class Interface:
    name: str
    mac_address: str
    ip_address: str
    netmask: str
    network_address: str
    prefix_length: int

    @property
    def subnet(self):
        return f'{self.network_address}/{self.prefix_length}'