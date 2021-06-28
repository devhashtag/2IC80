from dataclasses import dataclass

@dataclass(unsafe_hash=True)
class Host:
    ip_address: str
    mac_address: str