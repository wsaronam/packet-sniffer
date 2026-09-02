from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime




class Protocol(str, Enum):
    '''
    supported protocol labels
    '''
    ARP = 'ARP'
    TCP = 'TCP'
    UDP = 'UDP'
    ICMP = 'ICMP'
    ICMPV6 = 'ICMPv6'
    OTHER = 'OTHER'



@dataclass
class Packet:
    '''
    for 1 normalized network packet
    '''
    timestamp: datetime #when the packet was captured
    src_ip: str # source IP
    dst_ip: str # destionation IP
    protocol: Protocol # the Protocol enum
    length: int # packet size in bytes
    src_port: int | None = None # source port number
    dst_port: int | None = None # destination port number
    flags: str | None = None # optional TCP flags
    summary: str = '' # description of packet


    def to_dict(self) -> dict:
        '''
        converts packet into a dict to be stored in SQL or JSON
        '''
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['protocol'] = self.protocol.value
        return data


    @classmethod
    def from_dict(cls, data: dict) -> "Packet":
        '''
        Rebuilds a Packet object from a dict (from SQL or JSON)
        '''
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp']),
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            protocol=Protocol(data['protocol']),
            length=data['length'],
            src_port=data.get('src_port'),
            dst_port=data.get('dst_port'),
            flags=data.get('flags'),
            summary=data.get('summary', '')
        )