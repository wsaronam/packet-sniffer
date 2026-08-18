from enum import Enum
from dataclasses import dataclass
from datetime import datetime




class Protocol(str, Enum):
    '''
    supported protocol labels
    '''
    TCP = 'TCP'
    UDP = 'UDP'
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
        pass



    def from_dict(cls, data: dict) -> Packet:
        '''
        Rebuilds a Packet object from a dict (from SQL or JSON)
        '''
        pass