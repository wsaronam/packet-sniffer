from dataclasses import dataclass
from datetime import datetime, timedelta


from packet_sniffer.core.packet_model import Packet




@dataclass
class Alert:
    '''
    a detected security event
    '''
    timestamp: datetime
    alert_type: str
    src_ip: str
    description: str
    severity: str = 'medium'


class PortScanDetector:
    '''
    flags source IP as possible port scanner if it has contacts more than "port_threshold" within "windows_seconds" time
    '''
    def __init__(self,
                 port_threshold: int = 15,
                 window_seconds: int = 10,
                 cooldown_seconds: int = 30) -> None:
        self.port_threshold = port_threshold
        self.window = timedelta(seconds=window_seconds)
        self.cooldown = timedelta(seconds=cooldown_seconds)


    def check(self, packet: Packet) -> Alert | None:
        '''
        looks at one packet and returns Alert if it passes the port-scan threshold
        '''
        if packet.dst_port is None:
            return None