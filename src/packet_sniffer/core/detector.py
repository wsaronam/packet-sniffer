from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque


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

        # src_ip -> deque of (timestamp, dst_port) recently seen
        self._activity: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        # src_ip -> timestamp of last alert
        self._last_alerted: dict[str, datetime] = {}


    def check(self, packet: Packet) -> Alert | None:
        '''
        looks at one packet and returns Alert if it passes the port-scan threshold
        '''
        if packet.dst_port is None:
            return None

        now = packet.timestamp
        src = packet.src_ip
        history = self._activity[src]

        history.append((now, packet.dst_port))
        self._prune(history, now)

        unique_ports = {port for _, port in history}
        if len(unique_ports) < self.port_threshold:
            return None

        last_alert = self._last_alerted.get(src)
        if last_alert and (now - last_alert) < self.cooldown:
            return None #already already recently for this

        self._last_alerted[src] = now
        return Alert(
            timestamp=now,
            alert_type='PORT_SCAN',
            src_ip=src,
            description=(
                f'{src} contacted {len(unique_ports)} unique ports '
                f'in the last {int(self.window.total_seconds())}s'
            ),
            severity='high'
        )


    def _prune(self, history: deque[tuple[datetime, int]], now: datetime) -> None:
        '''
        drops entries older than the detection window
        '''
        while history and (now - history[0][0]) > self.window:
            history.popleft()