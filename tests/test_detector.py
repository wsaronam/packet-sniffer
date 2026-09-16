from packet_sniffer.core.packet_model import Packet, Protocol
from packet_sniffer.core.detector import PortScanDetector

from datetime import datetime, timedelta, timezone




BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)



def make_packet(t, src_ip, dst_port):
    return Packet(
        timestamp=t,
        src_ip=src_ip,
        dst_ip="192.168.1.50",
        protocol=Protocol.TCP,
        length=60,
        src_port=51000,
        dst_port=dst_port,
    )


