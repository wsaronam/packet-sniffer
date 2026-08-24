import logging
from collections.abc import Callable
from datetime import datetime, timezone

from packet_sniffer.core.packet_model import Packet, Protocol

from scapy.all import sniff, Packet as ScapyPacket
from scapy.layers.inet import IP, TCP, UDP




logger = logging.getLogger(__name__)

PacketHandler = Callable[[Packet], None]



class PacketSniffer:
    '''
    captures live network traffic and converts each packet into
    a 'Packet' object
    '''

    def __init__(
            self,
            callback: PacketHandler,
            interface: str | None = None,
            bpf_filter: str | None = None,
            packet_count: int = 0
                ) -> None:
        '''
        callback: func called once per packet for getting a Packet object
        interface: network interface to capture on
        bpf_filter: optional packet filter to capture only matching traffic
        packet_count: amount of packets to get before stopping (0 if infinite)
        '''
        self.callback = callback
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self._packets_captured = 0


    def start(self) -> None:
        '''
        starts capturing packets until stopped
        '''
        logger.info(
            'Starting capture on interface=%s filter=%r count=%s',
            self.interface or 'default',
            self.bpf_filter,
            self.packet_count or 'unlimited'
        )

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                count=self.packet_count,
                store=False
            )
        except:
            logger.error()
            raise


    def _on_packet(self, raw_packet: ScapyPacket) -> None:
        '''
        converts raw packet and forwards it to handler
        '''
        packet = self._translate(raw_packet)
        if packet is None:
            return
        self._packets_captured += 1
        self.callback(packet)


    def _translate(raw_packet: ScapyPacket) -> Packet | None:
        '''
        convers the raw Scapy packet into our Packet model.
        will return None if the type we don't handle yet
        '''
        timestamp = datetime.now(timezone.utc)
        length = len(raw_packet)

        if not raw_packet.haslayer(IP):
            return None

        ip_layer = raw_packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        

        if raw_packet.haslayer(TCP):
            return

        if raw_packet.haslayer(UDP):
            return

        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=Protocol.OTHER,
            length=length,
            summary=f'Other {src_ip} -> {dst_ip}'
        )