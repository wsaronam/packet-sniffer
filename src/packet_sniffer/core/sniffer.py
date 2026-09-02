import logging
from collections.abc import Callable
from datetime import datetime, timezone

from scapy.all import sniff, Packet as ScapyPacket
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from packet_sniffer.core.packet_model import Packet, Protocol




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


    @staticmethod
    def _translate(raw_packet: ScapyPacket) -> Packet | None:
        '''
        convers the raw Scapy packet into our Packet model.
        will return None if the type we don't handle yet
        '''
        timestamp = datetime.now(timezone.utc)
        length = len(raw_packet)


        if raw_packet.haslayer(ARP):
            arp=raw_packet[ARP]
            return Packet(
                timestamp=timestamp,
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                protocol=Protocol.ARP,
                length=length,
                summary=f'ARP {arp.psrc} -> {arp.pdst}'
            )


        if raw_packet.haslayer(IP):
            ip_layer = raw_packet[IP]
        elif raw_packet.haslayer(IPv6):
            ip_layer = raw_packet[IPv6]
        else:
            return None

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        

        if raw_packet.haslayer(IPv6) and ip_layer.nh == 58: #58 == ICMPv6
            return Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=Protocol.ICMPV6,
                length=length,
                summary=f'ICMPv6 {src_ip} -> {dst_ip}'
            )

        if raw_packet.haslayer(TCP):
            tcp = raw_packet[TCP]
            flags = str(tcp.flags)
            return Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=Protocol.TCP,
                length=length,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                flags=flags,
                summary=f'TCP {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport} [{flags}]'
            )


        if raw_packet.haslayer(UDP):
            udp = raw_packet[UDP]
            return Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=Protocol.UDP,
                length=length,
                src_port=udp.sport,
                dst_port=udp.dport,
                summary=f'UDP {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}'
            )


        if raw_packet.haslayer(ICMP):
            return Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=Protocol.ICMP,
                length=length,
                summary=f'ICMP {src_ip} -> {dst_ip}'
            )


        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=Protocol.OTHER,
            length=length,
            summary=f'Other {src_ip} -> {dst_ip}'
        )