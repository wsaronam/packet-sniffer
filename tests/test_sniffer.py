from scapy.layers.inet import IP, TCP, UDP, ICMP

from packet_sniffer.core.packet_model import Protocol
from packet_sniffer.core.sniffer import PacketSniffer




def test_ipv4_tcp():
    pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="S")
    result = PacketSniffer._translate(pkt)
    assert result.protocol == Protocol.TCP
    assert result.src_ip == "192.168.1.10"
    assert result.dst_port == 443


def test_ipv4_udp():
    pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=51000, dport=53)
    result = PacketSniffer._translate(pkt)
    assert result.protocol == Protocol.UDP
    assert result.dst_port == 53


def test_ipv4_icmp():
    pkt = IP(src="192.168.1.10", dst="8.8.8.8") / ICMP()
    result = PacketSniffer._translate(pkt)
    assert result.protocol == Protocol.ICMP