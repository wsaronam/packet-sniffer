from packet_sniffer.core.packet_model import Packet, Protocol

from datetime import datetime, timezone



def make_sample_packet() -> Packet:
    return Packet(
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        protocol=Protocol.TCP,
        length=1500,
        src_port=51000,
        dst_port=443,
        flags="SYN",
        summary="TCP SYN test",
    )


def test_to_dict_contains_expected_fields():
    packet = make_sample_packet()
    data = packet.to_dict()

    assert data["src_ip"] == "192.168.1.10"
    assert data["protocol"] == "TCP"
    assert data["timestamp"] == "2026-01-01T12:00:00+00:00"


def test_round_trip_preserves_all_fields():
    original = make_sample_packet()
    rebuilt = Packet.from_dict(original.to_dict())

    assert rebuilt == original


def test_round_trip_with_optional_fields_missing():
    original = Packet(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.1",
        dst_ip="192.168.1.10",
        protocol=Protocol.ARP,
        length=42,
        summary="ARP reply",
    )

    rebuilt = Packet.from_dict(original.to_dict())

    assert rebuilt.src_port is None
    assert rebuilt.dst_port is None
    assert rebuilt.flags is None