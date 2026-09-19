from packet_sniffer.core.packet_model import Packet, Protocol
from packet_sniffer.core.storage import PacketStorage

from datetime import datetime, timedelta, timezone

import pytest




def make_packet(src_ip="192.168.1.10", protocol=Protocol.TCP, **overrides):
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip="93.184.216.34",
        protocol=protocol,
        length=100,
    )
    defaults.update(overrides)
    return Packet(**defaults)


@pytest.fixture
def storage(tmp_path):
    """
    a fresh PacketStorage on a temp file,removed by pytest after each test
    """
    db_path = tmp_path / "test_packets.db"
    return PacketStorage(db_path)


def test_starts_empty(storage):
    assert storage.total_count() == 0


def test_save_and_count(storage):
    storage.save(make_packet())
    storage.save(make_packet())
    assert storage.total_count() == 2


def test_count_by_protocol(storage):
    storage.save(make_packet(protocol=Protocol.TCP))
    storage.save(make_packet(protocol=Protocol.TCP))
    storage.save(make_packet(protocol=Protocol.UDP))

    counts = storage.count_by_protocol()
    assert counts["TCP"] == 2
    assert counts["UDP"] == 1


def test_clear_removes_all_packets(storage):
    storage.save(make_packet())
    storage.save(make_packet())
    storage.clear()
    assert storage.total_count() == 0


def test_connections_are_closed_after_each_call(storage):
    """
    test if the connection is closed after storage call is completed
    """
    import sqlite3

    with storage._connect() as conn:
        pass  # connection is used and released here

    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")