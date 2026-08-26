from pathlib import Path
import logging
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from packet_sniffer.core.packet_model import Packet




logger = logging.getLogger(__name__)

_CREATE_TABLE_SQL = '''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        length INTEGER NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        flags TEXT,
        summary TEXT
    );
'''

_CREATE_INDEX_SQL = '''
    CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp);
'''


class PacketStorage:
    '''
    Handles reads and writes to database
    '''
    def __init__(self, db_path: str | Path = 'packets.db') -> None:
        self.db_path = Path(db_path)
        self._init_db()


    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()


    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE_SQL)
            conn.execute(_CREATE_INDEX_SQL)
        logger.info('Database ready at %s', self.db_path.resolve())


    def save(self, packet: Packet) -> None:
        data = packet.to_dict()
        # insert packet info into database
        pass


    def total_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute('SELECT COUNT(*) as total FROM packets').fetchone()
        return row['total']


    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute('DELETE FROM packets')
        logger.info('Cleared all packets from %s', self.db_path)