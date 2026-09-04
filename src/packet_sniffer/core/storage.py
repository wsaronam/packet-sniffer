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
        '''
        Gets and yields a connection and makes sure that is closes when it's done with
        '''
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
        '''
        saves one packet into the database
        '''
        data = packet.to_dict()
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT INTO packets
                    (timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port, flags, summary)
                VALUES
                    (:timestamp, :src_ip, :dst_ip, :protocol, :length, :src_port, :dst_port, :flags, :summary)
                ''',
                data
            )


    def total_count(self) -> int:
        '''
        returns the total amount of packets captured
        '''
        with self._connect() as conn:
            row = conn.execute('SELECT COUNT(*) as total FROM packets').fetchone()
        return row['total']


    def count_by_protocol(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT protocol, COUNT(*) as total FROM packets '
                'GROUP BY protocol ORDER BY total DESC'
            ).fetchall()
        return {row['protocol']: row['total'] for row in rows}


    def clear(self) -> None:
        '''
        deletes all captured packets
        '''
        with self._connect() as conn:
            conn.execute('DELETE FROM packets')
        logger.info('Cleared all packets from %s', self.db_path)