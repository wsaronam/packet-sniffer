from packet_sniffer.core.packet_model import Packet, Protocol

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text




PROTOCOL_STYLES = {
    Protocol.TCP: 'cyan',
    Protocol.UDP: 'magenta',
    Protocol.ICMP: 'yellow',
    Protocol.ICMPV6: 'yellow',
    Protocol.ARP: 'green',
    Protocol.OTHER: 'white'
}


PORT_NAMES = {
    21: 'ftp',
    22: 'ssh',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    443: 'https',
    3389: 'rdp'
}




class PacketFormatter:
    '''
    Takes packets and summaries in the console and makes them look better
    '''

    def __init__(self) -> None:
        self.console = Console(soft_wrap=True)


    def print_banner(self, db_path: str) -> None:
        self.console.print(
            Panel.fit(
                f'[bold]Packet Sniffer[/bold]\n'
                f'Saving captures to: [cyan]{db_path}[/cyan]\n'
                f'Press [bold]Ctrl+C[/bold] to stop'
            )
        )


    def print_packet(self, packet: Packet) -> None:
        style = PROTOCOL_STYLES.get(packet.protocol, 'white')
        pak = packet.timestamp.strftime('%H:%M:%S.%f')[:-3]

        line = Text()

        #put stuff here

        self.console.print(line)


    def print_summary(self, total: int, by_protocol: dict[str, int]) -> None:
        table = Table(title='Capture Summary', show_header=True, header_style='bold blue')
        table.add_column('Protocol')
        table.add_column('Count', justify='right')
        table.add_column('Share', justify='right')

        for proto, count in by_protocol.items():
            pct = (count / total * 100) if total else 0
            style = PROTOCOL_STYLES.get(Protocol(proto), 'white')
            table.add_row(f'[{style}]{proto}[/{style}]', str(count), f'{pct:.1f}%')

        self.console.print()
        self.console.print(table)
        self.console.print(f'[bold]Total:[/bold] {total} packet(s)')
        