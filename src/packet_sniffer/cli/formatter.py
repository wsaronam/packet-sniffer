from packet_sniffer.core.packet_model import Packet, Protocol

from rich.console import Console
from rich.panel import Panel




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
        return


    def print_summary(self, total: int) -> None:
        return