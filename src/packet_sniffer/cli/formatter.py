from packet_sniffer.core.packet_model import Packet, Protocol
from packet_sniffer.core.detector import Alert

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


def _port_label(port: int | None) -> str:
    if port is None:
        return ''
    else:
        name = PORT_NAMES.get(port)
        return f'{port} ({name})' if name else str(port)




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
        line.append(f'{pak}  ', style='dim')
        line.append(f'{packet.protocol.value:<7}', style=f'bold {style}')

        if packet.src_port or packet.dst_port:
            endpoint = (
                f'{packet.src_ip}:{_port_label(packet.src_port)}'
                f' \u2192 {packet.dst_ip}:{_port_label(packet.dst_port)}'
            )
        else:
            endpoint = f'{packet.src_ip} \u2192 {packet.dst_ip}'
        line.append(endpoint, style=style)

        if packet.flags:
            line.append(f'  [{packet.flags}]', style='dim')

        line.append(f'  {packet.length}B', style='dim')


        self.console.print(line)



    def print_alert(self, alert: Alert) -> None:
        '''
        prints the detected security event and make it look different from other packet lines
        '''
        pak = alert.timestamp.strftime('%H:%M:%S.%f')[:-3]
        self.console.print(
            Panel(
                f'[bold]{alert.alert_type}[/bold]  {alert.description}',
                title=f'\u26a0 ALERT  [{pak}]',
                border_style='bold red',
                style='red'
            )
        )


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
        