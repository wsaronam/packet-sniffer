import sys
import argparse

from scapy.all import get_if_list

from packet_sniffer.core.packet_model import Packet
from packet_sniffer.core.sniffer import PacketSniffer
from packet_sniffer.core.storage import PacketStorage
from packet_sniffer.cli.formatter import PacketFormatter




def make_packet_handler(storage: PacketStorage, formatter: PacketFormatter):
    '''
    returns callback function that saves the packet to storage
    '''
    def handle_packet(packet: Packet) -> None:
        # pak = packet.timestamp.strftime('%H:%M:%S.%f')[:-3]
        # print(f'[{pak}] {packet.summary} ({packet.length} bytes)')
        formatter.print_packet(packet)
        storage.save(packet)
    return handle_packet


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='packet-sniffer',
        description='network packet sniffer using Scapy'
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture on (ex "Wi-Fi" or "Ethernet")'
            'Defaults to Scapy default interface',
        default=None
    )
    parser.add_argument(
        '-f', '--filter',
        dest='bpf_filter',
        help='Berkeley Packet Filter expression ex "tcp port 443"',
        default=None
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture before stopping (0 = unlimited)'
    )
    parser.add_argument(
        '--db',
        default='packets.db',
        help='Path to SQL db file (default: packets.db)'
    )
    parser.add_argument(
        '--clear-db',
        action='store_true',
        help='Clear all stored packets from the database'
    )
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List all available network interfaces'
    )

    return parser


def list_interfaces() -> None:
    '''
    prints available interfaces for user to pick
    '''
    print("Available interfaces:")
    for iface in get_if_list():
        print(f' - {iface}')



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    storage = PacketStorage(args.db)
    formatter = PacketFormatter()

    if args.clear_db:
        storage.clear()
        print(f'Cleared all packets from {args.db}')
        return

    formatter.print_banner(args.db)

    sniffer = PacketSniffer(
        callback=make_packet_handler(storage, formatter),
        interface=args.interface,
        bpf_filter=args.bpf_filter,
        packet_count=args.count
    )

    try:
        sniffer.start()
    except PermissionError:
        print('Permission denied.  Please make sure your have proper administrator permissions.',
              file=sys.stderr
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        total = storage.total_count()
        by_protocol = storage.count_by_protocol()
        formatter.print_summary(total, by_protocol)




if __name__ == '__main__':
    main()



# testing purposes
# $env:PYTHONPATH = "src"
# python -m packet_sniffer.cli.main