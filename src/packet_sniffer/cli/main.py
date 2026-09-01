import sys
import argparse

from scapy.all import get_if_list

from packet_sniffer.core.packet_model import Packet
from packet_sniffer.core.sniffer import PacketSniffer
from packet_sniffer.core.storage import PacketStorage




def make_packet_handler(storage: PacketStorage):
    '''
    returns callback function that saves the packet to storage
    '''
    def handle_packet(packet: Packet) -> None:
        pak = packet.timestamp.strftime('%H:%M:%S.%f')[:-3]
        print(f'[{pak}] {packet.summary} ({packet.length} bytes)')
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

    return parser


def print_interfaces() -> None:
    '''
    prints available interfaces for user to pick
    '''
    print("Available interfaces:")
    for iface in get_if_list():
        print(f' - {iface}')



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.print_interfaces:
        print_interfaces()
        return

    storage = PacketStorage(args.db)

    if args.clear_db:
        storage.clear()
        print(f'Cleared all packets from {args.db}')
        return


    print('Packet Sniffer - press Ctrl+C to stop')
    print(f'Saving captures to: {args.db}')

    sniffer = PacketSniffer(
        callback='',
        interface='',
        bpf_filter='',
        packet_count=''
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
        print(f'Capture stopped.  {total} packet(s) total')




if __name__ == '__main__':
    main()