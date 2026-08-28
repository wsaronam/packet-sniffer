import sys

from packet_sniffer.core.packet_model import Packet
from packet_sniffer.core.sniffer import PacketSniffer
from packet_sniffer.core.storage import PacketStorage




def make_packet_handler(storage: PacketStorage):
    '''
    returns callback function that saves the packet to storage
    '''
    return



def main() -> None:
    #parser = build_parser()
    storage = PacketStorage()
    sniffer = PacketSniffer(
        callback='',
        interface='',
        bpf_filter='',
        packet_count=''
    )

    try:
        sniffer.start()
    except KeyboardInterrupt:
        pass
    except:
        sys.exit(1)
    finally:
        total = storage.total_count()
        print(f'Capture stopped.  {total} packet(s) total')




if __name__ == '__main__':
    main()