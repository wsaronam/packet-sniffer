from packet_sniffer.core.packet_model import Packet
from collections.abc import Callable




PacketHandler = Callable[[Packet], None]



class PacketSniffer:
    '''
    captures live network traffic and converts each packet into
    a 'Packet' object
    '''

    def __init__(
            self,
            callback: PacketHandler,
            interface: str | None = None,
            bpf_filter: str | None = None,
            packet_count: int = 0
                ) -> None:
        '''
        callback: func called once per packet for getting a Packet object
        interface: network interface to capture on
        bpf_filter: optional packet filter to capture only matching traffic
        packet_count: amount of packets to get before stopping (0 if infinite)
        '''
        self.callback = callback
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self._packets_captured = 0


    def start(self) -> None:
        '''
        starts capturing packets until stopped
        '''
        pass

