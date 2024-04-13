from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata

from arp_handler import ArpHandler

import time

class MacLearningController(Thread):
    def __init__(self, sw, start_wait=0.3):
        super(MacLearningController, self).__init__()

        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.stop_event = Event()

        self.sw = sw
        self.iface = sw.intfs[1].name

        self.arp_handler = ArpHandler(sw, self.send)


    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            self.arp_handler.handle(pkt)

        elif IP in pkt:
            pkt.show2()

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)
