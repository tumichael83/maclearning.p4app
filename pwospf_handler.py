from scapy.all import Packet, Ether, IP
from cpu_metadata import CPUMetadata
from pwospf_packet import PWOSPF_Hdr, PWOSPF_Hello, PWOSPF_Lsu
from datetime import datetime as dt

BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

PROTO_PWOSPF = 89

HELLOINT_DFLT = 10
ALLOSPFADDR = '224.0.0.5'

class PWOSPFHandler():
    def __init__(self, stop_event, sw, send_func, ip, mac, routerID, areaID, mask):

        self.stop_event     = stop_event
        self.send           = send_func

        self.sw             = sw
        self.areaID         = send_func

        self.ip             = ip
        self.mac            = mac

        self.routerID       = routerID
        self.areaID         = areaID
        self.mask           = mask

        self.helloint       = HELLOINT_DFLT
        self.last_hello     = dt.now()

        # receive PWOSPF broadcasts
        sw.insertTableEntry(
            table_name="MyIngress.local_ip_table",
            match_fields={"hdr.ipv4.dstAddr": [ALLOSPFADDR]},
            action_name="MyIngress.send_to_cpu",
            action_params={},
        )

    def broadcast(self):
        while not self.stop_event.wait(1): # loop in 1 second intervals
            
            if (dt.now() - self.last_hello).total_seconds() >= self.helloint:
                self.send_hello()
                self.last_hello = dt.now()

    def send_hello(self):
        hello = Ether(src=self.mac, dst=BCAST_MAC)
        hello /= CPUMetadata()
        hello /= IP(src=self.ip, dst=ALLOSPFADDR, ttl=1) # ttl == 1 bc we only broadcast to our neighbors
        hello /= PWOSPF_Hdr(routerID=self.routerID, areaID=self.areaID)
        hello /= PWOSPF_Hello(mask=self.mask, helloint=self.helloint)
        self.send(hello)

    def handle(self, pkt):
        if pkt[PWOSPF_Hdr].type == 1:
            self.handle_hello(pkt)

        elif pkt[PWOSPF_Hdr].type == 4:
            self.handle_lsu(pkt)

    def handle_hello(self, pkt):
        print('received hello')

    def handle_lsu(self, pkt):
        pass


