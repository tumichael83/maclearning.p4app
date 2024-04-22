from scapy.all import Packet, Ether, IP
from cpu_metadata import CPUMetadata
from pwospf_packet import PWOSPF_Hdr, PWOSPF_Hello, PWOSPF_Lsu, PWOSPF_LSA
from datetime import datetime as dt

from collections import namedtuple
NeighborEntry = namedtuple("NeighborEntry", "")


BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

PROTO_PWOSPF = 89

HELLOINT_DFLT = 10
LSUINT_DFLT = 15
TTL_DFLT    = 255

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

        self.lsuint         = LSUINT_DFLT
        self.last_lsu       = dt.now()
        self.seq            = 0
        self.ttl            = TTL_DFLT

        # receive PWOSPF broadcasts
        sw.insertTableEntry(
            table_name="MyIngress.local_ip_table",
            match_fields={"hdr.ipv4.dstAddr": [ALLOSPFADDR]},
            action_name="MyIngress.send_to_cpu",
            action_params={},
        )

    def broadcast(self):
        while not self.stop_event.wait(1): # loop in 1 second intervals
            # send my helloint
            if (dt.now() - self.last_hello).total_seconds() >= self.helloint:
                self.send_hello()
                self.last_hello = dt.now()

            # send my lsu
            if (dt.now() - self.last_lsu).total_seconds() >= self:
                self.send_lsu()
                self.last_lsu = dt.now()

    def send_hello(self):
        hello = Ether(src=self.mac, dst=BCAST_MAC)
        hello /= CPUMetadata()
        hello /= IP(src=self.ip, dst=ALLOSPFADDR, ttl=2)    # need 2 because its decremented once b4 sending
        hello /= PWOSPF_Hdr(routerID=self.routerID, areaID=self.areaID)
        hello /= PWOSPF_Hello(mask=self.mask, helloint=self.helloint)

        self.send(hello)

    def send_lsu(self):
        print('sending lsu')

        # not really sure about subnet=self.routerID
        lsalist = [PWOSPF_LSA(subnet=self.routerID,mask=self.mask,routerID=self.routerID)]



        self.seq += 1

    def handle(self, pkt):
        if not self.is_valid_ospf(pkt): return

        if pkt[PWOSPF_Hdr].type == 1:
            self.handle_hello(pkt)

        elif pkt[PWOSPF_Hdr].type == 4:
            self.handle_lsu(pkt)

    def handle_hello(self, pkt):
        print('received hello')

    def handle_lsu(self, pkt):
        print(self.sw.name+': received lsu')

    def is_valid_ospf(self, pkt):
        # TODO: Checksum
        if pkt[PWOSPF_Hdr].version != 2:
            return False
        
        elif pkt[PWOSPF_Hdr].areaID != self.areaID:
            return False
        
        else:
            return True


class PWOSPF_Iface():
    def __init__(self, mask, helloint):

        self.mask           = mask
        self.helloint       = helloint

        self.neighbors      = {} # 

