from scapy.all import Packet, Ether, IP
from cpu_metadata import CPUMetadata
from pwospf_packet import PWOSPF_Hdr, PWOSPF_Hello, PWOSPF_Lsu, PWOSPF_LSA
from datetime import datetime as dt

from collections import namedtuple
NeighborEntry = namedtuple("NeighborEntry", "routerID helloint last_hello mac")


BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

PROTO_PWOSPF = 89

HELLOINT_DFLT = 10
LSUINT_DFLT = 15
TTL_DFLT    = 255

ALLOSPFADDR = '224.0.0.5'

class PWOSPFHandler():
    def __init__(self, stop_event, sw, ifaces, send_func, ip, mac, routerID, areaID, mask):

        self.stop_event     = stop_event
        self.send           = send_func

        self.sw             = sw
        self.ifaces         = ifaces
        self.send           = send_func

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
        while not self.stop_event.wait(0.5): # loop in 1 second intervals
            # send my helloint
            if (dt.now() - self.last_hello).total_seconds() >= self.helloint:
                self.send_hello()
                self.last_hello = dt.now()

            # send my lsu
            if (dt.now() - self.last_lsu).total_seconds() >= self.lsuint:
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
        for port, iface in self.ifaces.items():
            for router_ip, neighbor in iface.neighbors.items():
                pass

        for port, iface in self.ifaces.items():
            for router_ip, neighbor in iface.neighbors.items():
                pkt = Ether(dst=neighbor.mac,src=self.mac)
                pkt /= CPUMetadata()
                pkt /= IP(src=self.ip, dst=router_ip)
                pkt /= PWOSPF_Hdr(routerID=self.routerID,areaID=self.areaID)
                pkt /= PWOSPF_Lsu(seq=self.seq,ttl=self.ttl,count=len(lsalist),lsalist=lsalist)

                self.send(pkt)


        self.seq += 1

    def handle(self, pkt):
        if not self.is_valid_ospf(pkt): return

        if pkt[PWOSPF_Hdr].type == 1:
            self.handle_hello(pkt)

        elif pkt[PWOSPF_Hdr].type == 4:
            self.handle_lsu(pkt)

    def handle_hello(self, pkt):

        # match to iface
        srcPort = pkt[CPUMetadata].srcPort
        iface = self.ifaces[srcPort]

        # check network mask and helloint
        if pkt[PWOSPF_Hello].mask != iface.mask or pkt[PWOSPF_Hello].helloint != iface.helloint:
            return

        neighbor_router_ip = pkt[IP].src
        neighbor_mac = pkt[CPUMetadata].origEtherSrc

        if neighbor_router_ip not in iface.neighbors.keys():
            self.sw.insertTableEntry( # arp entry for neighbor, should this be a call to arp_handler?
                table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': neighbor_router_ip},
                action_name='MyIngress.find_next_hop_mac',
                action_params={'dstAddr': neighbor_mac}
            )
            self.sw.insertTableEntry(
                table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': neighbor_mac},
                action_name='MyIngress.set_egr',
                action_params={'port': srcPort}
            )

        iface.neighbors[neighbor_router_ip] = NeighborEntry(
            routerID=pkt[PWOSPF_Hdr].routerID, 
            helloint=pkt[PWOSPF_Hello].helloint, 
            last_hello=dt.now(), 
            mac=neighbor_mac
        )

        # print(iface.neighbors)
        

    def handle_lsu(self, pkt):
        # if self.sw.name == 's1':
        #     pkt.show2()

    def is_valid_ospf(self, pkt):
        # TODO: Checksum
        if pkt[PWOSPF_Hdr].version != 2:
            return False
        
        elif pkt[PWOSPF_Hdr].areaID != self.areaID:
            return False
        
        else:
            return True


class PWOSPF_Iface():
    def __init__(self,ip,mask,helloint):

        self.ip             = ip
        self.mask           = mask
        self.helloint       = helloint

        self.neighbors      = {} # device ip: routerID helloint last_hello mac

