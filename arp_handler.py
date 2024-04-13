from scapy.all import Packet, Ether, IP, ARP
from cpu_metadata import CPUMetadata, TYPE_CPU_METADATA

TYPE_ARP     = 0x0806

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class ArpHandler():

    def __init__(self, sw, send_func):
        self.sw = sw
        self.send = send_func

        self.mac_for_ip     = {}
        self.port_for_mac   = {}

    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': [ip]},
                action_name='MyIngress.find_next_hop_mac',
                action_params={'dstAddr': mac})
        self.mac_for_ip[ip] = mac

    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def handleArpReply(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)

        if (pkt[ARP].pdst not in self.mac_for_ip):
            self.send(pkt)
        else:
            # cached mac addr for this IP address
            hwsrc = self.mac_for_ip[pkt[ARP].pdst] 

            reply = Ether(dst=pkt[Ether].src, 
                          src=pkt[Ether].dst, 
                          type=TYPE_CPU_METADATA
                          )

            # spoof a cpu metadata from the actual response
            reply /= CPUMetadata(srcPort=pkt[CPUMetadata].srcPort,
                                 origEtherDst=pkt[CPUMetadata].origEtherSrc,
                                 origEtherSrc=hwsrc,
                                 origEtherType=TYPE_ARP,
                                 fromCpu=1)
            reply /= ARP(hwsrc=hwsrc,
                         hwdst=pkt[ARP].hwsrc,
                         psrc=pkt[ARP].pdst,
                         pdst=pkt[ARP].psrc)

            self.send(reply)

    def handle(self, pkt):

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

