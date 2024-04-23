from scapy.all import Packet, Ether, IP, ARP
from cpu_metadata import CPUMetadata, TYPE_CPU_METADATA

import ipaddress

TYPE_ARP     = 0x0806

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

class ArpHandler():

    def __init__(self, sw, ip, mac, mask, send_func):
        self.sw = sw
        self.send = send_func

        self.ip = ip
        self.mac = mac
        self.mask = mask
        self.subnet = ipaddress.IPv4Network('%s/%s' % (ip, mask),strict=False)

        self.mac_for_ip     = {}
        self.port_for_mac   = {}

        self.arp_queue      = {}

    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return
        # print(self.sw.name+': adding '+ip)
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': [ip]},
                action_name='MyIngress.find_next_hop_mac',
                action_params={'dstAddr': mac})
        self.mac_for_ip[ip] = mac

    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        # print(self.sw.name+': mac '+mac)
        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def handleArpReply(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

        to_remove = []
        for ip, pkts in self.arp_queue.items():
            if ip not in self.mac_for_ip:
                continue
            for pkt in pkts:
                self.send(pkt)

            to_remove.append(ip)

        for ip in to_remove:
            del self.mac_for_ip[ip]




    def handleArpRequest(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)

        if pkt[ARP].pdst not in self.mac_for_ip and self.on_my_subnet(pkt[ARP].pdst) and pkt[ARP].pdst != self.ip:
            self.send(pkt)
        else:
            # cached mac addr for this IP address
            if pkt[ARP].pdst in self.mac_for_ip:
                hwsrc = self.mac_for_ip[pkt[ARP].pdst] 
                psrc = pkt[ARP].pdst

            else:
                # everything else (including off subnet) respond with self
                hwsrc = self.mac
                psrc = pkt[ARP].pdst

            reply = Ether(dst=pkt[Ether].src, 
                          src=pkt[Ether].dst, 
                          type=TYPE_CPU_METADATA
                          )

            # spoof a cpu metadata from the actual response
            reply /= CPUMetadata(origEtherType=TYPE_ARP,fromCpu=1)
            reply /= ARP(hwsrc=hwsrc,
                         hwdst=pkt[ARP].hwsrc,
                         psrc=psrc,
                         pdst=pkt[ARP].psrc,
                         op=ARP_OP_REPLY)

            self.send(reply)

    def on_my_subnet(self, ip):
        return ipaddress.ip_address(ip) in self.subnet

    def enqueue_ip(self, pkt):
        if pkt[IP].dst not in self.arp_queue:
            self.arp_queue[pkt[IP].dst] = [pkt]

        else:
            self.arp_queue[pkt[IP].dst] += [pkt]

    def arp_req_for(self, ip):
        req = Ether(dst=BCAST_MAC, src=self.mac)
        req /= CPUMetadata()
        req /= ARP(hwsrc=self.mac,hwdst=BCAST_MAC,psrc=self.ip,pdst=ip,op=ARP_OP_REQ)

        self.send(req)

    def handle(self, pkt):

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

