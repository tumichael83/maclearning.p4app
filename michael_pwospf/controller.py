from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from michael_pwospf.async_sniff import sniff
from michael_pwospf.cpu_metadata import CPUMetadata, TYPE_CPU_METADATA

from michael_pwospf.arp_handler import ArpHandler
from michael_pwospf.pwospf_handler import PWOSPFHandler, PROTO_PWOSPF, PWOSPF_Iface, HELLOINT_DFLT, ALLOSPFADDR

import time

PROTO_ICMP = 1

class MacLearningController(Thread):
    def __init__(self,sw, ip, mac, mask, nPorts):
        super(MacLearningController, self).__init__()

        self.start_wait = 0.3 # time to wait for the controller to be listenning
        self.stop_event = Event()

        self.sw = sw
        self.iface = sw.intfs[1].name

        self.ip = ip
        self.mac = mac

        # local ip
        sw.insertTableEntry(
            table_name="MyIngress.local_ip_table",
            match_fields={"hdr.ipv4.dstAddr": [self.ip]},
            action_name="MyIngress.send_to_cpu",
            action_params={},
        )

        self.arp_handler = ArpHandler(sw=sw,ip=ip,mac=mac,mask='255.255.255.0',send_func=self.send)

        # must be manually configured, don't pass in here?
        ifaces = {port:PWOSPF_Iface(ip=self.ip,mask='255.255.255.0',helloint=HELLOINT_DFLT) for port in range(2, nPorts+1)}

        self.pwospf_handler = PWOSPFHandler(
            stop_event=self.stop_event,
            sw=sw,
            ifaces=ifaces,
            send_func=self.send,
            ip=ip,
            mac=mac,
            routerID=self.ip,       # use the routers IP as its router ID
            areaID='0.0.0.0',       # use default for now
            mask='255.255.255.0',   # same
            arp_handler=self.arp_handler,
        )
        self.pwospf_bcast_thread = Thread(target=self.pwospf_handler.broadcast)


    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            self.arp_handler.handle(pkt)

        elif IP in pkt:
            self.handle_ip(pkt)


    def handle_ip(self, pkt):
        if pkt[IP].ttl == 0:
            if pkt[IP].proto == PROTO_PWOSPF and (pkt[IP].dst == ALLOSPFADDR or pkt[IP].dst == self.ip):
                self.pwospf_handler.handle(pkt)

            else:                
                # print(self.sw.name+': invalid ttl received')
                reply = Ether(src=self.mac, dst=pkt[Ether].src, type=TYPE_CPU_METADATA)
                reply /= CPUMetadata()
                reply /= IP(src=self.ip, dst=pkt[IP].src, proto=PROTO_ICMP)
                reply /= ICMP(type=11,code=0)
                reply /= pkt[IP]

                self.send(reply)


        elif pkt[IP].dst == self.ip:
            if pkt[IP].proto == PROTO_ICMP:
                if pkt[ICMP].type == 8:
                    reply = Ether(src=self.mac, dst=pkt[Ether].src, type=TYPE_CPU_METADATA)
                    reply /= CPUMetadata()
                    reply /= IP(src=self.ip, dst=pkt[IP].src, proto=PROTO_ICMP)
                    reply /= ICMP(type=0,id=pkt[ICMP].id,seq=1)

                    self.send(reply)

            elif pkt[IP].proto == PROTO_PWOSPF:
                self.pwospf_handler.handle(pkt)


        elif pkt[IP].proto == PROTO_PWOSPF:
            self.pwospf_handler.handle(pkt)

        elif self.arp_handler.on_my_subnet(pkt[IP].dst):
            if pkt[IP].dst not in self.arp_handler.mac_for_ip:
                if pkt[IP].dst not in self.arp_handler.arp_queue.keys():
                    # print(self.sw.name+': sending arp')
                    self.arp_handler.arp_req_for(pkt[IP].dst)

                self.arp_handler.enqueue_ip(pkt)


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
        self.pwospf_bcast_thread.start()

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)


