from scapy.all import Packet, Ether, IP
from michael_pwospf.cpu_metadata import CPUMetadata
from michael_pwospf.pwospf_packet import PWOSPF_Hdr, PWOSPF_Hello, PWOSPF_Lsu, PWOSPF_LSA
import time

import ipaddress

from collections import namedtuple, deque
NeighborEntry = namedtuple("NeighborEntry", "routerID helloint last_hello mac")



BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

PROTO_PWOSPF = 89

HELLOINT_DFLT = 10
LSUINT_DFLT = 15
TTL_DFLT    = 255

ALLOSPFADDR = '224.0.0.5'

class PWOSPFHandler():
    def __init__(self, stop_event, sw, ifaces, send_func, ip, mac, routerID, areaID, mask, arp_handler):

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
        self.last_hello     = time.time()

        self.lsuint         = LSUINT_DFLT
        self.last_lsu       = time.time()
        self.seq            = 0
        self.ttl            = TTL_DFLT

        self.all_routers    = {}    # router_ip: router_id
        self.router_states  = {}    # router_id: Router_Status

        self.routingDB      = RoutingDB(sw)

        self.arp_handler    = arp_handler

        # receive PWOSPF broadcasts
        sw.insertTableEntry(
            table_name="MyIngress.local_ip_table",
            match_fields={"hdr.ipv4.dstAddr": [ALLOSPFADDR]},
            action_name="MyIngress.send_to_cpu",
            action_params={},
        )

        # broadcast PWOSPF hellos!
        self.sw.insertTableEntry(
            table_name='MyIngress.arp_table',
            match_fields={'next_hop_ip': [ALLOSPFADDR]},
            action_name='MyIngress.find_next_hop_mac',
            action_params={'dstAddr': BCAST_MAC}
        )

    def broadcast(self):
        while not self.stop_event.wait(0.5): # loop in 1 second intervals
            # send my helloint
            if time.time() - self.last_hello >= self.helloint:
                self.send_hello()
                self.last_hello = time.time()

            # send my lsu
            if time.time() - self.last_lsu >= self.lsuint:
                self.send_lsu()
                self.last_lsu = time.time()

    def send_hello(self):
        hello = Ether(src=self.mac, dst=BCAST_MAC)
        hello /= CPUMetadata()
        hello /= IP(src=self.ip, dst=ALLOSPFADDR, ttl=2)    # need 2 because its decremented once b4 sending
        hello /= PWOSPF_Hdr(routerID=self.routerID, areaID=self.areaID)
        hello /= PWOSPF_Hello(mask=self.mask, helloint=self.helloint)

        self.send(hello)

    def send_lsu(self):
        # TODO: not really sure about subnet=self.routerID
        lsalist = [PWOSPF_LSA(subnet=self.routerID,mask=self.mask,routerID=self.routerID)]
        for port, iface in self.ifaces.items():
            for router_ip, neighbor_info in iface.neighbors.items():
                # TODO: subnet == router_ip???????
                lsalist.append(PWOSPF_LSA(subnet=router_ip,mask=iface.mask,routerID=neighbor_info.routerID))

        for router_ip, routerID in list(self.all_routers.items()):
            pkt = Ether(src=self.mac) # the ether dest should be calculated by the arp table (routing table?)
            pkt /= CPUMetadata()
            pkt /= IP(src=self.ip, dst=router_ip, ttl=255)
            pkt /= PWOSPF_Hdr(routerID=self.routerID,areaID=self.areaID)
            pkt /= PWOSPF_Lsu(seq=self.seq,ttl=self.ttl,count=len(lsalist),lsalist=lsalist)

            # if self.sw.name == 's2': pkt.show2()

            self.send(pkt)

        # if self.sw.name == 's1': pkt.show2()

        self.seq += 1


    def handle(self, pkt):
        if not self.is_valid_ospf(pkt): return

        # if self.sw.name == 's1': pkt.show2()

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
            self.arp_handler.mac_for_ip[neighbor_router_ip] = neighbor_mac
            self.arp_handler.port_for_mac[neighbor_mac] = srcPort

            # should be able to get rid of this if you work with arp_handler correctly!
            self.sw.insertTableEntry( # arp entry for neighbor, TODO: should this be a call to arp_handler?
                table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': neighbor_router_ip},
                action_name='MyIngress.find_next_hop_mac',
                action_params={"dstAddr": neighbor_mac}
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
            last_hello=time.time(), 
            mac=neighbor_mac
        )

        self.all_routers[neighbor_router_ip] = pkt[PWOSPF_Hdr].routerID

        # print(iface.neighbors)
        

    def handle_lsu(self, pkt):
        # if self.sw.name == 's1': pkt.show2()

        new_routerID = pkt[PWOSPF_Hdr].routerID
        # if self.sw.name == 's1': print('new routerID: ' + new_routerID)

        # stale lsu
        if new_routerID in self.all_routers.values() and new_routerID in self.router_states and self.router_states[new_routerID].seq >= pkt[PWOSPF_Lsu].seq:
            # if self.sw.name == 's1':
            #     print('stale')
                # pkt.show2()
            return
        
        self.all_routers[pkt[IP].src] = new_routerID
        self.router_states[new_routerID] = Router_State(pkt)

        # if self.sw.name == 's1': print(self.router_states)

        # compute topology
        routing_entries = self.compute_topology()
        # update database
        self.routingDB.update_routing_table(routing_entries)

        # flood to all neighbors!
        if pkt[PWOSPF_Lsu].ttl > 0:
            pkt[PWOSPF_Lsu].ttl -= 1

            for port, iface in self.ifaces.items():
                for router_ip, neighbor in iface.neighbors.items():
                    if router_ip != pkt[IP].src:
                        pkt[IP].chksum = None       # no idea why this is necessary but it is?
                        pkt[IP].dst = router_ip
                        self.send(pkt)


    # use self.router_status to generate graph
    def compute_topology(self):

        # TODO: add verification?
        
        # routers are nodes
        graph = {}

        graph[self.routerID] = set([self.routerID])
        for port,iface in self.ifaces.items():
            for device_ip, neighbor_entry in iface.neighbors.items():
                graph[self.routerID].add(neighbor_entry.routerID)

        for target_router, router_status in self.router_states.items():
            graph[target_router] = {lsa.routerID for lsa in router_status.lsalist}

        
        # if self.sw.name == 's1': print(graph)

        path_parent = {router: None for router in graph}

        q = deque([self.routerID])

        while q:
            cur_router = q.popleft()

            # reachable routers
            for nxt_router in graph[cur_router]:
                # first time visitng?
                if nxt_router in path_parent and path_parent[nxt_router] == None:
                    path_parent[nxt_router] = cur_router
                    q.append(nxt_router)


        # if self.sw.name == 's1': print(path_parent)

        neighbor_ip_2_mac_and_port = {}
        for port, iface in self.ifaces.items():
            for router_ip, neighbor_entry in iface.neighbors.items():
                neighbor_ip_2_mac_and_port[router_ip] = (neighbor_entry.mac, port)

        routing_entries = {}
        for final_router in path_parent:
            if path_parent[final_router] == None or final_router == self.routerID:
                continue # unreachable? or the router itself? or neighbor

            else:
                next_hop_router = final_router
                
                while path_parent[next_hop_router] != self.routerID:
                    next_hop_router = path_parent[next_hop_router]

                routing_entries[(final_router, self.mask)] = RoutingDB.TableEntry(
                    final_router = final_router,
                    mask = self.mask, # this has to change, but I'm not sure how .-.
                    next_hop_router = next_hop_router,
                )
                
        # if self.sw.name == 's1': print(routing_entries)

        return routing_entries


    def is_valid_ospf(self, pkt):
        # TODO: Checksum
        if pkt[PWOSPF_Hdr].version != 2:
            return False
        
        elif pkt[PWOSPF_Hdr].areaID != self.areaID:
            return False
        
        else:
            return True


class PWOSPF_Iface():
    '''
        neighbors are device ip -> routerID helloint last_hello mac
    '''
    def __init__(self,ip,mask,helloint):

        self.ip             = ip
        self.mask           = mask
        self.helloint       = helloint

        self.neighbors      = {} # device ip: routerID helloint last_hello mac



class Router_State():
    '''

    '''

    def __init__(self, pkt):
        self.time_received  = time.time()

        self.routerID       = pkt[PWOSPF_Hdr].routerID
        self.seq            = pkt[PWOSPF_Lsu].seq

        self.lsalist        = pkt[PWOSPF_Lsu].lsalist


'''
    When you add a new entry, you add a routing table, arp table, and l2_fwd table entry
    an entry requires 
        - a final router and a next_hop_router
            - should it be a final router? it should be the final network

        - next_hop_router to its mac -> these are added on hello
        - the mac to its port -> these are also added on hello
'''
class RoutingDB():
    class TableEntry():
        def __init__(self, final_router, mask, next_hop_router):
            self.final_router = final_router
            self.mask = mask # going to ignore this temporarily
            self.next_hop_router = next_hop_router

        def __str__(self):
            return 'final router: %s; mask: %s; next hop router: %s;' % (self.final_router, self.mask, self.next_hop_router)

        def __eq__(self, other):
            return self.final_router == other.final_router and self.mask == other.mask and self.next_hop_router == other.next_hop_router

    def __init__(self, sw):
        self.sw             = sw
        self.entries        = {}

    def update_routing_table(self, entries):
        old_entries = self.entries
        new_entries = entries

        old_keys = old_entries.keys()
        new_keys = new_entries.keys()

        entries_to_add_keys = new_keys - old_keys

        for k in entries_to_add_keys:

            ip, mask = k
            subnet = ipaddress.IPv4Network('%s/%s' % (ip, mask), strict=False)
            ip, mask = str(subnet.network_address), subnet.prefixlen

            next_hop_router = new_entries[k].next_hop_router

            self.sw.insertTableEntry(
                table_name='MyIngress.ipv4_routing',
                match_fields={'hdr.ipv4.dstAddr': [ip, mask]},
                action_name='MyIngress.find_next_hop_ip',
                action_params={"dstAddr": next_hop_router}
            )

            self.entries[k] = new_entries[k]


        # if self.sw.name == 's2':
        #     self.sw.printTableEntries()
        #     print(entries_to_add_keys)
        #     for k,v  in entries.items():
        #         print(k, v)

def subnet_mask_to_bits(subnet_mask):
    network = ipaddress.IPv4Network("0.0.0.0/%s" % subnet_mask)
    return network.prefixlen

