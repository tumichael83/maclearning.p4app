from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo, CustomTopo

nSwitches, nHosts = 2, 3
links = [[1,2]]

topo = CustomTopo(nSwitches,nHosts,links)
net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
net.start()

for i in range(1, nSwitches + 1):
    swName = 's%d' % i

    # Add a mcast group for all ports (except for the CPU port)
    bcast_mgid = 1
    sw = net.get(swName)
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, topo.link_count[swName] + 1))

    # Send MAC bcast packets to the bcast multicast group
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

    # Start the MAC learning controller
    h1 = net.get("s%dh1" % i)
    cpu = MacLearningController(
        sw=sw,
        ip = h1.IP(),
        mac = h1.MAC(),
    )
    cpu.start()

h2, h3 = net.get("s1h2"), net.get("s1h3")

print(h2.cmd("arping -c 1 10.0.1.3"))
print(h2.cmd("arping -c 1 10.0.1.3")) # second arping is faster bc response is cached on cpu

print(h2.cmd("ping -c 1 10.0.1.3"))
print(h2.cmd("ping -c 1 10.0.1.1"))

# These table entries were added by the CPU:
net.get('s1').printTableEntries()
