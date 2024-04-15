from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch("s1")

        for i in range(1, n + 1):
            host = self.addHost(
                "h%d" % i, ip="10.0.0.%d" % i, mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)


class CustomTopo(Topo):
    def __init__(self, nSwitches, nHosts, links=[], **opts):
        Topo.__init__(self, **opts)

        switches = {i: self.addSwitch('s%d' % i) for i in range(1, nSwitches+1)}
        self.link_count = {sw:0 for sw in switches.values()}

        for i in range(1, nSwitches+1):
            switch = switches[i]

            for j in range(1, nHosts+1):
                host = self.addHost(
                    "s%dh%d" % (i, j),
                    ip="10.0.%d.%d" % (i,j),
                    mac='00:00:00:00:%02x:%02x' % (i, j)
                )
                self.addLink(host, switch, port2=j)
                self.link_count[switch] += 1

        for link in links:
            s0 = switches[link[0]]
            s1 = switches[link[1]]
            self.link_count[s0] += 1
            self.link_count[s1] += 1
            self.addLink(s1,s0)

