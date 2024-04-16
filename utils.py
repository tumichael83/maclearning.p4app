from scapy.all import Packet, IP
import ipaddress


def valid_checksum(pkt):
    out = pkt[IP].chksum

    del pkt[IP].chksum
    pkt[IP] = pkt.__class__(bytes(pkt[IP]))

    return out == pkt[IP].chksum

def subnet_mask_to_bits(subnet_mask):
    network = ipaddress.IPv4Network("0.0.0.0/%s" % subnet_mask)
    return network.prefixlen