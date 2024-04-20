from scapy.fields import BitField, ByteField, ShortField
from scapy.layers.l2 import DestMACField, SourceMACField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ShortField("srcPort", None),
                    DestMACField("origEtherDst"),
                    SourceMACField("origEtherSrc"),
                    ShortField("origEtherType", None),
                    ByteField("fromCpu", 0),
                ]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
