from scapy.all import *
'''
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Version #   |       1       |         Packet length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Router ID                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Area ID                             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           Checksum            |             Autype            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Authentication                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Authentication                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Network Mask                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         HelloInt              |           padding             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
_OSPF_types = { 1: "Hello",
                2: "DBDesc",
                3: "LSReq",
                4: "LSUpd",
                5: "LSAck" }

class PWOSPF_Hdr(Packet):
    name = "OSPF Header"
    fields_desc = [
                    ByteField("version", 2),
                    ByteEnumField("type", 1, _OSPF_types),
                    LenField("len", None),
                    IPField("routerID", "0.0.0.0"),
                    IPField("areaID", "0.0.0.0"),
                    ShortField("chksum", None),
                    ShortField("autype", 0),
                    LongField("auth", 0),
                ]

    def post_build(self, p, pay):
        if self.len is None:
            new_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", new_len) + p[4:]
        if self.chksum is None:
            # Checksum is calculated without authentication data
            # Algorithm is the same as in IP()
            ck = checksum(p[:16] + pay)
            p = p[:12] + struct.pack("!H", ck) + p[14:]
        return p + pay

class PWOSPF_Hello(Packet):
    name = "OSPF Hello"
    fields_desc = [
                    IPField("mask", "255.255.255.0"),
                    ShortField("helloint",10),
                    ShortField("pad", 0)
                ]

class PWOSPF_LSA(Packet):
    name = "OSPF Lsa"
    fields_desc = [
                    IPField("subnet", "0.0.0.0"),
                    IPField("mask", "255.255.255.0"),
                    IPField("routerID", "0.0.0.0")
                    ]

    def extract_padding(self, p):
        return "", p

class PWOSPF_Lsu(Packet):
    name = "OSPF Lsu"
    fields_desc = [
                    ShortField("seq", 0),
                    ShortField("ttl", 64),
                    FieldLenField("count", None, fmt="I", count_of="lsalist"),
                    PacketListField(
                        "lsalist", 
                        default=[], 
                        cls=PWOSPF_LSA,
                        count_from=lambda pkt: pkt.count)
                ]


bind_layers(IP, PWOSPF_Hdr, proto=89)
bind_layers(PWOSPF_Hdr, PWOSPF_Lsu, type=4)
bind_layers(PWOSPF_Hdr, PWOSPF_Hello, type=1)

    




