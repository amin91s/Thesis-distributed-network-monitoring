#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    Ether,
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    Packet, StrFixedLenField, ByteField, IntField, bind_layers
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
class P4calc(Packet):
    name = "P4calc"
    fields_desc = [ StrFixedLenField("srcAdd", "", length=6),
                    StrFixedLenField("dstAdd", "", length=6),
                    ByteField("protocol", 6),
                    IntField("srcPort", 0),
                    IntField("dstPort", 0),
                    IntField("result", 0)]


class Update(Packet):
    name = "P4calc"
    fields_desc = [ IntField("index", 0xDEADBEAF),
                    IntField("r1", 0xDEADBEAF),
                    IntField("r2", 0xDEADBEAF),
                    IntField("r3", 0xDEADBEAF)]

bind_layers(Ether, Update, type=0x1234)

class Probe(Packet):
    name = "Probe"
    fields_desc = [ IntField("index", 0xDEADBEAF),
                    IntField("r1", 0xDEADBEAF),
                    IntField("r2", 0xDEADBEAF),
                    IntField("r3", 0xDEADBEAF)]

bind_layers(Ether, Probe, type=0x9999)

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")
        pkt.show2()
    #    hexdump(pkt)
        sys.stdout.flush()
    elif pkt[Ether].type == 0x1234:  
        print("receive update: ") 
        pkt.show()
        sys.stdout.flush()
    elif pkt[Ether].type == 0x9999:
        print("receive probe: ") 
        pkt.show()
        sys.stdout.flush()

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
