#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import (
    get_if_hwaddr,
    get_if_list,
    Ether,
    IP,
    IntField,
    Packet,
    StrFixedLenField,
    IPField,
    ByteField,
    IntField,
    bind_layers,
    sendp,
    ShortField
)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class Probe(Packet):
    name = "Probe"
    fields_desc = [ IntField("index", 0xDEADBEAF),
                    IntField("r1", 0xDEADBEAF),
                    IntField("r2", 0xDEADBEAF),
                    IntField("r3", 0xDEADBEAF)]

bind_layers(Ether, Probe, type=0x9999)



def main():
    iface = get_if()
    
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x9999) / Probe(index=0, r1=0, r2=0, r3=0)
    #pkt = pkt/' '
    #pkt.show()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()