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
    srp1,
    ShortField,
    sendp,
    BitField
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


class Cpu(Packet):
    name = "Cpu"
    fields_desc = [ BitField("op", 0, 8),
                    BitField("operand0", 0, 8)]

bind_layers(Ether, Cpu, type=0x4321)



def main():
    iface = get_if()
    
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x4321) / Cpu(op=1, operand0=1)
    #pkt = pkt/' '
    #pkt.show()
    #sendp(pkt, iface=iface, verbose=False)
    sendp(pkt, iface=iface, verbose=True)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x4321) / Cpu(op=1, operand0=2)
    sendp(pkt, iface="h4-eth1", verbose=True)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x4321) / Cpu(op=1, operand0=3)
    sendp(pkt, iface="h4-eth2", verbose=True)
if __name__ == '__main__':
    main()