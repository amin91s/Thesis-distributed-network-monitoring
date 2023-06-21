#!/usr/bin/env python3
import random
import socket
import sys
import time

from scapy.all import (
    get_if_hwaddr,
    get_if_list,
    Ether,
    sendp
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





def main():
    iface = get_if()
    
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x1234)
    #pkt = pkt/' '
    #pkt.show()
    r = 0
    while True:
        sendp(pkt, iface=iface, verbose=False)
        sendp(pkt, iface="h4-eth1", verbose=False)
        sendp(pkt, iface="h4-eth2", verbose=False)
        print("window: ", r)
        r += 1
        time.sleep(3.1)

if __name__ == '__main__':
    main()