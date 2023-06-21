#!/usr/bin/env python3
import os
import sys
from enum import Enum

from scapy.all import (
    get_if_hwaddr,
    Ether,
    TCP,
    IP,
    Raw,
    Padding,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    Packet, StrFixedLenField, ByteField, IntField, bind_layers, sendp, BitField, ByteEnumField
)
from scapy.layers.inet import _IPOption_HDR
seq_number = 0
p_buf = [] 
switchId = 0
switch_A = 0
switch_B = 0
p_buf_dic = {}
expecting_ack = 0

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

class UpdateOpcodeEnum(Enum):
    UPDATE = 0
    ACK =1

class Update(Packet):
    name = "update"
    fields_desc = [
        BitField("switch_id", 0, 8),
        IntField("seq", 0),
        ByteEnumField("op", UpdateOpcodeEnum.UPDATE.value, {opt.name: opt.value for opt in UpdateOpcodeEnum}),
        IntField("reg_1_index", 0),
        IntField("reg_2_index", 0),
        IntField("reg_3_index", 0),
    ]
bind_layers(Ether, Update, type=0x1234)

class Cpu(Packet):
    name = "Cpu"
    fields_desc = [ BitField("op", 0, 8),
                    BitField("operand0", 0, 8),
                    IntField("operand1", 0)]

bind_layers(Ether, Cpu, type=0x4321)

class TCP_OPT(Packet):
    name = "CTCP_OPT"
    fields_desc = [IntField("seq", 0)]

#bind_layers(Ether,  TCP_OPT )


def set_ack(pkt, iface):
    global p_buf_dic,expecting_ack, switch_A, switch_B

    seq_number = pkt[Update].seq
    if seq_number not in p_buf_dic:
        print("TODO: seq not found: ", seq_number)
        return
        
    p_buf_dic[seq_number][1][pkt[Update].switch_id] = 1
    if p_buf_dic[seq_number][1][switch_A] == 1 and p_buf_dic[seq_number][1][switch_B] == 1:
        tmp = p_buf_dic[seq_number][0]
        sendp(tmp, iface=iface, verbose=False)
        del p_buf_dic[seq_number]

def handle_pkt(pkt, iface):
    global seq_number, p_buf, expecting_ack, p_buf_dic
    if TCP in pkt:
        seq_number += 1
        
        p_buf_dic[seq_number] = [pkt,[0,0,0,0]]
        expecting_ack = seq_number
        

        """
        p_buf.append((pkt, seq_number))
        last_packet = p_buf[-1]  # Get the last tuple in p_buf
        last_seq_number = last_packet[1]  # Retrieve the sequence number from the tuple
        """

        #print("Sequence number of the last packet: ", seq_number)
        #p_buf_dic[seq_number][0].show()
        #sys.stdout.flush()
        
    elif pkt[Ether].type == 0x1234 and pkt[Update].op == UpdateOpcodeEnum.ACK.value:  
        #print("received ack: ") 
        #pkt.show2()
        set_ack(pkt, iface)
        #sys.stdout.flush()





def main():
    if len(sys.argv) < 2:
        print('pass 1 argument: <switch_id>')
        exit(1)
    global switchId,switch_A,switch_B
    switchId = int(sys.argv[1])
    if switchId == 1:
        switch_A = 2
        switch_B = 3
    elif switchId == 2:   
        switch_A = 1
        switch_B = 3
    else:    
        switch_A = 1
        switch_B = 2

    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]

    print("setting switch id to ",switchId)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x4321) / Cpu(op=1, operand0=switchId)    
    sendp(pkt, iface=iface, verbose=False)

    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, iface))

if __name__ == '__main__':
    main()
