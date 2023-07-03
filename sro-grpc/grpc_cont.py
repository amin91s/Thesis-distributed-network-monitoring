from scapy import *
from scapy.all import *
import argparse
import os
import sys
from time import sleep
import ptf.testutils as tu
import grpc

# Import P4Runtime lib from parent utils dir

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


switchId = 0
switch_A = 0
switch_B = 0
seq_number = 0

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

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


class PacketOut_metadata(Packet):
    name = "PacketOut_metadata"
    fields_desc = [ BitField("op", 0, 8)]

class PacketIn_metadata(Packet):
    name = "PacketIn_metadata"
    fields_desc = [ IntField("seq", 0)]

def send_cpu_pkt(operation,operand,p4info_helper,s1):
    pkt =  Ether(src='ff:ff:ff:ff:ff:ff', dst='ff:ff:ff:ff:ff:ff', type=0x4321) / Cpu(op=operation, operand0=operand)
    packetout = p4info_helper.buildPacketOut(
                        payload = bytes(pkt),
                        metadata = {
                            1: bytes(PacketOut_metadata(op=0)),
                            2: bytes(PacketOut_metadata(op=0))
                        }
                    )
    
    s1.PacketOut(packetout)
    


def main(p4info_file_path, bmv2_file_path, sid, port, seq):
    
    global switchId,switch_A,switch_B,seq_number
    switchId = int(sid)
    p_buf_dic = {}
    if switchId < 1 or switchId > 3:
        print("please pick a unique switch ID from 1 to 3")
        exit(0)
    dev_id =0
    if switchId == 1:
        switch_A = 2
        switch_B = 3
    elif switchId == 2:
        dev_id = 1   
        switch_A = 1
        switch_B = 3
    else:
        dev_id = 2
        switch_A = 1
        switch_B = 2

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    try:
        # Create a switch connection object;
        s = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s{}'.format(sid),
            address='127.0.0.1:{}'.format(port),
            device_id=dev_id,
            proto_dump_file='logs/s{}-p4runtime-requests.txt'.format(sid))
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s.MasterArbitrationUpdate()
        

        if args.seq >= 0:
            send_cpu_pkt(2,seq,p4info_helper,s)
            print("setting seq to ", seq)

        
        #setting the switch id
        send_cpu_pkt(1,switchId,p4info_helper,s)
        
        
        while True:
            packetin = s.PacketIn()
            if packetin.WhichOneof('update')=='packet':
                pkt = Ether(packetin.packet.payload)
                if TCP in pkt:
                    for metadata in packetin.packet.metadata:
                        seq_number = metadata.value
                        break
                    seq = int.from_bytes(seq_number, byteorder='big')
                    #print("Seq:", seq)
                    p_buf_dic[seq] = [pkt,[0,0,0,0]]
                    
                    
                elif pkt[Ether].type == 0x1234 and pkt[Update].op == UpdateOpcodeEnum.ACK.value:
                    seq_number = pkt[Update].seq
                    if seq_number not in p_buf_dic:
                        print("ERROR: seq not found: ", seq_number)
                        return
        
                    p_buf_dic[seq_number][1][pkt[Update].switch_id] = 1
                    if p_buf_dic[seq_number][1][switch_A] == 1 and p_buf_dic[seq_number][1][switch_B] == 1:
                        tmp = p_buf_dic[seq_number][0]
                        packetout = p4info_helper.buildPacketOut(
                        payload = bytes(tmp),
                        metadata = {
                            1: bytes(PacketOut_metadata(op=0)),
                            2: bytes(PacketOut_metadata(op=0))
                        }
                        )
    
                        s.PacketOut(packetout)
                        del p_buf_dic[seq_number]
                        #print("delete was successful")
                    
                
    
    except KeyboardInterrupt:
        # using ctrl + c to exit
        print ("Shutting down.")
    except grpc.RpcError as e:
        print("ERROR")
        printGrpcError(e)

    # Then close all the connections
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--sid', help='switch id',
                        type=str, action="store", required=True)
    parser.add_argument('--seq', help='set sequence number register on the switch',
                        type=int, action="store", required=False, default= -1)
    parser.add_argument('--port', help='grpc port',
                        type=str, action="store", required=True)

    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/sro.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/sro.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.sid, args.port, args.seq)
