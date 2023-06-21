import socket
import sys
from scapy.all import *
import time

def main():
    if len(sys.argv) < 2:
        print('Pass 1 argument: <pcap file name>')
        exit(1)
    pcap_file = sys.argv[1]
    
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    # Set the interface to "eth0"
    iface = "eth0"

    
    sock.bind((iface, 0))

    my_reader = PcapReader(pcap_file)

    print("sending ...")
    start_time = time.time()
   
    for packet in my_reader:
        sock.send(bytes(packet))
    end_time = time.time()
    total_time = end_time - start_time
    print("Total time taken: {:.2f} seconds".format(total_time))
if __name__ == "__main__":
    main()
