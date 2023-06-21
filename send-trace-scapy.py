from scapy.all import *
import time

def send_packet(packet):
    sendp(packet, iface="eth0", verbose=False)

def process_pcap_file(infile):
    packets = rdpcap(infile)
    for packet in packets:
        send_packet(packet)

def main():
    try:
        if len(sys.argv) < 2:
            print('pass 1 argument: <pcap file name>')
            exit(1)
        infile = sys.argv[1]
        my_reader = PcapReader(infile)
        print("sending ...")
        start_time = time.time()
        for packet in my_reader:
            send_packet(packet)
        end_time = time.time()
        total_time = end_time - start_time
        print("Total time taken: {:.2f} seconds".format(total_time))
    except IOError:
        print ("Failed reading file %s contents" % infile)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
