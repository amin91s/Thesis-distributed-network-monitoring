## Topology:
![topology](./topo.png)
## high-level overview of the replication protocol
![sync-proto](./ewo-proto.png)

## Brief Explanation:
Each switch in the network has a CMS that consists of three registers for tracking local updates, as well as one sketch per switch. Additionally, there is a packet_count register on each switch that tracks the number of received packets. When a packet is received on port 1 from the host, it is added to the local sketch, and the packet counter is incremented. If the counter reaches the pre-defined batch size (in includes/defines.p4), the local sketch will be synchronized between switches. 

During synchronization, the protocol clones the TCP packet and creates a replication packet (update packet) that will multicast the local CMS index by index to other switches. Each update packet contains an index and the three corresponding values for each register in the sketch. Since the sketch is a CRDT G-Counter (Grow-only Counter), each switch takes the maximum of the current value in the register and the value in the received update packet so that older updates do not overwrite the sketch.

Furthermore, there is a script called "probe.py" that sends a "probe" packet from the host to the switch. The switch then adds up all sketches and sends them back to the host index by index. (The receive.py script should also be running.)


