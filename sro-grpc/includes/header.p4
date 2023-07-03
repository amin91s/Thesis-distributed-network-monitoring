#include "defines.p4"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PROBE = 0x9999;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_UPDATE  = 0x1234;
const bit<16> TYPE_CPU  = 0x4321;
const bit<32> TRIGGER_MSG = 500;


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

enum bit<8> controllerOpcode_t{
    NO_OP           = 0,
    SET_SWITCH_ID   = 1,
    RESET_SEQ       =2
}


@controller_header("packet_in")
header packet_in_header_t {
    bit<32> seq;
   
}

@controller_header("packet_out")
header packet_out_header_t {
    controllerOpcode_t op;
    bit<8> operand0;
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header probe_t {
    bit<32> index;
    bit<32> reg_1_val;
    bit<32> reg_2_val; 
    bit<32> reg_3_val;
} 

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


struct update_meta_t {
    bit<32> recirculation_round;
    bit<8> switch_id;
    bit<32> seq;
    bit<32> reg_1_index;
    bit<32> reg_2_index; 
    bit<32> reg_3_index;
    bit<CMS_CELL_WIDTH> reg_1_val;
    bit<CMS_CELL_WIDTH> reg_2_val;
    bit<CMS_CELL_WIDTH> reg_3_val;
}

struct metadata {
    @field_list(1)
    update_meta_t update_meta;
    @field_list(1)
    bit<32> recirculate;

}

enum bit<8> updateOpcode_t{
    UPDATE           = 0,
    ACK              = 1
}

header update_t {
    bit<8> switch_id;
    bit<32> seq;
    updateOpcode_t  op;
    bit<32> reg_1_index;
    bit<32> reg_2_index; 
    bit<32> reg_3_index;
}


header cpu_t{
    controllerOpcode_t op;
    bit<8> operand0;
    bit<32> operand1;
}


struct headers {
    packet_in_header_t  packet_in;
    packet_out_header_t packet_out;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    probe_t      probe;
    update_t     update;
    cpu_t        cpu;
}


