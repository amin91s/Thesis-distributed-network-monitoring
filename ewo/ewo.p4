/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "includes/header.p4"
#include "includes/parser.p4"
#include "includes/defines.p4"


#define COMPUTE_HASH(num, alg) hash(meta.reg_##num##_index,HashAlgorithm.alg, (bit<32>)0,{hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},(bit<32>)CMS_ENTRIES)

#define CMS_COUNT(num, alg) COMPUTE_HASH(num, alg); \
 layer##num.read(meta.reg_##num##_val,meta.reg_##num##_index); \
 meta.reg_##num##_val = meta.reg_##num##_val +1; \
 layer##num.write(meta.reg_##num##_index, meta.reg_##num##_val)

#define MAXIMUM(a, b, result) result = ((a) > (b) ? (a) : (b))

#define UPDATE(num) s##num##l1.read(meta.update_meta.reg_1_val, hdr.update.index);\
 s##num##l2.read(meta.update_meta.reg_2_val, hdr.update.index);\
 s##num##l3.read(meta.update_meta.reg_3_val, hdr.update.index);\
 MAXIMUM(meta.update_meta.reg_1_val, hdr.update.reg_1_val, meta.update_meta.reg_1_val);\
 MAXIMUM(meta.update_meta.reg_2_val, hdr.update.reg_2_val, meta.update_meta.reg_2_val);\
 MAXIMUM(meta.update_meta.reg_3_val, hdr.update.reg_3_val, meta.update_meta.reg_3_val);\
 s##num##l1.write(hdr.update.index, meta.update_meta.reg_1_val);\
 s##num##l2.write(hdr.update.index, meta.update_meta.reg_2_val);\
 s##num##l3.write(hdr.update.index, meta.update_meta.reg_3_val)

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //creating local sketches
    CREATE_REGISTER(layer1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(layer2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(layer3, CMS_CELL_WIDTH, CMS_ENTRIES);
    //for updates from other registers
    CREATE_REGISTER(s2l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    CREATE_REGISTER(s3l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    

    register<bit<32>>(1) packet_count;



    action drop() {
        mark_to_drop(standard_metadata);
    }

 

    action send_trigger_msg(bit<32> num){
        meta.recirculate = num;
        meta.update_meta.recirculation_round = 0;
        clone_preserving_field_list(CloneType.I2E, 500,1);
    }

    action update_local_cms(){
        CMS_COUNT(1, L1_HASH_ALG);
        CMS_COUNT(2, L2_HASH_ALG);
        CMS_COUNT(3, L3_HASH_ALG);
    }
    
    action handle_clone(){
        bit<32> r = meta.update_meta.recirculation_round;  
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        clone_preserving_field_list(CloneType.I2E, 500,1);
        layer1.read(meta.update_meta.reg_1_val, r);
        layer2.read(meta.update_meta.reg_2_val, r);
        layer3.read(meta.update_meta.reg_3_val, r);
        hdr.update.index = r;
        hdr.update.reg_1_val = meta.update_meta.reg_1_val;
        hdr.update.reg_2_val = meta.update_meta.reg_2_val;
        hdr.update.reg_3_val = meta.update_meta.reg_3_val;
        standard_metadata.mcast_grp = 1;
        
    }

    action handle_probe(){
        bit<32> r = meta.update_meta.recirculation_round;  
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        meta.recirculate = 2;
        clone_preserving_field_list(CloneType.I2E, 500,1);
        //add local updates
        layer1.read(meta.update_meta.reg_1_val, r);
        layer2.read(meta.update_meta.reg_2_val, r);
        layer3.read(meta.update_meta.reg_3_val, r);
        hdr.probe.index = r;
        hdr.probe.reg_1_val = meta.update_meta.reg_1_val;
        hdr.probe.reg_2_val = meta.update_meta.reg_2_val;
        hdr.probe.reg_3_val = meta.update_meta.reg_3_val;
        //add updates from other switches
        s2l1.read(meta.update_meta.reg_1_val, r);
        s2l2.read(meta.update_meta.reg_2_val, r);
        s2l3.read(meta.update_meta.reg_3_val, r);
        hdr.probe.reg_1_val = hdr.probe.reg_1_val + meta.update_meta.reg_1_val;
        hdr.probe.reg_2_val = hdr.probe.reg_2_val + meta.update_meta.reg_2_val;
        hdr.probe.reg_3_val = hdr.probe.reg_3_val + meta.update_meta.reg_3_val;

        s3l1.read(meta.update_meta.reg_1_val, r);
        s3l2.read(meta.update_meta.reg_2_val, r);
        s3l3.read(meta.update_meta.reg_3_val, r);
        hdr.probe.reg_1_val = hdr.probe.reg_1_val + meta.update_meta.reg_1_val;
        hdr.probe.reg_2_val = hdr.probe.reg_2_val + meta.update_meta.reg_2_val;
        hdr.probe.reg_3_val = hdr.probe.reg_3_val + meta.update_meta.reg_3_val;

        standard_metadata.egress_spec = (egressSpec_t) HOST_PORT;
    }


    apply {
        if(meta.recirculate == 1 ){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES)
                handle_clone();
            else drop();

        } else if(meta.recirculate == 2){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES)
                handle_probe();
            else drop();

        }else if(hdr.update.isValid()){
            // this is for testing. change to match action if needed
            if( (bit<32>)standard_metadata.ingress_port == 2){ 
                UPDATE(2);
            } else if((bit<32>)standard_metadata.ingress_port == 3){
                UPDATE(3);
            }
            else {
                log_msg("got update from wrong port: {}",{standard_metadata.ingress_port});
                drop();
            }
            //for printing the update packets
            //standard_metadata.egress_spec = (egressSpec_t) 1;
        }
        else if (hdr.ipv4.isValid()) {
            
            if(hdr.tcp.isValid() ){
                //why this does not stop counting flows on the destination switch?
                if(standard_metadata.ingress_port == (egressSpec_t) HOST_PORT){
                    //log_msg("adding msg from port {} to local cms",{standard_metadata.ingress_port});
                    update_local_cms();
                    bit<32> temp;
                    packet_count.read(temp,0);
                    if (temp < BATCH_SIZE){
                        packet_count.write(0, temp+1);
                    } else {
                        packet_count.write(0, 0);
                        send_trigger_msg(1);
                    }

                }

            }
            
            //ipv4_lpm.apply();
            drop();
        }
        else if(hdr.probe.isValid()){
            send_trigger_msg(2);
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }                
    apply { 
        if(hdr.probe.isValid() && standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            meta.recirculate = 2;
            recirculate_preserving_field_list(1);
        }  
        else if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            if(standard_metadata.mcast_grp == 0 && meta.recirculate == 1){
                if(!hdr.update.isValid()){
                    //truncate(14); not working!!!
                    hdr.ethernet.etherType = TYPE_UPDATE;
                    hdr.ipv4.setInvalid();
                    hdr.tcp.setInvalid();
                    hdr.update.setValid();
                     
                }
                recirculate_preserving_field_list(1);
            }
        }
        
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
