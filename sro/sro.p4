/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "includes/header.p4"
#include "includes/parser.p4"
#include "includes/defines.p4"
#include "includes/checksum.p4"

#define COMPUTE_HASH(num, alg) hash(meta.update_meta.reg_##num##_index,HashAlgorithm.alg, (bit<32>)0,{hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},(bit<32>)CMS_ENTRIES)

#define INCREMENT_SEQ() seq.read(meta.update_meta.seq, 0);\
 meta.update_meta.seq = meta.update_meta.seq + 1;\
 seq.write(0,meta.update_meta.seq)


#define UPDATE(num) s##num##l1.read(meta.update_meta.reg_1_val, hdr.update.reg_1_index);\
 s##num##l2.read(meta.update_meta.reg_2_val, hdr.update.reg_2_index);\
 s##num##l3.read(meta.update_meta.reg_3_val, hdr.update.reg_3_index);\
 s##num##l1.write(hdr.update.reg_1_index, meta.update_meta.reg_1_val + 1);\
 s##num##l2.write(hdr.update.reg_2_index, meta.update_meta.reg_2_val + 1);\
 s##num##l3.write(hdr.update.reg_3_index, meta.update_meta.reg_3_val + 1)

#define CMS_COUNT(id, num, alg) COMPUTE_HASH(num, alg); \
 s##id##l##num.read(meta.update_meta.reg_##num##_val,meta.update_meta.reg_##num##_index); \
 meta.update_meta.reg_##num##_val = meta.update_meta.reg_##num##_val +1; \
 s##id##l##num.write(meta.update_meta.reg_##num##_index, meta.update_meta.reg_##num##_val)

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {



    register<bit<32>>(1) seq;
    register<bit<8>>(1) switch_id;

    //creating  sketches
    CREATE_REGISTER(s1l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s1l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s1l3, CMS_CELL_WIDTH, CMS_ENTRIES);
    
    CREATE_REGISTER(s2l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    CREATE_REGISTER(s3l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action send_update(){
        hdr.ethernet.etherType = TYPE_UPDATE;
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        hdr.update.setValid();
        meta.recirculate = 0;
        switch_id.read(hdr.update.switch_id, 0);
        hdr.update.seq = meta.update_meta.seq;
        hdr.update.op = updateOpcode_t.UPDATE;
        hdr.update.reg_1_index = meta.update_meta.reg_1_index;
        hdr.update.reg_2_index = meta.update_meta.reg_2_index;
        hdr.update.reg_3_index = meta.update_meta.reg_3_index;
        standard_metadata.mcast_grp = 1;

    }


    action handle_probe(){
        bit<32> r = meta.update_meta.recirculation_round; 
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        meta.recirculate = PROBE_LOOP;
        clone_preserving_field_list(CloneType.I2E, 500,1);
        
        bit<32> tmp1; bit<32> tmp2; bit<32> tmp3;
        s1l1.read(tmp1, r);
        s1l2.read(tmp2, r);
        s1l3.read(tmp3, r);

        s2l1.read(meta.update_meta.reg_1_val, r);
        s2l2.read(meta.update_meta.reg_2_val, r);
        s2l3.read(meta.update_meta.reg_3_val, r);
        tmp1 = tmp1 + meta.update_meta.reg_1_val;
        tmp2 = tmp2 + meta.update_meta.reg_2_val;
        tmp3 = tmp3 + meta.update_meta.reg_3_val;

        s3l1.read(meta.update_meta.reg_1_val, r);
        s3l2.read(meta.update_meta.reg_2_val, r);
        s3l3.read(meta.update_meta.reg_3_val, r);
        tmp1 = tmp1 + meta.update_meta.reg_1_val;
        tmp2 = tmp2 + meta.update_meta.reg_2_val;
        tmp3 = tmp3 + meta.update_meta.reg_3_val;

        hdr.probe.index = r;
        hdr.probe.reg_1_val = tmp1;
        hdr.probe.reg_2_val = tmp2;
        hdr.probe.reg_3_val = tmp3;
   
        standard_metadata.egress_spec = (egressSpec_t) HOST_PORT;
        
    }



    action update_trigger_msg(){
        meta.recirculate = 1;
        clone_preserving_field_list(CloneType.I2E, 500,1);
    }

    action send_trigger_msg(bit<32> num){
        meta.recirculate = num;
        meta.update_meta.recirculation_round = 0;
        clone_preserving_field_list(CloneType.I2E, 500,1);
    }

    action send_to_cpu(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }
    action send_ack(){
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.update.op = updateOpcode_t.ACK;
        switch_id.read(hdr.update.switch_id, 0);
    }

    apply {
        if(hdr.cpu.isValid()){
            switch (hdr.cpu.op){
                controllerOpcode_t.SET_SWITCH_ID:{
                    switch_id.write(0, hdr.cpu.operand0);
                    log_msg("setting switch id to {}",{hdr.cpu.operand0});
                }
                controllerOpcode_t.NO_OP:{
                    drop();
                    return;
                }
                controllerOpcode_t.RESET_SEQ:{
                    seq.write(0,(bit<32>) hdr.cpu.operand0);
                }
            }           
        }
        else if(meta.recirculate == 1){
            send_update();
        } else if(meta.recirculate == PROBE_LOOP){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES){
                handle_probe();
            }
                
            else drop();

        }

        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if(standard_metadata.ingress_port == HOST_PORT){
                INCREMENT_SEQ();
                COMPUTE_HASH(1, L1_HASH_ALG);
                COMPUTE_HASH(2, L2_HASH_ALG);
                COMPUTE_HASH(3, L3_HASH_ALG);
                update_trigger_msg();
                send_to_cpu();
            }  
            else if(standard_metadata.ingress_port == CONTROLLER_PORT){
                bit<8> id;
                switch_id.read(id,0);
                switch(id){
                    1:{CMS_COUNT(1,1,L1_HASH_ALG);CMS_COUNT(1,2,L2_HASH_ALG);CMS_COUNT(1,3,L3_HASH_ALG);}
                    2:{CMS_COUNT(2,1,L1_HASH_ALG);CMS_COUNT(2,2,L2_HASH_ALG);CMS_COUNT(2,3,L3_HASH_ALG);}
                    3:{CMS_COUNT(3,1,L1_HASH_ALG);CMS_COUNT(3,2,L2_HASH_ALG);CMS_COUNT(3,3,L3_HASH_ALG);}
                }
                //ipv4_lpm.apply();
                drop();
            }
            else
                //ipv4_lpm.apply();
                drop();
                
                
        } else if(hdr.update.isValid()){
            switch(hdr.update.op){
                updateOpcode_t.UPDATE:{
                    //log_msg("received update from port {}",{standard_metadata.ingress_port});
                    switch(hdr.update.switch_id){
                        1:{UPDATE(1);}
                        2:{UPDATE(2);}
                        3:{UPDATE(3);}
                    }
                    send_ack();
                    
                }
                updateOpcode_t.ACK:{
                    //log_msg("received ack from switch {} with seq num {} on port {}",{hdr.update.switch_id, hdr.update.seq, standard_metadata.ingress_port});
                    send_to_cpu();
                }
            }
        } else if(hdr.probe.isValid()){
            send_trigger_msg(PROBE_LOOP);
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
        //todo: this is for debugging. merge these later
        if(hdr.probe.isValid() && standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            meta.recirculate = PROBE_LOOP;
            recirculate_preserving_field_list(1);
        } 
        if(hdr.probe.isValid()) return; 
        if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            meta.recirculate =1;
            recirculate_preserving_field_list(1);
        }
        
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