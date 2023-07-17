/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "includes/header.p4"
#include "includes/parser.p4"
#include "includes/defines.p4"
#include "includes/checksum.p4"


#define COMPUTE_HASH(num, alg) hash(meta.update_meta.reg_##num##_index,HashAlgorithm.alg, (bit<32>)0,{hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},(bit<32>)CMS_ENTRIES)

#define INCREMENT_UPDATE_CNT(num) s##num##UpdPktCnt.read(meta.update_meta.temp, 0);\
 meta.update_meta.temp = meta.update_meta.temp + 1;\
 s##num##UpdPktCnt.write(0,meta.update_meta.temp)


#define UPDATE(num) s##num##l1.write(hdr.update.index, hdr.update.reg_1_val);\
 s##num##l2.write(hdr.update.index, hdr.update.reg_2_val);\
 s##num##l3.write(hdr.update.index, hdr.update.reg_3_val)

#define CMS_COUNT(num, alg) COMPUTE_HASH(num, alg); \
 layer##num.read(meta.update_meta.reg_##num##_val,meta.update_meta.reg_##num##_index); \
 meta.update_meta.reg_##num##_val = meta.update_meta.reg_##num##_val +1; \
 layer##num.write(meta.update_meta.reg_##num##_index, meta.update_meta.reg_##num##_val)


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {



    register<bit<32>>(1) window;
    register<bit<8>>(1) switch_id;
    //assuming acks and update packets are not droped.
    //otherwise, create separate ack and update counters per register
    register<bit<32>>(1) ack_count;
    register<bit<32>>(1) total_update_count;
    register<bit<32>>(1) s1UpdPktCnt;
    register<bit<32>>(1) s2UpdPktCnt;
    register<bit<32>>(1) s3UpdPktCnt;
    register<bit<32>>(1) status;
    
    
//creating  sketches
    
    CREATE_REGISTER(layer1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(layer2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(layer3, CMS_CELL_WIDTH, CMS_ENTRIES);
    
    CREATE_REGISTER(s1l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s1l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s1l3, CMS_CELL_WIDTH, CMS_ENTRIES);
    
    CREATE_REGISTER(s2l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s2l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    CREATE_REGISTER(s3l1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(s3l3, CMS_CELL_WIDTH, CMS_ENTRIES);

    CREATE_REGISTER(sync1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(sync2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(sync3, CMS_CELL_WIDTH, CMS_ENTRIES);

    CREATE_REGISTER(merge1, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(merge2, CMS_CELL_WIDTH, CMS_ENTRIES);
    CREATE_REGISTER(merge3, CMS_CELL_WIDTH, CMS_ENTRIES);

    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    
    action send_update(){
        switch_id.read(hdr.update.switch_id, 0);
        window.read(hdr.update.window,0);
        bit<32> r = meta.update_meta.recirculation_round;  
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        meta.recirculate = UPDATE_LOOP;
        standard_metadata.mcast_grp = 0;
        clone_preserving_field_list(CloneType.I2E, 500,1);
        layer1.read(meta.update_meta.reg_1_val, r);
        layer2.read(meta.update_meta.reg_2_val, r);
        layer3.read(meta.update_meta.reg_3_val, r);
        
        hdr.update.index = r;
        hdr.update.reg_1_val = meta.update_meta.reg_1_val;
        hdr.update.reg_2_val = meta.update_meta.reg_2_val;
        hdr.update.reg_3_val = meta.update_meta.reg_3_val;
        hdr.update.op = updateOpcode_t.UPDATE;
        standard_metadata.mcast_grp = 1;
        //meta.recirculate = 0;
        //copy update register to sync register
        sync1.write(r, meta.update_meta.reg_1_val);
        sync2.write(r, meta.update_meta.reg_2_val);
        sync3.write(r, meta.update_meta.reg_3_val);
        //reset the update register
        layer1.write(r,0);
        layer2.write(r,0);
        layer3.write(r,0);
    }
    action merge(){
        bit<32> r = meta.update_meta.recirculation_round;
        //log_msg("merging index {}",{r});  
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        resubmit_preserving_field_list(1);
        bit<32> tmp1; bit<32> tmp2; bit<32> tmp3;

        merge1.read(tmp1,r);
        merge2.read(tmp2,r);
        merge3.read(tmp3,r);

        s1l1.read(meta.update_meta.reg_1_val, r);
        s1l2.read(meta.update_meta.reg_2_val, r);
        s1l3.read(meta.update_meta.reg_3_val, r);
        tmp1 = tmp1 + meta.update_meta.reg_1_val;
        tmp2 = tmp2 + meta.update_meta.reg_2_val;
        tmp3 = tmp3 + meta.update_meta.reg_3_val;

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

        sync1.read(meta.update_meta.reg_1_val, r);
        sync2.read(meta.update_meta.reg_2_val, r);
        sync3.read(meta.update_meta.reg_3_val, r);
        
        tmp1 = tmp1 + meta.update_meta.reg_1_val;
        tmp2 = tmp2 + meta.update_meta.reg_2_val;
        tmp3 = tmp3 + meta.update_meta.reg_3_val;

        merge1.write(r,tmp1);
        merge2.write(r,tmp2);
        merge3.write(r,tmp3);
        meta.recirculate = MERGE;
    }

    action update_local_cms(){
        CMS_COUNT(1, L1_HASH_ALG);
        CMS_COUNT(2, L2_HASH_ALG);
        CMS_COUNT(3, L3_HASH_ALG);
    }
    
    action send_ack(){
        //log_msg("sending ack to switch {}",{hdr.update.switch_id});
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        standard_metadata.egress_port = standard_metadata.ingress_port;
        hdr.update.op = updateOpcode_t.ACK;
        switch_id.read(hdr.update.switch_id, 0);
        meta.recirculate = SEND_ACK;
    }
    action send_trigger_msg(bit<32> num){
        meta.recirculate = num;
        meta.update_meta.recirculation_round = 0;
        clone_preserving_field_list(CloneType.I2E, 500,1);
    }
    
    action advance_window(){
        ack_count.write(0,0);
        total_update_count.write(0,0);
        s1UpdPktCnt.write(0,0);
        s2UpdPktCnt.write(0,0);
        s3UpdPktCnt.write(0,0);
        window.read(meta.update_meta.temp,0);
        window.write(0,meta.update_meta.temp +1);
        status.write(0,DONE);
        send_trigger_msg(MERGE);
    }

    action handle_probe(){
        bit<32> r = meta.update_meta.recirculation_round; 
        meta.update_meta.recirculation_round = meta.update_meta.recirculation_round +1;
        meta.recirculate = PROBE_LOOP;
        clone_preserving_field_list(CloneType.I2E, 500,1);
        
        merge1.read(meta.update_meta.reg_1_val, r);
        merge2.read(meta.update_meta.reg_2_val, r);
        merge3.read(meta.update_meta.reg_3_val, r);
        hdr.probe.index = r;
        hdr.probe.reg_1_val = meta.update_meta.reg_1_val;
        hdr.probe.reg_2_val = meta.update_meta.reg_2_val;
        hdr.probe.reg_3_val = meta.update_meta.reg_3_val;
   
        standard_metadata.egress_spec = (egressSpec_t) HOST_PORT;
        
    }

    apply {
        if(hdr.cpu.isValid()){
            switch (hdr.cpu.op){
                controllerOpcode_t.SET_SWITCH_ID:{
                    switch_id.write(0, hdr.cpu.operand0);
                    status.write(0,DONE);
                }
                controllerOpcode_t.NO_OP:{
                    drop();
                    return;
                }
            }           
        }
        else if(hdr.ethernet.etherType == TYPE_TIMER){
            status.read(meta.update_meta.temp,0);
            if (meta.update_meta.temp == DONE){
                status.write(0,PENDING);
                send_trigger_msg(UPDATE_LOOP);
                drop();
            } else {
                //TODO: MAKE THIS INTO A FUNCTION
                bit<32> tmp_ack;
                bit<32> tmp_upd;
                total_update_count.read(tmp_upd,0);
                ack_count.read(tmp_ack,0);
                if(tmp_ack == NUM_SWITCHES_IN_TOPO && tmp_upd == NUM_SWITCHES_IN_TOPO){
                    advance_window();
                }
                drop();
            }
        }
        else if(meta.recirculate == UPDATE_LOOP){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES){
                send_update();
            }else {
                drop();
            }
        }
        else if(meta.recirculate == PROBE_LOOP){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES){
                handle_probe();
            }
                
            else drop();

        }
        else if(meta.recirculate == MERGE){
            if(meta.update_meta.recirculation_round < CMS_ENTRIES){
                merge();
            }
                
            else {
                drop();
            }
        }
        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if(standard_metadata.ingress_port == (egressSpec_t) HOST_PORT){
                update_local_cms();             
            } 
            //ipv4_lpm.apply();  
            drop();

        } else if(hdr.update.isValid()){
            window.read(meta.update_meta.temp,0);
            if(meta.update_meta.temp != hdr.update.window){
                //log_msg("received old update with window {}. curr wind is {}",{hdr.update.window,meta.update_meta.temp});
                        drop();
                        return;
                    }
            switch(hdr.update.op){
                updateOpcode_t.ACK:{
                    //log_msg("received ack from switch {}",{hdr.update.switch_id});
                    ack_count.read(meta.update_meta.temp,0);
                    ack_count.write(0,meta.update_meta.temp+1);
                    
                }
                updateOpcode_t.UPDATE:{
                        switch(hdr.update.switch_id){
                            1:{UPDATE(1);INCREMENT_UPDATE_CNT(1);}
                            2:{UPDATE(2);INCREMENT_UPDATE_CNT(2);}
                            3:{UPDATE(3);INCREMENT_UPDATE_CNT(3);}
                        }
                    meta.recirculate = 0;
                    if(meta.update_meta.temp == CMS_ENTRIES){
                        total_update_count.read(meta.update_meta.temp,0);
                        total_update_count.write(0,meta.update_meta.temp+1);
                        //log_msg("received all updates from switch {}",{hdr.update.switch_id});
                        send_ack();
                    }
                    
                }
                
            }
            /* bit<32> tmp_ack;
            bit<32> tmp_upd;
            total_update_count.read(tmp_upd,0);
            ack_count.read(tmp_ack,0);
            if(tmp_ack == NUM_SWITCHES_IN_TOPO && tmp_upd == NUM_SWITCHES_IN_TOPO){
                advance_window();
                bit<32> win;
                window.read(win,0);
                log_msg("advancing window to {}",{win});
            } */
            if(meta.recirculate != SEND_ACK)
                drop();
        }  else if(hdr.probe.isValid()){
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
    
    apply { 
        //todo: this is for debugging. merge these later
        if(hdr.probe.isValid() && standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            meta.recirculate = PROBE_LOOP;
            recirculate_preserving_field_list(1);
        } 
        if(hdr.probe.isValid()) return; 
        if(meta.recirculate == SEND_ACK) return;
        if(meta.recirculate != 0 ){
            if(standard_metadata.mcast_grp == 0){
                
                    if(!hdr.update.isValid()){
                    //truncate(14); does not work!!!
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