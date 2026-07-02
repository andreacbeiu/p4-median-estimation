/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ***********************  H E A D E R S / S T R U C T S ******************
 *************************************************************************/


#define WINDOW 100 //
#define MEDIAN_THRESHOLD 500

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

struct my_ingress_headers_t {
	ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
}

/***********************  M Y   H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
}

struct my_ingress_metadata_t {
    bit<32> curr_time;
    bit<32> last_time;
    bit<32> iat;
    bit<1> flag;
    bit<1> comp;
    int<32> count;
    int<32> change;
    bit<1> alarm;
    int<32> c_val;
}

struct digest_flag_t {
    int<32> change;
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/* Ingress PARSER */
parser IngressParser(
    packet_in                                   pkt,
    /*User-defined structs:*/
    out my_ingress_headers_t                    hdr,
    out my_ingress_metadata_t                   meta,
    /*Intrinsic structs:*/
    out ingress_intrinsic_metadata_t            ig_intr_md)
{
    state start {
     	pkt.extract(ig_intr_md);
        //extract the timestamp value into meta.curr_time for further processing
        meta.curr_time[31:0] = ig_intr_md.ingress_mac_tstamp[39:8];

     	transition select (ig_intr_md.resubmit_flag) {
     		1: parse_resubmit;
     		0: parse_port_metadata;
     	}
    }
     
    state parse_resubmit {
	    //advance past the resubmit portion and portmetadata portion
        pkt.advance(64);
	    transition accept;
    }

    state parse_port_metadata {
	    //advance past the resubmit portion and portmetadata portion
        pkt.advance(PORT_METADATA_SIZE); 
	    transition accept;
    }
     

}

/*************************************************************************
 **************  CONTROL   ************************************************************************************************************************
 *************************************************************************/
control Ingress(
    /* User-defined structs: */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic structs: */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    //define R1: timestamp buffer, keeps track of last packets arrival time so that IAT = curr - last can occur in Control Block
    Register<bit<32>, bit<1>>(1) regone;
    RegisterAction<bit<32>, bit<1>, bit<32>>(regone) updateone = {
        void apply(inout bit<32> curr, out bit<32> prev) {
            prev = curr; //save the last packet's arrival time to output
            curr = meta.curr_time; //save the current incoming packet's time to register
        }
    };

    //define R2: window keeper
    Register<bit<32>, bit<1>>(1) regtwo;
    RegisterAction<bit<32>, bit<1>, bit<1>>(regtwo) updatetwo = {
        void apply(inout bit<32> curr, out bit<1> ret) {
            ret = 0;
            if(curr < WINDOW) {
                //we are still in the same window
                curr = curr + 1;
            } else {
                //we are in a new window
                curr = 0;
                ret = 1;
            }
        }
    };

    // Register A: just the counter c
    Register<int<32>, bit<1>>(1) regthree;
    RegisterAction<int<32>, bit<1>, void>(regthree) actionrthree = {
        void apply(inout int<32> value) {
            if(meta.comp == 1) {
                //current iat is strictly smaller than estimate
                value = value - 1;
            } else {
                //current iat is larger than or equal to estimate
                value = value + 1;
            }
        }
    };
    RegisterAction<int<32>, bit<1>, int<32>>(regthree) actionrthreetwo = {
        void apply(inout int<32> value, out int<32> ret) {
            ret = value;
            value = 0;
        }
    };  

    // Register B: just the median estimate m
    Register<int<32>, bit<1>>(1) regfour;
    RegisterAction<int<32>, bit<1>, bit<1>>(regfour) actionrfour = {
        void apply(inout int<32> value, out bit<1> ret) {
            if((int<32>) meta.iat >= value) { 
                //current iat is larger than or equal to estimate
                ret = 0;
            } else {
                //current iat is strictly smaller than estimate
                ret = 1;
            }
        }
    };
    RegisterAction<int<32>, bit<1>, bit<1>>(regfour) actionrfourtwo = {
        void apply(inout int<32> value, out bit<1> ret) {
            value = value + meta.change;
            if(value < MEDIAN_THRESHOLD) {
                //median estimate is smaller than expected iats, need to set alarm flag
                ret = 1;
            } else {
                ret = 0;
            }
        }
    };

    // Lookup table: maps c -> a*c, populated by control plane
    action set_change(int<32> result) {
        meta.change = result;
    }

    table multiply_lookup {
        key = { meta.c_val : exact; }
        actions = { set_change; }
        size = 200;  // covers [-100, 100] with room to spare
    }


    apply {

        //1. exchange current packet's timestamp arrival using _regone_
        meta.last_time = updateone.execute(0);


        //2. calculate current packet's IAT using curr_time, last_time
        meta.iat = meta.curr_time - meta.last_time;

        //3. check window output from _regtwo_ into meta.flag
        meta.flag = updatetwo.execute(0);

        
        

        meta.comp = actionrfour.execute(0);
        //4. comparison to check whether IAT has fluctuated upwards or downwards
        if(meta.flag == 0) { //we are in the middle of a window
            actionrthree.execute(0);
            
        } else {//we are in the first pane of a new window
            meta.c_val = actionrthreetwo.execute(0);
            multiply_lookup.apply();
            meta.alarm = actionrfourtwo.execute(0);
        }

        if(meta.alarm == 1) {
            //amount of flow increase is too large, need to send digest alert
            ig_dprsr_md.digest_type = 1;
        }
    }
    
}

/*************************************************************************
 **************  I N G R E S S     D E P A R S E R   ************************************************************************************************************************
 *************************************************************************/
control IngressDeparser(
    packet_out                                      pkt,
    /* User */
    inout my_ingress_headers_t                      hdr,
    in    my_ingress_metadata_t                     meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Digest<digest_flag_t>() digest_flag;

    apply {
        if (ig_dprsr_md.digest_type == 1) {
            //we need to send a digest message 
            digest_flag.pack({meta.change});
        }

        pkt.emit(hdr);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/* Egress PARSER */
parser EgressParser(
    packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/* Match-Action CONTROL */
control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {}
}

/* Egress DEPARSER */
control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
