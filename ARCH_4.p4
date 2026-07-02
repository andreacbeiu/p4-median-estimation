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
    bit<2> flag;
    bit<1> comp;
    bit<1> count;
    int<32> change;
    int<32> median;
    bit<1> alarm;
}

struct regthree_t {
    int<32> count;
    int<32> median;
}

struct regfour_t {
    int<32> median_holder;
    int<32> comparison;
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

    //define R1: timestamp buffer, keeps track of last packetś arrival time so that IAT = curr - last can occur in Control Block
    Register<bit<32>, bit<1>>(1) regone;
    RegisterAction<bit<32>, bit<1>, bit<32>>(regone) updateone = {
        void apply(inout bit<32> curr, out bit<32> prev) {
            prev = curr; //save the last packet's arrival time to output
            curr = meta.curr_time; //save the current incoming packet's time to register
        }
    };

    //define R2: window keeper
    Register<bit<32>, bit<1>>(1) regtwo;
    RegisterAction<bit<32>, bit<1>, bit<2>>(regtwo) updatetwo = {
        void apply(inout bit<32> curr, out bit<2> ret) {
            ret = 0;
            if(curr >= WINDOW) {
                ret = 1;
                curr = 0;
            } else {
                curr = curr + 1;
            }
        }
    };

    
    Register<regthree_t, bit<1>>(1) regthree;
    MathUnit<int<32>>(MathOp_t.MUL, 1, 5) multiply_by_5;

    RegisterAction<regthree_t, bit<1>, void>(regthree) midwindow = {
        void apply(inout regthree_t value) {
            if((int<32>) meta.iat >= value.median) {
                //current iat is larger than or equal to estimate => flow is the "same" or slower than estimate
                value.count = value.count - 1;
            } else {
                //current iat is strictly smaller than estimate => flow is faster than estimate
                value.count = value.count + 1;
            }
        }
    };
    RegisterAction<regthree_t, bit<1>, int<32>>(regthree) newwindow = {
        void apply(inout regthree_t value, out int<32> ret) {
            value.count = multiply_by_5.execute(value.count);
            value.median = value.median + value.count;
            value.count = 0;
            ret = value.median;
        }
    };

    Register<int<32>, bit<1>>(1) regfour;
    RegisterAction<int<32>, bit<1>, bit<1>>(regfour) compare = {
        void apply(inout int<32> value, out bit<1> ret) {
            ret = 0;
            if((int<32>) meta.median < MEDIAN_THRESHOLD) {
                ret = 1;
            }
        }
    }; 

    apply {

        //1. exchange current packet's timestamp arrival using _regone_
        meta.last_time = updateone.execute(0);

        meta.alarm = 0;
        meta.median = 0;
        meta.change = 0;

        //2. calculate current packet's IAT using curr_time, last_time
        meta.iat = meta.curr_time - meta.last_time;

        //3. check window output from _regtwo_ into meta.flag
        meta.flag = updatetwo.execute(0);

        //4. fork on which window stage we are in
        if(meta.flag == 1) { //we are starting a new window frame
            meta.median = newwindow.execute(0);  
        } else { //we are in the first window pane of a new frame
            midwindow.execute(0);
        }

        meta.alarm = compare.execute(0);
        
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
