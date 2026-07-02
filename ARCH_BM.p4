/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ***********************  H E A D E R S / S T R U C T S ******************
 *************************************************************************/


#define WINDOW 100 //
#define MEDIAN_THRESHOLD 500
#define IAT_THRESHOLD 500

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
    bit<1> count;
    int<32> change;
    int<32> median;
    bit<1> alarm;
    int<32> c_val;
}

struct time_window_t {
    bit<32> time;
    bit<32> window;
}

struct digest_flag_t {
    int<32> median;
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
	    //advance past the resubmit portion and portmetadata portion VIP TO COMPLETE
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
    //additionally combined with the window tracker, returns bitmask that indicates both the last IAT and the window phase we are in
    Register<time_window_t, bit<1>>(1) reg_time_window;
    RegisterAction<time_window_t, bit<1>, bit<32>>(reg_time_window) updatetime = {
        void apply(inout time_window_t curr, out bit<32> prev) {
            bit<32> var;
            if(curr.window > WINDOW) {
                curr.window = 0;
                //flag = 1;
                var = 0x00000001 | curr.time;
            } else {
                curr.window = curr.window + 1;
                //flag = 0;
                var = 0xFFFFFFFE & curr.time;
            }
            prev = var;
            curr.time = meta.curr_time;

        }
    };

    Register<bit<32>, bit<1>>(1) reg_compare;
    RegisterAction<bit<32>, bit<1>, bit<1>>(reg_compare) compare = {
        void apply(inout bit<32> curr, out bit<1> comp) {
            comp = 0;
            if(curr > IAT_THRESHOLD) {
                comp = 1;
            }
            curr = meta.iat;
        }
    };

    // Register three: just the counter c
    Register<int<32>, bit<1>>(1) reg_count;
    RegisterAction<int<32>, bit<1>, void>(reg_count) midwindow = {
        void apply(inout int<32> value) {
            if(meta.comp == 1) {
                value = value + 1;
            } else {
                value = value - 1;
            }
        }
    };

    RegisterAction<int<32>, bit<1>, int<32>>(reg_count) read_and_reset = {
        void apply(inout int<32> value, out int<32> ret) {
            ret = value;   // read c out
            value = 0;     // reset for new window
        }
    };
    
    // Register four: just the median estimate m
    Register<int<32>, bit<1>>(1) reg_median;
    RegisterAction<int<32>, bit<1>, int<32>>(reg_median) read_median = {
        void apply(inout int<32> value, out int<32> ret) {
            ret = value;   // just read current estimate
        }
    };

    RegisterAction<int<32>, bit<1>, bit<1>>(reg_median) update_median = {
        void apply(inout int<32> value, out bit<1> ret) {
            value = value + (int<32>) meta.change;  // m = m + a*c
            ret = 0;
            if(value < MEDIAN_THRESHOLD) {
                ret = 1;
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
        size = 256;  // covers [-100, 100] with room to spare
    }


    apply {

        //1. exchange current packet's timestamp arrival using _regone_, extract both last IAT and also window phase from bitmask
        bit<32> time_result = updatetime.execute(0);
        meta.last_time = (bit<32>) time_result[31:1];
        meta.flag      = time_result[0:0];

        meta.alarm = 0;
        meta.change = 0;
        meta.median = MEDIAN_THRESHOLD + 1;

        //2. calculate current packet's IAT using curr_time, last_time
        meta.iat = meta.curr_time - meta.last_time;

        //3. comparison checker to check range of IAT
        meta.comp = compare.execute(0);

        //4. fork on which window phase we are in
        if(meta.flag == 0) { //we are starting a new window frame
            meta.c_val = read_and_reset.execute(0);
            multiply_lookup.apply();
            meta.alarm = update_median.execute(0);
        } else {
            //we are in the middle of a window, need to read the median and update the counter
            meta.median = read_median.execute(0);
            midwindow.execute(0);
        }


        // Alarm check — now just normal pipeline logic, no regfour needed
        if(meta.alarm == 1) {
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
            digest_flag.pack({meta.median});
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
