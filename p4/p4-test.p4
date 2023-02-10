/***
        The starting page from where this work is based:
        https://opennetworking.org/news-and-events/blog/getting-started-with-p4/

        ---- <> ---- <> ---- <> ---- <> ----

        To compile this P4 program: p4c -b bmv2 p4-test.p4 -o test.bmv2
        The -b option selects bmv2 (Behavioral Model Version 2) as the target,
        which is the software switch that we will use to run the P4 program.

        This compiler generates a directory test.bmv2 which contains a file test.json
        which the generated “executable” code which is run by the software switch.

        ---- <> ---- <> ---- <> ---- <> ----

        p4c-bm2-ss --p4v 16 -o test.json --p4runtime-files test.p4info p4-test.p4

        in a symbolic way:
        p4c-bm2-ss --p4v 16 -o name_file_json --p4runtime-files name_file_p4info name_file_p4

        --p4v is the version of p4 which is used
        -o is the "executable" code generated by the compiler from the .p4 file
        --p4runtime-files to indicate the name of the two files generated
        test.p4info.txt     is the name of the program written in p4info
        name_file_p4        is the name of the program written in p4

        ---- <> ---- <> ---- <> ---- <> ----
        
        This program has a single lookup table, which does:
            an exact match on the source IP address in the received packet
            an exact match on the destination IP address in the received packet
            a ternary match on the source port in the received packet
            a ternary match on the destination port in the received packet

            (in this way, we can use wildcards for the ports)
        
        The actions are:
            drop the packet,
            forward the packet to a specific output port,
            no action,
            send the packet to the controller (default one)
***/

// To understand better how to clone, recirculate, etc...
// https://carolinafernandez.github.io/development/2019/08/06/Recurrent-processing-in-P4
// https://github.com/CarolinaFernandez/p4-tutorials/blob/master/exercises/clone/solution/clone.p4

// This is the official repository p4-guide
// https://github.com/jafingerhut/p4-guide/blob/7dc15e2c24d60c52ad59dd71a0962a87086bb57b/v1model-special-ops/v1model-special-ops.p4

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
#define CONTROLLER_PORT 255

// These definitions are derived from the numerical values of the enum
// named "PktInstanceType" in the p4lang/behavioral-model source file
// targets/simple_switch/simple_switch.h

// https://github.com/p4lang/behavioral-model/blob/main/targets/simple_switch/simple_switch.h#L145-L153

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

#define IS_RESUBMITTED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)

const bit<32> I2E_CLONE_SESSION_ID = 5;
const bit<8> CLONE_FL_1 = 2;

/***HEADERS***/

typedef bit<48> EthernetAddress;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

//https://www.rfc-editor.org/rfc/rfc9263.html#name-nsh-md-type-2-format
header nsh_t {
    // nsh base
    bit<2> version;
    bit<1> oam;
    bit<1> u1;
    bit<6> ttl;
    bit<6> length;
    bit<4> u2;
    bit<4> md_type;
    bit<8> nextproto;
    bit<24> service_path_identifier;
    bit<8> service_index;
    // nsh with the variable-length context headers
    bit<16> metadata_class;
    bit<8> type;
    bit<1> u3;
    bit<7> vlch_length;
    // this is our focus
    bit<512> metadata_payload;
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

//https://www.ietf.org/rfc/rfc9293.html#name-header-format
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header packet_out_header_t {
    bit<16> egress_port;
}

header packet_in_header_t {
    bit<16> ingress_port;
}

//user metadata
struct metadata_t {
    @field_list(CLONE_FL_1)
    bit<16> tcpLength;
}

struct headers_t {
    @field_list(CLONE_FL_1)
    packet_in_header_t  packet_in;
    @field_list(CLONE_FL_1)
    packet_out_header_t packet_out;
    @field_list(CLONE_FL_1)
    ethernet_t       ethernet;
    @field_list(CLONE_FL_1)
    nsh_t            nsh;
    @field_list(CLONE_FL_1)
    ipv4_t           ipv4;
    @field_list(CLONE_FL_1)
    tcp_t            tcp;
    @field_list(CLONE_FL_1)
    udp_t            udp;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

  /************/
 /*  PARSER  */
/************/
parser my_parser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition parse_nsh;
    }

    state parse_nsh {
        packet.extract(hdr.nsh);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // needed for doing a correct checksum
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

  /**************************/
 /* CHECKSUM VERIFICATION  */
/**************************/
control my_verify_checksum( inout headers_t hdr,
                            inout metadata_t meta)
{
    apply { }
}

  /**************/
 /*  INGRESS  */
/************/
control my_ingress( inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata)
{

    bit<16> src_port = 0;
    bit<16> dst_port = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ethernet_forward(EthernetAddress dstAddr, EthernetAddress srcAddr){
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action ipv4_forward(EthernetAddress dstAddr, EthernetAddress srcAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        ethernet_forward(dstAddr, srcAddr);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action send_to_controller(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    } 

    action hmac_forward() {
        // I have to duplicate the packet to notify the control plan that I have received
        // a packet with a correct hmac inside the NSH, so I can send it to the
        // next table and set to 1 my metadata support
        // duplicate the packet and set it to go to the controller
        // so he can add the table row in the table my_ingress.forward

        // @field_list(CLONE_FL_1) in the components up we want to preservate for the controller
        clone_preserving_field_list(CloneType.I2E, 5, CLONE_FL_1);
    }

    table hmac {
        key = {
            hdr.nsh.metadata_payload: exact;
        }
        actions = {
            hmac_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            src_port: ternary;
            dst_port: ternary;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {

        if (hdr.nsh.isValid()){
            // Copy the packet --- IF AND ONLY IF --- the nsh match was verified
            // so, the packet can go towards the server
            hmac.apply();
        }
        if (hdr.ipv4.isValid()) {

            if (hdr.tcp.isValid()){
                src_port = hdr.tcp.srcPort;
                dst_port = hdr.tcp.dstPort;
                forward.apply();
            }
            else if (hdr.udp.isValid()){
                src_port = hdr.udp.srcPort;
                dst_port = hdr.udp.dstPort;
                forward.apply();
            }
            else{
                drop();
            }
            
        }
        else {
            drop();
        }
        
    }
}

  /************/
 /*  EGRESS  */
/************/
control my_egress(  inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata)
{
     apply{
        // if it is a cloned packet, send it to the controller to notify that
        // an hmac match is happened so he can update the strict table
        if(standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE){
            standard_metadata.egress_spec = CONTROLLER_PORT;
        }
     }
}

  /**************************/
 /*  CHECKSUM COMPUTATION  */
/**************************/
control my_compute_checksum(    inout headers_t hdr,
                                inout metadata_t meta)
{
    // it's not important the presence of the checksum inside the {...} because it will be considered as 0 like the RFC standard
    // in this way the kernel of the VMs will not drop out the packet incoming
    apply { 
        update_checksum( hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
        update_checksum_with_payload ( hdr.tcp.isValid(),
            { 
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLength,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
    }
}


  /**************/
 /*  DEPARSER  */
/**************/
control my_deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.packet_out);
        packet.emit(hdr.ethernet);
        // don't emit the nsh header
        // it's just an information for us
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

// we need to match these 6 component for the V1Switch atchitecture
// because its are the 6 phases for this type of switch
V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;