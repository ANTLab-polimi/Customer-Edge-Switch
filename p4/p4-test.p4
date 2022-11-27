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
        
        This program has a single lookup table, which does:
            an exact match on the source IP address in the received packet
            an exact match on the destination IP address in the received packet
            a ternary match on the source port in the received packet
            an exact match on the destination port in the received packet
        
        The actions are:
            drop the packet,
            forward the packet to a specific output port,
            no action,
            send the packet to the controller (default one)
***/

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
#define CONTROLLER_PORT 255


/***HEADERS***/

typedef bit<48> EthernetAddress;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
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

struct metadata_t {

}

struct headers_t {
    packet_in_header_t  packet_in;
    packet_out_header_t packet_out;
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    udp_t            udp;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}


/***PARSER***/

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
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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


/***CHECKSUM VERIFICATION***/

control my_verify_checksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { }
}


/***INGRESS***/

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{

    bit<16> src_port = 0;
    bit<16> dst_port = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ethernet_forward(EthernetAddress dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action ipv4_forward(EthernetAddress dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        ethernet_forward(dstAddr);
    }

    action send_to_controller(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }

    table forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            src_port: ternary;
            dst_port: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    apply {
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
                send_to_controller();
                /*drop();*/
            }
        }
        else {
            send_to_controller();
            /*drop();*/
        }
    }
}


/***EGRESS***/

control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}


/***CHECKSUM COMPUTATION***/

control my_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { }
}



/***DEPARSER***/

control my_deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.packet_out);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}


V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;