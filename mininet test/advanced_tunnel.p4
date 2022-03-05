#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CONTROLLER_PORT 255


/***HEADERS***/

typedef bit<48> EthernetAddress;
typedef bit<32> ip4Addr_t;
typedef bit<4>  dport;
typedef bit<9>  egressSpec_t;

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
    ethernet_t          ethernet;
    ipv4_t              ipv4;
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
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ethernet_forward(EthernetAddress dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        /*ethernet_forward(dstAddr);*/
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action send_to_controller(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }


    table ipv4_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_exact.apply();
        }
        else
            drop();
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
    }
}


V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;