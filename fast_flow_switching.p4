/* -*- P4_14 -*- */

#ifdef __TARGET_TOFINO__
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>
#else
#error This program is intended to compile for Tofino P4 architecture only
#endif

// Scheduled media switching based on RTP timestamp
// Author: Thomas Edwards (thomas.edwards@fox.com)

// Fast Flow Switching based on register change

// "Although registers cannot be used directly in matching, they may be used as
// the source of a modify_field action allowing the current value of the
// register to be copied to a packet’s metadata and be available for matching
// in subsequent tables."

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}

header_type flow_set_id_t {
    fields {
        flow_set_id : 32;
    }
}

metadata flow_set_id_t flow_set_id_metadata;

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

#define ETHERTYPE_IPV4 0x0800

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
   }
}

header ipv4_t ipv4;

#define PROTOCOL_UDP 0x11

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}


register r_flow_set{
    width : 32;
    instance_count : 1;
}


/* Statefule ALU Program Code */
blackbox stateful_alu salu_prog_read_my_reg {
	reg : r_flow_set;

	update_lo_1_value: register_lo;

	output_value: 	alu_lo;
	output_dst:	flow_set_id_metadata.flow_set_id;
}

action copy_register_to_metadata() {
//        modify_field(flow_set_id_metadata.flow_set_id,r_flow_set);
	  salu_prog_read_my_reg.execute_stateful_alu(0);
}

action _drop() {
    drop();
}

table copy_flow_set_id {
    reads {
      ipv4.dstAddr: exact;
    }
    actions {
      copy_register_to_metadata;
      _drop;
    }
}

action take_video(dst_ip,dport) {
//      modify_field(standard_metadata.egress_spec,dport);
      modify_field(ig_intr_md_for_tm.ucast_egress_port,dport);
      modify_field(ipv4.dstAddr,dst_ip);
}

table schedule_table {
    reads {
        ipv4.dstAddr: exact;
        flow_set_id_metadata.flow_set_id: exact;
    }
    actions {
        take_video;
        _drop;
    }
    size : 128;
}

control ingress {
    apply(copy_flow_set_id);
    apply(schedule_table);
}

control egress {
}
