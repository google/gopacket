// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/google/gopacket"
)

const (
	/* Openflow Meter control */
	OFPv14MeterAdd = 0 /* New meter */
	OFPv14MeterMod = 1 /* Modify specified meter */
	OFPv14MeterDel = 2 /* Delete specified meter */
)

const (
	/* Immutable symmetric messages */
	OFPv14TypeHello       = 0
	OFPv14TypeError       = 1
	OFPv14TypeEchoRequest = 2
	OFPv14TypeEchoReply   = 3
	OFPv14TypeExperiment  = 4

	/* Switch configuration messages */
	OFPv14TypeFeaturesRequest  = 5
	OFPv14TypeFeaturesReply    = 6
	OFPv14TypeGetConfigRequest = 7
	OFPv14TypeGetConfigReply   = 8
	OFPv14TypeSetConfig        = 9

	/* Asynchronous messages */
	OFPv14TypePacketIn    = 10
	OFPv14TypeFlowRemoved = 11
	OFPv14TypePortStatus  = 12

	/* Controller/switch command messages */
	OFPT_PACKET_OUT = 13
	OFPT_FLOW_MOD   = 14
	OFPT_GROUP_MOD  = 15
	OFPT_PORT_MOD   = 16
	OFPT_TABLE_MOD  = 17

	/* Multipart messages */
	OFPT_MULTIPART_REQUEST = 18
	OFPT_MULTIPART_REPLY   = 19

	/* Barrier messages. */
	OFPT_BARRIER_REQUEST = 20
	OFPT_BARRIER_REPLY   = 21

	/* Queue Configuration messages */
	OFPT_QUEUE_GET_CONFIG_REQUEST = 22
	OFPT_QUEUE_GET_CONFIG_REPLY   = 23

	/* Controller role change request messages */
	OFPT_ROLE_REQUEST = 24
	OFPT_ROLE_REPLY   = 25

	/* Asynchronous message configuration */
	OFPT_GET_ASYNC_REQUEST = 26
	OFPT_GET_ASYNC_REPLY   = 27
	OFPT_SET_ASYNC         = 28

	/* Meters and rate limiters configuration messages */
	OFPT_METER_MOD = 29
)

const (
	OFPPC_PORT_DOWN    = 1 << 0 /* Port is administratively down. */
	OFPPC_NO_STP       = 1 << 1 /* Disable 802.1D spanning tree on port. */
	OFPPC_NO_RECV      = 1 << 2 /* Drop all packets received by port. */
	OFPPC_NO_RECV_STP  = 1 << 3 /* Drop received 802.1D STP packets. */
	OFPPC_NO_FLOOD     = 1 << 4 /* Do not include this port when flooding. */
	OFPPC_NO_FWD       = 1 << 5 /* Drop packets forwarded to port. */
	OFPPC_NO_PACKET_IN = 1 << 6 /* Do not send packet-in msgs for port. */
)

const (
	/* Openflow port status */
	OpenflowPortStatusLinkDown = 1 << 0 /* No physical link present. */
	OpenflowPortStatusBlocked  = 1 << 1 /* Port is blocked */
	OpenflowPortStatusLive     = 1 << 2 /* Live for Fast Failover Group. */
)

const (
	/* Maximum number of physical and logical switch ports. */
	OFPP_MAX        = 0xffffff00 /* Reserved OpenFlow Port (fake output "ports"). */
	OFPP_IN_PORT    = 0xfffffff8 /* Send the packet out the input port.  Thisreserved port must be explicitly usedin order to send back out of the inputport. */
	OFPP_TABLE      = 0xfffffff9 /* Submit the packet to the first flow tableNB: This destination port can only beused in packet-out messages. */
	OFPP_NORMAL     = 0xfffffffa /* Process with normal L2/L3 switching. */
	OFPP_FLOOD      = 0xfffffffb /* All physical ports in VLAN, except inputport and those blocked or link down. */
	OFPP_ALL        = 0xfffffffc /* All physical ports except input port. */
	OFPP_CONTROLLER = 0xfffffffd /* Send to controller. */
	OFPP_LOCAL      = 0xfffffffe /* Local openflow "port". */
	OFPP_ANY        = 0xffffffff /* Wildcard port used only for flow mod(delete) and flow stats requests. Selectsall flows regardless of output port(including flows with no output port). */
)

const (
	OFPPF_10MB_HD    = 1 << 0  /* 10 Mb half-duplex rate support. */
	OFPPF_10MB_FD    = 1 << 1  /* 10 Mb full-duplex rate support. */
	OFPPF_100MB_HD   = 1 << 2  /* 100 Mb half-duplex rate support. */
	OFPPF_100MB_FD   = 1 << 3  /* 100 Mb full-duplex rate support. */
	OFPPF_1GB_HD     = 1 << 4  /* 1 Gb half-duplex rate support. */
	OFPPF_1GB_FD     = 1 << 5  /* 1 Gb full-duplex rate support. */
	OFPPF_10GB_FD    = 1 << 6  /* 10 Gb full-duplex rate support. */
	OFPPF_40GB_FD    = 1 << 7  /* 40 Gb full-duplex rate support. */
	OFPPF_100GB_FD   = 1 << 8  /* 100 Gb full-duplex rate support. */
	OFPPF_1TB_FD     = 1 << 9  /* 1 Tb full-duplex rate support. */
	OFPPF_OTHER      = 1 << 10 /* Other rate, not in the list. */
	OFPPF_COPPER     = 1 << 11 /* Copper medium. */
	OFPPF_FIBER      = 1 << 12 /* Fiber medium. */
	OFPPF_AUTONEG    = 1 << 13 /* Auto-negotiation. */
	OFPPF_PAUSE      = 1 << 14 /* Pause. */
	OFPPF_PAUSE_ASYM = 1 << 15 /* Asymmetric pause. */
)

const (
	OFPQT_MIN_RATE     = 1      /* Minimum datarate guaranteed. */
	OFPQT_MAX_RATE     = 2      /* Maximum datarate. */
	OFPQT_EXPERIMENTER = 0xffff /* Experimenter defined property. */
)

const (
	OFPMT_STANDARD = 0 /* Deprecated. */
	OFPMT_OXM      = 1 /* OpenFlow Extensible Match */

)

const (
	OFPXMC_NXM_0          = 0x0000 /* Backward compatibility with NXM */
	OFPXMC_NXM_1          = 0x0001 /* Backward compatibility with NXM */
	OFPXMC_OPENFLOW_BASIC = 0x8000 /* Basic class for OpenFlow */
	OFPXMC_EXPERIMENTER   = 0xFFFF /* Experimenter class */
)

const (
	OFPXMT_OFB_IN_PORT        = 0  /* Switch input port. */
	OFPXMT_OFB_IN_PHY_PORT    = 1  /* Switch physical input port. */
	OFPXMT_OFB_METADATA       = 2  /* Metadata passed between tables. */
	OFPXMT_OFB_ETH_DST        = 3  /* Ethernet destination address. */
	OFPXMT_OFB_ETH_SRC        = 4  /* Ethernet source address. */
	OFPXMT_OFB_ETH_TYPE       = 5  /* Ethernet frame type. */
	OFPXMT_OFB_VLAN_VID       = 6  /* VLAN id. */
	OFPXMT_OFB_VLAN_PCP       = 7  /* VLAN priority. */
	OFPXMT_OFB_IP_DSCP        = 8  /* IP DSCP (6 bits in ToS field). */
	OFPXMT_OFB_IP_ECN         = 9  /* IP ECN (2 bits in ToS field). */
	OFPXMT_OFB_IP_PROTO       = 10 /* IP protocol. */
	OFPXMT_OFB_IPV4_SRC       = 11 /* IPv4 source address. */
	OFPXMT_OFB_IPV4_DST       = 12 /* IPv4 destination address. */
	OFPXMT_OFB_TCP_SRC        = 13 /* TCP source port. */
	OFPXMT_OFB_TCP_DST        = 14 /* TCP destination port. */
	OFPXMT_OFB_UDP_SRC        = 15 /* UDP source port. */
	OFPXMT_OFB_UDP_DST        = 16 /* UDP destination port. */
	OFPXMT_OFB_SCTP_SRC       = 17 /* SCTP source port. */
	OFPXMT_OFB_SCTP_DST       = 18 /* SCTP destination port. */
	OFPXMT_OFB_ICMPV4_TYPE    = 19 /* ICMP type. */
	OFPXMT_OFB_ICMPV4_CODE    = 20 /* ICMP code. */
	OFPXMT_OFB_ARP_OP         = 21 /* ARP opcode. */
	OFPXMT_OFB_ARP_SPA        = 22 /* ARP source IPv4 address. */
	OFPXMT_OFB_ARP_TPA        = 23 /* ARP target IPv4 address. */
	OFPXMT_OFB_ARP_SHA        = 24 /* ARP source hardware address. */
	OFPXMT_OFB_ARP_THA        = 25 /* ARP target hardware address. */
	OFPXMT_OFB_IPV6_SRC       = 26 /* IPv6 source address. */
	OFPXMT_OFB_IPV6_DST       = 27 /* IPv6 destination address. */
	OFPXMT_OFB_IPV6_FLABEL    = 28 /* IPv6 Flow Label */
	OFPXMT_OFB_ICMPV6_TYPE    = 29 /* ICMPv6 type. */
	OFPXMT_OFB_ICMPV6_CODE    = 30 /* ICMPv6 code. */
	OFPXMT_OFB_IPV6_ND_TARGET = 31 /* Target address for ND. */
	OFPXMT_OFB_IPV6_ND_SLL    = 32 /* Source link-layer for ND. */
	OFPXMT_OFB_IPV6_ND_TLL    = 33 /* Target link-layer for ND. */
	OFPXMT_OFB_MPLS_LABEL     = 34 /* MPLS label. */
	OFPXMT_OFB_MPLS_TC        = 35 /* MPLS TC. */
	OFPXMT_OFP_MPLS_BOS       = 36 /* MPLS BoS bit. */
	OFPXMT_OFB_PBB_ISID       = 37 /* PBB I-SID. */
	OFPXMT_OFB_TUNNEL_ID      = 38 /* Logical Port Metadata. */
	OFPXMT_OFB_IPV6_EXTHDR    = 39 /* IPv6 Extension Header pseudo-field */
)

const (
	OFPVID_PRESENT = 0x1000 /* Bit that indicate that a VLAN id is set */
	OFPVID_NONE    = 0x0000 /* No VLAN id was set. */
)

const (
	OFPIEH_NONEXT = 1 << 0 /* "No next header" encountered. */
	OFPIEH_ESP    = 1 << 1 /* Encrypted Sec Payload header present. */
	OFPIEH_AUTH   = 1 << 2 /* Authentication header present. */
	OFPIEH_DEST   = 1 << 3 /* 1 or 2 dest headers present. */
	OFPIEH_FRAG   = 1 << 4 /* Fragment header present. */
	OFPIEH_ROUTER = 1 << 5 /* Router header present. */
	OFPIEH_HOP    = 1 << 6 /* Hop-by-hop header present. */
	OFPIEH_UNREP  = 1 << 7 /* Unexpected repeats encountered. */
	OFPIEH_UNSEQ  = 1 << 8 /* Unexpected sequencing encountered. */
)

const (
	OFPIT_GOTO_TABLE     = 1      /* Setup the next table in the lookuppipeline */
	OFPIT_WRITE_METADATA = 2      /* Setup the metadata field for use later inpipeline */
	OFPIT_WRITE_ACTIONS  = 3      /* Write the action(s) onto the datapath actionset */
	OFPIT_APPLY_ACTIONS  = 4      /* Applies the action(s) immediately */
	OFPIT_CLEAR_ACTIONS  = 5      /* Clears all actions from the datapathaction set */
	OFPIT_METER          = 6      /* Apply meter (rate limiter) */
	OFPIT_EXPERIMENTER   = 0xFFFF /* Experimenter instruction */
)

const (
	OFPAT_OUTPUT       = 0  /* Output to switch port. */
	OFPAT_COPY_TTL_OUT = 11 /* Copy TTL "outwards" -- from next-to-outermostto outermost */
	OFPAT_COPY_TTL_IN  = 12 /* Copy TTL "inwards" -- from outermost tonext-to-outermost */
	OFPAT_SET_MPLS_TTL = 15 /* MPLS TTL */
	OFPAT_DEC_MPLS_TTL = 16 /* Decrement MPLS TTL */
	OFPAT_PUSH_VLAN    = 17 /* Push a new VLAN tag */
	OFPAT_POP_VLAN     = 18 /* Pop the outer VLAN tag */
	OFPAT_PUSH_MPLS    = 19 /* Push a new MPLS tag */
	OFPAT_POP_MPLS     = 20 /* Pop the outer MPLS tag */
	OFPAT_SET_QUEUE    = 21 /* Set queue id when outputting to a port */
	OFPAT_GROUP        = 22 /* Apply group. */
	OFPAT_SET_NW_TTL   = 23 /* IP TTL. */
	OFPAT_DEC_NW_TTL   = 24 /* Decrement IP TTL. */
	OFPAT_SET_FIELD    = 25 /* Set a header field using OXM TLV format. */
	OFPAT_PUSH_PBB     = 26 /* Push a new PBB service tag (I-TAG) */
	OFPAT_POP_PBB      = 27 /* Pop the outer PBB service tag (I-TAG) */
	OFPAT_EXPERIMENTER = 0xffff
)

const (
	OFPCML_MAX       = 0xffe5 /* maximum max_len value which can be usedto request a specific byte length. */
	OFPCML_NO_BUFFER = 0xffff /* indicates that no buffering should beapplied and the whole packet is to besent to the controller. */
)

const (
	OFPC_FLOW_STATS   = 1 << 0 /* Flow statistics. */
	OFPC_TABLE_STATS  = 1 << 1 /* Table statistics. */
	OFPC_PORT_STATS   = 1 << 2 /* Port statistics. */
	OFPC_GROUP_STATS  = 1 << 3 /* Group statistics. */
	OFPC_IP_REASM     = 1 << 5 /* Can reassemble IP fragments. */
	OFPC_QUEUE_STATS  = 1 << 6 /* Queue statistics. */
	OFPC_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
)

const (
	OFPC_FRAG_NORMAL = 0      /* No special handling for fragments. */
	OFPC_FRAG_DROP   = 1 << 0 /* Drop fragments. */
	OFPC_FRAG_REASM  = 1 << 1 /* Reassemble (only if OFPC_IP_REASM set). */
	OFPC_FRAG_MASK   = 3
)

const (
	/* Last usable table number. */
	OFPTT_MAX = 0xfe /* Fake tables. */
	OFPTT_ALL = 0xff /* Wildcard table used for table config,flow stats and flow deletes. */
)

const (
	OFPFC_ADD           = 0 /* New flow. */
	OFPFC_MODIFY        = 1 /* Modify all matching flows. */
	OFPFC_MODIFY_STRICT = 2 /* Modify entry strictly matching wildcards andpriority. */
	OFPFC_DELETE        = 3 /* Delete all matching flows. */
	OFPFC_DELETE_STRICT = 4 /* Delete entry strictly matching wildcards andpriority. */
)

const (
	OFPFF_SEND_FLOW_REM = 1 << 0 /* Send flow removed message when flow* expires or is deleted. */
	OFPFF_CHECK_OVERLAP = 1 << 1 /* Check for overlapping entries first. */
	OFPFF_RESET_COUNTS  = 1 << 2 /* Reset flow packet and byte counts. */
	OFPFF_NO_PKT_COUNTS = 1 << 3 /* Don't keep track of packet count. */
	OFPFF_NO_BYT_COUNTS = 1 << 4 /* Don't keep track of byte count. */
)

const (
	OFPGC_ADD    = 0 /* New group. */
	OFPGC_MODIFY = 1 /* Modify all matching groups. */
	OFPGC_DELETE = 2 /* Delete all matching groups. */
)

const (
	OFPGT_ALL      = 0 /* All (multicast/broadcast) group. */
	OFPGT_SELECT   = 1 /* Select group. */
	OFPGT_INDIRECT = 2 /* Indirect group. */
	OFPGT_FF       = 3 /* Fast failover group. */
)

const (
	/* Last usable meter. */
	OFPM_MAX = 0xffff0000

	/* Virtual meters. */
	OFPM_SLOWPATH   = 0xfffffffd /* Meter for slow datapath, if any. */
	OFPM_CONTROLLER = 0xfffffffe /* Meter for controller connection. */
	OFPM_ALL        = 0xffffffff /* Represents all meters for stat requestscommands. */
)

const (
	OFPMF_KBPS  = 1 << 0 /* Rate value in kb/s (kilo-bit per second). */
	OFPMF_PKTPS = 1 << 1 /* Rate value in packet/sec. */
	OFPMF_BURST = 1 << 2 /* Do burst size. */
	OFPMF_STATS = 1 << 3 /* Collect statistics. */
)

const (
	OFPMBT_DROP         = 1      /* Drop packet. */
	OFPMBT_DSCP_REMARK  = 2      /* Remark DSCP in the IP header. */
	OFPMBT_EXPERIMENTER = 0xFFFF /* Experimenter meter band. */
)

const (
	OFPMPF_REQ_MORE = 1 << 0 /* More requests to follow. */
)

const (
	OFPMPF_REPLY_MORE = 1 << 0 /* More replies to follow. */
)

const (
	/* Description of this OpenFlow switch.* The request body is empty.* The reply body is struct ofp_desc. */ OFPMP_DESC = 0

	/* Individual flow statistics.* The request body is struct ofp_flow_stats_request.* The reply body is an array of struct ofp_flow_stats. */
	OFPMP_FLOW = 1

	/* Aggregate flow statistics.* The request body is struct ofp_aggregate_stats_request.* The reply body is struct ofp_aggregate_stats_reply. */
	OFPMP_AGGREGATE = 2

	/* Flow table statistics.* The request body is empty.* The reply body is an array of struct ofp_table_stats. */
	OFPMP_TABLE = 3

	/* Port statistics.* The request body is struct ofp_port_stats_request.* The reply body is an array of struct ofp_port_stats. */
	OFPMP_PORT_STATS = 4

	/* Queue statistics for a port* The request body is struct ofp_queue_stats_request.* The reply body is an array of struct ofp_queue_stats */
	OFPMP_QUEUE = 5

	/* Group counter statistics.* The request body is struct ofp_group_stats_request.* The reply is an array of struct ofp_group_stats. */
	OFPMP_GROUP = 6

	/* Group description.* The request body is empty.* The reply body is an array of struct ofp_group_desc_stats. */
	OFPMP_GROUP_DESC = 7

	/* Group features.* The request body is empty.* The reply body is struct ofp_group_features. */
	OFPMP_GROUP_FEATURES = 8

	/* Meter statistics.* The request body is struct ofp_meter_multipart_requests.* The reply body is an array of struct ofp_meter_stats. */
	OFPMP_METER = 9

	/* Meter configuration.* The request body is struct ofp_meter_multipart_requests.* The reply body is an array of struct ofp_meter_config. */
	OFPMP_METER_CONFIG = 10

	/* Meter features.* The request body is empty.* The reply body is struct ofp_meter_features. */
	OFPMP_METER_FEATURES = 11

	/* Table features.* The request body is either empty or contains an array of* struct ofp_table_features containing the controller's* desired view of the switch. If the switch is unable to* set the specified view an error is returned.* The reply body is an array of struct ofp_table_features. */
	OFPMP_TABLE_FEATURES = 12

	/* Port description.* The request body is empty.* The reply body is an array of struct ofp_port. */
	OFPMP_PORT_DESC = 13

	/* Experimenter extension.* The request and reply bodies begin with* struct ofp_experimenter_multipart_header.* The request and reply bodies are otherwise experimenter-defined. */
	OFPMP_EXPERIMENTER = 0xffff
)

const (
	OFPTFPT_INSTRUCTIONS        = 0      /* Instructions property. */
	OFPTFPT_INSTRUCTIONS_MISS   = 1      /* Instructions for table-miss. */
	OFPTFPT_NEXT_TABLES         = 2      /* Next Table property. */
	OFPTFPT_NEXT_TABLES_MISS    = 3      /* Next Table for table-miss. */
	OFPTFPT_WRITE_ACTIONS       = 4      /* Write Actions property. */
	OFPTFPT_WRITE_ACTIONS_MISS  = 5      /* Write Actions for table-miss. */
	OFPTFPT_APPLY_ACTIONS       = 6      /* Apply Actions property. */
	OFPTFPT_APPLY_ACTIONS_MISS  = 7      /* Apply Actions for table-miss. */
	OFPTFPT_MATCH               = 8      /* Match property. */
	OFPTFPT_WILDCARDS           = 10     /* Wildcards property. */
	OFPTFPT_WRITE_SETFIELD      = 12     /* Write Set-Field property. */
	OFPTFPT_WRITE_SETFIELD_MISS = 13     /* Write Set-Field for table-miss. */
	OFPTFPT_APPLY_SETFIELD      = 14     /* Apply Set-Field property. */
	OFPTFPT_APPLY_SETFIELD_MISS = 15     /* Apply Set-Field for table-miss. */
	OFPTFPT_EXPERIMENTER        = 0xFFFE /* Experimenter property. */
	OFPTFPT_EXPERIMENTER_MISS   = 0xFFFF /* Experimenter for table-miss. */
)

const (
	OFPGFC_SELECT_WEIGHT   = 1 << 0 /* Support weight for select groups */
	OFPGFC_SELECT_LIVENESS = 1 << 1 /* Support liveness for select groups */
	OFPGFC_CHAINING        = 1 << 2 /* Support chaining groups */
	OFPGFC_CHAINING_CHECKS = 1 << 3 /* Check chaining for loops and delete */
)

const (
	OFPCR_ROLE_NOCHANGE = 0 /* Don't change current role. */
	OFPCR_ROLE_EQUAL    = 1 /* Default role, full access. */
	OFPCR_ROLE_MASTER   = 2 /* Full access, at most one master. */
	OFPCR_ROLE_SLAVE    = 3 /* Read-only access. */
)

const (
	OFPR_NO_MATCH    = 0 /* No matching flow (table-miss flow entry). */
	OFPR_ACTION      = 1 /* Action explicitly output to controller. */
	OFPR_INVALID_TTL = 2 /* Packet has invalid TTL */
)

const (
	OFPRR_IDLE_TIMEOUT = 0 /* Flow idle time exceeded idle_timeout. */
	OFPRR_HARD_TIMEOUT = 1 /* Time exceeded hard_timeout. */
	OFPRR_DELETE       = 2 /* Evicted by a DELETE flow mod. */
	OFPRR_GROUP_DELETE = 3 /* Group was removed. */
)

const (
	OFPPR_ADD    = 0 /* The port was added. */
	OFPPR_DELETE = 1 /* The port was removed. */
	OFPPR_MODIFY = 2 /* Some attribute of the port has changed. */
)

const (
	OFPET_HELLO_FAILED          = 0      /* Hello protocol failed. */
	OFPET_BAD_REQUEST           = 1      /* Request was not understood. */
	OFPET_BAD_ACTION            = 2      /* Error in action description. */
	OFPET_BAD_INSTRUCTION       = 3      /* Error in instruction list. */
	OFPET_BAD_MATCH             = 4      /* Error in match. */
	OFPET_FLOW_MOD_FAILED       = 5      /* Problem modifying flow entry. */
	OFPET_GROUP_MOD_FAILED      = 6      /* Problem modifying group entry. */
	OFPET_PORT_MOD_FAILED       = 7      /* Port mod request failed. */
	OFPET_TABLE_MOD_FAILED      = 8      /* Table mod request failed. */
	OFPET_QUEUE_OP_FAILED       = 9      /* Queue operation failed. */
	OFPET_SWITCH_CONFIG_FAILED  = 10     /* Switch config request failed. */
	OFPET_ROLE_REQUEST_FAILED   = 11     /* Controller Role request failed. */
	OFPET_METER_MOD_FAILED      = 12     /* Error in meter. */
	OFPET_TABLE_FEATURES_FAILED = 13     /* Setting table features failed. */
	OFPET_EXPERIMENTER          = 0xffff /* Experimenter error messages. */
)

const (
	OFPHFC_INCOMPATIBLE = 0 /* No compatible version. */
	OFPHFC_EPERM        = 1 /* Permissions error. */
)

const (
	OFPBRC_BAD_VERSION               = 0  /* ofp_header.version not supported. */
	OFPBRC_BAD_TYPE                  = 1  /* ofp_header.type not supported. */
	OFPBRC_BAD_MULTIPART             = 2  /* ofp_multipart_request.type not supported. */
	OFPBRC_BAD_EXPERIMENTER          = 3  /* Experimenter id not supported* (in ofp_experimenter_header or* ofp_multipart_request or* ofp_multipart_reply). */
	OFPBRC_BAD_EXP_TYPE              = 4  /* Experimenter type not supported. */
	OFPBRC_EPERM                     = 5  /* Permissions error. */
	OFPBRC_BAD_LEN                   = 6  /* Wrong request length for type. */
	OFPBRC_BUFFER_EMPTY              = 7  /* Specified buffer has already been used. */
	OFPBRC_BUFFER_UNKNOWN            = 8  /* Specified buffer does not exist. */
	OFPBRC_BAD_TABLE_ID              = 9  /* Specified table-id invalid or does not* exist. */
	OFPBRC_IS_SLAVE                  = 10 /* Denied because controller is slave. */
	OFPBRC_BAD_PORT                  = 11 /* Invalid port. */
	OFPBRC_BAD_PACKET                = 12 /* Invalid packet in packet-out. */
	OFPBRC_MULTIPART_BUFFER_OVERFLOW = 13 /* ofp_multipart_requestoverflowed the assigned buffer. */
)

const (
	OFPBAC_BAD_TYPE           = 0  /* Unknown action type. */
	OFPBAC_BAD_LEN            = 1  /* Length problem in actions. */
	OFPBAC_BAD_EXPERIMENTER   = 2  /* Unknown experimenter id specified. */
	OFPBAC_BAD_EXP_TYPE       = 3  /* Unknown action for experimenter id. */
	OFPBAC_BAD_OUT_PORT       = 4  /* Problem validating output port. */
	OFPBAC_BAD_ARGUMENT       = 5  /* Bad action argument. */
	OFPBAC_EPERM              = 6  /* Permissions error. */
	OFPBAC_TOO_MANY           = 7  /* Can't handle this many actions. */
	OFPBAC_BAD_QUEUE          = 8  /* Problem validating output queue. */
	OFPBAC_BAD_OUT_GROUP      = 9  /* Invalid group id in forward action. */
	OFPBAC_MATCH_INCONSISTENT = 10 /* Action can't apply for this match,or Set-Field missing prerequisite. */
	OFPBAC_UNSUPPORTED_ORDER  = 11 /* Action order is unsupported for theaction list in an Apply-Actions instruction */
	OFPBAC_BAD_TAG            = 12 /* Actions uses an unsupportedtag/encap. */
	OFPBAC_BAD_SET_TYPE       = 13 /* Unsupported type in SET_FIELD action. */
	OFPBAC_BAD_SET_LEN        = 14 /* Length problem in SET_FIELD action. */
	OFPBAC_BAD_SET_ARGUMENT   = 15 /* Bad argument in SET_FIELD action. */
)

const (
	OFPBIC_UNKNOWN_INST        = 0 /* Unknown instruction. */
	OFPBIC_UNSUP_INST          = 1 /* Switch or table does not support theinstruction. */
	OFPBIC_BAD_TABLE_ID        = 2 /* Invalid Table-ID specified. */
	OFPBIC_UNSUP_METADATA      = 3 /* Metadata value unsupported by datapath. */
	OFPBIC_UNSUP_METADATA_MASK = 4 /* Metadata mask value unsupported bydatapath. */
	OFPBIC_BAD_EXPERIMENTER    = 5 /* Unknown experimenter id specified. */
	OFPBIC_BAD_EXP_TYPE        = 6 /* Unknown instruction for experimenter id. */
	OFPBIC_BAD_LEN             = 7 /* Length problem in instructions. */
	OFPBIC_EPERM               = 8 /* Permissions error. */
)

const (
	OFPBMC_BAD_TYPE         = 0  /* Unsupported match type specified by thematch */
	OFPBMC_BAD_LEN          = 1  /* Length problem in match. */
	OFPBMC_BAD_TAG          = 2  /* Match uses an unsupported tag/encap. */
	OFPBMC_BAD_DL_ADDR_MASK = 3  /* Unsupported datalink addr mask - switchdoes not support arbitrary datalinkaddress mask. */
	OFPBMC_BAD_NW_ADDR_MASK = 4  /* Unsupported network addr mask - switchdoes not support arbitrary networkaddress mask. */
	OFPBMC_BAD_WILDCARDS    = 5  /* Unsupported combination of fields maskedor omitted in the match. */
	OFPBMC_BAD_FIELD        = 6  /* Unsupported field type in the match. */
	OFPBMC_BAD_VALUE        = 7  /* Unsupported value in a match field. */
	OFPBMC_BAD_MASK         = 8  /* Unsupported mask specified in the match,field is not dl-address or nw-address. */
	OFPBMC_BAD_PREREQ       = 9  /* A prerequisite was not met. */
	OFPBMC_DUP_FIELD        = 10 /* A field type was duplicated. */
	OFPBMC_EPERM            = 11 /* Permissions error. */
)

const (
	OFPFMFC_UNKNOWN      = 0 /* Unspecified error. */
	OFPFMFC_TABLE_FULL   = 1 /* Flow not added because table was full. */
	OFPFMFC_BAD_TABLE_ID = 2 /* Table does not exist */
	OFPFMFC_OVERLAP      = 3 /* Attempted to add overlapping flow withCHECK_OVERLAP flag set. */
	OFPFMFC_EPERM        = 4 /* Permissions error. */
	OFPFMFC_BAD_TIMEOUT  = 5 /* Flow not added because of unsupportedidle/hard timeout. */
	OFPFMFC_BAD_COMMAND  = 6 /* Unsupported or unknown command. */
	OFPFMFC_BAD_FLAGS    = 7 /* Unsupported or unknown flags. */
)

const (
	OFPGMFC_GROUP_EXISTS         = 0  /* Group not added because a group ADDattempted to replace analready-present group. */
	OFPGMFC_INVALID_GROUP        = 1  /* Group not added because Groupspecified is invalid. */
	OFPGMFC_WEIGHT_UNSUPPORTED   = 2  /* Switch does not support unequal loadsharing with select groups. */
	OFPGMFC_OUT_OF_GROUPS        = 3  /* The group table is full. */
	OFPGMFC_OUT_OF_BUCKETS       = 4  /* The maximum number of action bucketsfor a group has been exceeded. */
	OFPGMFC_CHAINING_UNSUPPORTED = 5  /* Switch does not support groups thatforward to groups. */
	OFPGMFC_WATCH_UNSUPPORTED    = 6  /* This group cannot watch the watch_portor watch_group specified. */
	OFPGMFC_LOOP                 = 7  /* Group entry would cause a loop. */
	OFPGMFC_UNKNOWN_GROUP        = 8  /* Group not modified because a groupMODIFY attempted to modify anon-existent group. */
	OFPGMFC_CHAINED_GROUP        = 9  /* Group not deleted because anothergroup is forwarding to it. */
	OFPGMFC_BAD_TYPE             = 10 /* Unsupported or unknown group type. */
	OFPGMFC_BAD_COMMAND          = 11 /* Unsupported or unknown command. */
	OFPGMFC_BAD_BUCKET           = 12 /* Error in bucket. */
	OFPGMFC_BAD_WATCH            = 13 /* Error in watch port/group. */
	OFPGMFC_EPERM                = 14 /* Permissions error. */
)

const (
	OFPPMFC_BAD_PORT      = 0 /* Specified port number does not exist. */
	OFPPMFC_BAD_HW_ADDR   = 1 /* Specified hardware address does not* match the port number. */
	OFPPMFC_BAD_CONFIG    = 2 /* Specified config is invalid. */
	OFPPMFC_BAD_ADVERTISE = 3 /* Specified advertise is invalid. */
	OFPPMFC_EPERM         = 4 /* Permissions error. */
)

const (
	OFPTMFC_BAD_TABLE  = 0 /* Specified table does not exist. */
	OFPTMFC_BAD_CONFIG = 1 /* Specified config is invalid. */
	OFPTMFC_EPERM      = 2 /* Permissions error. */
)

const (
	OFPQOFC_BAD_PORT  = 0 /* Invalid port (or port does not exist). */
	OFPQOFC_BAD_QUEUE = 1 /* Queue does not exist. */
	OFPQOFC_EPERM     = 2 /* Permissions error. */
)

const (
	OFPSCFC_BAD_FLAGS = 0 /* Specified flags is invalid. */
	OFPSCFC_BAD_LEN   = 1 /* Specified len is invalid. */
	OFPQCFC_EPERM     = 2 /* Permissions error. */
)

const (
	OFPRRFC_STALE    = 0 /* Stale Message: old generation_id. */
	OFPRRFC_UNSUP    = 1 /* Controller role change unsupported. */
	OFPRRFC_BAD_ROLE = 2 /* Invalid role. */
)

const (
	OFPMMFC_UNKNOWN        = 0  /* Unspecified error. */
	OFPMMFC_METER_EXISTS   = 1  /* Meter not added because a Meter ADD* attempted to replace an existing Meter. */
	OFPMMFC_INVALID_METER  = 2  /* Meter not added because Meter specified* is invalid. */
	OFPMMFC_UNKNOWN_METER  = 3  /* Meter not modified because a MeterMODIFY attempted to modify a non-existentMeter. */
	OFPMMFC_BAD_COMMAND    = 4  /* Unsupported or unknown command. */
	OFPMMFC_BAD_FLAGS      = 5  /* Flag configuration unsupported. */
	OFPMMFC_BAD_RATE       = 6  /* Rate unsupported. */
	OFPMMFC_BAD_BURST      = 7  /* Burst size unsupported. */
	OFPMMFC_BAD_BAND       = 8  /* Band unsupported. */
	OFPMMFC_BAD_BAND_VALUE = 9  /* Band value unsupported. */
	OFPMMFC_OUT_OF_METERS  = 10 /* No more meters available. */
	OFPMMFC_OUT_OF_BANDS   = 11 /* The maximum number of properties* for a meter has been exceeded. */
)

const (
	OFPTFFC_BAD_TABLE    = 0 /* Specified table does not exist. */
	OFPTFFC_BAD_METADATA = 1 /* Invalid metadata mask. */
	OFPTFFC_BAD_TYPE     = 2 /* Unknown property type. */
	OFPTFFC_BAD_LEN      = 3 /* Length problem in properties. */
	OFPTFFC_BAD_ARGUMENT = 4 /* Unsupported property value. */
	OFPTFFC_EPERM        = 5 /* Permissions error. */
)

const (
	OFPFW_IN_PORT  = 1 << 0 /* Switch input port. */
	OFPFW_DL_VLAN  = 1 << 1 /* VLAN. */
	OFPFW_DL_SRC   = 1 << 2 /* Ethernet source address. */
	OFPFW_DL_DST   = 1 << 3 /* Ethernet destination address. */
	OFPFW_DL_TYPE  = 1 << 4 /* Ethernet frame type. */
	OFPFW_NW_PROTO = 1 << 5 /* IP protocol. */
	OFPFW_TP_SRC   = 1 << 6 /* TCP/UDP source port. */
	OFPFW_TP_DST   = 1 << 7 /* TCP/UDP destination port. */

	/* IP source address wildcard bit count.  0 is exact match, 1 ignores the* LSB, 2 ignores the 2 least-significant bits, ..., 32 and higher wildcard* the entire field.  This is the *opposite* of the usual convention where* e.g. /24 indicates that 8 bits (not 24 bits) are wildcarded. */
	OFPFW_NW_SRC_SHIFT = 8
	OFPFW_NW_SRC_BITS  = 6
	OFPFW_NW_SRC_MASK  = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT
	OFPFW_NW_SRC_ALL   = 32 << OFPFW_NW_SRC_SHIFT

	/* IP destination address wildcard bit count.  Same format as source. */
	OFPFW_NW_DST_SHIFT = 14
	OFPFW_NW_DST_BITS  = 6
	OFPFW_NW_DST_MASK  = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT
	OFPFW_NW_DST_ALL   = 32 << OFPFW_NW_DST_SHIFT

	/* Wildcard all fields. */
	OFPFW_ALL = ((1 << 20) - 1)
)

const (
	OFPER_IDLE_TIMEOUT = 0 /* Flow idle time exceeded idle_timeout. */
	OFPER_HARD_TIMEOUT = 1 /* Time exceeded hard_timeout. */
)

type OFPv14Message interface {
	SerializeTo([]byte)
	DecodeFromBytes([]byte) error
}

// Openflow layer struct
type OFPv14 struct {
	BaseLayer
	Version uint8
	Type    uint8
	Length  uint16
	Xid     uint32
	Message OFPv14Message
}

type OFPv14MsgHelloElement struct {
	Type    uint16
	Length  uint16
	Payload []byte
}

type OFPv14MsgHello struct {
	Elements []*OFPv14MsgHelloElement
}

func (m *OFPv14MsgHello) DecodeFromBytes(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid message type")
	}
	i := uint16(0)
	for {
		el := OFPv14MsgHelloElement{}
		el.Type = binary.BigEndian.Uint16(data[i : i+2])
		el.Length = binary.BigEndian.Uint16(data[i+2 : i+4])
		//		switch el.Type {
		//		case 0x01:
		el.Payload = data[i+4 : i+el.Length]
		//		default:
		//			return errors.New("invalid message type")
		//		}
		m.Elements = append(m.Elements, &el)
		i += el.Length
		if i >= uint16(len(data)) {
			break
		}
	}
	return nil
}

func (m *OFPv14MsgHello) SerializeTo(data []byte) {
	i := uint16(0)
	for _, el := range m.Elements {
		binary.BigEndian.PutUint16(data[i:], uint16(el.Type))
		binary.BigEndian.PutUint16(data[i+2:], uint16(el.Length))
		copy(data[i+4:], el.Payload)
		i += 4 + el.Length
	}
}

//func (m *OFPv14MsgHello) String() string {
//	return fmt.Sprintf("%v", m.Elements)
//}

func newOFPv14Message(otype uint8, data []byte) OFPv14Message {
	var msg OFPv14Message
	switch otype {
	case OFPv14TypeHello:
		msg = &OFPv14MsgHello{}
		msg.DecodeFromBytes(data)
		fmt.Fprintf(os.Stderr, "%#+v\n", msg.(*OFPv14MsgHello).Elements)
	}
	return msg
}

func (o *OFPv14) LayerType() gopacket.LayerType { return LayerTypeOFPv14 }

func (o *OFPv14) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	o.Version = data[0]
	o.Type = data[1]
	o.Length = binary.BigEndian.Uint16(data[2:4])
	o.Xid = binary.BigEndian.Uint32(data[4:8])
	o.BaseLayer = BaseLayer{Contents: data}
	o.Message = newOFPv14Message(o.Type, data[8:])
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (o *OFPv14) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	bytes[0] = o.Version
	bytes[1] = o.Type
	if opts.FixLengths {
		o.Length = uint16(len(payload)) + 8
	}
	binary.BigEndian.PutUint16(bytes[2:], uint16(o.Length))
	binary.BigEndian.PutUint32(bytes[4:], uint32(o.Xid))
	o.Message.SerializeTo(bytes)
	return nil
}

func (o *OFPv14) CanDecode() gopacket.LayerClass {
	return LayerTypeOFPv14
}

func (o *OFPv14) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (o *OFPv14) Payload() []byte {
	return nil
}

func decodeOFPv14(data []byte, p gopacket.PacketBuilder) error {
	ofp := &OFPv14{}
	err := ofp.DecodeFromBytes(data, p)
	p.AddLayer(ofp)
	if err != nil {
		return err
	}
	return p.NextDecoder(ofp.NextLayerType())
}
