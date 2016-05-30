// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

var opTypes = [3]string{
	0: "UNSPEC",
	1: "REQUEST",
	2: "RESPONSE",
}

type DHCPOperation uint8

const (
	DHCP_MSG_UNSPEC DHCPOperation = iota
	DHCP_MSG_DISCOVER
	DHCP_MSG_OFFER
	DHCP_MSG_REQUEST
	DHCP_MSG_DECLINE
	DHCP_MSG_ACK
	DHCP_MSG_NAK
	DHCP_MSG_RELEASE
	DHCP_MSG_INFORM
)

var messageTypes = map[DHCPOperation]string{
	0: "UNSPEC",
	1: "DISCOVER",
	2: "OFFER",
	3: "REQUEST",
	4: "DECLINE",
	5: "ACK",
	6: "NAK",
	7: "RELEASE",
	8: "INFORM",
}

func (o DHCPOperation) String() string {
	return opTypes[o]
}

const (
	_ = iota
	DHCP_MSG_REQ
	DHCP_MSG_RES
)

//RFC 2131 "magic cooke"
var dhcpMagic uint32 = 0x63825363

type DHCPv4 struct {
	BaseLayer
	Operation    DHCPOperation
	HardwareType byte
	HardwareLen  uint8
	HardwareOpts uint8
	Xid          uint32
	Secs         uint16
	Flags        uint16
	ClientIP     net.IP
	YourIP       net.IP
	ServerIP     net.IP
	GatewayIP    net.IP
	ClientHWAddr net.HardwareAddr
	ServerName   []byte
	File         []byte
	Options      []DHCPOption
}

const (
	DHCP_OPT_REQUEST_IP     byte = iota + 50 // 0x32, 4, net.IP
	DHCP_OPT_LEASE_TIME                      // 0x33, 4, uint32
	DHCP_OPT_EXT_OPTS                        // 0x34, 1, 1/2/3
	DHCP_OPT_MESSAGE_TYPE                    // 0x35, 1, 1-7
	DHCP_OPT_SERVER_ID                       // 0x36, 4, net.IP
	DHCP_OPT_PARAMS_REQUEST                  // 0x37, n, []byte
	DHCP_OPT_MESSAGE                         // 0x38, n, string
	DHCP_OPT_MAX_DHCP_SIZE                   // 0x39, 2, uint16
	DHCP_OPT_T1                              // 0x3a, 4, uint32
	DHCP_OPT_T2                              // 0x3b, 4, uint32
	DHCP_OPT_CLASS_ID                        // 0x3c, n, []byte
	DHCP_OPT_CLIENT_ID                       // 0x3d, n >=  2, []byte

)

const (
	DHCP_HW_TYPE_ETHERNET byte   = 0x01
	DHCP_FLAG_BROADCAST   uint16 = 0x80
)

// LayerType returns gopacket.LayerTypeDHCPv4
func (d *DHCPv4) LayerType() gopacket.LayerType { return LayerTypeDHCPv4 }

func (dhcp *DHCPv4) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	dhcp.Operation = DHCPOperation(data[0])
	dhcp.HardwareType = data[1]
	dhcp.HardwareLen = data[2]
	dhcp.HardwareOpts = data[3]
	dhcp.Xid = binary.BigEndian.Uint32(data[4:8])
	dhcp.Secs = binary.BigEndian.Uint16(data[8:10])
	dhcp.Flags = binary.BigEndian.Uint16(data[10:12])
	dhcp.ClientIP = net.IP(data[12:16])
	dhcp.YourIP = net.IP(data[16:20])
	dhcp.ServerIP = net.IP(data[20:24])
	dhcp.GatewayIP = net.IP(data[24:28])
	dhcp.ClientHWAddr = net.HardwareAddr(data[28 : 28+dhcp.HardwareLen])
	dhcp.ServerName = data[44:108]
	dhcp.File = data[108:236]
	if binary.BigEndian.Uint32(data[236:240]) != dhcpMagic {
		return errors.New("Bad DHCP header")
	}

	if len(data) <= 240 {
		// DHCP Packet could have no option (??)
		return nil
	}

	options := make([]byte, len(data)-240)
	if binary.Read(bytes.NewBuffer(data[240:]), binary.BigEndian, &options) != nil {
		return errors.New("failed to unmarshal options")
	}

	stop := len(options)
	start := 0
	for start < stop {
		o := DHCPOption{}
		if err := o.Unmarshal(options[start:]); err != nil {
			return err
		}
		if o.Type == DHCP_OPT_END {
			break
		}
		dhcp.Options = append(dhcp.Options, o)
		start += int(o.Length) + 2
	}
	return nil
}

func (dhcp *DHCPv4) Len() uint16 {
	n := uint16(240)
	for _, o := range dhcp.Options {
		n += uint16(o.Length) + 2
	}
	n += 1 // for opt end
	return n
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (dhcp *DHCPv4) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(dhcp.Len())
	if plen < 300 {
		plen = 300
	}

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	data[0] = byte(dhcp.Operation)
	data[1] = dhcp.HardwareType
	data[2] = dhcp.HardwareLen
	data[3] = dhcp.HardwareOpts
	binary.BigEndian.PutUint32(data[4:8], dhcp.Xid)
	binary.BigEndian.PutUint16(data[8:10], dhcp.Secs)
	binary.BigEndian.PutUint16(data[10:12], dhcp.Flags)
	copy(data[12:16], dhcp.ClientIP.To4())
	copy(data[16:20], dhcp.YourIP.To4())
	copy(data[20:24], dhcp.ServerIP.To4())
	copy(data[24:28], dhcp.GatewayIP.To4())
	copy(data[28:44], dhcp.ClientHWAddr)
	copy(data[44:108], dhcp.ServerName)
	copy(data[108:236], dhcp.File)
	binary.BigEndian.PutUint32(data[236:240], dhcpMagic)

	if len(dhcp.Options) > 0 {
		options := make([]byte, plen-240)
		start := 0
		for _, o := range dhcp.Options {
			buffer, err := o.Marshal()
			if err != nil {
				return err
			}
			copy(options[start:], buffer)
			start += len(buffer)
		}
		optend := NewDHCPOption(DHCP_OPT_END, nil)
		buffer, err := (&optend).Marshal()
		if err != nil {
			return err
		}
		copy(options[start:], buffer)
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.BigEndian, options); err != nil {
			return err
		}
		copy(data[240:], buf.Bytes())
	}

	return nil
}

func (dhcp *DHCPv4) CanDecode() gopacket.LayerClass {
	return LayerTypeDHCPv4
}

func (dhcp *DHCPv4) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDHCPv4(data []byte, p gopacket.PacketBuilder) error {
	dhcp := &DHCPv4{}
	err := dhcp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(dhcp)
	return p.NextDecoder(gopacket.LayerTypePayload)
}

const (
	DHCP_OPT_PAD                      byte = iota
	DHCP_OPT_SUBNET_MASK                          // 0x01, 4, net.IP
	DHCP_OPT_TIME_OFFSET                          // 0x02, 4, int32 (signed seconds from UTC)
	DHCP_OPT_DEFAULT_GATEWAY                      // 0x03, n*4, [n]net.IP
	DHCP_OPT_TIME_SERVER                          // 0x04, n*4, [n]net.IP
	DHCP_OPT_NAME_SERVER                          // 0x05, n*4, [n]net.IP
	DHCP_OPT_DOMAIN_NAME_SERVERS                  // 0x06, n*4, [n]net.IP
	DHCP_OPT_LOG_SERVER                           // 0x07, n*4, [n]net.IP
	DHCP_OPT_COOKIE_SERVER                        // 0x08, n*4, [n]net.IP
	DHCP_OPT_LPR_SERVER                           // 0x09, n*4, [n]net.IP
	DHCP_OPT_IMPRESS_SERVER                       // 0x0a, n*4, [n]net.IP
	DHCP_OPT_RLSERVER                             // 0x0b, n*4, [n]net.IP
	DHCP_OPT_HOST_NAME                            // 0x0c, n, string
	DHCP_OPT_BOOTFILE_SIZE                        // 0x0d, 2, uint16
	DHCP_OPT_MERIT_DUMP_FILE                      // 0x0e, >1, string
	DHCP_OPT_DOMAIN_NAME                          // 0x0f, n, string
	DHCP_OPT_SWAP_SERVER                          // 0x10, n*4, [n]net.IP
	DHCP_OPT_ROOT_PATH                            // 0x11, n, string
	DHCP_OPT_EXTENSIONS_PATH                      // 0x12, n, string
	DHCP_OPT_IP_FORWARDING                        // 0x13, 1, bool
	DHCP_OPT_SOURCE_ROUTING                       // 0x14, 1, bool
	DHCP_OPT_POLICY_FILTER                        // 0x15, 8*n, [n]{net.IP/net.IP}
	DHCP_OPT_DGRAM_MTU                            // 0x16, 2, uint16
	DHCP_OPT_DEFAULT_TTL                          // 0x17, 1, byte
	DHCP_OPT_PATH_MTU_AGING_TIMEOUT               // 0x18, 4, uint32
	DHCP_OPT_PATH_PLATEU_TABLE_OPTION             // 0x19, 2*n, []uint16
	DHCP_OPT_INTERFACE_MTU                        //0x1a, 2, uint16
	DHCP_OPT_ALL_SUBS_LOCAL                       // 0x1b, 1, bool
	DHCP_OPT_BROADCAST_ADDR                       // 0x1c, 4, net.IP
	DHCP_OPT_MASK_DISCOVERY                       // 0x1d, 1, bool
	DHCP_OPT_MASK_SUPPLIER                        // 0x1e, 1, bool
	DHCP_OPT_ROUTER_DISCOVERY                     // 0x1f, 1, bool
	DHCP_OPT_ROUTER_SOLICIT_ADDR                  // 0x20, 4, net.IP
	DHCP_OPT_STATIC_ROUTE                         // 0x21, n*8, [n]{net.IP/net.IP} -- note the 2nd is router not mask
	DHCP_OPT_ARP_TRAILERS                         // 0x22, 1, bool
	DHCP_OPT_ARP_TIMEOUT                          // 0x23, 4, uint32
	DHCP_OPT_ETHERNET_ENCAP                       // 0x24, 1, bool
	DHCP_OPT_TCP_TTL                              // 0x25,1, byte
	DHCP_OPT_TCP_KEEPALIVE_INT                    // 0x26,4, uint32
	DHCP_OPT_TCP_KEEPALIVE_GARBAGE                // 0x27,1, bool
	DHCP_OPT_NIS_DOMAIN                           // 0x28,n, string
	DHCP_OPT_NIS_SERVERS                          // 0x29,4*n,  [n]net.IP
	DHCP_OPT_NTP_SERVERS                          // 0x2a, 4*n, [n]net.IP
	DHCP_OPT_VENDOR_OPT                           // 0x2b, n, [n]byte // may be encapsulated.
	DHCP_OPT_NETBIOS_IPNS                         // 0x2c, 4*n, [n]net.IP
	DHCP_OPT_NETBIOS_DDS                          // 0x2d, 4*n, [n]net.IP
	DHCP_OPT_NETBIOS_NODE_TYPE                    // 0x2e, 1, magic byte
	DHCP_OPT_NETBIOS_SCOPE                        // 0x2f, n, string
	DHCP_OPT_X_FONT_SERVER                        // 0x30, n, string
	DHCP_OPT_X_DISPLAY_MANAGER                    // 0x31, n, string
	DHCP_OPT_SIP_SERVERS              byte = 0x78 // 0x78!, n, url
	DHCP_OPT_END                      byte = 0xff
)

var DHCPOptionTypeStrings = [256]string{
	DHCP_OPT_PAD:                      "(padding)",
	DHCP_OPT_SUBNET_MASK:              "SubnetMask",
	DHCP_OPT_TIME_OFFSET:              "TimeOffset",
	DHCP_OPT_DEFAULT_GATEWAY:          "DefaultGateway",
	DHCP_OPT_TIME_SERVER:              "rfc868", // old time server protocol, stringified to dissuade confusion w. NTP
	DHCP_OPT_NAME_SERVER:              "ien116", // obscure nameserver protocol, stringified to dissuade confusion w. DNS
	DHCP_OPT_DOMAIN_NAME_SERVERS:      "DNS",
	DHCP_OPT_LOG_SERVER:               "mitLCS", // MIT LCS server protocol, yada yada w. Syslog
	DHCP_OPT_COOKIE_SERVER:            "OPT_COOKIE_SERVER",
	DHCP_OPT_LPR_SERVER:               "OPT_LPR_SERVER",
	DHCP_OPT_IMPRESS_SERVER:           "OPT_IMPRESS_SERVER",
	DHCP_OPT_RLSERVER:                 "OPT_RLSERVER",
	DHCP_OPT_HOST_NAME:                "Hostname",
	DHCP_OPT_BOOTFILE_SIZE:            "BootfileSize",
	DHCP_OPT_MERIT_DUMP_FILE:          "OPT_MERIT_DUMP_FILE",
	DHCP_OPT_DOMAIN_NAME:              "DomainName",
	DHCP_OPT_SWAP_SERVER:              "OPT_SWAP_SERVER",
	DHCP_OPT_ROOT_PATH:                "RootPath",
	DHCP_OPT_EXTENSIONS_PATH:          "OPT_EXTENSIONS_PATH",
	DHCP_OPT_IP_FORWARDING:            "OPT_IP_FORWARDING",
	DHCP_OPT_SOURCE_ROUTING:           "OPT_SOURCE_ROUTING",
	DHCP_OPT_POLICY_FILTER:            "OPT_POLICY_FILTER",
	DHCP_OPT_DGRAM_MTU:                "OPT_DGRAM_MTU",
	DHCP_OPT_DEFAULT_TTL:              "OPT_DEFAULT_TTL",
	DHCP_OPT_PATH_MTU_AGING_TIMEOUT:   "OPT_PATH_MTU_AGING_TIMEOUT",
	DHCP_OPT_PATH_PLATEU_TABLE_OPTION: "OPT_PATH_PLATEU_TABLE_OPTION",
	DHCP_OPT_INTERFACE_MTU:            "OPT_INTERFACE_MTU",
	DHCP_OPT_ALL_SUBS_LOCAL:           "OPT_ALL_SUBS_LOCAL",
	DHCP_OPT_BROADCAST_ADDR:           "OPT_BROADCAST_ADDR",
	DHCP_OPT_MASK_DISCOVERY:           "OPT_MASK_DISCOVERY",
	DHCP_OPT_MASK_SUPPLIER:            "OPT_MASK_SUPPLIER",
	DHCP_OPT_ROUTER_DISCOVERY:         "OPT_ROUTER_DISCOVERY",
	DHCP_OPT_ROUTER_SOLICIT_ADDR:      "OPT_ROUTER_SOLICIT_ADDR",
	DHCP_OPT_STATIC_ROUTE:             "OPT_STATIC_ROUTE",
	DHCP_OPT_ARP_TRAILERS:             "OPT_ARP_TRAILERS",
	DHCP_OPT_ARP_TIMEOUT:              "OPT_ARP_TIMEOUT",
	DHCP_OPT_ETHERNET_ENCAP:           "OPT_ETHERNET_ENCAP",
	DHCP_OPT_TCP_TTL:                  "OPT_TCP_TTL",
	DHCP_OPT_TCP_KEEPALIVE_INT:        "OPT_TCP_KEEPALIVE_INT",
	DHCP_OPT_TCP_KEEPALIVE_GARBAGE:    "OPT_TCP_KEEPALIVE_GARBAGE",
	DHCP_OPT_NIS_DOMAIN:               "OPT_NIS_DOMAIN",
	DHCP_OPT_NIS_SERVERS:              "OPT_NIS_SERVERS",
	DHCP_OPT_NTP_SERVERS:              "OPT_NTP_SERVERS",
	DHCP_OPT_VENDOR_OPT:               "OPT_VENDOR_OPT",
	DHCP_OPT_NETBIOS_IPNS:             "OPT_NETBIOS_IPNS",
	DHCP_OPT_NETBIOS_DDS:              "OPT_NETBIOS_DDS",
	DHCP_OPT_NETBIOS_NODE_TYPE:        "OPT_NETBIOS_NODE_TYPE",
	DHCP_OPT_NETBIOS_SCOPE:            "OPT_NETBIOS_SCOPE",
	DHCP_OPT_X_FONT_SERVER:            "OPT_X_FONT_SERVER",
	DHCP_OPT_X_DISPLAY_MANAGER:        "OPT_X_DISPLAY_MANAGER",
	DHCP_OPT_END:                      "(end)",
	DHCP_OPT_SIP_SERVERS:              "SipServers",
	DHCP_OPT_REQUEST_IP:               "RequestIP",
	DHCP_OPT_LEASE_TIME:               "LeaseTime",
	DHCP_OPT_EXT_OPTS:                 "ExtOpts",
	DHCP_OPT_MESSAGE_TYPE:             "MessageType",
	DHCP_OPT_SERVER_ID:                "ServerID",
	DHCP_OPT_PARAMS_REQUEST:           "ParamsRequest",
	DHCP_OPT_MESSAGE:                  "Message",
	DHCP_OPT_MAX_DHCP_SIZE:            "MaxDHCPSize",
	DHCP_OPT_T1:                       "Timer1",
	DHCP_OPT_T2:                       "Timer2",
	DHCP_OPT_CLASS_ID:                 "ClassID",
	DHCP_OPT_CLIENT_ID:                "ClientID",
}

type DHCPOption struct {
	Type   uint8
	Length uint8
	Data   []byte
}

func (o DHCPOption) String() string {
	return fmt.Sprintf("Option(%v:%v)", DHCPOptionTypeStrings[o.Type], o.Data)
}

func NewDHCPOption(t uint8, data []byte) DHCPOption {
	o := DHCPOption{Type: t}
	if data != nil {
		o.Data = data
		o.Length = uint8(len(data))
	}
	return o
}

func (o *DHCPOption) Marshal() ([]byte, error) {
	var data []byte
	switch o.Type {
	case DHCP_OPT_PAD, DHCP_OPT_END:
		data = []byte{o.Type}
	default:
		if o.Length > 253 {
			return nil, errors.New("Data too long to marshal")
		}
		data = make([]byte, o.Length+2)
		data[0], data[1] = o.Type, o.Length
		copy(data[2:], o.Data)
	}
	return data, nil
}

func (o *DHCPOption) Unmarshal(data []byte) error {
	o.Type = data[0]
	switch o.Type {
	case DHCP_OPT_PAD, DHCP_OPT_END:
		o.Data = nil
	default:
		o.Length = data[1]
		if o.Length > 253 {
			return errors.New("Data too long to unmarshal")
		}
		o.Data = data[2 : 2+o.Length]
	}
	return nil
}
