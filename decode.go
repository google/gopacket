// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type LayerType int

const (
	TYPE_RAW            LayerType = iota // Contains raw bytes
	TYPE_DECODE_FAILURE                  // We were unable to decode this layer
	TYPE_ETHERNET
	TYPE_IP4
	TYPE_IP6
	TYPE_TCP
	TYPE_UDP
	TYPE_ICMP
	TYPE_DOT1Q
	TYPE_ARP
)

type Layer interface {
	LayerType() LayerType
}

type Payload struct {
	Data []byte
}

func (p *Payload) LayerType() LayerType { return TYPE_RAW }
func (p *Payload) Payload() []byte      { return p.Data }

// An address

type Address interface {
	Raw() []byte
	String() string
}
type MacAddress []byte

func (a MacAddress) Raw() []byte    { return a }
func (a MacAddress) String() string { return string(a) }

type IPv4Address []byte

func (a IPv4Address) Raw() []byte    { return a }
func (a IPv4Address) String() string { return string(a) }

type IPv6Address []byte

func (a IPv6Address) Raw() []byte    { return a }
func (a IPv6Address) String() string { return string(a) }

// These layers correspond to Internet Protocol Suite (TCP/IP) layers, and their
// corresponding OSI layers, as best as possible.

type LinkLayer interface {
	Layer
	SrcLinkAddr() Address
	DstLinkAddr() Address
}
type NetworkLayer interface {
	Layer
	SrcNetAddr() Address
	DstNetAddr() Address
}
type TransportLayer interface {
	Layer
	// SrcAppAddr() Address
	// DstAppAddr() Address
}
type ApplicationLayer interface {
	Layer
	Payload() []byte
}

type LinkType int

type Packet interface {
	// Returns all data associated with this packet
	Data() []byte
	// Returns all layers in this packet, computing them as necessary
	Layers() []Layer
	// Returns the first layer in this packet of the given type, or nil
	Layer(LayerType) Layer
	// Returns the data layer type
	LinkType() LinkType
	// Printable
	String() string
	// Accessors to specific commonly-available layers, return nil if the layer
	// doesn't exist.
	LinkLayer() LinkLayer
	NetworkLayer() NetworkLayer
	TransportLayer() TransportLayer
	ApplicationLayer() ApplicationLayer
}

type specificLayers struct {
	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
}

func (s *specificLayers) LinkLayer() LinkLayer {
	return s.link
}
func (s *specificLayers) NetworkLayer() NetworkLayer {
	return s.network
}
func (s *specificLayers) TransportLayer() TransportLayer {
	return s.transport
}
func (s *specificLayers) ApplicationLayer() ApplicationLayer {
	return s.application
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte
	// encoded contains all the packet data we have yet to decode
	encoded []byte
	// layers contains each layer we've already decoded
	layers []Layer
	// linkType contains the link type for the underlying transport
	linkType LinkType
	// decoder is the next decoder we should call (lazily)
	decoder decoder

	// The set of specific layers we have pointers to.
	specificLayers
}

func (p *packet) Data() []byte {
	return p.data
}
func (p *packet) LinkType() LinkType {
	return p.linkType
}

func (p *packet) appendLayer(l Layer) {
	p.layers = append(p.layers, l)
}

type decodeResult struct {
	// An error encountered in this decode call.  If this is set, everything else
	// will be ignored.
	err error
	// The layer we've created with this decode call
	layer Layer
	// The next decoder to call
	next decoder
	// The bytes that are left to be decoded
	left []byte
}

// decoder decodes the next layer in a packet.  It returns a set of useful
// information, which is used by the packet decoding logic to update packet
// state.  Optionally, the decode function may set any of the specificLayer
// pointers to point to the new layer it has created.
type decoder interface {
	decode([]byte, *specificLayers) decodeResult
}
type decoderFunc func([]byte, *specificLayers) decodeResult

func (d decoderFunc) decode(data []byte, s *specificLayers) decodeResult {
	return d(data, s)
}

func newPacket(data []byte, d decoder) Packet {
	return &packet{
		data:    data,
		encoded: data,
		decoder: d,
	}
}

// decodeNextLayer decodes the next layer, updates the payload, and returns it.
// Returns nil if there are no more layers to decode.
func (p *packet) decodeNextLayer() (out Layer) {
	if p.decoder == nil || len(p.encoded) == 0 {
		return nil
	}
	result := p.decoder.decode(p.encoded, &p.specificLayers)
	if result.err != nil {
		p.encoded = nil
		p.decoder = nil
		out = &DecodeFailure{Data: p.encoded, Error: result.err}
	} else {
		p.encoded = result.left
		p.decoder = result.next
		out = result.layer
	}
	p.appendLayer(out)
	return out
}

func (p *packet) Layers() []Layer {
	for p.decodeNextLayer() != nil {
	}
	return p.layers
}

func (p *packet) Layer(t LayerType) Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	for l := p.decodeNextLayer(); l != nil; l = p.decodeNextLayer() {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}

func (p *packet) String() string {
	layers := []string{}
	for l := range p.Layers() {
		layers = append(layers, fmt.Sprintf("%#v", l))
	}
	return fmt.Sprintf("PACKET [%s]", strings.Join(layers, ", "))
}

const (
	ERRBUF_SIZE = 256

	// According to pcap-linktype(7).
	LINKTYPE_NULL             LinkType = 0
	LINKTYPE_ETHERNET         LinkType = 1
	LINKTYPE_TOKEN_RING       LinkType = 6
	LINKTYPE_ARCNET           LinkType = 7
	LINKTYPE_SLIP             LinkType = 8
	LINKTYPE_PPP              LinkType = 9
	LINKTYPE_FDDI             LinkType = 10
	LINKTYPE_ATM_RFC1483      LinkType = 100
	LINKTYPE_RAW              LinkType = 101
	LINKTYPE_PPP_HDLC         LinkType = 50
	LINKTYPE_PPP_ETHER        LinkType = 51
	LINKTYPE_C_HDLC           LinkType = 104
	LINKTYPE_IEEE802_11       LinkType = 105
	LINKTYPE_FRELAY           LinkType = 107
	LINKTYPE_LOOP             LinkType = 108
	LINKTYPE_LINUX_SLL        LinkType = 113
	LINKTYPE_LTALK            LinkType = 104
	LINKTYPE_PFLOG            LinkType = 117
	LINKTYPE_PRISM_HEADER     LinkType = 119
	LINKTYPE_IP_OVER_FC       LinkType = 122
	LINKTYPE_SUNATM           LinkType = 123
	LINKTYPE_IEEE802_11_RADIO LinkType = 127
	LINKTYPE_ARCNET_LINUX     LinkType = 129
	LINKTYPE_LINUX_IRDA       LinkType = 144
	LINKTYPE_LINUX_LAPD       LinkType = 177
)

type EthernetType uint16

const (
	ETHER_IP4   EthernetType = 0x0800
	ETHER_ARP   EthernetType = 0x0806
	ETHER_IP6   EthernetType = 0x86DD
	ETHER_DOT1Q EthernetType = 0x8100
)

type IpProtocol uint8

const (
	IP_ICMP IpProtocol = 1
	IP_TCP  IpProtocol = 6
	IP_UDP  IpProtocol = 17
)

func (l LinkType) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch l {
	case LINKTYPE_ETHERNET:
		return decodeEthernet(data, s)
	}
	out.err = errors.New("Unsupported link-layer type")
	return
}

func (l LinkType) Decode(data []byte) Packet {
	return newPacket(data, l)
}

type DecodeFailure struct {
	Data  []byte
	Error error
}

func (e *DecodeFailure) Payload() []byte {
	return e.Data
}

func (e *DecodeFailure) LayerType() LayerType {
	return TYPE_DECODE_FAILURE
}

type Ethernet struct {
	SrcMac, DstMac MacAddress
	EthernetType   EthernetType
}

func (e *Ethernet) LayerType() LayerType { return TYPE_ETHERNET }

func (e *Ethernet) SrcLinkAddr() Address {
	return e.SrcMac
}

func (e *Ethernet) DstLinkAddr() Address {
	return e.DstMac
}

var decodeUnknown decoderFunc = func(data []byte, _ *specificLayers) (out decodeResult) {
	out.err = errors.New("Link type not currently supported")
	return
}

// Decode decodes the headers of a Packet.
var decodeEthernet decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	if len(data) < 14 {
		out.err = errors.New("Ethernet packet too small")
		return
	}
	eth := &Ethernet{
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		DstMac:       MacAddress(data[0:6]),
		SrcMac:       MacAddress(data[6:12]),
	}
	out.layer = eth
	out.left = data[14:]
	out.next = eth.EthernetType
	s.link = eth
	return
}

var decodePayload decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	payload := &Payload{Data: data}
	out.layer = payload
	s.application = payload
	return
}

func (e EthernetType) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch e {
	case ETHER_IP4:
		return decodeIp4(data, s)
	case ETHER_IP6:
		return decodeIp6(data, s)
	case ETHER_ARP:
		return decodeArp(data, s)
	case ETHER_DOT1Q:
		return decodeDot1Q(data, s)
	}
	out.err = errors.New("Unsupported ethernet type")
	return
}

func (e EthernetType) Decode(data []byte) Packet {
	return newPacket(data, e)
}

// Arphdr is a ARP packet header.
type ARP struct {
	AddrType          LinkType
	Protocol          EthernetType
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DstHwAddress      []byte
	DstProtAddress    []byte
}

func (arp *ARP) String() (s string) {
	switch arp.Operation {
	case 1:
		s = "ARP request"
	case 2:
		s = "ARP Reply"
	}
	return
}

func (arp *ARP) LayerType() LayerType {
	return TYPE_ARP
}

var decodeArp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	arp := &ARP{
		AddrType:        LinkType(binary.BigEndian.Uint16(data[0:2])),
		Protocol:        EthernetType(binary.BigEndian.Uint16(data[2:4])),
		HwAddressSize:   data[4],
		ProtAddressSize: data[5],
		Operation:       binary.BigEndian.Uint16(data[6:8]),
	}
	arp.SourceHwAddress = data[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = data[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstHwAddress = data[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstProtAddress = data[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	out.layer = arp
	out.left = data[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
	out.next = decodePayload
	return
}

// IPv4 is the header of an IP packet.
type IPv4 struct {
	Version    uint8
	Ihl        uint8
	Tos        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	Ttl        uint8
	Protocol   IpProtocol
	Checksum   uint16
	SrcIp      IPv4Address
	DstIp      IPv4Address
}

func (i *IPv4) LayerType() LayerType { return TYPE_IP4 }
func (i *IPv4) SrcNetAddr() Address  { return i.SrcIp }
func (i *IPv4) DstNetAddr() Address  { return i.DstIp }

var decodeIp4 decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	ip := &IPv4{
		Version:    uint8(data[0]) >> 4,
		Ihl:        uint8(data[0]) & 0x0F,
		Tos:        data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Id:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsfrags >> 13),
		FragOffset: flagsfrags & 0x1FFF,
		Ttl:        data[8],
		Protocol:   IpProtocol(data[9]),
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIp:      data[12:16],
		DstIp:      data[16:20],
	}
	pEnd := int(ip.Length)
	if pEnd > len(data) {
		pEnd = len(data)
	}
	out.left = data[ip.Ihl*4 : pEnd]
	out.layer = ip
	out.next = ip.Protocol
	s.network = ip
	return
}

func (ip IpProtocol) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch ip {
	case IP_TCP:
		return decodeTcp(data, s)
	case IP_UDP:
		return decodeUdp(data, s)
	case IP_ICMP:
		return decodeIcmp(data, s)
	}
	out.err = errors.New("Unsupported IP protocol")
	return
}

func (ip IpProtocol) Decode(data []byte) Packet {
	return newPacket(data, ip)
}

type Dot1Q struct {
	Priority       uint8
	DropEligible   bool
	VlanIdentifier uint16
	Type           IpProtocol
}

func (d *Dot1Q) LayerType() LayerType { return TYPE_DOT1Q }

func (v *Dot1Q) String() {
	fmt.Sprintf("VLAN Prioity:%d Drop:%v Tag:%d", v.Priority, v.DropEligible, v.VlanIdentifier)
}

var decodeDot1Q decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	d := &Dot1Q{
		Priority:       (data[2] & 0xE0) >> 13,
		DropEligible:   data[2]&0x10 != 0,
		VlanIdentifier: binary.BigEndian.Uint16(data[:2]) & 0x0FFF,
		Type:           IpProtocol(binary.BigEndian.Uint16(data[2:4])),
	}
	out.layer = d
	out.next = d.Type
	out.left = data[4:]
	return
}

type TCP struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      TcpFlag
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

func (t *TCP) LayerType() LayerType { return TYPE_TCP }

type TcpFlag uint16

const (
	TCP_FIN TcpFlag = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
	TCP_ECE
	TCP_CWR
	TCP_NS
)

var decodeTcp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	tcp := &TCP{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] & 0xF0) >> 4,
		Flags:      TcpFlag(binary.BigEndian.Uint16(data[12:14]) & 0x1FF),
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}
	out.left = data[tcp.DataOffset*4:]
	out.layer = tcp
	out.next = decodePayload
	s.transport = tcp
	return
}

func (f TcpFlag) String() string {
	var sflags []string
	if 0 != (f & TCP_SYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (f & TCP_FIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (f & TCP_ACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (f & TCP_PSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (f & TCP_RST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (f & TCP_URG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (f & TCP_NS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (f & TCP_CWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (f & TCP_ECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, " "))
}

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func (u *UDP) LayerType() LayerType { return TYPE_UDP }

var decodeUdp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	out.layer = &UDP{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}
	out.next = decodePayload
	out.left = data[8:]
	return
}

type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
	Data     []byte
}

func (i *ICMP) LayerType() LayerType { return TYPE_ICMP }

var decodeIcmp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	out.layer = &ICMP{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		Id:       binary.BigEndian.Uint16(data[4:6]),
		Seq:      binary.BigEndian.Uint16(data[6:8]),
	}
	out.left = data[8:]
	out.next = decodePayload
	return
}

func (icmp *ICMP) TypeString() (result string) {
	switch icmp.Type {
	case 0:
		result = fmt.Sprintf("Echo reply seq=%d", icmp.Seq)
	case 3:
		switch icmp.Code {
		case 0:
			result = "Network unreachable"
		case 1:
			result = "Host unreachable"
		case 2:
			result = "Protocol unreachable"
		case 3:
			result = "Port unreachable"
		default:
			result = "Destination unreachable"
		}
	case 8:
		result = fmt.Sprintf("Echo request seq=%d", icmp.Seq)
	case 30:
		result = "Traceroute"
	}
	return
}

type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	Version      uint8       // 4 bits
	TrafficClass uint8       // 8 bits
	FlowLabel    uint32      // 20 bits
	Length       uint16      // 16 bits
	NextHeader   IpProtocol  // 8 bits, same as Protocol in Iphdr
	HopLimit     uint8       // 8 bits
	SrcIp        IPv6Address // 16 bytes
	DstIp        IPv6Address // 16 bytes
}

func (i *IPv6) LayerType() LayerType { return TYPE_IP6 }
func (i *IPv6) SrcNetAddr() Address  { return i.SrcIp }
func (i *IPv6) DstNetAddr() Address  { return i.DstIp }

var decodeIp6 decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	ip6 := &IPv6{
		Version:      uint8(data[0]) >> 4,
		TrafficClass: uint8((binary.BigEndian.Uint16(data[0:2]) >> 4) & 0x00FF),
		FlowLabel:    binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF,
		Length:       binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   IpProtocol(data[6]),
		HopLimit:     data[7],
		SrcIp:        data[8:24],
		DstIp:        data[24:40],
	}
	out.layer = ip6
	out.left = data[40:]
	out.next = ip6.NextHeader
	s.network = ip6
	return
}
