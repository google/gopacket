// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
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
	Type() LayerType
}

type Payload struct {
	Data []byte
}

func (p *Payload) Type() LayerType { return TYPE_RAW }
func (p *Payload) Payload() []byte { return p.Data }

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
	SrcHostAddr() Address
	DstHostAddr() Address
}
type TransportLayer interface {
	Layer
	SrcAppAddr() Address
	DstAppAddr() Address
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

func NewPacket(data []byte, linkType LinkType) Packet {
	return &packet{
		data:     data,
		encoded:  data,
		linkType: linkType,
		decoder:  topLevelDecoders[linkType],
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
		out = &DecodeFailure{data: p.encoded, Error: result.err}
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
		if l.Type() == t {
			return l
		}
	}
	for l := p.decodeNextLayer(); l != nil; l = p.decodeNextLayer() {
		if l.Type() == t {
			return l
		}
	}
	return nil
}

func (p *packet) String() string {
	return "PACKET!!!"
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
	ETHERTYPE_IP4  EthernetType = 0x0800
	ETHERTYPE_ARP  EthernetType = 0x0806
	ETHERTYPE_IP6  EthernetType = 0x86DD
	ETHERTYPE_VLAN EthernetType = 0x8100
)

var topLevelDecoders [256]decoder

func init() {
	for i := 0; i < 256; i++ {
		topLevelDecoders[i] = decodeUnknown
	}
	topLevelDecoders[LINKTYPE_ETHERNET] = decodeEthernet
}

type DecodeFailure struct {
	data  []byte
	Error error
}

func (e *DecodeFailure) Payload() []byte {
	return e.data
}

func (e *DecodeFailure) Type() LayerType {
	return TYPE_DECODE_FAILURE
}

type Ethernet struct {
	SrcMac, DstMac MacAddress
	EthernetType   EthernetType
}

func (e *Ethernet) Type() LayerType { return TYPE_ETHERNET }

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
	out.next = eth
	s.link = eth
	return
}

var decodePayload decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	payload := &Payload{Data: data}
	out.layer = payload
	s.application = payload
	return
}

func (e *Ethernet) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch e.EthernetType {
	/*
	  case TYPE_IP:
	    return decodeIp4(data, s)
	  case TYPE_IP6:
	    return decodeIp6(data, s)
	*/
	case ETHERTYPE_ARP:
		return decodeArp(data, s)
		/*
		  case TYPE_VLAN:
		    return decodeVlan(data, s)
		*/
	}
	out.err = errors.New("Unsupported ethernet type")
	return
}

// Arphdr is a ARP packet header.
type Arp struct {
	AddrType          LinkType
	Protocol          EthernetType
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DestHwAddress     []byte
	DestProtAddress   []byte
}

func (arp *Arp) String() (s string) {
	switch arp.Operation {
	case 1:
		s = "ARP request"
	case 2:
		s = "ARP Reply"
	}
	return
}

func (arp *Arp) Type() LayerType {
	return TYPE_ARP
}

var decodeArp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	arp := &Arp{
		AddrType:        LinkType(binary.BigEndian.Uint16(data[0:2])),
		Protocol:        EthernetType(binary.BigEndian.Uint16(data[2:4])),
		HwAddressSize:   data[4],
		ProtAddressSize: data[5],
		Operation:       binary.BigEndian.Uint16(data[6:8]),
	}
	arp.SourceHwAddress = data[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = data[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestHwAddress = data[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestProtAddress = data[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	out.layer = arp
	out.left = data[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
	out.next = decodePayload
	return
}

/*
// IPadr is the header of an IP packet.
type Iphdr struct {
	Version    uint8
	Ihl        uint8
	Tos        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	Ttl        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIp      []byte
	DestIp     []byte
}

func (p *Packet) decodeIp() {
	pkt := p.Payload
	ip := new(Iphdr)

	ip.Version = uint8(pkt[0]) >> 4
	ip.Ihl = uint8(pkt[0]) & 0x0F
	ip.Tos = pkt[1]
	ip.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip.Id = binary.BigEndian.Uint16(pkt[4:6])
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.Ttl = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	ip.SrcIp = pkt[12:16]
	ip.DestIp = pkt[16:20]
	pEnd := int(ip.Length)
	if pEnd > len(pkt) {
		pEnd = len(pkt)
	}
	p.Payload = pkt[ip.Ihl*4 : pEnd]
	p.Headers = append(p.Headers, ip)
	p.IP = ip

	switch ip.Protocol {
	case IP_TCP:
		p.decodeTcp()
	case IP_UDP:
		p.decodeUdp()
	case IP_ICMP:
		p.decodeIcmp()
	case IP_INIP:
		p.decodeIp()
	}
}

func (ip *Iphdr) SrcAddr() string  { return net.IP(ip.SrcIp).String() }
func (ip *Iphdr) DestAddr() string { return net.IP(ip.DestIp).String() }
func (ip *Iphdr) Len() int         { return int(ip.Length) }

type Vlanhdr struct {
	Priority       byte
	DropEligible   bool
	VlanIdentifier int
	Type           int // Not actually part of the vlan header, but the type of the actual packet
}

func (v *Vlanhdr) String() {
	fmt.Sprintf("VLAN Prioity:%d Drop:%v Tag:%d", v.Prioity, v.DropEligible, v.VlanIdentifier)
}

func (p *Packet) decodeVlan() {
	pkt := p.Payload
	vlan := new(Vlanhdr)
	vlan.Priority = (pkt[2] & 0xE0) >> 13
	vlan.DropEligible = pkt[2]&0x10 != 0
	vlan.VlanIdentifier = int(binary.BigEndian.Uint16(pkt[:2])) & 0x0FFF
	vlan.Type = int(binary.BigEndian.Uint16(p.Payload[2:4]))
	p.Headers = append(p.Headers, vlan)
	p.Payload = p.Payload[4:]
	switch vlan.Type {
	case TYPE_IP:
		p.decodeIp()
	case TYPE_IP6:
		p.decodeIp6()
	case TYPE_ARP:
		p.decodeArp()
	}
}

type Tcphdr struct {
	SrcPort    uint16
	DestPort   uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint16
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Data       []byte
}

const (
	TCP_FIN = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
	TCP_ECE
	TCP_CWR
	TCP_NS
)

func (p *Packet) decodeTcp() {
	pkt := p.Payload
	tcp := new(Tcphdr)
	tcp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	tcp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	tcp.Seq = binary.BigEndian.Uint32(pkt[4:8])
	tcp.Ack = binary.BigEndian.Uint32(pkt[8:12])
	tcp.DataOffset = (pkt[12] & 0xF0) >> 4
	tcp.Flags = binary.BigEndian.Uint16(pkt[12:14]) & 0x1FF
	tcp.Window = binary.BigEndian.Uint16(pkt[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(pkt[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(pkt[18:20])
	p.Payload = pkt[tcp.DataOffset*4:]
	p.Headers = append(p.Headers, tcp)
	p.TCP = tcp
}

func (tcp *Tcphdr) String(hdr addrHdr) string {
	return fmt.Sprintf("TCP %s:%d > %s:%d %s SEQ=%d ACK=%d LEN=%d",
		hdr.SrcAddr(), int(tcp.SrcPort), hdr.DestAddr(), int(tcp.DestPort),
		tcp.FlagsString(), int64(tcp.Seq), int64(tcp.Ack), hdr.Len())
}

func (tcp *Tcphdr) FlagsString() string {
	var sflags []string
	if 0 != (tcp.Flags & TCP_SYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (tcp.Flags & TCP_FIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (tcp.Flags & TCP_ACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (tcp.Flags & TCP_PSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (tcp.Flags & TCP_RST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (tcp.Flags & TCP_URG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (tcp.Flags & TCP_NS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (tcp.Flags & TCP_CWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (tcp.Flags & TCP_ECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, " "))
}

type Udphdr struct {
	SrcPort  uint16
	DestPort uint16
	Length   uint16
	Checksum uint16
}

func (p *Packet) decodeUdp() {
	pkt := p.Payload
	udp := new(Udphdr)
	udp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	udp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	udp.Length = binary.BigEndian.Uint16(pkt[4:6])
	udp.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	p.Headers = append(p.Headers, udp)
	p.UDP = udp
	p.Payload = pkt[8:]
}

func (udp *Udphdr) String(hdr addrHdr) string {
	return fmt.Sprintf("UDP %s:%d > %s:%d LEN=%d CHKSUM=%d",
		hdr.SrcAddr(), int(udp.SrcPort), hdr.DestAddr(), int(udp.DestPort),
		int(udp.Length), int(udp.Checksum))
}

type Icmphdr struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
	Data     []byte
}

func (p *Packet) decodeIcmp() *Icmphdr {
	pkt := p.Payload
	icmp := new(Icmphdr)
	icmp.Type = pkt[0]
	icmp.Code = pkt[1]
	icmp.Checksum = binary.BigEndian.Uint16(pkt[2:4])
	icmp.Id = binary.BigEndian.Uint16(pkt[4:6])
	icmp.Seq = binary.BigEndian.Uint16(pkt[6:8])
	p.Payload = pkt[8:]
	p.Headers = append(p.Headers, icmp)
	return icmp
}

func (icmp *Icmphdr) String(hdr addrHdr) string {
	return fmt.Sprintf("ICMP %s > %s Type = %d Code = %d ",
		hdr.SrcAddr(), hdr.DestAddr(), icmp.Type, icmp.Code)
}

func (icmp *Icmphdr) TypeString() (result string) {
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

type Ip6hdr struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	Version      uint8  // 4 bits
	TrafficClass uint8  // 8 bits
	FlowLabel    uint32 // 20 bits
	Length       uint16 // 16 bits
	NextHeader   uint8  // 8 bits, same as Protocol in Iphdr
	HopLimit     uint8  // 8 bits
	SrcIp        []byte // 16 bytes
	DestIp       []byte // 16 bytes
}

func (p *Packet) decodeIp6() {
	pkt := p.Payload
	ip6 := new(Ip6hdr)
	ip6.Version = uint8(pkt[0]) >> 4
	ip6.TrafficClass = uint8((binary.BigEndian.Uint16(pkt[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = binary.BigEndian.Uint32(pkt[0:4]) & 0x000FFFFF
	ip6.Length = binary.BigEndian.Uint16(pkt[4:6])
	ip6.NextHeader = pkt[6]
	ip6.HopLimit = pkt[7]
	ip6.SrcIp = pkt[8:24]
	ip6.DestIp = pkt[24:40]
	p.Payload = pkt[40:]
	p.Headers = append(p.Headers, ip6)

	switch ip6.NextHeader {
	case IP_TCP:
		p.decodeTcp()
	case IP_UDP:
		p.decodeUdp()
	case IP_ICMP:
		p.decodeIcmp()
	case IP_INIP:
		p.decodeIp()
	}
}

func (ip6 *Ip6hdr) SrcAddr() string  { return net.IP(ip6.SrcIp).String() }
func (ip6 *Ip6hdr) DestAddr() string { return net.IP(ip6.DestIp).String() }
func (ip6 *Ip6hdr) Len() int         { return int(ip6.Length) }
*/
