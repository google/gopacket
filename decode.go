package pcap

import (
	"fmt"
	"net"
	"time"
	"reflect"
	"strings"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

const (
	ERRBUF_SIZE = 256

	// according to pcap-linktype(7)
	LINKTYPE_NULL             = 0
	LINKTYPE_ETHERNET         = 1
	LINKTYPE_TOKEN_RING       = 6
	LINKTYPE_ARCNET           = 7
	LINKTYPE_SLIP             = 8
	LINKTYPE_PPP              = 9
	LINKTYPE_FDDI             = 10
	LINKTYPE_ATM_RFC1483      = 100
	LINKTYPE_RAW              = 101
	LINKTYPE_PPP_HDLC         = 50
	LINKTYPE_PPP_ETHER        = 51
	LINKTYPE_C_HDLC           = 104
	LINKTYPE_IEEE802_11       = 105
	LINKTYPE_FRELAY           = 107
	LINKTYPE_LOOP             = 108
	LINKTYPE_LINUX_SLL        = 113
	LINKTYPE_LTALK            = 104
	LINKTYPE_PFLOG            = 117
	LINKTYPE_PRISM_HEADER     = 119
	LINKTYPE_IP_OVER_FC       = 122
	LINKTYPE_SUNATM           = 123
	LINKTYPE_IEEE802_11_RADIO = 127
	LINKTYPE_ARCNET_LINUX     = 129
	LINKTYPE_LINUX_IRDA       = 144
	LINKTYPE_LINUX_LAPD       = 177
)

type addrHdr interface {
	SrcAddr() string
	DestAddr() string
	Len() int
}

type stringer interface {
	String() string
}

type addrStringer interface {
	String(addr addrHdr) string
}

func decodemac(pkt []byte) uint64 {
	mac := uint64(0)
	for i := uint(0); i < 6; i++ {
		mac = (mac << 8) + uint64(pkt[i])
	}
	return mac
}

func decodeuint16(pkt []byte) uint16 {
	return uint16(pkt[0])<<8 + uint16(pkt[1])
}

func decodeuint32(pkt []byte) uint32 {
	return uint32(pkt[0])<<24 + uint32(pkt[1])<<16 + uint32(pkt[2])<<8 + uint32(pkt[3])
}

// Decode decodes the headers of a packet.
func (p *Packet) Decode() {
	p.Type = int(decodeuint16(p.Data[12:14]))
	p.DestMac = decodemac(p.Data[0:6])
	p.SrcMac = decodemac(p.Data[6:12])
	p.Payload = p.Data[14:]

	switch p.Type {
	case TYPE_IP:
		p.decodeIp()
	case TYPE_IP6:
		p.decodeIp6()
	case TYPE_ARP:
		p.decodeArp()
	}
}

// TimeString returns the packet time in a human-readable string.
func (p *Packet) TimeString() string {
	t := time.SecondsToLocalTime(int64(p.Time.Sec))
	return fmt.Sprintf("%02d:%02d:%02d.%06d ", t.Hour, t.Minute, t.Second, p.Time.Usec)
}

func (p *Packet) headerString(headers []interface{}) string {
	// If there's just one header, return that.
	if len(headers) == 1 {
		if hdr, ok := headers[0].(stringer); ok {
			return hdr.String()
		}
	}
	// If there are two headers (IPv4/IPv6 -> TCP/UDP/IP..)
	if len(headers) == 2 {
		// Commonly the first header is an address.
		if addr, ok := p.Headers[0].(addrHdr); ok {
			if hdr, ok := p.Headers[1].(addrStringer); ok {
				return fmt.Sprintf("%s %s", p.TimeString(), hdr.String(addr))
			}
		}
	}
	// For IP in IP, we do a recursive call.
	if len(headers) >= 2 {
		if addr, ok := headers[0].(addrHdr); ok {
			if _, ok := headers[1].(addrHdr); ok {
				return fmt.Sprintf("%s > %s IP in IP: ",
					addr.SrcAddr(), addr.DestAddr(), p.headerString(headers[1:]))
			}
		}
	}

	var typeNames []string
	for _, hdr := range headers {
		typeNames = append(typeNames, reflect.TypeOf(hdr).String())
	}

	return fmt.Sprintf("unknown [%s]", strings.Join(typeNames, ","))
}

// String prints a one-line representation of the packet header.
// The output is suitable for use in a tcpdump program.
func (p *Packet) String() string {
	// If there are no headers, print "unsupported protocol".
	if len(p.Headers) == 0 {
		return fmt.Sprintf("%s unsupported protocol %d", p.TimeString(), int(p.Type))
	}
	return fmt.Sprintf("%s %s", p.TimeString(), p.headerString(p.Headers))
}

type Arphdr struct {
	Addrtype          uint16
	Protocol          uint16
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DestHwAddress     []byte
	DestProtAddress   []byte
}

func Arpop(op uint16) string {
	switch op {
	case 1:
		return "Request"
	case 2:
		return "Reply"
	}
	return ""
}

func (arp *Arphdr) String() string {
	result := fmt.Sprintf("ARP %s ", Arpop(arp.Operation))
	if arp.Addrtype == LINKTYPE_ETHERNET && arp.Protocol == TYPE_IP {
		result = fmt.Sprintf("%012x (%s) > %012x (%s)",
			decodemac(arp.SourceHwAddress), arp.SourceProtAddress,
			decodemac(arp.DestHwAddress), arp.DestProtAddress)
	} else {
		result = fmt.Sprintf("addrtype = %d protocol = %d", arp.Addrtype, arp.Protocol)
	}
	return result
}

func (p *Packet) decodeArp() {
	pkt := p.Payload
	arp := new(Arphdr)
	arp.Addrtype = decodeuint16(pkt[0:2])
	arp.Protocol = decodeuint16(pkt[2:4])
	arp.HwAddressSize = pkt[4]
	arp.ProtAddressSize = pkt[5]
	arp.Operation = decodeuint16(pkt[6:8])
	arp.SourceHwAddress = pkt[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = pkt[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestHwAddress = pkt[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestProtAddress = pkt[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	p.Headers = append(p.Headers, arp)
	p.Payload = p.Payload[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
}

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
	ip.Length = decodeuint16(pkt[2:4])
	ip.Id = decodeuint16(pkt[4:6])
	flagsfrags := decodeuint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.Ttl = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = decodeuint16(pkt[10:12])
	ip.SrcIp = pkt[12:16]
	ip.DestIp = pkt[16:20]
	p.Payload = pkt[ip.Ihl*4:]
	p.Headers = append(p.Headers, ip)

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

func (ip *Iphdr) SrcAddr() string {
	return net.IP(ip.SrcIp).String()
}

func (ip *Iphdr) DestAddr() string {
	return net.IP(ip.DestIp).String()
}

func (ip *Iphdr) Len() int {
	return int(ip.Length)
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
	tcp.SrcPort = decodeuint16(pkt[0:2])
	tcp.DestPort = decodeuint16(pkt[2:4])
	tcp.Seq = decodeuint32(pkt[4:8])
	tcp.Ack = decodeuint32(pkt[8:12])
	tcp.DataOffset = (pkt[12] & 0xF0) >> 4
	tcp.Flags = uint16(decodeuint16(pkt[12:14]) & 0x1FF)
	tcp.Window = decodeuint16(pkt[14:16])
	tcp.Checksum = decodeuint16(pkt[16:18])
	tcp.Urgent = decodeuint16(pkt[18:20])
	p.Payload = pkt[tcp.DataOffset*4:]
	p.Headers = append(p.Headers, tcp)
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
	udp.SrcPort = decodeuint16(pkt[0:2])
	udp.DestPort = decodeuint16(pkt[2:4])
	udp.Length = decodeuint16(pkt[4:6])
	udp.Checksum = decodeuint16(pkt[6:8])
	p.Headers = append(p.Headers, udp)
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
	icmp.Checksum = decodeuint16(pkt[2:4])
	icmp.Id = decodeuint16(pkt[4:6])
	icmp.Seq = decodeuint16(pkt[6:8])
	p.Payload = pkt[8:]
	p.Headers = append(p.Headers, icmp)
	return icmp
}

func (icmp *Icmphdr) String(hdr addrHdr) string {
	return fmt.Sprintf("ICMP %s > %s Type = %d Code = %d ",
		hdr.SrcAddr(), hdr.DestAddr(), icmp.Type, icmp.Code)
}

func (icmp *Icmphdr) TypeString() string {
	result := ""
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
	return result
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
	ip6.TrafficClass = uint8((decodeuint16(pkt[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = decodeuint32(pkt[0:4]) & 0x000FFFFF
	ip6.Length = decodeuint16(pkt[4:6])
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

func (ip6 *Ip6hdr) SrcAddr() string {
	return net.IP(ip6.SrcIp).String()
}

func (ip6 *Ip6hdr) DestAddr() string {
	return net.IP(ip6.DestIp).String()
}

func (ip6 *Ip6hdr) Len() int {
	return int(ip6.Length)
}